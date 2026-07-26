/*
   Copyright 2016 kanreisa

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
import * as stream from "stream";
import _ from "./_";
import * as common from "./common";
import { defaultRouteForType } from "./common";
import * as apid from "../../api";
import ServiceItem from "./ServiceItem";
import TSFilter from "./TSFilter";
import StreamFilter from "./StreamFilter";

/**
 * One MPEG-TS or TLV stream carried by a channel. Keyed by `streamKey`:
 * `0` = non-TSMF (plain TS or direct-TLV), `1..15` = TSMF slot (== relTs).
 */
export interface StreamEntry {
    streamId: number;
    networkId: number;
    isTlv: boolean;
    relTs?: number;
    serviceIds: Set<number>;
    /** serviceIds supplied via channels.yml — locked, not overwritten at runtime. */
    configServiceIds: Set<number>;
}

export default class ChannelItem {
    readonly name: string;
    readonly type: apid.ChannelType;
    readonly route: apid.ChannelRoute;
    readonly channel: string;
    readonly commandVars: apid.ConfigChannelsItem["commandVars"];
    private _tsmfRelTs: number;
    private _configTsmfRelTs: boolean;
    private _tsmfGroupId: number;
    private _configTsmfGroupId: boolean;
    private _streams = new Map<number, StreamEntry>();

    constructor(config: apid.ConfigChannelsItem) {
        this.name = config.name;
        this.type = config.type;
        this.route = config.route ?? defaultRouteForType(config.type);
        this.channel = config.channel;
        // channels.yml は tsmfRelTs に統一。TS/TLV の区別は runtime の auto-detect で扱う。
        this._tsmfRelTs = config.tsmfRelTs;
        this._configTsmfRelTs = config.tsmfRelTs !== null && config.tsmfRelTs !== undefined;
        this._tsmfGroupId = config.tsmfGroupId;
        this._configTsmfGroupId = config.tsmfGroupId !== null && config.tsmfGroupId !== undefined;
        this.commandVars = config.commandVars;
    }

    get tsmfRelTs(): number {
        return this._tsmfRelTs;
    }

    get tsmfGroupId(): number {
        return this._tsmfGroupId;
    }

    get hasConfigTsmfRelTs(): boolean {
        return this._configTsmfRelTs;
    }

    get hasConfigTsmfGroupId(): boolean {
        return this._configTsmfGroupId;
    }

    setTsmfRelTs(relTs: number): void {
        if (this._configTsmfRelTs || relTs === this._tsmfRelTs) {
            return;
        }
        this._tsmfRelTs = relTs;
    }

    setTsmfGroupId(groupId: number): void {
        if (this._configTsmfGroupId || groupId === this._tsmfGroupId) {
            return;
        }
        this._tsmfGroupId = groupId;
    }

    addServiceId(serviceId: number, streamKey: number, fromConfig = false): void {
        // Skip a config-loaded streamKey=0 entry on a channel that has TSMF
        // slot entries — likely a missing `tsmfRelTs:` in channels.yml.
        if (fromConfig && streamKey === 0) {
            for (const key of this._streams.keys()) {
                if (key >= 1) {
                    return;
                }
            }
        }
        let entry = this._streams.get(streamKey);
        if (!entry) {
            entry = {
                streamId: 0,
                networkId: 0,
                isTlv: false,
                relTs: streamKey >= 1 ? streamKey : undefined,
                serviceIds: new Set(),
                configServiceIds: new Set()
            };
            this._streams.set(streamKey, entry);
        }
        if (fromConfig) {
            entry.configServiceIds.add(serviceId);
            return;
        }
        if (entry.configServiceIds.has(serviceId) || entry.serviceIds.has(serviceId)) {
            return;
        }
        entry.serviceIds.add(serviceId);
    }

    getRelTs(serviceId?: number): number | undefined {
        if (serviceId !== undefined && serviceId !== null) {
            for (const entry of this._streams.values()) {
                if (entry.serviceIds.has(serviceId)) {
                    return entry.relTs;
                }
            }
        }
        return this.tsmfRelTs;
    }

    setStream(streamKey: number, streamId: number, networkId: number, isTlv: boolean, relTs?: number): void {
        if (streamId === 0xFFFF) {
            return;
        }

        if (streamKey >= 1) {
            const stale = this._streams.get(0);
            if (stale && stale.configServiceIds.size === 0) {
                this._streams.delete(0);
            }
        } else if (streamKey === 0) {
            const existing = this._streams.get(0);
            if (existing && existing.isTlv !== isTlv) {
                this._streams.delete(0);
            }
        }

        const existing = this._streams.get(streamKey);
        if (existing) {
            if (existing.streamId === streamId &&
                existing.networkId === networkId &&
                existing.isTlv === isTlv &&
                existing.relTs === relTs) {
                return;
            }
            existing.streamId = streamId;
            existing.networkId = networkId;
            existing.isTlv = isTlv;
            existing.relTs = relTs;
        } else {
            this._streams.set(streamKey, {
                streamId, networkId, isTlv, relTs,
                serviceIds: new Set(),
                configServiceIds: new Set()
            });
        }
    }

    getStreams(): ReadonlyMap<number, StreamEntry> {
        return this._streams;
    }

    getStreamForService(serviceId: number): StreamEntry | undefined {
        for (const entry of this._streams.values()) {
            if (entry.serviceIds.has(serviceId)) {
                return entry;
            }
        }
        return undefined;
    }

    getServices(): ServiceItem[] {
        return _.service.findByChannel(this);
    }

    /**
     * Same TSMF bonded multiplex (groupId match + slot-stream tuples match).
     * Slot-stream check guards against 8-bit groupId collisions between
     * unrelated CATV systems. Optimistic when either side has no slot data.
     */
    isSameTsmfGroup(other: ChannelItem | null | undefined): boolean {
        if (!other) {
            return false;
        }
        if (this._tsmfGroupId === null || this._tsmfGroupId === undefined) {
            return false;
        }
        if (other._tsmfGroupId === null || other._tsmfGroupId === undefined) {
            return false;
        }
        if (this._tsmfGroupId !== other._tsmfGroupId) {
            return false;
        }

        const entries = [...this._streams].filter(([k]) => k >= 1);
        const otherEntries = [...other._streams].filter(([k]) => k >= 1);
        if (entries.length === 0 || otherEntries.length === 0) {
            return true;
        }
        if (entries.length !== otherEntries.length) {
            return false;
        }
        for (const [streamKey, entry] of entries) {
            const otherEntry = other._streams.get(streamKey);
            if (!otherEntry ||
                entry.streamId !== otherEntry.streamId ||
                entry.networkId !== otherEntry.networkId ||
                entry.isTlv !== otherEntry.isTlv) {
                return false;
            }
        }
        return true;
    }

    getStream(user: common.User, output: stream.Writable, tsmfRelTs?: number): Promise<TSFilter | StreamFilter> {
        return _.tuner.initChannelStream(this, user, output, tsmfRelTs);
    }

    toJSON(): apid.Channel {
        return {
            type: this.type,
            channel: this.channel,
            name: this.name,
            route: this.route,
            ...(this._tsmfGroupId !== null && this._tsmfGroupId !== undefined && this._tsmfGroupId !== 255 && { tsmfGroupId: this._tsmfGroupId }),
            services: this.getServices().map(service => {
                const entry = this.getStreamForService(service.serviceId);
                const svc: apid.Service = {
                    id: service.id,
                    serviceId: service.serviceId,
                    networkId: service.networkId,
                    streamId: service.streamId,
                    name: service.name,
                    type: service.type
                };
                if (entry) {
                    svc.streamId = entry.streamId;
                    if (entry.relTs !== undefined) {
                        if (entry.isTlv) {
                            svc.tsmfRelTlv = entry.relTs;
                        } else {
                            svc.tsmfRelTs = entry.relTs;
                        }
                    }
                }
                return svc;
            })
        };
    }

}
