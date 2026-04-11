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
import * as apid from "../../api";
import ServiceItem from "./ServiceItem";
import TSFilter from "./TSFilter";
import StreamFilter from "./StreamFilter";

export default class ChannelItem {
    readonly name: string;
    readonly type: apid.ChannelType;
    readonly channel: string;
    readonly commandVars: apid.ConfigChannelsItem["commandVars"];
    private _tsmfRelTs: number;
    private _configTsmfRelTs: boolean;
    private _tsmfGroupId: number;
    private _configTsmfGroupId: boolean;
    /** TSMF stream info keyed by relTs. Stores stream_id, onId, serviceIds, and TS/TLV type. */
    private _tsmfStreams = new Map<number, {
        streamId: number;
        onId: number;
        isTlv: boolean;
        serviceIds: Set<number>;
        configServiceIds: Set<number>;
    }>();

    constructor(config: apid.ConfigChannelsItem) {
        this.name = config.name;
        this.type = config.type;
        this.channel = config.channel;
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

    /** True iff `tsmfRelTs` was supplied via channels.yml (and is therefore not auto-detected). */
    get hasConfigTsmfRelTs(): boolean {
        return this._configTsmfRelTs;
    }

    /** True iff `tsmfGroupId` was supplied via channels.yml. */
    get hasConfigTsmfGroupId(): boolean {
        return this._configTsmfGroupId;
    }

    setTsmfRelTs(relTs: number): void {
        if (this._configTsmfRelTs || relTs === this._tsmfRelTs) {
            return;
        }
        this._tsmfRelTs = relTs;
        _.tsmf?.schedule();
    }

    setTsmfGroupId(groupId: number): void {
        if (this._configTsmfGroupId || groupId === this._tsmfGroupId) {
            return;
        }
        this._tsmfGroupId = groupId;
        _.tsmf?.schedule();
    }

    addTsmfServiceId(serviceId: number, relTs: number, fromConfig = false): void {
        const entry = this._getOrCreateStream(relTs);
        if (fromConfig) {
            entry.configServiceIds.add(serviceId);
        }
        if (entry.configServiceIds.has(serviceId) && !fromConfig) {
            return;
        }
        if (entry.serviceIds.has(serviceId)) {
            return;
        }
        entry.serviceIds.add(serviceId);
        if (!fromConfig) {
            _.tsmf?.schedule();
        }
    }

    getTsmfRelTs(serviceId?: number): number | undefined {
        if (serviceId !== undefined && serviceId !== null) {
            for (const [relTs, entry] of this._tsmfStreams) {
                if (entry.serviceIds.has(serviceId)) {
                    return relTs;
                }
            }
        }
        return this.tsmfRelTs;
    }

    /**
     * Record TSMF stream info (relTs → streamId) parsed from the TSMF header.
     * Preserves existing serviceIds if the entry already exists.
     */
    setTsmfStream(relTs: number, streamId: number, onId: number, isTlv: boolean): void {
        const existing = this._tsmfStreams.get(relTs);
        if (existing) {
            if (existing.streamId === streamId && existing.onId === onId && existing.isTlv === isTlv) {
                return;
            }
            existing.streamId = streamId;
            existing.onId = onId;
            existing.isTlv = isTlv;
        } else {
            this._tsmfStreams.set(relTs, {
                streamId, onId, isTlv,
                serviceIds: new Set(),
                configServiceIds: new Set()
            });
        }
        _.tsmf?.schedule();
    }

    getTsmfStreams(): typeof this._tsmfStreams {
        return this._tsmfStreams;
    }

    getServices(): ServiceItem[] {
        return _.service.findByChannel(this);
    }

    isSameTsmfGroup(other: ChannelItem | null | undefined): boolean {
        if (!other) {
            return false;
        }
        if (this.tsmfGroupId === null || this.tsmfGroupId === undefined) {
            return false;
        }
        if (other.tsmfGroupId === null || other.tsmfGroupId === undefined) {
            return false;
        }
        return this.tsmfGroupId === other.tsmfGroupId;
    }

    getStream(user: common.User, output: stream.Writable, tsmfRelTs?: number): Promise<TSFilter | StreamFilter> {
        return _.tuner.initChannelStream(this, user, output, tsmfRelTs);
    }

    toJSON(): apid.Channel {
        return {
            type: this.type,
            channel: this.channel,
            name: this.name,
            ...(this._tsmfRelTs !== null && this._tsmfRelTs !== undefined && { tsmfRelTs: this._tsmfRelTs }),
            ...(this._tsmfGroupId !== null && this._tsmfGroupId !== undefined && { tsmfGroupId: this._tsmfGroupId }),
            services: this.getServices().map(service => {
                const tsmfRelTs = this.getTsmfRelTs(service.serviceId);
                return {
                    id: service.id,
                    serviceId: service.serviceId,
                    networkId: service.networkId,
                    name: service.name,
                    type: service.type,
                    ...(tsmfRelTs !== undefined && tsmfRelTs !== null && { tsmfRelTs })
                };
            })
        };
    }

    private _getOrCreateStream(relTs: number) {
        let entry = this._tsmfStreams.get(relTs);
        if (!entry) {
            entry = { streamId: 0, onId: 0, isTlv: false, serviceIds: new Set(), configServiceIds: new Set() };
            this._tsmfStreams.set(relTs, entry);
        }
        return entry;
    }
}
