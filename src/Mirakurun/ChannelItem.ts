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
    private _relTsMap = new Map<number, number>(); // <serviceId, tsmfRelTs>
    private _configRelTs = new Set<number>(); // serviceIds with config-specified tsmfRelTs

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

    addTsmfRelTsMapping(serviceId: number, tsmfRelTs: number, fromConfig = false): void {
        if (fromConfig) {
            this._configRelTs.add(serviceId);
        }
        if (this._configRelTs.has(serviceId) && !fromConfig) {
            return;
        }
        if (this._relTsMap.get(serviceId) === tsmfRelTs) {
            return;
        }
        this._relTsMap.set(serviceId, tsmfRelTs);
        if (!fromConfig) {
            _.tsmf?.schedule();
        }
    }

    getTsmfRelTs(serviceId?: number): number | undefined {
        if (serviceId !== undefined && serviceId !== null && this._relTsMap.has(serviceId)) {
            return this._relTsMap.get(serviceId);
        }
        return this.tsmfRelTs;
    }

    /** Returns the relTs→serviceIds mapping discovered by TSMF auto-detection. */
    getRelTsMap(): Map<number, Set<number>> {
        const map = new Map<number, Set<number>>();
        for (const [serviceId, relTs] of this._relTsMap) {
            if (!map.has(relTs)) {
                map.set(relTs, new Set());
            }
            map.get(relTs).add(serviceId);
        }
        return map;
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
}
