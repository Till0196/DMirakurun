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
import * as common from "./common";
import _ from "./_";
import * as apid from "../../api";
import Event from "./Event";
import ChannelItem, { StreamEntry } from "./ChannelItem";
import TSFilter from "./TSFilter";
import StreamFilter from "./StreamFilter";

export interface ServiceItemOptions {
    name?: string;
    type?: number;
    isFree?: boolean;
    logoId?: number;
    remoteControlKeyId?: number;
    epgReady?: boolean;
    epgUpdatedAt?: number;
}

export default class ServiceItem {
    static getId(networkId: number, serviceId: number): number {
        return parseInt(networkId + (serviceId / 100000).toFixed(5).slice(2), 10);
    }

    private _id: number;
    private _name?: string;
    private _type?: number;
    private _isFree?: boolean;
    private _logoId?: number;
    private _remoteControlKeyId?: number;
    private _epgReady: boolean;
    private _epgUpdatedAt: number;

    constructor(
        private _streamId: number,
        private _networkId: number,
        private _serviceId: number,
        options: ServiceItemOptions = {}
    ) {
        this._id = ServiceItem.getId(_networkId, _serviceId);
        this._name = options.name;
        this._type = options.type;
        this._isFree = options.isFree;
        this._logoId = options.logoId;
        this._remoteControlKeyId = options.remoteControlKeyId;
        this._epgReady = options.epgReady ?? false;
        this._epgUpdatedAt = options.epgUpdatedAt ?? 0;
    }

    get id(): number {
        return this._id;
    }

    get networkId(): number {
        return this._networkId;
    }

    get serviceId(): number {
        return this._serviceId;
    }

    get streamId(): number {
        return this._streamId;
    }

    get name(): string {
        return this._name || "";
    }

    set name(name: string) {
        if (this._name !== name) {
            this._name = name;

            _.service.save();
            this._updated();
        }
    }

    get type(): number {
        return this._type;
    }

    set type(type: number) {
        if (this._type !== type) {
            this._type = type;

            _.service.save();
            this._updated();
        }
    }

    get isFree(): boolean | undefined {
        return this._isFree;
    }

    set isFree(isFree: boolean | undefined) {
        if (this._isFree !== isFree) {
            this._isFree = isFree;

            _.service.save();
            this._updated();
        }
    }

    get logoId(): number {
        return this._logoId;
    }

    set logoId(logoId: number) {
        if (this._logoId !== logoId) {
            this._logoId = logoId;

            _.service.save();
            this._updated();
        }
    }

    get remoteControlKeyId(): number {
        return this._remoteControlKeyId;
    }

    set remoteControlKeyId(id: number) {
        if (this._remoteControlKeyId !== id) {
            this._remoteControlKeyId = id;

            _.service.save();
            this._updated();
        }
    }

    get epgReady(): boolean {
        return this._epgReady;
    }

    set epgReady(epgReady: boolean) {
        if (this._epgReady !== epgReady) {
            this._epgReady = epgReady;

            _.service.save();
            this._updated();
        }
    }

    get epgUpdatedAt(): number {
        return this._epgUpdatedAt;
    }

    set epgUpdatedAt(time: number) {
        if (this._epgUpdatedAt !== time) {
            this._epgUpdatedAt = time;

            _.service.save();
            this._updated();
        }
    }

    get channel(): ChannelItem | undefined {
        return _.channel?.findByStreamId(this._networkId, this._streamId)[0];
    }

    get channels(): ChannelItem[] {
        return _.channel?.findByStreamId(this._networkId, this._streamId) ?? [];
    }

    export(): apid.Service {
        const ret: apid.Service = {
            id: this._id,
            serviceId: this._serviceId,
            networkId: this._networkId,
            streamId: this._streamId,
            name: this._name || "",
            type: this._type,
            isFree: this._isFree,
            logoId: this._logoId,
            remoteControlKeyId: this._remoteControlKeyId,
            epgReady: this._epgReady,
            epgUpdatedAt: this._epgUpdatedAt
        };

        const serialize = (ch: ChannelItem): apid.Channel => {
            let entry: StreamEntry | undefined;
            for (const e of ch.getStreams().values()) {
                if (e.streamId === this._streamId && e.networkId === this._networkId) {
                    entry = e;
                    break;
                }
            }
            const c: apid.Channel = {
                type: ch.type,
                channel: ch.channel,
                route: ch.route
            };
            if (entry?.relTs !== undefined) {
                if (entry.isTlv) {
                    c.tsmfRelTlv = entry.relTs;
                } else {
                    c.tsmfRelTs = entry.relTs;
                }
            }
            if (ch.tsmfGroupId !== null && ch.tsmfGroupId !== undefined && ch.tsmfGroupId !== 255) {
                c.tsmfGroupId = ch.tsmfGroupId;
            }
            return c;
        };

        const all = this.channels;
        if (all.length > 0) {
            // streamId as channel string keeps the primary identifier stable
            // across route changes for clients that store one channel per service.
            ret.channel = {
                type: all[0].type,
                channel: String(this._streamId)
            };
        }
        if (all.length >= 2) {
            ret.channels = all.map(serialize);
        }

        return ret;
    }

    getStream(userRequest: common.UserRequest, output: stream.Writable): Promise<TSFilter | StreamFilter> {
        return _.tuner.initServiceStream(this, userRequest, output);
    }

    getOrder(): number {
        const channel = this.channel;
        let order: string;

        switch (channel?.type) {
            case "GR":
                order = "1";
                break;
            case "BS":
                order = "2";
                break;
            case "CS":
                order = "3";
                break;
            case "SKY":
                order = "4";
                break;
            case "BS4K":
                order = "5";
                break;
            default:
                order = "9";
                break;
        }

        if (this._remoteControlKeyId) {
            order += (100 + this._remoteControlKeyId).toString(10);
        } else {
            order += "200";
        }

        order += (10000 + this._serviceId).toString(10);

        return parseInt(order, 10);
    }

    private _updated(): void {
        Event.emit("service", "update", this.export());
    }
}
