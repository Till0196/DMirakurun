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

export default class ChannelItem {
    readonly name: string;
    readonly type: apid.ChannelType;
    readonly channel: string;
    readonly tsmfRelTs: number;
    readonly tsmfGroupId: number;
    readonly commandVars: apid.ConfigChannelsItem["commandVars"];

    constructor(config: apid.ConfigChannelsItem) {
        this.name = config.name;
        this.type = config.type;
        this.channel = config.channel;
        this.tsmfRelTs = config.tsmfRelTs;
        this.tsmfGroupId = config.tsmfGroupId;
        this.commandVars = config.commandVars;
    }

    getServices(): ServiceItem[] {
        return _.service.findByChannel(this);
    }

    isSameTsmfGroup(other: ChannelItem | null | undefined): boolean {
        if (!other) {
            return false;
        }
        if (this.type !== "BS4K" || other.type !== "BS4K") {
            return false;
        }
        if (this.tsmfGroupId === null || this.tsmfGroupId === undefined) {
            return false;
        }
        if (other.tsmfGroupId === null || other.tsmfGroupId === undefined) {
            return false;
        }
        if (this.tsmfRelTs === null || this.tsmfRelTs === undefined) {
            return false;
        }
        if (other.tsmfRelTs === null || other.tsmfRelTs === undefined) {
            return false;
        }
        return this.tsmfGroupId === other.tsmfGroupId && this.tsmfRelTs === other.tsmfRelTs;
    }

    getStream(user: common.User, output: stream.Writable): Promise<TSFilter> {
        return _.tuner.initChannelStream(this, user, output);
    }
}
