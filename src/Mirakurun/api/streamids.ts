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
import { Operation } from "express-openapi";
import * as api from "../api";
import * as apid from "../../../api";
import { StreamIDIndexItem } from "../Channel";
import _ from "../_";

function serializeChannel(value: StreamIDIndexItem["channels"][number]): apid.Channel {
    const { channel, entry } = value;
    const ret: apid.Channel = {
        type: channel.type,
        channel: channel.channel,
        route: channel.route
    };
    if (entry.relTs !== undefined) {
        if (entry.isTlv) {
            ret.tsmfRelTlv = entry.relTs;
        } else {
            ret.tsmfRelTs = entry.relTs;
        }
    }
    if (channel.tsmfGroupId !== null && channel.tsmfGroupId !== undefined && channel.tsmfGroupId !== 255) {
        ret.tsmfGroupId = channel.tsmfGroupId;
    }
    return ret;
}

export function serializeStreamID(item: StreamIDIndexItem): apid.StreamID {
    return {
        networkId: item.networkId,
        streamId: item.streamId,
        channels: item.channels.map(serializeChannel)
    };
}

export const get: Operation = (_req, res) => {
    api.responseJSON(res, _.channel.getStreamIDs().map(serializeStreamID));
};

get.apiDoc = {
    tags: ["streamids"],
    operationId: "getStreamIDs",
    responses: {
        200: {
            description: "OK",
            schema: {
                type: "array",
                items: {
                    $ref: "#/definitions/StreamID"
                }
            }
        },
        default: {
            description: "Unexpected Error",
            schema: {
                $ref: "#/definitions/Error"
            }
        }
    }
};
