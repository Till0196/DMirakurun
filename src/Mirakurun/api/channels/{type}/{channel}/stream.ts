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
import {Operation} from "express-openapi";
import * as api from "../../../../api";
import * as apid from "../../../../../../api";
import { channelTypes, OutputFormat } from "../../../../common";
import ChannelItem, { StreamEntry } from "../../../../ChannelItem";
import _ from "../../../../_";

export const parameters = [
    {
        in: "path",
        name: "type",
        type: "string",
        enum: channelTypes,
        required: true
    },
    {
        in: "path",
        name: "channel",
        description: "Channel name, or numeric streamId.",
        type: "string",
        required: true
    },
    {
        in: "header",
        name: "X-Mirakurun-Priority",
        type: "integer",
        minimum: 0
    },
    {
        in: "query",
        name: "decode",
        type: "integer",
        minimum: 0,
        maximum: 1
    },
    {
        in: "query",
        name: "format",
        type: "string",
        enum: ["ts", "tlv"]
    },
    {
        in: "query",
        name: "tsmfRelTs",
        type: "integer",
        minimum: 0,
        maximum: 15
    }
];

export const get: Operation = (req, res) => {
    const type = req.params.type as apid.ChannelType;
    const key = req.params.channel as string;

    // Numeric key falls back to streamId lookup so `channel.channel = String(streamId)`
    // from `/api/services` resolves here; multi-route matches feed the tuner picker.
    let channel: ChannelItem | null = _.channel.get(type, key);
    let streamEntry: StreamEntry | undefined;
    let altChannels: ChannelItem[] | undefined;
    if (channel === null && /^\d+$/.test(key)) {
        const streamId = parseInt(key, 10);
        const matches = _.channel.findByTypeAndStreamId(type, streamId);
        channel = matches[0] || null;
        altChannels = matches.length > 1 ? matches : undefined;
        if (channel) {
            for (const e of channel.getStreams().values()) {
                if (e.streamId === streamId) {
                    streamEntry = e;
                    break;
                }
            }
        }
    }

    if (channel === null) {
        api.responseError(res, 404);
        return;
    }

    const userId = (req.ip || "unix") + ":" + (req.socket.remotePort || Date.now());

    const queryFormat = req.query.format as ("ts" | "tlv" | undefined);
    const outputFormat: OutputFormat | undefined = queryFormat
        ? (queryFormat === "tlv" ? "tlv" : undefined)
        : (streamEntry?.isTlv ? "tlv" : undefined);
    const tsmfRelTs = req.query.tsmfRelTs !== undefined
        ? parseInt(req.query.tsmfRelTs as string, 10)
        : streamEntry?.relTs;

    const contentType = outputFormat === "tlv" ? "application/octet-stream" : "video/MP2T";

    // HEAD request support
    if (req.method === "HEAD") {
        res.setHeader("Content-Type", contentType);
        res.setHeader("X-Mirakurun-Tuner-User-ID", userId);
        res.status(200).end();
        return;
    }

    let requestAborted = false;
    req.once("close", () => requestAborted = true);

    (<any> res.socket)._writableState.highWaterMark = Math.max(res.writableHighWaterMark, 1024 * 1024 * 16);
    res.socket.setNoDelay(true);

    _.tuner.initChannelStream(channel, {
        id: userId,
        priority: parseInt(req.get("X-Mirakurun-Priority"), 10) || 0,
        agent: req.get("User-Agent"),
        url: req.url,
        disableDecoder: (<number> <any> req.query.decode === 0),
        outputFormat
    }, res, tsmfRelTs, altChannels)
        .then(tsFilter => {
            if (requestAborted === true || req.aborted === true) {
                return tsFilter.close();
            }

            req.once("close", () => tsFilter.close());

            res.setHeader("Content-Type", contentType);
            res.setHeader("X-Mirakurun-Tuner-User-ID", userId);
            res.status(200);
        })
        .catch((err) => api.responseStreamErrorHandler(res, err));
};

get.apiDoc = {
    tags: ["channels", "stream"],
    operationId: "getChannelStream",
    produces: ["video/MP2T"],
    responses: {
        200: {
            description: "OK",
            headers: {
                "X-Mirakurun-Tuner-User-ID": {
                    type: "string"
                }
            }
        },
        404: {
            description: "Not Found"
        },
        503: {
            description: "Tuner Resource Unavailable"
        },
        default: {
            description: "Unexpected Error"
        }
    }
};

// HEAD request support
export const head: Operation = (...args) => get(...args);

head.apiDoc = {
    ...get.apiDoc,
    operationId: undefined
};
