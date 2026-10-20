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
import * as api from "../../../../api";
import _ from "../../../../_";

export const parameters = [
    {
        in: "path",
        name: "networkId",
        type: "integer",
        minimum: 0,
        maximum: 65535,
        required: true
    },
    {
        in: "path",
        name: "streamId",
        type: "integer",
        minimum: 0,
        maximum: 65535,
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
    }
];

export const get: Operation = (req, res) => {
    const networkId = req.params.networkId as any as number;
    const streamId = req.params.streamId as any as number;
    const streamID = _.channel.getStreamID(networkId, streamId);

    if (!streamID) {
        api.responseError(res, 404);
        return;
    }

    if (req.query.format === "tlv" && streamID.streamFormat === "ts") {
        api.responseError(res, 406, "Requested Stream Format Unavailable");
        return;
    }
    const userId = (req.ip || "unix") + ":" + (req.socket.remotePort || Date.now());
    const outputFormat = api.requestedStreamFormat(req.query.format);
    if (req.method === "HEAD") {
        res.setHeader("Content-Type", api.streamContentType(outputFormat ?? streamID.streamFormat));
        res.setHeader("X-Mirakurun-Tuner-User-ID", userId);
        res.status(200).end();
        return;
    }
    let requestAborted = false;
    req.once("close", () => requestAborted = true);
    (<any> res.socket)._writableState.highWaterMark = Math.max(res.writableHighWaterMark, 1024 * 1024 * 16);
    res.socket.setNoDelay(true);
    _.tuner.initStreamIDStream(networkId, streamId, {
        id: userId,
        priority: parseInt(req.get("X-Mirakurun-Priority"), 10) || 0,
        agent: req.get("User-Agent"),
        url: req.url,
        disableDecoder: (<number> <any> req.query.decode === 0),
        outputFormat
    }, res).then(streamFilter => {
        if (requestAborted === true || req.aborted === true) {
            return streamFilter.close();
        }
        req.once("close", () => streamFilter.close());
        api.respondStream(res, streamFilter, userId);
    }).catch(err => api.responseStreamErrorHandler(res, err));
};

get.apiDoc = {
    tags: ["streamids", "stream"],
    operationId: "getStreamIDStream",
    produces: ["video/MP2T", "application/octet-stream"],
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
        406: {
            description: "Requested Stream Format Unavailable"
        },
        503: {
            description: "Tuner Resource Unavailable"
        },
        default: {
            description: "Unexpected Error"
        }
    }
};

export const head: Operation = (...args) => get(...args);

head.apiDoc = {
    ...get.apiDoc,
    operationId: undefined
};
