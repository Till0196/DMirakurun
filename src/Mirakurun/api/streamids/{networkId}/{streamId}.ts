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
import * as api from "../../../api";
import { serializeStreamID } from "../../streamids";
import _ from "../../../_";

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
    }
];

export const get: Operation = (req, res) => {
    const networkId = req.params.networkId as any as number;
    const streamId = req.params.streamId as any as number;
    const item = _.channel.getStreamID(networkId, streamId);

    if (!item) {
        api.responseError(res, 404);
        return;
    }

    api.responseJSON(res, serializeStreamID(item));
};

get.apiDoc = {
    tags: ["streamids"],
    operationId: "getStreamID",
    responses: {
        200: {
            description: "OK",
            schema: {
                $ref: "#/definitions/StreamID"
            }
        },
        404: {
            description: "Not Found",
            schema: {
                $ref: "#/definitions/Error"
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
