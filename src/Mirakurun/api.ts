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
import { promisify } from "util";
import * as yieldableJSON from "yieldable-json";
const stringifyAsync = promisify(yieldableJSON.stringifyAsync);
import * as express from "express";

import { OutputFormat } from "./common";

/**
 * Decide what a stream request gets when it does not say `format`.
 *
 * A TS stream is always TS. A TLV stream is handed out as `tlvDefault`
 * (server.yml `defaultTlvStreamFormat`), and `format=ts` turns on
 * `tlvToTsDecoder` regardless. (`format=tlv` on a TS stream is refused by
 * the caller before this.)
 */
export function resolveStreamFormat(requested: unknown, streamIsTlv: boolean, tlvDefault: OutputFormat = "tlv"): { outputFormat: OutputFormat; contentType: string } {
    const outputFormat: OutputFormat = (requested === "tlv" || requested === "ts") ? requested : (streamIsTlv ? tlvDefault : "ts");
    return {
        outputFormat,
        contentType: outputFormat === "tlv" ? "application/octet-stream" : "video/MP2T"
    };
}

export interface Error {
    readonly code: number;
    readonly reason: string;
    readonly errors: any[];
}

export function responseError(res: express.Response, code: number, reason?: string): express.Response {
    if (reason) {
        res.writeHead(code, reason, {
            "Content-Type": "application/json"
        });
    } else {
        res.writeHead(code, {
            "Content-Type": "application/json"
        });
    }

    const error: Error = {
        code: code,
        reason: reason || null,
        errors: []
    };

    res.end(JSON.stringify(error));

    return res;
}

export function responseStreamErrorHandler(res: express.Response, err: NodeJS.ErrnoException): express.Response {
    if (err.message === "no available tuners") {
        return responseError(res, 503, "Tuner Resource Unavailable");
    }

    return responseError(res, 500, err.message);
}

export async function responseJSON(res: express.Response, body: any): Promise<express.Response> {
    // this is lighter than res.json()
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.status(200);
    res.end(await stringifyAsync(body));

    return res;
}
