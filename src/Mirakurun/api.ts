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

/** The `format` query as a stream format, or `undefined` when it did not say. */
export function requestedStreamFormat(query: unknown): OutputFormat | undefined {
    return query === "tlv" || query === "ts" ? query : undefined;
}

export function streamContentType(format: OutputFormat | undefined): string {
    return format === "tlv" ? "application/octet-stream" : "video/MP2T";
}

/**
 * Answer a stream request with what the tuner turned out to deliver. The
 * Content-Type follows the container the filter emits, which is known only
 * after the input has been seen; a TS input that was asked for as TLV ends in
 * 406 instead of a transport stream under the wrong label.
 */
/** What respondStream needs from the filter; StreamFilter provides it. */
export interface StreamSink {
    readonly outputFormat?: OutputFormat | null;
    once(event: string, listener: (...args: any[]) => void): unknown;
}

export function respondStream(res: express.Response, filter: StreamSink, userId: string): void {
    const start = (format: OutputFormat) => {
        if (res.headersSent) {
            return;
        }
        res.setHeader("Content-Type", streamContentType(format));
        res.setHeader("X-Mirakurun-Tuner-User-ID", userId);
        res.status(200);
    };
    if (filter.outputFormat) {
        start(filter.outputFormat);
        return;
    }
    if (filter.outputFormat === undefined) {
        // A sink without detection only ever carries TS.
        start("ts");
        return;
    }
    filter.once("outputFormat", start);
    filter.once("unavailable", (reason: string) => {
        if (!res.headersSent) {
            responseError(res, 406, reason);
        }
    });
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
