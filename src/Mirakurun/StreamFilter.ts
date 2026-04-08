/*
   Copyright 2026 Till0196

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
import { Writable } from "stream";
import EventEmitter = require("eventemitter3");
import { StreamInfo } from "./common";
import * as log from "./log";
import TSFilter from "./TSFilter";
import TLVFilter from "./TLVFilter";
import TSDecoder from "./TSDecoder";
import ChannelItem from "./ChannelItem";

// Stream format detection constants
const TS_SYNC = 0x47;
const TS_PKT = 188;
const TLV_SYNC = 0x7f;
const TLV_VALID_TYPES = new Set([0x01, 0x02, 0x03, 0xfe]);
const DETECT_MIN_BYTES = 8192;

export type StreamFormat = "ts" | "tlv" | "tsmf-ts" | "tsmf-tlv";

export interface StreamFilterOptions {
    readonly output?: Writable;
    readonly decoder?: string;         // TS→TS decoder
    readonly tlvToTsDecoder?: string;  // TLV→TS decoder
    readonly tlvDecoder?: string;      // TLV→TLV decoder
    readonly disableDecoder?: boolean;
    readonly networkId?: number;
    readonly serviceId?: number;
    readonly eventId?: number;
    readonly parseNIT?: boolean;
    readonly parseSDT?: boolean;
    readonly parseEIT?: boolean;
    readonly tsmfRelTs?: number;
    readonly channel: ChannelItem;
}

export default class StreamFilter extends EventEmitter {

    streamInfo: StreamInfo = {};

    private _closed = false;
    private _detected = false;
    private _format: StreamFormat | null = null;
    private _options: StreamFilterOptions;
    private _innerFilter: TSFilter | TLVFilter = null;
    private _decoder: TSDecoder = null;
    private _detectChunks: Buffer[] = [];
    private _detectLen = 0;

    constructor(options: StreamFilterOptions) {
        super();
        this._options = options;
    }

    get closed(): boolean {
        return this._closed;
    }

    get detectedFormat(): StreamFormat | null {
        return this._format;
    }

    write(chunk: Buffer): void {
        if (this._closed) {
            return;
        }

        if (this._detected) {
            this._innerFilter.write(chunk);
            return;
        }

        // Buffer data for format detection
        this._detectChunks.push(chunk);
        this._detectLen += chunk.length;

        if (this._detectLen >= DETECT_MIN_BYTES) {
            this._detect();
        }
    }

    end(): void {
        if (!this._detected && this._detectLen > 0) {
            this._detect();
        }
        this.close();
    }

    close(): void {
        if (this._closed) {
            return;
        }
        this._closed = true;

        if (this._innerFilter) {
            this._innerFilter.close();
        }

        this.emit("close");
        this.emit("end");
    }

    // --- Private ---

    private _detect(): void {
        if (this._detected) {
            return;
        }
        this._detected = true;

        const buffer = Buffer.concat(this._detectChunks);
        this._detectChunks = [];

        this._format = this._detectStreamFormat(buffer);
        log.debug("StreamFilter: detected format: %s (%d bytes inspected)", this._format, buffer.length);

        switch (this._format) {
            case "tlv":
                this._setupTLV(buffer);
                break;
            case "ts":
            default:
                this._setupTS(buffer);
                break;
            // TODO: tsmf-ts, tsmf-tlv (Phase 2 - TSMF integration)
        }
    }

    private _setupTS(buffered: Buffer): void {
        const opts = this._options;

        let output: Writable;
        if (opts.disableDecoder || !opts.decoder) {
            output = opts.output;
        } else {
            this._decoder = new TSDecoder({
                output: opts.output,
                command: opts.decoder
            });
            output = this._decoder;
        }

        const tsFilter = new TSFilter({
            output,
            networkId: opts.networkId,
            serviceId: opts.serviceId,
            eventId: opts.eventId,
            parseNIT: opts.parseNIT,
            parseSDT: opts.parseSDT,
            parseEIT: opts.parseEIT
        });
        this._innerFilter = tsFilter;
        this._proxyEvents(tsFilter);

        // Replay buffered data
        tsFilter.write(buffered);
    }

    private _setupTLV(buffered: Buffer): void {
        const opts = this._options;

        let output: Writable;
        if (opts.disableDecoder) {
            output = opts.output;
        } else if (opts.tlvToTsDecoder) {
            this._decoder = new TSDecoder({
                output: opts.output,
                command: opts.tlvToTsDecoder
            });
            output = this._decoder;
        } else if (opts.tlvDecoder) {
            this._decoder = new TSDecoder({
                output: opts.output,
                command: opts.tlvDecoder
            });
            output = this._decoder;
        } else {
            output = opts.output;
        }

        const tlvFilter = new TLVFilter({
            output,
            networkId: opts.networkId,
            serviceId: opts.serviceId,
            eventId: opts.eventId,
            parseNIT: opts.parseNIT,
            parseSDT: opts.parseSDT,
            parseEIT: opts.parseEIT,
            channel: opts.channel.channel
        });
        this._innerFilter = tlvFilter;
        this._proxyEvents(tlvFilter);

        // Replay buffered data
        tlvFilter.write(buffered);
    }

    private _proxyEvents(filter: EventEmitter): void {
        const events = ["network", "services", "networkStreams", "epgReady"];
        for (const event of events) {
            filter.on(event, (...args: any[]) => this.emit(event, ...args));
        }
        filter.once("close", () => {
            if (!this._closed) {
                this.close();
            }
        });
        // Proxy streamInfo
        if ("streamInfo" in filter) {
            Object.defineProperty(this, "streamInfo", {
                get: () => (filter as any).streamInfo,
                configurable: true
            });
        }
    }

    /**
     * Detect stream format from buffered data.
     *
     * Primary: 3 consecutive TS sync at 188-byte intervals → ts
     * Primary: 3 chained TLV packets (0x7F + valid type + length) → tlv
     * Fallback: first recognizable sync byte
     * Default: ts
     */
    private _detectStreamFormat(buffer: Buffer): StreamFormat {
        // TSMF/TS check: 0x47 at 188-byte intervals
        for (let i = 0; i <= buffer.length - TS_PKT * 3; i++) {
            if (buffer[i] === TS_SYNC &&
                buffer[i + TS_PKT] === TS_SYNC &&
                buffer[i + TS_PKT * 2] === TS_SYNC) {
                // TODO: further check for TSMF (PID=0x2F) to distinguish tsmf-ts/tsmf-tlv
                return "ts";
            }
        }

        // TLV check: 3 consecutive valid TLV packets
        for (let i = 0; i <= buffer.length - 4; i++) {
            if (buffer[i] !== TLV_SYNC) {
                continue;
            }
            let offset = i;
            let valid = 0;
            while (valid < 3 && offset + 4 <= buffer.length) {
                if (buffer[offset] !== TLV_SYNC) {
                    break;
                }
                const tlvType = buffer[offset + 1];
                if (!TLV_VALID_TYPES.has(tlvType)) {
                    break;
                }
                const len = (buffer[offset + 2] << 8) | buffer[offset + 3];
                if (len > 65535 || offset + 4 + len > buffer.length) {
                    break;
                }
                offset += 4 + len;
                valid++;
            }
            if (valid >= 3) {
                return "tlv";
            }
        }

        // Fallback: first recognizable byte
        for (let i = 0; i < buffer.length; i++) {
            if (buffer[i] === TS_SYNC) {
                return "ts";
            }
            if (buffer[i] === TLV_SYNC) {
                return "tlv";
            }
        }

        return "ts";
    }
}
