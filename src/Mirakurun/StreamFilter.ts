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
import * as stream from "stream";
import { Writable } from "stream";
import EventEmitter = require("eventemitter3");
import { StreamInfo } from "./common";
import * as log from "./log";
import _ from "./_";
import TSFilter from "./TSFilter";
import TLVFilter from "./TLVFilter";
import TSDecoder from "./TSDecoder";
import TSMFFilter from "./TSMFFilter";
import { TSMFSlotFilter } from "./TSMFDemuxer";
import ChannelItem from "./ChannelItem";

// Stream format detection constants
const TS_SYNC = 0x47;
const TS_PKT = 188;
const TLV_SYNC = 0x7f;
const TLV_VALID_TYPES = new Set([0x01, 0x02, 0x03, 0xfe]);
const DETECT_MIN_BYTES = 8192;

// TSMF constants (must match TSMFDemuxer)
const TSMF_PID = 0x2f;
const TSMF_SYNC_A = 0x1a86;
const TSMF_SYNC_B = 0x0579;

export type StreamFormat = "ts" | "tlv" | "tsmf-ts" | "tsmf-tlv";

export interface StreamFilterOptions {
    readonly output?: Writable;
    readonly decoder?: string;         // TS→TS decoder (arib-b25-stream-test)
    readonly tlvToTsDecoder?: string;  // TLV→TS decoder (dantto4k)
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
    readonly onFatal?: (closing?: boolean) => void;
}

export default class StreamFilter extends EventEmitter {

    streamInfo: StreamInfo = {};

    private _closed = false;
    private _detected = false;
    private _format: StreamFormat | null = null;
    private _options: StreamFilterOptions;
    private _innerFilter: TSFilter | TLVFilter = null;
    private _decoder: TSDecoder = null;
    private _tsmfFilter: TSMFFilter = null;
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

    get tsmfFilter(): TSMFFilter | null {
        return this._tsmfFilter;
    }

    get isCarrierOnly(): boolean {
        return false; // carrier mode is handled separately in TunerDevice
    }

    get isMultiCarrier(): boolean {
        return this._tsmfFilter?.hasCarriers ?? false;
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
        if (this._tsmfFilter) {
            this._tsmfFilter.releaseCarriers();
            try { this._tsmfFilter.close(); } catch (e) { /* ignore */ }
        }

        this.emit("close");
        this.emit("end");
    }

    syncPriorities(newPriority: number): void {
        if (this._tsmfFilter) {
            this._tsmfFilter.syncPriorities(newPriority);
        }
    }

    cleanup(): void {
        if (this._tsmfFilter) {
            this._tsmfFilter.releaseCarriers();
        }
    }

    forceKillDecoder(): void {
        if (this._decoder) {
            // TSDecoder handles its own cleanup
        }
        if (this._tsmfFilter) {
            this._tsmfFilter.releaseCarriers();
            try { this._tsmfFilter.close(); } catch (e) { /* ignore */ }
            this._tsmfFilter = null;
        }
        this._closed = true;
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
            case "tsmf-ts":
                this._setupTSMF_TS(buffer);
                break;
            case "tsmf-tlv":
                this._setupTSMF_TLV(buffer);
                break;
            case "ts":
            default:
                this._setupTS(buffer);
                break;
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

        tlvFilter.write(buffered);
    }

    /**
     * TSMF with TS multiplexing (BS/CS over CATV).
     * Uses TSMFSlotFilter to extract the target relative stream.
     */
    private _setupTSMF_TS(buffered: Buffer): void {
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

        const tsmfRelTs = opts.tsmfRelTs;
        if (tsmfRelTs) {
            const passHeader = !opts.serviceId;
            tsFilter.setSlotFilter(new TSMFSlotFilter(tsmfRelTs, passHeader));
        } else {
            // Auto-detect TSMF mapping
            const detector = TSMFSlotFilter.createDetector();
            detector.once("detected", (mapping: Map<number, Set<number>>) => {
                for (const [relTs, serviceIds] of mapping) {
                    for (const sid of serviceIds) {
                        opts.channel.addTsmfRelTsMapping(sid, relTs);
                    }
                }
                if (detector.groupId !== null) {
                    opts.channel.setTsmfGroupId(detector.groupId);
                }
                log.info("StreamFilter TSMF auto-detected %d streams groupId=%s on %s",
                    mapping.size,
                    detector.groupId !== null ? String(detector.groupId) : "none",
                    opts.channel.channel);

                // Always select a stream after detection to prevent NIT/SDT interleaving
                if (mapping.size >= 1) {
                    const targetRelTs = opts.serviceId
                        ? opts.channel.getTsmfRelTs(opts.serviceId)
                        : undefined;
                    if (targetRelTs) {
                        detector.selectStream(targetRelTs);
                    } else {
                        const firstRelTs = Math.min(...mapping.keys());
                        detector.selectStream(firstRelTs);
                    }
                }

                _.service.save();
            });
            tsFilter.setSlotFilter(detector);
        }

        this._innerFilter = tsFilter;
        this._proxyEvents(tsFilter);

        tsFilter.write(buffered);
    }

    /**
     * TSMF with TLV multiplexing (BS4K over CATV).
     * Uses TSMFFilter/TSMFDemuxer to extract TLV, then feeds to TLVFilter.
     */
    private _setupTSMF_TLV(buffered: Buffer): void {
        const opts = this._options;
        const ch = opts.channel;
        const onFatal = opts.onFatal || (() => {});

        const hasGroup = ch.tsmfGroupId !== null && ch.tsmfGroupId !== undefined;
        log.info(
            "StreamFilter TSMF-TLV %s (tsmfRelTs=%d%s)",
            hasGroup ? "multi-carrier mode" : "single-carrier mode",
            ch.tsmfRelTs,
            hasGroup ? `, groupId=${ch.tsmfGroupId}` : ""
        );

        // Create TLV output pipeline
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

        // TSMFFilter wraps TSMFDemuxer for carrier management
        this._tsmfFilter = new TSMFFilter(0, {
            tsmfRelTs: ch.tsmfRelTs,
            groupId: ch.tsmfGroupId ?? undefined
        }, onFatal);

        const primaryInput = this._tsmfFilter.createInput();
        this._tsmfFilter.setupCarriers(ch);

        // When TSMF is ready, create TLVFilter for the extracted TLV stream
        const outputPassThrough = new stream.PassThrough();

        this._tsmfFilter.once("ready", () => {
            // Store auto-detected TSMF info on channel
            const detectedRelTs = this._tsmfFilter.detectedRelTs;
            const detectedGroupId = this._tsmfFilter.detectedGroupId;
            if (detectedRelTs !== null) {
                ch.setTsmfRelTs(detectedRelTs);
            }
            if (detectedGroupId !== null) {
                ch.setTsmfGroupId(detectedGroupId);
            }

            log.debug("StreamFilter TSMF ready, creating TLVFilter");
            this._tsmfFilter.setOutput(outputPassThrough);
        });

        // Create TLVFilter that reads from the TSMF-extracted TLV stream
        const tlvFilter = new TLVFilter({
            output,
            networkId: opts.networkId,
            serviceId: opts.serviceId,
            eventId: opts.eventId,
            parseNIT: opts.parseNIT,
            parseSDT: opts.parseSDT,
            parseEIT: opts.parseEIT,
            channel: ch.channel
        });
        this._innerFilter = tlvFilter;
        this._proxyEvents(tlvFilter);

        // Connect: outputPassThrough → TLVFilter
        outputPassThrough.on("data", (chunk: Buffer) => {
            if (!this._closed) {
                tlvFilter.write(chunk);
            }
        });

        // Pipe buffered data into TSMF primary input, then continue piping
        // Note: caller (TunerDevice._streamOnData) will call write() for subsequent data
        // which goes to this._innerFilter. But for TSMF-TLV, we need raw TSMF data
        // to go to the TSMFFilter, not to TLVFilter directly.
        // Override write() behavior for TSMF-TLV mode:
        this._detected = true; // prevent further detection
        primaryInput.write(buffered);

        // Override write to pipe to TSMF primary input instead of inner filter
        this.write = (chunk: Buffer) => {
            if (this._closed) {
                return;
            }
            primaryInput.write(chunk);
        };
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
        const inner = filter as TSFilter | TLVFilter;
        Object.defineProperty(this, "streamInfo", {
            get: () => inner.streamInfo,
            configurable: true
        });
    }

    /**
     * Detect stream format from buffered data.
     *
     * 1. Check for TSMF: 0x47 at 188-byte intervals with PID=0x2F and TSMF sync
     *    - stream_type bit=0 → tsmf-tlv, bit=1 → tsmf-ts
     * 2. Check for plain TS: 0x47 at 188-byte intervals (no TSMF)
     * 3. Check for TLV: 3 chained TLV packets (0x7F + valid type + length)
     * 4. Fallback: first recognizable sync byte
     * 5. Default: ts
     */
    private _detectStreamFormat(buffer: Buffer): StreamFormat {
        // Find 3 consecutive TS sync bytes at 188-byte intervals
        let tsStart = -1;
        for (let i = 0; i <= buffer.length - TS_PKT * 3; i++) {
            if (buffer[i] === TS_SYNC &&
                buffer[i + TS_PKT] === TS_SYNC &&
                buffer[i + TS_PKT * 2] === TS_SYNC) {
                tsStart = i;
                break;
            }
        }

        if (tsStart >= 0) {
            // Check if any packet is TSMF header (PID=0x2F with TSMF sync pattern)
            for (let offset = tsStart; offset + TS_PKT <= buffer.length; offset += TS_PKT) {
                if (buffer[offset] !== TS_SYNC) {
                    break;
                }
                const pid = ((buffer[offset + 1] & 0x1f) << 8) | buffer[offset + 2];
                if (pid !== TSMF_PID) {
                    continue;
                }
                // Check TSMF sync pattern in payload
                const sync = ((buffer[offset + 4] << 8) | buffer[offset + 5]) & 0x1fff;
                if (sync !== TSMF_SYNC_A && sync !== TSMF_SYNC_B) {
                    continue;
                }
                // TSMF detected — check stream_type bits to determine TS or TLV
                const streamTypeBits = (buffer[offset + 121] << 7) | (buffer[offset + 122] >> 1);
                // If any stream has type=0 (TLV), it's tsmf-tlv
                if (streamTypeBits !== 0x7fff) {
                    return "tsmf-tlv";
                }
                return "tsmf-ts";
            }

            // No TSMF header found — plain TS
            return "ts";
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
