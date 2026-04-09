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
import { StreamInfo, OutputFormat } from "./common";
import * as log from "./log";
import _ from "./_";
import TSFilter from "./TSFilter";
import TLVFilter from "./TLVFilter";
import TSDecoder from "./TSDecoder";
import TLVDecoder from "./TLVDecoder";
import TSMFFilter, { TsmfCCChecker, TSMFHeaderInfo } from "./TSMFFilter";
import { TSMFSlotFilter } from "./TSMFSlotFilter";
import ChannelItem from "./ChannelItem";

// Stream format detection constants
const TS_SYNC = 0x47;
const TS_PKT = 188;
const TLV_SYNC = 0x7f;
const TLV_VALID_TYPES = new Set([0x01, 0x02, 0x03, 0xfe, 0xff]);
// TSMF frames are 52 TS packets (9776 bytes). Need at least 1 full frame
// plus margin for sync alignment.
const DETECT_MIN_BYTES = 188 * 53 * 2; // ~20KB, guarantees 2 TSMF frames

// TSMF constants (must match TSMFDemuxer)
const TSMF_PID = 0x2f;
const TSMF_SYNC_A = 0x1a86;
const TSMF_SYNC_B = 0x0579;

export type StreamFormat = "ts" | "tlv" | "tsmf-ts" | "tsmf-tlv";

export interface DiscoveryResult {
    groupId: number;
    numberOfCarriers: number;
}

export interface StreamFilterOptions {
    readonly output?: Writable;
    readonly decoder?: string;         // TS→TS decoder (arib-b25-stream-test)
    readonly tlvToTsDecoder?: string;  // TLV→TS decoder (dantto4k)
    readonly tlvDecoder?: string;      // TLV→TLV decoder
    readonly disableDecoder?: boolean;
    readonly outputFormat?: OutputFormat;  // "ts" (default) or "tlv"
    readonly networkId?: number;
    readonly serviceId?: number;
    readonly eventId?: number;
    readonly parseNIT?: boolean;
    readonly parseSDT?: boolean;
    readonly parseEIT?: boolean;
    readonly tsmfRelTs?: number;
    readonly channel: ChannelItem;
    readonly tunerIndex?: number;      // needed for TSMF multi-carrier bonding
    readonly onFatal: (closing?: boolean) => void;
    readonly tsmfDiscovery?: boolean;   // deferred pipeline: detect groupId then branch
}

export default class StreamFilter extends EventEmitter {

    streamInfo: StreamInfo = {};

    private _closed = false;
    private _detected = false;
    private _format: StreamFormat | null = null;
    private _options: StreamFilterOptions;
    private _innerFilter: TSFilter | TLVFilter = null;
    private _decoder: TSDecoder | TLVDecoder = null;
    private _tsmfFilter: TSMFFilter = null;
    private _activePipeline: TSFilter | TLVFilter | Writable | { write(chunk: Buffer): void } = null;
    private _detectChunks: Buffer[] = [];
    private _detectLen = 0;

    // Multi-relTs auto-detect scan state (TSMF/TS one-pass scan)
    private _relStreams: Array<{
        relTs: number;
        slot: TSMFSlotFilter;
        ts: TSFilter;
        gotServices: boolean;
        gotNetwork: boolean;
        services: any[] | null;
    }> = [];
    private _aggregatedNetwork: any = null;
    private _emittedServices = false;
    private _aggregationTimer: NodeJS.Timeout | null = null;

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

    get isMultiCarrier(): boolean {
        return this._tsmfFilter?.hasCarriers ?? false;
    }

    write(chunk: Buffer): void {
        if (this._closed) {
            return;
        }

        if (this._activePipeline) {
            this._activePipeline.write(chunk);
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

        if (this._relStreams.length > 0) {
            if (this._aggregationTimer) {
                clearTimeout(this._aggregationTimer);
                this._aggregationTimer = null;
            }
            // Flush whatever we've collected so Tuner.getServices still
            // receives a services event before the close fires.
            if (!this._emittedServices) {
                this._emitMergedServices(true);
            }
            for (const e of this._relStreams) {
                e.ts.close();
            }
            this._relStreams = [];
        }

        if (this._innerFilter) {
            this._innerFilter.close();
        }
        if (this._tsmfFilter) {
            this._tsmfFilter.releaseCarriers();
            this._tsmfFilter.close();
            this._tsmfFilter = null;
        }

        this.emit("close");
        this.emit("end");
    }

    syncPriorities(newPriority: number): void {
        if (this._tsmfFilter) {
            this._tsmfFilter.syncPriorities(newPriority);
        }
    }

    /**
     * Release TSMF carrier links early (called while stream is still active)
     * so additional tuners can be freed at the same time as the primary,
     * before the full close sequence.
     */
    releaseTsmfCarriers(): void {
        if (this._tsmfFilter) {
            this._tsmfFilter.releaseCarriers();
        }
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
                this._initTlv(buffer);
                break;
            case "tsmf-ts":
                this._initTsmfTs(buffer);
                break;
            case "tsmf-tlv":
                this._initTsmfTlv(buffer);
                break;
            case "ts":
            default:
                this._initTs(buffer);
                break;
        }
    }

    private _selectTlvOutput(): Writable {
        const opts = this._options;
        if (opts.disableDecoder) {
            return opts.output;
        }
        if (opts.outputFormat === "tlv") {
            if (opts.tlvDecoder) {
                this._decoder = new TLVDecoder({
                    output: opts.output,
                    command: opts.tlvDecoder
                });
                return this._decoder;
            }
            return opts.output;
        }
        if (opts.tlvToTsDecoder) {
            this._decoder = new TLVDecoder({
                output: opts.output,
                command: opts.tlvToTsDecoder
            });
            return this._decoder;
        }
        if (opts.tlvDecoder) {
            this._decoder = new TLVDecoder({
                output: opts.output,
                command: opts.tlvDecoder
            });
            return this._decoder;
        }
        return opts.output;
    }

    private _initTs(buffered: Buffer): void {
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
        this._activePipeline = tsFilter;
        this._proxyEvents(tsFilter);

        tsFilter.write(buffered);
    }

    private _initTlv(buffered: Buffer): void {
        const opts = this._options;
        const output = this._selectTlvOutput();

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
        this._activePipeline = tlvFilter;
        this._proxyEvents(tlvFilter);

        tlvFilter.write(buffered);
    }

    /**
     * TSMF with TS multiplexing (BS/CS over CATV).
     * Uses TSMFSlotFilter to extract the target relative stream.
     */
    private _initTsmfTs(buffered: Buffer): void {
        const opts = this._options;

        // --- Resolve target relTs ---
        // 1. opts.tsmfRelTs: caller already knows which relTs to extract.
        // 2. else: run a slot-map probe to discover the active relative TSes.
        //    - parseSDT=false (streaming / EPG): pick the smallest active relTs.
        //    - parseSDT=true  (Tuner.getServices scan): leave undefined and
        //      fall through to the fan-out path below, which builds one
        //      TSFilter per active relTs and aggregates services.
        let targetRelTs: number | undefined = opts.tsmfRelTs;
        const activeStreams = new Set<number>();

        if (targetRelTs === undefined) {
            // The probe consumes the buffered bytes once and emits slotMap
            // synchronously (DETECT_MIN_BYTES guarantees ≥2 full TSMF frames).
            const probe = TSMFSlotFilter.createSlotMapProbe();
            let detectedGroupId: number | null = null;
            probe.on("slotMap", (slotMap: number[], groupId: number | null) => {
                for (const r of slotMap) {
                    if (r > 0) { activeStreams.add(r); }
                }
                if (groupId !== null && detectedGroupId === null) {
                    detectedGroupId = groupId;
                }
            }); // streamTypeBits emitted as 3rd arg, unused on the TS path
            probe.write(buffered);

            if (activeStreams.size === 0) {
                log.warn("StreamFilter TSMF slotMap probe failed on %s — closing", opts.channel.channel);
                this.close();
                return;
            }

            if (detectedGroupId !== null) {
                opts.channel.setTsmfGroupId(detectedGroupId);
            }

            if (!opts.parseSDT) {
                // Streaming / EPG: deterministically pick the smallest active
                // relTs from the parsed slot map. The TSMF header already
                // enumerates which relative TSes exist in the multiplex, so
                // there is nothing to "guess" — any non-zero entry is a valid
                // target and we just need a stable tie-breaker.
                targetRelTs = Math.min(...activeStreams);
                log.info("StreamFilter TSMF auto-detect (stream) on %s: active relTs=[%s], picking relTs=%d",
                    opts.channel.channel,
                    [...activeStreams].sort((a, b) => a - b).join(","),
                    targetRelTs);
            } else {
                log.info("StreamFilter TSMF auto-detect (scan) started: %d relTs groupId=%s on %s",
                    activeStreams.size,
                    detectedGroupId !== null ? String(detectedGroupId) : "none",
                    opts.channel.channel);
            }
        }

        // --- Single-relTs pipeline ---
        // Hit by both the explicit opts.tsmfRelTs path and the streaming
        // auto-detect fallback above.
        if (targetRelTs !== undefined) {
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

            const passHeader = !opts.serviceId;
            tsFilter.setSlotFilter(new TSMFSlotFilter(targetRelTs, passHeader));

            this._innerFilter = tsFilter;
            this._activePipeline = tsFilter;
            this._proxyEvents(tsFilter);

            tsFilter.write(buffered);
            return;
        }

        // --- Scanning path: discover services from every active relTs in parallel ---
        // The previous detector fed a single downstream TSFilter with interleaved
        // PAT/SDT/NIT from every relTs, which corrupted the parser. Instead we:
        //   1. Build one TSMFSlotFilter + TSFilter pair per active relTs.
        //   2. Replay buffered bytes into each. Each TSFilter sees a clean
        //      single-TS feed.
        //   3. Aggregate their `network` / `services` events and emit once.
        // Each per-relTs TSFilter is created with output=undefined; with no
        // output set TSFilter forces _ready=false and _processPackets drops
        // every packet before reaching the output buffer, so we don't need
        // a sink at all.
        for (const relTs of activeStreams) {
            const slot = new TSMFSlotFilter(relTs, false);
            const perTs = new TSFilter({
                networkId: opts.networkId,
                serviceId: opts.serviceId,
                eventId: opts.eventId,
                parseNIT: opts.parseNIT,
                parseSDT: opts.parseSDT,
                parseEIT: opts.parseEIT
            });
            perTs.setSlotFilter(slot);

            const entry = {
                relTs,
                slot,
                ts: perTs,
                gotServices: false,
                gotNetwork: false,
                services: null as any[] | null
            };

            perTs.on("network", (net: any) => {
                if (entry.gotNetwork) { return; }
                entry.gotNetwork = true;
                if (this._aggregatedNetwork === null) {
                    this._aggregatedNetwork = net;
                    this.emit("network", net);
                }
            });

            perTs.on("services", (svs: any[]) => {
                if (entry.gotServices) { return; }
                entry.gotServices = true;
                entry.services = svs;
                if (this._relStreams.every(e => e.gotServices)) {
                    this._emitMergedServices(false);
                }
            });

            this._relStreams.push(entry);
        }

        // Replay buffered bytes into every per-relTs TSFilter so each one
        // starts parsing from the same initial TSMF frame.
        for (const e of this._relStreams) {
            e.ts.write(buffered);
        }

        // Dispatcher: fan out subsequent writes to every per-relTs TSFilter.
        this._activePipeline = {
            write: (chunk: Buffer) => {
                for (const e of this._relStreams) {
                    if (!e.ts.closed) { e.ts.write(chunk); }
                }
            }
        };

        // Aggregation timeout: stay well under Tuner.getServices' 20s cap.
        // If at least one relTs has delivered services by now, emit partial.
        this._aggregationTimer = setTimeout(() => {
            this._emitMergedServices(true);
        }, 15000);

        // Proxy streamInfo from the first relTs TSFilter (used for UI display).
        Object.defineProperty(this, "streamInfo", {
            get: () => this._relStreams[0]?.ts.streamInfo ?? {},
            configurable: true
        });
    }

    /**
     * Merge services collected from each per-relTs TSFilter, persist the
     * serviceId→relTs mapping, and emit the aggregated "services" event.
     * Called when every relTs has delivered services, on the aggregation
     * timeout, or from close() if the session is torn down prematurely.
     */
    private _emitMergedServices(partial: boolean): void {
        if (this._emittedServices) { return; }
        this._emittedServices = true;
        if (this._aggregationTimer) {
            clearTimeout(this._aggregationTimer);
            this._aggregationTimer = null;
        }

        const seen = new Set<string>();
        const merged: any[] = [];
        for (const e of this._relStreams) {
            if (!e.services) { continue; }
            for (const svc of e.services) {
                const key = `${svc.networkId}:${svc.serviceId}`;
                if (seen.has(key)) { continue; }
                seen.add(key);
                merged.push(svc);
                // fromConfig locks are honoured inside addTsmfRelTsMapping.
                this._options.channel.addTsmfRelTsMapping(svc.serviceId, e.relTs);
            }
        }

        const gotCount = this._relStreams.filter(e => e.gotServices).length;
        if (partial) {
            log.info("StreamFilter TSMF auto-detect partial emit: %d/%d relTs, %d services on %s",
                gotCount, this._relStreams.length, merged.length, this._options.channel.channel);
        } else {
            log.info("StreamFilter TSMF auto-detect emit: %d relTs, %d services on %s",
                this._relStreams.length, merged.length, this._options.channel.channel);
        }

        if (_.service) {
            _.service.save();
        }
        this.emit("services", merged);
    }

    /**
     * TSMF with TLV multiplexing (BS4K over CATV).
     * Uses TSMFFilter/TSMFDemuxer to extract TLV, then feeds to TLVFilter.
     *
     * Two modes:
     * - default: full synchronous pipeline. setupCarriers() is called immediately
     *   to begin multi-carrier bonding. Used by stream delivery, EPG, update scans,
     *   and bonded scans.
     * - tsmfDiscovery=true: waits for groupId event from TSMF header, then branches:
     *   - numberOfCarriers==1: builds TLV pipeline (single-carrier, same session)
     *   - numberOfCarriers>1: emits "discovery" event (caller queues bonded scan)
     *   Used only by initial channel scan (getServices).
     */
    private _initTsmfTlv(buffered: Buffer): void {
        const opts = this._options;
        const ch = opts.channel;

        // Resolve target relTs in the same priority order as _initTsmfTs:
        //   1. URL query (?tsmfRelTs=)
        //   2. per-service mapping for opts.serviceId
        //   3. per-channel default (ch.tsmfRelTs)
        // For first-ever scans nothing is known yet, so fall back to a slot-map
        // probe. The TSMF header's streamTypeBits flags each relative TS as
        // TLV (bit=0) or TS/unused (bit=1) — we just pick the smallest TLV
        // relTs that actually appears in the slot map. The picked value is
        // persisted via channel.setTsmfRelTs() in `_attachTlvOutputPipeline`,
        // so subsequent sessions skip the probe.
        let targetRelTs = opts.tsmfRelTs
            ?? (opts.serviceId ? ch.getTsmfRelTs(opts.serviceId) : undefined)
            ?? ch.tsmfRelTs;

        if (targetRelTs === undefined || targetRelTs === null) {
            const probe = TSMFSlotFilter.createSlotMapProbe();
            let pickedRelTs = 0;
            probe.on("slotMap", (slotMap: number[], _groupId: number | null, streamTypeBits: number) => {
                if (pickedRelTs !== 0) { return; }
                const seen = new Set<number>();
                for (const v of slotMap) {
                    if (v >= 1 && v <= 15) { seen.add(v); }
                }
                for (let n = 1; n <= 15; n++) {
                    if (seen.has(n) && TSMFFilter.isTLVStream(streamTypeBits, n)) {
                        pickedRelTs = n;
                        break;
                    }
                }
            });
            probe.write(buffered);
            if (pickedRelTs > 0) {
                targetRelTs = pickedRelTs;
            }
        }

        if (targetRelTs === undefined || targetRelTs === null) {
            log.warn("StreamFilter TSMF-TLV probe failed on %s — no TLV slot found, closing",
                ch.channel);
            this.close();
            return;
        }

        log.info(
            "StreamFilter TSMF-TLV %s (tsmfRelTs=%d, groupId=%s)",
            opts.tsmfDiscovery ? "discovery" : "bonded scan",
            targetRelTs,
            ch.tsmfGroupId ?? "none"
        );

        this._tsmfFilter = new TSMFFilter(opts.tunerIndex ?? 0, {
            tsmfRelTs: targetRelTs,
            groupId: ch.tsmfGroupId ?? undefined
        }, opts.onFatal);

        const primaryInput = this._tsmfFilter.createInput();
        this._activePipeline = primaryInput;

        if (opts.tsmfDiscovery) {
            // Wait for groupId before deciding: single-carrier builds the pipeline,
            // multi-carrier bails and lets the caller retry with a bonded scan.
            this._tsmfFilter.once("groupId", (groupId: number, numberOfCarriers: number) => {
                if (this._closed) {
                    return;
                }
                ch.setTsmfGroupId(groupId);
                log.info("StreamFilter TSMF-TLV discovery: groupId=%d numberOfCarriers=%d on %s",
                    groupId, numberOfCarriers, ch.channel);
                if (_.service) {
                    _.service.save();
                }

                if (numberOfCarriers > 1) {
                    const discovery: DiscoveryResult = { groupId, numberOfCarriers };
                    this.emit("discovery", discovery);
                } else {
                    // Single-carrier: primary input alone is sufficient
                    this._attachTlvOutputPipeline();
                }
            });
        } else {
            this._attachTlvOutputPipeline();
            this._tsmfFilter.setupCarriers(ch);
        }

        primaryInput.write(buffered);
    }

    /**
     * Build the TLV output pipeline on top of the existing TSMFFilter.
     * Creates TLVFilter and wires the TSMF "ready" event to pass demuxed TLV
     * data through a PassThrough into TLVFilter.
     */
    private _attachTlvOutputPipeline(): void {
        const opts = this._options;
        const ch = opts.channel;
        const output = this._selectTlvOutput();
        const passThrough = new stream.PassThrough();

        this._tsmfFilter.once("ready", () => {
            const detectedRelTs = this._tsmfFilter.detectedRelTs;
            const detectedGroupId = this._tsmfFilter.detectedGroupId;
            if (detectedRelTs !== null) {
                ch.setTsmfRelTs(detectedRelTs);
            }
            if (detectedGroupId !== null) {
                ch.setTsmfGroupId(detectedGroupId);
            }
            log.debug("StreamFilter TSMF ready, creating TLVFilter");
            this._tsmfFilter.setOutput(passThrough);
        });

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

        passThrough.on("data", (chunk: Buffer) => {
            if (!this._closed) {
                tlvFilter.write(chunk);
            }
        });
    }

    private _proxyEvents(filter: EventEmitter): void {
        const events = ["network", "services", "networkStreams", "epgReady", "carrierBonding"];
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
     * Order: TS/TSMF first, then TLV. TS detection uses a strict threshold
     * (TS_MIN_CONSECUTIVE 0x47 bytes at 188-byte intervals) so that TLV payloads
     * containing coincidental 0x47 patterns do not falsely match TS. Pure TLV
     * streams contain null packets (0x7F 0xFF ...) and valid type packets that
     * chain correctly; TLV detection accepts those as confirmation.
     *
     * 1. Check for TS sync pattern (TS_MIN_CONSECUTIVE consecutive 0x47)
     *    - If found → check TSMF → tsmf-tlv / tsmf-ts / ts
     * 2. Check for TLV: chained TLV packets (0x7F + valid type + length)
     * 3. Default: ts
     */
    private _detectStreamFormat(buffer: Buffer): StreamFormat {
        // TS sync: require TS_MIN_CONSECUTIVE (8) consecutive 0x47 at 188 intervals.
        // 3 was too lax — TLV payloads frequently hit by chance.
        // 8 consecutive on random data: (1/256)^7 ≈ 2e-17 per position, effectively 0.
        const TS_MIN_CONSECUTIVE = 8;
        let tsStart = -1;
        const tsScanEnd = buffer.length - TS_PKT * TS_MIN_CONSECUTIVE;
        for (let i = 0; i <= tsScanEnd; i++) {
            if (buffer[i] !== TS_SYNC) {
                continue;
            }
            let ok = true;
            for (let k = 1; k < TS_MIN_CONSECUTIVE; k++) {
                if (buffer[i + TS_PKT * k] !== TS_SYNC) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                tsStart = i;
                break;
            }
        }

        if (tsStart >= 0) {
            // Find a CC-synced TSMF Extended frame header. After retune, the
            // first TSMF frames may be stale DVR buffer data from the previous
            // channel, so we require two consecutive CCs before trusting one.
            const ccChecker = new TsmfCCChecker();

            for (let offset = tsStart; offset + TS_PKT <= buffer.length; offset += TS_PKT) {
                if (buffer[offset] !== TS_SYNC) {
                    break;
                }
                const pid = ((buffer[offset + 1] & 0x1f) << 8) | buffer[offset + 2];
                if (pid !== TSMF_PID) {
                    continue;
                }
                const sync = ((buffer[offset + 4] << 8) | buffer[offset + 5]) & 0x1fff;
                if (sync !== TSMF_SYNC_A && sync !== TSMF_SYNC_B) {
                    continue;
                }
                if (!ccChecker.check(buffer[offset + 3] & 0x0f)) {
                    continue;
                }

                // CC-synced TSMF packet — parse the full extended header for
                // deterministic TLV/TS routing using stream_type[i].
                const packet = buffer.subarray(offset, offset + TS_PKT);
                const info = TSMFFilter.parseTSMFHeader(packet);
                if (!info) {
                    continue;
                }
                return this._routeTsmfFormat(info);
            }

            // TS sync found but no TSMF — plain TS
            return "ts";
        }

        // No TS pattern — try TLV detection.
        // Scan for 0x7F + valid type (incl. 0xFF null packet) with a successful chain
        // to the next TLV header, or a length that extends past the buffer end.
        for (let i = 0; i <= buffer.length - 4; i++) {
            if (buffer[i] !== TLV_SYNC) {
                continue;
            }
            const tlvType = buffer[i + 1];
            if (!TLV_VALID_TYPES.has(tlvType)) {
                continue;
            }
            const len = (buffer[i + 2] << 8) | buffer[i + 3];
            const next = i + 4 + len;
            if (next + 4 > buffer.length) {
                if (len > 0) {
                    return "tlv";
                }
                continue;
            }
            if (buffer[next] === TLV_SYNC && TLV_VALID_TYPES.has(buffer[next + 1])) {
                return "tlv";
            }
        }

        return "ts";
    }

    /**
     * Decide whether a TSMF multiplex should route through the TLV pipeline
     * or the TS pipeline, based on the `stream_type` bits in the TSMF header
     * (ARIB STD-B32 6.3.4.2).
     *
     * If the caller has already pinned a target relative TS (via URL query,
     * per-service mapping, or channel default), we honour their choice and
     * route by that relTs's stream_type. Otherwise we route to TLV iff any
     * active relTs in the multiplex carries TLV — the TLV pipeline can
     * handle the (currently theoretical) mixed multiplex by routing per
     * service inside `_initTsmfTlv`.
     */
    private _routeTsmfFormat(info: TSMFHeaderInfo): StreamFormat {
        const opts = this._options;
        const ch = opts.channel;
        const target = opts.tsmfRelTs
            ?? (opts.serviceId ? ch.getTsmfRelTs(opts.serviceId) : undefined)
            ?? ch.tsmfRelTs;

        let isTLV: boolean;
        if (target) {
            isTLV = TSMFFilter.isTLVStream(info.streamTypeBits, target);
        } else {
            isTLV = false;
            for (const r of info.slotMap) {
                if (r >= 1 && r <= 15 && TSMFFilter.isTLVStream(info.streamTypeBits, r)) {
                    isTLV = true;
                    break;
                }
            }
        }

        log.debug(
            "StreamFilter TSMF route: relTs=%s → %s (slotMap counts %j, streamTypeBits=0x%s)",
            target ?? "auto", isTLV ? "tsmf-tlv" : "tsmf-ts",
            countSlots(info.slotMap), info.streamTypeBits.toString(16)
        );
        return isTLV ? "tsmf-tlv" : "tsmf-ts";
    }
}

/** Aggregate slot counts per relative stream for diagnostic logging. */
function countSlots(slotMap: number[]): Record<number, number> {
    const counts: Record<number, number> = {};
    for (const v of slotMap) {
        if (v >= 1 && v <= 15) {
            counts[v] = (counts[v] || 0) + 1;
        }
    }
    return counts;
}
