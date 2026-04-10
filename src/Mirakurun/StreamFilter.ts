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
import TSMFFilter, { TSMFHeaderInfo } from "./TSMFFilter";
import { TSMFSlotFilter, TSMFCarrierBonding } from "./TSMF";
import ChannelItem from "./ChannelItem";

// Stream format detection constants
const TS_SYNC = 0x47;
const TS_PKT = 188;
const TLV_SYNC = 0x7f;
const TLV_VALID_TYPES = new Set([0x01, 0x02, 0x03, 0xfe, 0xff]);
// TSMF frames are 52 TS packets (9776 bytes). Need at least 1 full frame
// plus margin for sync alignment.
const DETECT_MIN_BYTES = 188 * 53 * 2; // ~20KB, guarantees 2 TSMF frames

/**
 * Top-level stream format. TSMF is conceptually a sub-classification of TS
 * (it's a TS-aligned multiplex transport), so it does not appear here — its
 * presence is encoded by the `tsmfHeader` field on `DetectionResult` instead.
 */
export type StreamFormat = "ts" | "tlv";

export interface DiscoveryResult {
    groupId: number;
    numberOfCarriers: number;
}

interface DetectionResult {
    format: StreamFormat;
    /**
     * Parsed TSMF Extended frame header. Present only on TS-family streams
     * that carry a TSMF wrapper (`format === "ts"` and `tsmfHeader !== undefined`).
     */
    tsmfHeader?: TSMFHeaderInfo;
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
    readonly tsmfDiscovery?: boolean;   // deferred pipeline: detect groupId then branch
}

export default class StreamFilter extends EventEmitter {

    streamInfo: StreamInfo = {};

    private _closed = false;
    private _detected = false;
    private _format: StreamFormat | null = null;
    private _options: StreamFilterOptions;
    private _innerFilter: TSFilter | TLVFilter = null;
    private _tsmfFilter: TSMFFilter = null;
    private _tsmfBonding: TSMFCarrierBonding = null;
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
        return this._tsmfBonding?.hasCarriers ?? false;
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
        if (this._tsmfBonding) {
            this._tsmfBonding.releaseCarriers();
            this._tsmfBonding = null;
        }
        if (this._tsmfFilter) {
            this._tsmfFilter.close();
            this._tsmfFilter = null;
        }

        this.emit("close");
        this.emit("end");
    }

    syncPriorities(newPriority: number): void {
        this._tsmfBonding?.syncPriorities(newPriority);
    }

    /**
     * Release TSMF carrier links early (called while stream is still active)
     * so additional tuners can be freed at the same time as the primary,
     * before the full close sequence.
     */
    releaseTsmfCarriers(): void {
        this._tsmfBonding?.releaseCarriers();
    }

    // --- Private ---

    /**
     * Once enough bytes are buffered, classify the stream as TLV or TS-family
     * and dispatch to the appropriate init path.
     *
     * Top-level fork: **TLV vs TS-family**.
     *   - TLV     → `_initTlv` (rare; pure TLV with no transport wrapper)
     *   - TS-family → second fork on whether a TSMF Extended header is present:
     *       - no TSMF header → `_initTs`   (plain TS)
     *       - TSMF header    → `_initTsmf` (TSMF→TS / TSMF→TLV / TSMF→TS scan,
     *                                       routed inside `_initTsmf`)
     */
    private _detect(): void {
        if (this._detected) {
            return;
        }
        this._detected = true;

        const buffer = Buffer.concat(this._detectChunks);
        this._detectChunks = [];

        const result = this._detectStreamFormat(buffer);
        this._format = result.format;
        log.debug("StreamFilter: detected format: %s%s (%d bytes inspected)",
            this._format,
            result.tsmfHeader ? " (TSMF)" : "",
            buffer.length);

        // Step 1: TLV vs TS-family.
        if (result.format === "tlv") {
            this._initTlv(buffer);
            return;
        }

        // Step 2: within TS-family, plain TS or TSMF wrapper.
        if (result.tsmfHeader) {
            this._initTsmf(buffer, result.tsmfHeader);
        } else {
            this._initTs(buffer);
        }
    }

    /**
     * Build a TSFilter wired to the appropriate output sink (raw or via TSDecoder).
     * Returns an upstream-shape TSFilter — TSMF slot filtering, when needed,
     * is wired as a pre-stage by the caller (see `_initTs`).
     */
    private _createTsFilter(): TSFilter {
        const opts = this._options;
        let output: Writable;
        if (opts.disableDecoder || !opts.decoder) {
            output = opts.output;
        } else {
            output = new TSDecoder({
                output: opts.output,
                command: opts.decoder
            });
        }
        return new TSFilter({
            output,
            networkId: opts.networkId,
            serviceId: opts.serviceId,
            eventId: opts.eventId,
            parseNIT: opts.parseNIT,
            parseSDT: opts.parseSDT,
            parseEIT: opts.parseEIT
        });
    }

    /**
     * Build a TLVFilter wired to the appropriate output sink. Decoder selection
     * (TLV→TS, TLV→TLV, or pass-through) is delegated to TLVDecoder.create.
     */
    private _createTlvFilter(): TLVFilter {
        const opts = this._options;
        return new TLVFilter({
            output: TLVDecoder.create({
                output: opts.output,
                outputFormat: opts.outputFormat,
                tlvDecoder: opts.tlvDecoder,
                tlvToTsDecoder: opts.tlvToTsDecoder,
                disableDecoder: opts.disableDecoder
            }),
            networkId: opts.networkId,
            serviceId: opts.serviceId,
            eventId: opts.eventId,
            parseNIT: opts.parseNIT,
            parseSDT: opts.parseSDT,
            parseEIT: opts.parseEIT,
            channel: opts.channel.channel
        });
    }

    /**
     * TS pipeline. If `slot` is provided (TSMF→TS single-relTs case), the
     * TSMFSlotFilter is piped as a pre-stage in front of TSFilter so the
     * TSFilter itself stays at upstream parity.
     */
    private _initTs(buffered: Buffer, slot?: TSMFSlotFilter): void {
        const tsFilter = this._createTsFilter();
        this._innerFilter = tsFilter;
        this._proxyEvents(tsFilter);

        if (slot) {
            slot.on("data", (chunk: Buffer) => tsFilter.write(chunk));
            this._activePipeline = slot;
            slot.write(buffered);
        } else {
            this._activePipeline = tsFilter;
            tsFilter.write(buffered);
        }
    }

    private _initTlv(buffered: Buffer): void {
        const tlvFilter = this._createTlvFilter();
        this._innerFilter = tlvFilter;
        this._activePipeline = tlvFilter;
        this._proxyEvents(tlvFilter);
        tlvFilter.write(buffered);
    }

    /**
     * TSMF transport entry point. Delegates the routing decision to
     * `TSMFFilter.resolveRoute` (using the header parsed during format
     * detection) and dispatches to one of:
     *   - `_initTs(buf, slot)`        — TSMF→TS single-relTs (streaming/EPG)
     *   - `_initTsmfTlv(buf, relTs)`  — TSMF→TLV (single-carrier or bonded)
     *   - `_initTsmfTsScan(buf, set)` — TSMF→TS multi-relTs scan fan-out
     */
    private _initTsmf(buffered: Buffer, header: TSMFHeaderInfo): void {
        const opts = this._options;
        const ch = opts.channel;

        // Persist groupId early so subsequent sessions reach the bonded scan
        // flow without re-probing. groupId 0 / 255 = unset.
        if (header.groupId !== 0 && header.groupId !== 255) {
            ch.setTsmfGroupId(header.groupId);
        }

        const requestedRelTs = opts.tsmfRelTs
            ?? (opts.serviceId ? ch.getTsmfRelTs(opts.serviceId) : undefined)
            ?? ch.tsmfRelTs ?? undefined;

        const decision = TSMFFilter.resolveRoute(header, requestedRelTs, !!opts.parseSDT);

        switch (decision.kind) {
            case "empty":
                log.warn("StreamFilter TSMF slot map empty on %s — closing", ch.channel);
                this.close();
                return;

            case "tsmf-tlv":
                log.info("StreamFilter TSMF route: %s relTs=%d → tsmf-tlv on %s",
                    decision.pinned ? "pinned" : "auto", decision.relTs, ch.channel);
                this._initTsmfTlv(buffered, decision.relTs);
                return;

            case "tsmf-ts":
                log.info("StreamFilter TSMF route: %s relTs=%d → tsmf-ts on %s (active=[%s])",
                    decision.pinned ? "pinned" : "auto",
                    decision.relTs,
                    ch.channel,
                    [...decision.activeStreams].sort((a, b) => a - b).join(","));
                this._initTs(buffered, new TSMFSlotFilter(decision.relTs, !opts.serviceId));
                return;

            case "tsmf-ts-scan":
                log.info("StreamFilter TSMF auto-detect (scan) started: %d relTs groupId=%s on %s",
                    decision.activeStreams.size,
                    header.groupId !== 0 && header.groupId !== 255 ? String(header.groupId) : "none",
                    ch.channel);
                this._initTsmfTsScan(buffered, decision.activeStreams);
                return;
        }
    }

    /**
     * TSMF→TS multi-relTs scan pipeline. Builds one TSMFSlotFilter+TSFilter
     * pair per active relTs, fans out incoming bytes to all of them, and
     * aggregates per-stream `services` events into a single emit.
     *
     * Used only by Tuner.getServices() (parseSDT=true) on pure-TS multiplexes
     * where we need to discover services across every relative TS.
     *
     * The previous detector fed a single downstream TSFilter with interleaved
     * PAT/SDT/NIT from every relTs, which corrupted the parser. Each per-relTs
     * TSFilter sees a clean single-TS feed instead. They are created without
     * an output sink — TSFilter then forces _ready=false and drops every
     * payload packet, so we don't need to attach a sink at all.
     */
    private _initTsmfTsScan(buffered: Buffer, activeStreams: Set<number>): void {
        const opts = this._options;
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
            slot.on("data", (chunk: Buffer) => perTs.write(chunk));

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

        // Replay buffered bytes through each slot filter; the slot extracts
        // its target relTs and emits "data" into the corresponding TSFilter.
        for (const e of this._relStreams) {
            e.slot.write(buffered);
        }

        // Dispatcher: fan out subsequent writes to every per-relTs slot filter.
        this._activePipeline = {
            write: (chunk: Buffer) => {
                for (const e of this._relStreams) {
                    if (!e.ts.closed) { e.slot.write(chunk); }
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
     * TSMF→TLV pipeline. Builds a TSMFFilter for the chosen relTs, attaches
     * the TLV output stage, and (in non-discovery mode) starts multi-carrier
     * bonding setup.
     *
     * Two modes:
     * - default: full synchronous pipeline. setupCarriers() is called immediately
     *   to begin multi-carrier bonding. Used by stream delivery, EPG, update
     *   scans, and bonded scans.
     * - tsmfDiscovery=true: waits for groupId event from TSMF header, then branches:
     *   - numberOfCarriers==1: builds TLV pipeline (single-carrier, same session)
     *   - numberOfCarriers>1: emits "discovery" event (caller queues bonded scan)
     *   Used only by initial channel scan (getServices).
     */
    private _initTsmfTlv(buffered: Buffer, relTs: number): void {
        const opts = this._options;
        const ch = opts.channel;

        log.info(
            "StreamFilter TSMF-TLV %s (tsmfRelTs=%d, groupId=%s)",
            opts.tsmfDiscovery ? "discovery" : "bonded scan",
            relTs,
            ch.tsmfGroupId ?? "none"
        );

        this._tsmfFilter = new TSMFFilter(opts.tunerIndex ?? 0, {
            tsmfRelTs: relTs,
            groupId: ch.tsmfGroupId ?? undefined
        });
        this._tsmfBonding = new TSMFCarrierBonding(this._tsmfFilter, opts.tunerIndex ?? 0);
        this._tsmfFilter.once("close", () => {
            if (!this._closed) {
                this.close();
            }
        });

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
            this._tsmfBonding.setupCarriers(ch);
        }

        primaryInput.write(buffered);
    }

    /**
     * Build the TLV output pipeline on top of the existing TSMFFilter.
     * Creates TLVFilter via the shared factory and wires the TSMF "ready"
     * event to pass demuxed TLV data through a PassThrough into TLVFilter.
     */
    private _attachTlvOutputPipeline(): void {
        const ch = this._options.channel;
        const passThrough = new stream.PassThrough();

        this._tsmfFilter.once("ready", () => {
            const detectedRelTs = this._tsmfFilter.detectedRelTs;
            const detectedGroupId = this._tsmfFilter.detectedGroupId;
            if (detectedRelTs !== null) {
                ch.setTsmfRelTs(detectedRelTs);
                // Populate per-service relTs mapping so BS4K channels
                // store the same serviceId→relTs structure as TSMF→TS.
                for (const service of ch.getServices()) {
                    ch.addTsmfRelTsMapping(service.serviceId, detectedRelTs);
                }
            }
            if (detectedGroupId !== null) {
                ch.setTsmfGroupId(detectedGroupId);
            }
            log.debug("StreamFilter TSMF ready, creating TLVFilter");
            this._tsmfFilter.setOutput(passThrough);
        });

        const tlvFilter = this._createTlvFilter();
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
     * Classify a buffered chunk into one of three formats. The classification
     * mirrors the conceptual hierarchy used by `_detect`:
     *
     * - **TLV** (rare; pure TLV with no transport wrapper)
     * - **TS-family**, further split by whether a TSMF Extended header is present:
     *     - plain TS         → `{ format: "ts" }`
     *     - TSMF wrapper     → `{ format: "ts", tsmfHeader }` (header is reused
     *                          downstream so we don't have to re-parse the slot map)
     *
     * We probe TS sync first because it's cheap (8 consecutive 0x47s at 188-byte
     * intervals) and TS-family is by far the common case. The TLV scan is only
     * reached when no TS sync is found in the buffer at all.
     *
     * The strict TS threshold (8 consecutive 0x47s) prevents TLV payloads with
     * coincidental 0x47 patterns from falsely matching: (1/256)^7 ≈ 2e-17 per
     * position on random data.
     */
    private _detectStreamFormat(buffer: Buffer): DetectionResult {
        // --- Top-level fork: TLV vs TS-family ---
        const tsStart = this._findTsStart(buffer);
        if (tsStart >= 0) {
            // TS-family. Sub-classify: plain TS or TSMF wrapper.
            const tsmfHeader = TSMFFilter.findFirstExtendedHeader(buffer, tsStart);
            if (tsmfHeader) {
                log.debug(
                    "StreamFilter TSMF header: slotMap counts %j, streamTypeBits=0x%s, groupId=%d",
                    TSMFFilter.countSlots(tsmfHeader.slotMap),
                    tsmfHeader.streamTypeBits.toString(16),
                    tsmfHeader.groupId
                );
                return { format: "ts", tsmfHeader };
            }
            return { format: "ts" };
        }

        // Not TS-family — try TLV.
        if (this._isTlvBuffer(buffer)) {
            return { format: "tlv" };
        }

        // Neither TS sync nor a valid TLV chain found. Fall back to plain TS;
        // the inner filter will close the session if the bytes are unusable.
        return { format: "ts" };
    }

    /**
     * Locate the first byte offset that begins a run of `TS_MIN_CONSECUTIVE`
     * consecutive TS sync bytes (0x47) at 188-byte intervals. Returns -1 if
     * no such position exists in the buffer.
     */
    private _findTsStart(buffer: Buffer): number {
        const TS_MIN_CONSECUTIVE = 8;
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
                return i;
            }
        }
        return -1;
    }

    /**
     * True iff the buffer contains a recognisable TLV packet chain. Looks for
     * a TLV sync byte (0x7F) followed by a valid type and length, then
     * verifies that the following bytes either chain to another TLV header
     * or extend past the buffer end (indicating a long packet payload).
     */
    private _isTlvBuffer(buffer: Buffer): boolean {
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
                    return true;
                }
                continue;
            }
            if (buffer[next] === TLV_SYNC && TLV_VALID_TYPES.has(buffer[next + 1])) {
                return true;
            }
        }
        return false;
    }
}
