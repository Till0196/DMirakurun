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
const TS_PACKET_SIZE = 188;

/**
 * Extract service IDs from a PAT TS packet (used by TSMF auto-detection).
 * Returns empty array if the packet does not contain a parsable PAT section.
 */
function parsePATPacket(packet: Buffer): number[] {
    const pusi = (packet[1] & 0x40) !== 0;
    if (!pusi) {
        return [];
    }

    const afc = (packet[3] & 0x30) >> 4;
    let payloadStart = 4;
    if (afc === 0x03) {
        payloadStart = 5 + packet[4];
    } else if (afc !== 0x01) {
        return [];
    }

    const pointerField = packet[payloadStart];
    const sectionStart = payloadStart + 1 + pointerField;

    if (sectionStart + 8 > TS_PACKET_SIZE) {
        return [];
    }
    if (packet[sectionStart] !== 0x00) {
        return [];
    }

    const sectionLength = ((packet[sectionStart + 1] & 0x0f) << 8) | packet[sectionStart + 2];
    const serviceIds: number[] = [];
    const end = Math.min(sectionStart + 3 + sectionLength - 4, TS_PACKET_SIZE);

    for (let i = sectionStart + 8; i + 4 <= end; i += 4) {
        const serviceId = (packet[i] << 8) | packet[i + 1];
        if (serviceId !== 0) {
            serviceIds.push(serviceId);
        }
    }

    return serviceIds;
}

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
    private _activePipeline: TSFilter | TLVFilter | Writable = null;
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
            const serviceMap = new Map<number, Set<number>>();
            const activeStreams = new Set<number>();
            const detectedStreams = new Set<number>();
            let detectedGroupId: number | null = null;
            let completed = false;

            detector.on("slotMap", (slotMap: number[], groupId: number | null) => {
                if (groupId !== null && detectedGroupId === null) {
                    detectedGroupId = groupId;
                }
                for (const relTs of slotMap) {
                    if (relTs > 0) {
                        activeStreams.add(relTs);
                    }
                }
            });

            detector.on("patPacket", (relTs: number, packet: Buffer) => {
                if (completed || detectedStreams.has(relTs)) {
                    return;
                }
                const serviceIds = parsePATPacket(packet);
                if (serviceIds.length === 0) {
                    return;
                }
                let entry = serviceMap.get(relTs);
                if (!entry) {
                    entry = new Set();
                    serviceMap.set(relTs, entry);
                }
                for (const sid of serviceIds) {
                    entry.add(sid);
                }
                detectedStreams.add(relTs);

                if (activeStreams.size === 0 || detectedStreams.size < activeStreams.size) {
                    return;
                }

                completed = true;
                for (const [rel, sids] of serviceMap) {
                    for (const sid of sids) {
                        opts.channel.addTsmfRelTsMapping(sid, rel);
                    }
                }
                if (detectedGroupId !== null) {
                    opts.channel.setTsmfGroupId(detectedGroupId);
                }
                log.info("StreamFilter TSMF auto-detected %d streams groupId=%s on %s",
                    serviceMap.size,
                    detectedGroupId !== null ? String(detectedGroupId) : "none",
                    opts.channel.channel);

                // Always select a stream after detection to prevent NIT/SDT interleaving
                if (serviceMap.size >= 1) {
                    const targetRelTs = opts.serviceId
                        ? opts.channel.getTsmfRelTs(opts.serviceId)
                        : undefined;
                    if (targetRelTs) {
                        detector.selectStream(targetRelTs);
                    } else {
                        const firstRelTs = Math.min(...serviceMap.keys());
                        detector.selectStream(firstRelTs);
                    }
                }

                _.service.save();
            });
            tsFilter.setSlotFilter(detector);
        }

        this._innerFilter = tsFilter;
        this._activePipeline = tsFilter;
        this._proxyEvents(tsFilter);

        tsFilter.write(buffered);
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
        // Without this, TSMF-TLV multiplexes containing multiple services
        // (or future mixed TLV+TS multiplexes) cannot route per-service.
        const targetRelTs = opts.tsmfRelTs
            ?? (opts.serviceId ? ch.getTsmfRelTs(opts.serviceId) : undefined)
            ?? ch.tsmfRelTs;

        log.info(
            "StreamFilter TSMF-TLV %s (tsmfRelTs=%s, groupId=%s)",
            opts.tsmfDiscovery ? "discovery" : "bonded scan",
            targetRelTs ?? "auto",
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
     * Decide whether a TSMF Extended multiplex should route through the TLV
     * pipeline or the TS pipeline, based on the requested service's
     * `stream_type` bit (ARIB STD-B32 6.3.4.2).
     *
     * Resolution priority for the target relative stream:
     *   1. opts.tsmfRelTs (explicit URL query override)
     *   2. opts.channel.getTsmfRelTs(opts.serviceId) (per-service mapping)
     *   3. ch.tsmfRelTs (per-channel default)
     *   4. auto-pick: largest TLV stream → largest TS stream → relTs=1
     */
    private _routeTsmfFormat(info: TSMFHeaderInfo): StreamFormat {
        const opts = this._options;
        const ch = opts.channel;
        let target = opts.tsmfRelTs
            ?? (opts.serviceId ? ch.getTsmfRelTs(opts.serviceId) : undefined)
            ?? ch.tsmfRelTs;

        if (!target) {
            target = autoPickRelTs(info.slotMap, info.streamTypeBits);
        }

        const isTLV = TSMFFilter.isTLVStream(info.streamTypeBits, target);
        log.debug(
            "StreamFilter TSMF route: relTs=%d stream_type=%s → %s (slotMap counts %j, streamTypeBits=0x%s)",
            target, isTLV ? "TLV" : "TS", isTLV ? "tsmf-tlv" : "tsmf-ts",
            countSlots(info.slotMap), info.streamTypeBits.toString(16)
        );
        return isTLV ? "tsmf-tlv" : "tsmf-ts";
    }
}

/**
 * Auto-pick the relative stream most likely to be the user's intended target
 * when no explicit relTs was given. Prefers the TLV stream with the most
 * slots; falls back to the TS stream with the most slots; finally returns 1.
 */
function autoPickRelTs(slotMap: number[], streamTypeBits: number): number {
    const counts: number[] = new Array(16).fill(0);
    for (const v of slotMap) {
        if (v >= 1 && v <= 15) {
            counts[v]++;
        }
    }
    let bestTLV = 0;
    let bestTLVCount = 0;
    let bestTS = 0;
    let bestTSCount = 0;
    for (let n = 1; n <= 15; n++) {
        if (counts[n] === 0) {
            continue;
        }
        if (TSMFFilter.isTLVStream(streamTypeBits, n)) {
            if (counts[n] > bestTLVCount) {
                bestTLV = n;
                bestTLVCount = counts[n];
            }
        } else {
            if (counts[n] > bestTSCount) {
                bestTS = n;
                bestTSCount = counts[n];
            }
        }
    }
    return bestTLV || bestTS || 1;
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
