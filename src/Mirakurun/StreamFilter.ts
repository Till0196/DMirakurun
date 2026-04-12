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

// TSMF is a sub-classification of TS, encoded by `tsmfHeader` not by format.
export type StreamFormat = "ts" | "tlv";

export interface DiscoveryResult {
    groupId: number;
    numberOfCarriers: number;
}

interface DetectionResult {
    format: StreamFormat;
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

    // Multi-relTs auto-detect scan state (TSMF scan — TS and/or TLV)
    private _relStreams: Array<{
        relTs?: number;
        relTlv?: number;
        slot: TSMFSlotFilter;
        filter: TSFilter | TLVFilter;
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
                e.filter.close();
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

    releaseTsmfCarriers(): void {
        this._tsmfBonding?.releaseCarriers();
    }

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

        if (result.format === "tlv") {
            this._initTlv(buffer);
            return;
        }
        if (result.tsmfHeader) {
            this._initTsmf(buffer, result.tsmfHeader);
        } else {
            this._initTs(buffer);
        }
    }

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

    private _initTs(buffered: Buffer, slot?: TSMFSlotFilter): void {
        const tsFilter = this._createTsFilter();
        this._innerFilter = tsFilter;
        this._proxyEvents(tsFilter);

        if (!slot) {
            const ch = this._options.channel;
            tsFilter.once("streamInfo", ({ tsid, networkId }: { tsid: number; networkId: number }) => {
                ch.setStream(0, tsid, networkId, false);
            });
            tsFilter.on("services", (services: { serviceId: number }[]) => {
                for (const svc of services) {
                    ch.addServiceId(svc.serviceId, 0);
                }
            });
        }

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

        const ch = this._options.channel;
        // For TSMF-bonded channels, the slot entry was already populated by
        // TunerDevice's TSMF demux via `_initTsmf`. Skip the slotKey=0
        // writes here so we don't create a parallel entry that would make
        // `findByChannel` return duplicate services.
        const isBondedOutput = ch.tsmfGroupId !== null && ch.tsmfGroupId !== undefined;
        if (!isBondedOutput) {
            tlvFilter.once("streamInfo", ({ streamId, networkId }: { streamId: number; networkId: number }) => {
                ch.setStream(0, streamId, networkId, true);
            });
            tlvFilter.on("services", (services: { serviceId: number }[]) => {
                for (const svc of services) {
                    ch.addServiceId(svc.serviceId, 0);
                }
            });
        }

        tlvFilter.write(buffered);
    }

    private _initTsmf(buffered: Buffer, header: TSMFHeaderInfo): void {
        const opts = this._options;
        const ch = opts.channel;

        if (header.groupId !== 0 && header.groupId !== 255) {
            ch.setTsmfGroupId(header.groupId);
        }

        const activeStreams = new Set<number>();
        for (const r of header.slotMap) {
            if (r >= 1 && r <= 15) { activeStreams.add(r); }
        }
        for (const relTs of activeStreams) {
            const isTlv = TSMFFilter.isTLVStream(header.streamTypeBits, relTs);
            ch.setStream(relTs, header.streamIds[relTs - 1], header.originalNetworkIds[relTs - 1], isTlv, relTs);
        }

        // Multi-carrier: bail with DiscoveryResult so the caller queues a
        // bonded scan instead of stalling on a single-carrier TLVFilter.
        if (opts.tsmfDiscovery &&
            header.numberOfCarriers > 1 &&
            header.groupId !== 0 && header.groupId !== 255) {
            log.info(
                "StreamFilter TSMF discovery: groupId=%d numberOfCarriers=%d → emit discovery on %s",
                header.groupId, header.numberOfCarriers, ch.channel
            );
            if (_.service) {
                _.service.save();
            }
            const discovery: DiscoveryResult = {
                groupId: header.groupId,
                numberOfCarriers: header.numberOfCarriers
            };
            this.emit("discovery", discovery);
            return;
        }

        const requestedRelTs = opts.tsmfRelTs
            ?? (opts.serviceId ? ch.getRelTs(opts.serviceId) : undefined)
            ?? ch.tsmfRelTs;

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

            case "tsmf-scan":
                log.info("StreamFilter TSMF scan started: %d relTs groupId=%s on %s",
                    decision.activeStreams.size,
                    header.groupId !== 0 && header.groupId !== 255 ? String(header.groupId) : "none",
                    ch.channel);
                this._initTsmfScan(buffered, decision.activeStreams, decision.streamTypeBits);
                return;
        }
    }

    private _initTsmfScan(buffered: Buffer, activeStreams: Set<number>, streamTypeBits: number): void {
        const opts = this._options;
        const ch = opts.channel;
        for (const relTs of activeStreams) {
            const isTlv = TSMFFilter.isTLVStream(streamTypeBits, relTs);
            const slot = new TSMFSlotFilter(relTs, false);

            // TLV slot services may not parse during scan (needs dantto4k),
            // but the relTs is already known from streamTypeBits.
            if (isTlv) {
                ch.setTsmfRelTs(relTs);
            }

            const filter: TSFilter | TLVFilter = isTlv
                ? new TLVFilter({
                    networkId: opts.networkId,
                    serviceId: opts.serviceId,
                    eventId: opts.eventId,
                    parseNIT: opts.parseNIT,
                    parseSDT: opts.parseSDT,
                    parseEIT: opts.parseEIT,
                    channel: opts.channel.channel
                })
                : new TSFilter({
                    networkId: opts.networkId,
                    serviceId: opts.serviceId,
                    eventId: opts.eventId,
                    parseNIT: opts.parseNIT,
                    parseSDT: opts.parseSDT,
                    parseEIT: opts.parseEIT
                });

            slot.on("data", (chunk: Buffer) => filter.write(chunk));

            const entry = {
                ...(isTlv ? { relTlv: relTs } : { relTs }),
                slot,
                filter,
                gotServices: false,
                gotNetwork: false,
                services: null as any[] | null
            };

            filter.on("network", (net: any) => {
                if (entry.gotNetwork) { return; }
                entry.gotNetwork = true;
                if (this._aggregatedNetwork === null) {
                    this._aggregatedNetwork = net;
                    this.emit("network", net);
                }
            });

            filter.on("services", (svs: any[]) => {
                if (entry.gotServices) { return; }
                entry.gotServices = true;
                entry.services = svs;
                if (this._relStreams.every(e => e.gotServices)) {
                    this._emitMergedServices(false);
                }
            });

            this._relStreams.push(entry);
        }

        // Replay buffered bytes through each slot filter.
        for (const e of this._relStreams) {
            e.slot.write(buffered);
        }

        // Dispatcher: fan out subsequent writes to every per-relTs slot filter.
        this._activePipeline = {
            write: (chunk: Buffer) => {
                for (const e of this._relStreams) {
                    if (!e.filter.closed) { e.slot.write(chunk); }
                }
            }
        };

        // Aggregation timeout: stay well under Tuner.getServices' 20s cap.
        this._aggregationTimer = setTimeout(() => {
            this._emitMergedServices(true);
        }, 15000);

        // Proxy streamInfo from the first entry.
        Object.defineProperty(this, "streamInfo", {
            get: () => this._relStreams[0]?.filter.streamInfo ?? {},
            configurable: true
        });
    }

    /**
     * Merge services collected from each per-relTs filter, persist the
     * serviceId→relTs mapping (TS or TLV map as appropriate), and emit the
     * aggregated "services" event.
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

        const ch = this._options.channel;
        const seen = new Set<string>();
        const merged: any[] = [];
        for (const e of this._relStreams) {
            if (!e.services) { continue; }
            for (const svc of e.services) {
                const key = `${svc.networkId}:${svc.serviceId}`;
                if (seen.has(key)) { continue; }
                seen.add(key);
                merged.push(svc);
                if (e.relTs !== undefined) {
                    // fromConfig locks are honoured inside addServiceId.
                    ch.addServiceId(svc.serviceId, e.relTs);
                }
                // relTlv: per-service mapping is not needed; channel-level
                // tsmfRelTs is set in _initTsmfScan / _initTsmf.
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
     * TSMF→TLV pipeline. In `tsmfDiscovery` mode waits for the groupId event:
     * single-carrier proceeds to TLV setup, multi-carrier emits a discovery
     * result so the caller queues a bonded scan.
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
                    this._attachTlvOutputPipeline(relTs);
                }
            });
        } else {
            this._attachTlvOutputPipeline(relTs);
            this._tsmfBonding.setupCarriers(ch);
        }

        primaryInput.write(buffered);
    }

    private _attachTlvOutputPipeline(relTs: number): void {
        const ch = this._options.channel;
        const tlvFilter = this._createTlvFilter();
        this._innerFilter = tlvFilter;
        this._proxyEvents(tlvFilter);

        tlvFilter.on("services", (services: { serviceId: number }[]) => {
            for (const svc of services) {
                ch.addServiceId(svc.serviceId, relTs);
            }
        });

        const passThrough = new stream.PassThrough();
        passThrough.on("data", (chunk: Buffer) => {
            if (!this._closed) {
                tlvFilter.write(chunk);
            }
        });

        this._tsmfFilter.once("ready", () => {
            if (this._tsmfFilter.detectedRelTs !== null) {
                ch.setTsmfRelTs(this._tsmfFilter.detectedRelTs);
            }
            if (this._tsmfFilter.detectedGroupId !== null) {
                ch.setTsmfGroupId(this._tsmfFilter.detectedGroupId);
            }
            this._tsmfFilter.setOutput(passThrough);
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
        const inner = filter as TSFilter | TLVFilter;
        Object.defineProperty(this, "streamInfo", {
            get: () => inner.streamInfo,
            configurable: true
        });
    }

    private _detectStreamFormat(buffer: Buffer): DetectionResult {
        const tsStart = this._findTsStart(buffer);
        if (tsStart >= 0) {
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
