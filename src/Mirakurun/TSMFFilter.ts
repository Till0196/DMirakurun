import * as stream from "stream";
import EventEmitter = require("eventemitter3");
import { TsCrc32 } from "@chinachu/aribts";
import * as log from "./log";
import _ from "./_";
import * as common from "./common";
import TLVAssembler from "./TLVAssembler";
import ChannelItem from "./ChannelItem";
import * as apid from "../../api";
import TSFilter from "./TSFilter";
import type TunerDevice from "./TunerDevice";

// TS / TSMF constants (ARIB STD-B32)
const PACKET_SIZE = 188;
const TS_SYNC_BYTE = 0x47;
const TLV_PID = 0x2d;
const TSMF_PID = 0x2f;
const SLOT_COUNT = 52 as const;
const TSMF_SYNC_A = 0x1a86;
const TSMF_SYNC_B = 0x0579;

/**
 * TSMF continuity counter tracker.
 * Skips stale DVR buffer data after retune by requiring two consecutive CC values.
 */
export class TsmfCCChecker {
    private _lastCC = -1;
    private _synced = false;

    get synced(): boolean {
        return this._synced;
    }

    /** Returns true if this packet should be processed, false if it should be skipped. */
    check(cc: number): boolean {
        if (!this._synced) {
            if (this._lastCC >= 0 && cc === ((this._lastCC + 1) & 0x0f)) {
                this._synced = true;
            } else {
                this._lastCC = cc;
                return false;
            }
        }
        this._lastCC = cc;
        return true;
    }
}

/**
 * Check if a TS packet is a TSMF header packet.
 * Returns the CC (continuity_counter) if it is, or -1 if not.
 */
export function getTsmfPacketCC(packet: Buffer, offset = 0): number {
    if (packet[offset] !== TS_SYNC_BYTE) {
        return -1;
    }
    const pid = ((packet[offset + 1] & 0x1f) << 8) | packet[offset + 2];
    if (pid !== TSMF_PID) {
        return -1;
    }
    const sync = ((packet[offset + 4] << 8) | packet[offset + 5]) & 0x1fff;
    if (sync !== TSMF_SYNC_A && sync !== TSMF_SYNC_B) {
        return -1;
    }
    return packet[offset + 3] & 0x0f;
}

/**
 * Extract groupId from Extended TSMF header (frame_type=0x02) in a raw TS packet.
 * Returns the groupId, or -1 if not an Extended TSMF frame or groupId is 255.
 */
export function extractGroupIdFromPacket(packet: Buffer, offset = 0): number {
    const frameType = packet[offset + 6] & 0x0f;
    if (frameType !== 0x02) {
        return -1;
    }
    const groupId = packet[offset + 127];
    return groupId !== 255 ? groupId : -1;
}

export interface CarrierFrame {
    framePosition: number;
    numberOfFrames: number;
    slots: Buffer[];
    targetSlots: boolean[];
}

export interface CarrierSuperframe {
    numberOfFrames: number;
    frames: CarrierFrame[];
}

/**
 * Parsed information from a TSMF Extended frame header (frame_type=0x02).
 * See ARIB STD-B32 6.3.3 / 6.3.4. The `streamTypeBits` field encodes
 * stream_type[1..15] in MSB-first order: bit (15-n) corresponds to
 * relative stream `n`; value 0 = TLV, value 1 = TS or no stream.
 */
export interface TSMFHeaderInfo {
    payload: Buffer;
    slotMap: number[];        // 52 entries, each 0..15 (0 = unused)
    streamTypeBits: number;   // 15 bits, MSB = relative stream 1
    groupId: number;          // 0..254, 255 = undefined
    numberOfCarriers: number; // 1..16
    carrierSequence: number;  // 1..numberOfCarriers
    framePosition: number;
    numberOfFrames: number;
    headerCRC: number;
}

interface CarrierState {
    carrierSequence: number;
    numberOfCarriers: number;
    blocks: CarrierFrame[];
}

interface SourceState {
    sourceId: number;
    carrierSequence?: number;
    packet: Buffer;
    offset: number;
    currentFrame?: CarrierFrame;
    headerLocked: boolean;
    activeHeaderCRC: number;
    effectiveTargetStreamNumber: number;
    tsmfRelativeStreamNumber: number[];
    streamTypeBits: number;
    targetSlotsCache: boolean[];
    ccChecker: TsmfCCChecker;
}

interface CarrierLink {
    device: TunerDevice;
    user: common.User & { _stream?: TSFilter };
    tsFilter: TSFilter;
    sourceStream: stream.PassThrough;
    demuxerInput: stream.Writable;
}

/**
 * TSMF→TLV→TS pipeline orchestrator.
 *
 * - Parses TSMF frames (CRC, slot map, target stream selection, carrier bonding).
 * - Hands packed superframes to TLVAssembler for offset detection and TLV output.
 * - Manages additional tuner carriers for multi-carrier streams (BS4K bonding).
 */
export default class TSMFFilter extends EventEmitter {

    /**
     * Parse a TSMF frame header from a TS packet (PID=0x2F).
     *
     * Validates AFC, frame_sync, and CRC32. The header layout is the
     * "拡張 TSMF" (Extended TSMF) syntax defined in ARIB STD-B32 6.3.2 —
     * the byte positions of stream_status, slot_map, group_id and the
     * carrier bonding fields are identical regardless of frame_type.
     *
     * Per ARIB STD-B32 6.3.3.5 table 6.3-4, frame_type indicates how the
     * multiplex is used:
     *   0x1 = TS-only multiplexing, or partial mixed TS + multi-carrier.
     *         Carrier bonding fields are unused; operators commonly fill
     *         them with 0xFF.
     *   0x2 = Multi-carrier (carrier bonding) only. number_of_carriers /
     *         carrier_sequence are valid.
     *   0xF = Single TS (no multiplexing) — never appears in a header.
     *
     * Range-check the carrier bonding fields only when frame_type=0x2;
     * for frame_type=0x1 we synthesise (numberOfCarriers, carrierSequence)
     * = (1, 1) so the rest of the pipeline can treat the multiplex as a
     * single-carrier source.
     *
     * Used by `StreamFilter._detectStreamFormat` to deterministically route
     * each session to the TLV or TS pipeline based on the requested
     * service's `stream_type`.
     */
    static parseTSMFHeader(packet: Buffer): TSMFHeaderInfo | null {
        if (packet.length !== PACKET_SIZE || packet[0] !== TS_SYNC_BYTE) {
            return null;
        }
        // AFC 0x01: payload only; AFC 0x03: adaptation field + payload
        const afc = (packet[3] & 0x30) >> 4;
        if (afc !== 0x01 && afc !== 0x03) {
            return null;
        }
        const base = afc === 0x03 ? 5 + packet[4] : 4;
        if (base + 184 > PACKET_SIZE) {
            return null;
        }
        const payload = packet.subarray(base, base + 184);

        const frameSync = ((payload[0] << 8) | payload[1]) & 0x1fff;
        if (frameSync !== TSMF_SYNC_A && frameSync !== TSMF_SYNC_B) {
            return null;
        }
        if (TsCrc32.calc(payload) !== 0) {
            return null;
        }

        // frame_type: lower 4 bits of payload[2] (= TS packet byte 6).
        // Layout: payload[2] = version_number(3) | rel_stream_mode(1) | frame_type(4)
        const frameType = payload[2] & 0x0f;
        const isMultiCarrier = frameType === 0x02;

        let numberOfCarriers: number;
        let carrierSequence: number;
        if (isMultiCarrier) {
            numberOfCarriers = payload[124];
            carrierSequence = payload[125];
            if (numberOfCarriers < 1 || numberOfCarriers > 16 ||
                carrierSequence < 1 || carrierSequence > numberOfCarriers) {
                return null;
            }
        } else {
            // frame_type=0x1: TS-only multiplexing. Bonding fields are unused
            // and frequently filled with 0xFF, so we cannot trust them; treat
            // the multiplex as a single carrier.
            numberOfCarriers = 1;
            carrierSequence = 1;
        }

        const slotMap: number[] = new Array(SLOT_COUNT);
        for (let i = 0; i < SLOT_COUNT; i++) {
            const b = payload[69 + (i >> 1)];
            slotMap[i] = (i & 1) === 0 ? (b >> 4) & 0x0f : b & 0x0f;
        }

        const frameRaw = payload[126];
        return {
            payload,
            slotMap,
            streamTypeBits: (payload[121] << 7) | (payload[122] >> 1),
            // group_id is meaningful only when carrier bonding is in use.
            groupId: isMultiCarrier ? payload[123] : 0,
            numberOfCarriers,
            carrierSequence,
            framePosition: frameRaw & 0x0f,
            numberOfFrames: (frameRaw >> 4) & 0x0f,
            headerCRC: (payload[180] << 24) | (payload[181] << 16) | (payload[182] << 8) | payload[183]
        };
    }

    /**
     * True iff relative stream `n` (1..15) carries TLV.
     * stream_type bit 0 = TLV, 1 = TS or no stream (ARIB STD-B32 6.3.4.2,
     * table 6.3-8). Bit (15-n) of `streamTypeBits` corresponds to stream n.
     */
    static isTLVStream(streamTypeBits: number, n: number): boolean {
        return n >= 1 && n <= 15 && ((streamTypeBits >> (15 - n)) & 1) === 0;
    }

    private _tunerIndex: number;
    private _assembler: TLVAssembler;

    private _sources = new Map<number, SourceState>();
    private _carrierStates = new Map<number, CarrierState>();
    private _nextSourceId = 1;

    private _numberOfCarriers = 0;
    private _needCarriersEmitted = false;

    private _targetRelStream: number;
    private _expectedGroupId: number | null;
    private _detectedGroupId: number | null = null;

    private _carrierLinks: CarrierLink[] = [];
    private _carrierInitPending = false;
    private _closed = false;
    private _closing = false;

    constructor(tunerIndex: number, options: { tsmfRelTs: number; groupId?: number }) {
        super();
        this._tunerIndex = tunerIndex;
        this._targetRelStream = options.tsmfRelTs;
        this._expectedGroupId = typeof options?.groupId === "number" ? options.groupId : null;

        this._assembler = new TLVAssembler(tunerIndex, null);
        this._assembler.on("ready", () => this.emit("ready"));
        this._assembler.on("close", () => {
            if (!this._closed && !this._closing) {
                this._close();
            }
        });

        this.once("error", (err: Error) => {
            log.error("TunerDevice#%d TSMFFilter error: %s", this._tunerIndex, err.message);
            this._close();
        });
    }

    get ready(): boolean {
        return this._assembler.ready;
    }

    get hasCarriers(): boolean {
        return this._carrierLinks.length > 0;
    }

    get closed(): boolean {
        return this._closed;
    }

    get detectedRelTs(): number {
        return this._targetRelStream;
    }

    get detectedGroupId(): number | null {
        return this._detectedGroupId;
    }

    createInput(): stream.Writable {
        const sourceId = this._nextSourceId++;
        this._sources.set(sourceId, {
            sourceId,
            packet: Buffer.allocUnsafeSlow(PACKET_SIZE).fill(0),
            offset: -1,
            headerLocked: false,
            activeHeaderCRC: -1,
            effectiveTargetStreamNumber: 0,
            tsmfRelativeStreamNumber: [],
            streamTypeBits: 0,
            targetSlotsCache: new Array(SLOT_COUNT).fill(true),
            ccChecker: new TsmfCCChecker()
        });
        return new stream.Writable({
            write: (chunk, _enc, cb) => {
                try {
                    this._writeFromSource(sourceId, chunk as Buffer);
                    cb();
                } catch (err: any) {
                    this.emit("error", err);
                    cb(err);
                }
            },
            final: cb => {
                this._endSource(sourceId);
                cb();
            }
        });
    }

    setOutput(output: stream.Writable): void {
        this._assembler.setOutput(output);
    }

    setupCarriers(ch: ChannelItem): void {
        // Persist groupId to services DB as soon as detected (fires once).
        this.once("groupId", (groupId: number, numberOfCarriers: number) => {
            ch.setTsmfGroupId(groupId);
            log.debug("TunerDevice#%d TSMF detected groupId=%d numberOfCarriers=%d on %s",
                this._tunerIndex, groupId, numberOfCarriers, ch.channel);
            _.service?.save();
        });
        this.on("needCarriers", (count: number) => {
            log.debug("TunerDevice#%d need %d carriers", this._tunerIndex, count);
            if (count > 1) {
                this._waitAndStartCarriers(ch, count);
            }
        });
    }

    syncPriorities(newPriority: number): void {
        for (const link of this._carrierLinks) {
            if (link.user.priority !== newPriority) {
                (link.user as { priority: number }).priority = newPriority;
            }
        }
    }

    releaseCarriers(): void {
        this._closed = true;
        this._detachCarrierLinks();
    }

    close(): void {
        this.releaseCarriers();
        this._close();
    }

    // --- Private ---

    private _writeFromSource(sourceId: number, chunk: Buffer): void {
        if (this._closed || this._closing) {
            return;
        }
        const source = this._sources.get(sourceId);
        if (!source) {
            return;
        }
        if (this._assembler.closed) {
            this._close();
            return;
        }

        const length = chunk.length;
        const packets: Buffer[] = [];
        let offset = 0;

        // Drain partial packet from previous chunk, if any.
        if (source.offset > 0) {
            const need = PACKET_SIZE - source.offset;
            if (length < need) {
                chunk.copy(source.packet, source.offset);
                source.offset += length;
                return;
            }
            const head = Buffer.concat([
                source.packet.subarray(0, source.offset),
                chunk.subarray(0, need)
            ]);
            source.offset = 0;
            const p = head[0] === TS_SYNC_BYTE ? 0 : head.indexOf(TS_SYNC_BYTE);
            if (p >= 0 && head.length - p >= PACKET_SIZE) {
                packets.push(head.subarray(p, p + PACKET_SIZE));
            }
            offset = need;
        }

        while (offset + PACKET_SIZE <= length) {
            if (chunk[offset] === TS_SYNC_BYTE) {
                packets.push(chunk.subarray(offset, offset + PACKET_SIZE));
                offset += PACKET_SIZE;
            } else {
                offset++;
            }
        }

        if (offset < length) {
            chunk.copy(source.packet, 0, offset);
            source.offset = length - offset;
        }

        this._processPackets(source, packets);
    }

    private _endSource(sourceId: number): void {
        const source = this._sources.get(sourceId);
        if (!source) {
            return;
        }
        if (source.currentFrame?.slots.length && source.carrierSequence) {
            const carrier = this._carrierStates.get(source.carrierSequence);
            if (carrier) {
                this._addBlock(carrier, source.currentFrame);
            }
        }
        this._sources.delete(sourceId);
    }

    private _close(): void {
        // `_closing` guards against re-entry. `_closed` alone may already be
        // true (releaseCarriers sets it before close() calls _close).
        if (this._closing) {
            return;
        }
        this._closing = true;
        this._closed = true;
        this._assembler.close();
        process.nextTick(() => {
            this.emit("close");
            this.removeAllListeners();
        });
    }

    private _processPackets(source: SourceState, packets: Buffer[]): void {
        for (const packet of packets) {
            const pid = ((packet[1] & 0x1f) << 8) | packet[2];
            if (pid === TSMF_PID) {
                this._onTSMF(source, packet);
            }

            if (pid === TLV_PID && source.currentFrame && source.currentFrame.slots.length < SLOT_COUNT) {
                source.currentFrame.slots.push(Buffer.from(packet));
            }
        }
    }

    private _onTSMF(source: SourceState, packet: Buffer): void {
        const frameInfo = this._validateTSMFFrame(packet);
        if (!frameInfo) {
            return;
        }

        const cc = packet[3] & 0x0f;
        const wasSynced = source.ccChecker.synced;
        if (!source.ccChecker.check(cc)) {
            return;
        }
        if (!wasSynced) {
            log.debug("TunerDevice#%d source#%d TSMF CC synced (skipped stale frames)",
                this._tunerIndex, source.sourceId);
        }

        if (this._expectedGroupId !== null && frameInfo.groupId !== this._expectedGroupId) {
            return;
        }

        if (this._detectedGroupId === null && frameInfo.groupId !== 255) {
            this._detectedGroupId = frameInfo.groupId;
            this.emit("groupId", frameInfo.groupId, frameInfo.carriers.numberOfCarriers);
        }

        const carrierState = this._resolveCarrier(source, frameInfo);
        if (!carrierState) {
            return;
        }

        // Lock/re-lock header at frame boundaries (frame_position=0)
        // Skip when CRC matches the currently locked header.
        if (frameInfo.framePosition === 0 &&
            !(source.headerLocked && frameInfo.headerCRC === source.activeHeaderCRC)) {
            this._applyTSMFHeader(source, frameInfo.slotMap, frameInfo.streamTypeBits, frameInfo.headerCRC);
        }

        if (source.currentFrame && source.currentFrame.slots.length > 0) {
            this._addBlock(carrierState, source.currentFrame);
        }

        source.currentFrame = {
            framePosition: frameInfo.framePosition,
            numberOfFrames: frameInfo.numberOfFrames,
            slots: [],
            targetSlots: source.targetSlotsCache
        };
    }

    private _applyTSMFHeader(source: SourceState, slotMap: number[], streamTypeBits: number, headerCRC: number): void {
        const target = this._targetRelStream;

        source.tsmfRelativeStreamNumber = slotMap;
        source.streamTypeBits = streamTypeBits;
        source.effectiveTargetStreamNumber = target;
        source.headerLocked = true;
        source.activeHeaderCRC = headerCRC;
        // Pre-compute target slot mask used by every frame in this header epoch.
        // The caller is expected to have already verified that `target` is a
        // TLV slot in this multiplex (StreamFilter probes the slot map before
        // constructing TSMFFilter), so we don't second-guess the choice here.
        source.targetSlotsCache = slotMap.map(v => v === target && TSMFFilter.isTLVStream(streamTypeBits, v));
    }

    private _resolveCarrier(
        source: SourceState,
        frameInfo: {
            carriers: { numberOfCarriers: number; carrierSequence: number };
        }
    ): CarrierState | null {
        const { numberOfCarriers, carrierSequence } = frameInfo.carriers;

        // Commit numberOfCarriers on the first valid frame from any source.
        // The frame has already passed CRC32 validation in parseTSMFHeader and
        // CC sync in TsmfCCChecker, so the field value is authoritative — no
        // multi-frame confirmation is needed. (The previous "wait N frames"
        // heuristic was redundant defence against vanishingly rare CRC false
        // positives, and could not be expressed in spec terms because the
        // super-frame composition spans multiple carriers with potentially
        // different modulations, none of which is known until carriers are
        // actually attached.)
        if (this._numberOfCarriers === 0) {
            this._numberOfCarriers = numberOfCarriers;
            this._assembler.setNumberOfCarriers(numberOfCarriers);
            log.info("TunerDevice#%d TSMF confirmed %d carriers (from source%d)",
                this._tunerIndex, numberOfCarriers, source.sourceId);
        }

        source.carrierSequence = carrierSequence;

        let carrier = this._carrierStates.get(carrierSequence);
        if (!carrier) {
            carrier = { carrierSequence, numberOfCarriers, blocks: [] };
            this._carrierStates.set(carrierSequence, carrier);
        }

        if (!this._needCarriersEmitted && numberOfCarriers > 1) {
            this._needCarriersEmitted = true;
            process.nextTick(() => this.emit("needCarriers", numberOfCarriers));
        }

        return carrier;
    }

    private _addBlock(carrier: CarrierState, frame: CarrierFrame): void {
        const n = frame.numberOfFrames;
        if (n <= 0 || n > 15) {
            return;
        }
        carrier.blocks.push(frame);
        this._packFrames(carrier);
    }

    private _packFrames(carrier: CarrierState): void {
        const blocks = carrier.blocks;
        let i = 0;
        while (i < blocks.length) {
            const n = blocks[i].numberOfFrames;
            if (blocks[i].framePosition !== 0 || n <= 0 || n > 15) {
                i++;
                continue;
            }
            // Verify n contiguous blocks at framePosition 0..n-1 with the same n.
            let ok = true;
            for (let fp = 0; fp < n; fp++) {
                const b = blocks[i + fp];
                if (!b || b.numberOfFrames !== n || b.framePosition !== fp) {
                    ok = false;
                    break;
                }
            }
            if (!ok) {
                i++;
                continue;
            }
            const frames = blocks.splice(i, n);
            this._assembler.pushSuperframe(carrier.carrierSequence, { numberOfFrames: n, frames });
        }
    }

    private _validateTSMFFrame(packet: Buffer): {
        payload: Buffer;
        headerCRC: number;
        framePosition: number;
        numberOfFrames: number;
        carriers: { numberOfCarriers: number; carrierSequence: number };
        groupId: number;
        slotMap: number[];
        streamTypeBits: number;
    } | null {
        const info = TSMFFilter.parseTSMFHeader(packet);
        if (!info) {
            return null;
        }
        return {
            payload: info.payload,
            headerCRC: info.headerCRC,
            framePosition: info.framePosition,
            numberOfFrames: info.numberOfFrames,
            carriers: {
                numberOfCarriers: info.numberOfCarriers,
                carrierSequence: info.carrierSequence
            },
            groupId: info.groupId,
            slotMap: info.slotMap,
            streamTypeBits: info.streamTypeBits
        };
    }

    // --- Private: carrier link management ---

    private _detachCarrierLinks(): void {
        for (const link of this._carrierLinks) {
            link.sourceStream.removeAllListeners();
            if (!link.demuxerInput.writableEnded) {
                link.demuxerInput.end();
            }
            link.device.endStream(link.user, true);
        }
        this._carrierLinks = [];
        this._carrierInitPending = false;
    }

    /**
     * Start additional carriers for multi-carrier bonding.
     * Tuner availability is guaranteed by the job system's readyFn;
     * groupId discovery is handled by the reactive scan flow.
     */
    private _waitAndStartCarriers(ch: ChannelItem, count: number): void {
        if (this._closed) {
            return;
        }
        if (ch.tsmfGroupId === null || ch.tsmfGroupId === undefined) {
            log.warn("TunerDevice#%d cannot attach extra carriers without tsmfGroupId, aborting stream", this._tunerIndex);
            this._close();
            return;
        }
        // Only the first channel in the group (by config order) should manage bonding.
        // Others abort immediately to free their tuners.
        const groupChannels = _.channel.items.filter(item =>
            item.tsmfGroupId === ch.tsmfGroupId
        );
        const isFirstInGroup = groupChannels.length === 0 || groupChannels[0].channel === ch.channel;

        if (!isFirstInGroup) {
            log.info("TunerDevice#%d not first in group (groupId=%d), deferring bonding to %s",
                this._tunerIndex, ch.tsmfGroupId, groupChannels[0]?.channel);
            this._close();
            return;
        }

        if (groupChannels.length < count) {
            log.warn("TunerDevice#%d not enough group channels for groupId=%d, need %d but got %d — aborting stream",
                this._tunerIndex, ch.tsmfGroupId, count, groupChannels.length);
            this._close();
            return;
        }
        log.info("TunerDevice#%d starting %d additional carriers for groupId=%d",
            this._tunerIndex, count - 1, ch.tsmfGroupId);
        const additional = groupChannels.filter(item => item.channel !== ch.channel);
        this._startCarriers(ch, additional).catch(log.error);
    }

    private async _startCarriers(ch: ChannelItem, groupChannels: ChannelItem[]): Promise<void> {
        if (this._carrierInitPending || this._carrierLinks.length > 0 ||
            !_.tuner || ch.tsmfGroupId === null || ch.tsmfGroupId === undefined) {
            return;
        }

        this._carrierInitPending = true;
        try {
            const required = groupChannels.length;
            if (required < 1) {
                log.warn("TunerDevice#%d no additional channels found for groupId=%d",
                    this._tunerIndex, ch.tsmfGroupId);
                return;
            }

            const selected = this._selectDevices(required, ch.type);
            if (selected.length < required) {
                log.error("TunerDevice#%d failed to find %d BS4K tuners for multi-carrier, only %d available",
                    this._tunerIndex, required, selected.length);
                this._close();
                return;
            }

            log.info("TunerDevice#%d starting %d additional carriers on tuners %s",
                this._tunerIndex, selected.length, selected.map(d => `#${d.index}`).join(", "));

            // Start all additional carriers in parallel to minimize tuning latency.
            // Each startStream may need to kill/release an existing process (~1s each),
            // so parallel startup saves N seconds vs serial.
            const carrierPriority = _.tuner.get(this._tunerIndex)?.getPriority() ?? -1;
            const attempts = selected.map((device, i) => {
                const channel = groupChannels[i];
                const demuxerInput = this.createInput();
                const sourceStream = new stream.PassThrough();
                const tsFilter = sourceStream as unknown as TSFilter;
                const user: common.User & { _stream?: TSFilter } = {
                    id: "Mirakurun:addCarrier()",
                    priority: carrierPriority,
                    disableDecoder: true,
                    streamSetting: { channel }
                };
                return { device, channel, demuxerInput, sourceStream, tsFilter, user };
            });

            const results = await Promise.allSettled(attempts.map(a =>
                a.device.startStream(a.user, a.tsFilter, a.channel, { suppressGroupCombine: true })
            ));

            if (this._closed) {
                this.releaseCarriers();
                return;
            }

            let started = 0;
            for (let i = 0; i < results.length; i++) {
                const a = attempts[i];
                if (results[i].status === "rejected") {
                    log.error("TunerDevice#%d carrier start failed on tuner #%d `%s`",
                        this._tunerIndex, a.device.index,
                        (results[i] as PromiseRejectedResult).reason?.message);
                    continue;
                }
                started++;
                stream.pipeline(a.sourceStream, a.demuxerInput, err => {
                    if (err && !this._closed) {
                        log.error("TunerDevice#%d pipeline error: %s", this._tunerIndex, (err as Error).message);
                    }
                });
                a.sourceStream.once("end", () => {
                    if (!a.demuxerInput.writableEnded) {
                        a.demuxerInput.end();
                    }
                    if (!this._closed) {
                        log.warn("TunerDevice#%d carrier stream ended on tuner #%d, closing TSMFFilter",
                            this._tunerIndex, a.device.index);
                        this._close();
                    }
                });
                this._carrierLinks.push({
                    device: a.device, user: a.user, tsFilter: a.tsFilter,
                    sourceStream: a.sourceStream, demuxerInput: a.demuxerInput
                });
            }

            if (started < required) {
                log.warn("TunerDevice#%d only %d of %d additional carriers started, retrying...",
                    this._tunerIndex, started, required);
                this.releaseCarriers();
                this._close();
                return;
            }
            log.info("TunerDevice#%d all additional carriers started", this._tunerIndex);
        } finally {
            this._carrierInitPending = false;
        }
    }

    private _selectDevices(required: number, channelType: apid.ChannelType): TunerDevice[] {
        if (this._closed) {
            return [];
        }

        const all = _.tuner.devices
            .map(d => _.tuner.get(d.index))
            .filter((d): d is TunerDevice =>
                !!d && d.index !== this._tunerIndex && !d.isRemote &&
                d.config.types.includes(channelType)
            );

        // 1. Prefer free devices.
        const free = all.filter(d => d.isFree);
        if (free.length >= required) {
            return free.slice(0, required);
        }

        // 2. Not enough — take over lower-priority devices, lowest priority first.
        const selected = [...free];
        const carrierPriority = _.tuner.get(this._tunerIndex)?.getPriority() ?? -1;
        if (carrierPriority >= 0) {
            const takeover = all
                .filter(d => !d.isFree && !d.isAdditionalCarrier && d.isUsing &&
                    d.getPriority() < carrierPriority)
                .sort((a, b) => a.getPriority() - b.getPriority());
            for (const d of takeover) {
                if (selected.length >= required) {
                    break;
                }
                selected.push(d);
            }
        }

        return selected.slice(0, required);
    }
}
