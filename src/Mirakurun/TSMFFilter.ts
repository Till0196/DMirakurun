import * as stream from "stream";
import EventEmitter = require("eventemitter3");
import { TsCrc32 } from "@chinachu/aribts";
import * as log from "./log";
import TLVAssembler from "./TLVAssembler";

// TS / TSMF constants
const PACKET_SIZE = 188;
const TS_SYNC_BYTE = 0x47;
const TLV_PID = 0x2d;
const TSMF_PID = 0x2f;
const SLOT_COUNT = 52 as const;
const TSMF_SYNC_A = 0x1a86;
const TSMF_SYNC_B = 0x0579;

// Requires two consecutive CC values before trusting frames (skips stale DVR data).
export class TsmfCCChecker {
    private _lastCC = -1;
    private _synced = false;

    get synced(): boolean {
        return this._synced;
    }

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

// Returns CC if this is a TSMF header packet, or -1 if not.
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

// Returns groupId from Extended TSMF header, or -1.
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

// Extended TSMF header fields.
export interface TSMFHeaderInfo {
    payload: Buffer;
    slotMap: number[];        // 52 entries, each 0..15 (0 = unused)
    streamTypeBits: number;   // 15 bits, MSB = relative stream 1
    streamIds: number[];      // 15 entries, stream_id per relative stream
    originalNetworkIds: number[]; // 15 entries, original_network_id per relative stream
    groupId: number;          // 0..254, 255 = undefined
    numberOfCarriers: number; // 1..16
    carrierSequence: number;  // 1..numberOfCarriers
    framePosition: number;
    numberOfFrames: number;
    headerCRC: number;
}

export type TSMFRouteDecision =
    | { kind: "tsmf-tlv"; relTs: number; pinned: boolean; activeStreams: Set<number> }
    | { kind: "tsmf-ts"; relTs: number; pinned: boolean; activeStreams: Set<number> }
    | { kind: "tsmf-scan"; activeStreams: Set<number>; streamTypeBits: number }
    | { kind: "empty" };

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
    targetSlotsCache: boolean[];
    ccChecker: TsmfCCChecker;
}

export default class TSMFFilter extends EventEmitter {

    // Validates AFC, frame_sync, CRC32. frame_type=0x1 → single-carrier, 0x2 → bonded.
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

        // Parse stream_id[0..14] and original_network_id[0..14] from
        // 識別子/相対ストリーム番号対応情報 (payload[5..64], 480 bits).
        // Each entry: stream_id(16) + original_network_id(16) = 4 bytes.
        const streamIds: number[] = new Array(15);
        const originalNetworkIds: number[] = new Array(15);
        for (let i = 0; i < 15; i++) {
            const off = 5 + i * 4;
            streamIds[i] = (payload[off] << 8) | payload[off + 1];
            originalNetworkIds[i] = (payload[off + 2] << 8) | payload[off + 3];
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
            streamIds,
            originalNetworkIds,
            // group_id is meaningful only when carrier bonding is in use.
            groupId: isMultiCarrier ? payload[123] : 0,
            numberOfCarriers,
            carrierSequence,
            framePosition: frameRaw & 0x0f,
            numberOfFrames: (frameRaw >> 4) & 0x0f,
            headerCRC: (payload[180] << 24) | (payload[181] << 16) | (payload[182] << 8) | payload[183]
        };
    }

    // stream_type bit 0 = TLV, 1 = TS
    static isTLVStream(streamTypeBits: number, n: number): boolean {
        return n >= 1 && n <= 15 && ((streamTypeBits >> (15 - n)) & 1) === 0;
    }

    static getActiveRelTs(header: TSMFHeaderInfo): Set<number> {
        const activeStreams = new Set<number>();
        for (const r of header.slotMap) {
            if (r >= 1 && r <= 15) {
                activeStreams.add(r);
            }
        }
        return activeStreams;
    }

    static findFirstExtendedHeader(buffer: Buffer, tsStart: number): TSMFHeaderInfo | null {
        const ccChecker = new TsmfCCChecker();
        for (let offset = tsStart; offset + PACKET_SIZE <= buffer.length; offset += PACKET_SIZE) {
            if (buffer[offset] !== TS_SYNC_BYTE) {
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
            const packet = buffer.subarray(offset, offset + PACKET_SIZE);
            const info = TSMFFilter.parseTSMFHeader(packet);
            if (info) {
                return info;
            }
        }
        return null;
    }

    // Prefer TLV relTs → tsmf-tlv; pure TS: parseSDT → tsmf-scan, else → tsmf-ts.
    static resolveRoute(
        header: TSMFHeaderInfo,
        requestedRelTs: number | null | undefined,
        parseSDT: boolean
    ): TSMFRouteDecision {
        const activeStreams = TSMFFilter.getActiveRelTs(header);
        if (activeStreams.size === 0) {
            return { kind: "empty" };
        }

        if (requestedRelTs !== undefined && requestedRelTs !== null) {
            const isTLV = TSMFFilter.isTLVStream(header.streamTypeBits, requestedRelTs);
            return {
                kind: isTLV ? "tsmf-tlv" : "tsmf-ts",
                relTs: requestedRelTs,
                pinned: true,
                activeStreams
            };
        }

        // Prefer TLV regardless of mode. The TLV pipeline (TSMFFilter →
        // TLVFilter) is required to demux TLV bytes from TSMF correctly;
        // routing TLV slots through `tsmf-scan` (TSMFSlotFilter → TLVFilter)
        // hands raw TS packets to TLVFilter which only catches occasional
        // PLT fragments and never gets a clean NIT/SDT.
        for (let n = 1; n <= 15; n++) {
            if (activeStreams.has(n) && TSMFFilter.isTLVStream(header.streamTypeBits, n)) {
                return { kind: "tsmf-tlv", relTs: n, pinned: false, activeStreams };
            }
        }

        // Pure TS multiplex: scan mode fans out per-relTs TSFilters; streaming
        // picks the smallest active relTs.
        if (parseSDT) {
            return { kind: "tsmf-scan", activeStreams, streamTypeBits: header.streamTypeBits };
        }
        return {
            kind: "tsmf-ts",
            relTs: Math.min(...activeStreams),
            pinned: false,
            activeStreams
        };
    }

    static countSlots(slotMap: number[]): Record<number, number> {
        const counts: Record<number, number> = {};
        for (const v of slotMap) {
            if (v >= 1 && v <= 15) {
                counts[v] = (counts[v] || 0) + 1;
            }
        }
        return counts;
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
    // guards against bonding carriers from different CATV systems sharing a groupId
    private _detectedStreamIds: number[] | null = null;
    private _streamIdMismatchLogged = false;

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

    close(): void {
        this._close();
    }

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
        const info = TSMFFilter.parseTSMFHeader(packet);
        if (!info) {
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

        if (this._expectedGroupId !== null && info.groupId !== this._expectedGroupId) {
            return;
        }

        if (this._detectedGroupId === null && info.groupId !== 255) {
            this._detectedGroupId = info.groupId;
            this.emit("groupId", info.groupId, info.numberOfCarriers);
        }

        // Record / verify streamIds[] from the Extended TSMF header.
        // The first frame seen (typically from the primary carrier) sets the
        // expected streamIds; any later frame — from the primary itself OR
        // from an additional bonding carrier — whose streamIds differ is
        // dropped and logged once. This catches the case where two CATV
        // systems reuse the same groupId for different bonding groups.
        if (this._detectedStreamIds === null) {
            this._detectedStreamIds = info.streamIds.slice();
        } else {
            for (let i = 0; i < 15; i++) {
                if (info.streamIds[i] !== this._detectedStreamIds[i]) {
                    if (!this._streamIdMismatchLogged) {
                        log.warn(
                            "TunerDevice#%d source#%d TSMF stream_id mismatch: expected [%s], got [%s] — rejecting carrier (likely a groupId collision between different CATV systems)",
                            this._tunerIndex, source.sourceId,
                            this._detectedStreamIds.join(","),
                            info.streamIds.join(",")
                        );
                        this._streamIdMismatchLogged = true;
                    }
                    return;
                }
            }
        }

        const carrierState = this._resolveCarrier(source, info);
        if (!carrierState) {
            return;
        }

        // Lock/re-lock header at frame boundaries (frame_position=0)
        // Skip when CRC matches the currently locked header.
        if (info.framePosition === 0 &&
            !(source.headerLocked && info.headerCRC === source.activeHeaderCRC)) {
            this._applyTSMFHeader(source, info.slotMap, info.streamTypeBits, info.headerCRC);
        }

        if (source.currentFrame && source.currentFrame.slots.length > 0) {
            this._addBlock(carrierState, source.currentFrame);
        }

        source.currentFrame = {
            framePosition: info.framePosition,
            numberOfFrames: info.numberOfFrames,
            slots: [],
            targetSlots: source.targetSlotsCache
        };
    }

    private _applyTSMFHeader(source: SourceState, slotMap: number[], streamTypeBits: number, headerCRC: number): void {
        const target = this._targetRelStream;
        source.headerLocked = true;
        source.activeHeaderCRC = headerCRC;
        source.targetSlotsCache = slotMap.map(v => v === target && TSMFFilter.isTLVStream(streamTypeBits, v));
    }

    private _resolveCarrier(source: SourceState, info: TSMFHeaderInfo): CarrierState | null {
        const { numberOfCarriers, carrierSequence } = info;

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
        // _packFrames can only splice contiguous framePosition=0..n-1 runs;
        // stray blocks (framePosition!=0 at head, or numberOfFrames mismatch)
        // stay behind. Cap at 32 (> max superframe length 15) to bound memory
        // under noisy reception.
        if (carrier.blocks.length > 32) {
            carrier.blocks.splice(0, carrier.blocks.length - 32);
        }
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

}
