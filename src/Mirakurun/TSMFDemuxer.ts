import { Writable } from "stream";
import * as stream from "stream";
import EventEmitter = require("eventemitter3");
import * as log from "./log";

// TS packet constants
const PACKET_SIZE = 188;
const TS_SYNC_BYTE = 0x47;

// PID assignments for TSMF multi-carrier
const TLV_PID = 0x2d;
const TSMF_PID = 0x2f;
const SLOT_COUNT = 52 as const;

// TSMF sync patterns (ARIB STD-B32)
const TSMF_SYNC_A = 0x1a86;
const TSMF_SYNC_B = 0x0579;

// TLV packet constants (ARIB STD-B32)
const TLV_SYNC_BYTE = 0x7f;
const TLV_HEADER_SIZE = 4; // sync(1) + type(1) + length(2)
const TLV_TYPE_HEADER_COMPRESSED_IP = 0x03;

// Compressed IP header sizes
const CID_HEADER_BASE = 3;
const CID_HEADER_0x60_EXTRA = 42;

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

// Offset detection parameters
const OFFSET_MIN_SFS = 30;
const OFFSET_RETRY_SFS = 30;
const OFFSET_MMTP_MIN_PACKETS = 16;
const OFFSET_MAX_DROP_RATIO = 0.05;
const CARRIER_CONFIRM_THRESHOLD = 3;
const READY_MIN_SUPERFRAMES = 2;
const OUTPUT_MIN_BUFFER_SFS = 2;

interface CarrierFrame {
    framePosition: number;
    numberOfFrames: number;
    continuityCounter: number;
    frameSync: number;
    slots: Buffer[];
    targetSlots: boolean[];
}

interface CarrierSuperframe {
    numberOfFrames: number;
    frames: CarrierFrame[];
}

interface CarrierState {
    carrierSequence: number;
    numberOfCarriers: number;
    blocks: CarrierFrame[];
    superframes: CarrierSuperframe[];
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
    ccChecker: TsmfCCChecker;
}

interface MultiCarrierOptions {
    tsmfRelTs?: number;
    groupId?: number;
}

class CarrierInput extends stream.Writable {
    private _combiner: TSMFDemuxer;
    private _sourceId: number;

    constructor(combiner: TSMFDemuxer, sourceId: number) {
        super();
        this._combiner = combiner;
        this._sourceId = sourceId;
    }

    _write(chunk: any, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
        try {
            this._combiner.writeFromSource(this._sourceId, chunk as Buffer);
            callback();
        } catch (err: any) {
            this._combiner.emit("error", err);
            callback(err);
        }
    }

    _final(callback: (error?: Error | null) => void): void {
        this._combiner.endSource(this._sourceId);
        callback();
    }
}

export default class TSMFDemuxer extends EventEmitter {
    /**
     * Find a valid TLV sync position by verifying that at least 3 consecutive
     * TLV packets chain correctly (each packet's end points to the next 0x7F).
     */
    private static _findTlvSync(buffer: Buffer): number {
        let searchFrom = 0;
        while (searchFrom < buffer.length) {
            const pos = buffer.indexOf(TLV_SYNC_BYTE, searchFrom);
            if (pos < 0) {
                return -1;
            }
            let scan = pos;
            let valid = 0;
            while (valid < 3 && scan + TLV_HEADER_SIZE <= buffer.length) {
                if (buffer[scan] !== TLV_SYNC_BYTE) {
                    break;
                }
                const len = (buffer[scan + 2] << 8) | buffer[scan + 3];
                const next = scan + TLV_HEADER_SIZE + len;
                if (next > buffer.length) {
                    break;
                }
                valid++;
                scan = next;
            }
            if (valid >= 3) {
                return pos;
            }
            searchFrom = pos + 1;
        }
        return -1;
    }

    /** Extract TLV payload from a TSMF TS packet (PUSI=1: skip pointer field). */
    private static _extractTlvPayload(packet: Buffer): Buffer | null {
        if (packet.length !== PACKET_SIZE || packet[0] !== TS_SYNC_BYTE) {
            return null;
        }
        const pusi = (packet[1] & 0x40) !== 0;
        return packet.subarray(pusi ? 4 : 3);
    }

    private _tunerIndex: number;
    private _output: Writable | null;
    private _buffer: Buffer[] = [];

    private _sources = new Map<number, SourceState>();
    private _carrierStates = new Map<number, CarrierState>();
    private _nextSourceId = 1;

    private _numberOfCarriers = 0;
    private _carrierInfoEmitted = false;
    private _carrierConfirmCount = 0;
    private _carrierConfirmValue = 0;

    private _offsets: number[] | null = null;
    private _targetRelStream: number | null;
    private _expectedGroupId: number | null;
    private _detectedGroupId: number | null = null;
    private _headerFinalized = false;
    private _offsetsApplied = false;
    private _outputSuperframeCount = 0;
    private _offsetsLogged = false;

    private _closed = false;
    private _closing = false;
    private _sinkClosed = false;
    private _drainWaiting = false;
    private _pendingOutputChunks: Buffer[] = [];
    private _ready = false;
    private _crcTable?: number[];
    private _probeInProgress = false;
    private _nextProbeThreshold = 0;

    constructor(tunerIndex: number, output: Writable | null, options?: MultiCarrierOptions) {
        super();
        this._tunerIndex = tunerIndex;
        this._output = output;
        this._targetRelStream = options?.tsmfRelTs ? options.tsmfRelTs : null;
        this._expectedGroupId = typeof options?.groupId === "number" ? options.groupId : null;

        if (this._output) {
            this._setupOutputHandlers();
        }
    }

    get ready(): boolean {
        return this._ready;
    }

    get closed(): boolean {
        return this._closed;
    }

    get detectedRelTs(): number | null {
        return this._targetRelStream;
    }

    get detectedGroupId(): number | null {
        return this._detectedGroupId;
    }

    private get _isMultiCarrier(): boolean {
        return this._numberOfCarriers > 1;
    }

    createInput(): stream.Writable {
        const sourceId = this._nextSourceId++;
        const state: SourceState = {
            sourceId,
            packet: Buffer.allocUnsafeSlow(PACKET_SIZE).fill(0),
            offset: -1,
            headerLocked: false,
            activeHeaderCRC: -1,
            effectiveTargetStreamNumber: 0,
            tsmfRelativeStreamNumber: [],
            streamTypeBits: 0,
            ccChecker: new TsmfCCChecker()
        };
        this._sources.set(sourceId, state);
        return new CarrierInput(this, sourceId);
    }

    setOutput(output: stream.Writable): void {
        this._output = output;
        this._setupOutputHandlers();
    }

    writeFromSource(sourceId: number, chunk: Buffer): void {
        if (this._closed || this._closing) {
            return;
        }
        const source = this._sources.get(sourceId);
        if (!source) {
            return;
        }
        if (this._output?.destroyed || (this._output as any)?.writableEnded) {
            this._sinkClosed = true;
            this._close();
            return;
        }

        let offset = 0;
        const length = chunk.length;
        const packets: Buffer[] = [];

        if (source.offset > 0) {
            const need = PACKET_SIZE - source.offset;
            if (length >= need) {
                const head = Buffer.concat([
                    source.packet.subarray(0, source.offset),
                    chunk.subarray(0, need)
                ]);
                source.offset = 0;

                if (head[0] === TS_SYNC_BYTE) {
                    packets.push(head);
                } else {
                    const p = head.indexOf(TS_SYNC_BYTE);
                    if (p >= 0 && head.length - p >= PACKET_SIZE) {
                        packets.push(head.subarray(p, p + PACKET_SIZE));
                    }
                }
                offset = need;
            } else {
                chunk.copy(source.packet, source.offset);
                source.offset += length;
                return;
            }
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

    endSource(sourceId: number): void {
        const source = this._sources.get(sourceId);
        if (!source) {
            return;
        }

        if (source.currentFrame && source.currentFrame.slots.length > 0 && source.carrierSequence) {
            const carrier = this._carrierStates.get(source.carrierSequence);
            if (carrier) {
                this._addBlock(carrier, source.currentFrame);
            }
        }

        this._sources.delete(sourceId);
    }

    close(): void {
        if (!this._closed && !this._closing) {
            this._close();
        }
    }

    private _setupOutputHandlers(): void {
        if (!this._output) {
            return;
        }

        this._output.once("error", (err: any) => {
            log.debug("TunerDevice#%d TSMF output error: %s (code: %s)", this._tunerIndex, err.message, err.code);
            this._close();
        });
        this._output.once("finish", this._close.bind(this));
        this._output.once("close", this._close.bind(this));
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
        const payload = this._extractTSMFPayload(packet);
        if (!payload) {
            return;
        }

        const frameInfo = this._validateTSMFFrame(payload);
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

        this._parseTSMFHeader(source, payload, frameInfo);

        if (source.currentFrame && source.currentFrame.slots.length > 0) {
            this._addBlock(carrierState, source.currentFrame);
        }

        source.currentFrame = {
            framePosition: frameInfo.framePosition,
            numberOfFrames: frameInfo.numberOfFrames,
            continuityCounter: packet[3] & 0x0f,
            frameSync: frameInfo.frameSync,
            slots: [],
            targetSlots: this._getTargetSlots(source)
        };
    }

    private _parseTSMFHeader(
        source: SourceState,
        payload: Buffer,
        frameInfo: {
            headerCRC: number;
            framePosition: number;
            carriers: { numberOfCarriers: number; carrierSequence: number };
        }
    ): void {
        const { headerCRC, framePosition } = frameInfo;

        if (source.headerLocked && (this._headerFinalized || headerCRC === source.activeHeaderCRC)) {
            return;
        }

        // Lock/re-lock header at frame boundaries
        if (framePosition === 0) {
            this._applyTSMFHeader(source, payload, headerCRC);
        }
    }

    private _applyTSMFHeader(source: SourceState, payload: Buffer, headerCRC: number): void {
        source.tsmfRelativeStreamNumber = this._parseSlotMap(payload);
        source.streamTypeBits = this._parseStreamTypeBits(payload);
        source.effectiveTargetStreamNumber = this._resolveTargetStream(
            source.tsmfRelativeStreamNumber,
            source.streamTypeBits
        );
        source.headerLocked = true;
        source.activeHeaderCRC = headerCRC;
    }

    private _getTargetSlots(source: SourceState): boolean[] {
        if (!source.headerLocked || source.effectiveTargetStreamNumber <= 0) {
            return new Array(SLOT_COUNT).fill(true);
        }
        const target = source.effectiveTargetStreamNumber;
        const bits = source.streamTypeBits;
        return source.tsmfRelativeStreamNumber.map(
            value => value === target && this._isTLVStream(bits, value)
        );
    }

    private _resolveCarrier(
        source: SourceState,
        frameInfo: {
            numberOfFrames: number;
            carriers: { numberOfCarriers: number; carrierSequence: number };
        }
    ): CarrierState | null {
        const { numberOfCarriers, carrierSequence } = frameInfo.carriers;

        if (numberOfCarriers < 1 || carrierSequence < 1 || carrierSequence > numberOfCarriers) {
            return null;
        }

        // Require CARRIER_CONFIRM_THRESHOLD consecutive frames with the same
        // numberOfCarriers before committing — guards against stale DVR buffer
        // data or transient misparse at stream start.
        if (this._numberOfCarriers === 0) {
            if (numberOfCarriers === this._carrierConfirmValue) {
                this._carrierConfirmCount++;
            } else {
                if (this._carrierConfirmValue !== 0) {
                    log.debug(
                        "TunerDevice#%d TSMF carrier count changed %d -> %d, resetting confirmation",
                        this._tunerIndex, this._carrierConfirmValue, numberOfCarriers
                    );
                }
                this._carrierConfirmValue = numberOfCarriers;
                this._carrierConfirmCount = 1;
            }
            if (this._carrierConfirmCount < CARRIER_CONFIRM_THRESHOLD) {
                return null;
            }
            this._numberOfCarriers = numberOfCarriers;
            log.info(
                "TunerDevice#%d TSMF confirmed %d carriers",
                this._tunerIndex, numberOfCarriers
            );
        }

        source.carrierSequence = carrierSequence;

        let carrier = this._carrierStates.get(carrierSequence);
        if (!carrier) {
            carrier = {
                carrierSequence,
                numberOfCarriers,
                blocks: [],
                superframes: []
            };
            this._carrierStates.set(carrierSequence, carrier);
        }

        if (!this._carrierInfoEmitted) {
            this._carrierInfoEmitted = true;
            process.nextTick(() => {
                this.emit("carrierInfo", { numberOfCarriers, carrierSequence });
                if (numberOfCarriers > 1) {
                    this.emit("needCarriers", numberOfCarriers);
                }
            });
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
        let i = 0;
        while (i < carrier.blocks.length) {
            const first = carrier.blocks[i];
            if (first.framePosition !== 0) {
                i++;
                continue;
            }
            const n = first.numberOfFrames;
            if (n <= 0 || n > 15) {
                i++;
                continue;
            }

            let ok = true;
            for (let fp = 0; fp < n; fp++) {
                const block = carrier.blocks[i + fp];
                if (!block || block.numberOfFrames !== n || block.framePosition !== fp) {
                    ok = false;
                    break;
                }
            }
            if (!ok) {
                i++;
                continue;
            }

            const frames = carrier.blocks.slice(i, i + n);
            carrier.blocks.splice(i, n);
            carrier.superframes.push({ numberOfFrames: n, frames });

            this._detectOffsets();
            this._drainFrames();
        }
    }

    private _detectOffsets(): void {
        if (this._offsets || this._probeInProgress) {
            return;
        }
        if (this._carrierStates.size < this._numberOfCarriers) {
            return;
        }

        const carriers = this._carriersBySequence();
        const accumulated = Math.min(...carriers.map(c => c.superframes.length));
        const threshold = Math.max(OFFSET_MIN_SFS, this._nextProbeThreshold);
        if (accumulated < threshold) {
            return;
        }

        this._probeInProgress = true;
        const result = this._probeOffsets(carriers);
        this._probeInProgress = false;

        if (result) {
            this._commitOffsets(result);
        } else {
            this._nextProbeThreshold = accumulated + OFFSET_RETRY_SFS;
        }
    }

    private _commitOffsets(offsets: number[]): void {
        this._offsets = offsets;
        this._headerFinalized = true;
        this._offsetsApplied = false;
        (this._isMultiCarrier ? log.info : log.debug)(
            "TunerDevice#%d TSMF offsets finalized: %s", this._tunerIndex, offsets.join(",")
        );
        if (this._buffer.length) {
            this._buffer.length = 0;
        }
    }

    private _candidates(carriers: CarrierState[]): number[][] {
        const sfCounts = carriers.map(c => c.superframes.length);
        const minSf = Math.min(...sfCounts);
        const base = sfCounts.map(sf => sf - minSf);

        const candidates: number[][] = [base];
        const seen = new Set<string>([base.join(",")]);
        const add = (offsets: number[]) => {
            const key = offsets.join(",");
            if (!seen.has(key)) {
                seen.add(key);
                candidates.push(offsets);
            }
        };

        // ±1 per axis only (covers 99%+ of real cases)
        for (let i = 0; i < carriers.length; i++) {
            const plus = base.slice(); plus[i] += 1; add(plus);
            if (base[i] > 0) {
                const minus = base.slice(); minus[i] -= 1; add(minus);
            }
        }
        return candidates;
    }

    /** Probe offset candidates synchronously. Returns best offsets or null. */
    private _probeOffsets(carriers: CarrierState[]): number[] | null {
        const candidates = this._candidates(carriers);
        let bestOffsets: number[] | null = null;
        let bestDrops = Infinity;
        let bestPackets = 0;

        for (const offsets of candidates) {
            if (this._closed || this._closing) {
                return null;
            }

            const packets = this._alignPackets(carriers, offsets, 30);
            if (packets.length === 0) {
                continue;
            }

            const tlv = this._assembleTlv(packets);
            const syncStart = TSMFDemuxer._findTlvSync(tlv);
            if (syncStart < 0) {
                continue;
            }

            const stats = this._probeMmtp(tlv, syncStart);
            if (stats.mmtpPackets < OFFSET_MMTP_MIN_PACKETS) {
                continue;
            }

            // Perfect match — accept immediately
            if (stats.mmtpDrops === 0) {
                (this._isMultiCarrier ? log.info : log.debug)(
                    "TunerDevice#%d TSMF offsets=%s (mmtp=%d, drops=0, candidate %d/%d)",
                    this._tunerIndex, offsets.join(","), stats.mmtpPackets,
                    candidates.indexOf(offsets) + 1, candidates.length
                );
                return offsets;
            }

            if (stats.mmtpDrops < bestDrops ||
                (stats.mmtpDrops === bestDrops && stats.mmtpPackets > bestPackets)) {
                bestOffsets = offsets;
                bestDrops = stats.mmtpDrops;
                bestPackets = stats.mmtpPackets;
            }
        }

        // Accept best if drop ratio is acceptable
        if (bestOffsets && bestPackets >= OFFSET_MMTP_MIN_PACKETS &&
            bestDrops / bestPackets < OFFSET_MAX_DROP_RATIO) {
            (this._isMultiCarrier ? log.info : log.debug)(
                "TunerDevice#%d TSMF offsets=%s (mmtp=%d, drops=%d, best of %d)",
                this._tunerIndex, bestOffsets.join(","), bestPackets, bestDrops, candidates.length
            );
            return bestOffsets;
        }

        return null;
    }

    /** Iterate over interleaved slots across carrier superframes in TSMF order. */
    private _iterateSlots(
        superframes: CarrierSuperframe[],
        callback: (packet: Buffer) => void
    ): void {
        for (let sub = 0; sub < 53; sub++) {
            for (let sp = 0; sp < 4; sp++) {
                for (let c = 0; c < superframes.length; c++) {
                    const sf = superframes[c];
                    const n = sf.numberOfFrames;
                    if (sp >= n) {
                        continue;
                    }
                    const slotIndex = sub * n + sp;
                    const framePosition = Math.floor(slotIndex / 53);
                    const slotInFrame = slotIndex % 53;
                    if (framePosition >= n || slotInFrame === 0) {
                        continue;
                    }

                    const frame = sf.frames[framePosition];
                    const packetSlot = slotInFrame - 1;
                    if (!frame.targetSlots[packetSlot]) {
                        continue;
                    }
                    const packet = frame.slots[packetSlot];
                    if (packet) {
                        callback(packet);
                    }
                }
            }
        }
    }

    private _alignPackets(
        carriers: CarrierState[],
        offsets: number[],
        maxSuperframes: number
    ): Buffer[] {
        const available = Math.min(
            ...carriers.map((c, i) => c.superframes.length - (offsets[i] || 0))
        );
        const count = Math.min(available, maxSuperframes);
        if (count <= 0) {
            return [];
        }

        const outputChunks: Buffer[] = [];
        for (let sf = 0; sf < count; sf++) {
            const sfs = carriers.map((c, i) => c.superframes[(offsets[i] || 0) + sf]);
            this._iterateSlots(sfs, packet => outputChunks.push(packet));
        }
        return outputChunks;
    }

    /** Assemble a TLV byte stream from TS packets for offset probing. */
    private _assembleTlv(packets: Buffer[]): Buffer {
        const chunks: Buffer[] = [];
        for (const packet of packets) {
            const payload = TSMFDemuxer._extractTlvPayload(packet);
            if (payload) {
                chunks.push(payload);
            }
        }
        return Buffer.concat(chunks);
    }

    private _probeMmtp(
        buffer: Buffer,
        start: number
    ): { mmtpPackets: number; mmtpDrops: number } {
        let mmtpPackets = 0;
        let mmtpDrops = 0;
        const runs = new Map<number, { lastSeq: number }>();

        this._iterateTlv(buffer, start, (type, payload) => {
            const mmtp = this._parseMmtpHeader(type, payload);
            if (!mmtp) {
                return;
            }
            mmtpPackets++;
            const state = runs.get(mmtp.packetId);
            if (!state) {
                runs.set(mmtp.packetId, { lastSeq: mmtp.packetSequenceNumber });
                return;
            }
            if (state.lastSeq + 1 !== mmtp.packetSequenceNumber) {
                mmtpDrops++;
            }
            state.lastSeq = mmtp.packetSequenceNumber;
        });

        return { mmtpPackets, mmtpDrops };
    }

    /** Iterate over TLV packets in a buffer, re-syncing on noise bytes. */
    private _iterateTlv(
        buffer: Buffer,
        start: number,
        callback: (type: number, payload: Buffer) => void
    ): void {
        let offset = start;
        while (offset + TLV_HEADER_SIZE <= buffer.length) {
            if (buffer[offset] !== TLV_SYNC_BYTE) {
                const nextSync = buffer.indexOf(TLV_SYNC_BYTE, offset + 1);
                if (nextSync < 0) {
                    break;
                }
                offset = nextSync;
                continue;
            }
            const type = buffer[offset + 1];
            const length = (buffer[offset + 2] << 8) | buffer[offset + 3];
            const next = offset + TLV_HEADER_SIZE + length;
            if (next > buffer.length) {
                break;
            }
            callback(type, buffer.subarray(offset + TLV_HEADER_SIZE, next));
            offset = next;
        }
    }

    /**
     * Parse MMTP header from a TLV packet payload.
     * Only TLV type 0x03 (HeaderCompressedIP) contains MMTP.
     */
    private _parseMmtpHeader(
        tlvType: number,
        tlvPayload: Buffer
    ): { packetId: number; packetSequenceNumber: number } | null {
        if (tlvType !== TLV_TYPE_HEADER_COMPRESSED_IP || tlvPayload.length < 3) {
            return null;
        }

        // Skip compressed IP header to reach MMTP payload
        let mmtpStart: number;
        switch (tlvPayload[2]) {
            case 0x20: // PartialIpv4AndPartialUdp
            case 0x21: // Ipv4Identifier
            case 0x61: // NoCompressedHeader
                mmtpStart = CID_HEADER_BASE;
                break;
            case 0x60: // PartialIpv6AndPartialUdp
                mmtpStart = CID_HEADER_BASE + CID_HEADER_0x60_EXTRA;
                break;
            default:
                return null;
        }

        const mmtp = tlvPayload.subarray(mmtpStart);
        // MMTP minimum: V/flags(1) + reserved(1) + packetId(2) + timestamp(4) + seqNum(4) = 12
        if (mmtp.length < 12) {
            return null;
        }

        return {
            packetId: (mmtp[2] << 8) | mmtp[3],
            packetSequenceNumber: ((mmtp[8] << 24) | (mmtp[9] << 16) | (mmtp[10] << 8) | mmtp[11]) >>> 0
        };
    }

    private _drainFrames(): void {
        if (!this._offsets || this._carrierStates.size === 0) {
            return;
        }
        const carriers = this._carriersBySequence();
        if (!this._offsetsApplied) {
            for (let i = 0; i < carriers.length; i++) {
                const needed = this._offsets[i] || 0;
                if (carriers[i].superframes.length <= needed) {
                    return;
                }
            }
            for (let i = 0; i < carriers.length; i++) {
                const drop = this._offsets[i] || 0;
                if (drop > 0) {
                    carriers[i].superframes.splice(0, drop);
                }
            }
            this._offsetsApplied = true;
        }

        const readyCount = Math.min(...carriers.map(c => c.superframes.length));
        const drainCount = readyCount - OUTPUT_MIN_BUFFER_SFS;
        if (drainCount <= 0) {
            return;
        }

        for (let i = 0; i < drainCount; i++) {
            const sfs = carriers.map(c => c.superframes[i]);
            this._iterateSlots(sfs, packet => this._onTLV(packet));
            this._outputSuperframeCount++;
        }

        this._drain();
        for (const carrier of carriers) {
            carrier.superframes.splice(0, drainCount);
        }
    }

    private _carriersBySequence(): CarrierState[] {
        return Array.from(this._carrierStates.values()).sort((a, b) => a.carrierSequence - b.carrierSequence);
    }

    private _onTLV(packet: Buffer): void {
        if (this._closed || this._closing) {
            return;
        }
        const tlvChunk = TSMFDemuxer._extractTlvPayload(packet);
        if (!tlvChunk) {
            return;
        }

        const pusi = (packet[1] & 0x40) !== 0;
        if (pusi) {
            if (this._buffer.length > 0) {
                this._flush();
            }
            this._buffer.push(Buffer.from(tlvChunk));
        } else {
            if (this._buffer.length === 0) {
                return;
            }
            this._buffer.push(tlvChunk);
        }
    }

    private _flush(): void {
        if (!this._buffer.length || this._sinkClosed) {
            return;
        }
        if (!this._offsets && this._numberOfCarriers > 1) {
            return;
        }

        if (!this._ready) {
            // Wait until offsets are applied (when applicable)
            if (this._offsets && !this._offsetsApplied) {
                return;
            }
            // Multi-carrier requires minimum superframes before emitting
            if (this._numberOfCarriers > 1 && (!this._offsets || this._outputSuperframeCount < READY_MIN_SUPERFRAMES)) {
                return;
            }
            if (this._offsets && !this._offsetsLogged) {
                (this._isMultiCarrier ? log.info : log.debug)(
                    "TunerDevice#%d TSMF ready with offsets: %s",
                    this._tunerIndex,
                    this._offsets.join(",")
                );
                this._offsetsLogged = true;
            }
            this._ready = true;
            log.debug("TunerDevice#%d TSMF first TLV packet ready", this._tunerIndex);
            process.nextTick(() => this.emit("ready"));
        }

        if (!this._output || this._output.destroyed || (this._output as any).writableEnded) {
            if (this._output) {
                this._sinkClosed = true;
            }
            return;
        }

        const outputData = Buffer.concat(this._buffer);
        this._buffer.length = 0;
        this._pendingOutputChunks.push(outputData);
    }

    private _drain(): void {
        if (this._pendingOutputChunks.length === 0 || this._sinkClosed || this._drainWaiting) {
            return;
        }
        if (!this._output || this._output.destroyed || (this._output as any).writableEnded) {
            this._sinkClosed = true;
            return;
        }

        const outputData = this._pendingOutputChunks.length === 1
            ? this._pendingOutputChunks[0]
            : Buffer.concat(this._pendingOutputChunks);
        this._pendingOutputChunks = [];

        try {
            if (!this._output.write(outputData)) {
                this._drainWaiting = true;
                this._output.once("drain", () => {
                    this._drainWaiting = false;
                    if (this._pendingOutputChunks.length > 0 && !this._sinkClosed) {
                        this._drain();
                    }
                });
            }
        } catch (err: any) {
            log.debug("TunerDevice#%d TSMF output error: %s (code: %s)", this._tunerIndex, err.message, err.code);
            this._sinkClosed = true;
            this._close();
        }
    }

    private _close(): void {
        if (this._closed || this._closing) {
            return;
        }
        this._closing = true;

        if (this._offsets) {
            this._drainFrames();
        }
        this._flush();
        this._drain();
        this._sinkClosed = true;

        // Last-ditch write for data that couldn't be flushed (e.g., not ready)
        if (this._buffer.length && this._output && !this._output.destroyed) {
            try {
                this._output.write(Buffer.concat(this._buffer));
            } catch {
                // ignore
            }
        }
        this._buffer = [];

        if (this._output && !this._output.destroyed && !(this._output as any).writableEnded) {
            try {
                this._output.end();
            } catch {
                // ignore
            }
        }
        this._output = null;

        this._closed = true;
        this._closing = false;

        process.nextTick(() => {
            this.emit("close");
            this.removeAllListeners();
        });
    }

    private _extractTSMFPayload(packet: Buffer): Buffer | null {
        if (packet.length !== PACKET_SIZE || packet[0] !== TS_SYNC_BYTE) {
            return null;
        }
        const afc = (packet[3] & 0x30) >> 4;
        // AFC 0x01: payload only; AFC 0x03: adaptation field + payload
        if (afc !== 0x01 && afc !== 0x03) {
            return null;
        }
        const base = afc === 0x03 ? 5 + packet[4] : 4;
        return base + 184 <= PACKET_SIZE ? packet.subarray(base, base + 184) : null;
    }

    private _parseSlotMap(payload: Buffer): number[] {
        const relative = [];
        for (let i = 0; i < SLOT_COUNT; i++) {
            const b = payload[69 + (i >> 1)];
            relative.push((i & 1) === 0 ? (b >> 4) & 0x0f : b & 0x0f);
        }
        return relative;
    }

    private _parseStreamTypeBits(payload: Buffer): number {
        return (payload[121] << 7) | (payload[122] >> 1);
    }

    private _selectTargetStream(relative: number[], streamTypeBits: number): number {
        const tlvCounts = new Array(16).fill(0);
        const allCounts = new Array(16).fill(0);
        for (const value of relative) {
            if (value >= 1 && value <= 15) {
                allCounts[value]++;
                if (this._isTLVStream(streamTypeBits, value)) {
                    tlvCounts[value]++;
                }
            }
        }

        // Find stream with most TLV slots; fall back to most slots of any type
        for (const counts of [tlvCounts, allCounts]) {
            let best = 0;
            let bestCount = 0;
            for (let i = 1; i <= 15; i++) {
                if (counts[i] > bestCount) {
                    best = i;
                    bestCount = counts[i];
                }
            }
            if (best > 0) {
                return best;
            }
        }
        return 1;
    }

    private _resolveTargetStream(relative: number[], streamTypeBits: number): number {
        if (this._targetRelStream === null) {
            this._targetRelStream = this._selectTargetStream(relative, streamTypeBits);
        }

        let target = this._targetRelStream;
        if (!this._isTLVStream(streamTypeBits, target)) {
            const fallback = this._selectTargetStream(relative, streamTypeBits);
            if (this._isTLVStream(streamTypeBits, fallback)) {
                log.warn(
                    "TunerDevice#%d TSMF target stream %d is not TLV, fallback to %d",
                    this._tunerIndex, target, fallback
                );
                target = fallback;
            }
        }

        return target;
    }

    private _isTLVStream(streamTypeBits: number, streamNumber: number): boolean {
        if (streamNumber < 1 || streamNumber > 15) {
            return false;
        }
        return ((streamTypeBits >> (15 - streamNumber)) & 1) === 0;
    }

    private _validateTSMFFrame(payload: Buffer): {
        headerCRC: number;
        framePosition: number;
        numberOfFrames: number;
        frameSync: number;
        frameType: number;
        carriers: { numberOfCarriers: number; carrierSequence: number };
        groupId: number;
    } | null {
        if (payload.length < 184) {
            return null;
        }

        const frameSync = ((payload[0] << 8) | payload[1]) & 0x1fff;
        if (frameSync !== TSMF_SYNC_A && frameSync !== TSMF_SYNC_B) {
            return null;
        }

        if (this._calculateCRC32(payload) !== 0) {
            return null;
        }

        // frame_type: 4 bits at payload byte 2 lower nibble
        const frameType = payload[2] & 0x0f;

        const numberOfCarriers = payload[124];
        const carrierSequence = payload[125];
        if (numberOfCarriers < 1 || numberOfCarriers > 16 || carrierSequence < 1 || carrierSequence > numberOfCarriers) {
            return null;
        }

        const frameRaw = payload[126];

        return {
            headerCRC: (payload[180] << 24) | (payload[181] << 16) | (payload[182] << 8) | payload[183],
            framePosition: frameRaw & 0x0f,
            numberOfFrames: (frameRaw >> 4) & 0x0f,
            frameSync,
            frameType,
            carriers: { numberOfCarriers, carrierSequence },
            groupId: payload[123]
        };
    }

    private _calculateCRC32(data: Buffer): number {
        if (!this._crcTable) {
            this._crcTable = new Array(256);
            const polynomial = 0x04c11db7;
            for (let i = 0; i < 256; i++) {
                let crc = i << 24;
                for (let j = 0; j < 8; j++) {
                    crc = (crc & 0x80000000) ? ((crc << 1) ^ polynomial) >>> 0 : (crc << 1) >>> 0;
                }
                this._crcTable[i] = crc;
            }
        }

        let crc = 0xffffffff;
        for (let i = 0; i < data.length; i++) {
            crc = (crc << 8) ^ this._crcTable[((crc >>> 24) ^ data[i]) & 0xff];
            crc >>>= 0;
        }
        return crc >>> 0;
    }

}

/**
 * Lightweight TSMF slot filter as a Transform stream.
 * Extracts packets belonging to a specific relative stream number from TSMF frames.
 * Used for single-carrier TSMF splitting (non-TLV, e.g. BS/CS over CATV).
 */
export class TSMFSlotFilter extends stream.Transform {

    static createDetector(): TSMFSlotFilter {
        const filter = new TSMFSlotFilter(0, true);
        filter._detectMode = true;
        return filter;
    }

    private _targetStream: number;
    private _detectMode: boolean;
    private _slotCounter = -1;
    private _slotMap: number[] = [];
    private _partial = Buffer.alloc(PACKET_SIZE);
    private _partialLen = 0;
    private _detected = false;
    private _detectedGroupId: number | null = null;
    private _activeStreams = new Set<number>();
    private _serviceMap = new Map<number, Set<number>>();
    private _detectedStreams = new Set<number>();
    private _ccChecker = new TsmfCCChecker();

    constructor(tsmfRelTs: number, private _passHeader = false) {
        super();
        this._targetStream = tsmfRelTs;
        this._detectMode = false;
    }

    get tsmfDetected(): boolean {
        return this._detected;
    }

    get serviceMap(): Map<number, Set<number>> {
        return this._serviceMap;
    }

    get groupId(): number | null {
        return this._detectedGroupId;
    }

    _transform(chunk: Buffer, _encoding: BufferEncoding, callback: stream.TransformCallback): void {
        let offset = 0;

        if (this._partialLen > 0) {
            const need = PACKET_SIZE - this._partialLen;
            if (chunk.length >= need) {
                chunk.copy(this._partial, this._partialLen, 0, need);
                offset = need;
                if (this._partial[0] === TS_SYNC_BYTE) {
                    this._filterPacket(this._partial);
                }
                this._partialLen = 0;
            } else {
                chunk.copy(this._partial, this._partialLen);
                this._partialLen += chunk.length;
                callback();
                return;
            }
        }

        while (offset + PACKET_SIZE <= chunk.length) {
            if (chunk[offset] !== TS_SYNC_BYTE) {
                offset++;
                continue;
            }
            this._filterPacket(chunk.subarray(offset, offset + PACKET_SIZE));
            offset += PACKET_SIZE;
        }

        if (offset < chunk.length) {
            chunk.copy(this._partial, 0, offset);
            this._partialLen = chunk.length - offset;
        }

        callback();
    }

    private _filterPacket(packet: Buffer): void {
        const pid = ((packet[1] & 0x1f) << 8) | packet[2];

        if (pid === TSMF_PID) {
            const sync = ((packet[4] << 8) | packet[5]) & 0x1fff;
            if (sync === TSMF_SYNC_A || sync === TSMF_SYNC_B) {
                const cc = packet[3] & 0x0f;
                const wasSynced = this._ccChecker.synced;
                if (!this._ccChecker.check(cc)) {
                    this._slotCounter = -1;
                    return;
                }
                if (!wasSynced) {
                    log.debug("TSMFSlotFilter CC synced after skipping stale frame(s)");
                }

                this._slotMap = [];
                for (let i = 0; i < 26; i++) {
                    this._slotMap.push((packet[73 + i] & 0xf0) >> 4);
                    this._slotMap.push(packet[73 + i] & 0x0f);
                }
                this._slotCounter = 0;
                this._detected = true;

                // Extract group_id only from Extended TSMF (frame_type=0x2)
                // frame_type is payload byte 2 lower nibble = TS packet byte 6
                if (this._detectMode && this._detectedGroupId === null) {
                    const frameType = packet[6] & 0x0f;
                    if (frameType === 0x02) {
                        this._detectedGroupId = packet[127];
                    }
                }

                // Collect active stream numbers
                if (this._detectMode) {
                    for (const relTs of this._slotMap) {
                        if (relTs > 0) {
                            this._activeStreams.add(relTs);
                        }
                    }
                }
            }
            if (this._passHeader) {
                this.push(packet);
            }
            return;
        }

        if (this._slotCounter < 0 || this._slotCounter >= SLOT_COUNT) {
            if (this._detectMode) {
                this.push(packet);
            }
            return;
        }

        const slot = this._slotCounter++;
        const relTs = this._slotMap[slot];

        // Detection: correlate PAT with relative stream number
        if (this._detectMode && relTs > 0 && pid === 0x0000) {
            this._onDetectPAT(packet, relTs);
        }

        if (this._detectMode) {
            this.push(packet);
        } else if (relTs === this._targetStream) {
            this.push(packet);
        }
    }

    private _onDetectPAT(packet: Buffer, relTs: number): void {
        if (this._detectedStreams.has(relTs)) {
            return;
        }

        const serviceIds = this._parsePAT(packet);
        if (serviceIds.length === 0) {
            return;
        }

        if (!this._serviceMap.has(relTs)) {
            this._serviceMap.set(relTs, new Set());
        }
        for (const sid of serviceIds) {
            this._serviceMap.get(relTs).add(sid);
        }
        this._detectedStreams.add(relTs);

        // Check if all active streams have been detected
        if (this._activeStreams.size > 0 && this._detectedStreams.size >= this._activeStreams.size) {
            this.emit("detected", this._serviceMap);
        }
    }

    private _parsePAT(packet: Buffer): number[] {
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

        if (sectionStart + 8 > PACKET_SIZE) {
            return [];
        }
        if (packet[sectionStart] !== 0x00) {
            return [];
        }

        const sectionLength = ((packet[sectionStart + 1] & 0x0f) << 8) | packet[sectionStart + 2];
        const serviceIds: number[] = [];
        const end = Math.min(sectionStart + 3 + sectionLength - 4, PACKET_SIZE);

        for (let i = sectionStart + 8; i + 4 <= end; i += 4) {
            const serviceId = (packet[i] << 8) | packet[i + 1];
            if (serviceId !== 0) {
                serviceIds.push(serviceId);
            }
        }

        return serviceIds;
    }
}
