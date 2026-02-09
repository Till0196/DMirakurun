import { Writable } from "stream";
import * as stream from "stream";
import { EventEmitter } from "eventemitter3";
import * as log from "./log";

// TS packet constants
const PACKET_SIZE = 188;
const TS_SYNC_BYTE = 0x47;

// PID assignments for TSMF multi-carrier
const TLV_PID = 0x2d;
const TSMF_PID = 0x2f;
const SLOT_COUNT = 52 as const;

// TSMF sync patterns (ARIB STD-B32)
// AFL=0xfa → ((0xfa << 8) | AF[0]) & 0x1fff = 0x1a86
// AFL=0xe5 → ((0xe5 << 8) | AF[0]) & 0x1fff = 0x0579
const TSMF_SYNC_A = 0x1a86;
const TSMF_SYNC_B = 0x0579;
const AFC_ADAPTATION_ONLY = 0x01;
const AFC_WITH_ADAPTATION = 0x03;

// TLV packet constants (ARIB STD-B32)
const TLV_SYNC_BYTE = 0x7f;
const TLV_HEADER_SIZE = 4; // sync(1) + type(1) + length(2)
const TLV_TYPE_HEADER_COMPRESSED_IP = 0x03;

// Compressed IP header sizes (ARIB STD-B32 Table 3-2)
// headerType upper nibble: 0x2x = partial (3-byte header), 0x6x = full (3+42 byte header)
const CID_PARTIAL_HEADER_SIZE = 3;
const CID_FULL_HEADER_SIZE = 3 + 42;

// Offset detection parameters
const OFFSET_MIN_SFS_PER_CARRIER = 140;
const OFFSET_MMTP_MIN_PACKETS = 16;
const READY_MIN_SUPERFRAMES = 2;
const OUTPUT_MIN_BUFFER_SFS = 2;

interface CarrierFrame {
    framePosition: number;
    numberOfFrames: number;
    continuityCounter: number;
    frameSync: number;
    slots: Buffer[];
    targetSlots: boolean[];
    filledSlots: number;
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
    numberOfCarriers?: number;
    packet: Buffer;
    offset: number;
    currentFrame?: CarrierFrame;
    headerLocked: boolean;
    activeHeaderCRC: number;
    candidateHeaderCRC: number;
    candidateSeen: number;
    slotIndex: number;
    effectiveTargetStreamNumber: number;
    tsmfRelativeStreamNumber: number[];
    streamTypeBits: number;
    firstTSMFAt?: number;
    lastTsmfCC: number;
    tsmfDroppedFrames: number;
}

interface MultiCarrierOptions {
    offsets?: number[];
    tsmfRelTs?: number;
    groupId?: number;
}

class CarrierInput extends stream.Writable {
    private _combiner: TLVConverter;
    private _sourceId: number;

    constructor(combiner: TLVConverter, sourceId: number) {
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

export default class TLVConverter extends EventEmitter {
    /**
     * Find a valid TLV sync position by verifying that at least 3 consecutive
     * TLV packets chain correctly (each packet's end points to the next 0x7F).
     * A bare indexOf(0x7F) can hit data bytes that coincidentally equal 0x7F.
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

    /** Extract TLV payload from a TSMF TS packet (no pointer field — payload starts at byte 3 or 4). */
    private static _extractTlvPayload(packet: Buffer): Buffer | null {
        if (packet.length !== PACKET_SIZE || packet[0] !== TS_SYNC_BYTE) {
            return null;
        }
        const pusi = (packet[1] & 0x40) !== 0;
        return packet.subarray(pusi ? 4 : 3);
    }

    private _tunerIndex: number;
    private _output: Writable;
    private _buffer: Buffer[] = [];

    private _sources = new Map<number, SourceState>();
    private _carrierStates = new Map<number, CarrierState>();
    private _nextSourceId = 1;

    private _numberOfCarriers = 0;
    private _carrierInfoEmitted = false;

    private _offsets: number[] | null = null;
    private _offsetsFromOptions?: number[];
    private _targetRelStream: number | null;
    private _expectedGroupId: number | null;
    private _freezeHeader = false;
    private _offsetsApplied = false;
    private _readySuperframes = 0;
    private _loggedOffsetsBeforeReady = false;

    private _closed = false;
    private _closing = false;
    private _sinkClosed = false;
    private _drainWaiting = false;
    private _pendingOutputChunks: Buffer[] = [];
    private _pendingOutputSize = 0;
    private _ready = false;
    private _crcTable?: number[];
    private _tlvSyncFound = false;
    private _ccGraceUntil = 0;
    private _probeMinSfAtNextAttempt = 0;

    constructor(tunerIndex: number, output: Writable | null, options?: MultiCarrierOptions | number) {
        super();
        this._tunerIndex = tunerIndex;
        this._output = output;
        if (typeof options === "number") {
            this._offsetsFromOptions = undefined;
            this._targetRelStream = options;
            this._expectedGroupId = null;
        } else {
            this._offsetsFromOptions = options?.offsets;
            this._targetRelStream = typeof options?.tsmfRelTs === "number" ? options.tsmfRelTs : null;
            this._expectedGroupId = typeof options?.groupId === "number" ? options.groupId : null;
        }

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

    createInput(): stream.Writable {
        const sourceId = this._nextSourceId++;
        const state: SourceState = {
            sourceId,
            packet: Buffer.allocUnsafeSlow(PACKET_SIZE).fill(0),
            offset: -1,
            headerLocked: false,
            activeHeaderCRC: -1,
            candidateHeaderCRC: -1,
            candidateSeen: 0,
            slotIndex: -1,
            effectiveTargetStreamNumber: 0,
            tsmfRelativeStreamNumber: [],
            streamTypeBits: 0,
            lastTsmfCC: -1,
            tsmfDroppedFrames: 0
        };
        this._sources.set(sourceId, state);
        return new CarrierInput(this, sourceId);
    }

    setOutput(output: stream.Writable): void {
        this._output = output;
        this._setupOutputHandlers();
    }

    resetForSynchronizedStart(): void {
        log.info("TunerDevice#%d TLVConverter reset for synchronized start", this._tunerIndex);
        this._carrierStates.clear();
        this._offsets = null;
        this._offsetsApplied = false;
        this._readySuperframes = 0;
        this._ready = false;
        this._loggedOffsetsBeforeReady = false;
        this._freezeHeader = false;
        this._tlvSyncFound = false;
        this._probeMinSfAtNextAttempt = 0;
        if (this._buffer) {
            this._buffer.length = 0;
        }
        for (const source of this._sources.values()) {
            source.carrierSequence = undefined;
            source.numberOfCarriers = undefined;
            source.currentFrame = undefined;
            source.headerLocked = false;
            source.activeHeaderCRC = -1;
            source.candidateHeaderCRC = -1;
            source.candidateSeen = 0;
            source.slotIndex = -1;
            source.effectiveTargetStreamNumber = 0;
            source.tsmfRelativeStreamNumber = [];
            source.streamTypeBits = 0;
            source.offset = -1;
            source.lastTsmfCC = -1;
            source.tsmfDroppedFrames = 0;
        }
    }

    writeFromSource(sourceId: number, chunk: Buffer): void {
        if (this._closed || this._closing) {
            return;
        }
        const source = this._sources.get(sourceId);
        if (!source) {
            return;
        }
        if (this._output && (this._output.destroyed || (this._output as any).writableEnded)) {
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
            log.debug("TunerDevice#%d TLVConverter output error: %s (code: %s)", this._tunerIndex, err.message, err.code);
            this._close();
        });
        this._output.once("finish", this._close.bind(this));
        this._output.once("close", this._close.bind(this));
    }

    private _processPackets(source: SourceState, packets: Buffer[]): void {
        for (const packet of packets) {
            const pid = ((packet[1] & 0x1f) << 8) | packet[2];
            if (pid === TSMF_PID) {
                this._handleTSMFPacket(source, packet);
            }

            if (pid === TLV_PID && source.currentFrame && source.currentFrame.slots.length < SLOT_COUNT) {
                source.currentFrame.slots.push(Buffer.from(packet));
                source.currentFrame.filledSlots += 1;
            }
        }
    }

    private _handleTSMFPacket(source: SourceState, packet: Buffer): void {
        // Track TSMF CC for ALL packets to detect frame drops
        // Skip during grace period after offset detection (event loop was blocked → pipe overflow)
        const cc = packet[3] & 0x0f;
        if (source.lastTsmfCC >= 0 && Date.now() >= this._ccGraceUntil) {
            const expected = (source.lastTsmfCC + 1) & 0x0f;
            if (cc !== expected) {
                const gap = (cc - expected + 16) & 0x0f;
                source.tsmfDroppedFrames += gap;
            }
        }
        source.lastTsmfCC = cc;

        const payload = this._extractTSMFPayload(packet);
        if (!payload) {
            source.tsmfDroppedFrames += 1;
            return;
        }

        const frameInfo = this._validateTSMFFrame(payload);
        if (!frameInfo) {
            source.tsmfDroppedFrames += 1;
            return;
        }
        if (!source.firstTSMFAt) {
            source.firstTSMFAt = Date.now();
            log.info(
                "TunerDevice#%d TLVConverter first TSMF from sourceId=%d seq=%d",
                this._tunerIndex,
                source.sourceId,
                frameInfo.carriers.carrierSequence
            );
        }
        if (this._expectedGroupId !== null && frameInfo.groupId !== this._expectedGroupId) {
            return;
        }

        const carrierState = this._getOrCreateCarrier(source, frameInfo);
        if (!carrierState) {
            return;
        }

        this._processTSMFHeader(source, payload, frameInfo);

        if (source.currentFrame && source.currentFrame.slots.length > 0) {
            this._addBlock(carrierState, source.currentFrame);
        }

        // Soft reset on TSMF frame drops: clear all carrier buffers and let them re-align naturally
        if (source.tsmfDroppedFrames > 0 && this._offsets) {
            log.warn(
                "TunerDevice#%d TLVConverter TSMF frame drop: carrier=%d dropped=%d — soft reset",
                this._tunerIndex, carrierState.carrierSequence, source.tsmfDroppedFrames
            );

            this._writePendingOutput();

            for (const carrier of this._carrierStates.values()) {
                carrier.blocks.length = 0;
                carrier.superframes.length = 0;
            }

            if (this._buffer && this._buffer.length > 0) {
                this._buffer.length = 0;
            }
            this._tlvSyncFound = false;

            for (const s of this._sources.values()) {
                s.tsmfDroppedFrames = 0;
                s.currentFrame = undefined;
                s.lastTsmfCC = -1;
            }
            return;
        }

        const targetSlots = this._buildTargetSlots(source);
        const continuityCounter = packet[3] & 0x0f;

        source.currentFrame = {
            framePosition: frameInfo.framePosition,
            numberOfFrames: frameInfo.numberOfFrames,
            continuityCounter,
            frameSync: frameInfo.frameSync,
            slots: [],
            targetSlots,
            filledSlots: 0
        };
    }

    private _processTSMFHeader(
        source: SourceState,
        payload: Buffer,
        frameInfo: {
            frameType: number;
            headerCRC: number;
            framePosition: number;
            carriers: { numberOfCarriers: number; carrierSequence: number };
            groupId: number;
        }
    ): void {
        const { headerCRC, framePosition, carriers, groupId } = frameInfo;
        const atFrameStart = framePosition === 0;

        if (this._freezeHeader) {
            if (!source.headerLocked && atFrameStart) {
                this._lockTSMFHeader(source, payload, headerCRC, carriers, groupId);
            }
            return;
        }

        if (!source.headerLocked) {
            if (atFrameStart) {
                this._lockTSMFHeader(source, payload, headerCRC, carriers, groupId);
            }
            return;
        }

        if (headerCRC === source.activeHeaderCRC) {
            source.slotIndex = 0;
            return;
        }

        if (atFrameStart) {
            this._lockTSMFHeader(source, payload, headerCRC, carriers, groupId);
        }
    }

    private _lockTSMFHeader(
        source: SourceState,
        payload: Buffer,
        headerCRC: number,
        carriers: { numberOfCarriers: number; carrierSequence: number },
        groupId: number
    ): void {
        this._applyTSMFHeader(source, payload, headerCRC, carriers, groupId);
    }

    private _applyTSMFHeader(
        source: SourceState,
        payload: Buffer,
        headerCRC: number,
        _carriers: { numberOfCarriers: number; carrierSequence: number },
        _groupId: number
    ): void {
        source.tsmfRelativeStreamNumber = this._parseRelativeStreamNumbers(payload);
        source.streamTypeBits = this._parseStreamTypeBits(payload);
        source.effectiveTargetStreamNumber = this._resolveTargetStream(
            source.tsmfRelativeStreamNumber,
            source.streamTypeBits
        );

        source.headerLocked = true;
        source.activeHeaderCRC = headerCRC;
        source.slotIndex = 0;
        source.candidateHeaderCRC = -1;
        source.candidateSeen = 0;
    }

    private _buildTargetSlots(source: SourceState): boolean[] {
        if (!source.headerLocked || source.effectiveTargetStreamNumber <= 0) {
            return new Array(SLOT_COUNT).fill(true);
        }
        const slots = new Array(SLOT_COUNT).fill(false);
        for (let i = 0; i < SLOT_COUNT; i++) {
            const value = source.tsmfRelativeStreamNumber[i] || 0;
            slots[i] = value === source.effectiveTargetStreamNumber && this._isTLVStream(source.streamTypeBits, value);
        }
        return slots;
    }

    private _getOrCreateCarrier(
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

        if (this._numberOfCarriers === 0) {
            this._numberOfCarriers = numberOfCarriers;
        } else if (this._numberOfCarriers !== numberOfCarriers) {
            log.warn(
                "TunerDevice#%d TLVConverter carrier count mismatch: got=%d expected=%d",
                this._tunerIndex, numberOfCarriers, this._numberOfCarriers
            );
        }

        source.carrierSequence = carrierSequence;
        source.numberOfCarriers = numberOfCarriers;

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
        this._buildSuperframes(carrier);
    }

    private _buildSuperframes(carrier: CarrierState): void {
        let i = 0;
        while (i < carrier.blocks.length) {
            const first = carrier.blocks[i];
            if (first.framePosition !== 0) {
                i += 1;
                continue;
            }
            const n = first.numberOfFrames;
            if (n <= 0 || n > 15) {
                i += 1;
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
                i += 1;
                continue;
            }

            const frames = carrier.blocks.slice(i, i + n);
            carrier.blocks.splice(i, n);
            carrier.superframes.push({
                numberOfFrames: n,
                frames
            });
            this._maybeApplyOffsets();
            this._outputAvailableSuperframes();
        }
    }

    private _maybeApplyOffsets(): void {
        if (this._offsets) {
            return;
        }
        if (this._carrierStates.size < this._numberOfCarriers) {
            return;
        }

        const carriers = this._getCarriersSorted();
        const minSf = Math.min(...carriers.map(c => c.superframes.length));
        const effectiveMin = Math.max(OFFSET_MIN_SFS_PER_CARRIER, this._probeMinSfAtNextAttempt);
        if (minSf < effectiveMin) {
            return;
        }

        // Option-specified offsets (for testing)
        if (this._offsetsFromOptions?.length >= this._numberOfCarriers) {
            const minNeeded = Math.max(...this._offsetsFromOptions) + 30;
            if (carriers.every(c => c.superframes.length >= minNeeded)) {
                this._finalizeOffsets(this._offsetsFromOptions.slice(0, this._numberOfCarriers));
            }
            return;
        }

        const candidates = this._buildProbeCandidates(carriers);
        const result = this._probeOffsets(carriers, candidates);
        if (result) {
            this._finalizeOffsets(result);
        } else {
            // Require more SFs before retrying to avoid repeated probe on every SF
            this._probeMinSfAtNextAttempt = minSf + 60;
        }
    }

    private _finalizeOffsets(offsets: number[]): void {
        this._offsets = offsets;
        this._freezeHeader = true;
        this._offsetsApplied = false;
        log.info("TunerDevice#%d TLVConverter offsets finalized: %s", this._tunerIndex, offsets.join(","));
        if (this._buffer && this._buffer.length > 0) {
            this._buffer.length = 0;
        }
        this._tlvSyncFound = false;
        // Reset dropped frame counters AND set CC grace period.
        // Offset detection blocks the event loop briefly, causing pipe buffer overflow
        // and TSMF frame loss. A 2-second grace period covers the buffer drain period.
        for (const source of this._sources.values()) {
            source.tsmfDroppedFrames = 0;
            source.lastTsmfCC = -1;
        }
        this._ccGraceUntil = Date.now() + 2000;
    }

    private _buildProbeCandidates(carriers: CarrierState[]): number[][] {
        const count = carriers.length;
        const sfCounts = carriers.map(c => c.superframes.length);
        const minSf = Math.min(...sfCounts);
        const base = sfCounts.map(sf => sf - minSf);

        const candidates: number[][] = [];
        const seen = new Set<string>();
        const push = (offsets: number[]) => {
            const key = offsets.join(",");
            if (!seen.has(key)) { seen.add(key); candidates.push(offsets); }
        };

        push(base);
        // Single-axis ±1
        for (let i = 0; i < count; i++) {
            const plus = base.slice(); plus[i] += 1; push(plus);
            const minus = base.slice(); minus[i] = Math.max(0, base[i] - 1); push(minus);
        }
        // 2-axis simultaneous ±1
        for (let i = 0; i < count; i++) {
            for (let j = i + 1; j < count; j++) {
                for (const di of [-1, 1]) {
                    for (const dj of [-1, 1]) {
                        const combo = base.slice();
                        combo[i] = Math.max(0, base[i] + di);
                        combo[j] = Math.max(0, base[j] + dj);
                        push(combo);
                    }
                }
            }
        }
        // Single-axis ±2, ±4
        for (const delta of [2, 4]) {
            for (let i = 0; i < count; i++) {
                const plus = base.slice(); plus[i] += delta; push(plus);
                const minus = base.slice(); minus[i] = Math.max(0, base[i] - delta); push(minus);
            }
        }
        return candidates;
    }

    private _probeOffsets(carriers: CarrierState[], candidates: number[][]): number[] | null {
        for (const offsets of candidates) {
            const packets = this._assemblePacketsForOffsets(carriers, offsets, 30);
            if (packets.length === 0) {
                continue;
            }

            const tlv = this._assembleTLVFromPackets(packets);
            const syncStart = TLVConverter._findTlvSync(tlv);
            if (syncStart < 0) {
                continue;
            }
            const stats = this._collectMmtpStats(tlv, syncStart);

            if (stats.mmtpDrops === 0 && stats.mmtpPackets >= OFFSET_MMTP_MIN_PACKETS) {
                log.info(
                    "TunerDevice#%d TLVConverter offsets=[%s] (mmtpPkts=%d, candidate %d/%d)",
                    this._tunerIndex, offsets.join(","), stats.mmtpPackets,
                    candidates.indexOf(offsets) + 1, candidates.length
                );
                return offsets;
            }
        }
        return null;
    }

    private _assemblePacketsForOffsets(
        carriers: CarrierState[],
        offsets: number[],
        maxSuperframes: number
    ): Buffer[] {
        const minSuperframes = Math.min(
            ...carriers.map((c, idx) => c.superframes.length - (offsets[idx] || 0))
        );
        const count = Math.min(minSuperframes, maxSuperframes);
        if (count <= 0) {
            return [];
        }

        const outputChunks: Buffer[] = [];
        for (let sf = 0; sf < count; sf++) {
            for (let sub = 0; sub < 53; sub++) {
                for (let sp = 0; sp < 4; sp++) {
                    for (let c = 0; c < carriers.length; c++) {
                        const sfData = carriers[c].superframes[(offsets[c] || 0) + sf];
                        const n = sfData.numberOfFrames;
                        if (sp >= n) {
                            continue;
                        }

                        const slotIndex = sub * n + sp;
                        const framePosition = Math.floor(slotIndex / 53);
                        const slotInFrame = slotIndex % 53;
                        if (framePosition < 0 || framePosition >= n) {
                            continue;
                        }
                        if (slotInFrame === 0) {
                            continue;
                        }

                        const frame = sfData.frames[framePosition];
                        const packetSlot = slotInFrame - 1;
                        if (frame.targetSlots && frame.targetSlots.length > packetSlot && !frame.targetSlots[packetSlot]) {
                            continue;
                        }
                        const chunk = frame.slots[packetSlot];
                        if (chunk) {
                            outputChunks.push(chunk);
                        }
                    }
                }
            }
        }

        return outputChunks;
    }

    /**
     * Assemble a TLV byte stream from TS packets for offset probing.
     * Uses subarray(4) to get clean TS payload (184 bytes), avoiding the
     * subarray(3) used in the output path which includes byte 3 (CC/flags)
     * as noise — tolerated by dantto4k but fatal for TLV sync detection.
     */
    private _assembleTLVFromPackets(packets: Buffer[]): Buffer {
        const chunks: Buffer[] = [];
        for (const packet of packets) {
            if (packet.length !== PACKET_SIZE || packet[0] !== TS_SYNC_BYTE) {
                continue;
            }
            chunks.push(packet.subarray(4));
        }
        return Buffer.concat(chunks);
    }

    private _collectMmtpStats(
        buffer: Buffer,
        start: number
    ): { mmtpPackets: number; mmtpDrops: number; mmtpBestRun: number } {
        let mmtpPackets = 0;
        let mmtpDrops = 0;
        let mmtpBestRun = 0;
        const runs = new Map<number, { lastSeq: number; run: number }>();

        this._forEachTlvPacket(buffer, start, (type, payload) => {
            const mmtp = this._parseMmtpHeader(type, payload);
            if (!mmtp) {
                return;
            }
            mmtpPackets++;
            const state = runs.get(mmtp.packetId);
            if (!state) {
                runs.set(mmtp.packetId, { lastSeq: mmtp.packetSequenceNumber, run: 1 });
                mmtpBestRun = Math.max(mmtpBestRun, 1);
                return;
            }
            if (state.lastSeq + 1 === mmtp.packetSequenceNumber) {
                state.run++;
            } else {
                state.run = 1;
                mmtpDrops++;
            }
            state.lastSeq = mmtp.packetSequenceNumber;
            mmtpBestRun = Math.max(mmtpBestRun, state.run);
        });

        return { mmtpPackets, mmtpDrops, mmtpBestRun };
    }

    /** Iterate over TLV packets in a buffer, re-syncing on noise bytes. */
    private _forEachTlvPacket(
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
     *
     * TLV payload structure for type 0x03:
     *   [CID(2)] [headerType(1)] [optional: context+addr(38)+seq(4)] [MMTP packet...]
     *
     * MMTP header structure (first 12+ bytes):
     *   [V/flags(1)] [??(1)] [packetId(2)] [timestamp(4)] [packetSequenceNumber(4)]
     *   [optional: packetCounter(4)] [optional: extensionHeader(variable)]
     */
    private _parseMmtpHeader(
        tlvType: number,
        tlvPayload: Buffer
    ): { packetId: number; packetSequenceNumber: number } | null {
        if (tlvType !== TLV_TYPE_HEADER_COMPRESSED_IP || tlvPayload.length < 3) {
            return null;
        }

        // Skip compressed IP header to reach MMTP payload
        const cidType = tlvPayload[2] & 0xf0;
        const mmtpStart = cidType === 0x20 ? CID_PARTIAL_HEADER_SIZE
                        : cidType === 0x60 ? CID_FULL_HEADER_SIZE
                        : -1;
        if (mmtpStart < 0) {
            return null;
        }

        const mmtp = tlvPayload.subarray(mmtpStart);
        // MMTP minimum: V/flags(1) + ??(1) + packetId(2) + timestamp(4) + seqNum(4) = 12
        if (mmtp.length < 12) {
            return null;
        }

        const packetId = (mmtp[2] << 8) | mmtp[3];
        const packetSequenceNumber = (
            (mmtp[8] << 24) | (mmtp[9] << 16) | (mmtp[10] << 8) | mmtp[11]
        ) >>> 0;

        return { packetId, packetSequenceNumber };
    }

    private _outputAvailableSuperframes(): void {
        if (!this._offsets || this._carrierStates.size === 0) {
            return;
        }
        const carriers = this._getCarriersSorted();
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

        const minAvailable = Math.min(...carriers.map(c => c.superframes.length));
        const outputCount = minAvailable - OUTPUT_MIN_BUFFER_SFS;
        if (outputCount <= 0) {
            return;
        }

        for (let i = 0; i < outputCount; i++) {
            const sfs = carriers.map(c => c.superframes[i]);
            this._outputSuperframe(sfs);
            this._readySuperframes += 1;
        }

        this._writePendingOutput();

        carriers.forEach(carrier => {
            carrier.superframes.splice(0, outputCount);
        });
    }

    private _outputSuperframe(superframes: CarrierSuperframe[]): void {
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
                    if (framePosition < 0 || framePosition >= n) {
                        continue;
                    }
                    if (slotInFrame === 0) {
                        continue;
                    }

                    const frame = sf.frames[framePosition];
                    const packetSlot = slotInFrame - 1;
                    if (frame.targetSlots && frame.targetSlots.length > packetSlot && !frame.targetSlots[packetSlot]) {
                        continue;
                    }
                    const packet = frame.slots[packetSlot];
                    if (packet) {
                        this._handleTLVPacket(packet);
                    }
                }
            }
        }
    }

    private _getCarriersSorted(): CarrierState[] {
        return Array.from(this._carrierStates.values()).sort((a, b) => a.carrierSequence - b.carrierSequence);
    }

    private _handleTLVPacket(packet: Buffer): void {
        if (this._closed || this._closing || !this._buffer) {
            return;
        }
        const tlvChunk = TLVConverter._extractTlvPayload(packet);
        if (!tlvChunk) {
            return;
        }

        const pusi = (packet[1] & 0x40) !== 0;
        if (pusi) {
            if (this._buffer.length > 0) {
                this._flushBufferedOutput();
            }
            this._buffer.push(Buffer.from(tlvChunk));
        } else {
            if (this._buffer.length === 0) {
                return;
            }
            this._buffer.push(tlvChunk);
        }
    }

    private _flushBufferedOutput(): void {
        if (!this._buffer || this._buffer.length === 0 || this._sinkClosed || this._drainWaiting) {
            return;
        }
        if (!this._offsets && this._numberOfCarriers > 1) {
            return;
        }

        if (!this._ready) {
            if (this._numberOfCarriers > 1) {
                if (!this._offsets || !this._offsetsApplied) {
                    return;
                }
                if (this._readySuperframes < READY_MIN_SUPERFRAMES) {
                    return;
                }
            } else if (this._offsets && !this._offsetsApplied) {
                return;
            }
            if (this._offsets && !this._loggedOffsetsBeforeReady) {
                log.info(
                    "TunerDevice#%d TLVConverter ready offsets: %s",
                    this._tunerIndex,
                    this._offsets.join(",")
                );
                this._loggedOffsetsBeforeReady = true;
            }
            this._ready = true;
            log.debug("TunerDevice#%d TLVConverter: first TLV packet ready, emitting ready event", this._tunerIndex);
            process.nextTick(() => {
                this.emit("ready");
            });
        }

        if (!this._output) {
            return;
        }

        if (this._output.destroyed || (this._output as any).writableEnded) {
            this._sinkClosed = true;
            return;
        }

        let outputData = Buffer.concat(this._buffer);
        this._buffer.length = 0;

        // Ensure output starts with TLV sync byte
        if (!this._tlvSyncFound && outputData.length > 0) {
            const syncIndex = outputData.indexOf(TLV_SYNC_BYTE);
            if (syncIndex > 0) {
                outputData = outputData.subarray(syncIndex);
            } else if (syncIndex < 0) {
                return;
            }
            this._tlvSyncFound = true;
        }

        this._pendingOutputChunks.push(outputData);
        this._pendingOutputSize += outputData.length;
    }

    private _writePendingOutput(): void {
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
        this._pendingOutputSize = 0;

        try {
            const writeSuccess = this._output.write(outputData);
            if (!writeSuccess) {
                this._drainWaiting = true;
                this._output.once("drain", () => {
                    this._drainWaiting = false;
                    if (this._pendingOutputChunks.length > 0 && !this._sinkClosed) {
                        this._writePendingOutput();
                    }
                    if (this._buffer.length > 0 && !this._sinkClosed) {
                        this._flushBufferedOutput();
                    }
                });
            }
        } catch (err: any) {
            log.debug("TunerDevice#%d TLVConverter output error: %s (code: %s)", this._tunerIndex, err.message, err.code);
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
            this._outputAvailableSuperframes();
        }
        this._flushBufferedOutput();
        this._writePendingOutput();
        this._sinkClosed = true;

        if (this._buffer && this._buffer.length > 0 && this._output && !this._output.destroyed) {
            try {
                const outputData = Buffer.concat(this._buffer);
                this._output.write(outputData);
            } catch (e) {
                log.debug("TunerDevice#%d TLVConverter: error writing remaining buffer: %s", this._tunerIndex, (e as Error).message);
            }
        }

        setImmediate(() => {
            this._buffer = undefined as any;
        });

        if (this._output && !this._output.destroyed) {
            try {
                if (!(this._output as any).writableEnded) {
                    this._output.end();
                }
            } catch (e) {
                const err = e as any;
                log.debug("TunerDevice#%d TLVConverter output end error: %s", this._tunerIndex, err?.message ?? String(err));
            }
        }
        this._output = null as any;

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

        if (afc !== AFC_ADAPTATION_ONLY && afc !== AFC_WITH_ADAPTATION) {
            return null;
        }

        let base = 4;
        if (afc === AFC_WITH_ADAPTATION) {
            const afl = packet[4];
            base = 5 + afl;
            if (base > PACKET_SIZE) {
                return null;
            }
        }

        if (base + 184 > PACKET_SIZE) {
            return null;
        }

        return packet.subarray(base, base + 184);
    }

    private _parseRelativeStreamNumbers(payload: Buffer): number[] {
        const relative = [];
        for (let i = 0; i < SLOT_COUNT; i++) {
            const b = payload[69 + (i >> 1)];
            if ((i & 1) === 0) {
                relative.push((b >> 4) & 0x0f);
            } else {
                relative.push(b & 0x0f);
            }
        }
        return relative;
    }

    private _parseStreamTypeBits(payload: Buffer): number {
        return (payload[121] << 7) | (payload[122] >> 1);
    }

    private _selectTargetStream(relative: number[], streamTypeBits: number): number {
        const counts = new Array(16).fill(0);
        for (const value of relative) {
            if (value >= 1 && value <= 15) {
                const typeBit = (streamTypeBits >> (15 - value)) & 1;
                if (typeBit === 0) {
                    counts[value] += 1;
                }
            }
        }

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

        const fallback = new Array(16).fill(0);
        for (const value of relative) {
            if (value >= 1 && value <= 15) {
                fallback[value] += 1;
            }
        }
        for (let i = 1; i <= 15; i++) {
            if (fallback[i] > bestCount) {
                best = i;
                bestCount = fallback[i];
            }
        }
        return best || 1;
    }

    private _resolveTargetStream(relative: number[], streamTypeBits: number): number {
        let targetStream = this._targetRelStream;
        if (targetStream === null) {
            targetStream = this._selectTargetStream(relative, streamTypeBits);
            this._targetRelStream = targetStream;
        }

        if (!this._isTLVStream(streamTypeBits, targetStream)) {
            const fallback = this._selectTargetStream(relative, streamTypeBits);
            if (this._isTLVStream(streamTypeBits, fallback)) {
                log.warn(
                    "TunerDevice#%d TLVConverter target stream %d is not TLV, fallback to %d",
                    this._tunerIndex,
                    targetStream,
                    fallback
                );
                if (this._targetRelStream === null) {
                    this._targetRelStream = fallback;
                }
                targetStream = fallback;
            }
        }

        return targetStream ?? 1;
    }

    private _isTLVStream(streamTypeBits: number, streamNumber: number): boolean {
        if (streamNumber < 1 || streamNumber > 15) {
            return false;
        }
        const typeBit = (streamTypeBits >> (15 - streamNumber)) & 1;
        return typeBit === 0;
    }

    private _validateTSMFFrame(payload: Buffer): {
        frameType: number;
        headerCRC: number;
        framePosition: number;
        numberOfFrames: number;
        frameSync: number;
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

        const groupId = payload[123];
        const numberOfCarriers = payload[124];
        const carrierSequence = payload[125];
        if (numberOfCarriers < 1 || numberOfCarriers > 16 || carrierSequence < 1 || carrierSequence > numberOfCarriers) {
            return null;
        }

        const frameRaw = payload[126];
        const numberOfFrames = (frameRaw >> 4) & 0x0f;
        const framePosition = frameRaw & 0x0f;

        const frameType = payload[2] & 0x0f;
        const headerCRC = (payload[180] << 24) | (payload[181] << 16) | (payload[182] << 8) | payload[183];

        return {
            frameType,
            headerCRC,
            framePosition,
            numberOfFrames,
            frameSync,
            carriers: { numberOfCarriers, carrierSequence },
            groupId
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
