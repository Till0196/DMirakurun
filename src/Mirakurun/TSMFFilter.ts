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
    lastTsmfCC: number;
    tsmfDroppedFrames: number;
}

interface MultiCarrierOptions {
    tsmfRelTs?: number;
    groupId?: number;
}

export class StreamGate extends stream.Transform {
    private _opened = false;
    private _buffer: Buffer[] = [];
    private _bufferedBytes = 0;

    constructor(private _limitBytes: number) {
        super();
    }

    open(discardBuffer = false): void {
        if (this._opened) {
            return;
        }
        this._opened = true;
        if (discardBuffer) {
            this._buffer = [];
            this._bufferedBytes = 0;
        } else {
            for (const chunk of this._buffer) {
                this.push(chunk);
            }
            this._buffer = [];
            this._bufferedBytes = 0;
        }
    }

    close(): void {
        this._opened = false;
    }

    _transform(chunk: any, _encoding: BufferEncoding, callback: stream.TransformCallback): void {
        if (this._opened) {
            this.push(chunk);
            callback();
            return;
        }
        const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        if (this._bufferedBytes + data.length > this._limitBytes) {
            this._buffer = [];
            this._bufferedBytes = 0;
        }
        this._buffer.push(data);
        this._bufferedBytes += data.length;
        callback();
    }
}

class CarrierInput extends stream.Writable {
    private _combiner: TSMFFilter;
    private _sourceId: number;

    constructor(combiner: TSMFFilter, sourceId: number) {
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

export default class TSMFFilter extends EventEmitter {
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
    private _buffer: Buffer[] | null = [];

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
    private _freezeHeader = false;
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
    private _ccGraceUntil = 0;
    private _probeInProgress = false;
    private _nextProbeThreshold = 0;

    // Gate management for multi-carrier synchronization
    private _gates: StreamGate[] = [];
    private _gatesExpected: number | null = null;
    private _gatesOpened = false;

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
        log.info("TunerDevice#%d TSMFFilter reset for synchronized start", this._tunerIndex);
        this._carrierStates.clear();
        this._offsets = null;
        this._offsetsApplied = false;
        this._outputSuperframeCount = 0;
        this._ready = false;
        this._offsetsLogged = false;
        this._freezeHeader = false;
        this._probeInProgress = false;
        this._nextProbeThreshold = 0;
        if (this._buffer) {
            this._buffer.length = 0;
        }
        for (const source of this._sources.values()) {
            source.carrierSequence = undefined;
            source.currentFrame = undefined;
            source.headerLocked = false;
            source.activeHeaderCRC = -1;
            source.effectiveTargetStreamNumber = 0;
            source.tsmfRelativeStreamNumber = [];
            source.streamTypeBits = 0;
            source.offset = -1;
            source.lastTsmfCC = -1;
            source.tsmfDroppedFrames = 0;
        }
    }

    initGates(expected: number): void {
        this._gates = [];
        this._gatesExpected = expected;
        this._gatesOpened = false;
    }

    addGate(gate: StreamGate): void {
        if (!this._gatesExpected) {
            gate.open();
            return;
        }
        this._gates.push(gate);
        this._tryOpenGates();
    }

    resetGates(): void {
        for (const gate of this._gates) {
            gate.open();
        }
        this._gates = [];
        this._gatesExpected = null;
        this._gatesOpened = false;
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

    private _tryOpenGates(): void {
        if (this._gatesOpened || !this._gatesExpected || this._gates.length < this._gatesExpected) {
            return;
        }
        this._gatesOpened = true;
        this.resetForSynchronizedStart();
        for (const gate of this._gates) {
            gate.open(true);
        }
    }

    private _setupOutputHandlers(): void {
        if (!this._output) {
            return;
        }

        this._output.once("error", (err: any) => {
            log.debug("TunerDevice#%d TSMFFilter output error: %s (code: %s)", this._tunerIndex, err.message, err.code);
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
        // Track TSMF CC to detect frame drops (skip during grace period after offset detection)
        const cc = packet[3] & 0x0f;
        if (source.lastTsmfCC >= 0 && Date.now() >= this._ccGraceUntil) {
            const expected = (source.lastTsmfCC + 1) & 0x0f;
            if (cc !== expected) {
                source.tsmfDroppedFrames += ((cc - expected + 16) & 0x0f);
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

        if (this._expectedGroupId !== null && frameInfo.groupId !== this._expectedGroupId) {
            return;
        }

        const carrierState = this._getOrCreateCarrier(source, frameInfo);
        if (!carrierState) {
            return;
        }

        this._parseTSMFHeader(source, payload, frameInfo);

        if (source.currentFrame && source.currentFrame.slots.length > 0) {
            this._addBlock(carrierState, source.currentFrame);
        }

        // Soft reset on TSMF frame drops: clear all carrier buffers and re-align
        if (source.tsmfDroppedFrames > 0 && this._offsets) {
            log.warn(
                "TunerDevice#%d TSMFFilter TSMF frame drop: carrier=%d dropped=%d — soft reset",
                this._tunerIndex, carrierState.carrierSequence, source.tsmfDroppedFrames
            );

            this._drain();

            for (const carrier of this._carrierStates.values()) {
                carrier.blocks.length = 0;
                carrier.superframes.length = 0;
            }
            if (this._buffer?.length) {
                this._buffer.length = 0;
            }
            for (const s of this._sources.values()) {
                s.tsmfDroppedFrames = 0;
                s.currentFrame = undefined;
                s.lastTsmfCC = -1;
            }
            return;
        }

        source.currentFrame = {
            framePosition: frameInfo.framePosition,
            numberOfFrames: frameInfo.numberOfFrames,
            continuityCounter: packet[3] & 0x0f,
            frameSync: frameInfo.frameSync,
            slots: [],
            targetSlots: this._buildTargetSlots(source)
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

        // When header is frozen and source already locked, skip processing
        if (this._freezeHeader && source.headerLocked) {
            return;
        }

        // Current header still valid
        if (source.headerLocked && headerCRC === source.activeHeaderCRC) {
            return;
        }

        // Lock/re-lock header at frame boundaries
        if (framePosition === 0) {
            this._applyTSMFHeader(source, payload, headerCRC);
        }
    }

    private _applyTSMFHeader(source: SourceState, payload: Buffer, headerCRC: number): void {
        source.tsmfRelativeStreamNumber = this._parseRelativeStreamNumbers(payload);
        source.streamTypeBits = this._parseStreamTypeBits(payload);
        source.effectiveTargetStreamNumber = this._resolveTargetStream(
            source.tsmfRelativeStreamNumber,
            source.streamTypeBits
        );
        source.headerLocked = true;
        source.activeHeaderCRC = headerCRC;
    }

    private _buildTargetSlots(source: SourceState): boolean[] {
        if (!source.headerLocked || source.effectiveTargetStreamNumber <= 0) {
            return new Array(SLOT_COUNT).fill(true);
        }
        const target = source.effectiveTargetStreamNumber;
        const bits = source.streamTypeBits;
        return source.tsmfRelativeStreamNumber.map(
            value => value === target && this._isTLVStream(bits, value)
        );
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

        // Require CARRIER_CONFIRM_THRESHOLD consecutive frames with the same
        // numberOfCarriers before committing — guards against stale DVR buffer
        // data or transient misparse at stream start.
        if (this._numberOfCarriers === 0) {
            if (numberOfCarriers === this._carrierConfirmValue) {
                this._carrierConfirmCount++;
            } else {
                if (this._carrierConfirmValue !== 0) {
                    log.debug(
                        "TunerDevice#%d TSMFFilter carrier count changed during confirmation: %d -> %d (reset)",
                        this._tunerIndex, this._carrierConfirmValue, numberOfCarriers
                    );
                }
                this._carrierConfirmValue = numberOfCarriers;
                this._carrierConfirmCount = 1;
            }
            if (this._carrierConfirmCount < 3) {
                return null;
            }
            this._numberOfCarriers = numberOfCarriers;
            log.info(
                "TunerDevice#%d TSMFFilter confirmed numberOfCarriers=%d",
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
        this._buildSuperframes(carrier);
    }

    private _buildSuperframes(carrier: CarrierState): void {
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

            this._tryDetectOffsets();
            this._drainAlignedSuperframes();
        }
    }

    private _tryDetectOffsets(): void {
        if (this._offsets || this._probeInProgress) {
            return;
        }
        if (this._carrierStates.size < this._numberOfCarriers) {
            return;
        }

        const carriers = this._carriersBySequence();
        const accumulated = Math.min(...carriers.map(c => c.superframes.length));
        const threshold = Math.max(OFFSET_MIN_SFS_PER_CARRIER, this._nextProbeThreshold);
        if (accumulated < threshold) {
            return;
        }

        const candidates = this._buildProbeCandidates(carriers);
        this._probeInProgress = true;
        this._probeOffsets(carriers, candidates, accumulated);
    }

    private _finalizeOffsets(offsets: number[]): void {
        this._offsets = offsets;
        this._freezeHeader = true;
        this._offsetsApplied = false;
        (this._isMultiCarrier ? log.info : log.debug)(
            "TunerDevice#%d TSMFFilter offsets finalized: %s", this._tunerIndex, offsets.join(",")
        );
        if (this._buffer?.length) {
            this._buffer.length = 0;
        }
        // Reset dropped frame counters and set CC grace period.
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
        const aligned = Math.min(...sfCounts);
        const base = sfCounts.map(sf => sf - aligned);

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

    /**
     * Probe offset candidates asynchronously, yielding the event loop between
     * each candidate via setImmediate to prevent DVR buffer overflow (EOVERFLOW).
     */
    private _probeOffsets(carriers: CarrierState[], candidates: number[][], accumulated: number): void {
        let idx = 0;
        let bestOffsets: number[] | null = null;
        let bestMmtpPackets = 0;
        let bestMmtpDrops = Infinity;

        const tryNext = () => {
            if (this._closed || this._closing) {
                this._probeInProgress = false;
                return;
            }

            if (idx >= candidates.length) {
                // All candidates tested — accept best if good enough
                if (bestOffsets && bestMmtpPackets >= OFFSET_MMTP_MIN_PACKETS &&
                    bestMmtpDrops / bestMmtpPackets < 0.05) {
                    (this._isMultiCarrier ? log.info : log.debug)(
                        "TunerDevice#%d TSMFFilter offsets=[%s] (mmtpPkts=%d, drops=%d, best of %d)",
                        this._tunerIndex, bestOffsets.join(","), bestMmtpPackets, bestMmtpDrops,
                        candidates.length
                    );
                    this._probeInProgress = false;
                    this._finalizeOffsets(bestOffsets);
                    return;
                }
                this._probeInProgress = false;
                this._nextProbeThreshold = accumulated + 60;
                return;
            }

            const offsets = candidates[idx++];
            const packets = this._alignPackets(carriers, offsets, 30);
            if (packets.length > 0) {
                const tlv = this._assembleTlv(packets);
                const syncStart = TSMFFilter._findTlvSync(tlv);

                if (syncStart >= 0) {
                    const stats = this._probeMmtp(tlv, syncStart);

                    if (stats.mmtpPackets >= OFFSET_MMTP_MIN_PACKETS) {
                        // Immediate accept on perfect continuity
                        if (stats.mmtpDrops === 0) {
                            (this._isMultiCarrier ? log.info : log.debug)(
                                "TunerDevice#%d TSMFFilter offsets=[%s] (mmtpPkts=%d, drops=0, candidate %d/%d)",
                                this._tunerIndex, offsets.join(","), stats.mmtpPackets,
                                idx, candidates.length
                            );
                            this._probeInProgress = false;
                            this._finalizeOffsets(offsets);
                            return;
                        }

                        // Track best candidate
                        if (stats.mmtpDrops < bestMmtpDrops ||
                            (stats.mmtpDrops === bestMmtpDrops && stats.mmtpPackets > bestMmtpPackets)) {
                            bestOffsets = offsets;
                            bestMmtpPackets = stats.mmtpPackets;
                            bestMmtpDrops = stats.mmtpDrops;
                        }
                    }
                }
            }

            setImmediate(tryNext);
        };

        // First candidate tested synchronously (zero overhead for common case)
        tryNext();
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
            const payload = TSMFFilter._extractTlvPayload(packet);
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

    private _drainAlignedSuperframes(): void {
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
        if (this._closed || this._closing || !this._buffer) {
            return;
        }
        const tlvChunk = TSMFFilter._extractTlvPayload(packet);
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
        if (!this._buffer?.length || this._sinkClosed) {
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
                    "TunerDevice#%d TSMFFilter ready offsets: %s",
                    this._tunerIndex,
                    this._offsets.join(",")
                );
                this._offsetsLogged = true;
            }
            this._ready = true;
            log.debug("TunerDevice#%d TSMFFilter: first TLV packet ready, emitting ready event", this._tunerIndex);
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
            log.debug("TunerDevice#%d TSMFFilter output error: %s (code: %s)", this._tunerIndex, err.message, err.code);
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
            this._drainAlignedSuperframes();
        }
        this._flush();
        this._drain();
        this._sinkClosed = true;

        // Last-ditch write for data that couldn't be flushed (e.g., not ready)
        if (this._buffer?.length && this._output && !this._output.destroyed) {
            try {
                this._output.write(Buffer.concat(this._buffer));
            } catch {
                // ignore
            }
        }
        this._buffer = null;

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

    private _parseRelativeStreamNumbers(payload: Buffer): number[] {
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
                    "TunerDevice#%d TSMFFilter target stream %d is not TLV, fallback to %d",
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

        const numberOfCarriers = payload[124];
        const carrierSequence = payload[125];
        if (numberOfCarriers < 1 || numberOfCarriers > 16 || carrierSequence < 1 || carrierSequence > numberOfCarriers) {
            return null;
        }

        const frameRaw = payload[126];

        return {
            frameType: payload[2] & 0x0f,
            headerCRC: (payload[180] << 24) | (payload[181] << 16) | (payload[182] << 8) | payload[183],
            framePosition: frameRaw & 0x0f,
            numberOfFrames: (frameRaw >> 4) & 0x0f,
            frameSync,
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
