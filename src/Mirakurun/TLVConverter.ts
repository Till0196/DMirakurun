import { Writable } from "stream";
import * as stream from "stream";
import { EventEmitter } from "eventemitter3";
import * as log from "./log";

const PACKET_SIZE = 188;
const TLV_PID = 0x2d;
const TSMF_PID = 0x2f;
const SLOT_COUNT = 52 as const;
const TS_SYNC_BYTE = 0x47;
// TSMF sync patterns (ARIB STD-B32)
// Calculated as ((AFL << 8) | first_AF_byte) & 0x1fff
// AFL=0xfa -> 0x1a86, AFL=0xe5 -> 0x0579
const TSMF_SYNC_A = 0x1a86;
const TSMF_SYNC_B = 0x0579;
const AFC_ADAPTATION_ONLY = 0x01;
const AFC_WITH_ADAPTATION = 0x03;
const OFFSET_MIN_SUPERFRAMES = 3;
const OFFSET_STABLE_REQUIRED = 3;
const OFFSET_MIN_TLV_PACKETS = 8;
const OFFSET_MIN_HEADER_RATIO = 0.6;

interface CarrierFrame {
    framePosition: number;
    numberOfFrames: number;
    slots: Buffer[];
    targetSlots: boolean[];
    filledSlots: number;
    signature?: string;
}

interface CarrierSuperframe {
    numberOfFrames: number;
    frames: CarrierFrame[];
    signature?: string;
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
    private _pendingOffsets: number[] | null = null;
    private _pendingOffsetsStable = 0;
    private _readySuperframes = 0;
    private _loggedOffsetsBeforeReady = false;

    private _closed = false;
    private _closing = false;
    private _sinkClosed = false;
    private _drainWaiting = false;
    private _ready = false;
    private _crcTable?: number[];

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
            streamTypeBits: 0
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
                    } else {
                        log.warn("TunerDevice#%d TLVConverter TS resync failed at chunk head", this._tunerIndex);
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
        const payload = this._extractTSMFPayload(packet);
        if (!payload) {
            return;
        }

        const frameInfo = this._validateTSMFFrame(payload);
        if (!frameInfo) {
            return;
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

        const targetSlots = this._buildTargetSlots(source);
        const signature = frameInfo.framePosition === 0 ? this._buildTSMFSignature(payload) : undefined;

        source.currentFrame = {
            framePosition: frameInfo.framePosition,
            numberOfFrames: frameInfo.numberOfFrames,
            slots: [],
            targetSlots,
            filledSlots: 0,
            signature
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
        carriers: { numberOfCarriers: number; carrierSequence: number },
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

        if (source.carrierSequence && source.carrierSequence !== carrierSequence) {
            log.warn(
                "TunerDevice#%d TLVConverter source carrier sequence changed %d -> %d",
                this._tunerIndex, source.carrierSequence, carrierSequence
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
            this._maybeApplyOffsets();
            carrier.superframes.push({
                numberOfFrames: n,
                frames,
                signature: this._getSuperframeSignature(frames)
            });
            this._outputAvailableSuperframes();
        }
    }

    private _maybeApplyOffsets(): void {
        if (this._offsets) {
            return;
        }
        if (this._carrierStates.size === 0 || this._numberOfCarriers === 0) {
            return;
        }
        if (this._carrierStates.size < this._numberOfCarriers) {
            return;
        }
        const carriers = this._getCarriersSorted();
        const minAvailable = Math.min(...carriers.map(c => c.superframes.length));
        if (minAvailable <= 0) {
            return;
        }
        if (minAvailable < OFFSET_MIN_SUPERFRAMES) {
            return;
        }

        if (this._offsetsFromOptions && this._offsetsFromOptions.length >= this._numberOfCarriers) {
            this._finalizeOffsets(this._offsetsFromOptions.slice(0, this._numberOfCarriers));
            return;
        }

        const maxOffset = Math.min(12, minAvailable - 1);
        const preview = Math.min(60, minAvailable);
        if (maxOffset < 0 || preview < 2) {
            return;
        }

        const headerOffsets = this._findOffsetsByHeaderSync(carriers, maxOffset, preview);
        const tlvOffsets = this._findOffsetsByTLVHeuristics(carriers, maxOffset, preview);

        let offsets = tlvOffsets;
        if (headerOffsets) {
            const headerScore = this._scoreTLVBuffer(
                this._assembleTLVFromPackets(this._assemblePacketsForOffsets(carriers, headerOffsets, preview))
            );
            const tlvScore = this._scoreTLVBuffer(
                this._assembleTLVFromPackets(this._assemblePacketsForOffsets(carriers, tlvOffsets, preview))
            );
            offsets = headerScore >= tlvScore ? headerOffsets : tlvOffsets;
        }

        const tlvBuffer = this._assembleTLVFromPackets(this._assemblePacketsForOffsets(carriers, offsets, preview));
        const evaluation = this._evaluateTLVBuffer(tlvBuffer);
        if (evaluation.total < OFFSET_MIN_TLV_PACKETS || evaluation.headerRatio < OFFSET_MIN_HEADER_RATIO) {
            this._pendingOffsets = null;
            this._pendingOffsetsStable = 0;
            return;
        }

        if (!this._pendingOffsets || !this._areOffsetsEqual(this._pendingOffsets, offsets)) {
            this._pendingOffsets = offsets.slice();
            this._pendingOffsetsStable = 1;
            return;
        }

        this._pendingOffsetsStable += 1;
        if (this._pendingOffsetsStable < OFFSET_STABLE_REQUIRED) {
            return;
        }

        this._finalizeOffsets(offsets);
    }

    private _finalizeOffsets(offsets: number[]): void {
        this._offsets = offsets;
        this._freezeHeader = true;
        this._offsetsApplied = false;
        this._pendingOffsets = null;
        this._pendingOffsetsStable = 0;
        if (this._buffer && this._buffer.length > 0) {
            // Drop pre-offset TLV fragments to avoid feeding invalid data to decoder.
            this._buffer.length = 0;
        }
        // Reset carrier state to re-align from next header after offsets are fixed.
        for (const carrier of this._carrierStates.values()) {
            carrier.blocks = [];
            carrier.superframes = [];
        }
        for (const source of this._sources.values()) {
            source.currentFrame = undefined;
        }
        // offsets will be applied when outputting superframes
    }

    private _areOffsetsEqual(a: number[], b: number[]): boolean {
        if (a.length !== b.length) {
            return false;
        }
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) {
                return false;
            }
        }
        return true;
    }

    private _evaluateTLVBuffer(buffer: Buffer): { score: number; headerRatio: number; total: number } {
        const maxPackets = 2000;
        const maxStart = Math.min(4096, buffer.length > 4 ? buffer.length - 4 : 0);
        let bestScore = 0;
        let bestHeaderRatio = 0;
        let bestTotal = 0;

        const evaluate = (start: number): { score: number; headerRatio: number; total: number } => {
            let offset = start;
            let validHeaders = 0;
            let validIpv6 = 0;
            let validNull = 0;
            let validTypes = 0;
            let total = 0;

            while (offset + 4 <= buffer.length && total < maxPackets) {
                if (buffer[offset] !== 0x7f) {
                    break;
                }
                const type = buffer[offset + 1];
                const length = (buffer[offset + 2] << 8) | buffer[offset + 3];
                const next = offset + 4 + length;
                if (next > buffer.length) {
                    break;
                }
                const payload = buffer.subarray(offset + 4, next);
                const typeValid = type === 0x01 || type === 0x02 || type === 0x03 || type === 0xfe || type === 0xff;
                if (!typeValid) {
                    break;
                }
                validHeaders += 1;
                validTypes += 1;
                if (type === 0x02 && payload.length >= 40 && (payload[0] >> 4) === 0x06) {
                    const payloadLength = (payload[4] << 8) | payload[5];
                    if (payloadLength + 40 === payload.length) {
                        validIpv6 += 1;
                    }
                }
                if (type === 0xff) {
                    let ok = true;
                    for (let i = 0; i < payload.length; i++) {
                        if (payload[i] !== 0xff) {
                            ok = false;
                            break;
                        }
                    }
                    if (ok) {
                        validNull += 1;
                    }
                }
                if (next < buffer.length && buffer[next] !== 0x7f) {
                    break;
                }
                offset = next;
                total += 1;
            }

            if (total === 0) {
                return { score: 0, headerRatio: 0, total: 0 };
            }
            const headerRatio = validHeaders / total;
            const ipv6Ratio = validIpv6 / total;
            const score = headerRatio * 1000000 + ipv6Ratio * 500000 + validNull * 500 + validTypes * 100 + total;
            return { score, headerRatio, total };
        };

        for (let start = 0; start < maxStart; start++) {
            const result = evaluate(start);
            if (result.score > bestScore) {
                bestScore = result.score;
                bestHeaderRatio = result.headerRatio;
                bestTotal = result.total;
            }
        }

        return { score: bestScore, headerRatio: bestHeaderRatio, total: bestTotal };
    }

    private _findOffsetsByTLVHeuristics(
        carriers: CarrierState[],
        maxOffset: number,
        previewSuperframes: number
    ): number[] {
        const offsets = new Array(carriers.length).fill(0);
        let bestScore = -1;
        let bestOffsets = offsets.slice();

        const evaluate = () => {
            const packets = this._assemblePacketsForOffsets(carriers, offsets, previewSuperframes);
            if (packets.length === 0) {
                return;
            }
            const tlv = this._assembleTLVFromPackets(packets);
            const score = this._scoreTLVBuffer(tlv);
            if (score > bestScore) {
                bestScore = score;
                bestOffsets = offsets.slice();
            }
        };

        const search = (index: number) => {
            if (index >= carriers.length) {
                evaluate();
                return;
            }
            for (let o = 0; o <= maxOffset; o++) {
                offsets[index] = o;
                search(index + 1);
            }
        };

        if (carriers.length > 0) {
            offsets[0] = 0;
            search(1);
        } else {
            evaluate();
        }

        return bestOffsets;
    }

    private _findOffsetsByHeaderSync(
        carriers: CarrierState[],
        maxOffset: number,
        previewSuperframes: number
    ): number[] | null {
        if (carriers.length === 0) {
            return null;
        }

        const offsets = new Array(carriers.length).fill(0);
        const reference = carriers[0].superframes.map(sf => sf.signature || null);
        const refCount = reference.length;
        if (refCount === 0) {
            return null;
        }

        let bestScoreAcross = 0;
        for (let i = 1; i < carriers.length; i++) {
            const candidate = carriers[i].superframes.map(sf => sf.signature || null);
            if (candidate.length === 0) {
                continue;
            }

            let bestOffset = 0;
            let bestScore = -1;
            let bestMatches = -1;
            let bestTotal = 0;

            for (let o = 0; o <= maxOffset; o++) {
                const count = Math.min(refCount, candidate.length - o, previewSuperframes);
                if (count <= 0) {
                    continue;
                }
                let matches = 0;
                let total = 0;
                for (let k = 0; k < count; k++) {
                    const refSig = reference[k];
                    const candSig = candidate[o + k];
                    if (!refSig || !candSig) {
                        continue;
                    }
                    total += 1;
                    if (refSig === candSig) {
                        matches += 1;
                    }
                }
                const score = total > 0 ? matches / total : 0;
                if (
                    score > bestScore ||
                    (score === bestScore && matches > bestMatches) ||
                    (score === bestScore && matches === bestMatches && total > bestTotal)
                ) {
                    bestScore = score;
                    bestMatches = matches;
                    bestTotal = total;
                    bestOffset = o;
                }
            }

            offsets[i] = bestOffset;
            if (bestScore > bestScoreAcross) {
                bestScoreAcross = bestScore;
            }
        }

        if (bestScoreAcross <= 0) {
            return null;
        }

        return offsets;
    }

    private _buildTSMFSignature(payload: Buffer): string {
        const sig = Buffer.from(payload);
        sig[125] = 0; // carrier_sequence
        sig[126] &= 0xf0; // frame_position
        return sig.toString("hex");
    }

    private _getSuperframeSignature(frames: CarrierFrame[]): string | undefined {
        for (const frame of frames) {
            if (frame && frame.framePosition === 0 && frame.signature) {
                return frame.signature;
            }
        }
        return undefined;
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

    private _assembleTLVFromPackets(packets: Buffer[]): Buffer {
        const output: Buffer[] = [];
        let current: Buffer | null = null;

        for (const packet of packets) {
            if (packet.length !== PACKET_SIZE || packet[0] !== TS_SYNC_BYTE) {
                continue;
            }
            const pusi = (packet[1] & 0x40) !== 0;
            if (pusi) {
                const payload = packet.subarray(3);
                if (payload.length === 0) {
                    continue;
                }
                if (current) {
                    output.push(current);
                }
                const tlvChunk = packet.subarray(4);
                current = tlvChunk.length > 0 ? Buffer.from(tlvChunk) : null;
            } else {
                const tlvChunk = packet.subarray(3);
                if (tlvChunk.length === 0) {
                    continue;
                }
                current = current ? Buffer.concat([current, tlvChunk]) : Buffer.from(tlvChunk);
            }
        }

        if (current) {
            output.push(current);
        }

        return Buffer.concat(output);
    }

    private _scoreTLVBuffer(buffer: Buffer): number {
        const maxPackets = 5000;
        const maxStart = Math.min(16384, buffer.length > 4 ? buffer.length - 4 : 0);
        let bestScore = 0;

        const evaluate = (start: number): number => {
            let offset = start;
            let validHeaders = 0;
            let validTypes = 0;
            let validIpv6 = 0;
            let validNull = 0;
            let total = 0;

            while (offset + 4 <= buffer.length && total < maxPackets) {
                if (buffer[offset] !== 0x7f) {
                    break;
                }
                const type = buffer[offset + 1];
                const length = (buffer[offset + 2] << 8) | buffer[offset + 3];
                const next = offset + 4 + length;
                if (next > buffer.length) {
                    break;
                }
                const payload = buffer.subarray(offset + 4, next);
                const typeValid = type === 0x01 || type === 0x02 || type === 0x03 || type === 0xfe || type === 0xff;
                if (!typeValid) {
                    break;
                }
                validHeaders += 1;
                if (typeValid) {
                    validTypes += 1;
                }
                if (type === 0x02 && payload.length >= 40 && (payload[0] >> 4) === 0x06) {
                    const payloadLength = (payload[4] << 8) | payload[5];
                    if (payloadLength + 40 === payload.length) {
                        validIpv6 += 1;
                    }
                }
                if (type === 0xff) {
                    let ok = true;
                    for (let i = 0; i < payload.length; i++) {
                        if (payload[i] !== 0xff) {
                            ok = false;
                            break;
                        }
                    }
                    if (ok) {
                        validNull += 1;
                    }
                }
                if (next < buffer.length && buffer[next] !== 0x7f) {
                    break;
                }
                offset = next;
                total += 1;
            }

            if (total === 0) {
                return 0;
            }
            const headerRatio = validHeaders / total;
            const ipv6Ratio = validIpv6 / total;
            return headerRatio * 1000000 + ipv6Ratio * 500000 + validNull * 500 + validTypes * 100 + total;
        };

        for (let start = 0; start < maxStart; start++) {
            const score = evaluate(start);
            if (score > bestScore) {
                bestScore = score;
            }
        }

        return bestScore;
    }

    private _isValidIpPacket(payload: Buffer): boolean {
        if (payload.length < 1) {
            return false;
        }
        const version = payload[0] >> 4;
        if (version === 4) {
            if (payload.length < 20) {
                return false;
            }
            const ihl = payload[0] & 0x0f;
            if (ihl < 5) {
                return false;
            }
            const totalLength = (payload[2] << 8) | payload[3];
            if (totalLength !== payload.length) {
                return false;
            }
            return totalLength >= ihl * 4;
        }
        if (version === 6) {
            if (payload.length < 40) {
                return false;
            }
            const payloadLength = (payload[4] << 8) | payload[5];
            return payloadLength + 40 === payload.length;
        }
        return false;
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
        if (minAvailable <= 0) {
            return;
        }

        for (let i = 0; i < minAvailable; i++) {
            this._outputSuperframe(carriers.map(c => c.superframes[i]));
            this._readySuperframes += 1;
        }

        carriers.forEach(carrier => {
            carrier.superframes.splice(0, minAvailable);
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
        if (packet.length !== PACKET_SIZE || packet[0] !== TS_SYNC_BYTE) {
            return;
        }
        const pusi = (packet[1] & 0x40) !== 0;
        if (pusi) {
            const payload = packet.subarray(3);
            if (payload.length === 0) {
                return;
            }
            if (this._buffer.length > 0) {
                this._flushBufferedOutput();
            }
            const tlvChunk = packet.subarray(4);
            if (tlvChunk.length > 0) {
                this._buffer.push(tlvChunk);
            }
        } else {
            const tlvChunk = packet.subarray(3);
            if (tlvChunk.length === 0) {
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
                if (this._readySuperframes < 10) {
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

        const outputData = Buffer.concat(this._buffer);
        this._buffer.length = 0;

        try {
            const writeSuccess = this._output.write(outputData);
            if (!writeSuccess) {
                this._drainWaiting = true;
                this._output.once("drain", () => {
                    this._drainWaiting = false;
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

        // AFC=1: Adaptation field only - TSMF data is in adaptation field
        // AFC=3: Adaptation field + payload
        // For TSMF, we return data starting from byte 4 (including AFL byte)
        // The sync pattern is encoded as ((AFL << 8) | first_AF_byte) & 0x1fff
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

        // CRC32 check
        if (this._calculateCRC32(payload) !== 0) {
            return null;
        }

        // TSMF structure (matching combine_transmod_tlv_correct.js):
        // payload[123] = groupId
        // payload[124] = numberOfCarriers
        // payload[125] = carrierSequence
        // payload[126] = frameRaw (upper 4 bits = numberOfFrames, lower 4 bits = framePosition)
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
