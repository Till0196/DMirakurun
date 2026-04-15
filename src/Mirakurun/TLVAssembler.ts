import { Writable } from "stream";
import EventEmitter = require("eventemitter3");
import * as log from "./log";
import type { CarrierSuperframe } from "./TSMFFilter";

// TS packet constants
const PACKET_SIZE = 188;
const TS_SYNC_BYTE = 0x47;

// TLV packet constants (ARIB STD-B32)
const TLV_SYNC_BYTE = 0x7f;
const TLV_HEADER_SIZE = 4; // sync(1) + type(1) + length(2)
const TLV_TYPE_HEADER_COMPRESSED_IP = 0x03;

// Compressed IP header sizes
const CID_HEADER_BASE = 3;
const CID_HEADER_0x60_EXTRA = 42;

// Offset detection parameters
const OFFSET_MIN_SFS = 30;
const OFFSET_RETRY_SFS = 30;
const OFFSET_MMTP_MIN_PACKETS = 16;
const OFFSET_MAX_DROP_RATIO = 0.05;
// Upper bound on per-carrier superframes kept while offset detection is still
// pending. At ~15 frames × 52 × 188B ≈ 146KB/SF × 3 carriers, 600 SFs caps the
// pending state at ~260MB — enough for retries but prevents OOM if detection
// never commits (e.g. one carrier never arrives).
const OFFSET_MAX_KEEP = 600;
const READY_MIN_SUPERFRAMES = 2;
const OUTPUT_MIN_BUFFER_SFS = 2;

interface CarrierBucket {
    carrierSequence: number;
    superframes: CarrierSuperframe[];
}

/**
 * TLV layer of the TSMF→MPEG-TS pipeline.
 *
 * Receives completed superframes from the TSMF parser (TSMFDemuxer),
 * detects per-carrier offsets, interleaves slots in TSMF order, and
 * writes the resulting TLV byte stream to the configured Writable sink.
 *
 * Single-carrier streams skip offset detection entirely.
 */
export default class TLVAssembler extends EventEmitter {

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
    private _carriers = new Map<number, CarrierBucket>();
    private _numberOfCarriers = 0;

    private _offsets: number[] | null = null;
    private _offsetsApplied = false;
    private _outputSuperframeCount = 0;
    private _probeInProgress = false;
    private _nextProbeThreshold = 0;

    private _buffer: Buffer[] = [];
    private _pendingOutput: Buffer = Buffer.alloc(0);
    private _ready = false;
    private _closed = false;
    private _closing = false;
    private _sinkClosed = false;
    private _drainWaiting = false;

    constructor(tunerIndex: number, output: Writable | null) {
        super();
        this._tunerIndex = tunerIndex;
        this._output = output;
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

    setOutput(output: Writable): void {
        this._output = output;
        this._setupOutputHandlers();
    }

    setNumberOfCarriers(n: number): void {
        this._numberOfCarriers = n;
    }

    /** Reset all carrier state. Used by TSMFDemuxer on resetCarriers. */
    resetCarriers(): void {
        this._carriers.clear();
        this._offsets = null;
        this._offsetsApplied = false;
        this._numberOfCarriers = 0;
        this._nextProbeThreshold = 0;
        this._outputSuperframeCount = 0;
    }

    pushSuperframe(carrierSequence: number, sf: CarrierSuperframe): void {
        if (this._closed || this._closing) {
            return;
        }
        let bucket = this._carriers.get(carrierSequence);
        if (!bucket) {
            bucket = { carrierSequence, superframes: [] };
            this._carriers.set(carrierSequence, bucket);
        }
        bucket.superframes.push(sf);
        if (!this._offsets && bucket.superframes.length > OFFSET_MAX_KEEP) {
            bucket.superframes.splice(0, bucket.superframes.length - OFFSET_MAX_KEEP);
        }

        this._detectOffsets();
        this._drainFrames();
    }

    close(): void {
        if (this._closed || this._closing) {
            return;
        }
        this._close();
    }

    // --- Private ---

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

    private _carriersBySequence(): CarrierBucket[] {
        return Array.from(this._carriers.values()).sort((a, b) => a.carrierSequence - b.carrierSequence);
    }

    private _detectOffsets(): void {
        if (this._offsets || this._probeInProgress) {
            return;
        }
        if (this._numberOfCarriers === 0 || this._carriers.size < this._numberOfCarriers) {
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
        this._offsetsApplied = false;
        ((this._numberOfCarriers > 1) ? log.info : log.debug)(
            "TunerDevice#%d TSMF offsets finalized: %s", this._tunerIndex, offsets.join(",")
        );
        if (this._buffer.length) {
            this._buffer.length = 0;
        }
    }

    private _candidates(carriers: CarrierBucket[]): number[][] {
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
    private _probeOffsets(carriers: CarrierBucket[]): number[] | null {
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
            const syncStart = TLVAssembler._findTlvSync(tlv);
            if (syncStart < 0) {
                continue;
            }

            const stats = this._probeMmtp(tlv, syncStart);
            if (stats.mmtpPackets < OFFSET_MMTP_MIN_PACKETS) {
                continue;
            }

            // Perfect match — accept immediately
            if (stats.mmtpDrops === 0) {
                ((this._numberOfCarriers > 1) ? log.info : log.debug)(
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
            ((this._numberOfCarriers > 1) ? log.info : log.debug)(
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
        carriers: CarrierBucket[],
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
            const payload = TLVAssembler._extractTlvPayload(packet);
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
        if (!this._offsets || this._carriers.size === 0) {
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

        // Write any pending output to the sink WITHOUT flushing the partial
        // _buffer (which is still accumulating bytes for the in-progress TLV
        // packet — its bytes will arrive in the next drain batch via non-PUSI
        // slots, and `_buffer` is only flushed when the next PUSI arrives in
        // `_onTLV`). Flushing it here would write an incomplete TLV packet
        // and leave the next batch's continuation bytes orphaned.
        this._writePending();
        for (const carrier of carriers) {
            carrier.superframes.splice(0, drainCount);
        }
    }

    private _onTLV(packet: Buffer): void {
        if (this._closed || this._closing) {
            return;
        }
        const tlvChunk = TLVAssembler._extractTlvPayload(packet);
        if (!tlvChunk) {
            return;
        }

        const pusi = (packet[1] & 0x40) !== 0;
        if (pusi) {
            // PUSI marks the start of a new TLV packet, so the previous
            // partial buffer (if any) is now complete and can be flushed.
            if (this._buffer.length > 0) {
                this._flushPartialBuffer();
                this._writePending();
            }
            this._buffer.push(Buffer.from(tlvChunk));
        } else {
            if (this._buffer.length === 0) {
                return;
            }
            this._buffer.push(tlvChunk);
        }
    }

    /**
     * Move accumulated TLV chunks (`_buffer`) into `_pendingOutput`.
     * Caller MUST guarantee that `_buffer` represents a complete TLV packet
     * (i.e. invoked at PUSI=1 boundary). Does not write to the sink.
     */
    private _flushPartialBuffer(): void {
        if (this._sinkClosed || this._buffer.length === 0) {
            return;
        }
        if (!this._offsets && this._numberOfCarriers > 1) {
            return;
        }
        if (!this._ready) {
            if (this._offsets && !this._offsetsApplied) {
                return;
            }
            if (this._numberOfCarriers > 1 && (!this._offsets || this._outputSuperframeCount < READY_MIN_SUPERFRAMES)) {
                return;
            }
            this._ready = true;
            log.debug("TunerDevice#%d TSMF first TLV packet ready", this._tunerIndex);
            process.nextTick(() => this.emit("ready"));
        }
        if (!this._output || this._output.destroyed || (this._output as any).writableEnded) {
            this._buffer.length = 0;
            if (this._output) {
                this._sinkClosed = true;
            }
            return;
        }
        this._pendingOutput = this._pendingOutput.length === 0
            ? Buffer.concat(this._buffer)
            : Buffer.concat([this._pendingOutput, ...this._buffer]);
        this._buffer.length = 0;
    }

    /** Write `_pendingOutput` to the sink, honoring backpressure. */
    private _writePending(): void {
        if (this._sinkClosed || this._pendingOutput.length === 0 || this._drainWaiting) {
            return;
        }
        if (!this._output || this._output.destroyed || (this._output as any).writableEnded) {
            this._sinkClosed = true;
            return;
        }

        const outputData = this._pendingOutput;
        this._pendingOutput = Buffer.alloc(0);

        try {
            if (!this._output.write(outputData)) {
                this._drainWaiting = true;
                this._output.once("drain", () => {
                    this._drainWaiting = false;
                    if (this._pendingOutput.length > 0 && !this._sinkClosed) {
                        this._writePending();
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
        // On close, force-flush whatever's in `_buffer` even though it may
        // be a partial TLV packet — no more bytes will arrive to complete it.
        this._flushPartialBuffer();
        this._writePending();
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
}
