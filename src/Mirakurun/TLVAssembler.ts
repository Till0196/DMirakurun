import { Writable } from "stream";
import EventEmitter = require("eventemitter3");
import * as log from "./log";
import type { CarrierSuperframe } from "./TSMFFilter";

// TS packet constants
const PACKET_SIZE = 188;
const TS_SYNC_BYTE = 0x47;

// TLV packet constants
const TLV_SYNC_BYTE = 0x7f;
const TLV_HEADER_SIZE = 4; // sync(1) + type(1) + length(2)
const TLV_TYPE_IPV4 = 0x01;
const TLV_TYPE_IPV6 = 0x02;
const TLV_TYPE_HEADER_COMPRESSED_IP = 0x03;
const TLV_TYPE_SIGNALLING = 0xfe;
const TLV_TYPE_NULL = 0xff;

// Compressed IP header type bytes
const CID_TYPE_PARTIAL_IPV4_UDP = 0x20;
const CID_TYPE_IPV4_IDENTIFIER = 0x21;
const CID_TYPE_PARTIAL_IPV6_UDP = 0x60;
const CID_TYPE_NO_COMPRESSED_HEADER = 0x61;

// Offset detection parameters
const OFFSET_MIN_SFS = 10;
const OFFSET_RETRY_SFS = 60;
const OFFSET_MIN_CID_PACKETS = 16;
// Sanity backstop only — rejects candidates that are clearly broken.
// Disambiguation between surviving candidates is done by margin below, not
// by how close this floor is to 1.0 (the tail of the probe window is nearly
// always a truncated TLV packet, so even a correct candidate rarely reaches
// exactly 1.0).
const OFFSET_VALID_RATIO_FLOOR = 0.9;
// The best candidate must beat the runner-up by at least this much, or the
// probe is inconclusive and retried later with more accumulated data.
const OFFSET_VALID_RATIO_MARGIN = 0.02;
const OFFSET_MAX_PROBE_FAILURES = 3;
// Consecutive TLV-sync misses on the already-committed live output before
// we conclude alignment has drifted and re-probe from scratch.
const RESYNC_MISS_THRESHOLD = 3;
const RESYNC_MAX_ATTEMPTS = 5;
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

export default class TLVAssembler extends EventEmitter {

    // Find a valid TLV sync position by verifying 3 consecutive chained packets.
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

    // PUSI=1: skip pointer field
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
    private _probeFailures = 0;
    private _syncMisses = 0;
    private _resyncCount = 0;

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

    resetCarriers(): void {
        this._carriers.clear();
        this._offsets = null;
        this._offsetsApplied = false;
        this._numberOfCarriers = 0;
        this._nextProbeThreshold = 0;
        this._outputSuperframeCount = 0;
        this._probeFailures = 0;
        this._syncMisses = 0;
        this._resyncCount = 0;
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
            this._probeFailures = 0;
            this._commitOffsets(result);
        } else {
            this._probeFailures++;
            this._nextProbeThreshold = accumulated + OFFSET_RETRY_SFS;
            if (this._probeFailures >= OFFSET_MAX_PROBE_FAILURES) {
                log.error(
                    "TunerDevice#%d TSMF offset probe failed %d times (likely frame loss or signal issue) — closing",
                    this._tunerIndex, this._probeFailures
                );
                this._close();
            }
        }
    }

    // Like resetCarriers(), but keeps _numberOfCarriers: it's a stable
    // property of the broadcast (signalled per TSMF frame), not something
    // that needs rediscovery when only the alignment has drifted. Used when
    // the live output loses TLV sync after offsets were already committed.
    private _resyncOffsets(): void {
        this._carriers.clear();
        this._offsets = null;
        this._offsetsApplied = false;
        this._nextProbeThreshold = 0;
        this._outputSuperframeCount = 0;
        this._probeFailures = 0;
        this._syncMisses = 0;
    }

    private _commitOffsets(offsets: number[]): void {
        this._offsets = offsets;
        this._offsetsApplied = false;
        log.info("TunerDevice#%d TSMF offsets finalized: %s", this._tunerIndex, offsets.join(","));
        if (this._buffer.length) {
            this._buffer.length = 0;
        }
    }

    private _probeOffsets(carriers: CarrierBucket[]): number[] | null {
        const candidates = this._buildOffsetCandidates(carriers);
        const results: { offsets: number[]; validRatio: number; tried: number }[] = [];

        for (let i = 0; i < candidates.length; i++) {
            if (this._closed || this._closing) {
                return null;
            }
            const offsets = candidates[i];
            const packets = this._alignPackets(carriers, offsets, 30);
            if (packets.length === 0) {
                continue;
            }
            const tlv = this._assembleTlv(packets);
            const syncStart = TLVAssembler._findTlvSync(tlv);
            if (syncStart < 0) {
                continue;
            }
            const stats = this._measureTlvIntegrity(tlv, syncStart);
            if (stats.validRatio < OFFSET_VALID_RATIO_FLOOR ||
                stats.cidTotal < OFFSET_MIN_CID_PACKETS ||
                stats.cidOk !== stats.cidTotal) {
                continue;
            }
            results.push({ offsets, validRatio: stats.validRatio, tried: i + 1 });
        }

        if (results.length === 0) {
            return null;
        }
        results.sort((a, b) => b.validRatio - a.validRatio);
        const [best, runnerUp] = results;
        if (runnerUp && best.validRatio - runnerUp.validRatio < OFFSET_VALID_RATIO_MARGIN) {
            log.debug(
                "TunerDevice#%d TSMF offset probe ambiguous: best=%s (valid=%s%%) vs runner-up=%s (valid=%s%%) — retrying with more data",
                this._tunerIndex,
                best.offsets.join(","), (best.validRatio * 100).toFixed(2),
                runnerUp.offsets.join(","), (runnerUp.validRatio * 100).toFixed(2)
            );
            return null;
        }

        log.info(
            "TunerDevice#%d TSMF offsets=%s (tried %d/%d)",
            this._tunerIndex, best.offsets.join(","),
            best.tried, candidates.length
        );
        return best.offsets;
    }

    // base = sfCounts - minSf, ±1 single/two-axis, ±2 single-axis
    private _buildOffsetCandidates(carriers: CarrierBucket[]): number[][] {
        const sfCounts = carriers.map(c => c.superframes.length);
        const minSf = Math.min(...sfCounts);
        const base = sfCounts.map(sf => sf - minSf);
        const seen = new Set<string>();
        const candidates: number[][] = [];

        // With 2+ carriers, only the *relative* offsets between carriers
        // (their pairwise skew) represent a distinct alignment hypothesis —
        // shifting every carrier by the same amount re-tests the exact same
        // skew against a different window of buffered superframes (e.g.
        // base=[0,0] vs the matching-sign two-axis candidate [1,1]).
        // Keeping both feeds _probeOffsets two near-identical-quality
        // "competing" candidates, which can spuriously trip the runner-up
        // margin check below. Dedupe on that relative signature instead of
        // the absolute one so only genuinely different skews are tried.
        // With a single carrier there is no cross-carrier skew, so every
        // absolute shift is its own hypothesis (e.g. skipping a corrupted
        // leading superframe) and must stay distinguishable.
        const keyOf = (offsets: number[]): string =>
            carriers.length > 1 ? offsets.map(v => v - offsets[0]).join(",") : offsets.join(",");

        const add = (offsets: number[]): void => {
            if (offsets.some(v => v < 0)) {
                return;
            }
            const key = keyOf(offsets);
            if (seen.has(key)) {
                return;
            }
            seen.add(key);
            candidates.push(offsets);
        };

        add(base);

        // ±1 single-axis
        for (let i = 0; i < carriers.length; i++) {
            const plus = base.slice(); plus[i] += 1; add(plus);
            const minus = base.slice(); minus[i] -= 1; add(minus);
        }

        // ±1 two-axis pairs
        for (let i = 0; i < carriers.length; i++) {
            for (let j = i + 1; j < carriers.length; j++) {
                for (const signI of [-1, 1]) {
                    for (const signJ of [-1, 1]) {
                        const offsets = base.slice();
                        offsets[i] += signI;
                        offsets[j] += signJ;
                        add(offsets);
                    }
                }
            }
        }

        // ±2 single-axis
        for (let i = 0; i < carriers.length; i++) {
            const plus = base.slice(); plus[i] += 2; add(plus);
            const minus = base.slice(); minus[i] -= 2; add(minus);
        }

        return candidates;
    }

    private _measureTlvIntegrity(
        buffer: Buffer,
        start: number
    ): { validBytes: number; totalBytes: number; validRatio: number; cidOk: number; cidTotal: number } {
        let offset = start;
        let cidOk = 0;
        let cidTotal = 0;
        while (offset + TLV_HEADER_SIZE <= buffer.length) {
            if (buffer[offset] !== TLV_SYNC_BYTE) {
                break;
            }
            const type = buffer[offset + 1];
            if (type !== TLV_TYPE_IPV4 && type !== TLV_TYPE_IPV6 &&
                type !== TLV_TYPE_HEADER_COMPRESSED_IP &&
                type !== TLV_TYPE_SIGNALLING && type !== TLV_TYPE_NULL) {
                break;
            }
            const length = (buffer[offset + 2] << 8) | buffer[offset + 3];
            const next = offset + TLV_HEADER_SIZE + length;
            if (next > buffer.length) {
                break;
            }
            if (type === TLV_TYPE_HEADER_COMPRESSED_IP && length >= 3) {
                cidTotal++;
                const cid = buffer[offset + TLV_HEADER_SIZE + 2];
                if (cid !== CID_TYPE_PARTIAL_IPV4_UDP && cid !== CID_TYPE_IPV4_IDENTIFIER &&
                    cid !== CID_TYPE_PARTIAL_IPV6_UDP && cid !== CID_TYPE_NO_COMPRESSED_HEADER) {
                    break;
                }
                cidOk++;
            }
            offset = next;
        }
        const validBytes = offset - start;
        const totalBytes = Math.max(1, buffer.length - start);
        return { validBytes, totalBytes, validRatio: validBytes / totalBytes, cidOk, cidTotal };
    }

    private _forEachSlot(
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
            this._forEachSlot(sfs, packet => outputChunks.push(packet));
        }
        return outputChunks;
    }

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
            this._forEachSlot(sfs, packet => this._onTLV(packet));
            this._outputSuperframeCount++;
            // _onTLV may have called _resyncOffsets() on a sync-loss; stop
            // feeding it more slots from the now-stale alignment.
            if (!this._offsets) {
                break;
            }
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
            // PUSI=1 means this payload should start exactly on a TLV sync
            // byte (see _extractTlvPayload's pointer-field skip). This holds
            // for free as long as carrier alignment is still correct, so it
            // doubles as a continuous, near-zero-cost integrity check on the
            // already-committed offsets — catching drift that the one-shot
            // probe on a 30-superframe window can't see (e.g. a carrier
            // silently dropping a superframe later in the session).
            const synced = tlvChunk[0] === TLV_SYNC_BYTE;
            if (synced) {
                this._syncMisses = 0;
            } else if (++this._syncMisses >= RESYNC_MISS_THRESHOLD) {
                const attempt = ++this._resyncCount;
                const offsetsBeforeReset = this._offsets ? this._offsets.join(",") : "?";
                // Reset state (and null out _offsets) *before* possibly
                // calling _close() below — _close() re-enters _drainFrames()
                // while _offsets is still set, which would otherwise recurse
                // back into the very loop that got us here.
                this._resyncOffsets();
                if (attempt > RESYNC_MAX_ATTEMPTS) {
                    log.error(
                        "TunerDevice#%d TSMF lost TLV sync on live output %d times — giving up",
                        this._tunerIndex, attempt
                    );
                    this._close();
                } else {
                    log.warn(
                        "TunerDevice#%d TSMF lost TLV sync on live output (offsets=%s) — re-probing (%d/%d)",
                        this._tunerIndex, offsetsBeforeReset, attempt, RESYNC_MAX_ATTEMPTS
                    );
                }
                return;
            }

            // PUSI marks the start of a new TLV packet, so the previous
            // (already sync-verified) packet is now complete and can be
            // flushed.
            if (this._buffer.length > 0) {
                this._flushPartialBuffer();
                this._writePending();
            }
            // Only start accumulating the new packet if its own sync byte
            // checked out. A miss here means this one packet is either a
            // stray bit error or the leading edge of real drift — either
            // way, don't let it (or its continuation bytes, via the
            // _buffer.length===0 guard below) reach the output. Better to
            // drop one TLV packet than to emit a corrupted one; downstream
            // already has to tolerate lost packets.
            if (synced) {
                this._buffer.push(Buffer.from(tlvChunk));
            }
        } else {
            if (this._buffer.length === 0) {
                return;
            }
            this._buffer.push(tlvChunk);
        }
    }

    // flush _buffer into _pendingOutput (caller must invoke at PUSI=1 boundary)
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
