import { Writable } from "stream";
import * as stream from "stream";
import { EventEmitter } from "eventemitter3";
import * as log from "./log";

const PACKET_SIZE = 188;
const TLV_PID = 0x2d;
const TSMF_PID = 0x2f;
const SLOT_COUNT = 52 as const;
const TS_SYNC_BYTE = 0x47;
const TSMF_SYNC_A = 0x1a86;
const TSMF_SYNC_B = 0x0579;
const AFC_NO_PAYLOAD = 0x01;
const AFC_WITH_ADAPTATION = 0x03;
const TSMF_FRAME_TYPE_1 = 0x01;
const TSMF_FRAME_TYPE_2 = 0x02;

export default class TLVConverter extends EventEmitter {
    private _tunerIndex: number;
    private _output: Writable;

    private _buffer: Buffer[] = [];
    private _packet = Buffer.allocUnsafeSlow(PACKET_SIZE).fill(0);
    private _offset = -1;

    private _processedPackets = 0;
    private _tlvPackets = 0;

    private _closed = false;
    private _closing = false;
    private _sinkClosed = false;
    private _drainWaiting = false;
    private _ready = false;

    // --- ヘッダ管理・選択 ---
    private _headerLocked = false;
    private _activeHeaderCRC = -1;
    private _candidateHeaderCRC = -1;
    private _candidateSeen = 0;

    // TSMF関連
    private _tsmfRelativeStreamNumber: number[] = [];
    private _tsmfTsNumber = 1;
    private _numberOfCarriers = 0;
    private _carrierSequence = 0;

    // スロット追跡
    private _slotIndex = -1;
    private _effectiveTargetStreamNumber = 0;

    // CRC32計算用テーブル
    private _crcTable?: number[];

    // ログ用前回スナップショット
    private _lastLoggedHeaderCRC = -1;

    constructor(tunerIndex: number, output: Writable | null, tsmfRelTs?: number) {
        super();
        this._tunerIndex = tunerIndex;
        this._output = output;
        this._tsmfTsNumber = typeof tsmfRelTs === "number" ? tsmfRelTs : 0;

        if (this._output) {
            this._setupOutputHandlers();
        }

        log.debug("TunerDevice#%d TLVConverter created", this._tunerIndex);
    }

    get closed(): boolean {
        return this._closed;
    }

    get ready(): boolean {
        return this._ready;
    }

    get carrierInfo(): { numberOfCarriers: number; carrierSequence: number } {
        return { numberOfCarriers: this._numberOfCarriers, carrierSequence: this._carrierSequence };
    }

    get tsmfInfo(): { tsNumber: number; totalSlots: number } {
        return { tsNumber: this._tsmfTsNumber, totalSlots: this._tsmfRelativeStreamNumber.length };
    }

    setOutput(output: stream.Writable): void {
        this._output = output;
        this._setupOutputHandlers();
    }

    write(chunk: Buffer): void {
        if (!this._output) {
            // 出力先が設定されていない場合は処理を継続（バッファリングのみ）
        } else if (this._output.destroyed || (this._output as any).writableEnded) {
            this._sinkClosed = true;
            this._close();
            return;
        }

        this._flushBufferedOutput();

        let offset = 0;
        const length = chunk.length;
        const packets: Buffer[] = [];

        if (this._offset > 0) {
            const need = PACKET_SIZE - this._offset;
            if (length >= need) {
                const head = Buffer.concat([
                    this._packet.subarray(0, this._offset),
                    chunk.subarray(0, need)
                ]);
                this._offset = 0;

                if (head[0] === TS_SYNC_BYTE) {
                    packets.push(head);
                } else {
                    const p = head.indexOf(TS_SYNC_BYTE);
                    if (p >= 0 && head.length - p >= PACKET_SIZE) {
                        packets.push(head.subarray(p, p + PACKET_SIZE));
                    } else {
                        log.warn("TunerDevice#%d TS resync failed at chunk head", this._tunerIndex);
                    }
                }
                offset = need;
            } else {
                chunk.copy(this._packet, this._offset);
                this._offset += length;
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
            chunk.copy(this._packet, 0, offset);
            this._offset = length - offset;
        }

        this._processPackets(packets);
        this._flushBufferedOutput();
    }

    end(): void {
        if (!this._closed && !this._closing) {
            this._close();
        }
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

    private _flushBufferedOutput(): void {
        if (this._buffer.length === 0 || this._sinkClosed || this._drainWaiting || !this._headerLocked) {
            return;
        }

        // 初回TLV出力時にreadyイベントを発行（outputの有無に関わらず）
        if (!this._ready) {
            this._ready = true;
            log.debug("TunerDevice#%d TLVConverter: first TLV packet ready, emitting ready event", this._tunerIndex);
            process.nextTick(() => {
                this.emit("ready");
            });
        }

        // outputが設定されていない場合は、readyイベントのみ発行してreturn
        if (!this._output) {
            return;
        }

        if (this._output.destroyed || (this._output as any).writableEnded) {
            this._sinkClosed = true;
            return;
        }

        // 完全な分割TLVパケットを出力
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

    private _processPackets(packets: Buffer[]): void {
        for (const packet of packets) {
            this._processedPackets++;

            const pid = ((packet[1] & 0x1f) << 8) | packet[2];

            if (pid === TSMF_PID) {
                this._handleTSMFPacket(packet);
            }

            if (this._headerLocked && this._slotIndex >= 0) {
                const totalSlots = this._tsmfRelativeStreamNumber.length || SLOT_COUNT;
                const target = this._effectiveTargetStreamNumber;
                const curSlot = this._slotIndex % totalSlots;
                const streamInSlot = this._tsmfRelativeStreamNumber[curSlot] || 0;

                if (pid === TLV_PID && target > 0 && streamInSlot === target) {
                    this._handleTLVPacket(packet);
                }
            }
        }
    }

    /**
     * TSMFパケットからペイロードを抽出し、基本的な検証を行う
     */
    private _extractTSMFPayload(packet: Buffer): Buffer | null {
        if (packet.length !== PACKET_SIZE || packet[0] !== TS_SYNC_BYTE) {
            return null;
        }

        const afc = (packet[3] & 0x30) >> 4;
        if (afc !== AFC_NO_PAYLOAD && afc !== AFC_WITH_ADAPTATION) {
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

    /**
     * TSMFフレームの同期とCRC検証を行う
     */
    private _validateTSMFFrame(payload: Buffer): {
        frameType: number;
        headerCRC: number;
        framePosition: number;
        carriers: { numberOfCarriers: number; carrierSequence: number };
        groupId: number;
    } | null {
        const frameSync = ((payload[0] << 8) | payload[1]) & 0x1fff;
        if (frameSync !== TSMF_SYNC_A && frameSync !== TSMF_SYNC_B) {
            return null;
        }

        const frameType = payload[2] & 0x0f;
        if (frameType !== TSMF_FRAME_TYPE_1 && frameType !== TSMF_FRAME_TYPE_2) {
            return null;
        }

        if (this._calculateCRC32(payload) !== 0) {
            return null;
        }

        const headerCRC = (payload[180] << 24) | (payload[181] << 16) | (payload[182] << 8) | payload[183];

        const groupId = payload[123];
        const numberOfCarriers = payload[124];
        const carrierSequence = payload[125];
        if (numberOfCarriers < 1 || numberOfCarriers > 16 || carrierSequence < 1 || carrierSequence > numberOfCarriers) {
            if (this._lastLoggedHeaderCRC !== headerCRC) {
                log.warn(
                    "TunerDevice#%d Invalid carrier info: groupId=%d, carriers=%d, sequence=%d, skipping TSMF parsing",
                    this._tunerIndex,
                    groupId,
                    numberOfCarriers,
                    carrierSequence
                );
                this._lastLoggedHeaderCRC = headerCRC;
            }
            return null;
        }

        const frameRaw = payload[126];
        const framePosition = frameRaw & 0x0f;

        return {
            frameType,
            headerCRC,
            framePosition,
            carriers: { numberOfCarriers, carrierSequence },
            groupId
        };
    }

    /**
     * TSMFヘッダのロック/切替処理を行う
     */
    private _processTSMFHeader(
        payload: Buffer,
        frameInfo: {
            frameType: number;
            headerCRC: number;
            framePosition: number;
            carriers: { numberOfCarriers: number; carrierSequence: number };
            groupId: number;
        }
    ): void {
        const { frameType, headerCRC, framePosition, carriers, groupId } = frameInfo;
        const atFrameStart = framePosition === 0;

        if (!this._headerLocked) {
            if (!atFrameStart) {
                return;
            }
            if (headerCRC !== this._candidateHeaderCRC) {
                this._candidateHeaderCRC = headerCRC;
                this._candidateSeen = 1;
                return;
            }

            this._candidateSeen += 1;
            if (this._candidateSeen >= 2) {
                this._lockTSMFHeader(payload, headerCRC, frameType, carriers, groupId);
            }
        } else {
            if (headerCRC === this._activeHeaderCRC) {
                this._slotIndex = 0;
                return;
            }
            if (atFrameStart) {
                if (headerCRC !== this._candidateHeaderCRC) {
                    this._candidateHeaderCRC = headerCRC;
                    this._candidateSeen = 1;
                    return;
                }

                this._candidateSeen += 1;
                if (this._candidateSeen >= 2) {
                    this._lockTSMFHeader(payload, headerCRC, frameType, carriers, groupId);
                }
            }
        }
    }

    /**
     * TSMFヘッダをロック/切替する際の共通処理
     */
    private _lockTSMFHeader(
        payload: Buffer,
        headerCRC: number,
        frameType: number,
        carriers: { numberOfCarriers: number; carrierSequence: number },
        groupId: number
    ): void {
        log.debug("TunerDevice#%d TLVConverter: locking TSMF header, CRC=0x%s, frameType=%d, carriers=%d/%d, groupId=%d",
            this._tunerIndex, headerCRC.toString(16), frameType, carriers.carrierSequence, carriers.numberOfCarriers, groupId);
        this._applyTSMFHeader(payload, frameType, carriers.numberOfCarriers, carriers.carrierSequence, headerCRC, groupId);
    }

    /**
     * TSMF パケットを処理し、ヘッダをロック/切替、フレーム先頭で位相を同期する。
     */
    private _handleTSMFPacket(packet: Buffer): void {
        const payload = this._extractTSMFPayload(packet);
        if (!payload) {
            return;
        }

        const frameInfo = this._validateTSMFFrame(payload);
        if (!frameInfo) {
            return;
        }

        this._processTSMFHeader(payload, frameInfo);
    }

    /**
     * ロック/切替時にだけ呼ばれる。relative_stream_number の展開、選択、ログ、状態更新まで。
     */
    private _applyTSMFHeader(
        payload: Buffer,
        _frameType: number,
        numberOfCarriers: number,
        carrierSequence: number,
        headerCRCField: number,
        groupId: number
    ): void {
        // relative_stream_number (52 slots × 4bit) @ payload[69..94]
        this._tsmfRelativeStreamNumber = [];
        for (let i = 0; i < SLOT_COUNT; i++) {
            const b = payload[69 + (i >> 1)];
            if ((i & 1) === 0) {
                this._tsmfRelativeStreamNumber.push((b >> 4) & 0x0f);
            } else {
                this._tsmfRelativeStreamNumber.push(b & 0x0f);
            }
        }

        // stream_id @ payload[5 + (i * 4)] (16bit each, 15 streams)
        const streamIds: number[] = [];
        for (let i = 0; i < 15; i++) {
            const baseIndex = 5 + (i * 4);
            const streamId = (payload[baseIndex] << 8) | payload[baseIndex + 1];
            streamIds.push(streamId);
        }

        // stream_type bits (15bit) @ payload[121], [122]  0=TLV,1=TS
        const streamTypeBits = (payload[121] << 7) | (payload[122] >> 1);

        const counts = new Array(16).fill(0);
        for (const s of this._tsmfRelativeStreamNumber) {
            if (s >= 1 && s <= 15) {
                counts[s] += 1;
            }
        }

        let best = 0;
        let bestOcc = 0;

        for (let s = 1; s <= 15; s++) {
            const typeBit = (streamTypeBits >> (14 - (s - 1))) & 0x01; // 0=TLV,1=TS
            if (typeBit === 0 && counts[s] > bestOcc) {
                best = s;
                bestOcc = counts[s];
            }
        }
        if (best === 0) {
            for (let s = 1; s <= 15; s++) {
                if (counts[s] > bestOcc) {
                    best = s;
                    bestOcc = counts[s];
                }
            }
        }

        if (this._tsmfTsNumber >= 1 && this._tsmfTsNumber <= 15) {
            const manualOcc = counts[this._tsmfTsNumber] || 0;
            const manualTypeBit = (streamTypeBits >> (14 - (this._tsmfTsNumber - 1))) & 0x01;
            if (manualTypeBit === 1 && manualOcc > 0) {
                log.warn(
                    "TunerDevice#%d Manual stream %d is TS format (typeBit=1) but has %d slots. Processing as TLV anyway.",
                    this._tunerIndex,
                    this._tsmfTsNumber,
                    manualOcc
                );
                best = this._tsmfTsNumber;
            } else if (manualTypeBit === 1 && manualOcc === 0) {
                log.warn(
                    "TunerDevice#%d Manual stream %d is TS format with no slots. No output will be produced.",
                    this._tunerIndex,
                    this._tsmfTsNumber
                );
            } else {
                best = this._tsmfTsNumber;
            }
        }

        this._tsmfTsNumber = best;
        this._effectiveTargetStreamNumber = best;

        if (this._lastLoggedHeaderCRC !== headerCRCField) {
            const slotStats = new Map<number, number>();
            for (const v of this._tsmfRelativeStreamNumber) {
                slotStats.set(v, (slotStats.get(v) || 0) + 1);
            }

            log.debug("TunerDevice#%d Slot detection successful: validSlots=%d", this._tunerIndex, this._tsmfRelativeStreamNumber.length);

            if (slotStats.size === 1) {
                const [stream, count] = Array.from(slotStats.entries())[0];
                log.debug("TunerDevice#%d Single stream %d occupies all %d slots", this._tunerIndex, stream, count);
            } else {
                const statText = Array.from(slotStats.entries()).map(([s, c]) => `stream${s}:${c}`).join(", ");
                log.debug("TunerDevice#%d Slot statistics: %s", this._tunerIndex, statText);
            }

            log.debug("TunerDevice#%d Full slot contents: %s", this._tunerIndex, this._tsmfRelativeStreamNumber.join(","));

            const validStreamIds = streamIds.slice(0, 15);
            const streamIdText = validStreamIds.map((id, idx) => `stream${idx + 1}:0x${id.toString(16).padStart(2, "0")}`).join(", ");
            log.debug("TunerDevice#%d StreamIDs: %s", this._tunerIndex, streamIdText);

            if (best > 0) {
                const targetSlots = [];
                for (let i = 0; i < this._tsmfRelativeStreamNumber.length; i++) {
                    if (this._tsmfRelativeStreamNumber[i] === best) {
                        targetSlots.push(i);
                    }
                }
                if (targetSlots.length === 0) {
                    log.warn("TunerDevice#%d Selected stream %d not found in slot mapping. TLV will be filtered out.", this._tunerIndex, best);
                } else {
                    const selectedStreamId = best <= validStreamIds.length ? validStreamIds[best - 1] : 0;
                    log.debug("TunerDevice#%d Selected stream %d (StreamID:0x%s) slots: %s",
                        this._tunerIndex, best, selectedStreamId.toString(16).padStart(2, "0"), targetSlots.join(","));
                }
            } else {
                log.warn("TunerDevice#%d No valid target stream could be selected from TSMF header. TLV will be filtered out.", this._tunerIndex);
            }

            const selectedStreamId = best > 0 && best <= streamIds.length ? streamIds[best - 1] : 0;
            log.info(
                "TunerDevice#%d TSMF header applied. groupId=%d carriers=%d/%d tsmfRelTs=%d StreamID=0x%s",
                this._tunerIndex,
                groupId,
                carrierSequence,
                numberOfCarriers,
                this._tsmfTsNumber,
                selectedStreamId.toString(16).padStart(4, "0")
            );
            this._lastLoggedHeaderCRC = headerCRCField;
        }

        // 状態更新（ロック/切替確定）
        this._numberOfCarriers = numberOfCarriers;
        this._carrierSequence = carrierSequence;
        this._activeHeaderCRC = headerCRCField;
        this._headerLocked = true;
        this._slotIndex = 0;

        // 候補リセット
        this._candidateHeaderCRC = -1;
        this._candidateSeen = 0;
    }

    private _handleTLVPacket(packet: Buffer): void {
        this._tlvPackets++;
        const pusi = (packet[1] & 0x40) !== 0; // TLV packet start indicator

        if (pusi) {
            // 新しい分割TLVパケットの開始
            // 前の分割TLVパケットがあれば完成として出力
            if (this._buffer.length > 0) {
                this._flushBufferedOutput();
            }

            // 新しい分割TLVパケットの開始部分を追加
            const tlvChunk = packet.subarray(4); // PUSIありの場合は4バイト目から
            if (tlvChunk.length > 0) {
                this._buffer.push(tlvChunk);
            }
        } else {
            // 分割TLVパケットの継続部分
            const tlvChunk = packet.subarray(3); // PUSIなしの場合は3バイト目から
            if (tlvChunk.length > 0) {
                this._buffer.push(tlvChunk);
            }
        }
    }

    private _close(): void {
        if (this._closed || this._closing) {
            return;
        }
        log.debug("TunerDevice#%d TLVConverter _close() called", this._tunerIndex);
        this._closing = true;
        this._sinkClosed = true;

        // 残っている分割TLVパケットがあれば出力
        if (this._buffer && this._buffer.length > 0 && this._output && !this._output.destroyed) {
            log.debug("TunerDevice#%d TLVConverter: flushing remaining buffer on close", this._tunerIndex);
            try {
                const outputData = Buffer.concat(this._buffer);
                this._output.write(outputData);
            } catch (e) {
                log.debug("TunerDevice#%d TLVConverter: error writing remaining buffer: %s", this._tunerIndex, (e as Error).message);
            }
        }

        setImmediate(() => {
            this._packet = undefined as any;
            this._buffer = undefined as any;
        });

        if (this._output && !this._output.destroyed) {
            try { (this._output as any).destroy?.(); } catch (e) {
                const err = e as any;
                log.warn("TunerDevice#%d TLVConverter output destroy error: %s", this._tunerIndex, err?.message ?? String(err));
            }
        }
        this._output = null as any;

        this._closed = true;
        this._closing = false;

        log.debug("TunerDevice#%d TLVConverter closed", this._tunerIndex);

        process.nextTick(() => {
            this.emit("close");
            this.removeAllListeners();
        });
    }

    /**
     * CRC-32 計算メソッド (MPEG-2/DVB準拠) - TSMFヘッダ184Bの残差0チェック用
     */
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
