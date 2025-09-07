import { Writable } from "stream";
import EventEmitter = require("eventemitter3");
import * as log from "./log";

const PACKET_SIZE = 188;
const TLV_PID = 0x2d;
const TSMF_PID = 0x2f;

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
    private _tsmfHeaderParsed = false;
    private _isTlvStream = false;
    private _frameTypeValid = false;
    private _tsmfRelativeStreamNumber: number[] = [];
    private _tsmfTsNumber = 1;
    private _numberOfCarriers = 0;
    private _carrierSequence = 0;
    private _tlvPacketCount = 0;

    constructor(tunerIndex: number, output: Writable, tsmfRelTs?: number) {
        super();
        this._tunerIndex = tunerIndex;
        this._output = output;
        this._tsmfTsNumber = (typeof tsmfRelTs === "number") ? tsmfRelTs : 0;

        this._output.once("error", (err) => {
            log.error("TunerDevice#%d TLVConverter output error: %s", this._tunerIndex, err.message);
            this.emit("error", err);
            this._close();
        });

        this._output.once("finish", this._close.bind(this));
        this._output.once("close", this._close.bind(this));

        log.debug("TunerDevice#%d TLVConverter created", this._tunerIndex);
    }

    get closed(): boolean {
        return this._closed;
    }

    get carrierInfo(): { numberOfCarriers: number; carrierSequence: number } {
        return {
            numberOfCarriers: this._numberOfCarriers,
            carrierSequence: this._carrierSequence
        };
    }

    get tsmfInfo(): { tsNumber: number; totalSlots: number; tsmfHeaderParsed: boolean } {
        return {
            tsNumber: this._tsmfTsNumber,
            totalSlots: this._tsmfRelativeStreamNumber.length,
            tsmfHeaderParsed: this._tsmfHeaderParsed
        };
    }

    write(chunk: Buffer): void {
        if (this._closed || this._closing) {
            log.warn("TunerDevice#%d TLVConverter write called on closed converter", this._tunerIndex);
            return;
        }

        if (!this._output || this._output.destroyed) {
            log.warn("TunerDevice#%d TLVConverter output stream is destroyed", this._tunerIndex);
            this._close();
            return;
        }

        let offset = 0;
        const length = chunk.length;
        const packets: Buffer[] = [];

        if (this._offset > 0) {
            if (length >= PACKET_SIZE - this._offset) {
                offset = PACKET_SIZE - this._offset;
                packets.push(Buffer.concat([
                    this._packet.slice(0, this._offset),
                    chunk.slice(0, offset)
                ]));
                this._offset = 0;
            } else {
                chunk.copy(this._packet, this._offset);
                this._offset += length;
                return;
            }
        }

        for (; offset < length; offset += PACKET_SIZE) {
            // sync byte (0x47) verifying
            if (chunk[offset] !== 0x47) {
                offset -= PACKET_SIZE - 1;
                continue;
            }

            if (length - offset >= PACKET_SIZE) {
                packets.push(chunk.slice(offset, offset + PACKET_SIZE));
            } else {
                chunk.copy(this._packet, 0, offset);
                this._offset = length - offset;
            }
        }

        this._processPackets(packets);

        if (this._buffer.length !== 0) {
            if (this._output.writableLength < this._output.writableHighWaterMark) {
                const outputData = Buffer.concat(this._buffer);
                this._output.write(outputData);
                this._buffer.length = 0;
            }
        }
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

    private _processPackets(packets: Buffer[]): void {
        for (const packet of packets) {
            this._processedPackets++;

            const pid = ((packet[1] & 0x1F) << 8) | packet[2];

            // TSMFパケット処理
            if (pid === TSMF_PID) {
                // 未解析の場合のみヘッダー解析
                if (!this._tsmfHeaderParsed) {
                    this._handleTSMFPacket(packet);
                } else {
                    // TSMFパケット検出時は常にスロットリセット（フレーム境界）
                    this._tlvPacketCount = 0;
                }
                continue;
            }

            // TLV処理（ヘッダー解析後）
            if (this._tsmfHeaderParsed && pid === TLV_PID) {
                const slotIndex = this._tlvPacketCount;

                if (slotIndex < this._tsmfRelativeStreamNumber.length) {
                    const streamNumberInThisSlot = this._tsmfRelativeStreamNumber[slotIndex];

                    if (Number(streamNumberInThisSlot) === Number(this._tsmfTsNumber)) {
                        this._handleTLVPacket(packet);
                    }
                }

                this._tlvPacketCount++;
            }
        }
    }

    private _extractTSMFPayload(packet: Buffer): Buffer | null {
        try {
            const hasAdaptationField = (packet[3] & 0x20) !== 0;
            const hasPayload = (packet[3] & 0x10) !== 0;

            if (!hasPayload) {
                return null;
            }

            let payloadOffset = 4;
            if (hasAdaptationField) {
                const adaptationFieldLength = packet[4];
                if (adaptationFieldLength < 0 || adaptationFieldLength > PACKET_SIZE - 5) {
                    return null;
                }
                payloadOffset += 1 + adaptationFieldLength;
            }

            const payload_unit_start_indicator = (packet[1] & 0x40) !== 0;
            if (payload_unit_start_indicator) {
                if (payloadOffset >= PACKET_SIZE) {
                    return null;
                }
                const pointerField = packet[payloadOffset];
                if (pointerField < 0 || 1 + pointerField > PACKET_SIZE - payloadOffset) {
                    return null;
                }
                payloadOffset += 1 + pointerField;
            }

            if (payloadOffset >= PACKET_SIZE) {
                return null;
            }

            return packet.slice(payloadOffset);
        } catch (err) {
            return null;
        }
    }

    private _handleTSMFPacket(packet: Buffer): void {
        if (this._tsmfHeaderParsed) {
            return;
        }

        const payload = this._extractTSMFPayload(packet);
        if (!payload) {
            return;
        }

        try {
            // byte 2: version(3bit) + mode(1bit) + type(4bit)
            const byte2 = payload[2];
            const frameType = byte2 & 0b1111;

            // stream_status (15bit) + 予約 (1bit)
            // byte 3-4にまたがる16bitを読む
            const streamStatusWord = payload.readUInt16BE(3);
            const streamStatusBits = streamStatusWord >> 1;
            const streamStatus: boolean[] = [];
            for (let i = 0; i < 15; i++) {
                const isActive = ((streamStatusBits >> (14 - i)) & 1) === 1;
                streamStatus.push(isActive);
            }

            // --- スロット情報解析 ---
            this._tsmfRelativeStreamNumber = [];
            const slotInfoOffset = 77;
            for (let i = 0; i < 26; i++) {
                const byteOffset = slotInfoOffset + i;
                if (byteOffset >= payload.length) {
                    log.error("TunerDevice#%d Slot data truncated at offset %d", this._tunerIndex, byteOffset);
                    this.emit("error", new Error("TSMF payload too short for slot data"));
                    this._close();
                    return;
                }

                const byte = payload[byteOffset];
                const upperNibble = (byte & 0xf0) >> 4;
                const lowerNibble = byte & 0x0f;

                // 1-15の範囲のみ有効（0は無効スロット）
                this._tsmfRelativeStreamNumber.push(upperNibble >= 1 && upperNibble <= 15 ? upperNibble : 0);
                this._tsmfRelativeStreamNumber.push(lowerNibble >= 1 && lowerNibble <= 15 ? lowerNibble : 0);
            }

            // スロット占有状況を分析
            const slotStats = new Map<number, number>();
            this._tsmfRelativeStreamNumber.forEach(val => {
                slotStats.set(val, (slotStats.get(val) || 0) + 1);
            });

            // --- ストリーム種別の判定 ---
            const streamTypeWord = payload.readUInt16BE(121);
            const streamTypeBits = streamTypeWord >> 1;
            let targetStreamIsTlv = false;

            if (this._tsmfTsNumber === 0) {
                // TLVストリームの中から最も占有率の高いものを選択
                let bestStream = 0;
                let bestOccupancy = 0;

                for (let relTs = 1; relTs <= 15; relTs++) {
                    const typeBit = (streamTypeBits >> (15 - relTs)) & 1;
                    if (typeBit === 0) { // "0"ならTLV
                        const occupancy = slotStats.get(relTs) || 0;
                        if (occupancy > bestOccupancy) {
                            bestStream = relTs;
                            bestOccupancy = occupancy;
                        }
                    }
                }

                if (bestStream > 0) {
                    this._tsmfTsNumber = bestStream;
                    targetStreamIsTlv = true;
                    log.debug("TunerDevice#%d Auto-detected TLV stream: %d, %d slots",
                        this._tunerIndex, bestStream, bestOccupancy);
                }
            } else if (this._tsmfTsNumber > 0 && this._tsmfTsNumber <= 15) {
                const typeBit = (streamTypeBits >> (15 - this._tsmfTsNumber)) & 1;
                const occupancy = slotStats.get(this._tsmfTsNumber) || 0;

                log.debug("TunerDevice#%d Manual stream %d: typeBit=%d, %d slots",
                    this._tunerIndex, this._tsmfTsNumber, typeBit, occupancy);

                if (typeBit === 0) {  // "0"ならTLV
                    targetStreamIsTlv = true;
                }
            }

            // --- 搬送波情報の解析 ---
            const groupId = payload[123];
            const numberOfCarriers = payload[124];
            const carrierSequence = payload[125];

            // --- 解析結果をインスタンス変数に格納 ---
            this._frameTypeValid = (frameType === 0x1 || frameType === 0x2);
            this._numberOfCarriers = numberOfCarriers;
            this._carrierSequence = carrierSequence;

            // --- 複数搬送波時の分岐 ---
            if (this._frameTypeValid) {
                log.debug(`TunerDevice#%d TSMF: detected frameType=${frameType}, GroupID=${groupId}, Carriers=${carrierSequence}/${numberOfCarriers}`, this._tunerIndex);

                if (this._isTlvStream && this._numberOfCarriers > 1) {
                    // 8K放送など複数搬送波のTLVストリームは同時に複数チューナーを必要とするため現状は未サポート
                    log.error(`TunerDevice#%d Multiple carrier TLV stream is not supported. Terminating conversion.`, this._tunerIndex);
                    this.emit("error", new Error(`Multiple carrier TLV stream is not supported (${this._numberOfCarriers} carriers).`));
                    this._close();
                    return;
                }

                if (!targetStreamIsTlv) {
                    log.error(`TunerDevice#%d Target stream ${this._tsmfTsNumber} is not a TLV stream (type bit = 1). Terminating conversion.`, this._tunerIndex);
                    this.emit("error", new Error(`Target stream ${this._tsmfTsNumber} is not a TLV stream.`));
                    this._close();
                    return;
                }
            } else {
                log.error(`TunerDevice#%d Invalid frame type (${frameType}). TSMF frame type must be 0x1 or 0x2. Terminating conversion.`, this._tunerIndex);
                this.emit("error", new Error(`Invalid TSMF frame type: 0x${frameType.toString(16)}`));
                this._close();
                return;
            }

            // スロット統計の出力
            log.debug("TunerDevice#%d Total slots parsed: %d", this._tunerIndex, this._tsmfRelativeStreamNumber.length);

            if (slotStats.size === 1) {
                const [stream, count] = Array.from(slotStats.entries())[0];
                log.debug("TunerDevice#%d Single stream %d occupies all %d slots", this._tunerIndex, stream, count);
            } else {
                log.debug("TunerDevice#%d Slot statistics: %s", this._tunerIndex,
                    Array.from(slotStats.entries()).map(([stream, count]) => `stream${stream}:${count}`).join(", "));
            }

            // ターゲットストリーム番号がスロットに含まれているかチェック
            const targetSlots = this._tsmfRelativeStreamNumber.map((val, idx) => ({ slot: idx, stream: val }))
                .filter(item => item.stream === this._tsmfTsNumber);

            if (targetSlots.length === 0) {
                log.error(`TunerDevice#%d Target stream ${this._tsmfTsNumber} not found in slot mapping. Terminating conversion.`, this._tunerIndex);
                this.emit("error", new Error(`Target stream ${this._tsmfTsNumber} not found in TSMF slot mapping.`));
                this._close();
                return;
            }

            log.debug("TunerDevice#%d Target stream %d found in slots: %s", this._tunerIndex, this._tsmfTsNumber,
                targetSlots.map(s => s.slot).join(","));

            // 実際のスロット配列内容を一時的に確認
            log.debug("TunerDevice#%d Full slot contents: %s", this._tunerIndex,
                this._tsmfRelativeStreamNumber.join(","));

            this._isTlvStream = targetStreamIsTlv;
            this._tsmfHeaderParsed = true;

            log.info(`TunerDevice#%d TSMF header parsed successfully. FrameType=0x${frameType.toString(16)}, Target stream is TLV: ${this._isTlvStream}`, this._tunerIndex);

        } catch (err) {
            log.error("TunerDevice#%d Failed to parse TSMF header: %s", this._tunerIndex, err.message);
        }
    }

    private _handleTLVPacket(packet: Buffer): void {
        this._tlvPackets++;

        const payload_unit_start_indicator = (packet[1] & 0x40) !== 0;
        const tlvChunk = payload_unit_start_indicator ? packet.slice(4) : packet.slice(3);

        if (tlvChunk.length > 0) {
            this._buffer.push(tlvChunk);
        }
    }

    private _close(): void {
        if (this._closed || this._closing) {
            return;
        }

        this._closing = true;

        // clear buffer
        setImmediate(() => {
            delete this._packet;
            delete this._buffer;
        });

        // clear output stream
        if (this._output) {
            try {
                if (!this._output.destroyed && !this._output.writableEnded) {
                    this._output.end();
                }
            } catch (err) {
                log.warn("TunerDevice#%d TLVConverter output end error: %s", this._tunerIndex, err.message);
            }

            this._output.removeAllListeners();
            this._output = null;
        }

        this._closed = true;
        this._closing = false;

        log.debug("TunerDevice#%d TLVConverter closed", this._tunerIndex);

        // close
        process.nextTick(() => {
            this.emit("close");
            this.removeAllListeners();
        });
    }
}
