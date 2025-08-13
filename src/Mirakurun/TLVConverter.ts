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

    constructor(tunerIndex: number, output: Writable, tsmfRelTs?: number) {
        super();
        this._tunerIndex = tunerIndex;
        this._output = output;
        this._tsmfTsNumber = tsmfRelTs;

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
            const pid = ((packet[1] & 0b0001_1111) << 8) | packet[2];

            // TSMFヘッダー解析
            if (!this._tsmfHeaderParsed && pid === TSMF_PID) {
                try {
                    this._parseTSMFHeader(packet);
                } catch (err) {
                    log.warn("TunerDevice#%d TSMF header parse error: %s", this._tunerIndex, err.message);
                }
                continue;
            }

            if (this._tsmfHeaderParsed && pid === TLV_PID) {
                this._tlvPackets++;
                const payload_unit_start_indicator = (packet[1] & 0b0100_0000) >> 6;
                const tlvChunk = payload_unit_start_indicator === 1 ? packet.slice(4) : packet.slice(3);

                if (tlvChunk.length > 0) {
                    this._buffer.push(tlvChunk);
                }
            }
        }
    }

    private _parseTSMFHeader(packet: Buffer): void {
        const hasAdaptationField = (packet[3] & 0x20) !== 0;
        const hasPayload = (packet[3] & 0x10) !== 0;

        if (!hasPayload) {
            return;
        }

        let payloadOffset = 4;
        if (hasAdaptationField) {
            const adaptationFieldLength = packet[4];
            payloadOffset = 5 + adaptationFieldLength;
        }

        if (payloadOffset >= PACKET_SIZE || (PACKET_SIZE - payloadOffset) < 184) {
            return;
        }

        const payload = packet.slice(payloadOffset);

        try {
            const frameSync = payload.readUInt16BE(0) & 0x1FFF;
            if (frameSync !== 0x1A86 && frameSync !== 0x0579) {
                return;
            }

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

            // --- ストリーム種別の判定 ---
            const streamTypeWord = payload.readUInt16BE(121);
            const streamTypeBits = streamTypeWord >> 1;

            let targetStreamIsTlv = false;

            if (this._tsmfTsNumber === 0) {
                // targetRelTs=0の場合、最初のTLVストリームを自動で探す
                for (let relTs = 1; relTs <= 15; relTs++) {
                    const typeBit = (streamTypeBits >> (15 - relTs)) & 1;
                    if (typeBit === 0) { // "0"ならTLV
                        this._tsmfTsNumber = relTs;
                        targetStreamIsTlv = true;
                        log.debug("TunerDevice#%d Auto-detected TLV stream at relative TS number: %d", this._tunerIndex, relTs);
                        break;
                    }
                }
            } else if (this._tsmfTsNumber > 0 && this._tsmfTsNumber <= 15) {
                // 指定された相対ストリーム番号に対応するビットを抽出
                // 相対ストリーム番号1は最上位ビット(14)、15は最下位ビット(0)に対応
                const typeBit = (streamTypeBits >> (15 - this._tsmfTsNumber)) & 1;

                log.debug(
                    "TunerDevice#%d Stream Type Check: targetRelTs=%d, streamTypeBits=%s, extractedBit=%d",
                    this._tunerIndex,
                    this._tsmfTsNumber,
                    streamTypeBits.toString(2).padStart(15, "0"),
                    typeBit
                );

                if (typeBit === 0) { // "0"ならTLV
                    targetStreamIsTlv = true;
                }
            }

            // --- 搬送波情報の解析 ---
            const groupId = payload[123];
            const numberOfCarriers = payload[124];
            const carrierSequence = payload[125];

            // --- 解析結果をインスタンス変数に格納 ---
            this._frameTypeValid = (frameType === 0x1 || frameType === 0x2);
            this._isTlvStream = targetStreamIsTlv;
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

                if (!this._isTlvStream) {
                    log.error(`TunerDevice#%d No TLV stream found. Terminating conversion.`, this._tunerIndex);
                    this.emit("error", new Error("No TLV stream found in TSMF frame."));
                    this._close();
                    return;
                }
            } else {
                log.error(`TunerDevice#%d Invalid frame type (${frameType}). TSMF frame type must be 0x1 or 0x2. Terminating conversion.`, this._tunerIndex);
                this.emit("error", new Error(`Invalid TSMF frame type: 0x${frameType.toString(16)}`));
                this._close();
                return;
            }

            // スロット情報解析
            this._tsmfRelativeStreamNumber = [];
            const slotInfoOffset = 69;
            for (let i = 0; i < 26; i++) {
                const byte = payload[slotInfoOffset + i];
                this._tsmfRelativeStreamNumber.push((byte & 0xf0) >> 4);
                this._tsmfRelativeStreamNumber.push(byte & 0x0f);
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

            this._tsmfHeaderParsed = true;

            log.info(`TunerDevice#%d TSMF header parsed successfully. FrameType=0x${frameType.toString(16)}, Target stream is TLV: ${this._isTlvStream}`, this._tunerIndex);

        } catch (err) {
            log.error("TunerDevice#%d Failed to parse TSMF header: %s", this._tunerIndex, err.message);
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
