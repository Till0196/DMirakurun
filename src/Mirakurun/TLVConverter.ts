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
    private _tsmfRelativeStreamNumber: number[] = [];
    private _tsmfTsNumber = 1;
    private _numberOfCarriers = 0;
    private _carrierSequence = 0;

    // スロット追跡
    private _slotIndex = -1;
    private _effectiveTargetStreamNumber = 0;

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
            const outputData = Buffer.concat(this._buffer);
            this._output.write(outputData);
            this._buffer.length = 0;
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
                if (!this._tsmfHeaderParsed) {
                    this._handleTSMFPacket(packet);
                    this._slotIndex = 0;
                } else {
                    this._resyncTSMFFrame(packet);
                }
                continue;
            }

            // TLV処理
            if (pid === TLV_PID) {
                const allow = this._tsmfHeaderParsed
                    ? (() => {
                        const totalSlots = this._tsmfRelativeStreamNumber.length || 52;
                        const curSlot = (this._slotIndex >= 0 && this._slotIndex < totalSlots) ? this._slotIndex : 0;
                        const streamInSlot = this._tsmfRelativeStreamNumber[curSlot] || 0;
                        const target = this._effectiveTargetStreamNumber;
                        return target > 0 ? (streamInSlot === target) : false;
                      })()
                    : false;

                if (allow) {
                    this._handleTLVPacket(packet);
                } else {
                    if (this._tsmfHeaderParsed) {
                        const totalSlots = this._tsmfRelativeStreamNumber.length || 52;
                        this._slotIndex = (this._slotIndex + 1) % totalSlots;
                    }
                }
            }
        }
    }

    private _handleTSMFPacket(packet: Buffer): void {
        if (this._tsmfHeaderParsed) {
            return;
        }
        try {
            // ヘッダはTSヘッダ直後(オフセット4)からの固定配置
            const base = 4;
            if (188 < base + 126) { return; }
            const sync = packet.readUInt16BE(base) & 0x1FFF;
            if (sync !== 0x1A86 && sync !== 0x0579) { return; }

            const frameType = packet[base + 2] & 0x0f;
            if (frameType !== 0x01 && frameType !== 0x02) { return; }

            // スロット情報（base+69..base+94）
            this._tsmfRelativeStreamNumber = [];
            for (let i = 0; i < 26; i++) {
                const b = packet[base + 69 + i];
                const hi = (b & 0xf0) >> 4;
                const lo = b & 0x0f;
                this._tsmfRelativeStreamNumber.push(hi >= 1 && hi <= 15 ? hi : 0);
                this._tsmfRelativeStreamNumber.push(lo >= 1 && lo <= 15 ? lo : 0);
            }

            // 占有状況
            const slotStats = new Map<number, number>();
            this._tsmfRelativeStreamNumber.forEach(val => {
                slotStats.set(val, (slotStats.get(val) || 0) + 1);
            });

            // 搬送波情報（base+123..base+125）
            const groupId = packet[base + 123];
            const numberOfCarriers = packet[base + 124];
            const carrierSequence = packet[base + 125];
            this._numberOfCarriers = numberOfCarriers;
            this._carrierSequence = carrierSequence;

            // 複数伝送波は未対応のためエラーで落とす
            if (numberOfCarriers > 1) {
                log.error(
                    "TunerDevice#%d Multiple-carrier TSMF not supported (groupId=%d, carriers=%d, seq=%d)",
                    this._tunerIndex,
                    groupId,
                    numberOfCarriers,
                    carrierSequence
                );
                this.emit("error", new Error(`Multiple-carrier TSMF not supported: carriers=${numberOfCarriers}`));
                this._close();
                return;
            }

            // ストリームタイプビット（TLV=0, TS=1）
            const streamTypeWord = packet.readUInt16BE(base + 121);
            const streamTypeBits = streamTypeWord >> 1;

            // 選択ロジック：手動優先、未指定は TLV(typeBit=0) の中から最大占有
            if (this._tsmfTsNumber > 0 && this._tsmfTsNumber <= 15) {
                const occupancy = slotStats.get(this._tsmfTsNumber) || 0;
                const typeBit = (streamTypeBits >> (15 - this._tsmfTsNumber)) & 1;
                if (typeBit === 0) {
                    this._effectiveTargetStreamNumber = this._tsmfTsNumber;
                    log.debug(
                        "TunerDevice#%d Selected stream %d (manual TLV): %d slots",
                        this._tunerIndex,
                        this._tsmfTsNumber,
                        occupancy
                    );
                } else {
                    this._effectiveTargetStreamNumber = 0;
                    log.warn(
                        "TunerDevice#%d Manual stream %d is non-TLV (typeBit=1). No output will be produced.",
                        this._tunerIndex,
                        this._tsmfTsNumber
                    );
                }
            } else {
                let best = 0;
                let bestOcc = 0;
                for (let relTs = 1; relTs <= 15; relTs++) {
                    const occ = slotStats.get(relTs) || 0;
                    const typeBit = (streamTypeBits >> (15 - relTs)) & 1;
                    if (typeBit === 0 && occ > bestOcc) {
                        best = relTs;
                        bestOcc = occ;
                    }
                }
                this._tsmfTsNumber = best;
                this._effectiveTargetStreamNumber = best;
                if (best > 0) {
                    log.debug(
                        "TunerDevice#%d Selected stream %d (auto TLV by occupancy): %d slots",
                        this._tunerIndex,
                        best,
                        bestOcc
                    );
                } else {
                    log.warn(
                        "TunerDevice#%d No TLV stream found in TSMF header. No output will be produced.",
                        this._tunerIndex
                    );
                }
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

            // 相対TS番号がスロットに含まれるか確認
            const selectedTarget = this._effectiveTargetStreamNumber;
            if (selectedTarget > 0) {
                const targetSlots = this._tsmfRelativeStreamNumber
                    .map((val, idx) => ({ slot: idx, stream: val }))
                    .filter(item => item.stream === selectedTarget);
                if (targetSlots.length === 0) {
                    log.warn(`TunerDevice#%d Selected stream ${selectedTarget} not found in slot mapping. TLV will be filtered out.`, this._tunerIndex);
                } else {
                    log.debug("TunerDevice#%d Selected stream %d slots: %s", this._tunerIndex, selectedTarget,
                        targetSlots.map(s => s.slot).join(","));
                }
            } else {
                log.warn(`TunerDevice#%d No valid target stream could be selected from TSMF header. TLV will be filtered out.`, this._tunerIndex);
            }

            // 実際のスロット配列内容を一時的に確認
            log.debug("TunerDevice#%d Full slot contents: %s", this._tunerIndex,
                this._tsmfRelativeStreamNumber.join(","));

            this._tsmfHeaderParsed = true;
            this._slotIndex = 0;
            log.info(`TunerDevice#%d TSMF header parsed. frameType=0x${frameType.toString(16)} carriers=${carrierSequence}/${numberOfCarriers}`, this._tunerIndex);

        } catch (err) {
            log.error("TunerDevice#%d Failed to parse TSMF header: %s", this._tunerIndex, err.message);
        }
    }

    private _handleTLVPacket(packet: Buffer): void {
        this._tlvPackets++;
        const pusi = (packet[1] & 0x40) !== 0;
        // シンプル方式: pusi時は4バイト、非pusi時は3バイトをTSヘッダ分としてスキップ
        const tlvChunk = pusi ? packet.slice(4) : packet.slice(3);
        if (tlvChunk.length > 0) {
            this._buffer.push(tlvChunk);
        }

        // 次のスロットへ
        if (this._tsmfHeaderParsed) {
            const totalSlots = this._tsmfRelativeStreamNumber.length || 52;
            this._slotIndex = (this._slotIndex + 1) % totalSlots;
        }
    }

    // 軽量なTSMFフレーム境界再同期（スロット位相のみ合わせる）
    private _resyncTSMFFrame(packet: Buffer): void {
        const base = 4;
        if (!packet || packet.length < base + 2) {
            return;
        }
        if (packet[0] !== 0x47) {
            return;
        }
        const sync = packet.readUInt16BE(base) & 0x1FFF;
        if (sync === 0x1A86 || sync === 0x0579) {
            this._slotIndex = 0;
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
