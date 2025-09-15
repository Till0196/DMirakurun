import { Transform } from "stream";
import * as log from "./log";

export interface StreamFormat {
    isTS: boolean;
    isMMTS: boolean; // TSでない場合は全てMMTS/TLV扱い
}

export default class StreamDetector extends Transform {
    private _detected = false;
    private _buffer = Buffer.alloc(0);
    private _format: StreamFormat = { isTS: false, isMMTS: false };
    private _maxDetectionBytes = 2048; // 2KB分析して判定

    constructor() {
        super();
    }

    _transform(chunk: Buffer, encoding: string, callback: Function) {
        if (!this._detected && this._buffer.length < this._maxDetectionBytes) {
            this._buffer = Buffer.concat([this._buffer, chunk.slice(0, this._maxDetectionBytes - this._buffer.length)]);

            if (this._buffer.length >= this._maxDetectionBytes || this._buffer.length >= 512) {
                this._detectStreamFormat();
                this._detected = true;

                log.debug("StreamDetector: detected format - TS: %s, MMTS/TLV: %s",
                    this._format.isTS, this._format.isMMTS);

                this.emit('formatDetected', this._format);
            }
        }

        this.push(chunk);
        callback();
    }

    private _detectStreamFormat(): void {
        // MMT/TLV形式の検出
        const hasPid0x0D = this._checkForPid0x0D();
        if (hasPid0x0D) {
            this._format.isMMTS = true;
            log.debug("StreamDetector: PID 0x0D detected, confirmed MMTS/TLV format");
            return;
        }

        // MMTS/TLVでない場合、TSとして扱う
        if (!this._format.isMMTS) {
            this._format.isTS = true;
            log.debug("StreamDetector: Non-MMTS/TLV format detected, treating as TS");
        }
    }

    private _checkForPid0x0D(): boolean {
        // TSパケット内でPID 0x0Dを探す
        for (let i = 0; i <= this._buffer.length - 188; i += 188) {
            // TSパケットの同期バイト確認
            if (this._buffer[i] === 0x47) {
                // PID を抽出 (13ビット): バイト1の下位5ビット + バイト2の全8ビット
                const pidHigh = this._buffer[i + 1] & 0x1F; // 上位5ビット
                const pidLow = this._buffer[i + 2];         // 下位8ビット
                const pid = (pidHigh << 8) | pidLow;

                if (pid === 0x0D) {
                    log.debug("StreamDetector: found PID 0x0D (IPMP) at offset %d", i);
                    return true;
                }
            }
        }

        // TLV形式内でのMMTパケット検索も追加
        for (let i = 0; i <= this._buffer.length - 4; i++) {
            // TLV形式またはMMTパケットの特徴的なパターンを検索
            if (this._buffer[i] === 0x7F && this._buffer[i + 1] === 0x7F) {
                // MMTパケットヘッダー内でIPMPストリーム（0x0D）を検索
                for (let j = i + 2; j <= Math.min(i + 100, this._buffer.length - 2); j++) {
                    if (this._buffer[j] === 0x00 && this._buffer[j + 1] === 0x0D) {
                        log.debug("StreamDetector: found IPMP stream (0x0D) in MMT packet at offset %d", j);
                        return true;
                    }
                }
            }
        }

        return false;
    }

    get detectedFormat(): StreamFormat {
        return this._format;
    }

    get isDetected(): boolean {
        return this._detected;
    }
}
