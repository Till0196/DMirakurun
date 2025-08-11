import { Writable } from "stream";
import EventEmitter = require("eventemitter3");
import * as log from "./log";

const PACKET_SIZE = 188;
const TLV_PID = 0x2d;

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

    constructor(tunerIndex: number, output: Writable) {
        super();
        this._tunerIndex = tunerIndex;
        this._output = output;

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

    write(chunk: Buffer): void {
        if (this._closed || this._closing) {
            throw new Error("TLVConverter has closed already");
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
            if (packet.length !== PACKET_SIZE) {
                continue;
            }

            if (packet[0] !== 0x47) {
                continue;
            }

            this._processedPackets++;
            const pid = ((packet[1] & 0b0001_1111) << 8) | packet[2];

            if (pid === TLV_PID) {
                this._tlvPackets++;
                const payload_unit_start_indicator = (packet[1] & 0b0100_0000) >> 6;
                const tlvChunk = payload_unit_start_indicator === 1 ? packet.slice(4) : packet.slice(3);

                if (tlvChunk.length > 0) {
                    this._buffer.push(tlvChunk);
                }
            }
        }

    }

    private _close(): void {
        if (this._closed || this._closing) {
            return;
        }

        this._closing = true;
        log.debug("TunerDevice#%d TLVConverter starting close process", this._tunerIndex);

        // clear buffer
        setImmediate(() => {
            delete this._packet;
            delete this._buffer;
        });

        // clear output stream
        if (this._output) {
            if (this._output.writableEnded === false) {
                this._output.end();
            }
            this._output.removeAllListeners();
            delete this._output;
        }

        this._closed = true;
        this._closing = false;

        log.debug("TunerDevice#%d TLVConverter closed (processed: %d, TLV: %d)",
                this._tunerIndex, this._processedPackets, this._tlvPackets);

        // close
        this.emit("close");
    }
}
