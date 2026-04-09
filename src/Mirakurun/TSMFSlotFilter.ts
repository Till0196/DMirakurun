import * as stream from "stream";
import * as log from "./log";
import { TsmfCCChecker } from "./TSMFFilter";

// TS packet constants
const PACKET_SIZE = 188;
const TS_SYNC_BYTE = 0x47;

// PID assignments for TSMF multi-carrier
const TSMF_PID = 0x2f;
const SLOT_COUNT = 52 as const;

// TSMF sync patterns (ARIB STD-B32)
const TSMF_SYNC_A = 0x1a86;
const TSMF_SYNC_B = 0x0579;

/**
 * Lightweight TSMF slot filter as a Transform stream.
 * Extracts packets belonging to a specific relative stream number from TSMF frames.
 * Used for single-carrier TSMF splitting (non-TLV, e.g. BS/CS over CATV).
 *
 * Detection (PAT parsing, service map building) is delegated to listeners
 * via the `slotMap` and `patPacket` events — see StreamFilter._initTsmfTs.
 */
export class TSMFSlotFilter extends stream.Transform {

    static createDetector(): TSMFSlotFilter {
        const filter = new TSMFSlotFilter(0, true);
        filter._detectMode = true;
        return filter;
    }

    private _targetStream: number;
    private _detectMode: boolean;
    private _slotCounter = -1;
    private _slotMap: number[] = [];
    private _partial = Buffer.alloc(PACKET_SIZE);
    private _partialLen = 0;
    private _ccChecker = new TsmfCCChecker();

    constructor(tsmfRelTs: number, private _passHeader = false) {
        super();
        this._targetStream = tsmfRelTs;
        this._detectMode = false;
    }

    /** Switch from detect mode to filtering a specific stream. */
    selectStream(relTs: number): void {
        this._detectMode = false;
        this._targetStream = relTs;
    }

    _transform(chunk: Buffer, _encoding: BufferEncoding, callback: stream.TransformCallback): void {
        let offset = 0;

        if (this._partialLen > 0) {
            const need = PACKET_SIZE - this._partialLen;
            if (chunk.length >= need) {
                chunk.copy(this._partial, this._partialLen, 0, need);
                offset = need;
                if (this._partial[0] === TS_SYNC_BYTE) {
                    this._filterPacket(this._partial);
                }
                this._partialLen = 0;
            } else {
                chunk.copy(this._partial, this._partialLen);
                this._partialLen += chunk.length;
                callback();
                return;
            }
        }

        while (offset + PACKET_SIZE <= chunk.length) {
            if (chunk[offset] !== TS_SYNC_BYTE) {
                offset++;
                continue;
            }
            this._filterPacket(chunk.subarray(offset, offset + PACKET_SIZE));
            offset += PACKET_SIZE;
        }

        if (offset < chunk.length) {
            chunk.copy(this._partial, 0, offset);
            this._partialLen = chunk.length - offset;
        }

        callback();
    }

    private _filterPacket(packet: Buffer): void {
        const pid = ((packet[1] & 0x1f) << 8) | packet[2];

        if (pid === TSMF_PID) {
            const sync = ((packet[4] << 8) | packet[5]) & 0x1fff;
            if (sync === TSMF_SYNC_A || sync === TSMF_SYNC_B) {
                const cc = packet[3] & 0x0f;
                const wasSynced = this._ccChecker.synced;
                if (!this._ccChecker.check(cc)) {
                    this._slotCounter = -1;
                    return;
                }
                if (!wasSynced) {
                    log.debug("TSMFSlotFilter CC synced after skipping stale frame(s)");
                }

                this._slotMap = [];
                for (let i = 0; i < 26; i++) {
                    this._slotMap.push((packet[73 + i] & 0xf0) >> 4);
                    this._slotMap.push(packet[73 + i] & 0x0f);
                }
                this._slotCounter = 0;

                if (this._detectMode) {
                    // Extract group_id only from Extended TSMF (frame_type=0x2)
                    // frame_type is payload byte 2 lower nibble = TS packet byte 6
                    const frameType = packet[6] & 0x0f;
                    const groupId = frameType === 0x02 ? packet[127] : null;
                    this.emit("slotMap", this._slotMap.slice(), groupId);
                }
            }
            if (this._passHeader) {
                this.push(packet);
            }
            return;
        }

        if (this._slotCounter < 0 || this._slotCounter >= SLOT_COUNT) {
            if (this._detectMode) {
                this.push(packet);
            }
            return;
        }

        const slot = this._slotCounter++;
        const relTs = this._slotMap[slot];

        // Detection: correlate PAT with relative stream number
        if (this._detectMode && relTs > 0 && pid === 0x0000) {
            this.emit("patPacket", relTs, packet);
        }

        if (this._detectMode) {
            this.push(packet);
        } else if (relTs === this._targetStream) {
            this.push(packet);
        }
    }
}
