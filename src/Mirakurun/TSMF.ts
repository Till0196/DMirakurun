/*
   Copyright 2026 Till0196

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
import * as stream from "stream";
import * as apid from "../../api";
import * as common from "./common";
import * as log from "./log";
import * as db from "./db";
import _ from "./_";
import ChannelItem from "./ChannelItem";
import TSFilter from "./TSFilter";
import type TunerDevice from "./TunerDevice";
import TSMFFilter, { TsmfCCChecker } from "./TSMFFilter";

export { TsmfCCChecker };

// TS / TSMF constants (ARIB STD-B32) — duplicated from TSMFFilter for the
// slot filter; the parser/demuxer side keeps its own copies in TSMFFilter.ts.
const PACKET_SIZE = 188;
const TS_SYNC_BYTE = 0x47;
const TSMF_PID = 0x2f;
const SLOT_COUNT = 52 as const;
const TSMF_SYNC_A = 0x1a86;
const TSMF_SYNC_B = 0x0579;

// =============================================================================
// Persisted TSMF metadata (tsmf.json)
// =============================================================================

/**
 * Auto-detected TSMF state for one channel. Persisted in tsmf.json (sibling of
 * services.json) so multi-carrier groupId / per-service relTs mappings survive
 * restarts. The user-config tsmfRelTs / tsmfGroupId values from channels.yml
 * are NOT persisted here — they live in config and are applied at ChannelItem
 * construction time.
 */
export interface TsmfRecord {
    type: apid.ChannelType;
    channel: string;
    groupId?: number;
    relTs?: number;
    /** Per-service auto-detected relTs map (`serviceId → relTs`). */
    serviceRelTsMap?: { [serviceId: string]: number };
}

/**
 * TSMF persistence singleton. Snapshots ChannelItem auto-detected state to
 * `tsmf.json` via `db.loadTsmf` / `db.saveTsmf`, gated by an integrity hash of
 * `_.config.channels` so a `channels.yml` edit auto-clears the cache the same
 * way `services.json` does.
 *
 * Saves are debounced (~500 ms) so a burst of detector updates during a scan
 * collapses into a single disk write.
 */
export default class Tsmf {

    private _saveTimer: NodeJS.Timeout | null = null;

    /** Load tsmf.json and apply records to existing ChannelItems. */
    async load(): Promise<void> {
        const records = await db.loadTsmf(_.configIntegrity.channels);
        for (const record of records) {
            const channel = _.channel?.get(record.type, record.channel);
            if (!channel) {
                continue;
            }
            if (record.groupId !== undefined && record.groupId !== null) {
                channel.setTsmfGroupId(record.groupId);
            }
            if (record.relTs !== undefined && record.relTs !== null) {
                channel.setTsmfRelTs(record.relTs);
            }
            if (record.serviceRelTsMap) {
                for (const [serviceIdStr, relTs] of Object.entries(record.serviceRelTsMap)) {
                    channel.addTsmfRelTsMapping(Number(serviceIdStr), relTs);
                }
            }
        }
        log.info("loaded tsmf db (%d records)", records.length);
    }

    /**
     * Schedule a save. Subsequent calls within the debounce window collapse
     * into a single disk write.
     */
    schedule(): void {
        if (this._saveTimer) {
            return;
        }
        this._saveTimer = setTimeout(() => {
            this._saveTimer = null;
            this.save().catch(e => log.error("tsmf save failed: %s", (e as Error).message));
        }, 500);
    }

    /** Snapshot current ChannelItem state and write tsmf.json. */
    async save(): Promise<void> {
        if (!_.channel) {
            return;
        }
        const records: TsmfRecord[] = [];
        for (const channel of _.channel.items) {
            const record: TsmfRecord = { type: channel.type, channel: channel.channel };
            let hasData = false;

            // Only persist auto-detected values; user-config values come from channels.yml.
            if (channel.tsmfGroupId !== null && channel.tsmfGroupId !== undefined &&
                channel.tsmfGroupId !== 255 && !channel.hasConfigTsmfGroupId) {
                record.groupId = channel.tsmfGroupId;
                hasData = true;
            }
            if (channel.tsmfRelTs !== null && channel.tsmfRelTs !== undefined &&
                !channel.hasConfigTsmfRelTs) {
                record.relTs = channel.tsmfRelTs;
                hasData = true;
            }

            const relTsMap = channel.getRelTsMap();
            if (relTsMap.size > 0) {
                const serialized: { [serviceId: string]: number } = {};
                for (const [relTs, serviceIds] of relTsMap) {
                    for (const serviceId of serviceIds) {
                        serialized[String(serviceId)] = relTs;
                    }
                }
                if (Object.keys(serialized).length > 0) {
                    record.serviceRelTsMap = serialized;
                    hasData = true;
                }
            }

            if (hasData) {
                records.push(record);
            }
        }
        await db.saveTsmf(records, _.configIntegrity.channels);
    }
}

// =============================================================================
// TSMFSlotFilter — single-relTs Transform stream for TSMF→TS pipelines
// =============================================================================

/**
 * Lightweight TSMF slot filter as a Transform stream.
 * Extracts packets belonging to a specific relative stream number from TSMF frames.
 * Used for single-carrier TSMF splitting (non-TLV, e.g. BS/CS over CATV).
 *
 * Detection (PAT parsing, service map building) is delegated to listeners
 * via the `slotMap` and `patPacket` events — see StreamFilter._initTsmf.
 */
export class TSMFSlotFilter extends stream.Transform {

    static createDetector(): TSMFSlotFilter {
        const filter = new TSMFSlotFilter(0, true);
        filter._detectMode = true;
        return filter;
    }

    /**
     * Create a probe that emits only `slotMap` / `patPacket` events without
     * pushing any payload downstream. Used by StreamFilter to discover the
     * set of active relative TSes before fanning out per-relTs TSFilters.
     */
    static createSlotMapProbe(): TSMFSlotFilter {
        const filter = new TSMFSlotFilter(0, false);
        filter._detectMode = true;
        filter._slotMapOnly = true;
        return filter;
    }

    private _targetStream: number;
    private _detectMode: boolean;
    private _slotMapOnly = false;
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
                    // streamTypeBits: 15-bit field at payload[121..122] = TS
                    // packet bytes 125..126 (ARIB STD-B32 6.3.4.2). Bit (15-n)
                    // corresponds to relative stream n; 0=TLV, 1=TS or unused.
                    const streamTypeBits = (packet[125] << 7) | (packet[126] >> 1);
                    this.emit("slotMap", this._slotMap.slice(), groupId, streamTypeBits);
                }
            }
            if (this._passHeader && !this._slotMapOnly) {
                this.push(packet);
            }
            return;
        }

        if (this._slotCounter < 0 || this._slotCounter >= SLOT_COUNT) {
            if (this._detectMode && !this._slotMapOnly) {
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

        if (this._slotMapOnly) {
            // probe mode: drop all payload packets
            return;
        }

        if (this._detectMode) {
            this.push(packet);
        } else if (relTs === this._targetStream) {
            this.push(packet);
        }
    }
}

// =============================================================================
// TSMFCarrierBonding — multi-carrier orchestration on top of a TSMFFilter demuxer
// =============================================================================

/**
 * One additional carrier feeding bytes into a `TSMFFilter` demuxer instance.
 * The bonding orchestrator owns the lifetime of these links and tears them
 * down when the demuxer closes or carriers are released.
 */
interface CarrierLink {
    device: TunerDevice;
    user: common.User & { _stream?: TSFilter };
    tsFilter: TSFilter;
    sourceStream: stream.PassThrough;
    demuxerInput: stream.Writable;
}

/**
 * Multi-carrier bonding orchestrator. Wraps a `TSMFFilter` demuxer with the
 * runtime IO needed to acquire additional tuners when the demuxer signals
 * `needCarriers`, pipe their bytes into demuxer.createInput(), and tear the
 * links down on close.
 *
 * Lives in TSMF.ts (orchestrator layer) so TSMFFilter.ts stays a pure parser
 * + demuxer with no `_.tuner` / `child_process` dependency.
 */
export class TSMFCarrierBonding {

    private _demuxer: TSMFFilter;
    private _tunerIndex: number;
    private _carrierLinks: CarrierLink[] = [];
    private _carrierInitPending = false;

    constructor(demuxer: TSMFFilter, tunerIndex: number) {
        this._demuxer = demuxer;
        this._tunerIndex = tunerIndex;
        // Auto-cleanup when the demuxer dies for any reason.
        this._demuxer.once("close", () => this.releaseCarriers());
    }

    get hasCarriers(): boolean {
        return this._carrierLinks.length > 0;
    }

    /**
     * Subscribe to demuxer events for the given channel. Persists groupId on
     * first detection and starts additional carriers when the demuxer signals
     * `needCarriers`.
     */
    setupCarriers(ch: ChannelItem): void {
        // Persist groupId to services DB as soon as detected (fires once).
        this._demuxer.once("groupId", (groupId: number, numberOfCarriers: number) => {
            ch.setTsmfGroupId(groupId);
            log.debug("TunerDevice#%d TSMF detected groupId=%d numberOfCarriers=%d on %s",
                this._tunerIndex, groupId, numberOfCarriers, ch.channel);
            _.service?.save();
        });
        this._demuxer.on("needCarriers", (count: number) => {
            log.debug("TunerDevice#%d need %d carriers", this._tunerIndex, count);
            if (count > 1) {
                this._waitAndStartCarriers(ch, count);
            }
        });
    }

    syncPriorities(newPriority: number): void {
        for (const link of this._carrierLinks) {
            if (link.user.priority !== newPriority) {
                (link.user as { priority: number }).priority = newPriority;
            }
        }
    }

    releaseCarriers(): void {
        this._detachCarrierLinks();
    }

    // --- Private ---

    private _detachCarrierLinks(): void {
        for (const link of this._carrierLinks) {
            link.sourceStream.removeAllListeners();
            if (!link.demuxerInput.writableEnded) {
                link.demuxerInput.end();
            }
            link.device.endStream(link.user, true);
        }
        this._carrierLinks = [];
        this._carrierInitPending = false;
    }

    /**
     * Start additional carriers for multi-carrier bonding.
     * Tuner availability is guaranteed by the job system's readyFn;
     * groupId discovery is handled by the reactive scan flow.
     */
    private _waitAndStartCarriers(ch: ChannelItem, count: number): void {
        if (this._demuxer.closed) {
            return;
        }
        if (ch.tsmfGroupId === null || ch.tsmfGroupId === undefined) {
            log.warn("TunerDevice#%d cannot attach extra carriers without tsmfGroupId, aborting stream", this._tunerIndex);
            this._demuxer.close();
            return;
        }
        // Only the first channel in the group (by config order) should manage bonding.
        // Others abort immediately to free their tuners.
        const groupChannels = _.channel.items.filter(item =>
            item.tsmfGroupId === ch.tsmfGroupId
        );
        const isFirstInGroup = groupChannels.length === 0 || groupChannels[0].channel === ch.channel;

        if (!isFirstInGroup) {
            log.info("TunerDevice#%d not first in group (groupId=%d), deferring bonding to %s",
                this._tunerIndex, ch.tsmfGroupId, groupChannels[0]?.channel);
            this._demuxer.close();
            return;
        }

        if (groupChannels.length < count) {
            log.warn("TunerDevice#%d not enough group channels for groupId=%d, need %d but got %d — aborting stream",
                this._tunerIndex, ch.tsmfGroupId, count, groupChannels.length);
            this._demuxer.close();
            return;
        }
        log.info("TunerDevice#%d starting %d additional carriers for groupId=%d",
            this._tunerIndex, count - 1, ch.tsmfGroupId);
        const additional = groupChannels.filter(item => item.channel !== ch.channel);
        this._startCarriers(ch, additional).catch(log.error);
    }

    private async _startCarriers(ch: ChannelItem, groupChannels: ChannelItem[]): Promise<void> {
        if (this._carrierInitPending || this._carrierLinks.length > 0 ||
            !_.tuner || ch.tsmfGroupId === null || ch.tsmfGroupId === undefined) {
            return;
        }

        this._carrierInitPending = true;
        try {
            const required = groupChannels.length;
            if (required < 1) {
                log.warn("TunerDevice#%d no additional channels found for groupId=%d",
                    this._tunerIndex, ch.tsmfGroupId);
                return;
            }

            const selected = this._selectDevices(required, ch.type);
            if (selected.length < required) {
                log.error("TunerDevice#%d failed to find %d BS4K tuners for multi-carrier, only %d available",
                    this._tunerIndex, required, selected.length);
                this._demuxer.close();
                return;
            }

            log.info("TunerDevice#%d starting %d additional carriers on tuners %s",
                this._tunerIndex, selected.length, selected.map(d => `#${d.index}`).join(", "));

            // Start all additional carriers in parallel to minimize tuning latency.
            // Each startStream may need to kill/release an existing process (~1s each),
            // so parallel startup saves N seconds vs serial.
            const carrierPriority = _.tuner.get(this._tunerIndex)?.getPriority() ?? -1;
            const attempts = selected.map((device, i) => {
                const channel = groupChannels[i];
                const demuxerInput = this._demuxer.createInput();
                const sourceStream = new stream.PassThrough();
                const tsFilter = sourceStream as unknown as TSFilter;
                const user: common.User & { _stream?: TSFilter } = {
                    id: "Mirakurun:addCarrier()",
                    priority: carrierPriority,
                    disableDecoder: true,
                    streamSetting: { channel }
                };
                return { device, channel, demuxerInput, sourceStream, tsFilter, user };
            });

            const results = await Promise.allSettled(attempts.map(a =>
                a.device.startStream(a.user, a.tsFilter, a.channel, { suppressGroupCombine: true })
            ));

            if (this._demuxer.closed) {
                this.releaseCarriers();
                return;
            }

            let started = 0;
            for (let i = 0; i < results.length; i++) {
                const a = attempts[i];
                if (results[i].status === "rejected") {
                    log.error("TunerDevice#%d carrier start failed on tuner #%d `%s`",
                        this._tunerIndex, a.device.index,
                        (results[i] as PromiseRejectedResult).reason?.message);
                    continue;
                }
                started++;
                stream.pipeline(a.sourceStream, a.demuxerInput, err => {
                    if (err && !this._demuxer.closed) {
                        log.error("TunerDevice#%d pipeline error: %s", this._tunerIndex, (err as Error).message);
                    }
                });
                a.sourceStream.once("end", () => {
                    if (!a.demuxerInput.writableEnded) {
                        a.demuxerInput.end();
                    }
                    if (!this._demuxer.closed) {
                        log.warn("TunerDevice#%d carrier stream ended on tuner #%d, closing TSMFFilter",
                            this._tunerIndex, a.device.index);
                        this._demuxer.close();
                    }
                });
                this._carrierLinks.push({
                    device: a.device, user: a.user, tsFilter: a.tsFilter,
                    sourceStream: a.sourceStream, demuxerInput: a.demuxerInput
                });
            }

            if (started < required) {
                log.warn("TunerDevice#%d only %d of %d additional carriers started, retrying...",
                    this._tunerIndex, started, required);
                this.releaseCarriers();
                this._demuxer.close();
                return;
            }
            log.info("TunerDevice#%d all additional carriers started", this._tunerIndex);
        } finally {
            this._carrierInitPending = false;
        }
    }

    private _selectDevices(required: number, channelType: apid.ChannelType): TunerDevice[] {
        if (this._demuxer.closed) {
            return [];
        }

        const all = _.tuner.devices
            .map(d => _.tuner.get(d.index))
            .filter((d): d is TunerDevice =>
                !!d && d.index !== this._tunerIndex && !d.isRemote &&
                d.config.types.includes(channelType)
            );

        // 1. Prefer free devices.
        const free = all.filter(d => d.isFree);
        if (free.length >= required) {
            return free.slice(0, required);
        }

        // 2. Not enough — take over lower-priority devices, lowest priority first.
        const selected = [...free];
        const carrierPriority = _.tuner.get(this._tunerIndex)?.getPriority() ?? -1;
        if (carrierPriority >= 0) {
            const takeover = all
                .filter(d => !d.isFree && !d.isAdditionalCarrier && d.isUsing &&
                    d.getPriority() < carrierPriority)
                .sort((a, b) => a.getPriority() - b.getPriority());
            for (const d of takeover) {
                if (selected.length >= required) {
                    break;
                }
                selected.push(d);
            }
        }

        return selected.slice(0, required);
    }
}
