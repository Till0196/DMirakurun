/*
   Copyright 2016 kanreisa

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
import * as common from "./common";
import * as log from "./log";
import * as apid from "../../api";
import _ from "./_";
import * as db from "./db";
import status from "./status";
import ChannelItem from "./ChannelItem";
import { JobItem } from "./Job";

export class Channel {
    private _items: ChannelItem[] = [];
    private _startup: boolean = true;
    private _saveTimerId: NodeJS.Timeout = null;

    constructor() {
        this._load();

        if (_.config.server.disableEITParsing !== true) {
            const epgJob: JobItem = {
                key: "EPG.Gatherer",
                name: "EPG Gatherer",
                fn: () => this._epgGatherer()
            };

            _.job.add({
                ...epgJob,
                readyFn: async () => {
                    await common.sleep(1000 * 60);
                    return true;
                }
            });

            _.job.addSchedule({
                key: epgJob.key,
                schedule: _.config.server.epgGatheringJobSchedule || "20,50 * * * *",
                job: epgJob
            });
        }
    }

    get items(): ChannelItem[] {
        return this._items;
    }

    add(item: ChannelItem): void {
        if (this.get(item.type, item.channel) === null) {
            this._items.push(item);
        }
    }

    get(type: apid.ChannelType, channel: string): ChannelItem {
        const l = this._items.length;
        for (let i = 0; i < l; i++) {
            if (this._items[i].channel === channel && this._items[i].type === type) {
                return this._items[i];
            }
        }

        return null;
    }

    findByType(type: apid.ChannelType): ChannelItem[] {
        const items = [];

        const l = this._items.length;
        for (let i = 0; i < l; i++) {
            if (this._items[i].type === type) {
                items.push(this._items[i]);
            }
        }

        return items;
    }

    /**
     * Resolve the channel(s) that carry a logical multiplex identified by
     * `(networkId, streamId)`. May return multiple ChannelItems when the
     * same logical service is reachable via more than one route — e.g. a
     * BS channel listed once with `route: SAT, channel: BS13_1` and again
     * with `route: CATV, channel: CATV_13`.
     *
     * Used by `ServiceItem.channel` (lazy lookup) and by `Service.load()`
     * to skip orphaned services after channels.yml is edited.
     */
    findByStreamId(networkId: number, streamId: number): ChannelItem[] {
        const results: ChannelItem[] = [];
        for (const channel of this._items) {
            for (const entry of channel.getStreams().values()) {
                if (entry.networkId === networkId && entry.streamId === streamId) {
                    results.push(channel);
                    break;
                }
            }
        }
        return results;
    }

    /**
     * Debounced save of `channels.json` — the per-ChannelItem auto-detected
     * stream metadata (TSMF / non-TSMF TS / direct-TLV unified). Multiple
     * calls during a scan or detection burst collapse into a single disk
     * write. Mirrors the `Service.save()` style.
     */
    save(): void {
        clearTimeout(this._saveTimerId);
        this._saveTimerId = setTimeout(() => this._save(), 500);
    }

    /**
     * Read `channels.json` and apply each record to the matching ChannelItem.
     * Restores TSMF groupId, the unified streams map, and per-service relTs
     * mappings so a fresh process can serve content without re-scanning.
     *
     * Called once at startup from `server.ts` after `_.channel` is constructed.
     */
    async load(): Promise<void> {
        log.debug("loading channels db...");

        const records = await db.loadChannels(_.configIntegrity.channels);
        for (const record of records) {
            const channel = this.get(record.type, record.channel);
            if (!channel) {
                continue;
            }
            if (record.groupId !== undefined && record.groupId !== null) {
                channel.setTsmfGroupId(record.groupId);
            }
            let firstRelTs: number | undefined;
            if (record.streams) {
                for (const entry of record.streams) {
                    let slotKey: number;
                    let isTlv: boolean;
                    let relTs: number | undefined;
                    if (entry.relTs !== undefined) {
                        slotKey = entry.relTs;
                        isTlv = false;
                        relTs = entry.relTs;
                    } else if (entry.relTlv !== undefined) {
                        slotKey = entry.relTlv;
                        isTlv = true;
                        relTs = entry.relTlv;
                    } else {
                        slotKey = 0;
                        isTlv = false;
                        relTs = undefined;
                    }
                    channel.setStream(slotKey, entry.streamId, entry.networkId, isTlv, relTs);
                    if (entry.serviceIds) {
                        for (const sid of entry.serviceIds) {
                            channel.addServiceId(sid, slotKey);
                        }
                    }
                    if (firstRelTs === undefined && relTs !== undefined) {
                        firstRelTs = relTs;
                    }
                }
            }
            if (firstRelTs !== undefined) {
                channel.setTsmfRelTs(firstRelTs);
            }
        }
        log.info("loaded channels db (%d records)", records.length);
    }

    private _save(): void {
        log.debug("saving channels db...");

        const records: db.ChannelRecord[] = [];
        for (const channel of this._items) {
            const record: db.ChannelRecord = {
                type: channel.type,
                channel: channel.channel,
                route: channel.route
            };
            let hasData = false;

            if (channel.tsmfGroupId !== null && channel.tsmfGroupId !== undefined &&
                channel.tsmfGroupId !== 255 && !channel.hasConfigTsmfGroupId) {
                record.groupId = channel.tsmfGroupId;
                hasData = true;
            }

            const streams = channel.getStreams();
            if (streams.size > 0) {
                record.streams = [];
                for (const info of streams.values()) {
                    const entry: db.ChannelStreamEntry = {
                        streamId: info.streamId,
                        networkId: info.networkId
                    };
                    if (info.relTs !== undefined) {
                        if (info.isTlv) {
                            entry.relTlv = info.relTs;
                        } else {
                            entry.relTs = info.relTs;
                        }
                    }
                    if (info.serviceIds.size > 0) {
                        entry.serviceIds = [...info.serviceIds];
                    }
                    record.streams.push(entry);
                }
                hasData = true;
            }

            if (hasData) {
                records.push(record);
            }
        }
        db.saveChannels(records, _.configIntegrity.channels)
            .catch(e => log.error("channels db save failed: %s", (e as Error).message));
    }

    private _load(): void {
        log.debug("loading channels...");

        const channels = _.config.channels;

        channels.forEach((channel, i) => {
            if (typeof channel.name !== "string") {
                log.error("invalid type of property `name` in channel#%d configuration", i);
                return;
            }

            if (channel.type !== "GR" && channel.type !== "BS" && channel.type !== "CS" && channel.type !== "SKY" && channel.type !== "BS4K") {
                log.error("invalid type of property `type` in channel#%d (%s) configuration", i, channel.name);
                return;
            }

            if (channel.route !== undefined && channel.route !== "TER" && channel.route !== "SAT" && channel.route !== "CATV" && channel.route !== "HIKARI") {
                log.error("invalid type of property `route` in channel#%d (%s) configuration", i, channel.name);
                return;
            }

            if (typeof channel.channel !== "string") {
                log.error("invalid type of property `channel` in channel#%d (%s) configuration", i, channel.name);
                return;
            }

            if (channel.serviceId && typeof channel.serviceId !== "number") {
                log.error("invalid type of property `serviceId` in channel#%d (%s) configuration", i, channel.name);
                return;
            }

            if (channel.tsmfRelTs && typeof channel.tsmfRelTs !== "number") {
                log.error("invalid type of property `tsmfRelTs` in channel#%d (%s) configuration", i, channel.name);
                return;
            }
            if (channel.tsmfGroupId && typeof channel.tsmfGroupId !== "number") {
                log.error("invalid type of property `tsmfGroupId` in channel#%d (%s) configuration", i, channel.name);
                return;
            }

            if (channel.commandVars && typeof channel.commandVars !== "object") {
                log.error("invalid type of property `commandVars` in channel#%d (%s) configuration", i, channel.name);
                return;
            }
            if (!channel.commandVars) {
                channel.commandVars = {};
            }
            if (channel.satelite && !channel.satellite) {
                log.warn("renaming deprecated property name `satelite` to `satellite` in channel#%d (%s) configuration", i, channel.name);
                (<any> channel).satellite = channel.satelite;
            }
            if (channel.satellite) {
                // deprecated but not planned to remove (soft migration)
                if (!channel.commandVars.satellite) {
                    channel.commandVars.satellite = channel.satellite;
                }
            }
            if (channel.space) {
                // deprecated but not planned to remove (soft migration)
                if (!channel.commandVars.space) {
                    channel.commandVars.space = channel.space;
                }
            }
            if (channel.freq) {
                // deprecated but not planned to remove (soft migration)
                if (!channel.commandVars.freq) {
                    channel.commandVars.freq = channel.freq;
                }
            }
            if (channel.polarity) {
                // deprecated but not planned to remove (soft migration)
                if (!channel.commandVars.polarity) {
                    channel.commandVars.polarity = channel.polarity;
                }
            }
            for (const key in channel.commandVars) {
                if (typeof channel.commandVars[key] !== "number" && typeof channel.commandVars[key] !== "string") {
                    log.error("invalid type of property `commandVars.%s` in channel#%d (%s) configuration", key, i, channel.name);
                    delete channel.commandVars[key];
                }
            }

            if (channel.isDisabled === true) {
                return;
            }

            if (_.tuner.typeExists(channel.type) === false) {
                return;
            }

            // channels.yml は tsmfRelTs に統一。runtime は TS/TLV を auto-detect。
            const configRelSlot = channel.tsmfRelTs;
            const existing = this.get(channel.type, channel.channel);
            if (existing) {
                if (channel.serviceId && configRelSlot !== undefined && configRelSlot !== null) {
                    existing.addServiceId(channel.serviceId, configRelSlot, true);
                }
            } else {
                if (channel.serviceId) {
                    (<any> channel).name = `${channel.type}:${channel.channel}`;
                }
                const item = new ChannelItem(channel);
                if (channel.serviceId && configRelSlot !== undefined && configRelSlot !== null) {
                    item.addServiceId(channel.serviceId, configRelSlot, true);
                }
                this.add(item);
            }
        });
    }

    private async _epgGatherer(): Promise<void> {
        const startup = this._startup;
        if (this._startup === true) {
            this._startup = false;
        }

        // Wait here (in the parent EPG.Gatherer fn body) — not in the
        // per-network children's readyFn — to avoid filling standby/running
        // slots and deadlocking BondedScan.
        const hasPendingBondedScan = () => _.job.jobs.some(job =>
            job.status !== "finished" && job.key.startsWith("Service.Add.BondedScan.")
        );
        if (hasPendingBondedScan()) {
            log.info("EPG gathering is yielding to pending bonded scan(s)");
            while (hasPendingBondedScan()) {
                await common.sleep(3000);
            }
        }

        // MMT/TLV networks: MH-EIT is self-stream only (ARIB STD-B60 7.3.3.9)
        // so EPG must be gathered per-channel, handled by the second loop.
        const MMT_NETWORK_IDS = new Set([0x0B, 0x0C]);

        const networkIds = [...new Set(_.service.items.map(item => item.networkId))];

        for (const networkId of networkIds) {
            if (MMT_NETWORK_IDS.has(networkId)) {
                continue;
            }
            const services = _.service.findByNetworkId(networkId);
            if (services.length === 0) {
                continue;
            }
            const service = services[0];

            // Distinct ChannelItems carrying this networkId, in channels.yml
            // order (= implicit priority). Falls through routes on getEPG
            // failure so EPG gathering picks whichever tuner is free.
            const candidateChannels: ChannelItem[] = [];
            const seen = new Set<ChannelItem>();
            for (const svc of services) {
                for (const ch of svc.channels) {
                    if (!seen.has(ch)) {
                        seen.add(ch);
                        candidateChannels.push(ch);
                    }
                }
            }
            if (candidateChannels.length === 0) {
                continue;
            }

            _.job.add({
                key: `EPG.Gather.NID.${networkId}`,
                name: `EPG Gather Network#${networkId}`,
                isRerunnable: true,
                fn: async () => {
                    log.info("Network#%d EPG gathering has started", networkId);
                    let lastError: unknown = null;
                    for (const ch of candidateChannels) {
                        if (!(await _.tuner.readyForJob(ch))) {
                            continue;
                        }
                        try {
                            log.info("Network#%d EPG gathering using %s/%s", networkId, ch.type, ch.channel);
                            await _.tuner.getEPG(ch);
                            log.info("Network#%d EPG gathering has finished", networkId);
                            return;
                        } catch (e) {
                            lastError = e;
                            log.warn("Network#%d EPG gathering on %s failed [%s], trying next route",
                                networkId, ch.channel, e);
                        }
                    }
                    log.warn("Network#%d EPG gathering has failed on all routes [%s]", networkId, lastError);
                    throw new Error("EPG gathering failed");
                },
                readyFn: async () => {
                    await common.sleep(100);

                    if (status.epg[networkId] === true) {
                        log.info("Network#%d EPG gathering is already in progress on another stream", networkId);
                        return false;
                    }
                    if (service.epgReady === true) {
                        const now = Date.now();
                        if (startup && now - service.epgUpdatedAt < 1000 * 60 * 10) { // 10 mins
                            log.info("Network#%d EPG gathering has skipped because EPG is already up to date (in 10 mins)", networkId);
                            return false;
                        }
                        if (now - service.epgUpdatedAt > 1000 * 60 * 60 * 12) { // 12 hours
                            log.info("Network#%d EPG gathering is resuming forcibly because reached maximum pause time (12 hours)", networkId);
                            service.epgReady = false;
                        } else {
                            const currentPrograms = _.program.findByNetworkIdAndTime(networkId, now)
                                .filter(program => !!program.name && program.name !== "放送休止");
                            if (currentPrograms.length === 0) {
                                const networkPrograms = _.program.findByNetworkId(networkId);
                                if (networkPrograms.length > 0) {
                                    log.info("Network#%d EPG gathering has skipped because broadcast is off", networkId);
                                    return false;
                                }
                                service.epgReady = false;
                            }
                        }
                    }

                    // Ready when ANY candidate route currently has a free tuner.
                    for (const ch of candidateChannels) {
                        if (await _.tuner.readyForJob(ch)) {
                            return true;
                        }
                    }
                    return false;
                }
            });
        }

        // MMT per-channel EPG gathering. MH-EIT is self-stream only, so each
        // BS4K channel needs its own job; multi-carrier groups consolidate to
        // a single primary channel.
        const seenGroups = new Set<number>();
        for (const channel of _.channel.items) {
            const services = channel.getServices();
            if (services.length === 0) {
                continue;
            }
            if (!MMT_NETWORK_IDS.has(services[0].networkId)) {
                continue;
            }
            const gid = channel.tsmfGroupId;
            if (gid !== null && gid !== undefined) {
                if (seenGroups.has(gid)) {
                    continue;
                }
                seenGroups.add(gid);
            }
            const service = services[0];
            const isMultiCarrier = gid !== null && gid !== undefined &&
                _.channel.items.filter(ch => ch.tsmfGroupId === gid).length > 1;

            _.job.add({
                key: `EPG.Gather.${channel.type}.${channel.channel}`,
                name: `EPG Gather ${channel.type}/${channel.channel}`,
                isRerunnable: true,
                fn: async () => {
                    if (isMultiCarrier) {
                        // Multi-carrier: wait for all type-matching tuners to
                        // be free before claiming them.
                        const typeDevices = _.tuner.devices.filter(d => d.types.includes(channel.type));
                        while (typeDevices.some(d => !d.isFree)) {
                            await common.sleep(3000);
                        }
                    }

                    log.info("Channel#%s EPG gathering has started", channel.name);
                    try {
                        await _.tuner.getEPG(channel);
                        log.info("Channel#%s EPG gathering has finished", channel.name);
                    } catch (e) {
                        log.warn("Channel#%s EPG gathering has failed [%s]", channel.name, e);
                        throw new Error("EPG gathering failed");
                    }
                },
                readyFn: async () => {
                    await common.sleep(100);

                    if (service.epgReady === true) {
                        const now = Date.now();
                        if (startup && now - service.epgUpdatedAt < 1000 * 60 * 10) { // 10 mins
                            log.info("Channel#%s EPG gathering has skipped because EPG is already up to date (in 10 mins)", channel.name);
                            return false;
                        }
                        if (now - service.epgUpdatedAt > 1000 * 60 * 60 * 12) { // 12 hours
                            log.info("Channel#%s EPG gathering is resuming forcibly because reached maximum pause time (12 hours)", channel.name);
                            service.epgReady = false;
                        } else {
                            const currentPrograms = _.program.findByNetworkIdAndServiceIdAndTime(service.networkId, service.id, now)
                                .filter(program => !!program.name && program.name !== "放送休止");
                            if (currentPrograms.length === 0) {
                                const servicePrograms = _.program.findByNetworkIdServiceId(service.networkId, service.id);
                                if (servicePrograms.length > 0) {
                                    log.info("Channel#%s EPG gathering has skipped because broadcast is off", channel.name);
                                    return false;
                                }
                                service.epgReady = false;
                            }
                        }
                    }

                    return _.tuner.readyForJob(channel);
                }
            });
        }
    }
}

export default Channel;
