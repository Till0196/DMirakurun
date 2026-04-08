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
import status from "./status";
import ChannelItem from "./ChannelItem";
import { JobItem } from "./Job";

export class Channel {
    private _items: ChannelItem[] = [];
    private _startup: boolean = true;

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

            const existing = this.get(channel.type, channel.channel);
            if (existing) {
                if (channel.serviceId && channel.tsmfRelTs !== undefined && channel.tsmfRelTs !== null) {
                    existing.addTsmfRelTsMapping(channel.serviceId, channel.tsmfRelTs, true);
                }
            } else {
                if (channel.serviceId) {
                    (<any> channel).name = `${channel.type}:${channel.channel}`;
                }
                const item = new ChannelItem(channel);
                if (channel.serviceId && channel.tsmfRelTs !== undefined && channel.tsmfRelTs !== null) {
                    item.addTsmfRelTsMapping(channel.serviceId, channel.tsmfRelTs, true);
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

        // MMT/TLV network IDs: MH-EIT only contains self TLV stream data (ARIB STD-B60 7.3.3.9),
        // so EPG must be gathered per-channel, not per-network.
        const MMT_NETWORK_IDS = new Set([0x0B, 0x0C]);

        const addEPGJob = (networkId, service) => {
            _.job.add({
                key: `EPG.Gather.NID.${networkId}`,
                name: `EPG Gather Network#${networkId}`,
                isRerunnable: true,
                fn: async () => {
                    log.info("Network#%d EPG gathering has started", networkId);
                    try {
                        await _.tuner.getEPG(service.channel);
                        log.info("Network#%d EPG gathering has finished", networkId);
                    } catch (e) {
                        log.warn("Network#%d EPG gathering has failed [%s]", networkId, e);
                        throw new Error("EPG gathering failed");
                    }
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
                        return _.tuner.readyForJob(service.channel);
                    }
                }
            });
        };

        const addMMTEPGJob = (channel, service) => {
            const isMultiCarrier = (() => {
                const gid = channel.tsmfGroupId;
                if (gid === null || gid === undefined) { return false; }
                return _.channel.items.filter(ch => ch.tsmfGroupId === gid).length > 1;
            })();

            _.job.add({
                key: `EPG.Gather.MMT.${channel.channel}`,
                name: `EPG Gather MMT/${channel.channel}`,
                isRerunnable: true,
                fn: async () => {
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
                        // Multi-carrier: wait for all BS4K-capable tuners to be free
                        if (isMultiCarrier) {
                            const typeDevices = _.tuner.devices.filter(d => d.types.includes(channel.type));
                            while (true) {
                                if (typeDevices.every(d => d.isFree)) { break; }
                                await common.sleep(3000);
                            }
                        }
                        return _.tuner.readyForJob(channel);
                    }
                }
            });
        };

        const networkIds = [...new Set(_.service.items.map(item => item.networkId))];
        for (const networkId of networkIds) {
            // MMT: MH-EIT is self-stream only, skip per-network gathering
            if (MMT_NETWORK_IDS.has(networkId)) {
                continue;
            }
            const services = _.service.findByNetworkId(networkId);
            if (services.length === 0) {
                continue;
            }
            addEPGJob(networkId, services[0]);
        }

        // MMT: per-channel EPG gathering (MH-EIT is self-stream only)
        // For multi-carrier groups, only the first channel gathers EPG
        const seenGroups = new Set<number>();
        for (const channel of _.channel.items) {
            const services = channel.getServices();
            if (services.length === 0) {
                continue;
            }
            if (!MMT_NETWORK_IDS.has(services[0].networkId)) {
                continue;
            }
            // Skip non-primary carriers in bonded groups
            const gid = channel.tsmfGroupId;
            if (gid !== null && gid !== undefined) {
                if (seenGroups.has(gid)) {
                    continue;
                }
                seenGroups.add(gid);
            }
            addMMTEPGJob(channel, services[0]);
        }
    }
}

export default Channel;
