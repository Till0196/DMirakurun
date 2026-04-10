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
import { join, dirname } from "path";
import { existsSync } from "fs";
import { stat, mkdir, readFile, writeFile } from "fs/promises";
import { sleep } from "./common";
import * as log from "./log";
import * as db from "./db";
import * as apid from "../../api";
import _ from "./_";
import Event from "./Event";
import ChannelItem from "./ChannelItem";
import ServiceItem from "./ServiceItem";
import { DiscoveryResult } from "./StreamFilter";

function isDiscoveryResult(result: apid.Service[] | DiscoveryResult): result is DiscoveryResult {
    return result && !Array.isArray(result) && "groupId" in result && "numberOfCarriers" in result;
}

const { LOGO_DATA_DIR_PATH } = process.env;

export class Service {
    static getLogoDataPath(networkId: number, logoId: number) {
        if (typeof logoId !== "number" || logoId < 0) {
            throw new Error("Invalid `logoId`");
        }

        return join(LOGO_DATA_DIR_PATH, `${networkId}_${logoId}.png`);
    }

    static async getLogoDataMTime(networkId: number, logoId: number): Promise<number> {
        if (typeof logoId !== "number" || logoId < 0) {
            return 0;
        }

        try {
            return (await stat(Service.getLogoDataPath(networkId, logoId))).mtimeMs;
        } catch (e) {
            return 0;
        }
    }

    static async isLogoDataExists(networkId: number, logoId: number): Promise<boolean> {
        if (typeof logoId !== "number" || logoId < 0) {
            return false;
        }

        try {
            return (await stat(Service.getLogoDataPath(networkId, logoId))).isFile();
        } catch (e) {
            return false;
        }
    }

    static async loadLogoData(networkId: number, logoId: number): Promise<Buffer> {
        if (typeof logoId !== "number" || logoId < 0) {
            return null;
        }

        try {
            return await readFile(Service.getLogoDataPath(networkId, logoId));
        } catch (e) {
            return null;
        }
    }

    static async saveLogoData(networkId: number, logoId: number, data: Uint8Array, retrying = false): Promise<void> {
        log.info("Service.saveLogoData(): saving... (networkId=%d logoId=%d)", networkId, logoId);

        const path = Service.getLogoDataPath(networkId, logoId);

        try {
            await writeFile(path, data, { encoding: "binary" });
        } catch (e) {
            if (retrying === false) {
                // mkdir if not exists
                const dirPath = dirname(path);
                if (existsSync(dirPath) === false) {
                    log.warn("Service.saveLogoData(): making directory `%s`... (networkId=%d logoId=%d)", dirPath, networkId, logoId);
                    try {
                        await mkdir(dirPath, { recursive: true });
                    } catch (e) {
                        throw e;
                    }
                }
                // retry
                log.warn("Service.saveLogoData(): retrying... (networkId=%d logoId=%d)", networkId, logoId);
                return this.saveLogoData(networkId, logoId, data, true);
            }
            throw e;
        }

        log.info("Service.saveLogoData(): saved. (networkId=%d logoId=%d)", networkId, logoId);
    }

    private _items: ServiceItem[] = [];
    private _saveTimerId: NodeJS.Timeout;

    get items(): ServiceItem[] {
        return this._items;
    }

    add(item: ServiceItem): void {
        if (this.get(item.id) !== null) {
            return;
        }

        this._items.push(item);

        Event.emit("service", "create", item.export());

        this.save();
    }

    get(id: number): ServiceItem;
    get(networkId: number, serviceId: number): ServiceItem;
    get(id: number, serviceId?: number) {
        if (serviceId === undefined) {
            const l = this._items.length;
            for (let i = 0; i < l; i++) {
                if (this._items[i].id === id) {
                    return this._items[i];
                }
            }
        } else {
            const l = this._items.length;
            for (let i = 0; i < l; i++) {
                if (this._items[i].networkId === id && this._items[i].serviceId === serviceId) {
                    return this._items[i];
                }
            }
        }

        return null;
    }

    exists(id: number): boolean;
    exists(networkId: number, serviceId: number): boolean;
    exists(id: number, serviceId?: number) {
        return this.get(id, serviceId) !== null;
    }

    findByChannel(channel: ChannelItem): ServiceItem[] {
        const items = [];

        const l = this._items.length;
        for (let i = 0; i < l; i++) {
            const serviceChannel = this._items[i].channel;
            if (serviceChannel === channel || serviceChannel.isSameTsmfGroup(channel)) {
                items.push(this._items[i]);
            }
        }

        return items;
    }

    findByNetworkId(networkId: number): ServiceItem[] {
        const items = [];

        const l = this._items.length;
        for (let i = 0; i < l; i++) {
            if (this._items[i].networkId === networkId) {
                items.push(this._items[i]);
            }
        }

        return items;
    }

    findByNetworkIdWithLogoId(networkId: number, logoId: number): ServiceItem[] {
        const items = [];

        const l = this._items.length;
        for (let i = 0; i < l; i++) {
            if (this._items[i].networkId === networkId && this._items[i].logoId === logoId) {
                items.push(this._items[i]);
            }
        }

        return items;
    }

    save(): void {
        clearTimeout(this._saveTimerId);
        this._saveTimerId = setTimeout(() => this._save(), 1000 * 10);
    }

    async load(): Promise<void> {
        log.debug("loading services...");

        let updated = false;

        const services = await db.loadServices(_.configIntegrity.channels, true);
        for (const service of services) {
            const channelItem = _.channel.get(service.channel.type, service.channel.channel);

            if (channelItem === null) {
                updated = true;
                continue;
            }

            if (service.networkId === undefined || service.serviceId === undefined) {
                updated = true;
                continue;
            }

            // migrate logo data
            if (service.logoData) {
                const logoDataPath = Service.getLogoDataPath(service.networkId, service.logoId);
                log.warn("migrating deprecated property `logoData` to file `%s` in service#%d (%s) db", logoDataPath, service.id, service.name);
                Service.saveLogoData(service.networkId, service.logoId, Buffer.from(service.logoData, "base64"));

                // delete duplicates
                services.filter(s => s.networkId === service.networkId && s.logoId === service.logoId).forEach(s => {
                    delete s.logoData;
                });
                updated = true;
            }

            this.add(
                new ServiceItem(
                    channelItem,
                    service.networkId,
                    service.serviceId,
                    service.name,
                    service.type,
                    service.logoId,
                    service.remoteControlKeyId,
                    service.epgReady,
                    service.epgUpdatedAt
                )
            );
        }

        if (updated) {
            this.save();
        }

        setTimeout(() => this._initJobs(), 10000);
    }

    private async _initJobs(): Promise<void> {
        log.debug("init service jobs...");

        // add services from channel config
        for (const channelConfig of _.config.channels) {
            if (channelConfig.isDisabled || !channelConfig.serviceId) {
                continue;
            }
            const channel = _.channel.get(channelConfig.type, channelConfig.channel);
            if (!channel) {
                continue;
            }
            const serviceId = channelConfig.serviceId;
            if (this.findByChannel(channel).some(service => service.serviceId === serviceId)) {
                continue;
            }

            this._queueCheckToAdd(channel, serviceId);
        }

        // scan services (no service channel only)
        _.job.add({
            key: "Service.Add.Scan.Find-Channels",
            name: "Service Add Scan [Find Targets]",
            fn: async () => {
                for (const channel of _.channel.items) {
                    if (this.findByChannel(channel).length > 0) {
                        continue;
                    }

                    this._queueScanToAdd(channel);
                }

                // Fallback: after all initial scans finish, queue bonded scans for
                // groups that were discovered but never got enough carriers.
                _.job.add({
                    key: "Service.Add.BondedScan.Fallback",
                    name: "Service Add Bonded Scan [Fallback]",
                    fn: async () => {
                        const groupMap = new Map<number, ChannelItem[]>();
                        for (const ch of _.channel.items) {
                            if (ch.tsmfGroupId !== null && ch.tsmfGroupId !== undefined) {
                                if (!groupMap.has(ch.tsmfGroupId)) {
                                    groupMap.set(ch.tsmfGroupId, []);
                                }
                                groupMap.get(ch.tsmfGroupId).push(ch);
                            }
                        }
                        for (const [groupId, channels] of groupMap) {
                            if (channels.some(ch => this.findByChannel(ch).length > 0)) {
                                continue;
                            }
                            const bondedKey = `Service.Add.BondedScan.group${groupId}`;
                            if (_.job.jobs.some(j => j.key === bondedKey)) {
                                continue;
                            }
                            if (channels.length > 1) {
                                log.info("Fallback: queueing bonded scan for group %d with %d carriers",
                                    groupId, channels.length);
                                this._queueBondedScan(groupId, channels);
                            }
                        }
                    },
                    readyFn: async () => {
                        while (true) {
                            const pending = _.job.jobs.some(job =>
                                job.status !== "finished" &&
                                job.key.startsWith("Service.Add.Scan.") &&
                                job.key !== "Service.Add.Scan.Find-Channels"
                            );
                            if (!pending) {
                                return true;
                            }
                            await sleep(3000);
                        }
                    }
                });
            },
            readyFn: async () => {
                // wait for all Service.Check-Add.* jobs to finish
                while (true) {
                    if (_.job.jobs.some(job => job.status !== "finished" && job.key.includes("Service.Add.Check."))) {
                        await sleep(1000);
                        continue;
                    }
                    return true;
                }
            }
        });

        // schedule service scan
        _.job.add({
            key: "Service.Updater.Add-Schedule",
            name: "Service Updater [Add Schedule]",
            fn: async () => {
                _.job.addSchedule({
                    key: "Service.Updater",
                    schedule: "5 6 * * *", // todo: config
                    job: {
                        key: "Service.Updater",
                        name: "Service Updater",
                        fn: async () => {
                            for (const channel of _.channel.items) {
                                if (this.findByChannel(channel).length === 0) {
                                    continue;
                                }

                                this._queueScanToUpdate(channel);
                            }
                        }
                    }
                });
            }
        });
    }

    private _save(): void {
        log.debug("saving services...");
        db.saveServices(
            this._items.map(service => service.export()),
            _.configIntegrity.channels
        );
    }

    private _queueCheckToAdd(channel: ChannelItem, serviceId: number): void {
        _.job.add({
            key: `Service.Add.Check.${channel.type}.${channel.channel}.${serviceId}`,
            name: `Service Add Check ${channel.type}/${channel.channel}/${serviceId}`,
            fn: () => this._checkToAdd(channel, serviceId),
            readyFn: () => _.tuner.readyForJob(channel),
            retryOnFail: true,
            retryMax: (1000 * 60 * 60 * 12) / (1000 * 60 * 3), // (12時間 / retryDelay) = 12時間～
            retryDelay: 1000 * 60 * 3
        });
    }

    private _queueScanToAdd(channel: ChannelItem): void {
        // Each channel scans independently for discovery (no groupId dedup).
        // Multi-carrier channels detect groupId quickly and bail;
        // single-carrier channels complete full NIT/SDT in the same session.
        _.job.add({
            key: `Service.Add.Scan.${channel.type}.${channel.channel}`,
            name: `Service Add Scan ${channel.type}/${channel.channel}`,
            fn: async () => this._scan(channel, true),
            readyFn: () => _.tuner.readyForJob(channel),
            retryOnFail: true,
            retryMax: (1000 * 60 * 60 * 12) / (1000 * 60 * 3),
            retryDelay: 1000 * 60 * 3
        });
    }

    private _queueScanToUpdate(channel: ChannelItem): void {
        // For TSMF groups, only the first channel in the group scans
        if (channel.tsmfGroupId !== null && channel.tsmfGroupId !== undefined) {
            const first = _.channel.items.find(item => item.isSameTsmfGroup(channel));
            if (first && first.channel !== channel.channel) {
                return;
            }
        }
        _.job.add({
            key: `Service.Update.Scan.${channel.type}.${channel.channel}`,
            name: `Service Update Scan ${channel.type}/${channel.channel}`,
            fn: async () => this._scan(channel, false, false),
            readyFn: () => _.tuner.readyForJob(channel)
        });
    }

    private async _checkToAdd(channel: ChannelItem, serviceId: number): Promise<void> {
        log.info("ChannelItem#'%s' serviceId=%d check has started", channel.name, serviceId);

        let result: Awaited<ReturnType<typeof _.tuner.discoverServices>>;
        try {
            result = await _.tuner.discoverServices(channel, { serviceId });
        } catch (e) {
            log.warn("ChannelItem#'%s' serviceId=%d check has failed [%s]", channel.name, serviceId, e);
            throw new Error("Service check failed");
        }

        if (isDiscoveryResult(result)) {
            // Multi-carrier channel: service check can't complete without bonding.
            // groupId has been saved; scan jobs will handle bonded scan later.
            log.warn("ChannelItem#'%s' serviceId=%d check: multi-carrier (groupId=%d), deferring to bonded scan",
                channel.name, serviceId, result.groupId);
            throw new Error("Service check failed: multi-carrier channel requires bonded scan");
        }

        const service = result.find(service => service.serviceId === serviceId);
        if (!service) {
            log.warn("ChannelItem#'%s' serviceId=%d check has failed [no service]", channel.name, serviceId);

            // retry after 1 hour
            setTimeout(() => this._queueCheckToAdd(channel, serviceId), 3600000);
            return;
        }

        log.debug("ChannelItem#'%s' serviceId=%d: %s", channel.name, serviceId, JSON.stringify(service, null, "  "));

        this.add(
            new ServiceItem(channel, service.networkId, service.serviceId, service.name, service.type, service.logoId)
        );

        log.info("ChannelItem#'%s' serviceId=%d check has finished", channel.name, serviceId);
    }

    /**
     * Scan a channel for services.
     * @param tsmfDiscovery - true: deferred TSMF pipeline (initial scan, may return DiscoveryResult).
     *                        false: full pipeline with carrier bonding (bonded/update scans).
     */
    private async _scan(channel: ChannelItem, add: boolean, tsmfDiscovery = true): Promise<void> {
        log.info("ChannelItem#'%s' service scan has started (tsmfDiscovery=%s)", channel.name, tsmfDiscovery);

        let result: Awaited<ReturnType<typeof _.tuner.discoverServices>>;
        try {
            result = await _.tuner.discoverServices(channel, { tsmfDiscovery });
        } catch (e) {
            log.warn("ChannelItem#'%s' service scan has failed [%s]", channel.name, e);
            throw new Error("Service scan failed");
        }

        if (isDiscoveryResult(result)) {
            // Multi-carrier: groupId saved by StreamFilter, check group completeness
            const { groupId, numberOfCarriers } = result;
            log.info("ChannelItem#'%s' discovered groupId=%d numberOfCarriers=%d",
                channel.name, groupId, numberOfCarriers);
            const groupChannels = _.channel.items.filter(item =>
                item.tsmfGroupId === groupId
            );
            log.info("Group %d: %d/%d carriers discovered", groupId, groupChannels.length, numberOfCarriers);
            if (groupChannels.length >= numberOfCarriers) {
                this._queueBondedScan(groupId, groupChannels);
            }
            return;
        }

        this._applyScannedServices(channel, result, add);

        // After bonded scan completes, propagate groupId to sibling channels
        // and abort their individual scan jobs. Also save to persist groupId.
        if (!tsmfDiscovery && channel.tsmfGroupId !== null && channel.tsmfGroupId !== undefined) {
            const groupChannels = _.channel.items.filter(item =>
                item.type === channel.type &&
                item.channel !== channel.channel &&
                item.isSameTsmfGroup(channel)
            );
            for (const ch of groupChannels) {
                if (ch.tsmfGroupId !== channel.tsmfGroupId) {
                    ch.setTsmfGroupId(channel.tsmfGroupId);
                }
                const key = `Service.Add.Scan.${ch.type}.${ch.channel}`;
                _.job.abortByKey(key, "group primary scan completed");
            }
            this.save();
        }

        log.info("ChannelItem#'%s' service scan has finished", channel.name);
    }

    private _queueBondedScan(groupId: number, groupChannels: ChannelItem[]): void {
        const primaryChannel = groupChannels[0];
        const key = `Service.Add.BondedScan.group${groupId}`;
        const carrierCount = groupChannels.length;

        _.job.add({
            key,
            name: `Service Add Bonded Scan group${groupId} (${carrierCount} carriers)`,
            fn: async () => this._scan(primaryChannel, true, false),
            readyFn: async () => {
                // Wait for all initial scan jobs to finish first,
                // so all tuners are free for multi-carrier bonding.
                while (_.job.jobs.some(j =>
                    j.status !== "finished" &&
                    j.key.startsWith("Service.Add.Scan.") &&
                    j.key !== "Service.Add.Scan.Find-Channels"
                )) {
                    await sleep(3000);
                }
                return _.tuner.readyForJob(primaryChannel, carrierCount);
            },
            retryOnFail: true,
            retryMax: 3,
            retryDelay: 1000 * 60
        });
    }

    private _applyScannedServices(
        channel: ChannelItem,
        services: apid.Service[],
        add: boolean
    ): void {
        log.debug("ChannelItem#'%s' services: %s", channel.name, JSON.stringify(services, null, "  "));

        services.forEach(service => {
            const item = this.get(service.networkId, service.serviceId);
            if (item !== null) {
                item.name = service.name;
                item.type = service.type;
                if (service.logoId > -1) {
                    item.logoId = service.logoId;
                }
                item.remoteControlKeyId = service.remoteControlKeyId;
            } else if (add === true) {
                this.add(
                    new ServiceItem(
                        channel,
                        service.networkId,
                        service.serviceId,
                        service.name,
                        service.type,
                        service.logoId,
                        service.remoteControlKeyId
                    )
                );
            }
        });
    }

}

export default Service;
