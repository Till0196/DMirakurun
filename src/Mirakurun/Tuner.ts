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
import { Writable } from "stream";
import * as common from "./common";
import * as log from "./log";
import * as apid from "../../api";
import _ from "./_";
import TunerDevice, { TunerDeviceStatus } from "./TunerDevice";
import ChannelItem from "./ChannelItem";
import ServiceItem from "./ServiceItem";
import TSFilter from "./TSFilter";
import StreamFilter, { DiscoveryResult } from "./StreamFilter";
// Discard the first N bytes of cat/dvbv5-zap stdout to skip stale DVB DVR
// ring contents from the previous tune. Empirically ≤ 7 KiB on TBS6205SE.
const STALE_DVR_DRAIN_BYTES = 32 * 1024;

/**
 * Pick result from `_pickTunerDevice`. The picked `channel` is the candidate
 * whose `route` matches the picked `device`, so the caller can hand it to
 * `StreamFilter` / `TunerDevice.startStream` without re-resolving the route.
 */
interface TunerPickResult {
    device: TunerDevice;
    channel: ChannelItem;
}

export class Tuner {
    private _devices: TunerDevice[] = [];
    private _readyForJobPickedDeviceSet: Set<TunerDevice> = new Set();

    constructor() {
        this._load();
    }

    get devices(): TunerDeviceStatus[] {
        return this._devices.map(device => device.toJSON());
    }

    get(index: number): TunerDevice {
        const l = this._devices.length;
        for (let i = 0; i < l; i++) {
            if (this._devices[i].index === index) {
                return this._devices[i];
            }
        }

        return null;
    }

    /**
     * readyFn — wait until `requiredCount` tuners are available for the given channel type.
     */
    async readyForJob(channel: ChannelItem, requiredCount: number = 1): Promise<boolean> {
        const devices = this._getDevicesByType(channel.type, channel.route);
        if (devices.length === 0) {
            log.error("readyForJob: no tuners for channel type=%s route=%s", channel.type, channel.route);
            return false;
        }

        while (true) {
            // Count free devices (excluding already-picked ones)
            const freeDevices = devices.filter(d =>
                d.isFree && !this._readyForJobPickedDeviceSet.has(d)
            );
            // Also count devices already tuned to same channel/group (can be joined)
            const joinableDevices = devices.filter(d =>
                d.isAvailable && d.channel && !d.isAdditionalCarrier &&
                (d.channel === channel || d.channel.isSameTsmfGroup(channel)) &&
                !this._readyForJobPickedDeviceSet.has(d)
            );
            const available = freeDevices.length + joinableDevices.length;

            if (available >= requiredCount) {
                // Pick one device to reserve
                const picked = this._pickTunerDevice(devices, channel, -1);
                if (picked && !this._readyForJobPickedDeviceSet.has(picked.device)) {
                    const device = picked.device;
                    this._readyForJobPickedDeviceSet.add(device);
                    setTimeout(() => {
                        this._readyForJobPickedDeviceSet.delete(device);
                    }, 1000 * 5);
                    return true;
                }
            }
            await common.sleep(1000 * 10);
        }
    }

    typeExists(type: apid.ChannelType): boolean {
        const l = this._devices.length;
        for (let i = 0; i < l; i++) {
            if (this._devices[i].config.types.includes(type) === true) {
                return true;
            }
        }

        return false;
    }

    initChannelStream(channel: ChannelItem, userReq: common.UserRequest, output: Writable, tsmfRelTs?: number): Promise<StreamFilter | TSFilter> {
        let networkId: number;

        const services = channel.getServices();
        if (services.length !== 0) {
            networkId = services[0].networkId;
        }

        return this._initTS({
            ...userReq,
            streamSetting: {
                channel,
                networkId,
                parseEIT: true,
                tsmfRelTs
            }
        }, output);
    }

    initServiceStream(service: ServiceItem, userReq: common.UserRequest, output: Writable): Promise<StreamFilter | TSFilter> {
        const channels = _.channel.findByService(service.networkId, service.serviceId);
        return this._initTS({
            ...userReq,
            streamSetting: {
                channel: channels[0] ?? service.channel,
                channels: channels.length > 0 ? channels : undefined,
                serviceId: service.serviceId,
                networkId: service.networkId,
                parseEIT: true
            }
        }, output);
    }

    initProgramStream(program: apid.Program, userReq: common.UserRequest, output: Writable): Promise<StreamFilter | TSFilter> {
        const service = _.service.get(program.networkId, program.serviceId);
        const channels = _.channel.findByService(service.networkId, service.serviceId);
        return this._initTS({
            ...userReq,
            streamSetting: {
                channel: channels[0] ?? service.channel,
                channels: channels.length > 0 ? channels : undefined,
                serviceId: program.serviceId,
                eventId: program.eventId,
                networkId: program.networkId,
                parseEIT: true
            }
        }, output);
    }

    async getEPG(channel: ChannelItem, time?: number): Promise<void> {
        let timeout: NodeJS.Timeout;
        if (!time) {
            time = _.config.server.epgRetrievalTime || 1000 * 60 * 10;
        }

        let networkId: number;

        const services = channel.getServices();
        if (services.length === 0) {
            throw new Error("no available services in channel");
        }

        networkId = services[0].networkId;

        const tsFilter = await this._initTS({
            id: "Mirakurun:getEPG()",
            priority: -1,
            disableDecoder: true,
            streamSetting: {
                channel,
                networkId,
                parseEIT: true,
                drainBytes: STALE_DVR_DRAIN_BYTES
            }
        });

        if (tsFilter === null) {
            return;
        }

        return new Promise<void>((resolve) => {
            const fin = () => {
                clearTimeout(timeout);
                tsFilter.close();
            };
            timeout = setTimeout(fin, time);
            tsFilter.once("epgReady", fin);
            tsFilter.once("close", () => {
                fin();
                resolve();
            });
        });
    }

    async getServices(channel: ChannelItem, user: Partial<common.User> = {}): Promise<apid.Service[]> {
        // Upstream-shape: full pipeline, no TSMF discovery early-bail. Always
        // returns Service[] (or rejects). For the deferred TSMF discovery
        // flow, callers should use `discoverServices` instead.
        const result = await this.discoverServices(channel, { ...user, tsmfDiscovery: false });
        if (!Array.isArray(result)) {
            throw new Error("getServices unexpectedly returned a discovery result; use discoverServices for the deferred TSMF flow");
        }
        return result;
    }

    /**
     * Scan a channel and return either the parsed service list or, when
     * `tsmfDiscovery` is true (the default for initial scans), a
     * `DiscoveryResult` for multi-carrier TSMF channels that need a separate
     * bonded scan to complete.
     */
    async discoverServices(
        channel: ChannelItem,
        options: Partial<common.User> & {
            serviceId?: number;
            tsmfRelTs?: number;
            tsmfDiscovery?: boolean;
        } = {}
    ): Promise<apid.Service[] | DiscoveryResult> {
        const { serviceId, tsmfRelTs: explicitRelTs, tsmfDiscovery = true, ...user } = options;
        const tsmfRelTs = explicitRelTs ?? (serviceId !== undefined && serviceId !== null
            ? channel.getRelTs(serviceId)
            : undefined);

        const tsFilter = await this._initTS({
            id: "Mirakurun:getServices()",
            priority: -1,
            disableDecoder: true,
            streamSetting: {
                channel,
                parseNIT: true,
                parseSDT: true,
                tsmfRelTs,
                tsmfDiscovery,
                drainBytes: STALE_DVR_DRAIN_BYTES
            },
            ...user
        });
        return new Promise<apid.Service[] | DiscoveryResult>((resolve, reject) => {
            let network = {
                networkId: -1,
                areaCode: -1,
                remoteControlKeyId: -1
            };
            let services: apid.Service[] = null;
            let discoveryResult: DiscoveryResult = null;

            // discovery: bails on Extended header (~ms). bonded scan: needs
            // carrier bonding + TLV-NIT/SDT (~25-35s).
            const timeoutMs = tsmfDiscovery ? 20000 : 45000;
            setTimeout(() => tsFilter.close(), timeoutMs);

            tsFilter.once("discovery", (result: DiscoveryResult) => {
                discoveryResult = result;
                tsFilter.close();
            });

            Promise.all<void>([
                new Promise((resolve, reject) => {
                    tsFilter.once("network", _network => {
                        network = _network;
                        resolve();
                    });
                }),
                new Promise((resolve, reject) => {
                    tsFilter.once("services", _services => {
                        services = _services;
                        resolve();
                    });
                })
            ]).then(() => tsFilter.close());

            tsFilter.once("close", () => {
                tsFilter.removeAllListeners("network");
                tsFilter.removeAllListeners("services");
                tsFilter.removeAllListeners("discovery");

                if (discoveryResult) {
                    resolve(discoveryResult);
                } else if (network.networkId === -1) {
                    reject(new Error("stream has closed before get network"));
                } else if (services === null) {
                    reject(new Error("stream has closed before get services"));
                } else {
                    if (network.remoteControlKeyId !== -1) {
                        services.forEach(service => {
                            service.remoteControlKeyId = network.remoteControlKeyId;
                        });
                    }

                    resolve(services);
                }
            });
        });
    }

    private _load(): this {
        log.debug("loading tuners...");

        const tuners = _.config.tuners;

        tuners.forEach((tuner, i) => {
            if (!tuner.name || !tuner.types || (!tuner.remoteMirakurunHost && !tuner.command)) {
                log.error("missing required property in tuner#%s configuration", i);
                return;
            }

            if (typeof tuner.name !== "string") {
                log.error("invalid type of property `name` in tuner#%s configuration", i);
                return;
            }

            if (Array.isArray(tuner.types) === false) {
                console.log(tuner);
                log.error("invalid type of property `types` in tuner#%s configuration", i);
                return;
            }

            if (!tuner.remoteMirakurunHost && typeof tuner.command !== "string") {
                log.error("invalid type of property `command` in tuner#%s configuration", i);
                return;
            }

            if (tuner.dvbDevicePath && typeof tuner.dvbDevicePath !== "string") {
                log.error("invalid type of property `dvbDevicePath` in tuner#%s configuration", i);
                return;
            }

            if (tuner.remoteMirakurunHost && typeof tuner.remoteMirakurunHost !== "string") {
                log.error("invalid type of property `remoteMirakurunHost` in tuner#%s configuration", i);
                return;
            }

            if (tuner.remoteMirakurunPort && Number.isInteger(tuner.remoteMirakurunPort) === false) {
                log.error("invalid type of property `remoteMirakurunPort` in tuner#%s configuration", i);
                return;
            }

            if (tuner.remoteMirakurunDecoder !== undefined && typeof tuner.remoteMirakurunDecoder !== "boolean") {
                log.error("invalid type of property `remoteMirakurunDecoder` in tuner#%s configuration", i);
                return;
            }

            if (tuner.isDisabled) {
                return;
            }

            this._devices.push(
                new TunerDevice(i, tuner)
            );
        });

        log.info("%s of %s tuners loaded", this._devices.length, tuners.length);

        return this;
    }

    private async _initTS(user: common.User, dest?: Writable): Promise<StreamFilter | TSFilter | null> {
        const setting = user.streamSetting;

        if (_.config.server.disableEITParsing === true) {
            setting.parseEIT = false;
        }

        const candidateChannels = this._resolveCandidateChannels(setting);
        const routes = candidateChannels.map(ch => ch.route);
        const devices = this._getDevicesByType(setting.channel.type, routes);
        let tryCount = 50;

        if (!dest) {
            const remoteResult = await this._useRemoteData(user, devices);
            if (remoteResult) {
                return null;
            }
        }

        while (tryCount > 0) {
            const picked = this._pickTunerDevice(devices, candidateChannels, user.priority);

            if (picked === null) {
                // retry
                tryCount--;
                if (tryCount <= 0) {
                    throw new Error("no available tuners");
                }
                await new Promise(resolve => setTimeout(resolve, 250));
                continue;
            }

            const { device, channel: pickedChannel } = picked;

            // Commit the picked channel so downstream code (StreamFilter,
            // TunerDevice command template) uses the correct route.
            setting.channel = pickedChannel;
            this._resolveTsmfSlot(setting, pickedChannel);

            // Create StreamFilter — handles format detection (TS/TLV) and
            // routes to TSFilter or TLVFilter automatically
            const streamFilter = new StreamFilter({
                output: dest,
                decoder: device.decoder,
                tlvToTsDecoder: device.tlvToTsDecoder,
                tlvDecoder: device.tlvDecoder,
                disableDecoder: user.disableDecoder,
                outputFormat: user.outputFormat,
                networkId: setting.networkId,
                serviceId: setting.serviceId,
                eventId: setting.eventId,
                parseNIT: setting.parseNIT,
                parseSDT: setting.parseSDT,
                parseEIT: setting.parseEIT,
                tsmfRelTs: setting.tsmfRelTs ?? pickedChannel.getRelTs(setting.serviceId),
                channel: pickedChannel,
                tunerIndex: device.index,
                tsmfDiscovery: setting.tsmfDiscovery
            });

            Object.defineProperty(user, "streamInfo", {
                get: () => streamFilter.streamInfo
            });

            try {
                await device.startStream(user, streamFilter, pickedChannel, {
                    drainBytes: setting.drainBytes
                });
                return streamFilter;
            } catch (err) {
                streamFilter.end();
                throw err;
            }
        }
    }

    /**
     * Build the ordered list of candidate channels for `_initTS`. When the
     * caller passed `setting.channels` (multi-route service streaming) it is
     * used as-is; otherwise we fall back to the single `setting.channel`.
     * An empty list falls back to `[setting.channel]` for backward compat.
     */
    private _resolveCandidateChannels(setting: common.User["streamSetting"]): ChannelItem[] {
        const channels = setting.channels && setting.channels.length > 0
            ? setting.channels.filter(ch => ch)
            : [setting.channel];
        return channels.length > 0 ? channels : [setting.channel];
    }

    /**
     * Resolve the route-dependent TSMF slot for `pickedChannel` in-place on
     * `setting`. TSMF carriers also need `drainBytes` so the downstream
     * TSMFFilter does not lock onto stale DVR contents.
     */
    private _resolveTsmfSlot(setting: common.User["streamSetting"], pickedChannel: ChannelItem): void {
        if (setting.tsmfRelTs === undefined && setting.tsmfRelTlv === undefined) {
            let entry = setting.serviceId !== undefined && setting.serviceId !== null
                ? pickedChannel.getStreamForService(setting.serviceId)
                : undefined;
            if (!entry && pickedChannel.tsmfRelTs !== undefined && pickedChannel.tsmfRelTs !== null) {
                entry = pickedChannel.getStreams().get(pickedChannel.tsmfRelTs);
            }
            if (entry?.relTs !== undefined) {
                if (entry.isTlv) {
                    setting.tsmfRelTlv = entry.relTs;
                } else {
                    setting.tsmfRelTs = entry.relTs;
                }
            }
        }

        if (setting.drainBytes === undefined &&
            (setting.tsmfRelTs !== undefined || setting.tsmfRelTlv !== undefined)) {
            setting.drainBytes = STALE_DVR_DRAIN_BYTES;
        }
    }

    /**
     * リモートデータ利用 (EPG)
     */
    private async _useRemoteData(
        user: common.User,
        devices: TunerDevice[]
    ): Promise<boolean> {
        const setting = user.streamSetting;

        const remoteDevice = devices.find(device => device.isRemote);
        if (remoteDevice && setting.networkId !== undefined && setting.parseEIT === true) {
            try {
                const programs = await remoteDevice.getRemotePrograms({ networkId: setting.networkId });
                await common.sleep(1000);
                _.program.findByNetworkIdAndReplace(setting.networkId, programs);
                for (const service of _.service.findByNetworkId(setting.networkId)) {
                    service.epgReady = true;
                }
                await common.sleep(1000);
                return true;
            } catch (err) {
                throw err;
            }
        }

        return false;
    }

    /**
     * Pick a tuner device for one of the candidate channels.
     *
     * Accepts multiple candidates (one per route) when a service can be
     * tuned via more than one route. The returned `channel` is committed to
     * the picked device's route so the caller hands it straight to
     * `StreamFilter` / `TunerDevice.startStream` without re-resolving.
     */
    private _pickTunerDevice(
        devices: TunerDevice[],
        channels: ChannelItem[] | ChannelItem,
        priority: number
    ): TunerPickResult | null {
        const candidateChannels = Array.isArray(channels) ? channels : [channels];
        if (candidateChannels.length === 0) {
            return null;
        }

        const channelForDevice = (device: TunerDevice): ChannelItem => {
            const deviceRoutes = device.config.routes;
            if (!deviceRoutes || deviceRoutes.length === 0) {
                // No route constraint on the tuner — first candidate wins.
                return candidateChannels[0];
            }
            for (const ch of candidateChannels) {
                if (deviceRoutes.includes(ch.route)) {
                    return ch;
                }
            }
            return candidateChannels[0];
        };

        // 1. join to existing (cross-route aware: TSMF group / same-channel)
        for (const device of devices) {
            if (device.isAvailable !== true || !device.channel) {
                continue;
            }
            // Skip devices used as additional carriers — they have no TSMFFilter/decoder
            if (device.isAdditionalCarrier) {
                continue;
            }
            for (const ch of candidateChannels) {
                if (device.channel === ch || device.channel.isSameTsmfGroup(ch)) {
                    return { device, channel: ch };
                }
            }
        }

        // 2. start as new
        for (const device of devices) {
            if (device.isFree === true) {
                return { device, channel: channelForDevice(device) };
            }
        }

        // 3. replace existing
        for (const device of devices) {
            if (device.isAvailable === true && device.users.length === 0) {
                return { device, channel: channelForDevice(device) };
            }
        }

        // 4. takeover existing (prefer single-carrier first, then multi-carrier parent)
        // Killing a multi-carrier parent automatically frees all its carrier tuners.
        if (priority >= 0) {
            const candidates = devices
                .filter(d => d.isUsing === true && !d.isAdditionalCarrier && d.getPriority() < priority);

            // Sort: single-carrier first (less disruption), then by priority ascending
            candidates.sort((a, b) => {
                const aMulti = a.isMultiCarrier ? 1 : 0;
                const bMulti = b.isMultiCarrier ? 1 : 0;
                if (aMulti !== bMulti) {
                    return aMulti - bMulti;
                }
                return a.getPriority() - b.getPriority();
            });

            if (candidates.length > 0) {
                const device = candidates[0];
                return { device, channel: channelForDevice(device) };
            }
        }

        return null;
    }

    /**
     * Filter tuner devices that can handle a given type + route(s).
     *
     * - Tuners with no `routes` config accept every route (backward
     *   compatibility — existing tuners.yml files continue to work).
     * - Tuners with `routes` set are matched only when their route list
     *   intersects the requested `routes`.
     *
     * `routes` accepts a single route, an array of routes (preserves input
     * order, dedupes devices), or `undefined` to skip the route filter.
     */
    private _getDevicesByType(
        type: apid.ChannelType,
        routes?: apid.ChannelRoute | apid.ChannelRoute[]
    ): TunerDevice[] {
        const routeList = routes === undefined
            ? undefined
            : Array.isArray(routes) ? routes : [routes];

        const seen = new Set<TunerDevice>();
        const result: TunerDevice[] = [];

        const matchesRoute = (device: TunerDevice, route?: apid.ChannelRoute) => {
            if (route === undefined) {
                return true;
            }
            if (device.config.routes === undefined || device.config.routes.length === 0) {
                return true;
            }
            return device.config.routes.includes(route);
        };

        if (!routeList) {
            for (const device of this._devices) {
                if (device.config.types.includes(type) && !seen.has(device)) {
                    seen.add(device);
                    result.push(device);
                }
            }
            return result;
        }

        // Preserve the order implied by the route list so higher-priority
        // routes (earlier in `channels.yml`) are tried first.
        const seenRoutes = new Set<apid.ChannelRoute>();
        for (const route of routeList) {
            if (seenRoutes.has(route)) {
                continue;
            }
            seenRoutes.add(route);
            for (const device of this._devices) {
                if (seen.has(device) || !device.config.types.includes(type)) {
                    continue;
                }
                if (matchesRoute(device, route)) {
                    seen.add(device);
                    result.push(device);
                }
            }
        }
        return result;
    }
}

export default Tuner;
