/*
   Copyright 2016 kanreisa
   Copyright 2024 otya
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
import { Writable } from "stream";
import EventEmitter = require("eventemitter3");
import { StreamInfo } from "./common";
import * as log from "./log";
import status from "./status";
import _ from "./_";
import * as apid from "../../api";
import { getProgramItemId } from "./Program";
import Service from "./Service";
import ChannelItem from "./ChannelItem";
import { MMTTLVReader, createMMTTLVReader } from "arib-mmt-tlv-ts";
import {
    MHEventInformationTable,
    MHServiceDescriptionTable,
    MHTimeOffsetTable,
    MMTPackageTable,
    PackageListTable,
    mmtPackageIdToServiceId,
    MHCommonDataTable,
    MH_CDT_DATA_TYPE_LOGO_DATA,
    MH_CDT_LOGO_TYPE_LARGE
} from "arib-mmt-tlv-ts/mmt-si.js";
import { TLVNetworkInformationTable } from "arib-mmt-tlv-ts/tlv-si.js";
import MHEPG from "./MHEPG";
import { MH_LOGO_TRANSMISSION_TYPE_DIRECT } from "arib-mmt-tlv-ts/mmt-si-descriptor.js";
import { mjdBCDToUnixEpoch } from "arib-mmt-tlv-ts/utils.js";

const textDecoder = new TextDecoder();
function decodeUTF8(buffer: Uint8Array): string {
    return textDecoder.decode(buffer, { stream: false });
}

export interface TLVFilterOptions {
    readonly output?: Writable;
    readonly networkId?: number;
    readonly serviceId?: number;
    readonly eventId?: number;
    readonly parseNIT?: boolean;
    readonly parseSDT?: boolean;
    readonly parseEIT?: boolean;
    readonly channelItem: ChannelItem;
}

interface BasicExtState {
    basic: {
        flags: FlagState[];
        lastFlagsId: number;
    };
    extended: {
        flags: FlagState[];
        lastFlagsId: number;
    };
}

interface FlagState {
    flag: Buffer;
    ignore: Buffer;
    version_number: number;
}

export default class TLVFilter extends EventEmitter {

    streamInfo: StreamInfo = {};

    private _reader: MMTTLVReader;

    // output
    private _output: Writable;

    // options
    private _provideServiceId: number;
    private _provideEventId: number;
    private _parseNIT = false;
    private _parseSDT = false;
    private _parseEIT = false;
    private _targetNetworkId: number;

    // epg
    private _epg: MHEPG;
    private _epgReady = false;
    private _epgState: { [networkId: number]: { [serviceId: number]: BasicExtState } } = {};

    // stream info
    private _trackStreamInfo = false;
    private _tlvParseBuf: Buffer = null;

    // state
    private _closed = false;
    private _ready = true;
    private _serviceIds = new Set<number>();
    private _parseServiceIds = new Set<number>();
    private _mptPid = -1;
    private _streamInfoEmitted = false;
    private _pmtTimer: NodeJS.Timeout;
    private _streamTime: number = null;
    private _provideEventLastDetectedAt = -1;
    private _provideEventTimeout: NodeJS.Timeout = null;

    private _eventEndTimeout = _.config.server.eventEndTimeout || 1000;

    private _channelItem: ChannelItem;

    private _remoteControlKeyIdMap: Map<number, number> = null;
    private _logoTransmissions: Map<number, {
        startSectionNumber: number;
        numberOfSections: number;
        logoVersion: number;
        receivedSections: number;
        data: Uint8Array[];
    }> = new Map();

    constructor(options: TLVFilterOptions) {
        super();

        this._reader = createMMTTLVReader();
        this._targetNetworkId = options.networkId || null;
        this._provideServiceId = options.serviceId || null;
        this._provideEventId = options.eventId || null;
        this._channelItem = options.channelItem;

        if (this._provideServiceId !== null) {
            this._ready = false;
        }
        if (this._provideEventId !== null) {
            this._ready = false;

            const program = _.program.get(
                getProgramItemId(
                    this._targetNetworkId,
                    this._provideServiceId,
                    this._provideEventId
                )
            );
            if (program) {
                let timeout = program.startAt + program.duration - Date.now();
                if (program.duration === 1) {
                    timeout += 1000 * 60 * 3;
                }
                if (timeout < 0) {
                    timeout = 1000 * 60 * 3;
                }
                this._provideEventTimeout = setTimeout(() => this._observeProvideEvent(), timeout);
            }
        }
        if (options.output) {
            this._output = options.output;
            this._output.once("finish", this._close.bind(this));
            this._output.once("close", this._close.bind(this));
        } else {
            this._provideServiceId = null;
            this._provideEventId = null;
            this._ready = false;
        }
        if (options.parseNIT === true) {
            this._parseNIT = true;
        }
        if (options.parseSDT === true) {
            this._parseSDT = true;
        }
        if (options.parseEIT === true) {
            this._parseEIT = true;
        }

        this._reader.addEventListener("plt", (e) => this._onPLT(e.table));
        this._reader.addEventListener("mpt", (e) => this._onMPT(e.table));
        this._reader.addEventListener("nit", (e) => this._onNIT(e.table));
        this._reader.addEventListener("sdt", (e) => this._onSDT(e.table));
        this._reader.addEventListener("eit", (e) => this._onEIT(e.table));
        this._reader.addEventListener("tot", (e) => this._onTOT(e.table));
        this._reader.addEventListener("cdt", (e) => this._onCDT(e.table));

        // Stream quality tracking (only when output exists, matching TSFilter)
        if (options.output) {
            this._trackStreamInfo = true;
        }

        this.once("end", this._close.bind(this));
        this.once("close", this._close.bind(this));

        log.info("TLVFilter: created (serviceId=%d, eventId=%d)", this._provideServiceId, this._provideEventId);

        if (this._ready === false) {
            log.info("TLVFilter: waiting for serviceId=%d, eventId=%d", this._provideServiceId, this._provideEventId);
        }

        ++status.streamCount.tlvFilter;
    }

    get closed(): boolean {
        return this._closed;
    }

    write(chunk: Buffer): void {
        if (this._closed) {
            return;
        }
        if (this._trackStreamInfo) {
            this._countTLVPackets(chunk);
        }
        this._reader.push(chunk);
        if (this._ready && this._output) {
            this._output.write(chunk);
        }
    }

    end(): void {
        this._close();
    }

    close(): void {
        this._close();
    }

    private _countTLVPackets(chunk: Buffer): void {
        const buf = this._tlvParseBuf ? Buffer.concat([this._tlvParseBuf, chunk]) : chunk;
        this._tlvParseBuf = null;
        let pos = 0;

        while (pos + 4 <= buf.length) {
            if (buf[pos] !== 0x7f) {
                ++pos;
                continue;
            }
            const type = buf[pos + 1];
            const len = (buf[pos + 2] << 8) | buf[pos + 3];
            const pktEnd = pos + 4 + len;
            if (pktEnd > buf.length) {
                this._tlvParseBuf = buf.subarray(pos);
                return;
            }
            const key = String(type);
            if (this.streamInfo[key] === undefined) {
                this.streamInfo[key] = { packet: 0, drop: 0 };
            }
            ++this.streamInfo[key].packet;
            pos = pktEnd;
        }
        if (pos < buf.length) {
            this._tlvParseBuf = buf.subarray(pos);
        }
    }


    private _onPLT(plt: PackageListTable): void {
        const newServiceIds = new Set<number>();

        for (const pkg of plt.packages) {
            const serviceId = mmtPackageIdToServiceId(pkg.mmtPackageId);
            newServiceIds.add(serviceId);

            if (serviceId === this._provideServiceId) {
                if (this._mptPid !== pkg.locationInfo.packetId) {
                    this._mptPid = pkg.locationInfo.packetId;
                }
            }
        }

        // Only log and update when PLT content changes
        if (this._serviceIds.size === newServiceIds.size &&
            [...newServiceIds].every(id => this._serviceIds.has(id))) {
            return;
        }

        this._serviceIds = newServiceIds;
        this._parseServiceIds = new Set();

        for (const pkg of plt.packages) {
            const serviceId = mmtPackageIdToServiceId(pkg.mmtPackageId);
            const item = this._targetNetworkId === null ? null : _.service.get(this._targetNetworkId, serviceId);

            log.debug(
                "TLVFilter#_onPLT: detected MPT PID=%d as serviceId=%d (%s)",
                pkg.locationInfo.packetId, serviceId, item ? item.name : "unregistered"
            );

            if (this._parseEIT && item) {
                for (const service of this._channelItem.getServices()) {
                    if (this._parseServiceIds.has(service.serviceId) === false) {
                        this._parseServiceIds.add(service.serviceId);
                        log.debug("TLVFilter#_onPLT: parsing serviceId=%d (%s)", service.serviceId, service.name);
                    }
                }
            }
        }
    }

    private _onMPT(mpt: MMTPackageTable): void {
        if (this._ready === false && this._provideServiceId !== null && this._provideEventId === null) {
            if (mmtPackageIdToServiceId(mpt.mmtPackageId) !== this._provideServiceId) {
                return;
            }
            this._ready = true;
            log.info("TLVFilter#_onMPT: now ready for serviceId=%d", this._provideServiceId);
        }
    }

    private _onNIT(nit: TLVNetworkInformationTable): void {
        if (nit.tableId !== "TLV-NIT[actual]") {
            return;
        }

        const streamIdList = nit.tlvStreams.map(s => s.tlvStreamId);
        const channels = streamIdList.map(s => ({
            type: this._channelItem.type,
            channel: `${s}`
        }));
        this.emit("networkStreams", channels);
        // streamInfo is emitted from `_onSDT` using `SDT[actual].tlvStreamId`,
        // which uniquely identifies the currently received stream. The NIT's
        // `tlvStreams[]` is a network-wide list and `[0]` is not necessarily
        // the current stream.

        // Extract carrier bonding info (groupId per frequency/channel)
        for (const tlvStream of nit.tlvStreams) {
            for (const desc of tlvStream.descriptors) {
                if (desc.tag === "channelBondingCableDeliverySystem") {
                    this.emit("carrierBonding", {
                        tlvStreamId: tlvStream.tlvStreamId,
                        carriers: desc.carriers.map(c => ({
                            frequency: c.frequency,
                            groupId: c.groupId
                        }))
                    });
                }
            }
        }

        if (this._remoteControlKeyIdMap !== null) {
            return;
        }

        const _network = {
            networkId: nit.networkId,
            areaCode: -1,
            remoteControlKeyId: -1
        };

        this._remoteControlKeyIdMap = new Map();
        for (const desc of nit.networkDescriptors) {
            switch (desc.tag) {
                case "remoteControlKey":
                    for (const key of desc.keys) {
                        this._remoteControlKeyIdMap.set(key.serviceId, key.remoteControlKeyId);
                    }
                    break;
            }
        }

        this.emit("network", _network);
    }

    private _onSDT(sdt: MHServiceDescriptionTable): void {
        if (this._remoteControlKeyIdMap === null) {
            return;
        }

        if (sdt.tableId !== "SDT[actual]") {
            return;
        }

        // SDT[actual] uniquely identifies the currently received TLV stream.
        if (!this._streamInfoEmitted) {
            this._streamInfoEmitted = true;
            this.emit("streamInfo", {
                streamId: sdt.tlvStreamId,
                networkId: sdt.originalNetworkId
            });
        }

        const _services: Partial<apid.Service>[] = [];

        for (const service of sdt.services) {
            if (this._serviceIds.has(service.serviceId) === false) {
                continue;
            }

            let name = "";
            let type = -1;
            let logoId = -1;

            for (const desc of service.descriptors) {
                if (desc.tag === "mhServiceDescriptor") {
                    name = decodeUTF8(desc.serviceName);
                    type = desc.serviceType;
                }

                if (desc.tag === "mhLogoTransmission") {
                    logoId = desc.logoId;
                    if (desc.logoTransmissionType === MH_LOGO_TRANSMISSION_TYPE_DIRECT) {
                        const largeLogo = desc.logoList.find(x => x.logoType === MH_CDT_LOGO_TYPE_LARGE);
                        if (largeLogo !== undefined) {
                            const p = this._logoTransmissions.get(logoId);
                            if (p === undefined || p.logoVersion !== desc.logoVersion) {
                                this._logoTransmissions.set(logoId, {
                                    startSectionNumber: largeLogo.startSectionNumber,
                                    numberOfSections: largeLogo.numOfSections,
                                    logoVersion: desc.logoVersion,
                                    receivedSections: 0,
                                    data: []
                                });
                            }
                        }
                    }
                }

                if (name !== "" && logoId !== -1) {
                    break;
                }
            }

            if (_services.some(_service => _service.serviceId === service.serviceId) === false) {
                _services.push({
                    networkId: sdt.originalNetworkId,
                    serviceId: service.serviceId,
                    name,
                    type,
                    logoId,
                    remoteControlKeyId: this._remoteControlKeyIdMap.get(service.serviceId)
                });
            }
        }

        this.emit("services", _services);
    }

    private _onEIT(eit: MHEventInformationTable): void {
        // detect current event
        if (
            this._mptPid !== -1 &&
            eit.events.length !== 0 &&
            this._provideEventId !== null && eit.tableId === "EIT[p/f]" && eit.sectionNumber === 0 &&
            this._provideServiceId === eit.serviceId
        ) {
            if (eit.events[0].eventId === this._provideEventId) {
                this._provideEventLastDetectedAt = Date.now();

                if (this._ready === false) {
                    this._ready = true;
                    log.info("TLVFilter#_onEIT: now ready for eventId=%d", this._provideEventId);
                }
            } else {
                if (this._ready) {
                    log.info("TLVFilter#_onEIT: closing because eventId=%d has ended...", this._provideEventId);

                    const eventId = this._provideEventId;
                    this._provideEventId = null;
                    setTimeout(() => {
                        this._ready = false;
                        this._provideEventId = eventId;
                        this._close();
                    }, this._eventEndTimeout);
                }
            }
        }

        // write EPG stream and store result
        if (
            this._parseEIT &&
            this._parseServiceIds.has(eit.serviceId)
        ) {
            if (!this._epg && status.epgByChannel[this._channelItem.channel] !== true) {
                status.epgByChannel[this._channelItem.channel] = true;
                this._epg = new MHEPG();
            }

            if (this._epg) {
                this._epg.write(eit);

                if (!this._epgReady && eit.tableId !== "EIT[p/f]") {
                    this._updateEpgState(eit);
                }
            }
        }
    }

    private _onTOT(tot: MHTimeOffsetTable): void {
        this._streamTime = mjdBCDToUnixEpoch(tot.jstTime) * 1000;
    }

    private _onCDT(cdt: MHCommonDataTable): void {
        if (cdt.dataType !== MH_CDT_DATA_TYPE_LOGO_DATA) {
            return;
        }

        if (cdt.dataModule.logoType !== MH_CDT_LOGO_TYPE_LARGE) {
            return;
        }

        const trans = this._logoTransmissions.get(cdt.dataModule.logoId);
        if (trans === undefined || cdt.dataModule.logoVersion !== trans.logoVersion || trans.receivedSections === trans.numberOfSections) {
            return;
        }

        if (cdt.sectionNumber < trans.startSectionNumber || cdt.sectionNumber >= trans.startSectionNumber + trans.numberOfSections) {
            return;
        }

        if (trans.data[cdt.sectionNumber - trans.startSectionNumber] !== undefined) {
            return;
        }

        trans.data[cdt.sectionNumber - trans.startSectionNumber] = cdt.dataModule.data;
        trans.receivedSections += 1;
        if (trans.receivedSections !== trans.numberOfSections) {
            return;
        }
        const data = Buffer.concat(trans.data);
        trans.data = [];
        log.debug("TLVFilter#_onCDT: received logo data (networkId=%d, logoId=%d)", cdt.originalNetworkId, cdt.dataModule.logoId);
        Service.saveLogoData(cdt.originalNetworkId, cdt.dataModule.logoId, data);
    }


    private _observeProvideEvent(): void {
        if (Date.now() - this._provideEventLastDetectedAt < 10000) {
            this._provideEventTimeout = setTimeout(
                () => this._observeProvideEvent(),
                3000
            );
            return;
        }

        log.warn("TLVFilter#_observeProvideEvent: closing because EIT p/f timed out for eventId=%d...", this._provideEventId);
        this._close();
    }

    private _updateEpgState(eit: MHEventInformationTable): void {
        const networkId = eit.originalNetworkId;
        const serviceId = eit.serviceId;
        const versionNumber = eit.versionNumber;

        const stateByNet = this._epgState[networkId] || (this._epgState[networkId] = {});
        let stateBySrv = stateByNet[serviceId];

        if (!stateByNet[serviceId]) {
            stateBySrv = stateByNet[serviceId] = {
                basic: { flags: [], lastFlagsId: -1 },
                extended: { flags: [], lastFlagsId: -1 }
            };

            for (let i = 0; i < 0x08; i++) {
                for (const target of [stateBySrv.basic, stateBySrv.extended]) {
                    target.flags.push({
                        flag: Buffer.allocUnsafeSlow(32).fill(0x00),
                        ignore: Buffer.allocUnsafeSlow(32).fill(0xFF),
                        version_number: -1
                    });
                }
            }
        }

        const flagsId = eit.tableIndex & 0x07;
        const lastFlagsId = eit.lastTableIndex & 0x07;
        const segmentNumber = eit.sectionNumber >> 3;
        const lastSegmentNumber = eit.lastSectionNumber >> 3;
        const sectionNumber = eit.sectionNumber & 0x07;
        const segmentLastSectionNumber = eit.segmentLastSectionNumber & 0x07;
        const targetFlags = eit.tableId === "EIT[schedule basic]" ? stateBySrv.basic : stateBySrv.extended;
        const targetFlag = targetFlags.flags[flagsId];

        if ((targetFlags.lastFlagsId !== lastFlagsId) ||
            (targetFlag.version_number !== -1 && targetFlag.version_number !== versionNumber)) {
            if (targetFlag.version_number !== -1) {
                const verDiff = versionNumber - targetFlag.version_number;
                if (verDiff === -1 || verDiff > 1) {
                    return;
                }
            }
            for (let i = 0; i < 0x08; i++) {
                targetFlags.flags[i].flag.fill(0x00);
                targetFlags.flags[i].ignore.fill(i <= lastFlagsId ? 0x00 : 0xFF);
            }
        }

        // update ignore field (past segment)
        if (flagsId === 0 && this._streamTime !== null) {
            const segment = (this._streamTime + 9 * 60 * 60 * 1000) / (3 * 60 * 60 * 1000) & 0x07;
            for (let i = 0; i < segment; i++) {
                targetFlag.ignore[i] = 0xFF;
            }
        }

        for (let i = lastSegmentNumber + 1; i < 0x20; i++) {
            targetFlag.ignore[i] = 0xFF;
        }

        for (let i = segmentLastSectionNumber + 1; i < 8; i++) {
            targetFlag.ignore[segmentNumber] |= 1 << i;
        }

        targetFlag.flag[segmentNumber] |= 1 << sectionNumber;

        targetFlags.lastFlagsId = lastFlagsId;
        targetFlag.version_number = versionNumber;

        let ready = true;
        isReady: for (const nid in this._epgState) {
            for (const sid in this._epgState[nid]) {
                for (const table of this._epgState[nid][sid].basic.flags.concat(this._epgState[nid][sid].extended.flags)) {
                    for (let i = 0; i < table.flag.length; i++) {
                        if ((table.flag[i] | table.ignore[i]) !== 0xFF) {
                            ready = false;
                            break isReady;
                        }
                    }
                }
            }
        }

        if (ready === true) {
            this._epgReady = true;
            this._clearEpgState();

            for (const service of this._channelItem.getServices()) {
                service.epgReady = true;
            }

            process.nextTick(() => this.emit("epgReady"));
        }
    }

    private _clearEpgState() {
        if (!this._epgState) {
            return;
        }
        for (const nid in this._epgState) {
            delete this._epgState[nid];
        }
    }


    private _close(): void {
        if (this._closed) {
            return;
        }
        this._closed = true;

        clearTimeout(this._pmtTimer);
        clearTimeout(this._provideEventTimeout);

        this._reader.close();
        delete this._reader;

        if (this._epg) {
            this._epg.end();
            delete this._epg;
            status.epgByChannel[this._channelItem.channel] = false;

            if (this._epgReady === true) {
                const now = Date.now();
                for (const service of this._channelItem.getServices()) {
                    service.epgUpdatedAt = now;
                }
            }

            this._clearEpgState();
            delete this._epgState;
        }

        if (this._output) {
            if (this._output.writableEnded === false) {
                this._output.end();
            }
            this._output.removeAllListeners();
            delete this._output;
        }

        delete this.streamInfo;

        --status.streamCount.tlvFilter;

        log.info("TLVFilter#_close: closed (serviceId=%s, eventId=%s)", this._provideServiceId, this._provideEventId);

        this.emit("close");
        this.emit("end");
    }
}
