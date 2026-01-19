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
import * as child_process from "child_process";
import * as stream from "stream";
import * as util from "util";
import EventEmitter = require("eventemitter3");
import * as common from "./common";
import * as log from "./log";
import _ from "./_";
import * as apid from "../../api";
import status from "./status";
import Event from "./Event";
import ChannelItem from "./ChannelItem";
import TSFilter from "./TSFilter";
import TLVConverter from "./TLVConverter";
import Client, { ProgramsQuery } from "../client";

interface User extends common.User {
    _stream?: TSFilter;
}

interface StartStreamOptions {
    suppressGroupCombine?: boolean;
}

interface CarrierLink {
    device: TunerDevice;
    user: User;
    stream: TSFilter;
    output: stream.PassThrough;
    input: stream.Writable;
}

export interface TunerDeviceStatus {
    readonly index: number;
    readonly name: string;
    readonly types: apid.ChannelType[];
    readonly command: string;
    readonly pid: number;
    readonly users: common.User[];
    readonly isAvailable: boolean;
    readonly isRemote: boolean;
    readonly isFree: boolean;
    readonly isUsing: boolean;
    readonly isFault: boolean;
}

export default class TunerDevice extends EventEmitter {
    private _channel: ChannelItem = null;
    private _command: string = null;
    private _process: child_process.ChildProcess = null;
    private _mmtsDecoderProcess: child_process.ChildProcess = null;
    private _stream: stream.Readable = null;
    private _tlvConverter: any = null;
    private _carrierLinks: CarrierLink[] = [];
    private _carrierInitInProgress = false;

    private _users = new Set<User>();

    private _isAvailable = true;
    private _isRemote = false;
    private _isFault = false;
    private _fatalCount = 0;
    private _exited = false;
    private _closing = false;

    constructor(private _index: number, private _config: apid.ConfigTunersItem) {
        super();
        this._isRemote = !!this._config.remoteMirakurunHost;
        Event.emit("tuner", "create", this.toJSON());
        log.debug("TunerDevice#%d initialized", this._index);
    }

    get index(): number {
        return this._index;
    }

    get config(): apid.ConfigTunersItem {
        return this._config;
    }

    get channel(): ChannelItem {
        return this._channel;
    }

    get command(): string {
        return this._command;
    }

    get pid(): number {
        return this._process ? this._process.pid : null;
    }

    get users(): User[] {
        return [...this._users].map(user => {
            return {
                id: user.id,
                priority: user.priority,
                agent: user.agent,
                url: user.url,
                disableDecoder: user.disableDecoder,
                streamSetting: user.streamSetting,
                streamInfo: user.streamInfo
            };
        });
    }

    get decoder(): string {
        return this._config.decoder || null;
    }

    get mmtsDecoder(): string {
        return this._config.mmtsDecoder || null;
    }

    get isAvailable(): boolean {
        return this._isAvailable;
    }

    get isRemote(): boolean {
        return this._isRemote;
    }

    get isFree(): boolean {
        return this._isAvailable === true && this._channel === null && this._users.size === 0;
    }

    get isUsing(): boolean {
        return this._isAvailable === true && this._channel !== null && this._users.size !== 0;
    }

    get isFault(): boolean {
        return this._isFault;
    }

    getPriority(): number {
        let priority = -2;

        for (const user of this._users) {
            if (user.priority > priority) {
                priority = user.priority;
            }
        }

        return priority;
    }

    toJSON(): TunerDeviceStatus {
        return {
            index: this._index,
            name: this._config.name,
            types: this._config.types,
            command: this._command,
            pid: this.pid,
            users: this.users,
            isAvailable: this.isAvailable,
            isRemote: this.isRemote,
            isFree: this.isFree,
            isUsing: this.isUsing,
            isFault: this.isFault
        };
    }

    async kill(): Promise<void> {
        await this._kill(true);
    }

    async startStream(user: User, stream: TSFilter, channel?: ChannelItem, options?: StartStreamOptions): Promise<void> {
        log.debug("TunerDevice#%d start stream for user `%s` (priority=%d)...", this._index, user.id, user.priority);

        if (this._isAvailable === false) {
            throw new Error(util.format("TunerDevice#%d is not available", this._index));
        }

        if (!channel && !this._stream) {
            throw new Error(util.format("TunerDevice#%d has not stream", this._index));
        }

        if (channel) {
            if (this._config.types.includes(channel.type) === false) {
                throw new Error(util.format("TunerDevice#%d is not supported for channel type `%s`", this._index, channel.type));
            }

            if (this._stream) {
                const sameGroup = this._channel && this._channel.isSameTsmfGroup(channel);
                if (channel.channel !== this._channel.channel && !sameGroup) {
                    if (user.priority <= this.getPriority()) {
                        throw new Error(util.format("TunerDevice#%d has higher priority user", this._index));
                    }

                    await this._kill(true);
                    this._spawn(channel, options);
                }
            } else {
                this._spawn(channel, options);
            }
        }

        log.info("TunerDevice#%d streaming to user `%s` (priority=%d)", this._index, user.id, user.priority);

        user._stream = stream;
        this._users.add(user);
        if (stream.closed === true) {
            this.endStream(user);
        } else {
            stream.once("close", () => this.endStream(user));
        }

        this._updated();
    }

    endStream(user: User): void {
        log.debug("TunerDevice#%d end stream for user `%s` (priority=%d)...", this._index, user.id, user.priority);

        user._stream.end();
        this._users.delete(user);

        if (this._users.size === 0) {
            setTimeout(() => {
                if (this._users.size === 0 && this._process) {
                    this._kill(true).catch(log.error);
                }
            }, 3000);
        }

        log.info("TunerDevice#%d end streaming to user `%s` (priority=%d)", this._index, user.id, user.priority);

        this._updated();
    }

    async getRemotePrograms(query?: ProgramsQuery): Promise<apid.Program[]> {
        if (!this._isRemote) {
            throw new Error(util.format("TunerDevice#%d is not remote device", this._index));
        }

        const client = new Client();
        client.host = this.config.remoteMirakurunHost;
        client.port = this.config.remoteMirakurunPort || 40772;
        client.userAgent = "Mirakurun (Remote)";

        log.debug("TunerDevice#%d fetching remote programs from %s:%d...", this._index, client.host, client.port);

        const programs = await client.getPrograms(query);

        log.info("TunerDevice#%d fetched %d remote programs", this._index, programs.length);

        return programs;
    }

    private _spawn(ch: ChannelItem, options?: StartStreamOptions): void {
        log.debug("TunerDevice#%d spawn...", this._index);

        if (this._process) {
            throw new Error(util.format("TunerDevice#%d has process", this._index));
        }

        let cmd: string;

        if (this._isRemote === true) {
            cmd = "node lib/remote";
            cmd += " " + this._config.remoteMirakurunHost;
            cmd += " " + (this._config.remoteMirakurunPort || 40772);
            cmd += " " + ch.type;
            cmd += " " + ch.channel;
            if (this._config.remoteMirakurunDecoder === true) {
                cmd += " decode";
            }
        } else {
            cmd = this._config.command;
        }

        cmd = common.replaceCommandTemplate(cmd, {
            channel: ch.channel,
            satelite: ch.commandVars?.satellite || "", // deprecated, for backward compatibility
            space: 0, // default value for backward compatibility
            ...ch.commandVars
        });

        const parsed = common.parseCommandForSpawn(cmd);
        this._process = child_process.spawn(parsed.command, parsed.args);
        this._command = cmd;
        this._channel = ch;
            if (this._config.dvbDevicePath) {
                const cat = child_process.spawn("cat", [this._config.dvbDevicePath]);

                cat.once("error", (err) => {
                    log.error("TunerDevice#%d cat process error `%s` (pid=%d)", this._index, err.name, cat.pid);

                    this._kill(false);
                });

                cat.once("close", (code, signal) => {
                    const proc = this._process;
                    log.debug(
                        "TunerDevice#%d cat process has closed with code=%d by signal `%s` (pid=%d, procPid=%s, procExit=%s, procSignal=%s, procKilled=%s, closing=%s, users=%d)",
                        this._index,
                        code,
                        signal,
                        cat.pid,
                        proc?.pid ?? "null",
                        proc?.exitCode ?? "null",
                        proc?.signalCode ?? "null",
                        proc?.killed ?? false,
                        this._closing,
                        this._users.size
                    );

                    if (this._exited === false) {
                        this._kill(false);
                    }
                });

            this._process.once("exit", () => cat.kill("SIGKILL"));

            if (ch.type === "BS4K") {
                const useGroupCombine = !options?.suppressGroupCombine;
                if (!useGroupCombine) {
                    log.info("TunerDevice#%d carrier mode (raw stream for multi-carrier)", this._index);
                    this._stream = cat.stdout;
                } else if (ch.tsmfRelTs !== null && ch.tsmfRelTs !== undefined) {
                    log.info(
                        "TunerDevice#%d TLV combiner mode (tsmfRelTs=%d, groupId=%s)",
                        this._index,
                        ch.tsmfRelTs,
                        ch.tsmfGroupId !== null && ch.tsmfGroupId !== undefined ? String(ch.tsmfGroupId) : "none"
                    );

                    const outputStream = new stream.PassThrough();
                    this._tlvConverter = new TLVConverter(this._index, null, {
                        tsmfRelTs: ch.tsmfRelTs,
                        groupId: ch.tsmfGroupId ?? undefined
                    });
                    const primaryInput = this._tlvConverter.createInput();

                    this._tlvConverter.once("needCarriers", (count: number) => {
                        if (useGroupCombine && count === 3) {
                            if (ch.tsmfGroupId === null || ch.tsmfGroupId === undefined) {
                                log.warn("TunerDevice#%d tsmfGroupId is not set; cannot attach extra carriers", this._index);
                                return;
                            }
                            log.info("TunerDevice#%d starting additional carriers for groupId=%d", this._index, ch.tsmfGroupId);
                            this._startAdditionalCarriers(ch, this._tlvConverter as TLVConverter).catch(log.error);
                        }
                    });

                    this._tlvConverter.once("ready", () => {
                        log.info("TunerDevice#%d TLVConverter ready, starting mmtsDecoder", this._index);

                        const parsed = common.parseCommandForSpawn(this._config.mmtsDecoder);
                        this._mmtsDecoderProcess = child_process.spawn(parsed.command, parsed.args);

                        this._mmtsDecoderProcess.once("error", (err) => {
                            log.error("TunerDevice#%d mmtsDecoder process error `%s` (pid=%d)", this._index, err.name, this._mmtsDecoderProcess.pid);
                            this._kill(false);
                        });

                        const mmtsPid = this._mmtsDecoderProcess.pid;

                        this._mmtsDecoderProcess.once("exit", () => {
                            this._mmtsDecoderProcess?.stdin?.destroy();
                            if (this._tlvConverter) {
                                try {
                                    this._tlvConverter.close();
                                } catch (e) {
                                    // already closed
                                }
                                this._tlvConverter = null;
                            }
                            this._cleanupCarrierLinks();
                            this._mmtsDecoderProcess = null;
                        });

                        this._mmtsDecoderProcess.once("close", (code, signal) => {
                            log.debug(
                                "TunerDevice#%d mmtsDecoder process has closed with code=%d by signal `%s` (pid=%d)",
                                this._index, code, signal, mmtsPid
                            );

                            if (this._exited === false && !this._closing) {
                                this._kill(false);
                            }
                        });

                        this._mmtsDecoderProcess.stdout.pipe(outputStream);
                        this._tlvConverter.setOutput(this._mmtsDecoderProcess.stdin);

                        this._tlvConverter.once("close", () => {
                            log.debug("TunerDevice#%d TLVConverter closed", this._index);
                            if (this._mmtsDecoderProcess && !this._mmtsDecoderProcess.killed) {
                                if (!this._mmtsDecoderProcess.stdin.destroyed && !this._mmtsDecoderProcess.stdin.writableEnded) {
                                    this._mmtsDecoderProcess.stdin.end();
                                }
                            }
                        });
                    });

                    this._tlvConverter.once("error", (err) => {
                        log.error("TunerDevice#%d TLVConverter error: %s", this._index, err.message);
                        this._kill(false);
                    });

                    cat.stdout.on("data", (chunk) => {
                        if (!this._tlvConverter) {
                            return;
                        }
                        primaryInput.write(chunk);
                    });

                    cat.stdout.once("end", () => {
                        const tlvState = this._tlvConverter?.getDebugState ? this._tlvConverter.getDebugState() : null;
                        log.debug(
                            "TunerDevice#%d cat stdout ended, closing TLVConverter (tlv=%s)",
                            this._index,
                            tlvState ? JSON.stringify(tlvState) : "null"
                        );
                        if (this._tlvConverter) {
                            this._tlvConverter.close();
                        }
                    });

                    this._stream = outputStream;
                } else {
                    // 直接mmtsDecoderモード
                    log.info("TunerDevice#%d Direct mmtsDecoder mode", this._index);

                    const parsed = common.parseCommandForSpawn(this._config.mmtsDecoder);
                    this._mmtsDecoderProcess = child_process.spawn(parsed.command, parsed.args);

                    const mmtsPid = this._mmtsDecoderProcess.pid;

                    this._mmtsDecoderProcess.once("error", (err) => {
                        log.error("TunerDevice#%d mmtsDecoder process error `%s` (pid=%d)", this._index, err.name, mmtsPid);
                        this._kill(false);
                    });

                    this._mmtsDecoderProcess.once("exit", () => {
                        this._mmtsDecoderProcess?.stdin?.destroy();
                        this._mmtsDecoderProcess = null;
                    });

                    this._mmtsDecoderProcess.once("close", (code, signal) => {
                        log.debug(
                            "TunerDevice#%d mmtsDecoder process has closed with code=%d by signal `%s` (pid=%d)",
                            this._index, code, signal, mmtsPid
                        );

                        if (this._exited === false && !this._closing) {
                            this._kill(false);
                        }
                    });

                    stream.pipeline(cat.stdout, this._mmtsDecoderProcess.stdin, (err) => {
                        if (err && !this._closing) {
                            log.error("TunerDevice#%d pipeline error: %s", this._index, (err as Error).message);
                        }
                    });

                    this._stream = this._mmtsDecoderProcess.stdout;
                }
            } else {
                this._stream = cat.stdout;
            }
        } else {
            if (ch.type === "BS4K") {
                const useGroupCombine = !options?.suppressGroupCombine;
                if (!useGroupCombine) {
                    log.info("TunerDevice#%d carrier mode (raw stream for multi-carrier)", this._index);
                    this._stream = this._process.stdout;
                } else if (ch.tsmfRelTs !== null && ch.tsmfRelTs !== undefined) {
                    log.info(
                        "TunerDevice#%d TLV combiner mode (tsmfRelTs=%d, groupId=%s)",
                        this._index,
                        ch.tsmfRelTs,
                        ch.tsmfGroupId !== null && ch.tsmfGroupId !== undefined ? String(ch.tsmfGroupId) : "none"
                    );

                    const outputStream = new stream.PassThrough();
                    this._tlvConverter = new TLVConverter(this._index, null, {
                        tsmfRelTs: ch.tsmfRelTs,
                        groupId: ch.tsmfGroupId ?? undefined
                    });
                    const primaryInput = this._tlvConverter.createInput();

                    this._tlvConverter.once("needCarriers", (count: number) => {
                        if (useGroupCombine && count === 3) {
                            if (ch.tsmfGroupId === null || ch.tsmfGroupId === undefined) {
                                log.warn("TunerDevice#%d tsmfGroupId is not set; cannot attach extra carriers", this._index);
                                return;
                            }
                            log.info("TunerDevice#%d starting additional carriers for groupId=%d", this._index, ch.tsmfGroupId);
                            this._startAdditionalCarriers(ch, this._tlvConverter as TLVConverter).catch(log.error);
                        }
                    });

                    this._tlvConverter.once("ready", () => {
                        log.info("TunerDevice#%d TLVConverter ready, starting mmtsDecoder", this._index);

                        const parsed = common.parseCommandForSpawn(this._config.mmtsDecoder);
                        this._mmtsDecoderProcess = child_process.spawn(parsed.command, parsed.args);

                        this._mmtsDecoderProcess.once("error", (err) => {
                            log.error("TunerDevice#%d mmtsDecoder process error `%s` (pid=%d)", this._index, err.name, this._mmtsDecoderProcess.pid);
                            this._kill(false);
                        });

                        const mmtsPid = this._mmtsDecoderProcess.pid;

                        this._mmtsDecoderProcess.once("exit", () => {
                            this._mmtsDecoderProcess?.stdin?.destroy();
                            if (this._tlvConverter) {
                                try {
                                    this._tlvConverter.close();
                                } catch (e) {
                                    // already closed
                                }
                                this._tlvConverter = null;
                            }
                            this._cleanupCarrierLinks();
                            this._mmtsDecoderProcess = null;
                        });

                        this._mmtsDecoderProcess.once("close", (code, signal) => {
                            log.debug(
                                "TunerDevice#%d mmtsDecoder process has closed with code=%d by signal `%s` (pid=%d)",
                                this._index, code, signal, mmtsPid
                            );

                            if (this._exited === false && !this._closing) {
                                this._kill(false);
                            }
                        });

                        this._mmtsDecoderProcess.stdout.pipe(outputStream);
                        this._tlvConverter.setOutput(this._mmtsDecoderProcess.stdin);

                        this._tlvConverter.once("close", () => {
                            log.debug("TunerDevice#%d TLVConverter closed", this._index);
                            if (this._mmtsDecoderProcess && !this._mmtsDecoderProcess.killed) {
                                if (!this._mmtsDecoderProcess.stdin.destroyed && !this._mmtsDecoderProcess.stdin.writableEnded) {
                                    this._mmtsDecoderProcess.stdin.end();
                                }
                            }
                        });
                    });

                    this._tlvConverter.once("error", (err) => {
                        log.error("TunerDevice#%d TLVConverter error: %s", this._index, err.message);
                        this._kill(false);
                    });

                    this._process.stdout.on("data", (chunk) => {
                        if (!this._tlvConverter) {
                            return;
                        }
                        primaryInput.write(chunk);
                    });

                    this._process.stdout.once("end", () => {
                        const tlvState = this._tlvConverter?.getDebugState ? this._tlvConverter.getDebugState() : null;
                        log.debug(
                            "TunerDevice#%d process stdout ended, closing TLVConverter (tlv=%s)",
                            this._index,
                            tlvState ? JSON.stringify(tlvState) : "null"
                        );
                        if (this._tlvConverter) {
                            this._tlvConverter.close();
                        }
                    });

                    this._stream = outputStream;
                } else {
                    // 直接mmtsDecoderモード
                    log.info("TunerDevice#%d Direct mmtsDecoder mode", this._index);

                    const parsed = common.parseCommandForSpawn(this._config.mmtsDecoder);
                    this._mmtsDecoderProcess = child_process.spawn(parsed.command, parsed.args);

                    const mmtsPid = this._mmtsDecoderProcess.pid;

                    this._mmtsDecoderProcess.once("error", (err) => {
                        log.error("TunerDevice#%d mmtsDecoder process error `%s` (pid=%d)", this._index, err.name, mmtsPid);
                        this._kill(false);
                    });

                    this._mmtsDecoderProcess.once("exit", () => {
                        this._mmtsDecoderProcess?.stdin?.destroy();
                        this._mmtsDecoderProcess = null;
                    });

                    this._mmtsDecoderProcess.once("close", (code, signal) => {
                        log.debug(
                            "TunerDevice#%d mmtsDecoder process has closed with code=%d by signal `%s` (pid=%d)",
                            this._index, code, signal, mmtsPid
                        );

                        if (this._exited === false && !this._closing) {
                            this._kill(false);
                        }
                    });

                    stream.pipeline(this._process.stdout, this._mmtsDecoderProcess.stdin, (err) => {
                        if (err && !this._closing) {
                            log.error("TunerDevice#%d pipeline error: %s", this._index, (err as Error).message);
                        }
                    });

                    this._stream = this._mmtsDecoderProcess.stdout;
                }
            } else {
                this._stream = this._process.stdout;
            }
        }

        this._process.once("exit", () => {
            this._exited = true;
        });

        this._process.once("error", (err) => {
            log.fatal("TunerDevice#%d process error `%s` (pid=%d)", this._index, err.name, this._process.pid);

            ++this._fatalCount;
            if (this._fatalCount >= 3) {
                log.fatal("TunerDevice#%d has something fault! **RESTART REQUIRED** after fix it.", this._index);

                this._isFault = true;
                this._closing = true;
            }
            this._end();
            setTimeout(this._release.bind(this), this._config.dvbDevicePath ? 1000 : 100);
        });

        this._process.once("close", (code, signal) => {
            log.info(
                "TunerDevice#%d process has closed with exit code=%d by signal `%s` (pid=%d)",
                this._index, code, signal, this._process.pid
            );

            this._end();
            setTimeout(this._release.bind(this), this._config.dvbDevicePath ? 1000 : 100);
        });

        this._process.stderr.on("data", data => {
            log.debug("TunerDevice#%d > %s", this._index, data.toString().trim());
        });

        // flowing start
        this._stream.on("data", this._streamOnData.bind(this));

        this._updated();
        log.info("TunerDevice#%d process has spawned by command `%s` (pid=%d)", this._index, cmd, this._process.pid);
    }

    private _streamOnData(chunk: Buffer): void {
        for (const user of this._users) {
            user._stream.write(chunk);
        }
    }

    private async _startAdditionalCarriers(ch: ChannelItem, combiner: TLVConverter): Promise<void> {
        if (this._carrierInitInProgress || this._carrierLinks.length > 0) {
            return;
        }

        if (!_.tuner) {
            log.warn("TunerDevice#%d cannot start extra carriers (tuner registry missing)", this._index);
            return;
        }

        if (ch.tsmfGroupId === null || ch.tsmfGroupId === undefined) {
            return;
        }

        this._carrierInitInProgress = true;
        try {
            if (!_.channel) {
                log.warn("TunerDevice#%d cannot start extra carriers (channel registry missing)", this._index);
                return;
            }

            const groupChannels = _.channel.items.filter(item =>
                item.type === "BS4K" &&
                item.tsmfGroupId === ch.tsmfGroupId &&
                item.channel !== ch.channel
            );

            if (groupChannels.length < 2) {
                log.warn(
                    "TunerDevice#%d not enough channels for groupId=%d (need=2, available=%d)",
                    this._index,
                    ch.tsmfGroupId,
                    groupChannels.length
                );
                return;
            }

            const candidates = _.tuner.devices
                .map(device => _.tuner.get(device.index))
                .filter(device =>
                    device &&
                    device !== this &&
                    device.isFree &&
                    !device.isRemote &&
                    device.config.types.includes("BS4K")
                ) as TunerDevice[];

            if (candidates.length < 2) {
                log.warn("TunerDevice#%d not enough free BS4K tuners for multi-carrier (need=2, available=%d)", this._index, candidates.length);
                return;
            }

            const selected = candidates.slice(0, 2);
            const selectedChannels = groupChannels.slice(0, 2);

            log.info("TunerDevice#%d starting additional carriers: tuners=[%s] channels=[%s]",
                this._index,
                selected.map(d => d.index).join(","),
                selectedChannels.map(c => c.channel).join(",")
            );

            for (let i = 0; i < selected.length; i++) {
                const device = selected[i];
                const channel = selectedChannels[i];
                const input = combiner.createInput();
                // Use raw stream instead of TSFilter to pass TSMF/TLV packets (PID=0x2f,0x2d) unfiltered
                const rawStream = new stream.PassThrough();
                const tsFilter = rawStream as unknown as TSFilter;
                const user: User = {
                    id: `tlv-carrier-${this._index}-${device.index}`,
                    priority: 100,
                    disableDecoder: true
                };

                await device.startStream(user, tsFilter, channel, { suppressGroupCombine: true });

                rawStream.on("data", (chunk) => {
                    input.write(chunk);
                });

                rawStream.once("end", () => {
                    try {
                        input.end();
                    } catch (e) {
                        // ignore
                    }
                    if (!this._closing) {
                        log.warn("TunerDevice#%d carrier stream ended (device=%d)", this._index, device.index);
                        this._kill(false);
                    }
                });

                this._carrierLinks.push({ device, user, stream: tsFilter, output: rawStream, input });
            }

            log.info("TunerDevice#%d additional carriers started", this._index);
        } finally {
            this._carrierInitInProgress = false;
        }
    }

    private _cleanupCarrierLinks(): void {
        if (this._carrierLinks.length === 0) {
            return;
        }

        for (const link of this._carrierLinks) {
            try {
                link.output.removeAllListeners();
            } catch (e) {
                // ignore
            }
            try {
                link.input.end();
            } catch (e) {
                // ignore
            }
            try {
                link.device.endStream(link.user);
            } catch (e) {
                // ignore
            }
        }

        this._carrierLinks = [];
        this._carrierInitInProgress = false;
    }

    private _end(): void {
        this._isAvailable = false;

        this._stream.removeAllListeners("data");

        if (this._closing === true) {
            for (const user of this._users) {
                user._stream.end();
            }
            this._users.clear();
        }

        this._updated();
    }

    private async _kill(close: boolean): Promise<void> {
        log.debug("TunerDevice#%d kill...", this._index);

        if (!this._process || !this._process.pid) {
            throw new Error(util.format("TunerDevice#%d has not process", this._index));
        } else if (this._closing) {
            log.debug("TunerDevice#%d return because it is closing", this._index);
            return;
        }

        this._isAvailable = false;
        this._closing = close;

        this._updated();

        await new Promise<void>(resolve => {
            this.once("release", resolve);

            if (this._mmtsDecoderProcess?.pid) {
                this._process?.kill("SIGKILL");
                return;
            }

            if (/^dvbv5-zap /.test(this._command) === true) {
                this._process.kill("SIGKILL");
            } else {
                const timer = setTimeout(() => {
                    log.warn("TunerDevice#%d will force killed because SIGTERM timed out...", this._index);
                    this._process.kill("SIGKILL");
                }, 6000);
                this._process.once("exit", () => clearTimeout(timer));

                // regular way
                this._process.kill("SIGTERM");
            }
        });
    }

    private _release(): void {
        if (this._process) {
            this._process.stderr.removeAllListeners();
            this._process.removeAllListeners();
        }
        if (this._stream) {
            this._stream.removeAllListeners();
        }

        if (this._mmtsDecoderProcess) {
            this._mmtsDecoderProcess.stdin.removeAllListeners();
            this._mmtsDecoderProcess.stdout.removeAllListeners();
            this._mmtsDecoderProcess.stderr.removeAllListeners();
            this._mmtsDecoderProcess.removeAllListeners();
            if (this._mmtsDecoderProcess.pid) {
                this._mmtsDecoderProcess.kill("SIGKILL");
            }
        }

        this._command = null;
        this._process = null;
        this._stream = null;
        this._mmtsDecoderProcess = null;
        if (this._tlvConverter) {
            try {
                this._tlvConverter.close();
            } catch (e) {
                // already closed
            }
        }
        this._tlvConverter = null;
        this._cleanupCarrierLinks();

        if (this._closing === false && this._users.size !== 0) {
            log.warn("TunerDevice#%d respawning because request has not closed", this._index);
            ++status.errorCount.tunerDeviceRespawn;

            this._spawn(this._channel);
            return;
        }

        this._fatalCount = 0;
        this._channel = null;
        this._users.clear();

        if (this._isFault === false) {
            this._isAvailable = true;
        }

        this._closing = false;
        this._exited = false;

        this.emit("release");

        log.info("TunerDevice#%d released", this._index);

        this._updated();
    }

    private _updated(): void {
        Event.emit("tuner", "update", this.toJSON());
    }
}
