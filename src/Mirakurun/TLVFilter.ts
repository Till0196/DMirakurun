/*
   Copyright 2025 DMirakurun Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0
*/
import * as child_process from "child_process";
import * as stream from "stream";
import * as common from "./common";
import * as log from "./log";
import _ from "./_";
import * as apid from "../../api";
import TSMFFilter, { StreamGate } from "./TSMFFilter";
import ChannelItem from "./ChannelItem";
import TSFilter from "./TSFilter";
import type TunerDevice from "./TunerDevice";

interface CarrierLink {
    device: TunerDevice;
    user: common.User & { _stream?: TSFilter };
    stream: TSFilter;
    output: stream.PassThrough;
    input: stream.Writable;
}

export interface TLVFilterResult {
    outputStream: stream.Readable;
    isCarrierOnly: boolean;
}

export default class TLVFilter {

    private _tunerIndex: number;
    private _config: apid.ConfigTunersItem;
    private _mmtsDecoderProcess: child_process.ChildProcess | null = null;
    private _tsmfFilter: TSMFFilter | null = null;
    private _carrierLinks: CarrierLink[] = [];
    private _carrierInitInProgress = false;
    private _disposed = false;
    private _isCarrierOnly = false;
    private _onFatal: () => void;

    constructor(tunerIndex: number, config: apid.ConfigTunersItem, onFatal: () => void) {
        this._tunerIndex = tunerIndex;
        this._config = config;
        this._onFatal = onFatal;
    }

    get isCarrierOnly(): boolean {
        return this._isCarrierOnly;
    }

    get hasDecoderProcess(): boolean {
        return this._mmtsDecoderProcess?.pid !== null && this._mmtsDecoderProcess?.pid !== undefined;
    }

    get tsmfFilter(): TSMFFilter | null {
        return this._tsmfFilter;
    }

    setupPipeline(
        inputStream: stream.Readable,
        ch: ChannelItem,
        options?: { suppressGroupCombine?: boolean }
    ): TLVFilterResult {
        const useGroupCombine = !options?.suppressGroupCombine;

        // Mode 1: Raw carrier passthrough
        if (!useGroupCombine) {
            log.info("TunerDevice#%d carrier mode (raw stream for multi-carrier)", this._tunerIndex);
            this._isCarrierOnly = true;
            return { outputStream: inputStream, isCarrierOnly: true };
        }

        // Mode 2: TSMFFilter + mmtsDecoder
        if (ch.tsmfRelTs !== null && ch.tsmfRelTs !== undefined) {
            return this._setupTsmfPipeline(inputStream, ch);
        }

        // Mode 3: Direct mmtsDecoder
        return this._setupDirectDecoder(inputStream);
    }

    syncPriorities(newPriority: number): void {
        for (const link of this._carrierLinks) {
            if (link.user.priority !== newPriority) {
                (link.user as { priority: number }).priority = newPriority;
            }
        }
    }

    cleanup(): void {
        this._releaseCarriers();
    }

    forceKillDecoder(): void {
        if (this._mmtsDecoderProcess) {
            this._mmtsDecoderProcess.stdin.removeAllListeners();
            this._mmtsDecoderProcess.stdout.removeAllListeners();
            this._mmtsDecoderProcess.stderr.removeAllListeners();
            this._mmtsDecoderProcess.removeAllListeners();
            if (this._mmtsDecoderProcess.pid) {
                this._mmtsDecoderProcess.kill("SIGKILL");
            }
        }
        this._mmtsDecoderProcess = null;
        if (this._tsmfFilter) {
            try {
                this._tsmfFilter.close();
            } catch (e) {
                // already closed
            }
        }
        this._tsmfFilter = null;
        this._releaseCarriers();
        this._disposed = true;
    }

    // --- Private ---

    private _setupTsmfPipeline(inputStream: stream.Readable, ch: ChannelItem): TLVFilterResult {
        const hasGroup = ch.tsmfGroupId !== null && ch.tsmfGroupId !== undefined;
        log.info(
            "TunerDevice#%d TSMFFilter %s (tsmfRelTs=%d%s)",
            this._tunerIndex,
            hasGroup ? "multi-carrier mode" : "single-carrier mode",
            ch.tsmfRelTs,
            hasGroup ? `, groupId=${ch.tsmfGroupId}` : ""
        );

        const outputStream = new stream.PassThrough();
        this._tsmfFilter = new TSMFFilter(this._tunerIndex, null, {
            tsmfRelTs: ch.tsmfRelTs,
            groupId: ch.tsmfGroupId ?? undefined
        });
        const primaryInput = this._tsmfFilter.createInput();
        const primaryGate = new StreamGate(8 * 1024 * 1024);
        primaryGate.open();

        this._tsmfFilter.once("needCarriers", (count: number) => {
            log.debug("TunerDevice#%d needCarriers: %d", this._tunerIndex, count);
            if (count > 1) {
                if (ch.tsmfGroupId === null || ch.tsmfGroupId === undefined) {
                    log.warn("TunerDevice#%d tsmfGroupId is not set; cannot attach extra carriers", this._tunerIndex);
                    return;
                }
                const parsedCount = this._countGroupCarriers(ch);
                if (parsedCount < 2) {
                    log.warn("TunerDevice#%d not enough parsed group channels for groupId=%d (need>=2, available=%d)",
                        this._tunerIndex, ch.tsmfGroupId, parsedCount);
                    return;
                }
                if (parsedCount !== count) {
                    log.warn("TunerDevice#%d needCarriers mismatch (converterNeedCarriers=%d, parsedGroupCarrierCount=%d), using parsed group count",
                        this._tunerIndex, count, parsedCount);
                }
                primaryGate.close();
                this._tsmfFilter.initGates(parsedCount);
                this._tsmfFilter.addGate(primaryGate);
                log.info("TunerDevice#%d starting additional carriers for groupId=%d", this._tunerIndex, ch.tsmfGroupId);
                this._startCarriers(ch, this._tsmfFilter).catch(log.error);
            }
        });

        this._tsmfFilter.once("ready", () => {
            log.info("TunerDevice#%d TSMFFilter ready, starting mmtsDecoder", this._tunerIndex);
            const proc = this._spawnDecoder();
            if (!proc) {
                return;
            }
            proc.stdout.pipe(outputStream);
            this._tsmfFilter.setOutput(proc.stdin);

            this._tsmfFilter.once("close", () => {
                log.debug("TunerDevice#%d TSMFFilter closed", this._tunerIndex);
                if (proc && !proc.killed) {
                    if (!proc.stdin.destroyed && !proc.stdin.writableEnded) {
                        proc.stdin.end();
                    }
                }
            });
        });

        this._tsmfFilter.once("error", (err) => {
            log.error("TunerDevice#%d TSMFFilter error: %s", this._tunerIndex, err.message);
            this._onFatal();
        });

        stream.pipeline(inputStream, primaryGate, primaryInput, (err) => {
            if (err && !this._disposed) {
                log.error("TunerDevice#%d pipeline error: %s", this._tunerIndex, (err as Error).message);
            }
        });

        inputStream.once("end", () => {
            log.debug("TunerDevice#%d input stream ended, closing TSMFFilter", this._tunerIndex);
            if (this._tsmfFilter) {
                this._tsmfFilter.close();
            }
        });

        return { outputStream, isCarrierOnly: false };
    }

    private _setupDirectDecoder(inputStream: stream.Readable): TLVFilterResult {
        log.info("TunerDevice#%d Direct mmtsDecoder mode", this._tunerIndex);
        const proc = this._spawnDecoder();
        if (!proc) {
            return { outputStream: inputStream, isCarrierOnly: false };
        }

        stream.pipeline(inputStream, proc.stdin, (err) => {
            if (err && !this._disposed) {
                log.error("TunerDevice#%d pipeline error: %s", this._tunerIndex, (err as Error).message);
            }
        });

        return { outputStream: proc.stdout, isCarrierOnly: false };
    }

    private _spawnDecoder(): child_process.ChildProcess | null {
        const parsed = common.parseCommandForSpawn(this._config.mmtsDecoder);
        this._mmtsDecoderProcess = child_process.spawn(parsed.command, parsed.args);
        const pid = this._mmtsDecoderProcess.pid;

        this._mmtsDecoderProcess.once("error", (err) => {
            log.error("TunerDevice#%d mmtsDecoder process error `%s` (pid=%d)", this._tunerIndex, err.name, pid);
            this._onFatal();
        });

        this._mmtsDecoderProcess.once("exit", () => {
            this._mmtsDecoderProcess?.stdin?.destroy();
            if (this._tsmfFilter) {
                try {
                    this._tsmfFilter.close();
                } catch (e) {
                    // already closed
                }
                this._tsmfFilter = null;
            }
            this._releaseCarriers();
            this._mmtsDecoderProcess = null;
        });

        this._mmtsDecoderProcess.once("close", (code, signal) => {
            log.debug(
                "TunerDevice#%d mmtsDecoder process has closed with code=%d by signal `%s` (pid=%d)",
                this._tunerIndex, code, signal, pid
            );
            if (!this._disposed) {
                this._onFatal();
            }
        });

        return this._mmtsDecoderProcess;
    }

    private _countGroupCarriers(ch: ChannelItem): number {
        if (!_.channel || ch.tsmfGroupId === null || ch.tsmfGroupId === undefined) {
            return 0;
        }
        return _.channel.items.filter(item =>
            item.type === "BS4K" &&
            item.tsmfGroupId === ch.tsmfGroupId
        ).length;
    }

    private async _startCarriers(ch: ChannelItem, combiner: TSMFFilter): Promise<void> {
        if (this._carrierInitInProgress || this._carrierLinks.length > 0) {
            return;
        }
        if (!_.tuner || !_.channel || ch.tsmfGroupId === null || ch.tsmfGroupId === undefined) {
            return;
        }

        this._carrierInitInProgress = true;
        try {
            const groupChannels = _.channel.items.filter(item =>
                item.type === "BS4K" &&
                item.tsmfGroupId === ch.tsmfGroupId &&
                item.channel !== ch.channel
            );
            const required = groupChannels.length;
            if (required < 1) {
                log.warn("TunerDevice#%d not enough channels for groupId=%d",
                    this._tunerIndex, ch.tsmfGroupId);
                return;
            }

            let selected: TunerDevice[] = [];
            for (let attempt = 0; attempt < 6; attempt++) {
                if (this._disposed || this._tsmfFilter !== combiner) {
                    return;
                }
                if (attempt > 0) {
                    await new Promise(r => setTimeout(r, 500));
                    if (this._disposed || this._tsmfFilter !== combiner) {
                        return;
                    }
                }

                selected = _.tuner.devices
                    .map(d => _.tuner.get(d.index))
                    .filter(d =>
                        d && d.index !== this._tunerIndex && !d.isRemote && d.config.types.includes("BS4K") &&
                        (d.isFree || (d.isUsing && !d.isCarrierOnly && d.getPriority() <= 0))
                    )
                    .sort((a, b) => {
                        if (a.isFree !== b.isFree) {
                            return a.isFree ? -1 : 1;
                        }
                        return a.getPriority() - b.getPriority();
                    })
                    .slice(0, required) as TunerDevice[];

                if (selected.length >= required) {
                    break;
                }
            }

            if (selected.length < required) {
                log.error("TunerDevice#%d not enough BS4K tuners for multi-carrier (need=%d, available=%d)",
                    this._tunerIndex, required, selected.length);
                combiner.resetGates();
                this._onFatal();
                return;
            }

            log.info("TunerDevice#%d starting additional carriers: tuners=[%s] channels=[%s]",
                this._tunerIndex,
                selected.map(d => d.index).join(","),
                groupChannels.slice(0, required).map(c => c.channel).join(",")
            );

            let started = 0;
            for (let i = 0; i < selected.length; i++) {
                if (this._disposed || this._tsmfFilter !== combiner) {
                    this._releaseCarriers();
                    combiner.resetGates();
                    return;
                }

                const device = selected[i];
                const channel = groupChannels[i];
                const input = combiner.createInput();
                const rawStream = new stream.PassThrough();
                const gate = new StreamGate(8 * 1024 * 1024);
                const tsFilter = rawStream as unknown as TSFilter;
                const user: common.User & { _stream?: TSFilter } = {
                    id: `Mirakurun:addCarrier()`,
                    priority: 0,
                    disableDecoder: true,
                    streamSetting: { channel }
                };

                try {
                    await device.startStream(user, tsFilter, channel, { suppressGroupCombine: true });
                } catch (e) {
                    log.error("TunerDevice#%d failed to start carrier on tuner #%d: %s",
                        this._tunerIndex, device.index, (e as Error).message);
                    continue;
                }

                combiner.addGate(gate);
                started++;
                stream.pipeline(rawStream, gate, input, (err) => {
                    if (err && !this._disposed) {
                        log.error("TunerDevice#%d pipeline error: %s", this._tunerIndex, (err as Error).message);
                    }
                });

                rawStream.once("end", () => {
                    try { input.end(); } catch (e) { /* ignore */ }
                    if (!this._disposed) {
                        log.warn("TunerDevice#%d carrier stream ended (device=%d)", this._tunerIndex, device.index);
                        this._onFatal();
                    }
                });

                this._carrierLinks.push({ device, user, stream: tsFilter, output: rawStream, input });
            }

            if (started < required) {
                log.error("TunerDevice#%d only %d/%d additional carriers started", this._tunerIndex, started, required);
                this._releaseCarriers();
                combiner.resetGates();
                return;
            }

            log.info("TunerDevice#%d additional carriers started", this._tunerIndex);
        } finally {
            this._carrierInitInProgress = false;
        }
    }

    private _releaseCarriers(): void {
        for (const link of this._carrierLinks) {
            try { link.output.removeAllListeners(); } catch (e) { /* ignore */ }
            try { link.input.end(); } catch (e) { /* ignore */ }
            try { link.device.endStream(link.user, true); } catch (e) { /* ignore */ }
        }
        this._carrierLinks = [];
        this._carrierInitInProgress = false;
        if (this._tsmfFilter) {
            this._tsmfFilter.resetGates();
        }
    }
}
