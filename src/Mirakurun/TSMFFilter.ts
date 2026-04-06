/*
   Copyright 2025 DMirakurun Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0
*/
import * as stream from "stream";
import * as log from "./log";
import _ from "./_";
import * as common from "./common";
import TSMFDemuxer from "./TSMFDemuxer";
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

export class StreamGate extends stream.Transform {
    private _opened = false;
    private _buffer: Buffer[] = [];
    private _bufferedBytes = 0;

    constructor(private _limitBytes: number) {
        super();
    }

    open(discardBuffer = false): void {
        if (this._opened) {
            return;
        }
        this._opened = true;
        if (discardBuffer) {
            this._buffer = [];
            this._bufferedBytes = 0;
        } else {
            for (const chunk of this._buffer) {
                this.push(chunk);
            }
            this._buffer = [];
            this._bufferedBytes = 0;
        }
    }

    close(): void {
        this._opened = false;
    }

    _transform(chunk: any, _encoding: BufferEncoding, callback: stream.TransformCallback): void {
        if (this._opened) {
            this.push(chunk);
            callback();
            return;
        }
        const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        if (this._bufferedBytes + data.length > this._limitBytes) {
            this._buffer = [];
            this._bufferedBytes = 0;
        }
        this._buffer.push(data);
        this._bufferedBytes += data.length;
        callback();
    }
}

export default class TSMFFilter {

    private _tunerIndex: number;
    private _demuxer: TSMFDemuxer;
    private _carrierLinks: CarrierLink[] = [];
    private _carrierInitInProgress = false;
    private _disposed = false;
    private _onFatal: () => void;

    // Gate management
    private _gates: StreamGate[] = [];
    private _gatesExpected: number | null = null;
    private _gatesOpened = false;

    constructor(tunerIndex: number, options: { tsmfRelTs?: number; groupId?: number }, onFatal: () => void) {
        this._tunerIndex = tunerIndex;
        this._onFatal = onFatal;
        this._demuxer = new TSMFDemuxer(tunerIndex, null, options);

        this._demuxer.once("error", (err) => {
            log.error("TunerDevice#%d TSMFFilter error: %s", this._tunerIndex, err.message);
            this._onFatal();
        });
    }

    get demuxer(): TSMFDemuxer {
        return this._demuxer;
    }

    get ready(): boolean {
        return this._demuxer.ready;
    }

    get closed(): boolean {
        return this._demuxer.closed;
    }

    createInput(): stream.Writable {
        return this._demuxer.createInput();
    }

    setOutput(output: stream.Writable): void {
        this._demuxer.setOutput(output);
    }

    close(): void {
        this._demuxer.close();
    }

    // --- Gate management ---

    initGates(expected: number): void {
        this._gates = [];
        this._gatesExpected = expected;
        this._gatesOpened = false;
    }

    addGate(gate: StreamGate): void {
        if (!this._gatesExpected) {
            gate.open();
            return;
        }
        this._gates.push(gate);
        this._tryOpenGates();
    }

    resetGates(): void {
        for (const gate of this._gates) {
            gate.open();
        }
        this._gates = [];
        this._gatesExpected = null;
        this._gatesOpened = false;
    }

    // --- Carrier management ---

    syncPriorities(newPriority: number): void {
        for (const link of this._carrierLinks) {
            if (link.user.priority !== newPriority) {
                (link.user as { priority: number }).priority = newPriority;
            }
        }
    }

    releaseCarriers(): void {
        for (const link of this._carrierLinks) {
            try { link.output.removeAllListeners(); } catch (e) { /* ignore */ }
            try { link.input.end(); } catch (e) { /* ignore */ }
            try { link.device.endStream(link.user, true); } catch (e) { /* ignore */ }
        }
        this._carrierLinks = [];
        this._carrierInitInProgress = false;
        this.resetGates();
    }

    setupCarriers(ch: ChannelItem, primaryGate: StreamGate): void {
        this._demuxer.once("needCarriers", (count: number) => {
            log.debug("TunerDevice#%d need %d carriers", this._tunerIndex, count);
            if (count > 1) {
                if (ch.tsmfGroupId === null || ch.tsmfGroupId === undefined) {
                    log.warn("TunerDevice#%d cannot attach extra carriers without tsmfGroupId", this._tunerIndex);
                    return;
                }
                const parsedCount = this._countGroupCarriers(ch);
                if (parsedCount < 2) {
                    log.warn("TunerDevice#%d not enough group channels for groupId=%d, need 2 or more but got %d",
                        this._tunerIndex, ch.tsmfGroupId, parsedCount);
                    return;
                }
                if (parsedCount !== count) {
                    log.warn("TunerDevice#%d carrier count mismatch, stream says %d but config has %d, using config",
                        this._tunerIndex, count, parsedCount);
                }
                primaryGate.close();
                this.initGates(parsedCount);
                this.addGate(primaryGate);
                log.info("TunerDevice#%d starting %d additional carriers for groupId=%d",
                    this._tunerIndex, parsedCount - 1, ch.tsmfGroupId);
                this._startCarriers(ch).catch(log.error);
            }
        });
    }

    // --- Event proxy ---

    once(event: string, listener: (...args: any[]) => void): this {
        this._demuxer.once(event, listener);
        return this;
    }

    on(event: string, listener: (...args: any[]) => void): this {
        this._demuxer.on(event, listener);
        return this;
    }

    // --- Private ---

    private _tryOpenGates(): void {
        if (this._gatesOpened || !this._gatesExpected || this._gates.length < this._gatesExpected) {
            return;
        }
        this._gatesOpened = true;
        this._demuxer.resetForSynchronizedStart();
        for (const gate of this._gates) {
            gate.open(true);
        }
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

    private async _startCarriers(ch: ChannelItem): Promise<void> {
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
                log.warn("TunerDevice#%d no additional channels found for groupId=%d",
                    this._tunerIndex, ch.tsmfGroupId);
                return;
            }

            let selected: TunerDevice[] = [];
            for (let attempt = 0; attempt < 6; attempt++) {
                if (this._disposed) {
                    return;
                }
                if (attempt > 0) {
                    await new Promise(r => setTimeout(r, 500));
                    if (this._disposed) {
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
                log.error("TunerDevice#%d failed to find %d BS4K tuners for multi-carrier, only %d available",
                    this._tunerIndex, required, selected.length);
                this.resetGates();
                this._onFatal();
                return;
            }

            log.info("TunerDevice#%d starting %d additional carriers on tuners %s",
                this._tunerIndex, selected.length,
                selected.map(d => `#${d.index}`).join(", ")
            );

            let started = 0;
            for (let i = 0; i < selected.length; i++) {
                if (this._disposed) {
                    this.releaseCarriers();
                    this.resetGates();
                    return;
                }

                const device = selected[i];
                const channel = groupChannels[i];
                const input = this._demuxer.createInput();
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
                    log.error("TunerDevice#%d carrier start failed on tuner #%d `%s`",
                        this._tunerIndex, device.index, (e as Error).message);
                    continue;
                }

                this.addGate(gate);
                started++;
                stream.pipeline(rawStream, gate, input, (err) => {
                    if (err && !this._disposed) {
                        log.error("TunerDevice#%d pipeline error: %s", this._tunerIndex, (err as Error).message);
                    }
                });

                rawStream.once("end", () => {
                    try { input.end(); } catch (e) { /* ignore */ }
                    if (!this._disposed) {
                        log.warn("TunerDevice#%d carrier stream ended on tuner #%d", this._tunerIndex, device.index);
                        this._onFatal();
                    }
                });

                this._carrierLinks.push({ device, user, stream: tsFilter, output: rawStream, input });
            }

            if (started < required) {
                log.error("TunerDevice#%d only %d of %d additional carriers started", this._tunerIndex, started, required);
                this.releaseCarriers();
                this.resetGates();
                return;
            }

            log.info("TunerDevice#%d additional carriers started", this._tunerIndex);
        } finally {
            this._carrierInitInProgress = false;
        }
    }
}
