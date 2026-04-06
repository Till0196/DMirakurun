import * as stream from "stream";
import * as log from "./log";
import _ from "./_";
import * as common from "./common";
import TSMFDemuxer from "./TSMFDemuxer";
import ChannelItem from "./ChannelItem";
import TSFilter from "./TSFilter";
import type TunerDevice from "./TunerDevice";

const CARRIER_MAX_ATTEMPTS = 6;
const CARRIER_RETRY_DELAY_MS = 500;

interface CarrierLink {
    device: TunerDevice;
    user: common.User & { _stream?: TSFilter };
    tsFilter: TSFilter;
    sourceStream: stream.PassThrough;
    demuxerInput: stream.Writable;
}

export default class TSMFFilter {

    private _tunerIndex: number;
    private _demuxer: TSMFDemuxer;
    private _carrierLinks: CarrierLink[] = [];
    private _carrierInitPending = false;
    private _closed = false;
    private _onFatal: () => void;

    constructor(tunerIndex: number, options: { tsmfRelTs?: number; groupId?: number }, onFatal: () => void) {
        this._tunerIndex = tunerIndex;
        this._onFatal = onFatal;
        this._demuxer = new TSMFDemuxer(tunerIndex, null, options);

        this._demuxer.once("error", (err) => {
            log.error("TunerDevice#%d TSMFDemuxer error: %s", this._tunerIndex, err.message);
            this._onFatal();
        });
    }

    get ready(): boolean {
        return this._demuxer.ready;
    }

    get closed(): boolean {
        return this._demuxer.closed;
    }

    get detectedRelTs(): number | null {
        return this._demuxer.detectedRelTs;
    }

    get detectedGroupId(): number | null {
        return this._demuxer.detectedGroupId;
    }

    createInput(): stream.Writable {
        return this._demuxer.createInput();
    }

    setOutput(output: stream.Writable): void {
        this._demuxer.setOutput(output);
    }

    close(): void {
        this._closed = true;
        this.releaseCarriers();
        this._demuxer.close();
    }

    // --- Carrier management ---

    setupCarriers(ch: ChannelItem): void {
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
                log.info("TunerDevice#%d starting %d additional carriers for groupId=%d",
                    this._tunerIndex, parsedCount - 1, ch.tsmfGroupId);
                this._startCarriers(ch).catch(log.error);
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
        this._closed = true;
        for (const link of this._carrierLinks) {
            try { link.sourceStream.removeAllListeners(); } catch (e) { /* ignore */ }
            try { link.demuxerInput.end(); } catch (e) { /* ignore */ }
            try { link.device.endStream(link.user, true); } catch (e) { /* ignore */ }
        }
        this._carrierLinks = [];
        this._carrierInitPending = false;
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
        if (this._carrierInitPending || this._carrierLinks.length > 0) {
            return;
        }
        if (!_.tuner || !_.channel || ch.tsmfGroupId === null || ch.tsmfGroupId === undefined) {
            return;
        }

        this._carrierInitPending = true;
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

            const selected = await this._selectDevices(required);

            if (selected.length < required) {
                log.error("TunerDevice#%d failed to find %d BS4K tuners for multi-carrier, only %d available",
                    this._tunerIndex, required, selected.length);
                this._onFatal();
                return;
            }

            log.info("TunerDevice#%d starting %d additional carriers on tuners %s",
                this._tunerIndex, selected.length,
                selected.map(d => `#${d.index}`).join(", ")
            );

            let started = 0;
            for (let i = 0; i < selected.length; i++) {
                if (this._closed) {
                    this.releaseCarriers();
                    return;
                }

                const device = selected[i];
                const channel = groupChannels[i];
                const demuxerInput = this._demuxer.createInput();
                const sourceStream = new stream.PassThrough();
                const tsFilter = sourceStream as unknown as TSFilter;
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

                // Re-check after await — cleanup may have been called during startStream
                if (this._closed) {
                    device.endStream(user, true);
                    this.releaseCarriers();
                    return;
                }

                started++;
                stream.pipeline(sourceStream, demuxerInput, (err) => {
                    if (err && !this._closed) {
                        log.error("TunerDevice#%d pipeline error: %s", this._tunerIndex, (err as Error).message);
                    }
                });

                sourceStream.once("end", () => {
                    try { demuxerInput.end(); } catch (e) { /* ignore */ }
                    if (!this._closed) {
                        log.warn("TunerDevice#%d carrier stream ended on tuner #%d", this._tunerIndex, device.index);
                        this._onFatal();
                    }
                });

                this._carrierLinks.push({ device, user, tsFilter, sourceStream, demuxerInput });
            }

            if (started < required) {
                log.error("TunerDevice#%d only %d of %d additional carriers started", this._tunerIndex, started, required);
                this.releaseCarriers();
                return;
            }

            log.info("TunerDevice#%d all additional carriers started", this._tunerIndex);
        } finally {
            this._carrierInitPending = false;
        }
    }

    private async _selectDevices(required: number): Promise<TunerDevice[]> {
        for (let attempt = 0; attempt < CARRIER_MAX_ATTEMPTS; attempt++) {
            if (this._closed) {
                return [];
            }
            if (attempt > 0) {
                await new Promise(r => setTimeout(r, CARRIER_RETRY_DELAY_MS));
                if (this._closed) {
                    return [];
                }
            }

            const selected = _.tuner.devices
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
                return selected;
            }
        }
        return [];
    }
}
