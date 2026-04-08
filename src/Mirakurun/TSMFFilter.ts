import * as stream from "stream";
import * as log from "./log";
import _ from "./_";
import * as common from "./common";
import TSMFDemuxer from "./TSMFDemuxer";
import ChannelItem from "./ChannelItem";
import * as apid from "../../api";
import TSFilter from "./TSFilter";
import type TunerDevice from "./TunerDevice";

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
    private _onFatal: (closing?: boolean) => void;

    constructor(tunerIndex: number, options: { tsmfRelTs?: number; groupId?: number }, onFatal: (closing?: boolean) => void) {
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

    get hasCarriers(): boolean {
        return this._carrierLinks.length > 0;
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
        // Persist groupId to services DB as soon as detected.
        // This ensures groupId survives restarts even if bonding fails on first boot.
        this._demuxer.once("groupId", (groupId: number, numberOfCarriers: number) => {
            ch.setTsmfGroupId(groupId);
            log.debug("TunerDevice#%d TSMF detected groupId=%d numberOfCarriers=%d on %s",
                this._tunerIndex, groupId, numberOfCarriers, ch.channel);
            if (_.service) {
                _.service.save();
            }
        });

        this._demuxer.once("needCarriers", (count: number) => {
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

    /**
     * Start additional carriers for multi-carrier bonding.
     * Tuner availability is guaranteed by the job system's readyFn;
     * groupId discovery is handled by the reactive scan flow.
     */
    private _waitAndStartCarriers(ch: ChannelItem, count: number): void {
        if (this._closed) {
            return;
        }
        if (ch.tsmfGroupId === null || ch.tsmfGroupId === undefined) {
            log.warn("TunerDevice#%d cannot attach extra carriers without tsmfGroupId, aborting stream", this._tunerIndex);
            this._onFatal();
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
            this._onFatal(true);
            return;
        }

        const parsedCount = this._countGroupCarriers(ch);
        if (parsedCount < count) {
            log.warn("TunerDevice#%d not enough group channels for groupId=%d, need %d but got %d — aborting stream",
                this._tunerIndex, ch.tsmfGroupId, count, parsedCount);
            this._onFatal();
            return;
        }
        log.info("TunerDevice#%d starting %d additional carriers for groupId=%d",
            this._tunerIndex, count - 1, ch.tsmfGroupId);
        this._startCarriers(ch).catch(log.error);
    }

    private _countGroupCarriers(ch: ChannelItem): number {
        if (!_.channel || ch.tsmfGroupId === null || ch.tsmfGroupId === undefined) {
            return 0;
        }
        return _.channel.items.filter(item =>
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
                item.tsmfGroupId === ch.tsmfGroupId &&
                item.channel !== ch.channel
            );
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
                this._onFatal();
                return;
            }

            log.info("TunerDevice#%d starting %d additional carriers on tuners %s",
                this._tunerIndex, selected.length,
                selected.map(d => `#${d.index}`).join(", ")
            );

            // Start all additional carriers in parallel to minimize tuning latency.
            // Each startStream may need to kill/release an existing process (~1s each),
            // so parallel startup saves N seconds vs serial.
            const parentDevice = _.tuner.get(this._tunerIndex);
            const carrierPriority = parentDevice ? parentDevice.getPriority() : -1;

            const startPromises = selected.map((device, i) => {
                const channel = groupChannels[i];
                const demuxerInput = this._demuxer.createInput();
                const sourceStream = new stream.PassThrough();
                const tsFilter = sourceStream as unknown as TSFilter;
                const user: common.User & { _stream?: TSFilter } = {
                    id: `Mirakurun:addCarrier()`,
                    priority: carrierPriority,
                    disableDecoder: true,
                    streamSetting: { channel }
                };
                return { device, channel, demuxerInput, sourceStream, tsFilter, user };
            });

            const results = await Promise.allSettled(
                startPromises.map(p => p.device.startStream(p.user, p.tsFilter, p.channel, { suppressGroupCombine: true }))
            );

            let started = 0;
            for (let i = 0; i < results.length; i++) {
                if (this._closed) {
                    this.releaseCarriers();
                    return;
                }

                const { device, demuxerInput, sourceStream, tsFilter, user } = startPromises[i];

                if (results[i].status === "rejected") {
                    log.error("TunerDevice#%d carrier start failed on tuner #%d `%s`",
                        this._tunerIndex, device.index, (results[i] as PromiseRejectedResult).reason?.message);
                    continue;
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
                log.warn("TunerDevice#%d only %d of %d additional carriers started, retrying...",
                    this._tunerIndex, started, required);
                this.releaseCarriers();
                this._onFatal();
                return;
            }

            log.info("TunerDevice#%d all additional carriers started", this._tunerIndex);
        } finally {
            this._carrierInitPending = false;
        }
    }

    private _selectDevices(required: number, channelType: apid.ChannelType): TunerDevice[] {
        if (this._closed) {
            return [];
        }
        return _.tuner.devices
            .map(d => _.tuner.get(d.index))
            .filter(d =>
                d && d.index !== this._tunerIndex && !d.isRemote && d.config.types.includes(channelType) && d.isFree
            )
            .slice(0, required) as TunerDevice[];
    }
}
