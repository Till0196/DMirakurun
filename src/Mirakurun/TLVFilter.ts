import * as child_process from "child_process";
import * as stream from "stream";
import * as common from "./common";
import * as log from "./log";
import * as apid from "../../api";
import _ from "./_";
import TSMFFilter from "./TSMFFilter";
import ChannelItem from "./ChannelItem";

export interface TLVFilterResult {
    outputStream: stream.Readable;
    isCarrierOnly: boolean;
}

export default class TLVFilter {

    private _tunerIndex: number;
    private _config: apid.ConfigTunersItem;
    private _mmtsDecoderProcess: child_process.ChildProcess | null = null;
    private _tsmfFilter: TSMFFilter | null = null;
    private _closed = false;
    private _isCarrierOnly = false;
    private _onFatal: (closing?: boolean) => void;

    constructor(tunerIndex: number, config: apid.ConfigTunersItem, onFatal: (closing?: boolean) => void) {
        this._tunerIndex = tunerIndex;
        this._config = config;
        this._onFatal = onFatal;
    }

    get isCarrierOnly(): boolean {
        return this._isCarrierOnly;
    }

    get hasDecoderProcess(): boolean {
        return this._mmtsDecoderProcess !== null && this._mmtsDecoderProcess.pid !== undefined;
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

            // Detect groupId from TSMF header even in carrier mode (needed for probe)
            if (ch.tsmfGroupId === null || ch.tsmfGroupId === undefined) {
                this._detectGroupIdFromRawStream(inputStream, ch);
            }

            return { outputStream: inputStream, isCarrierOnly: true };
        }

        // TSMFFilter + mmtsDecoder
        // TSMFDemuxer auto-selects TLV stream from stream_type bits if tsmfRelTs is not configured
        return this._setupTsmfPipeline(inputStream, ch);
    }

    syncPriorities(newPriority: number): void {
        if (this._tsmfFilter) {
            this._tsmfFilter.syncPriorities(newPriority);
        }
    }

    cleanup(): void {
        if (this._tsmfFilter) {
            this._tsmfFilter.releaseCarriers();
        }
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
            this._tsmfFilter.releaseCarriers();
            try {
                this._tsmfFilter.close();
            } catch (e) {
                // already closed
            }
        }
        this._tsmfFilter = null;
        this._closed = true;
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
        this._tsmfFilter = new TSMFFilter(this._tunerIndex, {
            tsmfRelTs: ch.tsmfRelTs,
            groupId: ch.tsmfGroupId ?? undefined
        }, this._onFatal);

        const primaryInput = this._tsmfFilter.createInput();

        this._tsmfFilter.setupCarriers(ch);

        this._tsmfFilter.once("ready", () => {
            // Store auto-detected TSMF info on channel
            const detectedRelTs = this._tsmfFilter.detectedRelTs;
            const detectedGroupId = this._tsmfFilter.detectedGroupId;
            if (detectedRelTs !== null) {
                ch.setTsmfRelTs(detectedRelTs);
            }
            if (detectedGroupId !== null) {
                ch.setTsmfGroupId(detectedGroupId);
            }
            if (detectedRelTs !== null || detectedGroupId !== null) {
                log.info("TunerDevice#%d TSMF auto-detected relTs=%s groupId=%s on %s",
                    this._tunerIndex,
                    detectedRelTs !== null ? String(detectedRelTs) : "none",
                    detectedGroupId !== null ? String(detectedGroupId) : "none",
                    ch.channel);
            }

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

        stream.pipeline(inputStream, primaryInput, (err) => {
            if (err && !this._closed) {
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

    /**
     * Lightweight groupId detection from raw TSMF stream without full TSMFFilter pipeline.
     * Used in carrier mode to detect groupId for probe purposes.
     */
    private _detectGroupIdFromRawStream(inputStream: stream.Readable, ch: ChannelItem): void {
        const TSMF_PID = 0x2f;
        const TSMF_SYNC_A = 0x1a86;
        const TSMF_SYNC_B = 0x0579;
        let detected = false;
        let lastCC = -1;
        let ccSynced = false;

        const onData = (chunk: Buffer) => {
            if (detected) {
                return;
            }
            for (let i = 0; i <= chunk.length - 188; i += 188) {
                if (chunk[i] !== 0x47) {
                    continue;
                }
                const pid = ((chunk[i + 1] & 0x1f) << 8) | chunk[i + 2];
                if (pid !== TSMF_PID) {
                    continue;
                }
                const sync = ((chunk[i + 4] << 8) | chunk[i + 5]) & 0x1fff;
                if (sync !== TSMF_SYNC_A && sync !== TSMF_SYNC_B) {
                    continue;
                }
                // CC check: skip stale DVR buffer data
                const cc = chunk[i + 3] & 0x0f;
                if (!ccSynced) {
                    if (lastCC >= 0 && cc === ((lastCC + 1) & 0x0f)) {
                        ccSynced = true;
                    } else {
                        lastCC = cc;
                        continue;
                    }
                }
                const frameType = chunk[i + 6] & 0x0f;
                if (frameType === 0x02) {
                    const groupId = chunk[i + 127];
                    if (groupId !== 255) {
                        detected = true;
                        inputStream.removeListener("data", onData);
                        ch.setTsmfGroupId(groupId);
                        log.debug("TunerDevice#%d carrier mode detected groupId=%d on %s", this._tunerIndex, groupId, ch.channel);
                        if (_.service) {
                            _.service.save();
                        }
                    }
                }
                return;
            }
        };
        inputStream.on("data", onData);
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
                this._tsmfFilter.releaseCarriers();
                try {
                    this._tsmfFilter.close();
                } catch (e) {
                    // already closed
                }
                this._tsmfFilter = null;
            }
            this._mmtsDecoderProcess = null;
        });

        this._mmtsDecoderProcess.once("close", (code, signal) => {
            log.debug(
                "TunerDevice#%d mmtsDecoder process has closed with code=%d by signal `%s` (pid=%d)",
                this._tunerIndex, code, signal, pid
            );
            if (!this._closed) {
                this._onFatal();
            }
        });

        return this._mmtsDecoderProcess;
    }
}
