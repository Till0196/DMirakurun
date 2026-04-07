import * as child_process from "child_process";
import * as stream from "stream";
import * as common from "./common";
import * as log from "./log";
import * as apid from "../../api";
import _ from "./_";
import TSMFFilter from "./TSMFFilter";
import { TsmfCCChecker, getTsmfPacketCC, extractGroupIdFromPacket } from "./TSMFDemuxer";
import ChannelItem from "./ChannelItem";

// Stream format detection constants
const TS_SYNC = 0x47;
const TS_PKT = 188;
const TLV_SYNC = 0x7f;
const TLV_VALID_TYPES = new Set([0x01, 0x02, 0x03, 0xfe]);

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

        // Auto-detect stream format (TSMF vs raw TLV) then route to appropriate pipeline
        const outputStream = new stream.PassThrough();

        inputStream.once("data", (firstChunk: Buffer) => {
            const format = this._detectStreamFormat(firstChunk);
            log.info("TunerDevice#%d detected stream format: %s", this._tunerIndex, format);

            // Replay buffered data + forward subsequent data
            const replayStream = new stream.PassThrough();
            replayStream.write(firstChunk);
            inputStream.pipe(replayStream);

            let result: TLVFilterResult;
            if (format === "raw-tlv") {
                result = this._setupRawTlvPipeline(replayStream);
            } else {
                result = this._setupTsmfPipeline(replayStream, ch);
            }
            result.outputStream.pipe(outputStream);
        });

        return { outputStream, isCarrierOnly: false };
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

    /**
     * Detect whether the input stream is TSMF-wrapped (CATV) or raw TLV (satellite).
     *
     * Primary: pattern match (3 consecutive TS sync at 188-byte intervals, or 3 chained TLV packets)
     * Fallback: first sync byte found (0x47 = TSMF, 0x7F = TLV)
     * Default: TSMF (existing behavior)
     */
    private _detectStreamFormat(buffer: Buffer): "tsmf" | "raw-tlv" {
        // Primary: TSMF — find 0x47 with 188-byte interval pattern
        for (let i = 0; i <= buffer.length - TS_PKT * 3; i++) {
            if (buffer[i] === TS_SYNC &&
                buffer[i + TS_PKT] === TS_SYNC &&
                buffer[i + TS_PKT * 2] === TS_SYNC) {
                return "tsmf";
            }
        }

        // Primary: raw TLV — find 3 consecutive valid TLV packets
        for (let i = 0; i <= buffer.length - 4; i++) {
            if (buffer[i] !== TLV_SYNC) {
                continue;
            }
            let offset = i;
            let valid = 0;
            while (valid < 3 && offset + 4 <= buffer.length) {
                if (buffer[offset] !== TLV_SYNC) {
                    break;
                }
                const tlvType = buffer[offset + 1];
                if (!TLV_VALID_TYPES.has(tlvType)) {
                    break;
                }
                const len = (buffer[offset + 2] << 8) | buffer[offset + 3];
                if (len > 65535 || offset + 4 + len > buffer.length) {
                    break;
                }
                offset += 4 + len;
                valid++;
            }
            if (valid >= 3) {
                return "raw-tlv";
            }
        }

        // Fallback: first recognizable byte
        for (let i = 0; i < buffer.length; i++) {
            if (buffer[i] === TS_SYNC) {
                return "tsmf";
            }
            if (buffer[i] === TLV_SYNC) {
                return "raw-tlv";
            }
        }

        // Default to TSMF
        return "tsmf";
    }

    /**
     * Raw TLV pipeline: inputStream → mmtsDecoder → outputStream
     * Used for direct BS satellite reception where TLV is not wrapped in TSMF.
     */
    private _setupRawTlvPipeline(inputStream: stream.Readable): TLVFilterResult {
        log.info("TunerDevice#%d raw TLV mode (direct satellite reception)", this._tunerIndex);

        const outputStream = new stream.PassThrough();
        const proc = this._spawnDecoder();
        if (!proc) {
            return { outputStream, isCarrierOnly: false };
        }

        proc.stdout.pipe(outputStream);
        stream.pipeline(inputStream, proc.stdin, (err) => {
            if (err && !this._closed) {
                log.error("TunerDevice#%d raw TLV pipeline error: %s", this._tunerIndex, (err as Error).message);
            }
        });

        return { outputStream, isCarrierOnly: false };
    }

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
        let detected = false;
        const ccChecker = new TsmfCCChecker();

        const onData = (chunk: Buffer) => {
            if (detected) {
                return;
            }
            for (let i = 0; i <= chunk.length - 188; i += 188) {
                const cc = getTsmfPacketCC(chunk, i);
                if (cc < 0) {
                    continue;
                }
                if (!ccChecker.check(cc)) {
                    continue;
                }
                const groupId = extractGroupIdFromPacket(chunk, i);
                if (groupId >= 0) {
                    detected = true;
                    inputStream.removeListener("data", onData);
                    ch.setTsmfGroupId(groupId);
                    log.debug("TunerDevice#%d carrier mode detected groupId=%d on %s", this._tunerIndex, groupId, ch.channel);
                    if (_.service) {
                        _.service.save();
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
