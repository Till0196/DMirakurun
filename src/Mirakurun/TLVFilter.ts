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
import * as apid from "../../api";
import TSMFFilter, { StreamGate } from "./TSMFFilter";
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
        this._tsmfFilter = new TSMFFilter(this._tunerIndex, {
            tsmfRelTs: ch.tsmfRelTs,
            groupId: ch.tsmfGroupId ?? undefined
        }, this._onFatal);

        const primaryInput = this._tsmfFilter.createInput();
        const primaryGate = new StreamGate(8 * 1024 * 1024);
        primaryGate.open();

        this._tsmfFilter.setupCarriers(ch, primaryGate);

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
            if (!this._disposed) {
                this._onFatal();
            }
        });

        return this._mmtsDecoderProcess;
    }
}
