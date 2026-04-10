/*
   Copyright 2026 Till0196

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0
*/
import { dirname, join } from "path";
import { existsSync, readFileSync } from "fs";
import { mkdir, readFile, writeFile } from "fs/promises";
import * as apid from "../../api";
import * as log from "./log";
import _ from "./_";

/**
 * Auto-detected TSMF state for one channel. Persisted in tsmf-meta.json
 * (sibling of services.json) so multi-carrier groupId / per-service relTs
 * mappings survive restarts. The user-config tsmfRelTs / tsmfGroupId values
 * from channels.yml are NOT persisted here — they live in config and are
 * applied at ChannelItem construction time.
 */
export interface TsmfMetaRecord {
    type: apid.ChannelType;
    channel: string;
    groupId?: number;
    relTs?: number;
    /** Per-service auto-detected relTs map (`serviceId → relTs`). */
    serviceRelTsMap?: { [serviceId: string]: number };
}

const META_FILENAME = "tsmf-meta.json";

function getMetaPath(): string {
    const servicesPath = process.env.SERVICES_DB_PATH;
    if (!servicesPath) {
        throw new Error("SERVICES_DB_PATH is not set");
    }
    return join(dirname(servicesPath), META_FILENAME);
}

/**
 * Standalone TSMF metadata persistence. Snapshots ChannelItem auto-detected
 * state to disk so multi-carrier discovery doesn't have to repeat at every
 * restart. Save is debounced (~500ms) so a burst of updates during a scan
 * collapses to a single write.
 */
export default class TsmfMeta {

    private _saveTimer: NodeJS.Timeout | null = null;

    /**
     * Load tsmf-meta.json and apply records to existing ChannelItems. Falls
     * back to migrating any auto-detected fields still living in the legacy
     * services.json synthetic records (one-time on upgrade), if the meta
     * file doesn't exist yet.
     */
    async load(): Promise<void> {
        const path = getMetaPath();
        let records: TsmfMetaRecord[] = [];

        if (existsSync(path)) {
            try {
                const json = await readFile(path, "utf8");
                records = JSON.parse(json) as TsmfMetaRecord[];
                log.info("loaded tsmf-meta `%s` (%d records)", path, records.length);
            } catch (e) {
                log.error("tsmf-meta `%s` is broken (%s: %s)", path, (e as Error).name, (e as Error).message);
            }
        } else {
            // Legacy migration: scan existing services.json synthetic records.
            records = await this._migrateFromServicesDb();
            if (records.length > 0) {
                log.info("migrated %d tsmf records from legacy services.json", records.length);
            }
        }

        for (const record of records) {
            const channel = _.channel?.get(record.type, record.channel);
            if (!channel) {
                continue;
            }
            if (record.groupId !== undefined && record.groupId !== null) {
                channel.setTsmfGroupId(record.groupId);
            }
            if (record.relTs !== undefined && record.relTs !== null) {
                channel.setTsmfRelTs(record.relTs);
            }
            if (record.serviceRelTsMap) {
                for (const [serviceIdStr, relTs] of Object.entries(record.serviceRelTsMap)) {
                    channel.addTsmfRelTsMapping(Number(serviceIdStr), relTs);
                }
            }
        }
    }

    /**
     * Schedule a save. Subsequent calls within the debounce window collapse
     * into a single disk write.
     */
    schedule(): void {
        if (this._saveTimer) {
            return;
        }
        this._saveTimer = setTimeout(() => {
            this._saveTimer = null;
            this.save().catch(e => log.error("tsmf-meta save failed: %s", (e as Error).message));
        }, 500);
    }

    /** Snapshot current ChannelItem state and write tsmf-meta.json. */
    async save(): Promise<void> {
        if (!_.channel) {
            return;
        }
        const records: TsmfMetaRecord[] = [];
        for (const channel of _.channel.items) {
            const record: TsmfMetaRecord = { type: channel.type, channel: channel.channel };
            let hasData = false;

            // Only persist auto-detected values; user-config values come from channels.yml.
            if (channel.tsmfGroupId !== null && channel.tsmfGroupId !== undefined &&
                channel.tsmfGroupId !== 255 && !channel.hasConfigTsmfGroupId) {
                record.groupId = channel.tsmfGroupId;
                hasData = true;
            }
            if (channel.tsmfRelTs !== null && channel.tsmfRelTs !== undefined &&
                !channel.hasConfigTsmfRelTs) {
                record.relTs = channel.tsmfRelTs;
                hasData = true;
            }

            const relTsMap = channel.getRelTsMap();
            if (relTsMap.size > 0) {
                const serialized: { [serviceId: string]: number } = {};
                for (const [relTs, serviceIds] of relTsMap) {
                    for (const serviceId of serviceIds) {
                        serialized[String(serviceId)] = relTs;
                    }
                }
                if (Object.keys(serialized).length > 0) {
                    record.serviceRelTsMap = serialized;
                    hasData = true;
                }
            }

            if (hasData) {
                records.push(record);
            }
        }

        const path = getMetaPath();
        const dir = dirname(path);
        if (!existsSync(dir)) {
            await mkdir(dir, { recursive: true });
        }
        await writeFile(path, JSON.stringify(records, null, 2));
        log.info("saved tsmf-meta `%s` (%d records)", path, records.length);
    }

    /**
     * One-time migration: read existing services.json and pull out synthetic
     * `isMultiCarrier` records plus per-service `tsmfRelTs` / `tsmfGroupId`
     * fields that the previous fork put inside service records.
     */
    private async _migrateFromServicesDb(): Promise<TsmfMetaRecord[]> {
        const servicesPath = process.env.SERVICES_DB_PATH;
        if (!servicesPath || !existsSync(servicesPath)) {
            return [];
        }
        let raw: any[];
        try {
            raw = JSON.parse(readFileSync(servicesPath, "utf8"));
        } catch {
            return [];
        }
        // Skip the integrity header element if present.
        const records = raw.length > 0 && raw[0]?.__integrity__ ? raw.slice(1) : raw;
        const merged = new Map<string, TsmfMetaRecord>();
        for (const entry of records) {
            const ch = entry?.channel;
            if (!ch?.type || !ch?.channel) {
                continue;
            }
            const key = `${ch.type}:${ch.channel}`;
            const record: TsmfMetaRecord = merged.get(key) ?? { type: ch.type, channel: ch.channel };
            if (ch.tsmfGroupId !== undefined && ch.tsmfGroupId !== null && ch.tsmfGroupId !== 255) {
                record.groupId = ch.tsmfGroupId;
            }
            if (ch.tsmfRelTs !== undefined && ch.tsmfRelTs !== null) {
                if (entry.serviceId !== undefined && entry.serviceId !== null) {
                    record.serviceRelTsMap ??= {};
                    record.serviceRelTsMap[String(entry.serviceId)] = ch.tsmfRelTs;
                } else {
                    record.relTs = ch.tsmfRelTs;
                }
            }
            merged.set(key, record);
        }
        return [...merged.values()];
    }
}
