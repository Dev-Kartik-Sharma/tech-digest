import { mkdir, readdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { LIMITS } from '../config/sources.js';
import type { Priority, ScoredItem } from '../types.js';
import { mergeDay, pendingKey, type DayArchive, type SeenEntry, type Store } from './store.js';

const DAY_MS = 86_400_000;
const PENDING_TTL_DAYS = 14;

interface StateFile {
  version: 1;
  /** alias → priority handled at + expiry (epoch ms) */
  seen: Record<string, { p: Priority; exp: number }>;
  pending: Record<string, { item: ScoredItem; exp: number }>;
  lastDigestDate?: string;
}

/**
 * JSON-file store, committed back to the repo by the GitHub Actions workflow: `state.json` plus one
 * `days/<date>.json` per published brief. Changes stay in memory until `save()`.
 */
export class FileStore implements Store {
  private readonly changedDays = new Set<string>();
  private readonly removedDays = new Set<string>();

  private constructor(
    private readonly path: string,
    private readonly now: number,
    private readonly state: StateFile,
    private readonly days: Map<string, DayArchive>,
  ) {}

  private get daysDir() {
    return join(dirname(this.path), 'days');
  }

  static async load(path: string, now = new Date()): Promise<FileStore> {
    let state: StateFile = { version: 1, seen: {}, pending: {} };
    try {
      state = JSON.parse(await readFile(path, 'utf8')) as StateFile;
    } catch (err) {
      // a missing file is a first run; anything else (corrupt JSON) must not reset dedupe silently
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw new Error(`cannot read state ${path}: ${(err as Error).message}`);
    }
    const t = now.getTime();
    for (const [k, v] of Object.entries(state.seen)) if (v.exp <= t) delete state.seen[k];
    for (const [k, v] of Object.entries(state.pending)) if (v.exp <= t) delete state.pending[k];
    const days = new Map<string, DayArchive>();
    const daysDir = join(dirname(path), 'days');
    const files = await readdir(daysDir).catch(() => [] as string[]);
    for (const f of files.filter((f) => /^\d{4}-\d{2}-\d{2}\.json$/.test(f))) {
      const day = JSON.parse(await readFile(join(daysDir, f), 'utf8')) as DayArchive;
      days.set(day.date, day);
    }
    return new FileStore(path, t, state, days);
  }

  async getSeen(aliases: string[]) {
    return new Map(aliases.filter((a) => this.state.seen[a]).map((a) => [a, this.state.seen[a]!.p]));
  }

  async markSeen(items: SeenEntry[]) {
    const exp = this.now + LIMITS.seenTtlDays * DAY_MS;
    for (const i of items) for (const a of i.aliases) this.state.seen[a] = { p: i.priority, exp };
  }

  async addPending(items: ScoredItem[]) {
    const exp = this.now + PENDING_TTL_DAYS * DAY_MS;
    for (const i of items) this.state.pending[pendingKey(i)] = { item: i, exp };
  }

  async listPending() {
    return Object.entries(this.state.pending).map(([key, v]) => ({ key, item: v.item }));
  }

  async deletePending(keys: string[]) {
    for (const k of keys) delete this.state.pending[k];
  }

  async getLastDigestDate() {
    return this.state.lastDigestDate;
  }

  async setLastDigestDate(date: string) {
    this.state.lastDigestDate = date;
  }

  async saveDay(day: DayArchive) {
    this.days.set(day.date, mergeDay(this.days.get(day.date), day));
    this.changedDays.add(day.date);
    this.removedDays.delete(day.date);
  }

  async listDays() {
    return [...this.days.values()].sort((a, b) => b.date.localeCompare(a.date));
  }

  async pruneDays(keep: number) {
    for (const d of (await this.listDays()).slice(keep)) {
      this.days.delete(d.date);
      this.changedDays.delete(d.date);
      this.removedDays.add(d.date);
    }
  }

  async save() {
    await atomicWrite(this.path, this.state);
    for (const date of this.changedDays) await atomicWrite(join(this.daysDir, `${date}.json`), this.days.get(date));
    for (const date of this.removedDays) await rm(join(this.daysDir, `${date}.json`), { force: true });
    this.changedDays.clear();
    this.removedDays.clear();
  }
}

/** Temp file + rename, so a killed run can't leave half a file. */
async function atomicWrite(path: string, data: unknown) {
  await mkdir(dirname(path), { recursive: true });
  const tmp = `${path}.tmp`;
  await writeFile(tmp, `${JSON.stringify(data)}\n`);
  await rename(tmp, path);
}
