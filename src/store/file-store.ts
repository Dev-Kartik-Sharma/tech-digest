import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { LIMITS } from '../config/sources.js';
import type { Priority, ScoredItem } from '../types.js';
import { pendingKey, type SeenEntry, type Store } from './store.js';

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
 * JSON-file store, committed back to the repo by the GitHub Actions workflow.
 * Changes stay in memory until `save()`.
 */
export class FileStore implements Store {
  private constructor(
    private readonly path: string,
    private readonly now: number,
    private readonly state: StateFile,
  ) {}

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
    return new FileStore(path, t, state);
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

  /** Atomic write (temp file + rename) so a killed run can't leave half a file. */
  async save() {
    await mkdir(dirname(this.path), { recursive: true });
    const tmp = `${this.path}.tmp`;
    await writeFile(tmp, `${JSON.stringify(this.state)}\n`);
    await rename(tmp, this.path);
  }
}
