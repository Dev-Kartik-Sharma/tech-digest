import type { Priority, ScoredItem } from '../types.js';

export interface PendingEntry {
  key: string;
  item: ScoredItem;
}

/** What marking an item as seen needs: every alias, and the priority it was handled at. */
export type SeenEntry = Pick<ScoredItem, 'aliases' | 'priority'>;

/** One day's published brief: everything that was queued for that day's digest. */
export interface DayArchive {
  date: string;
  generatedAt: string;
  items: ScoredItem[];
}

/** A second archive of the same day (e.g. a manual run) adds to it instead of replacing it. */
export function mergeDay(existing: DayArchive | undefined, day: DayArchive): DayArchive {
  if (!existing) return day;
  const items = new Map(existing.items.map((i) => [i.id, i]));
  for (const i of day.items) items.set(i.id, i);
  return { date: day.date, generatedAt: day.generatedAt, items: [...items.values()] };
}

export interface Store {
  /** Returns alias → priority it was handled at, for the aliases already seen. */
  getSeen(aliases: string[]): Promise<Map<string, Priority>>;
  markSeen(items: SeenEntry[]): Promise<void>;
  addPending(items: ScoredItem[]): Promise<void>;
  listPending(): Promise<PendingEntry[]>;
  deletePending(keys: string[]): Promise<void>;
  /** Local date (YYYY-MM-DD) of the last digest, so it goes out once per day. */
  getLastDigestDate(): Promise<string | undefined>;
  setLastDigestDate(date: string): Promise<void>;
  saveDay(day: DayArchive): Promise<void>;
  /** Newest first. */
  listDays(): Promise<DayArchive[]>;
  /** Keeps only the newest `keep` days. */
  pruneDays(keep: number): Promise<void>;
}

export const pendingKey = (item: ScoredItem) => `${item.priority}#${item.publishedAt}#${item.id}`;

export class MemoryStore implements Store {
  seen = new Map<string, Priority>();
  pending = new Map<string, ScoredItem>();
  lastDigestDate: string | undefined;
  days = new Map<string, DayArchive>();

  async getSeen(aliases: string[]) {
    return new Map(aliases.filter((a) => this.seen.has(a)).map((a) => [a, this.seen.get(a)!]));
  }
  async markSeen(items: SeenEntry[]) {
    for (const i of items) for (const a of i.aliases) this.seen.set(a, i.priority);
  }
  async addPending(items: ScoredItem[]) {
    for (const i of items) this.pending.set(pendingKey(i), i);
  }
  async listPending() {
    return [...this.pending.entries()].map(([key, item]) => ({ key, item }));
  }
  async deletePending(keys: string[]) {
    for (const k of keys) this.pending.delete(k);
  }
  async getLastDigestDate() {
    return this.lastDigestDate;
  }
  async setLastDigestDate(date: string) {
    this.lastDigestDate = date;
  }
  async saveDay(day: DayArchive) {
    this.days.set(day.date, mergeDay(this.days.get(day.date), day));
  }
  async listDays() {
    return [...this.days.values()].sort((a, b) => b.date.localeCompare(a.date));
  }
  async pruneDays(keep: number) {
    for (const d of (await this.listDays()).slice(keep)) this.days.delete(d.date);
  }
}
