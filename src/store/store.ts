import type { Priority, ScoredItem } from '../types.js';

export interface PendingEntry {
  key: string;
  item: ScoredItem;
}

/** What marking an item as seen needs: every alias, and the priority it was handled at. */
export type SeenEntry = Pick<ScoredItem, 'aliases' | 'priority'>;

export interface Store {
  /** Returns alias → priority it was handled at, for the aliases already seen. */
  getSeen(aliases: string[]): Promise<Map<string, Priority>>;
  markSeen(items: SeenEntry[]): Promise<void>;
  addPending(items: ScoredItem[]): Promise<void>;
  listPending(): Promise<PendingEntry[]>;
  deletePending(keys: string[]): Promise<void>;
}

export const pendingKey = (item: ScoredItem) => `${item.priority}#${item.publishedAt}#${item.id}`;

export class MemoryStore implements Store {
  seen = new Map<string, Priority>();
  pending = new Map<string, ScoredItem>();

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
}
