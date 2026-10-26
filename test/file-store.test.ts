import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { FileStore } from '../src/store/file-store.js';
import type { ScoredItem } from '../src/types.js';

const tmpFile = () => join(mkdtempSync(join(tmpdir(), 'tech-updates-')), 'nested', 'state.json');

const item = (id: string, over: Partial<ScoredItem> = {}): ScoredItem => ({
  id,
  aliases: [id, `${id}-alias`],
  kind: 'vuln',
  source: 's',
  title: 't',
  url: 'u',
  publishedAt: '2026-10-26T00:00:00Z',
  snippet: '',
  priority: 'high',
  category: 'vuln-js',
  ...over,
});

const NOW = new Date('2026-10-26T12:00:00Z');

describe('FileStore', () => {
  it('starts empty when the state file does not exist yet', async () => {
    const store = await FileStore.load(tmpFile(), NOW);
    expect((await store.getSeen(['a'])).size).toBe(0);
    expect(await store.listPending()).toEqual([]);
  });

  it('persists seen aliases and pending items across save and load', async () => {
    const path = tmpFile();
    const store = await FileStore.load(path, NOW);
    await store.markSeen([item('A', { priority: 'critical' })]);
    await store.addPending([item('B')]);
    await store.save();

    const reloaded = await FileStore.load(path, NOW);
    expect(await reloaded.getSeen(['A-alias', 'B', 'zzz'])).toEqual(new Map([['A-alias', 'critical']]));
    expect((await reloaded.listPending()).map((e) => e.item.id)).toEqual(['B']);
  });

  it('deletes pending entries by key', async () => {
    const store = await FileStore.load(tmpFile(), NOW);
    await store.addPending([item('A'), item('B')]);
    const [first] = await store.listPending();
    await store.deletePending([first!.key]);
    expect(await store.listPending()).toHaveLength(1);
  });

  it('forgets seen aliases after the TTL', async () => {
    const path = tmpFile();
    const store = await FileStore.load(path, NOW);
    await store.markSeen([item('A')]);
    await store.save();
    const later = new Date(NOW.getTime() + 46 * 86_400_000);
    expect((await (await FileStore.load(path, later)).getSeen(['A'])).size).toBe(0);
    expect(readFileSync(path, 'utf8')).toContain('"A"');
  });

  it('refuses to start from a corrupt state file instead of silently re-alerting everything', async () => {
    const path = tmpFile();
    const store = await FileStore.load(path, NOW);
    await store.save();
    writeFileSync(path, '{ not json');
    await expect(FileStore.load(path, NOW)).rejects.toThrow();
  });
});
