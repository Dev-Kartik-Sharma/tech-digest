import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
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

  it('persists the last digest date', async () => {
    const path = tmpFile();
    const store = await FileStore.load(path, NOW);
    expect(await store.getLastDigestDate()).toBeUndefined();
    await store.setLastDigestDate('2026-10-27');
    await store.save();
    expect(await (await FileStore.load(path, NOW)).getLastDigestDate()).toBe('2026-10-27');
  });

  it('archives days as separate files, newest first, merging a second archive of the same day', async () => {
    const path = tmpFile();
    const store = await FileStore.load(path, NOW);
    await store.saveDay({ date: '2026-10-26', generatedAt: '2026-10-26T05:00:00Z', items: [item('A')] });
    await store.saveDay({ date: '2026-10-27', generatedAt: '2026-10-27T05:00:00Z', items: [item('B')] });
    await store.saveDay({ date: '2026-10-27', generatedAt: '2026-10-27T09:00:00Z', items: [item('C'), item('B')] });
    await store.save();
    expect(existsSync(join(dirname(path), 'days', '2026-10-27.json'))).toBe(true);

    const days = await (await FileStore.load(path, NOW)).listDays();
    expect(days.map((d) => d.date)).toEqual(['2026-10-27', '2026-10-26']);
    expect(days[0]?.items.map((i) => i.id).sort()).toEqual(['B', 'C']);
    expect(days[0]?.generatedAt).toBe('2026-10-27T09:00:00Z');
  });

  it('prunes old days and deletes their files', async () => {
    const path = tmpFile();
    const store = await FileStore.load(path, NOW);
    for (const d of ['2026-10-25', '2026-10-26', '2026-10-27']) await store.saveDay({ date: d, generatedAt: NOW.toISOString(), items: [] });
    await store.save();
    await store.pruneDays(2);
    await store.save();
    expect((await store.listDays()).map((d) => d.date)).toEqual(['2026-10-27', '2026-10-26']);
    expect(existsSync(join(dirname(path), 'days', '2026-10-25.json'))).toBe(false);
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
