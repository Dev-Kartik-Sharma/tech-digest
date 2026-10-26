import { describe, expect, it } from 'vitest';
import { addDownloads } from '../src/pipeline/popularity.js';
import type { Item } from '../src/types.js';

const item = (id: string, names: string[]): Item => ({
  id,
  aliases: [id],
  kind: 'vuln',
  source: 'GitHub Advisories',
  title: 't',
  url: 'u',
  publishedAt: '2026-10-25T00:00:00Z',
  snippet: '',
  ecosystem: 'npm',
  packages: names.map((name) => ({ name, ecosystem: 'npm' as const })),
});

describe('addDownloads', () => {
  it('sets downloads to the most popular affected package and looks each package up once', async () => {
    const calls: string[] = [];
    const lookup = async (name: string) => {
      calls.push(name);
      return ({ a: 10, b: 5_000 } as Record<string, number>)[name];
    };
    const out = await addDownloads([item('1', ['a', 'b']), item('2', ['a'])], lookup);
    expect(out.map((i) => i.downloads)).toEqual([5_000, 10]);
    expect(calls.sort()).toEqual(['a', 'b']);
  });

  it('leaves downloads unset when every lookup fails', async () => {
    const out = await addDownloads([item('1', ['a'])], async () => {
      throw new Error('boom');
    });
    expect(out[0]?.downloads).toBeUndefined();
  });

  it('passes the ecosystem to the lookup so pip packages hit PyPI stats', async () => {
    const seen: string[] = [];
    const py: Item = { ...item('p', []), ecosystem: 'pip', packages: [{ name: 'django', ecosystem: 'pip' }] };
    await addDownloads([py], async (name, eco) => (seen.push(`${eco}:${name}`), 1));
    expect(seen).toEqual(['pip:django']);
  });

  it('skips items without packages', async () => {
    const news: Item = { ...item('n', []), kind: 'news', packages: undefined };
    const out = await addDownloads([news], async () => 1);
    expect(out[0]?.downloads).toBeUndefined();
  });
});
