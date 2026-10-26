import { describe, expect, it } from 'vitest';
import { mergeDuplicates, splitBySeen } from '../src/pipeline/dedupe.js';
import type { Item, ScoredItem } from '../src/types.js';

const base = { kind: 'vuln' as const, title: 't', url: 'u', publishedAt: '2026-10-25T00:00:00Z', snippet: '' };

describe('mergeDuplicates', () => {
  it('merges the same CVE from GHSA, NVD and KEV into one item', () => {
    const items: Item[] = [
      { ...base, id: 'CVE-1', aliases: ['CVE-1'], source: 'NVD', ecosystem: 'php-core', cvss: 9.8, snippet: 'nvd text' },
      { ...base, id: 'CVE-1', aliases: ['CVE-1'], source: 'CISA KEV', kev: true },
      {
        ...base,
        id: 'CVE-1',
        aliases: ['CVE-1', 'GHSA-aaaa'],
        source: 'GitHub Advisories',
        ecosystem: 'composer',
        cvss: 9.1,
        title: 'ghsa title',
        packages: [{ name: 'a/b', ecosystem: 'composer' }],
      },
    ];
    const merged = mergeDuplicates(items);
    expect(merged).toHaveLength(1);
    expect(merged[0]).toMatchObject({
      id: 'CVE-1',
      source: 'GitHub Advisories',
      title: 'ghsa title',
      kev: true,
      cvss: 9.8,
      ecosystem: 'composer',
    });
    expect(merged[0]?.aliases.sort()).toEqual(['CVE-1', 'GHSA-aaaa']);
  });

  it('folds a news article that mentions a CVE into the vulnerability', () => {
    const merged = mergeDuplicates([
      { ...base, kind: 'news', id: 'url-1', aliases: ['url-1'], mentions: ['CVE-2'], source: 'The Hacker News', feedKind: 'security-news' },
      { ...base, id: 'CVE-2', aliases: ['CVE-2'], source: 'NVD', ecosystem: 'node-core' },
    ]);
    expect(merged).toHaveLength(1);
    expect(merged[0]).toMatchObject({ id: 'CVE-2', kind: 'vuln', source: 'NVD' });
    expect(merged[0]?.aliases).toContain('url-1');
  });

  it('never merges two different CVEs because one article mentions both', () => {
    const merged = mergeDuplicates([
      { ...base, id: 'CVE-5', aliases: ['CVE-5'], source: 'NVD' },
      { ...base, id: 'CVE-6', aliases: ['CVE-6'], source: 'NVD' },
      { ...base, kind: 'news', id: 'url-9', aliases: ['url-9'], mentions: ['CVE-5', 'CVE-6'], source: 'The Hacker News' },
    ]);
    expect(merged.map((i) => i.id).sort()).toEqual(['CVE-5', 'CVE-6']);
    expect(merged.every((i) => i.aliases.includes('url-9'))).toBe(true);
  });

  it('keeps a news article separate, without CVE aliases, when no vulnerability matches its mentions', () => {
    const merged = mergeDuplicates([
      { ...base, kind: 'news', id: 'url-7', aliases: ['url-7'], mentions: ['CVE-7'], source: 'The Hacker News' },
    ]);
    expect(merged).toHaveLength(1);
    expect(merged[0]?.aliases).toEqual(['url-7']);
  });

  it('keeps unrelated items apart', () => {
    const merged = mergeDuplicates([
      { ...base, id: 'CVE-3', aliases: ['CVE-3'], source: 'NVD' },
      { ...base, kind: 'news', id: 'url-2', aliases: ['url-2'], source: 'BleepingComputer' },
    ]);
    expect(merged).toHaveLength(2);
  });
});

describe('splitBySeen', () => {
  const scored = (id: string, priority: ScoredItem['priority']): ScoredItem => ({
    ...base,
    id,
    aliases: [id, `${id}-alias`],
    source: 's',
    priority,
    category: 'vuln-js',
  });

  it('returns unseen items as fresh and drops seen ones', () => {
    const { fresh, escalated } = splitBySeen(
      [scored('A', 'high'), scored('B', 'low')],
      new Map([['B-alias', 'low']]),
    );
    expect(fresh.map((i) => i.id)).toEqual(['A']);
    expect(escalated).toEqual([]);
  });

  it('escalates a seen item that has now become critical', () => {
    const { fresh, escalated } = splitBySeen([scored('A', 'critical')], new Map([['A', 'high']]));
    expect(fresh).toEqual([]);
    expect(escalated.map((i) => i.id)).toEqual(['A']);
  });

  it('does not re-alert an item already seen as critical', () => {
    const { fresh, escalated } = splitBySeen([scored('A', 'critical')], new Map([['A', 'critical']]));
    expect(fresh).toEqual([]);
    expect(escalated).toEqual([]);
  });
});
