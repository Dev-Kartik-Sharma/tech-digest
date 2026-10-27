import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { buildSite } from '../src/site/build.js';
import type { DayArchive } from '../src/store/store.js';
import type { ScoredItem } from '../src/types.js';

const item = (over: Partial<ScoredItem> = {}): ScoredItem => ({
  id: 'CVE-2026-1',
  aliases: ['CVE-2026-1', 'GHSA-abcd', 'url-1234'],
  kind: 'vuln',
  source: 'GitHub Advisories',
  title: 'Laravel auth bypass',
  url: 'https://github.com/advisories/GHSA-abcd',
  publishedAt: '2026-10-26T10:00:00Z',
  snippet: 'raw snippet text',
  summary: 'AI summary. Upgrade laravel/framework to 13.29.0 or later.',
  priority: 'critical',
  category: 'vuln-php',
  cvss: 9.2,
  kev: true,
  alertedAt: '2026-10-26T11:00:00Z',
  ecosystem: 'composer',
  packages: [{ name: 'laravel/framework', ecosystem: 'composer', vulnerableRange: '< 13.29.0', patched: '13.29.0' }],
  ...over,
});

const days: DayArchive[] = [
  {
    date: '2026-10-27',
    generatedAt: '2026-10-27T04:45:00Z',
    items: [
      item(),
      item({ id: 'n1', kind: 'news', priority: 'high', category: 'ai-update', summary: undefined, packages: undefined, cvss: undefined, kev: undefined, alertedAt: undefined }),
      item({ id: 'bad', kind: 'news', priority: 'low', category: 'tech-news', url: 'javascript:alert(1)', packages: undefined }),
    ],
  },
  { date: '2026-10-26', generatedAt: '2026-10-26T04:45:00Z', items: [item({ id: 'old', priority: 'medium' })] },
];

function build() {
  const outDir = join(mkdtempSync(join(tmpdir(), 'site-')), 'site');
  return buildSite(days, { outDir }).then(() => ({
    outDir,
    read: (f: string) => JSON.parse(readFileSync(join(outDir, f), 'utf8')),
  }));
}

describe('buildSite', () => {
  it('writes the page, its assets and the icon', async () => {
    const { outDir } = await build();
    for (const f of ['index.html', 'style.css', 'app.js', 'icon.svg', '.nojekyll']) expect(existsSync(join(outDir, f))).toBe(true);
  });

  it('writes a day index, newest first, with counts and category labels', async () => {
    const { read } = await build();
    const index = read('data/days.json');
    expect(index.days.map((d: { date: string }) => d.date)).toEqual(['2026-10-27', '2026-10-26']);
    expect(index.days[0]).toMatchObject({ generatedAt: '2026-10-27T04:45:00Z', counts: { critical: 1, high: 1, medium: 0, low: 1 } });
    expect(index.categories).toContainEqual({ id: 'vuln-php', label: 'PHP vulnerability' });
  });

  it('writes each day with only the fields the page shows', async () => {
    const { read } = await build();
    const [crit, news] = read('data/2026-10-27.json').items;
    expect(crit).toEqual({
      id: 'CVE-2026-1',
      title: 'Laravel auth bypass',
      url: 'https://github.com/advisories/GHSA-abcd',
      source: 'GitHub Advisories',
      publishedAt: '2026-10-26T10:00:00Z',
      priority: 'critical',
      category: 'vuln-php',
      summary: 'AI summary. Upgrade laravel/framework to 13.29.0 or later.',
      cvss: 9.2,
      kev: true,
      alerted: true,
      ids: ['CVE-2026-1', 'GHSA-abcd'],
      fix: 'fix: laravel/framework 13.29.0',
      affected: [{ name: 'laravel/framework', range: '< 13.29.0', patched: '13.29.0' }],
    });
    // falls back to the snippet, and omits what doesn't apply
    expect(news).toMatchObject({ id: 'n1', summary: 'raw snippet text' });
    expect(news).not.toHaveProperty('fix');
    expect(news).not.toHaveProperty('alerted');
  });

  it('drops links that are not https', async () => {
    const { read } = await build();
    const bad = read('data/2026-10-27.json').items.find((i: { id: string }) => i.id === 'bad');
    expect(bad).not.toHaveProperty('url');
  });
});
