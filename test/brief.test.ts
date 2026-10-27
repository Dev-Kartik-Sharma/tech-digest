import { describe, expect, it } from 'vitest';
import { formatBrief } from '../src/slack/format.js';
import type { ScoredItem } from '../src/types.js';

const SITE = 'https://dev-kartik-sharma.github.io/tech-updates-for-slack/';

let n = 0;
const item = (over: Partial<ScoredItem> = {}): ScoredItem => {
  n++;
  return {
    id: `id-${n}`,
    aliases: [`id-${n}`],
    kind: 'news',
    source: 'The Hacker News',
    title: `Headline ${n}`,
    url: `https://example.com/${n}`,
    publishedAt: '2026-10-27T00:00:00Z',
    snippet: '',
    priority: 'high',
    category: 'tech-news',
    ...over,
  };
};

const allText = (p: object) => JSON.stringify(p);
const lines = (p: { blocks: Record<string, unknown>[] }) =>
  p.blocks
    .map((b) => (b as { text?: { text?: string } }).text?.text ?? '')
    .join('\n')
    .split('\n')
    .filter((l) => l.startsWith('• '));

describe('formatBrief', () => {
  it('returns null on a quiet day', () => {
    expect(formatBrief([], '2026-10-27', SITE)).toBeNull();
  });

  it('shows the date, counts per priority, and that alerted criticals were already sent', () => {
    const p = formatBrief(
      [
        item({ priority: 'critical', alertedAt: '2026-10-27T01:00:00Z' }),
        item({ priority: 'critical', alertedAt: '2026-10-27T02:00:00Z' }),
        item({ priority: 'high' }),
        item({ priority: 'low' }),
      ],
      '2026-10-27',
      SITE,
    )!;
    expect(allText(p)).toContain('Sentinel brief · Tue 27 Oct');
    expect(allText(p)).toMatch(/🔴 2 critical \(already alerted\) · 🟠 1 high · 🟢 1 low/);
    expect(p.text).toMatch(/2026-10-27/);
  });

  it('lists at most 5 top items, round-robin across categories, with the area and fix version', () => {
    const cloud = Array.from({ length: 6 }, () => item({ category: 'vuln-cloud', title: 'AWS bulletin', kind: 'vuln' }));
    const php = item({
      category: 'vuln-php',
      kind: 'vuln',
      title: 'Brotli fix in PHP Windows builds',
      cvss: 9,
      packages: [{ name: 'PHP', ecosystem: 'core', patched: '8.5.12-1' }],
    });
    const exploited = item({ category: 'exploited-in-wild', title: 'PHP2Shell exploitation continues' });
    const top = lines(formatBrief([...cloud, php, exploited], '2026-10-27', SITE)!);
    expect(top).toHaveLength(5);
    expect(top[0]).toMatch(/^• PHP · <https:\/\/example\.com\/\d+\|Brotli fix in PHP Windows builds> · fix: PHP 8\.5\.12-1$/);
    expect(top.some((l) => l.includes('Exploited · '))).toBe(true);
    expect(top.filter((l) => l.includes('Cloud · '))).toHaveLength(3);
  });

  it('puts criticals that were not alerted (over the per-run cap) at the top of the list', () => {
    const top = lines(
      formatBrief([item({ priority: 'high', title: 'HIGH' }), item({ priority: 'critical', title: 'CRIT' })], '2026-10-27', SITE)!,
    );
    expect(top[0]).toContain('🔴');
    expect(top[0]).toContain('CRIT');
  });

  it("links the button to that day's page and turns off unfurling", () => {
    const p = formatBrief([item()], '2026-10-27', SITE)!;
    expect(allText(p)).toContain(`"url":"${SITE}?day=2026-10-27"`);
    expect(allText(p)).toContain("Open today's brief");
    expect(p).toMatchObject({ unfurl_links: false, unfurl_media: false });
  });

  it('escapes titles', () => {
    expect(allText(formatBrief([item({ title: 'a <b> & c' })], '2026-10-27', SITE)!)).toContain('a &lt;b&gt; &amp; c');
  });

  it('omits the top list when there is nothing high or unalerted-critical', () => {
    const p = formatBrief([item({ priority: 'low' }), item({ priority: 'critical', alertedAt: 'x' })], '2026-10-27', SITE)!;
    expect(lines(p)).toHaveLength(0);
    expect(allText(p)).not.toContain('Top');
  });
});
