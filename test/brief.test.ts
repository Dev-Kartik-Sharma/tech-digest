import { describe, expect, it } from 'vitest';
import { formatBrief } from '../src/slack/format.js';
import type { ScoredItem } from '../src/types.js';

const SITE = 'https://dev-kartik-sharma.github.io/tech-digest/';

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
    snippet: `snippet ${n}`,
    summary: `AI summary ${n}.`,
    priority: 'high',
    category: 'tech-news',
    ...over,
  };
};

const allText = (p: object) => JSON.stringify(p);
/** Titles of the cards, in order (each card's title is the first bold link in a section). */
const cardTitles = (p: { blocks: Record<string, unknown>[] }) =>
  p.blocks
    .map((b) => (b as { text?: { text?: string } }).text?.text ?? '')
    .map((t) => /^\*<[^|]+\|([^>]+)>\*/.exec(t)?.[1])
    .filter((t): t is string => !!t);

describe('formatBrief', () => {
  it('returns null on a quiet day', () => {
    expect(formatBrief([], '2026-10-27', SITE)).toBeNull();
  });

  it('shows the date and counts per priority', () => {
    const p = formatBrief(
      [item({ priority: 'critical', alertedAt: '2026-10-27T01:00:00Z' }), item({ priority: 'high' }), item({ priority: 'low' })],
      '2026-10-27',
      SITE,
    )!;
    expect(allText(p)).toContain('Sentinel brief · Tue 27 Oct');
    expect(allText(p)).toMatch(/🔴 1 critical · 🟠 1 high · 🟢 1 low/);
    expect(p.text).toMatch(/2026-10-27/);
  });

  it('shows up to 3 critical cards, highest CVSS first, even if they were already alerted', () => {
    const crits = [7.0, 9.8, 8.1, 9.1].map((cvss, i) =>
      item({ priority: 'critical', kind: 'vuln', category: 'vuln-php', cvss, title: `CRIT ${cvss}`, alertedAt: i ? 'x' : undefined }),
    );
    const p = formatBrief([...crits, item({ priority: 'high', title: 'HIGH' })], '2026-10-27', SITE)!;
    expect(cardTitles(p)).toEqual(['CRIT 9.8', 'CRIT 9.1', 'CRIT 8.1']);
    expect(allText(p)).toContain('Top critical');
  });

  it('renders each card with priority, category, AI summary, CVSS, KEV and the fix', () => {
    const p = formatBrief(
      [
        item({
          priority: 'critical',
          kind: 'vuln',
          category: 'vuln-php',
          title: 'Laravel auth bypass',
          summary: 'Attackers can log in as any user. Upgrade laravel/framework to 13.29.0 or later.',
          cvss: 9.2,
          kev: true,
          packages: [{ name: 'laravel/framework', ecosystem: 'composer', patched: '13.29.0' }],
        }),
      ],
      '2026-10-27',
      SITE,
    )!;
    const t = allText(p);
    expect(t).toContain('🔴 CRITICAL · PHP vulnerability');
    expect(t).toContain('Attackers can log in as any user. Upgrade laravel/framework to 13.29.0 or later.');
    expect(t).toContain('CVSS 9.2');
    expect(t).toContain('Actively exploited');
    expect(t).toContain('fix: laravel/framework 13.29.0');
  });

  it('fills up with high, then medium items when there are fewer than 3 criticals', () => {
    const p = formatBrief(
      [
        item({ priority: 'medium', title: 'MED' }),
        item({ priority: 'critical', title: 'CRIT', kind: 'vuln', category: 'vuln-js' }),
        item({ priority: 'high', title: 'HIGH' }),
        item({ priority: 'low', title: 'LOW' }),
      ],
      '2026-10-27',
      SITE,
    )!;
    expect(cardTitles(p)).toEqual(['CRIT', 'HIGH', 'MED']);
  });

  it('never lets a medium item take a slot before a remaining high one, even in another category', () => {
    const p = formatBrief(
      [
        item({ priority: 'critical', title: 'CRIT', kind: 'vuln', category: 'vuln-php' }),
        item({ priority: 'high', title: 'HIGH 1', category: 'vuln-cloud' }),
        item({ priority: 'high', title: 'HIGH 2', category: 'vuln-cloud' }),
        item({ priority: 'medium', title: 'MED', category: 'vuln-js' }),
      ],
      '2026-10-27',
      SITE,
    )!;
    expect(cardTitles(p)).toEqual(['CRIT', 'HIGH 1', 'HIGH 2']);
  });

  it('includes the top AI item when there are no criticals', () => {
    const p = formatBrief(
      [
        ...[1, 2, 3, 4].map((i) => item({ priority: 'high', category: 'vuln-cloud', kind: 'vuln', title: `CLOUD ${i}` })),
        item({ priority: 'medium', category: 'ai-update', title: 'Introducing GPT-7' }),
      ],
      '2026-10-27',
      SITE,
    )!;
    const titles = cardTitles(p);
    expect(titles).toHaveLength(3);
    expect(titles).toContain('Introducing GPT-7');
    expect(allText(p)).toContain('Top picks');
  });

  it('puts PHP, JS and AI criticals ahead of other areas, even with a lower CVSS', () => {
    const p = formatBrief(
      [
        item({ priority: 'critical', kind: 'vuln', category: 'vuln-database', cvss: 9.8, title: 'DB' }),
        item({ priority: 'critical', kind: 'vuln', category: 'vuln-php', cvss: 9.1, title: 'PHP' }),
        item({ priority: 'critical', kind: 'vuln', category: 'vuln-ai', cvss: 9.0, title: 'AI' }),
        item({ priority: 'critical', kind: 'vuln', category: 'vuln-cloud', cvss: 10, title: 'CLOUD' }),
      ],
      '2026-10-27',
      SITE,
    )!;
    expect(cardTitles(p)).toEqual(['PHP', 'AI', 'CLOUD']);
  });

  it('keeps a slot for the top AI item after the criticals when there is room', () => {
    const p = formatBrief(
      [
        item({ priority: 'critical', kind: 'vuln', category: 'vuln-php', title: 'CRIT' }),
        item({ priority: 'high', category: 'vuln-cloud', title: 'HIGH 1' }),
        item({ priority: 'high', category: 'vuln-cloud', title: 'HIGH 2' }),
        item({ priority: 'medium', category: 'ai-update', title: 'Claude Opus 6' }),
      ],
      '2026-10-27',
      SITE,
    )!;
    expect(cardTitles(p)).toEqual(['CRIT', 'HIGH 1', 'Claude Opus 6']);
  });

  it('shows no cards on a low-only day, just counts and the button', () => {
    const p = formatBrief([item({ priority: 'low' })], '2026-10-27', SITE)!;
    expect(cardTitles(p)).toHaveLength(0);
    expect(allText(p)).toContain("Open today's brief");
  });

  it("links the button to that day's page, says how many more are there, and turns off unfurling", () => {
    const p = formatBrief([1, 2, 3, 4, 5].map(() => item({ priority: 'high' })), '2026-10-27', SITE)!;
    expect(allText(p)).toContain(`"url":"${SITE}?day=2026-10-27"`);
    expect(allText(p)).toContain('+2 more updates on the brief page');
    expect(p).toMatchObject({ unfurl_links: false, unfurl_media: false });
  });

  it('says on a card when the AI held it back from an instant alert', () => {
    const p = formatBrief([item({ priority: 'critical', holdReason: 'Needs a <non-default> config' })], '2026-10-27', SITE)!;
    expect(allText(p)).toContain('Not alerted instantly: Needs a &lt;non-default&gt; config');
  });

  it('falls back to the snippet and escapes titles and summaries', () => {
    const p = formatBrief([item({ title: 'a <b> & c', summary: undefined, snippet: 'x < y' })], '2026-10-27', SITE)!;
    expect(allText(p)).toContain('a &lt;b&gt; &amp; c');
    expect(allText(p)).toContain('x &lt; y');
  });
});
