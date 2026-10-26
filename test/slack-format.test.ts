import { describe, expect, it } from 'vitest';
import { escapeMrkdwn, formatCritical, formatDigest } from '../src/slack/format.js';
import type { ScoredItem } from '../src/types.js';

const item = (over: Partial<ScoredItem> = {}): ScoredItem => ({
  id: 'CVE-2026-1',
  aliases: ['CVE-2026-1'],
  kind: 'vuln',
  source: 'GitHub Advisories',
  title: 'Laravel RCE via <crafted> payload & more',
  url: 'https://github.com/advisories/GHSA-x',
  publishedAt: '2026-10-25T00:00:00Z',
  snippet: 'raw snippet',
  priority: 'critical',
  category: 'vuln-php',
  cvss: 9.8,
  ...over,
});

const allText = (payload: { text: string; blocks: unknown[] }) => JSON.stringify(payload);

describe('escapeMrkdwn', () => {
  it('escapes Slack control characters', () => {
    expect(escapeMrkdwn('a & <b> c')).toBe('a &amp; &lt;b&gt; c');
  });
});

describe('formatCritical', () => {
  it('includes priority, category, escaped linked title, summary, CVSS, KEV and patched versions', () => {
    const p = formatCritical(
      item({ summary: 'AI summary here', kev: true, packages: [{ name: 'laravel/framework', ecosystem: 'composer', patched: '13.29.0' }] }),
    );
    expect(p.text).toMatch(/CRITICAL/);
    const t = allText(p);
    expect(t).toContain('PHP vulnerability');
    expect(t).toContain('<https://github.com/advisories/GHSA-x|Laravel RCE via &lt;crafted&gt; payload &amp; more>');
    expect(t).toContain('AI summary here');
    expect(t).toContain('CVSS 9.8');
    expect(t).toContain('Actively exploited (CISA KEV)');
    expect(t).toContain('laravel/framework');
    expect(t).toContain('13.29.0');
  });

  it('escapes the notification fallback text and patched versions', () => {
    const p = formatCritical(item({ title: 'x <!channel> & y', packages: [{ name: 'a', ecosystem: 'npm', patched: '<2.0' }] }));
    expect(p.text).not.toContain('<!channel>');
    expect(p.text).toContain('&lt;!channel&gt; &amp; y');
    expect(allText(p)).toContain('&lt;2.0');
  });

  it('truncates very long titles', () => {
    expect(allText(formatCritical(item({ title: 'T'.repeat(5000) }))).length).toBeLessThan(4000);
  });

  it('falls back to the snippet when there is no summary', () => {
    expect(allText(formatCritical(item()))).toContain('raw snippet');
  });

  it('marks escalations', () => {
    expect(formatCritical(item(), { escalated: true }).text).toMatch(/escalated/i);
  });
});

describe('formatDigest', () => {
  it('returns null when there is nothing to report', () => {
    expect(formatDigest([], '2026-10-26')).toBeNull();
  });

  it('orders sections by priority and shows counts in the header', () => {
    const p = formatDigest(
      [
        item({ id: 'l', priority: 'low', category: 'tech-news', title: 'LOW ITEM' }),
        item({ id: 'h', priority: 'high', category: 'vuln-js', title: 'HIGH ITEM' }),
        item({ id: 'c', priority: 'critical', title: 'CRIT ITEM' }),
      ],
      '2026-10-26',
    )!;
    const t = allText(p);
    expect(t).toContain('2026-10-26');
    expect(t.indexOf('CRIT ITEM')).toBeLessThan(t.indexOf('HIGH ITEM'));
    expect(t.indexOf('HIGH ITEM')).toBeLessThan(t.indexOf('LOW ITEM'));
    expect(p.text).toMatch(/1 critical.*1 high.*1 low/);
  });

  it('omits headings for categories with no items', () => {
    const t = allText(formatDigest([item({ priority: 'high', category: 'vuln-js', title: 'only one' })], '2026-10-26')!);
    expect(t).toContain('JS / Node vulnerability');
    expect(t).not.toContain('PHP vulnerability');
    expect(t).not.toContain('Tech news');
  });

  it('caps each priority and reports how many were left out', () => {
    const lows = Array.from({ length: 8 }, (_, i) => item({ id: `l${i}`, priority: 'low', category: 'tech-news', title: `low ${i}` }));
    const t = allText(formatDigest(lows, '2026-10-26', { low: 5 })!);
    expect(t).toContain('low 4');
    expect(t).not.toContain('low 5');
    expect(t).toMatch(/3 more/);
  });

  it('stays within Slack block limits for a large digest', () => {
    const many = Array.from({ length: 400 }, (_, i) =>
      item({ id: `x${i}`, priority: 'high', category: i % 2 ? 'vuln-js' : 'vuln-php', title: `item ${i} ${'x'.repeat(150)}` }),
    );
    const p = formatDigest(many, '2026-10-26', { high: 400 })!;
    expect(p.blocks.length).toBeLessThanOrEqual(50);
    for (const b of p.blocks as { text?: { text: string } }[]) {
      if (b.text) expect(b.text.text.length).toBeLessThanOrEqual(3000);
    }
  });
});
