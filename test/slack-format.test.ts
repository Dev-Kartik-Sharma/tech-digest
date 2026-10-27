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

  it('shows the fix version on digest lines for vulnerabilities', () => {
    const t = allText(
      formatDigest(
        [
          item({ id: 'p', priority: 'high', title: 'FIXED', packages: [{ name: 'laravel/framework', ecosystem: 'composer', patched: '13.29.0, 12.68.0' }] }),
          item({ id: 'n', priority: 'high', title: 'UNFIXED', packages: [{ name: 'left-pad', ecosystem: 'npm' }] }),
          item({ id: 'x', priority: 'high', kind: 'news', category: 'tech-news', title: 'NEWS', packages: undefined }),
        ],
        '2026-10-26',
      )!,
    );
    expect(t).toMatch(/FIXED[^•]*fix: laravel\/framework 13\.29\.0, 12\.68\.0/);
    expect(t).toMatch(/UNFIXED[^•]*no fix yet/);
    expect(t).not.toMatch(/NEWS[^•]*fix/);
  });

  it('titles core-product version lists as affected versions', () => {
    const p = formatCritical(item({ ecosystem: 'core', packages: [{ name: 'PHP', ecosystem: 'core', vulnerableRange: '>= 8.3.0, < 8.3.8', patched: '8.3.8' }] }));
    expect(allText(p)).toContain('Affected versions');
    expect(allText(p)).toContain('8.3.8');
  });

  it('labels the new tech-area categories', () => {
    const t = allText(formatDigest([item({ priority: 'high', category: 'vuln-web-server' }), item({ id: 'd', priority: 'high', category: 'vuln-devops' })], '2026-10-26')!);
    expect(t).toContain('Nginx / web server vulnerability');
    expect(t).toContain('GitHub / GitLab vulnerability');
  });

  it('labels AI categories', () => {
    const t = allText(formatDigest([item({ priority: 'medium', kind: 'news', category: 'ai-update' }), item({ id: 'v', priority: 'high', category: 'vuln-ai' })], '2026-10-26')!);
    expect(t).toContain('AI models &amp; tools');
    expect(t).toContain('AI tools vulnerability');
  });

  it('shows the publish date for items older than two days, and not for fresh ones', () => {
    const now = new Date('2026-10-27T04:30:00Z');
    const t = allText(
      formatDigest(
        [
          item({ id: 'old', priority: 'high', title: 'OLD', publishedAt: '2026-10-12T10:00:00Z' }),
          item({ id: 'new', priority: 'high', title: 'NEW', publishedAt: '2026-10-26T20:00:00Z' }),
        ],
        '2026-10-27',
        undefined,
        now,
      )!,
    );
    expect(t).toMatch(/OLD[^•]*published 12 Oct/);
    expect(t).not.toMatch(/NEW[^•]*published/);
  });

  it('shares a priority cap across categories so scored advisories cannot crowd out news', () => {
    const advisories = Array.from({ length: 20 }, (_, i) => item({ id: `a${i}`, priority: 'high', category: 'vuln-js', cvss: 8, title: `ADV ${i}` }));
    const bulletins = Array.from({ length: 3 }, (_, i) =>
      item({ id: `b${i}`, priority: 'high', category: 'vuln-cloud', cvss: undefined, title: `AWS ${i}` }),
    );
    const t = allText(formatDigest([...advisories, ...bulletins], '2026-10-26', { high: 10 })!);
    for (const i of [0, 1, 2]) expect(t).toContain(`AWS ${i}`);
    expect(t.match(/ADV \d+/g)).toHaveLength(7);
    expect(t).toMatch(/13 more high/);
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
