import { describe, expect, it } from 'vitest';
import { CATEGORY_LABEL, escapeMrkdwn, formatCritical } from '../src/slack/format.js';
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

  it('titles core-product version lists as affected versions', () => {
    const p = formatCritical(item({ ecosystem: 'core', packages: [{ name: 'PHP', ecosystem: 'core', vulnerableRange: '>= 8.3.0, < 8.3.8', patched: '8.3.8' }] }));
    expect(allText(p)).toContain('Affected versions');
    expect(allText(p)).toContain('8.3.8');
  });

  it('turns off link unfurling and links to the brief page when a site URL is given', () => {
    const p = formatCritical(item(), { siteUrl: 'https://example.github.io/repo/' });
    expect(p).toMatchObject({ unfurl_links: false, unfurl_media: false });
    expect(allText(p)).toContain('<https://example.github.io/repo/|');
  });

  it('marks escalations', () => {
    expect(formatCritical(item(), { escalated: true }).text).toMatch(/escalated/i);
  });
});

describe('CATEGORY_LABEL', () => {
  it('labels GitHub/GitLab, containers and hosting platforms as Infrastructure', () => {
    expect(CATEGORY_LABEL['vuln-devops']).toMatch(/^Infrastructure/);
  });
});
