import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { ghsaForKev, nextLink, parseGhsa } from '../src/sources/github-advisories.js';
import { parseKev } from '../src/sources/cisa-kev.js';
import { NVD_CPES } from '../src/config/sources.js';
import { parseNvd } from '../src/sources/nvd.js';
import { parseFeed } from '../src/sources/rss.js';

const fixture = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');
const json = (name: string) => JSON.parse(fixture(name));

describe('parseGhsa', () => {
  it('normalizes a composer advisory with CVE id, cvss v4 score, and patched version', () => {
    const [item] = parseGhsa(json('ghsa-composer.json'));
    expect(item).toMatchObject({
      id: 'CVE-2026-114509',
      kind: 'vuln',
      source: 'GitHub Advisories',
      ecosystem: 'composer',
      cvss: 9.2,
      title: 'Laravel TokenGuard authentication bypass through non-string API credentials',
      url: 'https://github.com/advisories/GHSA-f9x3-7vq9-cph6',
      publishedAt: '2026-10-23T21:50:27Z',
    });
    expect(item?.aliases).toEqual(expect.arrayContaining(['CVE-2026-114509', 'GHSA-f9x3-7vq9-cph6']));
    expect(item?.packages?.[0]).toEqual({
      name: 'laravel/framework',
      ecosystem: 'composer',
      vulnerableRange: '>= 13.0.0, < 13.29.0 | < 12.68.0',
      patched: '13.29.0, 12.68.0',
    });
    expect(item?.cwes).toContain('CWE-287');
  });

  it('dedupes affected packages and uses the cvss v3 score when v4 is 0', () => {
    const items = parseGhsa(json('ghsa-npm.json'));
    const undici = items.find((i) => i.id === 'CVE-2026-109869');
    expect(undici?.cvss).toBe(7.5);
    expect(undici?.packages?.map((p) => p.name)).toEqual(['undici']);
    expect(undici?.packages?.[0]?.patched).toBe('6.29.1, 7.30.1, 8.12.2');
  });

  it('strips markdown headings and emphasis from snippets', () => {
    for (const item of [...parseGhsa(json('ghsa-npm.json')), ...parseGhsa(json('ghsa-composer.json'))]) {
      expect(item.snippet).not.toMatch(/(^|\s)#{1,6}\s|\*\*/);
    }
  });
});

describe('nextLink', () => {
  it('extracts the rel="next" URL from a GitHub Link header', () => {
    const h = '<https://api.github.com/advisories?after=Y3Vy&per_page=100>; rel="next", <https://api.github.com/advisories?before=X>; rel="prev"';
    expect(nextLink(h)).toBe('https://api.github.com/advisories?after=Y3Vy&per_page=100');
    expect(nextLink(null)).toBeUndefined();
    expect(nextLink('<https://x>; rel="prev"')).toBeUndefined();
  });
});

describe('ghsaForKev', () => {
  it('looks up GHSA advisories for KEV CVEs that no GHSA item already covers', async () => {
    const asked: string[] = [];
    const kev = parseKev(json('kev.json'), new Date('2026-10-21T12:00:00Z'));
    const covered = kev[0]!.id;
    const found = await ghsaForKev(kev, new Set([covered]), async (cve) => {
      asked.push(cve);
      return parseGhsa(json('ghsa-composer.json')).slice(0, 1).map((i) => ({ ...i, id: cve, aliases: [cve] }));
    });
    expect(asked).toEqual([kev[1]!.id]);
    expect(found.map((i) => i.id)).toEqual([kev[1]!.id]);
  });

  it('ignores lookup failures', async () => {
    const kev = parseKev(json('kev.json'), new Date('2026-10-21T12:00:00Z'));
    expect(await ghsaForKev(kev, new Set(), async () => Promise.reject(new Error('rate limited')))).toEqual([]);
  });
});

const PHP_PRODUCT = { cpe: 'cpe:2.3:a:php:php', stack: 'php' as const, label: 'PHP' };

describe('parseNvd', () => {
  it('reads affected ranges and fixed versions for the queried product only', () => {
    const items = parseNvd(json('nvd-php.json'), PHP_PRODUCT);
    expect(items.find((i) => i.id === 'CVE-2024-5585')?.packages).toEqual([
      {
        name: 'PHP',
        ecosystem: 'core',
        vulnerableRange: '>= 8.1.0, < 8.1.29 | >= 8.2.0, < 8.2.20 | >= 8.3.0, < 8.3.8',
        patched: '8.1.29, 8.2.20, 8.3.8',
      },
    ]);
    // end-of-life branches (only versionEndIncluding) are affected but have no fix
    const eol = items.find((i) => i.id === 'CVE-2024-5458')?.packages?.[0];
    expect(eol?.vulnerableRange).toContain('>= 7.3.27, <= 7.3.33');
    expect(eol?.patched).toBe('8.1.29, 8.2.20, 8.3.8');
  });

  it('normalizes CVEs with the highest available CVSS score', () => {
    const items = parseNvd(json('nvd-php.json'), PHP_PRODUCT);
    const cve = items.find((i) => i.id === 'CVE-2024-5585');
    expect(cve).toMatchObject({
      kind: 'vuln',
      source: 'NVD',
      ecosystem: 'core',
      stackHint: 'php',
      cvss: 8.8,
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-5585',
    });
    expect(cve?.snippet).toMatch(/^In PHP versions/);
    expect(cve?.title).toBe('CVE-2024-5585 in PHP');
    expect(cve?.publishedAt).toBe('2024-06-09T19:15:52.597Z');
  });
});

describe('parseKev', () => {
  it('keeps only entries added on or after the cutoff date and marks them kev', () => {
    const items = parseKev(json('kev.json'), new Date('2026-10-21T12:00:00Z'));
    expect(items.map((i) => i.id)).toEqual(['CVE-2026-114625', 'CVE-2026-110447']);
    expect(items[0]).toMatchObject({
      kind: 'vuln',
      kev: true,
      source: 'CISA KEV',
      title: 'Arista VeloCloud Orchestrator SQL Injection Vulnerability',
      url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-114625',
    });
  });
});

describe('parseFeed', () => {
  it('parses an Atom feed into news items tagged with the feed kind and stack', async () => {
    const items = await parseFeed(fixture('php-atom.xml'), {
      name: 'PHP.net',
      url: 'https://www.php.net/feed.atom',
      kind: 'release',
      stack: 'php',
    });
    expect(items).toHaveLength(3);
    expect(items[0]).toMatchObject({
      kind: 'news',
      source: 'PHP.net',
      feedKind: 'release',
      stackHint: 'php',
      title: 'Security advisory: Critical remote code execution vulnerabilities, update now',
      url: 'https://www.php.net/index.php#2026-10-21-5',
      publishedAt: '2026-10-21T00:35:26.000Z',
    });
    expect(items[0]?.id).toMatch(/^url-[0-9a-f]{16}$/);
  });

  it('parses an RSS feed, strips HTML from snippets, and records CVE ids as mentions only', async () => {
    const items = await parseFeed(fixture('thn.xml'), {
      name: 'The Hacker News',
      url: 'x',
      kind: 'security-news',
    });
    expect(items.length).toBeGreaterThan(5);
    for (const i of items) {
      expect(i.snippet).not.toMatch(/<[a-z]/i);
      expect(i.snippet.length).toBeLessThanOrEqual(400);
    }
    const withCve = items.find((i) => i.title.includes('PHP Issues Second Windows Security Update'));
    expect(withCve?.mentions).toContain('CVE-2026-111497');
    for (const i of items) expect(i.aliases).toEqual([i.id]);
  });

  it('drops placeholder descriptions like AWS bulletins\' "Read this article"', async () => {
    const xml = `<?xml version="1.0"?><rss version="2.0"><channel><title>AWS</title>
      <item><title>CVE-2026-1 - Issue in X</title><link>https://aws.amazon.com/security/security-bulletins/x/</link>
      <description>Read this article</description><pubDate>Mon, 26 Oct 2026 10:00:00 +0000</pubDate></item></channel></rss>`;
    const [item] = await parseFeed(xml, { name: 'AWS Security Bulletins', url: 'x', kind: 'release', stack: 'cloud' });
    expect(item?.snippet).toBe('');
  });

  it('strips Hacker News link boilerplate from snippets', async () => {
    const xml = `<?xml version="1.0"?><rss version="2.0"><channel><title>HN</title>
      <item><title>Show HN: thing</title><link>https://example.com/t</link>
      <description><![CDATA[<p>Article URL: <a href="https://example.com/t">https://example.com/t</a></p><p>Comments URL: <a href="https://news.ycombinator.com/item?id=1">https://news.ycombinator.com/item?id=1</a></p><p>Points: 412</p><p># Comments: 120</p>]]></description>
      <pubDate>Mon, 26 Oct 2026 10:00:00 +0000</pubDate></item></channel></rss>`;
    const [item] = await parseFeed(xml, { name: 'Hacker News', url: 'x', kind: 'tech-news' });
    expect(item?.snippet).toBe('');
  });
});

describe('NVD_CPES', () => {
  it('checks NVD for Kubernetes, runc, Docker Engine and Docker Desktop as infrastructure', () => {
    const labels = NVD_CPES.filter((c) => c.stack === 'devops').map((c) => c.label);
    expect(labels).toEqual(expect.arrayContaining(['Kubernetes', 'runc', 'Docker Engine', 'Docker Desktop']));
  });
});
