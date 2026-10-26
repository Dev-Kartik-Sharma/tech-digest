import { describe, expect, it } from 'vitest';
import { scoreItem } from '../src/pipeline/score.js';
import type { Item } from '../src/types.js';

const vuln = (over: Partial<Item>): Item => ({
  id: 'CVE-2026-0001',
  aliases: ['CVE-2026-0001'],
  kind: 'vuln',
  source: 'test',
  title: 'Some vulnerability',
  url: 'https://example.com',
  publishedAt: '2026-10-25T00:00:00Z',
  snippet: '',
  ...over,
});

const news = (over: Partial<Item>): Item => ({
  id: 'url-1',
  aliases: ['url-1'],
  kind: 'news',
  source: 'test',
  title: 'Some headline',
  url: 'https://example.com/a',
  publishedAt: '2026-10-25T00:00:00Z',
  snippet: '',
  feedKind: 'security-news',
  ...over,
});

describe('scoreItem: vulnerabilities', () => {
  it('rates a CVSS 9.8 PHP core RCE as critical vuln-php', () => {
    const s = scoreItem(vuln({ ecosystem: 'core', stackHint: 'php', cvss: 9.8, title: 'PHP CGI remote code execution' }));
    expect(s).toMatchObject({ priority: 'critical', category: 'vuln-php' });
  });

  it('rates a Node.js core RCE as critical even below CVSS 9', () => {
    const s = scoreItem(vuln({ ecosystem: 'core', stackHint: 'js', cvss: 8.1, snippet: 'allows remote code execution' }));
    expect(s).toMatchObject({ priority: 'critical', category: 'vuln-js' });
  });

  it('rates CVSS 9+ in a popular npm package as critical', () => {
    const s = scoreItem(
      vuln({ ecosystem: 'npm', cvss: 9.1, downloads: 2_000_000, packages: [{ name: 'some-lib', ecosystem: 'npm' }] }),
    );
    expect(s?.priority).toBe('critical');
  });

  it('downgrades CVSS 9+ in an unpopular npm package to high', () => {
    const s = scoreItem(
      vuln({ ecosystem: 'npm', cvss: 9.8, downloads: 5_000, packages: [{ name: 'obscure-lib', ecosystem: 'npm' }] }),
    );
    expect(s?.priority).toBe('high');
  });

  it('treats MAJOR_PACKAGES as popular when downloads are unknown', () => {
    const s = scoreItem(vuln({ ecosystem: 'npm', cvss: 9.3, packages: [{ name: 'next', ecosystem: 'npm' }] }));
    expect(s?.priority).toBe('critical');
  });

  it('drops advisories for packages below the download floor', () => {
    const s = scoreItem(
      vuln({ ecosystem: 'npm', cvss: 7.5, downloads: 40, packages: [{ name: 'tiny', ecosystem: 'npm' }] }),
    );
    expect(s).toBeNull();
  });

  it('maps CVSS bands to high/medium/low for in-stack packages', () => {
    const pkg = { downloads: 10_000, packages: [{ name: 'x/y', ecosystem: 'composer' as const }] };
    expect(scoreItem(vuln({ ecosystem: 'composer', cvss: 7.2, ...pkg }))?.priority).toBe('high');
    expect(scoreItem(vuln({ ecosystem: 'composer', cvss: 5.3, ...pkg }))?.priority).toBe('medium');
    expect(scoreItem(vuln({ ecosystem: 'composer', cvss: 2.1, ...pkg }))?.priority).toBe('low');
  });

  it('rates an in-stack CISA KEV entry as critical', () => {
    const s = scoreItem(vuln({ kev: true, title: 'PHP-CGI OS Command Injection Vulnerability' }));
    expect(s).toMatchObject({ priority: 'critical', category: 'vuln-php' });
  });

  it('rates an out-of-stack KEV entry as high exploited-in-wild', () => {
    const s = scoreItem(vuln({ kev: true, title: 'Arista VeloCloud Orchestrator SQL Injection Vulnerability' }));
    expect(s).toMatchObject({ priority: 'high', category: 'exploited-in-wild' });
  });

  it('rates a CVSS 9.8 in a popular pip package as critical vuln-python', () => {
    const s = scoreItem(
      vuln({ ecosystem: 'pip', cvss: 9.8, downloads: 500_000, packages: [{ name: 'some-py', ecosystem: 'pip' }] }),
    );
    expect(s).toMatchObject({ priority: 'critical', category: 'vuln-python' });
  });

  it('rates core products by their tech area', () => {
    const core = (stackHint: Item['stackHint'], cvss: number) => scoreItem(vuln({ ecosystem: 'core', stackHint, cvss }));
    expect(core('web-server', 9.8)).toMatchObject({ priority: 'critical', category: 'vuln-web-server' });
    expect(core('devops', 9.6)).toMatchObject({ priority: 'critical', category: 'vuln-devops' });
    expect(core('database', 7.5)).toMatchObject({ priority: 'high', category: 'vuln-database' });
    expect(core('python', 5.0)).toMatchObject({ priority: 'medium', category: 'vuln-python' });
  });

  it('recognises nginx, MongoDB and GitLab in KEV titles', () => {
    expect(scoreItem(vuln({ kev: true, title: 'F5 NGINX Plus Buffer Overflow Vulnerability' }))).toMatchObject({ priority: 'critical', category: 'vuln-web-server' });
    expect(scoreItem(vuln({ kev: true, title: 'MongoDB Server Use-After-Free Vulnerability' }))).toMatchObject({ priority: 'critical', category: 'vuln-database' });
    expect(scoreItem(vuln({ kev: true, title: 'GitLab Improper Access Control Vulnerability' }))).toMatchObject({ priority: 'critical', category: 'vuln-devops' });
  });

  it('drops an out-of-stack vulnerability that is not on KEV', () => {
    expect(scoreItem(vuln({ cvss: 9.8, title: 'Apache Struts OGNL injection' }))).toBeNull();
  });
});

describe('scoreItem: news', () => {
  it('rates an actively exploited Node.js flaw in security news as high', () => {
    const s = scoreItem(news({ title: 'Node.js zero-day actively exploited in the wild' }));
    expect(s).toMatchObject({ priority: 'high', category: 'exploited-in-wild' });
  });

  it('treats ongoing exploitation of a PHP flaw as high exploited-in-wild', () => {
    const s = scoreItem(news({ title: 'PHP2Shell Exploitation Attempts Continue Amid Global Scanning Activity' }));
    expect(s).toMatchObject({ priority: 'high', category: 'exploited-in-wild' });
  });

  it('categorizes an npm supply-chain attack as supply-chain, medium or higher', () => {
    const s = scoreItem(news({ title: 'Malicious npm packages steal developer credentials' }));
    expect(s?.category).toBe('supply-chain');
    expect(['critical', 'high', 'medium']).toContain(s?.priority);
  });

  it('rates generic security news without stack keywords as low', () => {
    const s = scoreItem(news({ title: 'Hospital chain hit by ransomware' }));
    expect(s).toMatchObject({ priority: 'low', category: 'breach-malware' });
  });

  it('rates a Node.js security release as high vuln-js', () => {
    const s = scoreItem(
      news({ feedKind: 'release', stackHint: 'js', title: 'Tuesday, October 21, 2026 Security Releases' }),
    );
    expect(s).toMatchObject({ priority: 'high', category: 'vuln-js' });
  });

  it('rates a normal PHP release as low release-update', () => {
    const s = scoreItem(news({ feedKind: 'release', stackHint: 'php', title: 'PHP 8.5.3 Released!' }));
    expect(s).toMatchObject({ priority: 'low', category: 'release-update' });
  });

  it('detects the newer tech areas in news', () => {
    const area = (title: string) => scoreItem(news({ title: `${title} remote code execution flaw patched` }))?.category;
    expect(area('NestJS')).toBe('vuln-js');
    expect(area('Angular')).toBe('vuln-js');
    expect(area('Django')).toBe('vuln-python');
    expect(area('PostgreSQL')).toBe('vuln-database');
    expect(area('MySQL')).toBe('vuln-database');
    expect(area('Nginx')).toBe('vuln-web-server');
    expect(area('GitHub Actions')).toBe('vuln-devops');
    expect(area('AWS Lambda')).toBe('vuln-cloud');
  });

  it('rates a cloud provider security bulletin as high', () => {
    const s = scoreItem(news({ feedKind: 'release', stackHint: 'cloud', title: 'Issue in the Linux kernel affecting EC2 instances', snippet: 'AWS is aware of a security issue (CVE-2026-1234)' }));
    expect(s).toMatchObject({ priority: 'high', category: 'vuln-cloud' });
  });

  it('rates general tech news as low tech-news', () => {
    const s = scoreItem(news({ feedKind: 'tech-news', title: 'A new open-source text editor' }));
    expect(s).toMatchObject({ priority: 'low', category: 'tech-news' });
  });
});
