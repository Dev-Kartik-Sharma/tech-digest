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

  it('matches MAJOR_PACKAGES case-insensitively (GitHub names some PyPI packages "Django")', () => {
    const s = scoreItem(vuln({ ecosystem: 'pip', cvss: 9.1, packages: [{ name: 'Django', ecosystem: 'pip' }] }));
    expect(s?.priority).toBe('critical');
  });

  it('treats common third-party service SDKs as major packages', () => {
    const sdk = (name: string, ecosystem: 'npm' | 'composer' | 'pip') =>
      scoreItem(vuln({ ecosystem, cvss: 9.1, packages: [{ name, ecosystem }] }))?.priority;
    expect(sdk('@sendgrid/mail', 'npm')).toBe('critical');
    expect(sdk('twilio/sdk', 'composer')).toBe('critical');
    expect(sdk('google-auth-library', 'npm')).toBe('critical');
    expect(sdk('stripe', 'pip')).toBe('critical');
  });

  it('treats platform and container SDKs as major packages', () => {
    const sdk = (name: string, ecosystem: 'npm' | 'pip') => scoreItem(vuln({ ecosystem, cvss: 9.1, packages: [{ name, ecosystem }] }))?.priority;
    expect(sdk('@supabase/supabase-js', 'npm')).toBe('critical');
    expect(sdk('wrangler', 'npm')).toBe('critical');
    expect(sdk('kubernetes', 'pip')).toBe('critical');
  });

  it('files advisories in AI SDKs and agent tooling as AI security, critical-eligible', () => {
    const ai = (name: string, ecosystem: 'npm' | 'pip' | 'composer') => scoreItem(vuln({ ecosystem, cvss: 9.1, packages: [{ name, ecosystem }] }));
    expect(ai('@modelcontextprotocol/sdk', 'npm')).toMatchObject({ priority: 'critical', category: 'vuln-ai' });
    expect(ai('litellm', 'pip')).toMatchObject({ priority: 'critical', category: 'vuln-ai' });
    expect(ai('openai-php/client', 'composer')).toMatchObject({ priority: 'critical', category: 'vuln-ai' });
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

  it('recognises Redis, MariaDB and SQLite as databases', () => {
    for (const db of ['Redis', 'MariaDB', 'SQLite']) {
      expect(scoreItem(vuln({ kev: true, title: `${db} Use-After-Free Vulnerability` }))).toMatchObject({ category: 'vuln-database' });
    }
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

  it('files a breach at a third-party service as a medium third-party services item', () => {
    for (const name of ['SendGrid', 'Twilio', 'Mailchimp', 'Stripe', 'Auth0', 'Okta']) {
      expect(scoreItem(news({ title: `${name} data breach exposes customer API keys` }))).toMatchObject({ priority: 'medium', category: 'vuln-services' });
    }
  });

  it('rates an actively exploited flaw in Google sign-in as high', () => {
    const s = scoreItem(news({ title: 'Google OAuth flaw actively exploited to hijack accounts' }));
    expect(s).toMatchObject({ priority: 'high', category: 'exploited-in-wild' });
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
    expect(area('Kubernetes')).toBe('vuln-devops');
    expect(area('Docker Desktop')).toBe('vuln-devops');
    expect(area('runc')).toBe('vuln-devops');
    expect(area('Vercel')).toBe('vuln-devops');
    expect(area('Supabase')).toBe('vuln-devops');
    expect(area('Cloudflare Workers')).toBe('vuln-devops');
    expect(area('AWS Lambda')).toBe('vuln-cloud');
  });

  it('rates a cloud provider security bulletin as high', () => {
    const s = scoreItem(news({ feedKind: 'release', stackHint: 'cloud', title: 'Issue in the Linux kernel affecting EC2 instances', snippet: 'AWS is aware of a security issue (CVE-2026-1234)' }));
    expect(s).toMatchObject({ priority: 'high', category: 'vuln-cloud' });
  });

  it('rates an AI model launch from an AI feed as medium ai-update', () => {
    const s = scoreItem(news({ feedKind: 'ai-news', title: 'Introducing GPT-6', snippet: 'Our new model scores 80% on SWE-bench.' }));
    expect(s).toMatchObject({ priority: 'medium', category: 'ai-update' });
  });

  it('rates other AI feed posts as low ai-update', () => {
    const s = scoreItem(news({ feedKind: 'ai-news', title: 'How our team thinks about AI safety' }));
    expect(s).toMatchObject({ priority: 'low', category: 'ai-update' });
  });

  it('recognises AI launches in general tech news', () => {
    const s = scoreItem(news({ feedKind: 'tech-news', title: 'Anthropic launches Claude Example 6 for agentic coding' }));
    expect(s).toMatchObject({ priority: 'medium', category: 'ai-update' });
  });

  it('treats a vulnerability in an AI coding tool as vuln-ai', () => {
    const s = scoreItem(news({ title: 'Claude Code flaw allowed remote code execution via malicious repo' }));
    expect(s).toMatchObject({ priority: 'high', category: 'vuln-ai' });
  });

  it('files AI security research as vuln-ai: medium, or high for prompt injection and CVEs', () => {
    const feed = { feedKind: 'security-news' as const, stackHint: 'ai' as const };
    expect(scoreItem(news({ ...feed, title: 'Breaking Claude Code Opus 5 Auto Mode' }))).toMatchObject({ priority: 'medium', category: 'vuln-ai' });
    expect(scoreItem(news({ ...feed, title: 'Visual Studio Copilot remote code execution (CVE-2026-103572)' }))).toMatchObject({ priority: 'high', category: 'vuln-ai' });
    expect(scoreItem(news({ title: 'Prompt injection in GitHub Copilot leaks private repo secrets' }))).toMatchObject({ priority: 'high', category: 'vuln-ai' });
  });

  it('only files AI stories from general security sites as AI security when they are about an attack, flaw or breach', () => {
    expect(scoreItem(news({ title: 'OpenAI launches GPT-6.1 Terra with 3x faster AI agents, 50% lower pricing' }))?.category).toBe('ai-update');
    expect(scoreItem(news({ title: 'Warp discloses breach exposing AI agent logs, user telemetry data' }))?.category).toBe('vuln-ai');
    expect(scoreItem(news({ title: 'OpenAI Compaction Flaw Let Researchers Bypass Hidden Reasoning Protections' }))?.category).toBe('vuln-ai');
    expect(scoreItem(news({ title: 'OpenAI AI Agents Demonstrate VM Escapes and Secret Cross-Sandbox Communication' }))?.category).toBe('vuln-ai');
  });

  it('rates AI coding tool updates as medium even without launch words', () => {
    const ai = { feedKind: 'ai-news' as const, stackHint: 'ai' as const };
    expect(scoreItem(news({ ...ai, title: 'Agent SDK', snippet: 'Build your own agents on top of Cursor.' }))).toMatchObject({ priority: 'medium', category: 'ai-update' });
    expect(scoreItem(news({ ...ai, title: 'Copilot assisted permissions in pull requests' }))).toMatchObject({ priority: 'medium', category: 'ai-update' });
    expect(scoreItem(news({ ...ai, title: 'Our thoughts on AI policy' }))).toMatchObject({ priority: 'low', category: 'ai-update' });
  });

  it('rates a compromised popular package or worm in npm, Composer or AI tooling as critical supply chain', () => {
    expect(scoreItem(news({ title: 'Popular npm package chalk compromised to steal crypto' }))).toMatchObject({ priority: 'critical', category: 'supply-chain' });
    expect(scoreItem(news({ title: 'Self-replicating worm spreads through npm maintainer accounts' }))).toMatchObject({ priority: 'critical', category: 'supply-chain' });
    // ordinary malicious-package reports stay high
    expect(scoreItem(news({ title: 'Malicious npm packages steal developer credentials' }))).toMatchObject({ priority: 'high', category: 'supply-chain' });
    expect(scoreItem(news({ title: 'Malicious npm packages that compromised developer machines' }))).toMatchObject({ priority: 'high', category: 'supply-chain' });
  });

  it('treats malicious MCP servers and IDE extensions as supply chain', () => {
    expect(scoreItem(news({ title: 'Malicious MCP server quietly copies every email to attackers' }))?.category).toBe('supply-chain');
    expect(scoreItem(news({ title: 'Malicious VS Code extensions target Cursor users' }))?.category).toBe('supply-chain');
  });

  it('rates general tech news as low tech-news', () => {
    const s = scoreItem(news({ feedKind: 'tech-news', title: 'A new open-source text editor' }));
    expect(s).toMatchObject({ priority: 'low', category: 'tech-news' });
  });
});
