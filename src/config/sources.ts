import type { FeedKind, Stack } from '../types.js';

export interface FeedSource {
  name: string;
  url: string;
  kind: FeedKind;
  /** Set when everything in the feed belongs to one stack. */
  stack?: Stack;
}

export const RSS_FEEDS: FeedSource[] = [
  // security news
  { name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews', kind: 'security-news' },
  { name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/', kind: 'security-news' },
  { name: 'GitHub Security Blog', url: 'https://github.blog/security/feed/', kind: 'security-news', stack: 'devops' },
  // official security / release announcements
  { name: 'Node.js Security', url: 'https://nodejs.org/en/feed/vulnerability.xml', kind: 'release', stack: 'js' },
  { name: 'PHP.net', url: 'https://www.php.net/feed.atom', kind: 'release', stack: 'php' },
  { name: 'Python Insider', url: 'https://blog.python.org/feeds/posts/default', kind: 'release', stack: 'python' },
  { name: 'Django', url: 'https://www.djangoproject.com/rss/weblog/', kind: 'release', stack: 'python' },
  { name: 'PostgreSQL', url: 'https://www.postgresql.org/news.rss', kind: 'release', stack: 'database' },
  { name: 'nginx', url: 'https://nginx.org/index.rss', kind: 'release', stack: 'web-server' },
  { name: 'GitLab Security Releases', url: 'https://about.gitlab.com/security-releases.xml', kind: 'release', stack: 'devops' },
  { name: 'AWS Security Bulletins', url: 'https://aws.amazon.com/security/security-bulletins/rss/feed/', kind: 'release', stack: 'cloud' },
  // dev news
  { name: 'Node.js Blog', url: 'https://nodejs.org/en/feed/blog.xml', kind: 'dev-news', stack: 'js' },
  { name: 'Laravel News', url: 'https://laravel-news.com/feed', kind: 'dev-news', stack: 'php' },
  { name: 'React Blog', url: 'https://react.dev/rss.xml', kind: 'dev-news', stack: 'js' },
  { name: 'Angular Blog', url: 'https://blog.angular.dev/feed', kind: 'dev-news', stack: 'js' },
  { name: 'MongoDB Blog', url: 'https://www.mongodb.com/blog/rss', kind: 'dev-news', stack: 'database' },
  // AI models, research and developer tools (Anthropic has no feed: see sources/anthropic.ts)
  { name: 'OpenAI', url: 'https://openai.com/news/rss.xml', kind: 'ai-news', stack: 'ai' },
  { name: 'Google AI', url: 'https://blog.google/technology/ai/rss/', kind: 'ai-news', stack: 'ai' },
  { name: 'Google DeepMind', url: 'https://deepmind.google/blog/rss.xml', kind: 'ai-news', stack: 'ai' },
  { name: 'Hugging Face', url: 'https://huggingface.co/blog/feed.xml', kind: 'ai-news', stack: 'ai' },
  { name: 'GitHub AI & ML', url: 'https://github.blog/ai-and-ml/feed/', kind: 'ai-news', stack: 'ai' },
  { name: 'Simon Willison', url: 'https://simonwillison.net/atom/entries/', kind: 'ai-news', stack: 'ai' },
  { name: 'Latent Space', url: 'https://www.latent.space/feed', kind: 'ai-news', stack: 'ai' },
  { name: 'TechCrunch AI', url: 'https://techcrunch.com/category/artificial-intelligence/feed/', kind: 'ai-news', stack: 'ai' },
  { name: 'Hacker News', url: 'https://hnrss.org/frontpage?points=300', kind: 'tech-news' },
];

/** GitHub Advisory Database ecosystems to poll (npm also covers Nest.js, Angular, Next.js… packages). */
export const GHSA_ECOSYSTEMS = ['npm', 'composer', 'pip'] as const;

/** NVD CPE match strings for products that aren't packages (runtimes, databases, servers, platforms). */
export const NVD_CPES: { cpe: string; stack: Stack; label: string }[] = [
  { cpe: 'cpe:2.3:a:php:php', stack: 'php', label: 'PHP' },
  { cpe: 'cpe:2.3:a:nodejs:node.js', stack: 'js', label: 'Node.js' },
  { cpe: 'cpe:2.3:a:python:python', stack: 'python', label: 'Python' },
  { cpe: 'cpe:2.3:a:mongodb:mongodb', stack: 'database', label: 'MongoDB' },
  { cpe: 'cpe:2.3:a:postgresql:postgresql', stack: 'database', label: 'PostgreSQL' },
  { cpe: 'cpe:2.3:a:oracle:mysql', stack: 'database', label: 'MySQL' },
  { cpe: 'cpe:2.3:a:oracle:mysql_server', stack: 'database', label: 'MySQL' },
  { cpe: 'cpe:2.3:a:f5:nginx', stack: 'web-server', label: 'nginx' },
  { cpe: 'cpe:2.3:a:f5:nginx_open_source', stack: 'web-server', label: 'nginx' },
  { cpe: 'cpe:2.3:a:f5:nginx_plus', stack: 'web-server', label: 'NGINX Plus' },
  { cpe: 'cpe:2.3:a:gitlab:gitlab', stack: 'devops', label: 'GitLab' },
  { cpe: 'cpe:2.3:a:github:enterprise_server', stack: 'devops', label: 'GitHub Enterprise Server' },
];

export const STACK_KEYWORDS: Record<Stack, RegExp[]> = {
  php: [
    /\bphp(?=\b|\d)/i, // also "PHP8", "PHP2Shell"
    /\blaravel\b/i,
    /\blivewire\b/i,
    /\bsymfony\b/i,
    /\bwordpress\b/i,
    /\bdrupal\b/i,
    /\bmagento\b/i,
    /\bcodeigniter\b/i,
    /\bcakephp\b/i,
    /\bguzzle\b/i,
    /\bpackagist\b/i,
  ],
  js: [
    /\bnode\.?js\b/i,
    /\bnpm\b/i,
    /\bexpress\.?js\b/i,
    /\bnest\.?js\b/i,
    /\bangular(\.?js)?\b/i,
    /\bme[ar]n stack\b/i,
    /\breact(\.?js| native| server components|-dom)\b/i,
    /\bReact\b/, // case-sensitive: avoids "investors react"
    /\bnext\.?js\b/i,
    /\bvite\b/i,
    /\bwebpack\b/i,
    /\bjavascript\b/i,
    /\btypescript\b/i,
    /\bdeno\b/i,
    /\bvue(\.?js)?\b/i,
  ],
  python: [/\bpython\b/i, /\bdjango\b/i, /\bflask\b/i, /\bfastapi\b/i, /\bpypi\b/i, /\bpip\b/],
  database: [/\bpostgres(ql)?\b/i, /\bmysql\b/i, /\bmariadb\b/i, /\bmongo(db|ose)\b/i],
  'web-server': [/\bnginx\b/i],
  devops: [/\bgithub\b/i, /\bgitlab\b/i],
  cloud: [/\baws\b/i, /\bamazon web services\b/i, /\bamazon (s3|ec2|rds)\b/i, /\bazure\b/i, /\bgoogle cloud\b/i, /\bgcp\b/i, /\bcloudflare\b/i],
  ai: [
    /\bclaude\b/i,
    /\banthropic\b/i,
    /\bopenai\b/i,
    /\bchatgpt\b/i,
    /\bgpt-\d/i,
    /\bgemini\b/i,
    /\bdeepmind\b/i,
    /\bllama\b/i,
    /\bmistral\b/i,
    /\bdeepseek\b/i,
    /\bqwen\b/i,
    /\bgrok\b/i,
    /\bLLMs?\b/,
    /\bcopilot\b/i,
    /\bCursor\b/, // case-sensitive: the editor, not a mouse cursor
    /\bcodex\b/i,
    /\bMCP\b/,
    /\bmodel context protocol\b/i,
    /\blangchain\b/i,
    /\bollama\b/i,
    /\bhugging ?face\b/i,
    /\bAI (coding )?(agent|assistant)s?\b/i,
    /\bagentic\b/i,
  ],
};

export const SIGNALS = {
  rce: /remote code execution|\bRCE\b|code injection|command injection|arbitrary code|deserializ/i,
  rceCwes: ['CWE-94', 'CWE-95', 'CWE-77', 'CWE-78', 'CWE-502'],
  exploited: /actively exploited|exploited in the wild|being exploited|\bexploitation (attempts|activity|campaign)|under active exploitation|zero[- ]day|\b0-day\b/i,
  supplyChain: /supply[- ]chain|malicious (npm |composer |pypi )?packages?|typosquat|hijacked package|compromised package|self-replicating worm/i,
  breachMalware: /\bbreach|ransomware|malware|infostealer|stealer|botnet|backdoor|data leak/i,
  security: /security|vulnerab|\bflaws?\b|\bCVE-\d{4}-\d+/i,
  release: /\breleased?\b|\bv?\d+\.\d+(\.\d+)?\b|\bannounc/i,
  /** AI posts worth more than a skim: launches, new capabilities, benchmark results. */
  aiLaunch: /\b(introduc(es|ing)|launch(es|ed|ing)?|unveil(s|ed)?|releas(es|ed|ing)|announc(es|ed|ing)|debuts?|now available|generally available|benchmarks?|SWE-bench)\b/i,
};

/** Popular packages that are critical-eligible even if the download lookup fails. */
export const MAJOR_PACKAGES = new Set([
  'express', 'react', 'react-dom', 'next', 'mongoose', 'mongodb', 'axios', 'lodash', 'vite', 'webpack',
  'jsonwebtoken', 'body-parser', 'multer', 'socket.io', 'dompurify', 'node-fetch', 'ws', 'sequelize',
  'laravel/framework', 'symfony/symfony', 'symfony/http-kernel', 'guzzlehttp/guzzle', 'livewire/livewire',
  '@nestjs/core', '@nestjs/common', '@angular/core', '@angular/common', 'pg', 'mysql2', 'mysql',
  'phpmailer/phpmailer', 'monolog/monolog', 'twig/twig', 'composer/composer',
  'django', 'flask', 'fastapi', 'requests', 'urllib3', 'jinja2', 'pydantic', 'sqlalchemy', 'pillow',
]);

export const POPULARITY = {
  /** npm and pip: weekly downloads; composer: monthly. At or above this many downloads a package counts as popular (critical-eligible). */
  popular: { npm: 50_000, composer: 50_000, pip: 50_000 },
  /** Below this many downloads an advisory is dropped as noise (unless on CISA KEV). */
  floor: { npm: 1_000, composer: 1_000, pip: 1_000 },
};

export const LIMITS = {
  /** How far back each poll looks; dedupe makes overlap harmless. */
  lookbackHours: 48,
  /** NVD results are fetched by last-modified date; ignore CVEs older than this. */
  nvdMaxAgeDays: 30,
  /** Extra critical alerts beyond this go to the digest (protects the first run). */
  maxCriticalPerRun: 5,
  /** Criticals in these categories skip the instant alert and only appear in the daily brief. */
  briefOnlyCategories: ['vuln-python'] as readonly string[],
  geminiBatchSize: 30,
  geminiMaxCallsPerRun: 3,
  seenTtlDays: 45,
  /** Days of briefs kept on the web page. */
  daysKept: 30,
  fetchTimeoutMs: 15_000,
};
