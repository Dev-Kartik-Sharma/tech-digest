import type { Ecosystem, FeedKind, Stack } from '../types.js';

export interface FeedSource {
  name: string;
  url: string;
  kind: FeedKind;
  /** Set when everything in the feed belongs to one stack. */
  stack?: Stack;
}

export const RSS_FEEDS: FeedSource[] = [
  { name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews', kind: 'security-news' },
  { name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/', kind: 'security-news' },
  { name: 'Node.js Security', url: 'https://nodejs.org/en/feed/vulnerability.xml', kind: 'release', stack: 'js' },
  { name: 'PHP.net', url: 'https://www.php.net/feed.atom', kind: 'release', stack: 'php' },
  { name: 'Node.js Blog', url: 'https://nodejs.org/en/feed/blog.xml', kind: 'dev-news', stack: 'js' },
  { name: 'Laravel News', url: 'https://laravel-news.com/feed', kind: 'dev-news', stack: 'php' },
  { name: 'React Blog', url: 'https://react.dev/rss.xml', kind: 'dev-news', stack: 'js' },
  { name: 'MongoDB Blog', url: 'https://www.mongodb.com/blog/rss', kind: 'dev-news', stack: 'js' },
  { name: 'Hacker News', url: 'https://hnrss.org/frontpage?points=300', kind: 'tech-news' },
];

/** GitHub Advisory Database ecosystems to poll. */
export const GHSA_ECOSYSTEMS = ['npm', 'composer'] as const;

/** NVD CPE match strings for core runtimes (CVEs not tied to a package registry). */
export const NVD_CPES: { cpe: string; ecosystem: Ecosystem }[] = [
  { cpe: 'cpe:2.3:a:php:php', ecosystem: 'php-core' },
  { cpe: 'cpe:2.3:a:nodejs:node.js', ecosystem: 'node-core' },
  { cpe: 'cpe:2.3:a:mongodb:mongodb', ecosystem: 'mongodb' },
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
    /\breact(\.?js| native| server components|-dom)\b/i,
    /\bReact\b/, // case-sensitive: avoids "investors react"
    /\bnext\.?js\b/i,
    /\bvite\b/i,
    /\bwebpack\b/i,
    /\bmongo(db|ose)\b/i,
    /\bjavascript\b/i,
    /\btypescript\b/i,
    /\bdeno\b/i,
    /\bvue(\.?js)?\b/i,
  ],
};

export const SIGNALS = {
  rce: /remote code execution|\bRCE\b|code injection|command injection|arbitrary code|deserializ/i,
  rceCwes: ['CWE-94', 'CWE-95', 'CWE-77', 'CWE-78', 'CWE-502'],
  exploited: /actively exploited|exploited in the wild|being exploited|\bexploitation (attempts|activity|campaign)|under active exploitation|zero[- ]day|\b0-day\b/i,
  supplyChain: /supply[- ]chain|malicious (npm |composer |pypi )?packages?|typosquat|hijacked package|compromised package|self-replicating worm/i,
  breachMalware: /\bbreach|ransomware|malware|infostealer|stealer|botnet|backdoor|data leak/i,
  security: /security|vulnerab|\bCVE-\d{4}-\d+/i,
  release: /\breleased?\b|\bv?\d+\.\d+(\.\d+)?\b|\bannounc/i,
};

/** Popular packages that are critical-eligible even if the download lookup fails. */
export const MAJOR_PACKAGES = new Set([
  'express', 'react', 'react-dom', 'next', 'mongoose', 'mongodb', 'axios', 'lodash', 'vite', 'webpack',
  'jsonwebtoken', 'body-parser', 'multer', 'socket.io', 'dompurify', 'node-fetch', 'ws', 'sequelize',
  'laravel/framework', 'symfony/symfony', 'symfony/http-kernel', 'guzzlehttp/guzzle', 'livewire/livewire',
  'phpmailer/phpmailer', 'monolog/monolog', 'twig/twig', 'composer/composer',
]);

export const POPULARITY = {
  /** At or above this many downloads a package counts as popular (critical-eligible). */
  popular: { npm: 50_000, composer: 50_000 },
  /** Below this many downloads an advisory is dropped as noise (unless on CISA KEV). */
  floor: { npm: 1_000, composer: 1_000 },
};

export const LIMITS = {
  /** How far back each poll looks; dedupe makes overlap harmless. */
  lookbackHours: 48,
  /** NVD results are fetched by last-modified date; ignore CVEs older than this. */
  nvdMaxAgeDays: 30,
  /** Extra critical alerts beyond this go to the digest (protects the first run). */
  maxCriticalPerRun: 5,
  geminiBatchSize: 30,
  geminiMaxCallsPerRun: 3,
  seenTtlDays: 45,
  digestCaps: { critical: 10, high: 15, medium: 10, low: 5 },
  fetchTimeoutMs: 15_000,
};
