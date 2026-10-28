import type { Category, FeedKind, Stack } from '../types.js';

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
  // AI coding tools the team works with
  { name: 'GitHub Copilot changelog', url: 'https://github.blog/changelog/label/copilot/feed/', kind: 'ai-news', stack: 'ai' },
  { name: 'Cursor changelog', url: 'https://cursor.com/changelog/rss.xml', kind: 'ai-news', stack: 'ai' },
  // AI security research (prompt injection, agent and MCP attacks)
  { name: 'Embrace The Red', url: 'https://embracethered.com/blog/index.xml', kind: 'security-news', stack: 'ai' },
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
  { cpe: 'cpe:2.3:a:mariadb:mariadb', stack: 'database', label: 'MariaDB' },
  { cpe: 'cpe:2.3:a:redis:redis', stack: 'database', label: 'Redis' },
  { cpe: 'cpe:2.3:a:sqlite:sqlite', stack: 'database', label: 'SQLite' },
  { cpe: 'cpe:2.3:a:f5:nginx', stack: 'web-server', label: 'nginx' },
  { cpe: 'cpe:2.3:a:f5:nginx_open_source', stack: 'web-server', label: 'nginx' },
  { cpe: 'cpe:2.3:a:f5:nginx_plus', stack: 'web-server', label: 'NGINX Plus' },
  { cpe: 'cpe:2.3:a:gitlab:gitlab', stack: 'devops', label: 'GitLab' },
  { cpe: 'cpe:2.3:a:github:enterprise_server', stack: 'devops', label: 'GitHub Enterprise Server' },
  { cpe: 'cpe:2.3:a:kubernetes:kubernetes', stack: 'devops', label: 'Kubernetes' },
  { cpe: 'cpe:2.3:a:linuxfoundation:runc', stack: 'devops', label: 'runc' },
  { cpe: 'cpe:2.3:a:mobyproject:moby', stack: 'devops', label: 'Docker Engine' },
  { cpe: 'cpe:2.3:a:docker:desktop', stack: 'devops', label: 'Docker Desktop' },
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
  database: [/\bpostgres(ql)?\b/i, /\bmysql\b/i, /\bmariadb\b/i, /\bmongo(db|ose)\b/i, /\bredis\b/i, /\bsqlite\d?\b/i],
  'web-server': [/\bnginx\b/i],
  // providers whose API keys and SDKs live in our apps: email, SMS, payments, sign-in
  services: [
    /\bsendgrid\b/i,
    /\btwilio\b/i,
    /\bmailchimp\b/i,
    /\bmandrill\b/i,
    /\bmailgun\b/i,
    /\bPostmark\b/, // case-sensitive: not the postal mark
    /\bstripe\b/i,
    /\bpaypal\b/i,
    /\brazorpay\b/i,
    /\bbraintree\b/i,
    /\bauth0\b/i,
    /\bokta\b/i,
    /\bgoogle (oauth|sign[- ]in|login|auth(entication)?|identity)\b/i,
    /\bfirebase\b/i,
    /\bSentry\b/, // case-sensitive: the error tracker
    /\balgolia\b/i,
    /\bcloudinary\b/i,
  ],
  // "Infrastructure": code hosting and CI, containers, and app hosting platforms
  devops: [
    /\bgithub\b/i,
    /\bgitlab\b/i,
    /\bdocker\b/i,
    /\bkubernetes\b/i,
    /\bk8s\b/i,
    /\bcontainerd\b/i,
    /\brunc\b/i,
    /\bvercel\b/i,
    /\bnetlify\b/i,
    /\bsupabase\b/i,
    /\bheroku\b/i,
    /\bcloudflare\b/i,
  ],
  cloud: [/\baws\b/i, /\bamazon web services\b/i, /\bamazon (s3|ec2|rds)\b/i, /\bazure\b/i, /\bgoogle cloud\b/i, /\bgcp\b/i],
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
  supplyChain:
    /supply[- ]chain|malicious (npm |composer |pypi )?packages?|typosquat|slopsquat|hijacked package|compromised package|self-replicating worm|malicious (MCP|VS ?Code|IDE|browser|Cursor) (servers?|extensions?|plugins?)|poisoned (extensions?|packages?|models?)|\b(npm|pypi|composer|packagist) (packages?|librar(y|ies)|maintainers?)\b.{0,40}\b(compromised|hijacked|backdoored)/i,
  /** A real package or maintainer taken over (not just a typosquat): critical in the focus stacks. */
  compromised:
    /\b(packages?|maintainers?|accounts?|librar(y|ies)|extensions?)( (?!that\b|which\b|to\b)[\w@/.-]+)? (was |were |got |been |is |has )*(compromised|hijacked|backdoored)|\b(compromised|hijacked|backdoored) (popular |npm |pypi |composer )*(packages?|maintainers?|accounts?|librar(y|ies)|extensions?)|self-replicating|\bworms?\b/i,
  breachMalware: /\bbreach|ransomware|malware|infostealer|stealer|botnet|backdoor|data leak/i,
  security: /security|vulnerab|\bflaws?\b|\bCVE-\d{4}-\d+/i,
  release: /\breleased?\b|\bv?\d+\.\d+(\.\d+)?\b|\bannounc/i,
  /** AI posts worth more than a skim: launches, new capabilities, benchmark results. */
  /** Attacks on AI tools and agents. */
  aiSecurity: /prompt[- ]injection|jailbreak|tool[- ]poisoning|exfiltrat|(sandbox|vm|container) (escape|bypass)|\bvm escapes?\b|guardrail bypass/i,
  /** AI coding tools and workflows the team uses: updates to these are worth a look even without launch words. */
  aiDevTools: [
    /\b(claude code|copilot|codex|windsurf|gemini cli|model context protocol|agent sdk|coding agents?|ai[- ]assisted|vibe coding|agentic)\b/i,
    /\b(Cursor|MCP|IDE)\b/, // case-sensitive
  ],
  aiLaunch: /\b(introduc(es|ing)|launch(es|ed|ing)?|unveil(s|ed)?|releas(es|ed|ing)|announc(es|ed|ing)|debuts?|now available|generally available|benchmarks?|SWE-bench)\b/i,
};

/** AI SDKs and agent tooling: their advisories are filed as AI security, not under the language. Lower-case. */
export const AI_PACKAGES = new Set([
  '@modelcontextprotocol/sdk', '@anthropic-ai/sdk', '@anthropic-ai/claude-code', '@anthropic-ai/claude-agent-sdk', 'openai', 'ai',
  'langchain', '@langchain/core', 'llamaindex', '@google/genai', '@openai/codex',
  'anthropic', 'langchain-core', 'llama-index', 'mcp', 'litellm', 'transformers', 'claude-agent-sdk',
  'openai-php/client', 'openai-php/laravel', 'prism-php/prism', 'anthropic-ai/sdk',
]);

/** Categories where a critical always goes to Slack instantly (the AI can't hold it back). */
export const FOCUS_CATEGORIES: readonly Category[] = ['vuln-php', 'vuln-js', 'vuln-ai', 'ai-update', 'supply-chain'];

/** Popular packages that are critical-eligible even if the download lookup fails. Lower-case: matched case-insensitively. */
export const MAJOR_PACKAGES = new Set([
  ...AI_PACKAGES,
  'express', 'react', 'react-dom', 'next', 'mongoose', 'mongodb', 'axios', 'lodash', 'vite', 'webpack',
  'jsonwebtoken', 'body-parser', 'multer', 'socket.io', 'dompurify', 'node-fetch', 'ws', 'sequelize',
  'laravel/framework', 'symfony/symfony', 'symfony/http-kernel', 'guzzlehttp/guzzle', 'livewire/livewire',
  '@nestjs/core', '@nestjs/common', '@angular/core', '@angular/common', 'pg', 'mysql2', 'mysql',
  'phpmailer/phpmailer', 'monolog/monolog', 'twig/twig', 'composer/composer',
  'django', 'flask', 'fastapi', 'requests', 'urllib3', 'jinja2', 'pydantic', 'sqlalchemy', 'pillow',
  // database clients
  'redis', 'ioredis', 'sqlite3', 'better-sqlite3', 'mariadb', 'predis/predis',
  // third-party service SDKs, auth and email
  '@sendgrid/mail', '@sendgrid/client', 'twilio', '@mailchimp/mailchimp_marketing', '@mailchimp/mailchimp_transactional',
  'mailgun.js', 'stripe', 'razorpay', 'google-auth-library', 'googleapis', 'firebase', 'firebase-admin',
  'passport', 'passport-google-oauth20', 'next-auth', '@auth/core', 'jose', 'nodemailer', 'aws-sdk',
  '@aws-sdk/client-s3', '@sentry/node',
  'sendgrid/sendgrid', 'twilio/sdk', 'mailchimp/marketing', 'stripe/stripe-php', 'razorpay/razorpay',
  'google/apiclient', 'google/auth', 'aws/aws-sdk-php', 'firebase/php-jwt', 'kreait/firebase-php',
  'league/oauth2-client', 'laravel/socialite', 'laravel/passport', 'sentry/sentry',
  'sendgrid', 'google-auth', 'boto3', 'pyjwt', 'authlib',
  // containers and hosting platforms
  '@supabase/supabase-js', 'wrangler', 'vercel', '@kubernetes/client-node', 'dockerode', 'docker', 'kubernetes', 'supabase',
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
