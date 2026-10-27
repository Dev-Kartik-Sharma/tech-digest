export const PRIORITIES = ['critical', 'high', 'medium', 'low'] as const;
export type Priority = (typeof PRIORITIES)[number];

/** Tech areas the team cares about, in detection order (first keyword match wins). */
export const STACKS = ['php', 'js', 'python', 'database', 'web-server', 'devops', 'cloud', 'ai'] as const;
export type Stack = (typeof STACKS)[number];

export const CATEGORIES = [
  'vuln-php',
  'vuln-js',
  'vuln-python',
  'vuln-database',
  'vuln-web-server',
  'vuln-devops',
  'vuln-cloud',
  'vuln-ai',
  'exploited-in-wild',
  'supply-chain',
  'breach-malware',
  'ai-update',
  'release-update',
  'tech-news',
] as const;
export type Category = (typeof CATEGORIES)[number];

/** Where a vulnerability lives: a package registry, or `core` = the product itself (PHP, nginx, MySQL…). */
export type Ecosystem = 'npm' | 'composer' | 'pip' | 'core';

/** How a news feed should be treated when scoring. */
export type FeedKind = 'security-news' | 'release' | 'dev-news' | 'ai-news' | 'tech-news';

export interface AffectedPackage {
  name: string;
  ecosystem: Ecosystem;
  vulnerableRange?: string;
  patched?: string;
}

/** A normalized item from any source, before scoring. */
export interface Item {
  /** Canonical id: CVE id when known, else GHSA id, else a hash of the URL. */
  id: string;
  /** Every id this item is known by (including `id`); used for cross-source dedupe. */
  aliases: string[];
  kind: 'vuln' | 'news';
  source: string;
  title: string;
  url: string;
  publishedAt: string;
  snippet: string;

  // vuln-only
  cvss?: number;
  kev?: boolean;
  ecosystem?: Ecosystem;
  packages?: AffectedPackage[];
  cwes?: string[];
  /** Weekly (npm) / monthly (packagist) downloads of the most popular affected package. */
  downloads?: number;

  // news-only
  feedKind?: FeedKind;
  /** CVE ids the article mentions. Not identity aliases: one article can cover several CVEs. */
  mentions?: string[];
  /** Tech area implied by the source: a single-topic feed (Laravel News → php) or an NVD product (nginx → web-server). */
  stackHint?: Stack;
}

export interface ScoredItem extends Item {
  priority: Priority;
  category: Category;
  /** Short AI summary; falls back to the snippet when absent. */
  summary?: string;
  /** Why Gemini bumped the priority, if it did. */
  bumpReason?: string;
  /** When the instant Slack alert went out (criticals only); the daily brief doesn't repeat these. */
  alertedAt?: string;
}
