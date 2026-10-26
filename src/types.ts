export const PRIORITIES = ['critical', 'high', 'medium', 'low'] as const;
export type Priority = (typeof PRIORITIES)[number];

export const CATEGORIES = [
  'vuln-php',
  'vuln-js',
  'exploited-in-wild',
  'supply-chain',
  'breach-malware',
  'release-update',
  'tech-news',
] as const;
export type Category = (typeof CATEGORIES)[number];

export type Stack = 'php' | 'js';

/** Where a vulnerability lives. `core` = the language runtime / database itself. */
export type Ecosystem = 'npm' | 'composer' | 'php-core' | 'node-core' | 'mongodb';

/** How a news feed should be treated when scoring. */
export type FeedKind = 'security-news' | 'release' | 'dev-news' | 'tech-news';

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
  /** Stack implied by the feed itself (e.g. Laravel News → php). */
  feedStack?: Stack;
}

export interface ScoredItem extends Item {
  priority: Priority;
  category: Category;
  /** Short AI summary; falls back to the snippet when absent. */
  summary?: string;
  /** Why Gemini bumped the priority, if it did. */
  bumpReason?: string;
}
