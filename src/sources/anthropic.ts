import { AI_SNIPPET_MAX, stripHtml, toIso, truncate, urlId } from '../pipeline/normalize.js';
import type { Item } from '../types.js';
import { fetchText } from './http.js';

/**
 * Anthropic publishes no RSS feed, so new posts are found through the sitemap (which has
 * last-modified times) and each new page's JSON-LD article data.
 */
const SITEMAP_URL = 'https://www.anthropic.com/sitemap.xml';
const SECTION = '/news/';
/** Pages are fetched individually, so only look at recent changes and cap how many. */
const WINDOW_HOURS = 12;
const MAX_PAGES = 8;

export function parseSitemap(xml: string, section: string, since: Date): string[] {
  const out: string[] = [];
  for (const [, entry] of xml.matchAll(/<url>([\s\S]*?)<\/url>/g)) {
    const loc = /<loc>([^<]+)<\/loc>/.exec(entry!)?.[1]?.trim();
    const lastmod = /<lastmod>([^<]+)<\/lastmod>/.exec(entry!)?.[1]?.trim();
    if (!loc || !lastmod || !new URL(loc).pathname.startsWith(section)) continue;
    if (new Date(lastmod) >= since) out.push(loc);
  }
  return out;
}

interface ArticleData {
  headline?: string;
  description?: string;
  datePublished?: string;
}

export function parseArticle(html: string): { title: string; publishedAt: string; text: string } | undefined {
  let article: ArticleData | undefined;
  for (const [, json] of html.matchAll(/<script[^>]+type="application\/ld\+json"[^>]*>([\s\S]*?)<\/script>/g)) {
    try {
      const data = JSON.parse(json!) as ArticleData | ArticleData[];
      article = (Array.isArray(data) ? data : [data]).find((d) => d.headline);
      if (article) break;
    } catch {
      // ignore malformed blocks
    }
  }
  if (!article?.headline) return undefined;

  // body paragraphs; `<p(\s…)?>` so <path>/<picture> don't match
  const scope = /<article[\s\S]*?<\/article>/.exec(html)?.[0] ?? html;
  const paragraphs = [...scope.matchAll(/<p(?:\s[^>]*)?>([\s\S]*?)<\/p>/g)]
    .map(([, p]) => stripHtml(p!))
    .filter((p) => p.length > 40 && !p.startsWith('Skip to'));
  // posts usually open by restating the description ("Today, we're …"); don't repeat it
  const words = (t: string) => t.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
  const probe = words(article.description ?? '').split(' ').slice(0, 6).join(' ');
  const body = probe ? paragraphs.filter((p) => !words(p).includes(probe)) : paragraphs;
  const text = [article.description?.trim(), ...body].filter(Boolean).join(' ');
  return {
    title: stripHtml(article.headline),
    publishedAt: toIso(article.datePublished),
    text: truncate(text, AI_SNIPPET_MAX),
  };
}

export async function fetchAnthropic(since: Date): Promise<Item[]> {
  const windowStart = new Date(Math.max(since.getTime(), Date.now() - WINDOW_HOURS * 3_600_000));
  const urls = parseSitemap(await fetchText(SITEMAP_URL), SECTION, windowStart).slice(0, MAX_PAGES);
  const items: Item[] = [];
  for (const url of urls) {
    try {
      const article = parseArticle(await fetchText(url));
      // datePublished is a date at midnight, so allow a day of slack; edits to old posts are skipped
      if (!article || new Date(article.publishedAt).getTime() < since.getTime() - 86_400_000) continue;
      const id = urlId(url);
      items.push({
        id,
        aliases: [id],
        kind: 'news',
        source: 'Anthropic',
        title: article.title,
        url,
        publishedAt: article.publishedAt,
        snippet: article.text,
        feedKind: 'ai-news',
        stackHint: 'ai',
      });
    } catch (err) {
      console.warn(`Anthropic page ${url} failed: ${(err as Error).message}`);
    }
  }
  return items;
}
