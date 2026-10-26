import Parser from 'rss-parser';
import type { FeedSource } from '../config/sources.js';
import { extractCves, SNIPPET_MAX, stripHtml, toIso, truncate, urlId } from '../pipeline/normalize.js';
import type { Item } from '../types.js';
import { fetchText } from './http.js';

const parser = new Parser();

/** hnrss.org descriptions are just links and counters. */
const HN_BOILERPLATE = /(Article URL|Comments URL):\s*\S+|Points:\s*\d+|#\s*Comments:\s*\d+/g;

export async function parseFeed(xml: string, feed: FeedSource): Promise<Item[]> {
  const parsed = await parser.parseString(xml);
  return parsed.items
    .filter((e) => e.link && e.title)
    .map((e): Item => {
      const url = e.link!;
      const title = stripHtml(e.title!);
      const snippet = truncate(
        stripHtml(e.contentSnippet ?? e.summary ?? e.content ?? '').replace(HN_BOILERPLATE, '').trim(),
        SNIPPET_MAX,
      );
      const id = urlId(url);
      const mentions = extractCves(`${title} ${snippet}`);
      return {
        id,
        aliases: [id],
        ...(mentions.length ? { mentions } : {}),
        kind: 'news',
        source: feed.name,
        title,
        url,
        publishedAt: toIso(e.isoDate ?? e.pubDate),
        snippet,
        feedKind: feed.kind,
        ...(feed.stack ? { stackHint: feed.stack } : {}),
      };
    });
}

export async function fetchFeed(feed: FeedSource, since: Date): Promise<Item[]> {
  const items = await parseFeed(await fetchText(feed.url), feed);
  return items.filter((i) => new Date(i.publishedAt) >= since);
}
