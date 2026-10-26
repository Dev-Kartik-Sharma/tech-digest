import { RSS_FEEDS } from '../config/sources.js';
import type { Item } from '../types.js';
import { fetchKev } from './cisa-kev.js';
import { fetchGhsa, fetchGhsaByCve, ghsaForKev } from './github-advisories.js';
import { fetchNvd } from './nvd.js';
import { fetchFeed } from './rss.js';

export interface SourceKeys {
  githubToken?: string;
  nvdApiKey?: string;
}

/** Fetches every source in parallel; a failing source is logged and skipped. */
export async function fetchAll(since: Date, keys: SourceKeys = {}): Promise<Item[]> {
  const jobs: [string, Promise<Item[]>][] = [
    ['GitHub Advisories', fetchGhsa(since, keys.githubToken)],
    ['NVD', fetchNvd(since, keys.nvdApiKey)],
    ['CISA KEV', fetchKev(since)],
    ...RSS_FEEDS.map((f): [string, Promise<Item[]>] => [f.name, fetchFeed(f, since)]),
  ];
  const results = await Promise.allSettled(jobs.map(([, p]) => p));
  const items = results.flatMap((r, i) => {
    const name = jobs[i]![0];
    if (r.status === 'fulfilled') {
      console.log(`source ${name}: ${r.value.length} items`);
      return r.value;
    }
    console.warn(`source ${name} failed: ${(r.reason as Error).message}`);
    return [];
  });

  const ghsaCves = new Set(items.filter((i) => i.source === 'GitHub Advisories').flatMap((i) => i.aliases));
  const kev = items.filter((i) => i.source === 'CISA KEV');
  return [...items, ...(await ghsaForKev(kev, ghsaCves, (cve) => fetchGhsaByCve(cve, keys.githubToken)))];
}
