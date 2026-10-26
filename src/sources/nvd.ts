import { LIMITS, NVD_CPES } from '../config/sources.js';
import { SNIPPET_MAX, truncate } from '../pipeline/normalize.js';
import type { Item, Stack } from '../types.js';
import { fetchJson } from './http.js';

interface NvdResponse {
  vulnerabilities: {
    cve: {
      id: string;
      published: string;
      vulnStatus?: string;
      descriptions: { lang: string; value: string }[];
      metrics?: Record<string, { cvssData?: { baseScore?: number } }[]>;
      weaknesses?: { description: { value: string }[] }[];
    };
  }[];
}

export function parseNvd(res: NvdResponse, product: { stack: Stack; label: string }): Item[] {
  return res.vulnerabilities
    .filter(({ cve }) => cve.vulnStatus !== 'Rejected')
    .map(({ cve }): Item => {
      const scores = Object.entries(cve.metrics ?? {})
        .filter(([k]) => k.startsWith('cvssMetric'))
        .flatMap(([, list]) => list.map((m) => m.cvssData?.baseScore))
        .filter((s): s is number => typeof s === 'number');
      const description = cve.descriptions.find((d) => d.lang === 'en')?.value ?? '';
      // NVD timestamps have no zone suffix but are UTC
      const published = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(cve.published) ? cve.published : `${cve.published}Z`);
      return {
        id: cve.id,
        aliases: [cve.id],
        kind: 'vuln',
        source: 'NVD',
        title: `${cve.id} in ${product.label}`,
        url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
        publishedAt: published.toISOString(),
        snippet: truncate(description, SNIPPET_MAX),
        ecosystem: 'core',
        stackHint: product.stack,
        cwes: [...new Set(cve.weaknesses?.flatMap((w) => w.description.map((d) => d.value)) ?? [])],
        ...(scores.length ? { cvss: Math.max(...scores) } : {}),
      };
    });
}

const fmt = (d: Date) => d.toISOString().replace(/Z$/, '').replace(/(\.\d{3})?$/, '.000') + 'Z';

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Queried by last-modified date so CVEs show up once NVD attaches the CPE (often days after
 * publication); CVEs published more than `nvdMaxAgeDays` ago are ignored.
 */
export async function fetchNvd(since: Date, apiKey?: string): Promise<Item[]> {
  const now = new Date();
  const minPublished = new Date(now.getTime() - LIMITS.nvdMaxAgeDays * 86_400_000);
  const items: Item[] = [];
  const failures: string[] = [];
  for (const [i, { cpe, ...product }] of NVD_CPES.entries()) {
    // without an API key NVD allows 5 requests / 30s
    if (i > 0 && !apiKey) await pause(6_500);
    const url =
      `https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=${encodeURIComponent(cpe)}` +
      `&lastModStartDate=${fmt(since)}&lastModEndDate=${fmt(now)}`;
    try {
      const res = await fetchJson<NvdResponse>(url, apiKey ? { apiKey } : {});
      items.push(...parseNvd(res, product).filter((it) => new Date(it.publishedAt) >= minPublished));
    } catch (err) {
      // one product failing shouldn't drop the others
      failures.push(`${product.label}: ${(err as Error).message}`);
    }
  }
  if (failures.length === NVD_CPES.length) throw new Error(`all NVD queries failed: ${failures[0]}`);
  if (failures.length) console.warn(`NVD: ${failures.length} queries failed: ${failures.join('; ')}`);
  return items;
}
