import { GHSA_ECOSYSTEMS } from '../config/sources.js';
import { SNIPPET_MAX, stripHtml, stripMarkdown, truncate } from '../pipeline/normalize.js';
import type { AffectedPackage, Ecosystem, Item } from '../types.js';
import { fetchJsonPage } from './http.js';

interface GhsaAdvisory {
  ghsa_id: string;
  cve_id: string | null;
  html_url: string;
  summary: string;
  description: string | null;
  severity: string;
  published_at: string;
  withdrawn_at: string | null;
  cvss?: { score: number | null } | null;
  cvss_severities?: Record<string, { score: number | null } | null>;
  cwes?: { cwe_id: string }[];
  vulnerabilities?: {
    package: { ecosystem: string; name: string } | null;
    vulnerable_version_range: string | null;
    first_patched_version: string | { identifier: string } | null;
  }[];
}

const SEVERITY_FALLBACK: Record<string, number> = { critical: 9, high: 7, medium: 4, low: 1 };

function bestScore(a: GhsaAdvisory): number | undefined {
  const scores = [a.cvss?.score, ...Object.values(a.cvss_severities ?? {}).map((s) => s?.score)].filter(
    (s): s is number => typeof s === 'number' && s > 0,
  );
  return scores.length ? Math.max(...scores) : SEVERITY_FALLBACK[a.severity];
}

function packages(a: GhsaAdvisory, ecosystem: Ecosystem): AffectedPackage[] {
  const byName = new Map<string, AffectedPackage>();
  for (const v of a.vulnerabilities ?? []) {
    if (!v.package) continue;
    const patched = typeof v.first_patched_version === 'string' ? v.first_patched_version : v.first_patched_version?.identifier;
    const existing = byName.get(v.package.name);
    if (existing) {
      if (v.vulnerable_version_range) existing.vulnerableRange = [existing.vulnerableRange, v.vulnerable_version_range].filter(Boolean).join(' | ');
      if (patched) existing.patched = [existing.patched, patched].filter(Boolean).join(', ');
    } else {
      byName.set(v.package.name, {
        name: v.package.name,
        ecosystem,
        ...(v.vulnerable_version_range ? { vulnerableRange: v.vulnerable_version_range } : {}),
        ...(patched ? { patched } : {}),
      });
    }
  }
  return [...byName.values()];
}

export function parseGhsa(advisories: GhsaAdvisory[]): Item[] {
  return advisories
    .filter((a) => !a.withdrawn_at)
    .map((a): Item => {
      const ecosystem: Ecosystem = a.vulnerabilities?.[0]?.package?.ecosystem === 'composer' ? 'composer' : 'npm';
      const cvss = bestScore(a);
      return {
        id: a.cve_id ?? a.ghsa_id,
        aliases: [a.cve_id, a.ghsa_id].filter((x): x is string => !!x),
        kind: 'vuln',
        source: 'GitHub Advisories',
        title: a.summary,
        url: a.html_url,
        publishedAt: a.published_at,
        snippet: truncate(stripHtml(stripMarkdown(a.description ?? '')), SNIPPET_MAX),
        ecosystem,
        packages: packages(a, ecosystem),
        cwes: a.cwes?.map((c) => c.cwe_id) ?? [],
        ...(cvss !== undefined ? { cvss } : {}),
      };
    });
}

const MAX_PAGES = 5;

export function nextLink(header: string | null): string | undefined {
  return header?.split(',').map((part) => /<([^>]+)>;\s*rel="next"/.exec(part)?.[1]).find(Boolean);
}

const ghsaHeaders = (token?: string): Record<string, string> => ({
  Accept: 'application/vnd.github+json',
  'X-GitHub-Api-Version': '2022-11-28',
  ...(token ? { Authorization: `Bearer ${token}` } : {}),
});

export async function fetchGhsa(since: Date, token?: string): Promise<Item[]> {
  const day = since.toISOString().slice(0, 10);
  const items: Item[] = [];
  for (const eco of GHSA_ECOSYSTEMS) {
    // the API paginates with an `after` cursor in the Link header (`page=` is ignored)
    let url: string | undefined =
      `https://api.github.com/advisories?type=reviewed&ecosystem=${eco}&per_page=100` +
      `&sort=published&direction=desc&published=${encodeURIComponent(`>=${day}`)}`;
    for (let page = 0; url && page < MAX_PAGES; page++) {
      const res: { data: GhsaAdvisory[]; link: string | null } = await fetchJsonPage<GhsaAdvisory[]>(url, ghsaHeaders(token));
      items.push(...parseGhsa(res.data).filter((i) => new Date(i.publishedAt) >= since));
      url = nextLink(res.link);
    }
  }
  return items;
}

/** Package advisories for one CVE, in the ecosystems we watch, regardless of publish date. */
export async function fetchGhsaByCve(cve: string, token?: string): Promise<Item[]> {
  const { data } = await fetchJsonPage<GhsaAdvisory[]>(
    `https://api.github.com/advisories?type=reviewed&cve_id=${encodeURIComponent(cve)}`,
    ghsaHeaders(token),
  );
  return parseGhsa(data.filter((a) => a.vulnerabilities?.some((v) => GHSA_ECOSYSTEMS.includes(v.package?.ecosystem as never))));
}

/**
 * CISA usually adds a CVE to KEV weeks after its package advisory was published, and the KEV text
 * rarely names the ecosystem (e.g. "Strapi Strapi"). Fetching the GHSA advisory by CVE gives the
 * merged item its ecosystem, packages and popularity, so stack detection doesn't depend on keywords.
 */
export async function ghsaForKev(
  kev: Item[],
  coveredCves: Set<string>,
  lookup: (cve: string) => Promise<Item[]>,
): Promise<Item[]> {
  const found: Item[] = [];
  for (const item of kev.filter((k) => !coveredCves.has(k.id))) {
    try {
      found.push(...(await lookup(item.id)));
    } catch (err) {
      console.warn(`GHSA lookup for ${item.id} failed: ${(err as Error).message}`);
    }
  }
  return found;
}
