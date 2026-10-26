import { SNIPPET_MAX, truncate } from '../pipeline/normalize.js';
import type { Item } from '../types.js';
import { fetchJson } from './http.js';

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

interface KevCatalog {
  vulnerabilities: {
    cveID: string;
    vendorProject: string;
    product: string;
    vulnerabilityName: string;
    dateAdded: string;
    shortDescription: string;
    requiredAction: string;
    cwes?: string[];
  }[];
}

export function parseKev(catalog: KevCatalog, since: Date): Item[] {
  const sinceDay = since.toISOString().slice(0, 10);
  return catalog.vulnerabilities
    .filter((v) => v.dateAdded >= sinceDay)
    .map(
      (v): Item => ({
        id: v.cveID,
        aliases: [v.cveID],
        kind: 'vuln',
        kev: true,
        source: 'CISA KEV',
        title: v.vulnerabilityName,
        url: `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
        publishedAt: new Date(`${v.dateAdded}T00:00:00Z`).toISOString(),
        snippet: truncate(`${v.vendorProject} ${v.product}: ${v.shortDescription}`, SNIPPET_MAX),
        cwes: v.cwes ?? [],
      }),
    );
}

export async function fetchKev(since: Date): Promise<Item[]> {
  return parseKev(await fetchJson<KevCatalog>(KEV_URL), since);
}
