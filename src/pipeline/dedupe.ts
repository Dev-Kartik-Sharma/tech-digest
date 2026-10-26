import type { Item, Priority, ScoredItem } from '../types.js';

/** Lower = preferred as the base of a merged item (richest data first). */
const SOURCE_RANK: Record<string, number> = { 'GitHub Advisories': 0, 'NVD': 1, 'CISA KEV': 2 };
const rank = (i: Item) => (i.kind === 'vuln' ? (SOURCE_RANK[i.source] ?? 3) : 10);

function merge(group: Item[]): Item {
  const [first, ...rest] = [...group].sort((a, b) => rank(a) - rank(b));
  const merged: Item = { ...first!, aliases: [...first!.aliases] };
  for (const other of rest) {
    merged.aliases.push(...other.aliases);
    if (other.kev) merged.kev = true;
    if (other.cvss !== undefined && (merged.cvss === undefined || other.cvss > merged.cvss)) merged.cvss = other.cvss;
    merged.ecosystem ??= other.ecosystem;
    if (!merged.packages?.length && other.packages?.length) merged.packages = other.packages;
    if (other.cwes?.length) merged.cwes = [...new Set([...(merged.cwes ?? []), ...other.cwes])];
    if (!merged.snippet) merged.snippet = other.snippet;
  }
  merged.aliases = [...new Set(merged.aliases)];
  merged.id = merged.aliases.find((a) => a.startsWith('CVE-')) ?? merged.id;
  return merged;
}

/** Groups items sharing any alias (CVE, GHSA, URL id) and merges each group into one item. */
export function mergeDuplicates(items: Item[]): Item[] {
  const parent = items.map((_, i) => i);
  const find = (i: number): number => (parent[i] === i ? i : (parent[i] = find(parent[i]!)));
  const owner = new Map<string, number>();
  items.forEach((item, i) => {
    for (const alias of item.aliases) {
      const j = owner.get(alias);
      if (j === undefined) owner.set(alias, i);
      else parent[find(i)] = find(j);
    }
  });
  const groups = new Map<number, Item[]>();
  items.forEach((item, i) => {
    const root = find(i);
    groups.set(root, [...(groups.get(root) ?? []), item]);
  });
  const merged = [...groups.values()].map(merge);

  // A news article about a CVE we already have folds into that vulnerability (its URL id becomes an
  // alias, so it isn't posted separately later). Mentions never link two vulnerabilities together.
  const vulnByAlias = new Map<string, Item>();
  for (const v of merged) if (v.kind === 'vuln') for (const a of v.aliases) vulnByAlias.set(a, v);
  return merged.filter((item) => {
    if (item.kind !== 'news' || !item.mentions?.length) return true;
    const targets = new Set(item.mentions.map((m) => vulnByAlias.get(m)).filter((v): v is Item => !!v));
    for (const v of targets) v.aliases.push(...item.aliases.filter((a) => !v.aliases.includes(a)));
    return targets.size === 0;
  });
}

/**
 * `seen` maps every alias already handled to the priority it was handled at.
 * Unseen → fresh. Seen but now critical when it wasn't before (e.g. newly added to KEV) → escalated.
 */
export function splitBySeen(items: ScoredItem[], seen: Map<string, Priority>) {
  const fresh: ScoredItem[] = [];
  const escalated: ScoredItem[] = [];
  for (const item of items) {
    const previous = item.aliases.map((a) => seen.get(a)).filter((p): p is Priority => !!p);
    if (!previous.length) fresh.push(item);
    else if (item.priority === 'critical' && !previous.includes('critical')) escalated.push(item);
  }
  return { fresh, escalated };
}
