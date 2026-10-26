import { fetchJson } from '../sources/http.js';
import type { AffectedPackage, Item } from '../types.js';

export type DownloadLookup = (name: string, ecosystem: AffectedPackage['ecosystem']) => Promise<number | undefined>;

/** npm: weekly downloads. Packagist: monthly downloads. */
export const registryDownloads: DownloadLookup = async (name, ecosystem) => {
  if (ecosystem === 'npm') {
    const res = await fetchJson<{ downloads?: number }>(`https://api.npmjs.org/downloads/point/last-week/${name}`);
    return res.downloads;
  }
  if (ecosystem === 'composer') {
    const res = await fetchJson<{ package?: { downloads?: { monthly?: number } } }>(
      `https://packagist.org/packages/${name}.json`,
    );
    return res.package?.downloads?.monthly;
  }
  return undefined;
};

const CONCURRENCY = 5;

export async function addDownloads(items: Item[], lookup: DownloadLookup = registryDownloads): Promise<Item[]> {
  const pkgs = new Map<string, AffectedPackage>();
  for (const p of items.flatMap((i) => i.packages ?? [])) pkgs.set(`${p.ecosystem}:${p.name}`, p);

  const counts = new Map<string, number>();
  const queue = [...pkgs.entries()];
  await Promise.all(
    Array.from({ length: CONCURRENCY }, async () => {
      for (let next = queue.shift(); next; next = queue.shift()) {
        const [key, p] = next;
        try {
          const n = await lookup(p.name, p.ecosystem);
          if (typeof n === 'number') counts.set(key, n);
        } catch {
          // unknown popularity is handled by the scorer (MAJOR_PACKAGES fallback)
        }
      }
    }),
  );

  return items.map((item) => {
    const known = (item.packages ?? [])
      .map((p) => counts.get(`${p.ecosystem}:${p.name}`))
      .filter((n): n is number => n !== undefined);
    return known.length ? { ...item, downloads: Math.max(...known) } : item;
  });
}
