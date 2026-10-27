import { cp, mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { truncate } from '../pipeline/normalize.js';
import { CATEGORY_LABEL, fixNote } from '../slack/format.js';
import type { DayArchive } from '../store/store.js';
import { CATEGORIES, PRIORITIES, type ScoredItem } from '../types.js';

const STATIC_DIR = fileURLToPath(new URL('./static/', import.meta.url));
const ICON = fileURLToPath(new URL('../../assets/sentinel-icon.svg', import.meta.url));

/** What the page shows for one item. Kept small: the page loads a whole day at once. */
export interface PageItem {
  id: string;
  title: string;
  url?: string;
  source: string;
  publishedAt: string;
  priority: ScoredItem['priority'];
  category: ScoredItem['category'];
  summary: string;
  cvss?: number;
  kev?: boolean;
  alerted?: boolean;
  ids?: string[];
  fix?: string;
  affected?: { name: string; range?: string; patched?: string }[];
}

/** Only https links reach the page, so a feed can't smuggle in `javascript:` URLs. */
const safeUrl = (url: string) => {
  try {
    return new URL(url).protocol === 'https:' ? url : undefined;
  } catch {
    return undefined;
  }
};

export function toPageItem(i: ScoredItem): PageItem {
  const url = safeUrl(i.url);
  const ids = i.aliases.filter((a) => /^(CVE|GHSA)-/.test(a));
  const fix = fixNote(i);
  const affected = (i.packages ?? []).slice(0, 10).map((p) => ({
    name: p.name,
    ...(p.vulnerableRange ? { range: truncate(p.vulnerableRange, 300) } : {}),
    ...(p.patched ? { patched: p.patched } : {}),
  }));
  return {
    id: i.id,
    title: i.title,
    ...(url ? { url } : {}),
    source: i.source,
    publishedAt: i.publishedAt,
    priority: i.priority,
    category: i.category,
    summary: truncate(i.summary ?? i.snippet, 600),
    ...(i.cvss !== undefined ? { cvss: i.cvss } : {}),
    ...(i.kev ? { kev: true } : {}),
    ...(i.alertedAt ? { alerted: true } : {}),
    ...(ids.length ? { ids } : {}),
    ...(fix ? { fix } : {}),
    ...(affected.length ? { affected } : {}),
  };
}

const counts = (items: ScoredItem[]) =>
  Object.fromEntries(PRIORITIES.map((p) => [p, items.filter((i) => i.priority === p).length]));

/**
 * Writes the static brief site: the page (index.html, style.css, app.js, icon), `data/days.json`
 * (index of days + category labels) and `data/<date>.json` per day. The output dir is replaced.
 */
export async function buildSite(days: DayArchive[], { outDir }: { outDir: string }) {
  await rm(outDir, { recursive: true, force: true });
  await mkdir(join(outDir, 'data'), { recursive: true });
  await cp(STATIC_DIR, outDir, { recursive: true });
  await cp(ICON, join(outDir, 'icon.svg'));
  // served as-is by GitHub Pages
  await writeFile(join(outDir, '.nojekyll'), '');

  const sorted = [...days].sort((a, b) => b.date.localeCompare(a.date));
  const index = {
    days: sorted.map((d) => ({ date: d.date, generatedAt: d.generatedAt, counts: counts(d.items) })),
    categories: CATEGORIES.map((id) => ({ id, label: CATEGORY_LABEL[id] })),
  };
  await writeFile(join(outDir, 'data', 'days.json'), JSON.stringify(index));
  for (const d of sorted) {
    const page = { date: d.date, generatedAt: d.generatedAt, items: d.items.map(toPageItem) };
    await writeFile(join(outDir, 'data', `${d.date}.json`), JSON.stringify(page));
  }
}
