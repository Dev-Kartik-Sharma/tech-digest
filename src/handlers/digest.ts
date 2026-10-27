import { LIMITS } from '../config/sources.js';
import { formatBrief, type SlackPayload } from '../slack/format.js';
import type { Store } from '../store/store.js';
import type { ScoredItem } from '../types.js';

/** YYYY-MM-DD in the given time zone. */
export const localDate = (d: Date, timeZone: string) => new Intl.DateTimeFormat('en-CA', { timeZone }).format(d);

export interface DigestDeps {
  store: Store;
  now?: Date;
  timeZone: string;
  /** Brief page base URL, for the Slack button. */
  siteUrl: string;
  daysKept?: number;
}

export interface DigestResult {
  date: string;
  items: ScoredItem[];
  /** The short Slack message; null on a quiet day. Posted only after the page is deployed. */
  brief: SlackPayload | null;
}

/**
 * Publishes the day: archives everything queued since the last digest as that day's brief page data,
 * and returns the short Slack message announcing it. Posting happens later, once the page is live.
 */
export async function runDigest(deps: DigestDeps): Promise<DigestResult> {
  const now = deps.now ?? new Date();
  const date = localDate(now, deps.timeZone);
  const pending = await deps.store.listPending();
  const items = pending.map((e) => e.item);

  if (items.length) {
    await deps.store.saveDay({ date, generatedAt: now.toISOString(), items });
    await deps.store.pruneDays(deps.daysKept ?? LIMITS.daysKept);
    await deps.store.deletePending(pending.map((e) => e.key));
    console.log(`digest: archived ${items.length} items for ${date}`);
  } else {
    console.log('digest: nothing pending');
  }
  // a quiet day still counts as done
  await deps.store.setLastDigestDate(date);
  return { date, items, brief: formatBrief(items, date, deps.siteUrl) };
}
