import { LIMITS } from '../config/sources.js';
import { mergeDuplicates, splitBySeen } from '../pipeline/dedupe.js';
import { enrichWithGemini, type Generate } from '../pipeline/enrich-gemini.js';
import { addDownloads, type DownloadLookup } from '../pipeline/popularity.js';
import { scoreItem } from '../pipeline/score.js';
import { formatCritical, type SlackPayload } from '../slack/format.js';
import { SlackError } from '../slack/post.js';
import type { Store } from '../store/store.js';
import { PRIORITIES, type Item, type Priority, type ScoredItem } from '../types.js';

export interface PollDeps {
  fetchAll: (since: Date) => Promise<Item[]>;
  lookupDownloads?: DownloadLookup;
  /** Omit to skip AI enrichment. */
  generate?: Generate;
  store: Store;
  post: (payload: SlackPayload) => Promise<void>;
  now?: Date;
  /** Brief page, linked from critical alerts. */
  siteUrl?: string;
}

const highest = (ps: (Priority | undefined)[]): Priority =>
  PRIORITIES.find((p) => ps.includes(p)) ?? 'low';

export async function runPoll(deps: PollDeps) {
  const now = deps.now ?? new Date();
  const since = new Date(now.getTime() - LIMITS.lookbackHours * 3_600_000);

  const raw = await deps.fetchAll(since);
  const merged = mergeDuplicates(raw);
  const seen = await deps.store.getSeen(merged.flatMap((i) => i.aliases));
  const isSeen = (i: Item) => i.aliases.some((a) => seen.has(a));

  // popularity is looked up once, on first sight: re-checking seen items every poll would let a
  // flaky registry flip their score (and fake an escalation)
  const withDownloads = new Map((await addDownloads(merged.filter((i) => !isSeen(i)), deps.lookupDownloads)).map((i) => [i.id, i]));
  const prepared = merged.map((i) => withDownloads.get(i.id) ?? i);

  const scored: ScoredItem[] = [];
  const dropped: Item[] = [];
  for (const item of prepared) {
    const s = scoreItem(item);
    if (s) scored.push(s);
    else dropped.push(item);
  }

  const { fresh, escalated } = splitBySeen(scored, seen);
  const escalatedIds = new Set(escalated.map((i) => i.id));

  const toEnrich = [...fresh, ...escalated];
  const enriched = deps.generate && toEnrich.length ? await enrichWithGemini(toEnrich, deps.generate) : toEnrich;

  const criticals = enriched
    .filter((i) => i.priority === 'critical' && !i.holdReason && !LIMITS.briefOnlyCategories.includes(i.category))
    .sort((a, b) => Number(escalatedIds.has(b.id)) - Number(escalatedIds.has(a.id)) || (b.cvss ?? 0) - (a.cvss ?? 0));
  const toAlert = criticals.slice(0, LIMITS.maxCriticalPerRun);
  const alertIds = new Set(toAlert.map((i) => i.id));

  const failed = new Set<string>();
  const rejected = new Set<string>();
  for (const item of toAlert) {
    try {
      await deps.post(
        formatCritical(item, { escalated: escalatedIds.has(item.id), ...(deps.siteUrl ? { siteUrl: deps.siteUrl } : {}) }),
      );
      // record each alert immediately so nothing after this point can cause a duplicate
      await deps.store.markSeen([item]);
    } catch (err) {
      if (err instanceof SlackError && err.status === 400) {
        // Slack will never accept this payload; retrying every poll would just lose it, so digest it
        rejected.add(item.id);
        console.error(`alert for ${item.id} rejected by Slack, sending it to the digest: ${err.message}`);
      } else {
        failed.add(item.id);
        console.error(`alert for ${item.id} failed, will retry next run: ${(err as Error).message}`);
      }
    }
  }

  // Not handled this run, so left out of state and retried next poll: failed alerts, and
  // escalations beyond the per-run cap (they keep their old seen record).
  const retryLater = (i: ScoredItem) => failed.has(i.id) || (criticals.includes(i) && escalatedIds.has(i.id) && !alertIds.has(i.id));

  // Everything goes in the day's record for the brief page; alerted items are marked so the Slack
  // brief doesn't repeat them. Escalations were in an earlier day's record already.
  const alerted = new Set(toAlert.filter((i) => !failed.has(i.id) && !rejected.has(i.id)).map((i) => i.id));
  const alertedAt = now.toISOString();
  await deps.store.addPending(
    enriched
      .filter((i) => !retryLater(i) && !(escalatedIds.has(i.id) && alerted.has(i.id)))
      .map((i) => (alerted.has(i.id) ? { ...i, alertedAt } : i)),
  );

  const enrichedById = new Map(enriched.map((i) => [i.id, i]));
  await deps.store.markSeen([
    // the pre-enrichment set, so news Gemini dropped isn't sent to Gemini again
    ...toEnrich.filter((i) => !retryLater(i)).map((i) => enrichedById.get(i.id) ?? i),
    // items the rules dropped: remembered at low, so a later KEV listing still escalates them
    ...dropped.filter((i) => !isSeen(i)).map((i) => ({ aliases: i.aliases, priority: 'low' as const })),
    // aliases learned since an item was first seen (e.g. a CVE id assigned later), recorded at the
    // highest priority already handled so they can't trigger a duplicate alert or a false escalation
    ...prepared
      .filter((i) => isSeen(i) && !escalatedIds.has(i.id) && i.aliases.some((a) => !seen.has(a)))
      .map((i) => ({ aliases: i.aliases, priority: highest(i.aliases.map((a) => seen.get(a))) })),
  ]);

  const stats = {
    fetched: raw.length,
    relevant: scored.length,
    fresh: fresh.length,
    escalated: escalated.length,
    alerted: toAlert.length - failed.size - rejected.size,
    failedAlerts: failed.size,
    rejectedAlerts: rejected.size,
    heldBack: enriched.filter((i) => i.holdReason).length,
  };
  console.log('poll done', JSON.stringify(stats));
  return stats;
}
