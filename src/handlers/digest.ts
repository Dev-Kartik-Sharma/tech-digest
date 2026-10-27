import { formatDigest, type SlackPayload } from '../slack/format.js';
import type { Store } from '../store/store.js';

/** YYYY-MM-DD in the given time zone. */
export const localDate = (d: Date, timeZone: string) => new Intl.DateTimeFormat('en-CA', { timeZone }).format(d);

export interface DigestDeps {
  store: Store;
  post: (payload: SlackPayload) => Promise<void>;
  now?: Date;
  timeZone: string;
}

export async function runDigest(deps: DigestDeps) {
  const pending = await deps.store.listPending();
  const date = localDate(deps.now ?? new Date(), deps.timeZone);
  const payload = formatDigest(
    pending.map((e) => e.item),
    date,
    undefined,
    deps.now,
  );
  if (!payload) {
    console.log('digest: nothing pending');
  } else {
    await deps.post(payload);
    await deps.store.deletePending(pending.map((e) => e.key));
    console.log(`digest: posted ${pending.length} items`);
  }
  // a quiet day still counts as done; a failed post (thrown above) does not, so the next run retries
  await deps.store.setLastDigestDate(date);
  return { posted: payload ? pending.length : 0 };
}
