import { formatDigest, type SlackPayload } from '../slack/format.js';
import type { Store } from '../store/store.js';

export interface DigestDeps {
  store: Store;
  post: (payload: SlackPayload) => Promise<void>;
  now?: Date;
  timeZone: string;
}

export async function runDigest(deps: DigestDeps) {
  const pending = await deps.store.listPending();
  const date = new Intl.DateTimeFormat('en-CA', { timeZone: deps.timeZone }).format(deps.now ?? new Date());
  const payload = formatDigest(
    pending.map((e) => e.item),
    date,
  );
  if (!payload) {
    console.log('digest: nothing pending');
    return { posted: 0 };
  }
  await deps.post(payload);
  await deps.store.deletePending(pending.map((e) => e.key));
  console.log(`digest: posted ${pending.length} items`);
  return { posted: pending.length };
}
