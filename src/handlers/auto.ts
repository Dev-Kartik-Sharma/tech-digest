import { localDate, runDigest } from './digest.js';
import { runPoll, type PollDeps } from './poll.js';

export interface AutoDeps extends PollDeps {
  timeZone: string;
  /** Local time (HH:MM, 24h) from which the day's digest may go out. */
  digestAfter: string;
}

const localTime = (d: Date, timeZone: string) =>
  new Intl.DateTimeFormat('en-GB', { timeZone, hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).format(d);

/**
 * What every scheduled run does: poll, then post the day's digest if it's past `digestAfter` and
 * today's hasn't gone out. Exact trigger times don't matter: the first run after the digest time
 * sends it, once, and a missed run is made up by the next one.
 */
export async function runAuto(deps: AutoDeps) {
  const now = deps.now ?? new Date();
  const poll = await runPoll({ ...deps, now });

  const today = localDate(now, deps.timeZone);
  if (localTime(now, deps.timeZone) < deps.digestAfter || (await deps.store.getLastDigestDate()) === today) {
    return { poll, digest: null };
  }
  return { poll, digest: await runDigest({ ...deps, now }) };
}
