import { describe, expect, it } from 'vitest';
import { runAuto } from '../src/handlers/auto.js';
import { MemoryStore } from '../src/store/store.js';
import type { Item } from '../src/types.js';

const at = (iso: string) => new Date(iso);
// IST = UTC+5:30, so 04:30Z is 10:00 IST
const BEFORE_10_IST = at('2026-10-27T04:00:00Z');
const AFTER_10_IST = at('2026-10-27T04:45:00Z');
const LATER_SAME_DAY = at('2026-10-27T09:45:00Z');
const NEXT_DAY = at('2026-10-28T05:15:00Z');

let n = 0;
const mediumNews = (): Item => {
  n++;
  return {
    id: `url-${n}`,
    aliases: [`url-${n}`],
    kind: 'news',
    source: 'BleepingComputer',
    title: `Node.js app hit by data breach ${n}`,
    url: `https://x/${n}`,
    publishedAt: '2026-10-27T00:00:00Z',
    snippet: '',
    feedKind: 'security-news',
  };
};

function setup() {
  const store = new MemoryStore();
  const run = (now: Date, fresh: Item[] = []) =>
    runAuto({
      fetchAll: async () => fresh,
      lookupDownloads: async () => undefined,
      store,
      post: async () => {},
      now,
      timeZone: 'Asia/Kolkata',
      digestAfter: '10:00',
      siteUrl: 'https://example.github.io/repo/',
    });
  return { store, run };
}

describe('runAuto', () => {
  it('only polls before the digest time', async () => {
    const { run, store } = setup();
    const res = await run(BEFORE_10_IST, [mediumNews()]);
    expect(res.digest).toBeNull();
    expect(await store.listPending()).toHaveLength(1);
  });

  it('publishes the day on the first run after the digest time, once per day', async () => {
    const { run, store } = setup();
    await run(BEFORE_10_IST, [mediumNews()]);
    const first = await run(AFTER_10_IST, [mediumNews()]);
    expect(first.digest?.date).toBe('2026-10-27');
    expect(first.digest?.items).toHaveLength(2);
    expect(first.digest?.brief).not.toBeNull();
    const later = await run(LATER_SAME_DAY, [mediumNews()]);
    expect(later.digest).toBeNull();
    expect(await store.listDays()).toHaveLength(1);
  });

  it('publishes again the next day, including items queued after the previous digest', async () => {
    const { run } = setup();
    await run(AFTER_10_IST, [mediumNews()]);
    await run(LATER_SAME_DAY, [mediumNews()]);
    const next = await run(NEXT_DAY, []);
    expect(next.digest?.date).toBe('2026-10-28');
    expect(next.digest?.items).toHaveLength(1);
  });

  it('counts a quiet day as done without a brief', async () => {
    const { run, store } = setup();
    const res = await run(AFTER_10_IST, []);
    expect(res.digest?.brief).toBeNull();
    expect(await store.getLastDigestDate()).toBe('2026-10-27');
  });
});
