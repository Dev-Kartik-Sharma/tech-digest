import { describe, expect, it } from 'vitest';
import { runAuto } from '../src/handlers/auto.js';
import { runDigest } from '../src/handlers/digest.js';
import type { SlackPayload } from '../src/slack/format.js';
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
  const posts: SlackPayload[] = [];
  let items: Item[] = [];
  const run = (now: Date, fresh: Item[] = []) => {
    items = fresh;
    return runAuto({
      fetchAll: async () => items,
      lookupDownloads: async () => undefined,
      store,
      post: async (p) => void posts.push(p),
      now,
      timeZone: 'Asia/Kolkata',
      digestAfter: '10:00',
    });
  };
  const digests = () => posts.filter((p) => p.text.startsWith('Tech & Security Digest'));
  return { store, posts, run, digests };
}

describe('runAuto', () => {
  it('only polls before the digest time', async () => {
    const { run, digests, store } = setup();
    await run(BEFORE_10_IST, [mediumNews()]);
    expect(digests()).toHaveLength(0);
    expect(await store.listPending()).toHaveLength(1);
  });

  it('posts the digest on the first run after the digest time, once per day', async () => {
    const { run, digests } = setup();
    await run(BEFORE_10_IST, [mediumNews()]);
    await run(AFTER_10_IST, [mediumNews()]);
    expect(digests()).toHaveLength(1);
    expect(digests()[0]?.text).toMatch(/2026-10-27.*2 medium/);
    await run(LATER_SAME_DAY, [mediumNews()]);
    expect(digests()).toHaveLength(1);
  });

  it('posts again the next day, including items queued after the previous digest', async () => {
    const { run, digests } = setup();
    await run(AFTER_10_IST, [mediumNews()]);
    await run(LATER_SAME_DAY, [mediumNews()]);
    await run(NEXT_DAY, []);
    expect(digests()).toHaveLength(2);
    expect(digests()[1]?.text).toMatch(/2026-10-28.*1 medium/);
  });

  it('counts a quiet day as done without posting', async () => {
    const { run, digests, store } = setup();
    await run(AFTER_10_IST, []);
    expect(digests()).toHaveLength(0);
    expect(await store.getLastDigestDate()).toBe('2026-10-27');
  });

  it('retries the digest on the next run when posting fails', async () => {
    const store = new MemoryStore();
    let fail = true;
    const posts: SlackPayload[] = [];
    const deps = {
      fetchAll: async () => [mediumNews()],
      lookupDownloads: async () => undefined,
      store,
      post: async (p: SlackPayload) => {
        if (fail && p.text.startsWith('Tech & Security Digest')) throw new Error('slack down');
        posts.push(p);
      },
      timeZone: 'Asia/Kolkata',
      digestAfter: '10:00',
    };
    await expect(runAuto({ ...deps, now: AFTER_10_IST })).rejects.toThrow('slack down');
    expect(await store.getLastDigestDate()).toBeUndefined();
    fail = false;
    await runAuto({ ...deps, now: LATER_SAME_DAY });
    expect(posts.filter((p) => p.text.startsWith('Tech & Security Digest'))).toHaveLength(1);
  });
});

describe('runDigest', () => {
  it('records the day it ran, so a manual digest also counts for today', async () => {
    const store = new MemoryStore();
    await runDigest({ store, post: async () => {}, now: AFTER_10_IST, timeZone: 'Asia/Kolkata' });
    expect(await store.getLastDigestDate()).toBe('2026-10-27');
  });
});
