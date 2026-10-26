import { describe, expect, it } from 'vitest';
import { runDigest } from '../src/handlers/digest.js';
import { runPoll, type PollDeps } from '../src/handlers/poll.js';
import { SlackError } from '../src/slack/post.js';
import { MemoryStore } from '../src/store/store.js';
import type { SlackPayload } from '../src/slack/format.js';
import type { Item } from '../src/types.js';

const NOW = new Date('2026-10-26T12:00:00Z');

const phpRce = (n: number, over: Partial<Item> = {}): Item => ({
  id: `CVE-2026-${1000 + n}`,
  aliases: [`CVE-2026-${1000 + n}`],
  kind: 'vuln',
  source: 'NVD',
  title: `PHP remote code execution #${n}`,
  url: `https://nvd/${n}`,
  publishedAt: '2026-10-26T00:00:00Z',
  snippet: '',
  ecosystem: 'php-core',
  cvss: 9.8,
  ...over,
});

const mediumNpm: Item = {
  id: 'GHSA-med',
  aliases: ['GHSA-med'],
  kind: 'vuln',
  source: 'GitHub Advisories',
  title: 'express ReDoS',
  url: 'https://gh/med',
  publishedAt: '2026-10-26T00:00:00Z',
  snippet: '',
  ecosystem: 'npm',
  cvss: 5.3,
  packages: [{ name: 'express', ecosystem: 'npm' }],
};

function deps(items: Item[], over: Partial<PollDeps> = {}) {
  const posts: SlackPayload[] = [];
  const store = new MemoryStore();
  const d: PollDeps = {
    fetchAll: async () => items,
    lookupDownloads: async () => undefined,
    store,
    post: async (p) => {
      posts.push(p);
    },
    now: NOW,
    ...over,
  };
  return { d, posts, store };
}

describe('runPoll', () => {
  it('posts criticals now, queues the rest for the digest, and is idempotent', async () => {
    const { d, posts, store } = deps([phpRce(1), mediumNpm]);
    const stats = await runPoll(d);
    expect(posts).toHaveLength(1);
    expect(posts[0]?.text).toMatch(/CRITICAL.*PHP remote code execution #1/);
    const pending = (await store.listPending()).map((e) => e.item.id).sort();
    expect(pending).toEqual(['CVE-2026-1001', 'GHSA-med']); // critical kept for the digest recap
    expect(stats).toMatchObject({ fetched: 2, fresh: 2, alerted: 1 });

    await runPoll(d);
    expect(posts).toHaveLength(1);
  });

  it('caps instant alerts per run and sends the overflow to the digest', async () => {
    const items = Array.from({ length: 8 }, (_, n) => phpRce(n));
    const { d, posts, store } = deps(items);
    await runPoll(d);
    expect(posts).toHaveLength(5);
    expect((await store.listPending()).filter((e) => e.item.priority === 'critical')).toHaveLength(8);
  });

  it('does not mark an alert as seen when Slack fails, so the next run retries it', async () => {
    let fail = true;
    const { d, posts, store } = deps([phpRce(1)], {
      post: async (p) => {
        if (fail) throw new Error('slack down');
        posts.push(p);
      },
    });
    await runPoll(d);
    expect(store.seen.size).toBe(0);
    expect(await store.listPending()).toEqual([]);
    fail = false;
    await runPoll(d);
    expect(posts).toHaveLength(1);
  });

  it('never re-alerts a posted critical even if queueing for the digest fails', async () => {
    const { d, posts, store } = deps([phpRce(1), mediumNpm]);
    const addPending = store.addPending.bind(store);
    store.addPending = async () => {
      throw new Error('throttled');
    };
    await expect(runPoll(d)).rejects.toThrow('throttled');
    store.addPending = addPending;
    await runPoll(d);
    expect(posts).toHaveLength(1);
    expect((await store.listPending()).map((e) => e.item.id)).toEqual(['GHSA-med']);
  });

  it('escalates an item seen earlier at a lower priority once it becomes critical', async () => {
    const before: Item = { ...mediumNpm, cvss: 7.5 };
    const { d, posts, store } = deps([before]);
    await runPoll(d);
    expect(posts).toHaveLength(0);

    await runPoll({ ...d, fetchAll: async () => [{ ...before, kev: true }] });
    expect(posts).toHaveLength(1);
    expect(posts[0]?.text).toMatch(/escalated/);
    expect(store.seen.get('GHSA-med')).toBe('critical');
  });

  it('keeps working when Gemini is unavailable', async () => {
    const { d, posts } = deps([phpRce(1)], {
      generate: async () => {
        throw new Error('429');
      },
    });
    await runPoll(d);
    expect(posts).toHaveLength(1);
  });

  it('marks news Gemini dropped as seen so it is not re-sent to Gemini next run', async () => {
    const promo: Item = {
      id: 'url-promo',
      aliases: ['url-promo'],
      kind: 'news',
      source: 'MongoDB Blog',
      title: 'Join our webinar',
      url: 'https://m/w',
      publishedAt: '2026-10-26T00:00:00Z',
      snippet: '',
      feedKind: 'dev-news',
      feedStack: 'js',
    };
    let calls = 0;
    const { d, store } = deps([promo], {
      generate: async () => {
        calls++;
        return JSON.stringify([{ i: 0, summary: 'x', category: 'tech-news', relevant: false, bump: false }]);
      },
    });
    await runPoll(d);
    await runPoll(d);
    expect(calls).toBe(1);
    expect(await store.listPending()).toEqual([]);
  });
});

describe('runPoll: review fixes', () => {
  it('escalates when KEV later lists a CVE first seen as a GHSA advisory, even if the KEV text has no stack keywords', async () => {
    const ghsa: Item = { ...mediumNpm, id: 'CVE-2026-7', aliases: ['CVE-2026-7', 'GHSA-strapi'], cvss: 7.5, title: 'strapi auth bypass', packages: [{ name: '@strapi/strapi', ecosystem: 'npm' }] };
    const { d, posts } = deps([ghsa], { lookupDownloads: async () => 100_000 });
    await runPoll(d);
    expect(posts).toHaveLength(0);
    const kevOnly: Item = { ...phpRce(0), id: 'CVE-2026-7', aliases: ['CVE-2026-7'], source: 'CISA KEV', kev: true, ecosystem: undefined, cvss: undefined, title: 'Strapi Improper Authentication Vulnerability', snippet: 'Strapi Strapi: improper authentication' };
    // the KEV source looks the CVE up in GHSA, so both arrive together
    await runPoll({ ...d, fetchAll: async () => [kevOnly, ghsa] });
    expect(posts).toHaveLength(1);
    expect(posts[0]?.text).toMatch(/escalated/);
  });

  it('records aliases learned after an item was first seen, so a later source cannot re-alert it', async () => {
    const before: Item = { ...phpRce(1), id: 'GHSA-x', aliases: ['GHSA-x'], source: 'GitHub Advisories' };
    const { d, posts, store } = deps([before]);
    await runPoll(d);
    expect(posts).toHaveLength(1);
    await runPoll({ ...d, fetchAll: async () => [{ ...before, id: 'CVE-2026-9', aliases: ['CVE-2026-9', 'GHSA-x'] }] });
    expect(store.seen.get('CVE-2026-9')).toBe('critical');
    await runPoll({ ...d, fetchAll: async () => [{ ...phpRce(1), id: 'CVE-2026-9', aliases: ['CVE-2026-9'], source: 'NVD' }] });
    expect(posts).toHaveLength(1);
  });

  it('only looks up download counts for items not seen before', async () => {
    const looked: string[] = [];
    const { d } = deps([mediumNpm], { lookupDownloads: async (name) => (looked.push(name), 10_000_000) });
    await runPoll(d);
    await runPoll(d);
    expect(looked).toEqual(['express']);
  });

  it('marks items the rules dropped as seen at low, so a later KEV listing still escalates them', async () => {
    const tiny: Item = { ...mediumNpm, id: 'CVE-2026-11', aliases: ['CVE-2026-11'], cvss: 9.8, packages: [{ name: 'tiny', ecosystem: 'npm' }] };
    const { d, posts, store } = deps([tiny], { lookupDownloads: async () => 10 });
    await runPoll(d);
    expect(store.seen.get('CVE-2026-11')).toBe('low');
    await runPoll({ ...d, fetchAll: async () => [{ ...tiny, kev: true }] });
    expect(posts).toHaveLength(1);
  });

  it('keeps escalations beyond the per-run cap for the next run instead of losing them', async () => {
    const items = Array.from({ length: 7 }, (_, n) => ({ ...mediumNpm, id: `CVE-2026-2${n}`, aliases: [`CVE-2026-2${n}`], cvss: 7.5 }));
    const { d, posts } = deps(items);
    await runPoll(d);
    const kev = items.map((i) => ({ ...i, kev: true }));
    await runPoll({ ...d, fetchAll: async () => kev });
    expect(posts).toHaveLength(5);
    await runPoll({ ...d, fetchAll: async () => kev });
    expect(posts).toHaveLength(7);
  });

  it('sends an alert Slack rejects as invalid to the digest instead of retrying it forever', async () => {
    const { d, store } = deps([phpRce(1)], {
      post: async () => {
        throw new SlackError(400, 'invalid_blocks');
      },
    });
    await runPoll(d);
    expect((await store.listPending()).map((e) => e.item.id)).toEqual(['CVE-2026-1001']);
    expect(store.seen.get('CVE-2026-1001')).toBe('critical');
  });
});

describe('runDigest', () => {
  it('posts one digest with everything pending and clears it', async () => {
    const { d, store } = deps([phpRce(1), mediumNpm]);
    await runPoll(d);
    const posts: SlackPayload[] = [];
    const res = await runDigest({ store, post: async (p) => void posts.push(p), now: NOW, timeZone: 'UTC' });
    expect(res.posted).toBe(2);
    expect(posts).toHaveLength(1);
    expect(posts[0]?.text).toMatch(/2026-10-26.*1 critical · 1 medium/);
    expect(await store.listPending()).toEqual([]);
  });

  it('posts nothing on a quiet day', async () => {
    const posts: SlackPayload[] = [];
    await runDigest({ store: new MemoryStore(), post: async (p) => void posts.push(p), now: NOW, timeZone: 'UTC' });
    expect(posts).toHaveLength(0);
  });

  it('keeps pending items when posting fails', async () => {
    const { d, store } = deps([mediumNpm]);
    await runPoll(d);
    await expect(
      runDigest({ store, post: async () => Promise.reject(new Error('down')), now: NOW, timeZone: 'UTC' }),
    ).rejects.toThrow('down');
    expect(await store.listPending()).toHaveLength(1);
  });
});
