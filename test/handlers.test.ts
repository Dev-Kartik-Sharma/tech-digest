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
  ecosystem: 'core', stackHint: 'php',
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
    const pending = await store.listPending();
    expect(pending.map((e) => e.item.id).sort()).toEqual(['CVE-2026-1001', 'GHSA-med']);
    // the alerted critical stays in the day's record, marked so the Slack brief doesn't repeat it
    expect(pending.find((e) => e.item.id === 'CVE-2026-1001')?.item.alertedAt).toBe(NOW.toISOString());
    expect(pending.find((e) => e.item.id === 'GHSA-med')?.item.alertedAt).toBeUndefined();
    expect(stats).toMatchObject({ fetched: 2, fresh: 2, alerted: 1 });

    await runPoll(d);
    expect(posts).toHaveLength(1);
  });

  it('caps instant alerts per run and sends the overflow to the digest', async () => {
    const items = Array.from({ length: 8 }, (_, n) => phpRce(n));
    const { d, posts, store } = deps(items);
    await runPoll(d);
    expect(posts).toHaveLength(5);
    const criticals = (await store.listPending()).filter((e) => e.item.priority === 'critical');
    expect(criticals).toHaveLength(8);
    expect(criticals.filter((e) => e.item.alertedAt)).toHaveLength(5);
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
      stackHint: 'js',
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

describe('runPoll: Python criticals', () => {
  const pyRce = (over: Partial<Item> = {}) => phpRce(1, { id: 'CVE-2026-3001', aliases: ['CVE-2026-3001'], title: 'Python remote code execution', stackHint: 'python', ...over });

  it('keeps a Python critical out of instant alerts and puts it in the day\'s brief as critical', async () => {
    const { d, posts, store } = deps([pyRce(), phpRce(2)]);
    const stats = await runPoll(d);
    expect(posts).toHaveLength(1);
    expect(posts[0]?.text).toMatch(/PHP remote code execution #2/);
    const py = (await store.listPending()).find((e) => e.item.id === 'CVE-2026-3001')?.item;
    expect(py).toMatchObject({ priority: 'critical', category: 'vuln-python' });
    expect(py?.alertedAt).toBeUndefined();
    expect(store.seen.get('CVE-2026-3001')).toBe('critical');
    expect(stats.alerted).toBe(1);

    await runPoll(d);
    expect(posts).toHaveLength(1);
  });

  it('does not alert a Python item escalated to critical, and records it for the brief once', async () => {
    const high = pyRce({ title: 'Python path traversal', cvss: 7.5 });
    const { d, posts, store } = deps([high]);
    await runPoll(d);
    expect(store.seen.get('CVE-2026-3001')).toBe('high');
    await store.deletePending((await store.listPending()).map((e) => e.key));
    await runPoll({ ...d, fetchAll: async () => [{ ...high, kev: true }] });
    await runPoll({ ...d, fetchAll: async () => [{ ...high, kev: true }] });
    expect(posts).toHaveLength(0);
    expect(store.seen.get('CVE-2026-3001')).toBe('critical');
    expect((await store.listPending()).map((e) => e.item.priority)).toEqual(['critical']);
  });
});

describe('runDigest', () => {
  const SITE = 'https://example.github.io/repo/';

  it("archives the day's items, clears the queue, and returns the Slack brief", async () => {
    const { d, store } = deps([phpRce(1), mediumNpm]);
    await runPoll(d);
    const res = await runDigest({ store, now: NOW, timeZone: 'UTC', siteUrl: SITE });
    expect(res.date).toBe('2026-10-26');
    expect(res.items.map((i) => i.id).sort()).toEqual(['CVE-2026-1001', 'GHSA-med']);
    expect(res.brief?.text).toMatch(/2026-10-26/);
    expect(JSON.stringify(res.brief)).toContain(`${SITE}?day=2026-10-26`);
    const [day] = await store.listDays();
    expect(day).toMatchObject({ date: '2026-10-26', generatedAt: NOW.toISOString() });
    expect(day?.items).toHaveLength(2);
    expect(await store.listPending()).toEqual([]);
    expect(await store.getLastDigestDate()).toBe('2026-10-26');
  });

  it('prunes the archive to the number of days kept', async () => {
    const store = new MemoryStore();
    for (const date of ['2026-10-20', '2026-10-21', '2026-10-22']) await store.saveDay({ date, generatedAt: '', items: [] });
    await store.addPending([{ ...mediumNpm, priority: 'medium', category: 'vuln-js' }]);
    await runDigest({ store, now: NOW, timeZone: 'UTC', siteUrl: SITE, daysKept: 2 });
    expect((await store.listDays()).map((d) => d.date)).toEqual(['2026-10-26', '2026-10-22']);
  });

  it('archives nothing and returns no brief on a quiet day, but still counts the day as done', async () => {
    const store = new MemoryStore();
    const res = await runDigest({ store, now: NOW, timeZone: 'UTC', siteUrl: SITE });
    expect(res.brief).toBeNull();
    expect(await store.listDays()).toEqual([]);
    expect(await store.getLastDigestDate()).toBe('2026-10-26');
  });
});
