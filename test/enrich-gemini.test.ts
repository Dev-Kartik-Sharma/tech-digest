import { describe, expect, it } from 'vitest';
import { enrichWithGemini, type Generate } from '../src/pipeline/enrich-gemini.js';
import type { ScoredItem } from '../src/types.js';

const scored = (i: number, over: Partial<ScoredItem> = {}): ScoredItem => ({
  id: `id-${i}`,
  aliases: [`id-${i}`],
  kind: 'news',
  source: 's',
  title: `title ${i}`,
  url: `https://x/${i}`,
  publishedAt: '2026-10-25T00:00:00Z',
  snippet: 'snippet',
  priority: 'low',
  category: 'tech-news',
  ...over,
});

/** Fake model: replies with the given per-index results for whatever batch it receives. */
const fakeModel = (reply: (i: number) => object, calls: string[] = []): Generate => {
  return async (prompt) => {
    calls.push(prompt);
    const ids = [...prompt.matchAll(/"i":\s*(\d+)/g)].map((m) => Number(m[1]));
    return JSON.stringify(ids.map((i) => ({ i, ...reply(i) })));
  };
};

describe('enrichWithGemini', () => {
  it('adds summaries, lets news change category and bump one level, but never changes vuln priority', async () => {
    const items = [
      scored(0),
      scored(1, { kind: 'vuln', priority: 'high', category: 'vuln-js' }),
    ];
    const out = await enrichWithGemini(
      items,
      fakeModel(() => ({ summary: 'AI summary', category: 'supply-chain', relevant: true, bump: true, reason: 'big' })),
    );
    expect(out[0]).toMatchObject({ summary: 'AI summary', category: 'supply-chain', priority: 'medium', bumpReason: 'big' });
    expect(out[1]).toMatchObject({ summary: 'AI summary', category: 'vuln-js', priority: 'high' });
    expect(out[1]?.bumpReason).toBeUndefined();
  });

  it('drops news Gemini marks irrelevant but keeps vulnerabilities', async () => {
    const out = await enrichWithGemini(
      [scored(0), scored(1, { kind: 'vuln', category: 'vuln-php' })],
      fakeModel(() => ({ summary: 's', category: 'tech-news', relevant: false, bump: false })),
    );
    expect(out.map((i) => i.id)).toEqual(['id-1']);
  });

  it('ignores categories outside the fixed list', async () => {
    const out = await enrichWithGemini(
      [scored(0)],
      fakeModel(() => ({ summary: 's', category: 'cooking', relevant: true, bump: false })),
    );
    expect(out[0]?.category).toBe('tech-news');
  });

  it('returns items unchanged when the model call fails', async () => {
    const items = [scored(0)];
    const out = await enrichWithGemini(items, async () => {
      throw new Error('429 RESOURCE_EXHAUSTED');
    });
    expect(out).toEqual(items);
  });

  it('batches requests and caps the number of calls per run', async () => {
    const calls: string[] = [];
    const items = Array.from({ length: 100 }, (_, i) => scored(i));
    const out = await enrichWithGemini(
      items,
      fakeModel(() => ({ summary: 'ok', category: 'tech-news', relevant: true, bump: false }), calls),
      { batchSize: 30, maxCalls: 3 },
    );
    expect(calls).toHaveLength(3);
    expect(out).toHaveLength(100);
    expect(out.filter((i) => i.summary === 'ok')).toHaveLength(90);
  });

  it('sends fixed versions to Gemini and asks for a concrete next step', async () => {
    const calls: string[] = [];
    await enrichWithGemini(
      [scored(0, { kind: 'vuln', category: 'vuln-php', packages: [{ name: 'laravel/framework', ecosystem: 'composer', patched: '13.29.0' }] })],
      fakeModel(() => ({ summary: 's', category: 'vuln-php', relevant: true, bump: false }), calls),
    );
    expect(calls[0]).toContain('laravel/framework');
    expect(calls[0]).toContain('13.29.0');
    expect(calls[0]).toMatch(/upgrade/i);
  });

  it('sends AI news with more text and asks for capabilities and stated benchmarks', async () => {
    const calls: string[] = [];
    const long = `Model scores 81.2% on SWE-bench Verified. ${'Details. '.repeat(80)}END-MARKER`;
    await enrichWithGemini(
      [scored(0, { feedKind: 'ai-news', category: 'ai-update', snippet: long.slice(0, 700) })],
      fakeModel(() => ({ summary: 's', category: 'ai-update', relevant: true, bump: false }), calls),
    );
    expect(calls[0]).toContain(long.slice(0, 650));
    expect(calls[0]).toMatch(/benchmark/i);
  });

  it('makes no call when there are no items', async () => {
    const calls: string[] = [];
    await enrichWithGemini([], fakeModel(() => ({}), calls));
    expect(calls).toHaveLength(0);
  });
});
