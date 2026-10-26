import { describe, expect, it } from 'vitest';
import { postToSlack } from '../src/slack/post.js';

const payload = { text: 'hi', blocks: [] };

describe('postToSlack', () => {
  it('posts JSON to the webhook', async () => {
    const seen: { url: string; body: string }[] = [];
    const fakeFetch = (async (url: string, init: RequestInit) => {
      seen.push({ url, body: String(init.body) });
      return new Response('ok', { status: 200 });
    }) as typeof fetch;
    await postToSlack('https://hooks.slack.com/x', payload, fakeFetch);
    expect(seen).toEqual([{ url: 'https://hooks.slack.com/x', body: JSON.stringify(payload) }]);
  });

  it('retries once after a 429 using Retry-After', async () => {
    let calls = 0;
    const fakeFetch = (async () => {
      calls++;
      return calls === 1
        ? new Response('rate_limited', { status: 429, headers: { 'Retry-After': '0' } })
        : new Response('ok', { status: 200 });
    }) as typeof fetch;
    await postToSlack('https://hooks.slack.com/x', payload, fakeFetch);
    expect(calls).toBe(2);
  });

  it('throws with Slack\'s error body on failure', async () => {
    const fakeFetch = (async () => new Response('invalid_blocks', { status: 400 })) as typeof fetch;
    await expect(postToSlack('https://hooks.slack.com/x', payload, fakeFetch)).rejects.toThrow(/400.*invalid_blocks/);
  });

  it('exposes the HTTP status on the error', async () => {
    const fakeFetch = (async () => new Response('no_service', { status: 404 })) as typeof fetch;
    await expect(postToSlack('https://hooks.slack.com/x', payload, fakeFetch)).rejects.toMatchObject({ status: 404 });
  });
});
