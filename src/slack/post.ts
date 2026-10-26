import type { SlackPayload } from './format.js';

export class SlackError extends Error {
  constructor(
    readonly status: number,
    body: string,
  ) {
    super(`Slack webhook → ${status}: ${body}`);
  }
}

const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function postToSlack(webhookUrl: string, payload: SlackPayload, doFetch: typeof fetch = fetch): Promise<void> {
  for (let attempt = 0; ; attempt++) {
    const res = await doFetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (res.ok) return;
    if (res.status === 429 && attempt === 0) {
      await pause(Number(res.headers.get('Retry-After') ?? '1') * 1000);
      continue;
    }
    throw new SlackError(res.status, await res.text());
  }
}
