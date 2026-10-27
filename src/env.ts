import { existsSync } from 'node:fs';
import { geminiGenerate } from './pipeline/enrich-gemini.js';
import type { SlackPayload } from './slack/format.js';
import { postToSlack } from './slack/post.js';
import { fetchAll } from './sources/index.js';
import type { Item } from './types.js';

/**
 * Builds runtime dependencies from env vars (or ./.env when present):
 * SLACK_WEBHOOK_URL (required unless dryRun), GEMINI_API_KEY, GITHUB_TOKEN, NVD_API_KEY, GEMINI_MODEL,
 * DIGEST_TIMEZONE (default UTC), DIGEST_AFTER (local HH:MM the daily digest may go out, default 10:00).
 */
export function depsFromEnv({ dryRun }: { dryRun: boolean }) {
  if (existsSync('.env')) process.loadEnvFile('.env');
  const env = (name: string) => process.env[name]?.trim() || undefined;

  const webhook = env('SLACK_WEBHOOK_URL');
  if (!dryRun && !webhook) throw new Error('SLACK_WEBHOOK_URL is not set (or pass --dry-run)');

  const gemini = env('GEMINI_API_KEY');
  if (!gemini) console.warn('GEMINI_API_KEY not set: skipping AI summaries');

  const digestAfter = env('DIGEST_AFTER') ?? '10:00';
  if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(digestAfter)) throw new Error(`DIGEST_AFTER must be HH:MM (24h), got "${digestAfter}"`);

  const githubToken = env('GITHUB_TOKEN');
  const nvdApiKey = env('NVD_API_KEY');
  return {
    fetchAll: (since: Date): Promise<Item[]> =>
      fetchAll(since, { ...(githubToken ? { githubToken } : {}), ...(nvdApiKey ? { nvdApiKey } : {}) }),
    ...(gemini ? { generate: geminiGenerate(gemini) } : {}),
    post: async (p: SlackPayload) => {
      if (dryRun) console.log(`\n──── Slack message ────\n${JSON.stringify(p, null, 2)}`);
      else await postToSlack(webhook!, p);
    },
    timeZone: env('DIGEST_TIMEZONE') ?? 'UTC',
    digestAfter,
  };
}
