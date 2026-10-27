/**
 * Preview: runs one poll + brief against real feeds with a throwaway in-memory store, and builds
 * the brief page into ./site.
 *
 *   npm run local -- --dry-run        print Slack messages instead of posting
 *   npm run local                     post to SLACK_WEBHOOK_URL (use a test channel!)
 *   --lookback-hours=120              look further back than the default 48h
 *
 * Then: npx serve site   (or any static server) and open the printed URL.
 */
import { LIMITS } from '../src/config/sources.js';
import { depsFromEnv } from '../src/env.js';
import { runDigest } from '../src/handlers/digest.js';
import { runPoll } from '../src/handlers/poll.js';
import { buildSite } from '../src/site/build.js';
import { MemoryStore } from '../src/store/store.js';

const lookback = process.argv.find((a) => a.startsWith('--lookback-hours='));
if (lookback) LIMITS.lookbackHours = Number(lookback.split('=')[1]);

const deps = depsFromEnv({ dryRun: process.argv.includes('--dry-run') });
const store = new MemoryStore();
await runPoll({ ...deps, store });
const { brief } = await runDigest({ ...deps, store });
await buildSite(await store.listDays(), { outDir: 'site' });
console.log('site: built site/');
if (brief) await deps.post(brief);
