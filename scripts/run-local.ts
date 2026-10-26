/**
 * Preview: runs one poll + digest against real feeds with a throwaway in-memory store.
 *
 *   npm run local -- --dry-run        print Slack payloads instead of posting
 *   npm run local                     post to SLACK_WEBHOOK_URL (use a test channel!)
 *   --lookback-hours=120              look further back than the default 48h
 */
import { LIMITS } from '../src/config/sources.js';
import { depsFromEnv } from '../src/env.js';
import { runDigest } from '../src/handlers/digest.js';
import { runPoll } from '../src/handlers/poll.js';
import { MemoryStore } from '../src/store/store.js';

const lookback = process.argv.find((a) => a.startsWith('--lookback-hours='));
if (lookback) LIMITS.lookbackHours = Number(lookback.split('=')[1]);

const deps = depsFromEnv({ dryRun: process.argv.includes('--dry-run') });
const store = new MemoryStore();
await runPoll({ ...deps, store });
await runDigest({ ...deps, store });
