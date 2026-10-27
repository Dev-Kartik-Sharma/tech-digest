/**
 * Entry point for the GitHub Actions workflow (and manual runs).
 *
 *   npm run auto   [-- --dry-run]    poll, then post the day's digest if it's due (what the schedule runs)
 *   npm run poll   [-- --dry-run]    fetch, alert criticals, queue the rest
 *   npm run digest [-- --dry-run]    post everything queued since the last digest, now
 *
 * State (seen items + digest queue) lives in STATE_FILE (default state/state.json).
 * See src/env.ts for the other env vars.
 */
import { depsFromEnv } from './env.js';
import { runAuto } from './handlers/auto.js';
import { runDigest } from './handlers/digest.js';
import { runPoll } from './handlers/poll.js';
import { FileStore } from './store/file-store.js';

const command = process.argv[2];
if (command !== 'auto' && command !== 'poll' && command !== 'digest') {
  console.error('usage: tsx src/main.ts <auto|poll|digest> [--dry-run]');
  process.exit(2);
}

const dryRun = process.argv.includes('--dry-run');
const deps = depsFromEnv({ dryRun });
const store = await FileStore.load(process.env.STATE_FILE ?? 'state/state.json');

try {
  if (command === 'auto') await runAuto({ ...deps, store });
  else if (command === 'poll') await runPoll({ ...deps, store });
  else await runDigest({ ...deps, store });
} finally {
  // save even after a failure: alerts already posted must stay marked as seen.
  // a dry run never touches state
  if (!dryRun) await store.save();
}
