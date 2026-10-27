/**
 * Entry point for the GitHub Actions workflow (and manual runs).
 *
 *   npm run auto   [-- --dry-run]    poll, then publish the day's brief if it's due (what the schedule runs)
 *   npm run poll   [-- --dry-run]    fetch, alert criticals, queue the rest
 *   npm run digest [-- --dry-run]    publish everything queued since the last brief, now
 *
 * Publishing a brief archives the day, rebuilds the site into SITE_DIR (default site/), writes the
 * Slack brief to ANNOUNCE_FILE (default announce.json) and sets `digest=<date>` in $GITHUB_OUTPUT;
 * the workflow then deploys the site and only after that posts the brief.
 * State lives in STATE_FILE (default state/state.json). See src/env.ts for the other env vars.
 */
import { appendFile, writeFile } from 'node:fs/promises';
import { depsFromEnv } from './env.js';
import { runAuto } from './handlers/auto.js';
import { runDigest, type DigestResult } from './handlers/digest.js';
import { runPoll } from './handlers/poll.js';
import { buildSite } from './site/build.js';
import { FileStore } from './store/file-store.js';

const command = process.argv[2];
if (command !== 'auto' && command !== 'poll' && command !== 'digest') {
  console.error('usage: tsx src/main.ts <auto|poll|digest> [--dry-run]');
  process.exit(2);
}

const dryRun = process.argv.includes('--dry-run');
const deps = depsFromEnv({ dryRun });
const store = await FileStore.load(process.env.STATE_FILE ?? 'state/state.json');

let published: DigestResult | null = null;
try {
  if (command === 'auto') published = (await runAuto({ ...deps, store })).digest;
  else if (command === 'poll') await runPoll({ ...deps, store });
  else published = await runDigest({ ...deps, store });
} finally {
  // save even after a failure: alerts already posted must stay marked as seen.
  // a dry run never touches state
  if (!dryRun) await store.save();
}

if (published?.items.length) {
  const siteDir = process.env.SITE_DIR ?? 'site';
  await buildSite(await store.listDays(), { outDir: siteDir });
  console.log(`site: built ${siteDir}/ for ${published.date}`);
  if (published.brief) {
    if (dryRun) console.log(`\n──── Slack brief (posted after deploy) ────\n${JSON.stringify(published.brief, null, 2)}`);
    await writeFile(process.env.ANNOUNCE_FILE ?? 'announce.json', JSON.stringify(published.brief));
  }
  if (process.env.GITHUB_OUTPUT) await appendFile(process.env.GITHUB_OUTPUT, `digest=${published.date}\n`);
}
