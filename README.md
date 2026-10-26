# tech-updates

A Slack bot for developers working in **PHP** and **MERN / JS**. It watches security advisories and
tech news, then:

- posts **critical** items to Slack straight away (e.g. a PHP or Next.js remote code execution bug,
  or anything in your stack on CISA's actively-exploited list), and
- posts **one daily digest** with everything else, grouped by priority (🔴 critical, 🟠 high, 🟡 medium,
  🟢 low) and category.

It runs on **GitHub Actions cron** with no server and no cloud account. It uses your **Gemini AI Studio
free-tier key** for short summaries: one batched request per poll, and only when something new arrived
(up to 3 on a busy first run).

## How it works

```
GitHub Actions cron ─ every 30 min ─▶ npm run poll
    fetch sources → merge duplicates → popularity lookup → rule-based score
    → drop already-seen → 1 batched Gemini call → critical? post now : queue for digest
GitHub Actions cron ─ daily ─▶ npm run digest → one Slack message → clear queue
```

State is one JSON file: the items already handled (kept 45 days) plus the digest queue. The workflow keeps
it on a `state` branch as a **single force-pushed commit**, so repo history doesn't grow. Runs never
overlap (there's a concurrency group), and if a run fails partway, the state it reached is still saved, so
alerts already posted are never sent again.

| Source | What it gives |
|---|---|
| GitHub Advisory DB (npm, composer) | Package vulnerabilities, with CVSS and affected/fixed versions |
| NVD (CPEs for PHP, Node.js, MongoDB) | CVEs in the runtimes themselves |
| CISA KEV | Vulnerabilities being actively exploited |
| Node.js security feed, php.net | Official security releases |
| The Hacker News, BleepingComputer | Security news |
| Laravel News, Node.js blog, React blog, MongoDB blog, HN front page (300+ pts) | Dev and tech news |

**Priority rules** (deterministic, so alerts still work if Gemini is down). They live in `src/pipeline/score.ts`:

- **Critical:** in your stack and either on CISA KEV, or CVSS ≥ 9, or an RCE in a runtime or a popular package.
  "Popular" means ≥ 50k downloads (npm per week, Packagist per month) or listed in `MAJOR_PACKAGES`.
- **High:** in your stack with CVSS ≥ 7, or on KEV but outside your stack, or security news about
  your stack being actively exploited or hit by RCE or supply-chain attacks.
- **Medium / Low:** lower CVSS bands, and general security and tech news.
- Advisories for packages with fewer than 1k downloads are dropped as noise.
- Without a Gemini key, all security and tech news is kept (as low unless it touches your stack), and
  the digest caps keep the volume in check.
- When CISA adds a CVE to KEV, the bot looks up the GitHub advisory for that CVE, so a package
  vulnerability is recognised as in-stack even when the KEV text never mentions npm or PHP.
- Gemini writes the summaries. For **news only**, it can change the category, raise the priority by one
  level, or drop promotional posts. It never changes a vulnerability's priority.

## Cost: $0

| | Public repo | Private repo (Free plan) |
|---|---|---|
| Actions minutes | unlimited, free | 2,000 / month included. This bot uses ~1,450 (each run rounds up to 1 min) |
| Gemini AI Studio free tier | ≤ ~50 requests / day | same |

On a private repo, if you want more headroom, change the poll cron to hourly (`7 * * * *`, ~750 min/month).
The state file holds only public advisory and news data, so a public repo is fine.

**Good to know**
- GitHub's cron is best-effort: runs can start 5–30 minutes late at busy times. That's fine for news.
- Cron times are **UTC**. Set the digest time in the workflow, and set the `DIGEST_TIMEZONE` variable so
  the digest's date header uses your local date.
- GitHub disables scheduled workflows in **public** repos after 60 days without repository activity. If
  that happens you'll get an email; re-enable the workflow in the Actions tab.
- On Gemini's free tier, Google may use prompts to improve its products. The bot only sends public
  headlines and advisories.

## Setup

### 1. Keys (all free)

| Key | Where to get it | Required? |
|---|---|---|
| Slack webhook URL | api.slack.com/apps → Create app → Incoming Webhooks → add to your channel | yes |
| Gemini API key | aistudio.google.com → Get API key | recommended |
| NVD API key | nvd.nist.gov/developers/request-an-api-key | optional (makes NVD faster) |

There's no GitHub token to create: the workflow's built-in `GITHUB_TOKEN` is used for the Advisory API.
For local runs you can set `GITHUB_TOKEN` in `.env` to raise the API rate limit.

### 2. Try it locally

```bash
npm install
cp .env.example .env              # fill in what you have
npm test
npm run local -- --dry-run        # real feeds, prints Slack messages instead of sending them
npm run local -- --dry-run --lookback-hours=120   # look back 5 days to see more
npm run local                     # actually posts (point SLACK_WEBHOOK_URL at a test channel)
```

### 3. Run it on GitHub Actions

1. Push this project to a GitHub repo.
2. **Settings → Secrets and variables → Actions → Secrets:** add `SLACK_WEBHOOK_URL`, `GEMINI_API_KEY`
   and, optionally, `NVD_API_KEY`.
3. **Same page → Variables** (optional): `DIGEST_TIMEZONE` (e.g. `Asia/Kolkata`), `GEMINI_MODEL`.
4. Set the digest time: edit the second cron in `.github/workflows/tech-updates.yml` **and** the
   `DIGEST_CRON` value to match. Both are in UTC. The default `30 3 * * *` is 03:30 UTC (09:00 IST).
5. **Actions tab → tech-updates → Run workflow** with `poll` for the first run. Check the channel,
   then run `digest`.

The first poll looks back 48 hours. It sends at most 5 instant alerts, and anything beyond that goes into
the digest. Running `poll` again right away should post nothing, because those items are now marked as seen.

Manual runs on your machine use the same state format: `npm run poll` and `npm run digest`, with state kept
in `state/state.json`.

## Tuning

Everything you're likely to change is in `src/config/sources.ts`: feeds, stack keywords, `MAJOR_PACKAGES`,
popularity thresholds, digest caps, and the Gemini batch size and call limits. Run `npm test` after changing it.

## Layout

```
src/config/sources.ts     feeds, CPEs, keywords, thresholds
src/sources/              one fetcher + pure parser per source
src/pipeline/             normalize, dedupe, popularity, score, enrich-gemini
src/slack/                Block Kit formatting + webhook posting
src/store/                Store interface, in-memory store, JSON file store
src/handlers/             runPoll / runDigest (all dependencies injected, so they're testable offline)
src/main.ts               entry point used by the workflow: `poll` | `digest`
scripts/run-local.ts      preview runner (in-memory state)
.github/workflows/        cron schedule, state restore/save
```
