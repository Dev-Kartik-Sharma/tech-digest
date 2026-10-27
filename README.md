# tech-updates

A Slack bot for developers. It watches security advisories and tech news for these tech areas:

| Tech area (digest category) | Covers |
|---|---|
| PHP | PHP, Laravel, Symfony, WordPress, Drupal, Composer packages |
| JS / Node | Node.js, Express, NestJS, React, Next.js, Angular, Vue (MERN / MEAN), every npm package |
| Python | Python, Django, Flask, FastAPI, PyPI packages |
| Database | PostgreSQL, MySQL / MariaDB, MongoDB |
| Nginx / web server | nginx, NGINX Plus |
| GitHub / GitLab | GitHub (incl. Enterprise Server, Actions), GitLab |
| Cloud | AWS (security bulletins), plus Azure, Google Cloud, Cloudflare mentions |
| AI models & tools | New models and capabilities from Anthropic (Claude), OpenAI (ChatGPT / GPT), Google (Gemini, DeepMind), open-weight models (Hugging Face), and developer AI tools and workflows (Copilot, Cursor, Claude Code, MCP); security issues in AI tools get their own *AI tools vulnerability* category |

On top of those, news is also grouped as *exploited in the wild*, *supply chain*, *breach / malware*,
*release / update* and *tech news*. The bot:

- posts **critical** items to Slack straight away (e.g. a PHP or Next.js remote code execution bug,
  or anything in your stack on CISA's actively-exploited list). Alerts aren't repeated in the digest;
  only criticals beyond the 5-per-poll cap go there instead. And it
- posts **one daily digest, on the first run after 10:00 IST** (usually by ~11:00), with everything else, grouped by priority (🔴 critical, 🟠 high,
  🟡 medium, 🟢 low) and then by category.

**What "new" means:** each digest contains what the bot first saw since the previous digest, i.e. roughly
the last 24 hours. Every item appears once. Almost everything was published in the last 1–2 days. The
exception is NVD, which sometimes finishes analysing an older CVE (up to 30 days old) and only then
links it to a product like PHP or nginx. Those lines show *published 12 Oct* so you can tell.

It runs on **GitHub Actions**, triggered hourly by a free external scheduler (cron-job.org), with no
server and no cloud account. It uses your **Gemini AI Studio
free-tier key** for short summaries: one batched request per poll, and only when something new arrived
(up to 3 on a busy first run).

## How it works

```
cron-job.org (hourly) ──┐
GitHub cron (every 2h) ─┴─▶ workflow `auto`
  1. poll:   fetch sources → merge duplicates → popularity lookup → rule-based score
             → drop already-seen → 1 batched Gemini call → critical? post now : queue for digest
  2. digest: past DIGEST_AFTER (10:00 IST) and today's not sent yet? → one Slack message
```

State is one JSON file: the items already handled (kept 45 days) plus the digest queue. The workflow keeps
it on a `state` branch as a **single force-pushed commit**, so repo history doesn't grow. Runs never
overlap (there's a concurrency group), and if a run fails partway, the state it reached is still saved, so
alerts already posted are never sent again.

| Source | What it gives |
|---|---|
| GitHub Advisory DB (npm, composer, pip) | Package vulnerabilities, with CVSS and affected/fixed versions |
| NVD (PHP, Node.js, Python, PostgreSQL, MySQL, MongoDB, nginx, GitLab, GitHub Enterprise Server) | CVEs in the products themselves |
| CISA KEV | Vulnerabilities being actively exploited |
| Node.js security, php.net, Python Insider, Django, PostgreSQL, nginx.org, GitLab security releases, AWS security bulletins | Official security releases |
| The Hacker News, BleepingComputer, GitHub Security Blog | Security news |
| Laravel News, Node.js / React / Angular / MongoDB blogs, HN front page (300+ pts) | Dev and tech news |
| Anthropic news (via its sitemap: no RSS), OpenAI, Google AI, Google DeepMind, Hugging Face, GitHub AI & ML, Simon Willison, Latent Space, TechCrunch AI | AI models, benchmarks and developer AI tools |

**Priority rules** (deterministic, so alerts still work if Gemini is down). They live in `src/pipeline/score.ts`:

- **Critical:** in your stack and either on CISA KEV, or CVSS ≥ 9, or an RCE in a runtime or a popular package.
  "Popular" means ≥ 50k downloads (npm / PyPI per week, Packagist per month) or listed in `MAJOR_PACKAGES`.
- **High:** in your stack with CVSS ≥ 7, or on KEV but outside your stack, or security news about
  your stack being actively exploited or hit by RCE or supply-chain attacks.
- **Medium / Low:** lower CVSS bands, and general security and tech news.
- Advisories for packages with fewer than 1k downloads are dropped as noise.
- Without a Gemini key, all security and tech news is kept (as low unless it touches your stack), and
  the digest caps keep the volume in check.
- When CISA adds a CVE to KEV, the bot looks up the GitHub advisory for that CVE, so a package
  vulnerability is recognised as in-stack even when the KEV text never mentions npm or PHP.
- An item matching several areas gets the first one in the table above (e.g. "PHP app on AWS" → PHP).
- AI posts: launches, new capabilities and benchmark results are medium; other AI posts are low. Gemini
  summarises what launched, its key capabilities, benchmark scores **only when the article states them**,
  and how to try it, and filters out funding / IPO / lawsuit stories.
- Gemini writes the summaries and ends each with a concrete next step, e.g. "Upgrade laravel/framework to
  13.29.0 or later".
- For **news only**, Gemini can also change the category, raise the priority by one
  level, or drop promotional posts. It never changes a vulnerability's priority.

## Cost: $0

| | Public repo | Private repo (Free plan) |
|---|---|---|
| Actions minutes | unlimited, free | 2,000 / month included. This bot uses ~1,100–1,500 (~36 runs/day, ~1–1.5 min each) |
| Gemini AI Studio free tier | ≤ ~36 requests / day | same |
| cron-job.org | free | same |
The state file holds only public advisory and news data, so a public repo is fine.

**Good to know**
- GitHub's own cron is best-effort and on this repo it skipped most runs, which is why an external
  scheduler is the main trigger. Because every run is `auto`, it doesn't matter which trigger fires, or
  if one is missed: the next run catches up, and the digest still goes out exactly once a day.
- GitHub disables the backup **schedule** in public repos after 60 days without repository activity
  (you'll get an email). The cron-job.org trigger keeps working regardless.
- On Gemini's free tier, Google may use prompts to improve its products. The bot only sends public
  headlines and advisories.

## Setup

### 1. Keys (all free)

| Key | Where to get it | Required? |
|---|---|---|
| Slack webhook URL | api.slack.com/apps → Create app → Incoming Webhooks → add to your channel | yes |
| Gemini API key | aistudio.google.com → Get API key | recommended |
| NVD API key | nvd.nist.gov/developers/request-an-api-key | recommended: without it, NVD's rate limit adds ~75 s to each run (12 product queries) |

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
3. **Same page → Variables** (optional): `DIGEST_TIMEZONE` (default `Asia/Kolkata`), `DIGEST_AFTER`
   (local time the digest may go out, default `10:00`), `GEMINI_MODEL`.
4. Set up the hourly trigger (below).
5. **Actions tab → tech-updates → Run workflow** (`auto`) for the first run and check the channel.
   You can also run `poll` or `digest` by hand; a manual `digest` counts as that day's digest.

The first poll looks back 48 hours. It sends at most 5 instant alerts, and anything beyond that goes into
the digest. Running it again right away should post nothing, because those items are now marked as seen.

Manual runs on your machine use the same state format: `npm run auto`, `npm run poll` and
`npm run digest`, with state kept in `state/state.json`.

### 4. Hourly trigger with cron-job.org

1. **Create a token** that can only start this repo's workflows: GitHub → Settings → Developer settings →
   Fine-grained tokens → Generate new token.
   - Repository access: *Only select repositories* → this repo.
   - Permissions → Repository → **Actions: Read and write** (nothing else).
   - Expiration: up to 1 year; set yourself a reminder to renew it.

   It can start or cancel this repo's workflow runs, but it can't read secrets or change code.
2. **Create a cron job** at cron-job.org (free account):
   - URL: `https://api.github.com/repos/<owner>/<repo>/actions/workflows/tech-updates.yml/dispatches`
   - Schedule: every hour (e.g. at minute 15), time zone Asia/Kolkata.
   - Advanced → Request method **POST**, headers:
     - `Authorization: Bearer <token>`
     - `Accept: application/vnd.github+json`
     - `X-GitHub-Api-Version: 2022-11-28`
     - `Content-Type: application/json`
   - Request body: `{"ref":"main","inputs":{"command":"auto"}}`
   - Notifications: on failure. GitHub answers **204 No Content** on success.
3. Press **Test run** and check that a new `workflow_dispatch` run appears in the Actions tab.

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
.github/workflows/        triggers (external + backup cron), state restore/save
```
