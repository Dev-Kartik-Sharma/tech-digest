import { LIMITS } from '../config/sources.js';
import { truncate } from '../pipeline/normalize.js';
import { CATEGORIES, PRIORITIES, type Category, type Priority, type ScoredItem } from '../types.js';

export interface SlackPayload {
  text: string;
  blocks: Record<string, unknown>[];
}

const EMOJI: Record<Priority, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };

const CATEGORY_LABEL: Record<Category, string> = {
  'vuln-php': 'PHP vulnerability',
  'vuln-js': 'JS / Node vulnerability',
  'vuln-python': 'Python vulnerability',
  'vuln-database': 'Database vulnerability',
  'vuln-web-server': 'Nginx / web server vulnerability',
  'vuln-devops': 'GitHub / GitLab vulnerability',
  'vuln-cloud': 'Cloud (AWS & co.) vulnerability',
  'vuln-ai': 'AI tools vulnerability',
  'exploited-in-wild': 'Exploited in the wild',
  'supply-chain': 'Supply chain',
  'breach-malware': 'Breach / malware',
  'ai-update': 'AI models & tools',
  'release-update': 'Release / update',
  'tech-news': 'Tech news',
};

const MAX_BLOCKS = 50;
const MAX_SECTION_CHARS = 2900;

export const escapeMrkdwn = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const link = (url: string, title: string) => `<${url}|${escapeMrkdwn(title).replace(/\|/g, '¦')}>`;

const section = (text: string) => ({ type: 'section', text: { type: 'mrkdwn', text } });
const context = (text: string) => ({ type: 'context', elements: [{ type: 'mrkdwn', text }] });

export function formatCritical(item: ScoredItem, { escalated = false } = {}): SlackPayload {
  const title = truncate(item.title, 200);
  const label = `${EMOJI.critical} CRITICAL · ${escapeMrkdwn(CATEGORY_LABEL[item.category])}${escalated ? ' · ⬆️ escalated' : ''}`;
  const facts = [
    item.cvss !== undefined ? `*CVSS ${item.cvss.toFixed(1)}*` : undefined,
    item.kev ? '*Actively exploited (CISA KEV)*' : undefined,
    item.aliases.filter((a) => /^(CVE|GHSA)-/.test(a)).join(', ') || undefined,
  ].filter(Boolean);
  const pkgs = (item.packages ?? []).slice(0, 5).map(
    (p) =>
      `• \`${p.name}\`${p.vulnerableRange ? ` ${escapeMrkdwn(truncate(p.vulnerableRange, 200))}` : ''} → fixed in *${escapeMrkdwn(p.patched ?? 'no fix yet')}*`,
  );
  const blocks = [
    context(`*${label}*`),
    section(`*${link(item.url, title)}*\n${escapeMrkdwn(truncate(item.summary ?? item.snippet, 600))}`),
    ...(facts.length ? [context(facts.join('  ·  '))] : []),
    ...(pkgs.length ? [section(`*Affected ${item.ecosystem === 'core' ? 'versions' : 'packages'}*\n${pkgs.join('\n')}`)] : []),
    context(`Source: ${escapeMrkdwn(item.source)}${item.bumpReason ? ` · bumped: ${escapeMrkdwn(item.bumpReason)}` : ''}`),
  ];
  return { text: `${label}: ${escapeMrkdwn(title)}`, blocks };
}

const OLD_AFTER_MS = 2 * 86_400_000;
const shortDate = new Intl.DateTimeFormat('en-GB', { day: 'numeric', month: 'short', timeZone: 'UTC' });

function digestLine(item: ScoredItem, now: Date): string {
  // most items are from the last day; flag the few that aren't (e.g. NVD finishing an older CVE)
  const old = now.getTime() - new Date(item.publishedAt).getTime() > OLD_AFTER_MS;
  const extra = [
    item.cvss !== undefined ? `CVSS ${item.cvss.toFixed(1)}` : '',
    item.kev ? 'KEV' : '',
    old ? `published ${shortDate.format(new Date(item.publishedAt))}` : '',
  ]
    .filter(Boolean)
    .join(', ');
  // long enough to keep the summary's closing "Upgrade X to Y" step
  const summary = truncate(item.summary ?? item.snippet, 240);
  const fix = fixNote(item);
  return `• ${link(item.url, truncate(item.title, 120))}${extra ? ` (${extra})` : ''}${fix ? ` · *${escapeMrkdwn(fix)}*` : ''}${summary ? ` — ${escapeMrkdwn(summary)}` : ''} · _${escapeMrkdwn(item.source)}_`;
}

/** "fix: laravel/framework 13.29.0" / "no fix yet" for vulnerabilities with version info. */
function fixNote(item: ScoredItem): string {
  if (item.kind !== 'vuln' || !item.packages?.length) return '';
  const fixed = item.packages.find((p) => p.patched);
  if (!fixed) return 'no fix yet';
  const others = item.packages.length - 1;
  return `fix: ${fixed.name} ${truncate(fixed.patched!, 60)}${others ? ` (+${others} more)` : ''}`;
}

/** Takes up to `cap` items round-robin across categories (each already in best-first order). */
function fairShare(items: ScoredItem[], cap: number): ScoredItem[] {
  const queues = CATEGORIES.map((c) => items.filter((i) => i.category === c)).filter((q) => q.length);
  const out: ScoredItem[] = [];
  for (let round = 0; out.length < cap && queues.some((q) => q.length > round); round++) {
    for (const q of queues) if (q[round] && out.length < cap) out.push(q[round]!);
  }
  return out;
}

/** Packs lines into as few ≤ MAX_SECTION_CHARS sections as possible. */
function packSections(heading: string, lines: string[]): string[] {
  const out: string[] = [];
  let current = heading;
  for (const line of lines) {
    if (current.length + line.length + 1 > MAX_SECTION_CHARS) {
      out.push(current);
      current = line;
    } else {
      current += `\n${line}`;
    }
  }
  out.push(current);
  return out;
}

export function formatDigest(
  items: ScoredItem[],
  date: string,
  caps: Partial<Record<Priority, number>> = LIMITS.digestCaps,
  now = new Date(),
): SlackPayload | null {
  if (!items.length) return null;

  const counts = PRIORITIES.map((p) => [p, items.filter((i) => i.priority === p).length] as const).filter(([, n]) => n);
  const summaryText = counts.map(([p, n]) => `${n} ${p}`).join(' · ');

  // every block remembers how many item lines it carries, so truncation can be reported
  const candidates: { block: Record<string, unknown>; lines: number }[] = [];
  let selected = 0;
  for (const priority of PRIORITIES) {
    const all = items
      .filter((i) => i.priority === priority)
      .sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0) || b.publishedAt.localeCompare(a.publishedAt));
    if (!all.length) continue;
    const shown = fairShare(all, caps[priority] ?? Infinity);
    selected += shown.length;

    candidates.push({ block: { type: 'divider' }, lines: 0 });
    candidates.push({ block: section(`*${EMOJI[priority]} ${priority.toUpperCase()}*`), lines: 0 });
    for (const category of CATEGORIES) {
      const lines = shown.filter((i) => i.category === category).map((i) => digestLine(i, now));
      if (!lines.length) continue;
      for (const text of packSections(`*${escapeMrkdwn(CATEGORY_LABEL[category])}*`, lines)) {
        candidates.push({ block: section(text), lines: text.split('\n• ').length - 1 + (text.startsWith('• ') ? 1 : 0) });
      }
    }
    if (all.length > shown.length) {
      candidates.push({ block: context(`…and ${all.length - shown.length} more ${priority} items`), lines: 0 });
    }
  }

  const blocks: Record<string, unknown>[] = [
    { type: 'header', text: { type: 'plain_text', text: `🛡️ Tech & Security Digest — ${date}` } },
    context(summaryText),
  ];
  const budget = MAX_BLOCKS - 1; // room for the "not shown" note
  let included = 0;
  for (const c of candidates) {
    if (blocks.length >= budget) break;
    blocks.push(c.block);
    included += c.lines;
  }
  if (included < selected) blocks.push(context(`…${selected - included} more items not shown (Slack message limit)`));
  return { text: `Tech & Security Digest ${date}: ${summaryText}`, blocks };
}
