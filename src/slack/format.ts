import { truncate } from '../pipeline/normalize.js';
import { CATEGORIES, PRIORITIES, type Category, type Priority, type ScoredItem } from '../types.js';

export interface SlackPayload {
  text: string;
  blocks: Record<string, unknown>[];
  unfurl_links?: boolean;
  unfurl_media?: boolean;
}

const EMOJI: Record<Priority, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };

export const CATEGORY_LABEL: Record<Category, string> = {
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

export const escapeMrkdwn = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const link = (url: string, title: string) => `<${url}|${escapeMrkdwn(title).replace(/\|/g, '¦')}>`;

const section = (text: string) => ({ type: 'section', text: { type: 'mrkdwn', text } });
const context = (text: string) => ({ type: 'context', elements: [{ type: 'mrkdwn', text }] });

export function formatCritical(item: ScoredItem, { escalated = false, siteUrl }: { escalated?: boolean; siteUrl?: string } = {}): SlackPayload {
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
    context(
      `Source: ${escapeMrkdwn(item.source)}${item.bumpReason ? ` · bumped: ${escapeMrkdwn(item.bumpReason)}` : ''}` +
        (siteUrl ? ` · <${siteUrl}|Sentinel brief page →>` : ''),
    ),
  ];
  return { text: `${label}: ${escapeMrkdwn(title)}`, blocks, unfurl_links: false, unfurl_media: false };
}

/** "fix: laravel/framework 13.29.0" / "no fix yet" for vulnerabilities with version info. */
export function fixNote(item: ScoredItem): string {
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

/** Short tech-area tags for one-line brief entries. */
const AREA: Record<Category, string> = {
  'vuln-php': 'PHP',
  'vuln-js': 'JS',
  'vuln-python': 'Python',
  'vuln-database': 'DB',
  'vuln-web-server': 'Nginx',
  'vuln-devops': 'GitHub/GitLab',
  'vuln-cloud': 'Cloud',
  'vuln-ai': 'AI tools',
  'exploited-in-wild': 'Exploited',
  'supply-chain': 'Supply chain',
  'breach-malware': 'Breach',
  'ai-update': 'AI',
  'release-update': 'Release',
  'tech-news': 'Tech',
};

const TOP_ITEMS = 5;

/** Vulnerabilities with a known fix first (actionable), then by CVSS. */
const actionableFirst = (a: ScoredItem, b: ScoredItem) =>
  Number(fixNote(b).startsWith('fix:')) - Number(fixNote(a).startsWith('fix:')) || (b.cvss ?? 0) - (a.cvss ?? 0);

const dayLabel = (date: string) =>
  new Intl.DateTimeFormat('en-GB', { weekday: 'short', day: 'numeric', month: 'short', timeZone: 'UTC' })
    .format(new Date(`${date}T12:00:00Z`))
    .replace(',', '');

/**
 * The once-a-day Slack message: counts, the top few items, and a button to the full brief page.
 * Criticals that were already alerted are only counted.
 */
export function formatBrief(items: ScoredItem[], date: string, siteUrl: string): SlackPayload | null {
  if (!items.length) return null;

  const counts = PRIORITIES.map((p) => {
    const ofP = items.filter((i) => i.priority === p);
    if (!ofP.length) return '';
    const alerted = ofP.filter((i) => i.alertedAt).length;
    const note = !alerted ? '' : alerted === ofP.length ? ' (already alerted)' : ` (${alerted} already alerted)`;
    return `${EMOJI[p]} ${ofP.length} ${p}${note}`;
  }).filter(Boolean);

  const unalertedCriticals = items.filter((i) => i.priority === 'critical' && !i.alertedAt).sort(actionableFirst);
  const highs = items.filter((i) => i.priority === 'high').sort(actionableFirst);
  const top = [...unalertedCriticals, ...fairShare(highs, TOP_ITEMS)].slice(0, TOP_ITEMS);
  const lines = top.map((i) => {
    const fix = fixNote(i);
    return `• ${i.priority === 'critical' ? '🔴 ' : ''}${AREA[i.category]} · ${link(i.url, truncate(i.title, 110))}${fix ? ` · ${escapeMrkdwn(fix)}` : ''}`;
  });

  const title = `🛡️ Sentinel brief · ${dayLabel(date)}`;
  const blocks: Record<string, unknown>[] = [
    section(`*${title}*\n${counts.join(' · ')}`),
    ...(lines.length ? [section(`*Top ${unalertedCriticals.length ? 'items' : 'high-priority'}*\n${lines.join('\n')}`)] : []),
    {
      type: 'actions',
      elements: [
        { type: 'button', text: { type: 'plain_text', text: "Open today's brief →" }, url: `${siteUrl}?day=${date}`, style: 'primary' },
      ],
    },
  ];
  return { text: `Sentinel brief ${date}: ${counts.join(' · ')}`, blocks, unfurl_links: false, unfurl_media: false };
}
