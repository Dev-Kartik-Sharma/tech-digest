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
  'vuln-services': 'Third-party services (APIs & SDKs)',
  'vuln-devops': 'Infrastructure vulnerability',
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

const TOP_CARDS = 3;

/** Highest CVSS first, then vulnerabilities with a known fix (actionable). */
const mostUrgent = (a: ScoredItem, b: ScoredItem) =>
  (b.cvss ?? 0) - (a.cvss ?? 0) || Number(fixNote(b).startsWith('fix:')) - Number(fixNote(a).startsWith('fix:'));

const dayLabel = (date: string) =>
  new Intl.DateTimeFormat('en-GB', { weekday: 'short', day: 'numeric', month: 'short', timeZone: 'UTC' })
    .format(new Date(`${date}T12:00:00Z`))
    .replace(',', '');

/**
 * The brief's featured items: the day's criticals (even if already alerted), topped up with High,
 * then Medium. Without any critical, one slot goes to the top AI item so it isn't all vulnerabilities.
 */
function pickCards(items: ScoredItem[]): ScoredItem[] {
  const of = (p: Priority, skip?: ScoredItem) => items.filter((i) => i.priority === p && i !== skip).sort(mostUrgent);
  // High before Medium; within each, spread across categories so one busy feed can't take every slot
  const fill = (n: number, skip?: ScoredItem) => {
    const highs = fairShare(of('high', skip), n);
    return [...highs, ...fairShare(of('medium', skip), n - highs.length)];
  };

  const criticals = of('critical').slice(0, TOP_CARDS);
  if (criticals.length) return [...criticals, ...fill(TOP_CARDS - criticals.length)];

  const ai = [...of('high'), ...of('medium')].find((i) => i.category === 'ai-update');
  return ai ? [...fill(TOP_CARDS - 1, ai), ai] : fill(TOP_CARDS);
}

/** One featured item, laid out like a critical alert: label, linked title, AI summary, key facts. */
function briefCard(item: ScoredItem): Record<string, unknown>[] {
  const facts = [
    item.cvss !== undefined ? `*CVSS ${item.cvss.toFixed(1)}*` : '',
    item.kev ? '*Actively exploited*' : '',
    escapeMrkdwn(fixNote(item)),
    escapeMrkdwn(item.source),
    item.holdReason ? `Not alerted instantly: ${escapeMrkdwn(item.holdReason)}` : '',
  ].filter(Boolean);
  return [
    context(`*${EMOJI[item.priority]} ${item.priority.toUpperCase()} · ${escapeMrkdwn(CATEGORY_LABEL[item.category])}*`),
    section(`*${link(item.url, truncate(item.title, 150))}*\n${escapeMrkdwn(truncate(item.summary ?? item.snippet, 350))}`),
    context(facts.join('  ·  ')),
  ];
}

/** The once-a-day Slack message: counts, up to 3 featured cards, and a button to the full brief page. */
export function formatBrief(items: ScoredItem[], date: string, siteUrl: string): SlackPayload | null {
  if (!items.length) return null;

  const counts = PRIORITIES.map((p) => {
    const n = items.filter((i) => i.priority === p).length;
    return n ? `${EMOJI[p]} ${n} ${p}` : '';
  }).filter(Boolean);

  const cards = pickCards(items);
  const more = items.length - cards.length;
  const hasCritical = cards.some((i) => i.priority === 'critical');

  const blocks: Record<string, unknown>[] = [
    section(`*🛡️ Sentinel brief · ${dayLabel(date)}*\n${counts.join(' · ')}`),
    ...(cards.length ? [{ type: 'divider' }, section(`*${hasCritical ? 'Top critical' : 'Top picks'}*`)] : []),
    ...cards.flatMap((c, i) => [...(i ? [{ type: 'divider' }] : []), ...briefCard(c)]),
    { type: 'divider' },
    {
      type: 'actions',
      elements: [
        { type: 'button', text: { type: 'plain_text', text: "Open today's brief →" }, url: `${siteUrl}?day=${date}`, style: 'primary' },
      ],
    },
    ...(more > 0 ? [context(`+${more} more updates on the brief page`)] : []),
  ];
  return { text: `Sentinel brief ${date}: ${counts.join(' · ')}`, blocks, unfurl_links: false, unfurl_media: false };
}
