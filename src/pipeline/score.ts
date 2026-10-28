import { AI_PACKAGES, MAJOR_PACKAGES, POPULARITY, SIGNALS, STACK_KEYWORDS } from '../config/sources.js';
import { STACKS, type Category, type Ecosystem, type Item, type Priority, type ScoredItem, type Stack } from '../types.js';

const REGISTRY_STACK: Record<Exclude<Ecosystem, 'core'>, Stack> = { npm: 'js', composer: 'php', pip: 'python' };

const text = (item: Item) => `${item.title}\n${item.snippet}`;

export function detectStack(item: Item): Stack | undefined {
  if (item.packages?.some((p) => AI_PACKAGES.has(p.name.toLowerCase()))) return 'ai';
  if (item.ecosystem && item.ecosystem !== 'core') return REGISTRY_STACK[item.ecosystem];
  if (item.stackHint) return item.stackHint;
  const t = text(item);
  // STACKS order decides ties: specific stacks before broad ones like "GitHub" or "AWS"
  return STACKS.find((stack) => STACK_KEYWORDS[stack].some((re) => re.test(t)));
}

const registry = (item: Item) => (item.ecosystem && item.ecosystem !== 'core' ? item.ecosystem : undefined);

/** On CISA KEV or reported as exploited: always worth an instant alert, whatever the AI thinks. */
export const isActivelyExploited = (item: Item & { category?: Category }) =>
  !!item.kev || item.category === 'exploited-in-wild' || SIGNALS.exploited.test(text(item));

const isRce = (item: Item) =>
  SIGNALS.rce.test(text(item)) || (item.cwes ?? []).some((c) => SIGNALS.rceCwes.includes(c));

// registry names are case-insensitive, and GitHub reports some PyPI packages capitalised ("Django")
const hasMajorPackage = (item: Item) => !!item.packages?.some((p) => MAJOR_PACKAGES.has(p.name.toLowerCase()));

/** true / false when we can tell, undefined when popularity is unknown. */
function isPopular(item: Item): boolean | undefined {
  if (hasMajorPackage(item)) return true;
  const eco = registry(item);
  if (item.downloads === undefined || !eco) return undefined;
  return item.downloads >= POPULARITY.popular[eco];
}

function belowFloor(item: Item): boolean {
  const eco = registry(item);
  if (item.downloads === undefined || !eco || hasMajorPackage(item)) return false;
  return item.downloads < POPULARITY.floor[eco];
}

function scoreVuln(item: Item): ScoredItem | null {
  const stack = detectStack(item);
  if (!stack) {
    return item.kev ? { ...item, priority: 'high', category: 'exploited-in-wild' } : null;
  }
  if (!item.kev && belowFloor(item)) return null;

  const category: Category = `vuln-${stack}`;
  const cvss = item.cvss ?? 0;
  const core = item.ecosystem === 'core';
  const prominent = core || isPopular(item) === true;

  let priority: Priority;
  if (item.kev || (cvss >= 9 && prominent) || (isRce(item) && prominent && (cvss >= 7 || !item.cvss))) {
    priority = 'critical';
  } else if (cvss >= 7) {
    priority = 'high';
  } else if (cvss >= 4) {
    priority = 'medium';
  } else {
    priority = 'low';
  }
  return { ...item, priority, category };
}

function newsCategory(item: Item, stack: Stack | undefined): Category {
  const t = text(item);
  if (SIGNALS.supplyChain.test(t)) return 'supply-chain';
  if (SIGNALS.exploited.test(t)) return 'exploited-in-wild';
  // attacks on AI tools and agents: everything from the AI security feeds, and AI stories from
  // general security sites when they're about a flaw or breach (not model launches they also cover)
  const aiSecurityStory =
    SIGNALS.aiSecurity.test(t) ||
    (item.feedKind === 'security-news' && (item.stackHint === 'ai' || SIGNALS.security.test(t) || SIGNALS.breachMalware.test(t)));
  if (stack === 'ai' && aiSecurityStory) return 'vuln-ai';
  if (stack && (isRce(item) || (item.feedKind === 'release' && SIGNALS.security.test(t)))) {
    return `vuln-${stack}`;
  }
  if (SIGNALS.breachMalware.test(t)) {
    // a breach at a provider we integrate with means checking and rotating our keys for it
    return stack === 'services' ? 'vuln-services' : 'breach-malware';
  }
  if (item.feedKind === 'ai-news' || stack === 'ai') return 'ai-update';
  if (item.feedKind === 'release' || (item.feedKind === 'dev-news' && SIGNALS.release.test(t))) {
    return 'release-update';
  }
  return 'tech-news';
}

function scoreNews(item: Item): ScoredItem {
  const t = text(item);
  const stack = detectStack(item);
  const category = newsCategory(item, stack);
  const severe = SIGNALS.exploited.test(t) || isRce(item);

  let priority: Priority = 'low';
  if (item.feedKind === 'release') {
    if (stack && SIGNALS.security.test(t)) priority = 'high';
  } else if (item.feedKind === 'security-news') {
    if (stack && (severe || category === 'supply-chain')) priority = 'high';
    else if (stack || category === 'supply-chain' || SIGNALS.exploited.test(t)) priority = 'medium';
  }
  if (category === 'ai-update' && priority === 'low' && (SIGNALS.aiLaunch.test(t) || SIGNALS.aiDevTools.some((re) => re.test(t)))) {
    priority = 'medium';
  }
  if (category === 'vuln-ai') {
    if (severe || /\bCVE-\d{4}-\d+/i.test(t) || SIGNALS.aiSecurity.test(t)) priority = 'high';
    else if (priority === 'low') priority = 'medium';
  }
  // a real package or maintainer takeover in the focus stacks: everyone may have it installed
  if (category === 'supply-chain' && (stack === 'php' || stack === 'js' || stack === 'ai') && SIGNALS.compromised.test(t)) {
    priority = 'critical';
  }
  return { ...item, priority, category };
}

/** Deterministic priority + category. Returns null when the item is irrelevant. */
export function scoreItem(item: Item): ScoredItem | null {
  return item.kind === 'vuln' ? scoreVuln(item) : scoreNews(item);
}
