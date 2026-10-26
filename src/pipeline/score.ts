import { MAJOR_PACKAGES, POPULARITY, SIGNALS, STACK_KEYWORDS } from '../config/sources.js';
import { STACKS, type Category, type Ecosystem, type Item, type Priority, type ScoredItem, type Stack } from '../types.js';

const REGISTRY_STACK: Record<Exclude<Ecosystem, 'core'>, Stack> = { npm: 'js', composer: 'php', pip: 'python' };

const text = (item: Item) => `${item.title}\n${item.snippet}`;

export function detectStack(item: Item): Stack | undefined {
  if (item.ecosystem && item.ecosystem !== 'core') return REGISTRY_STACK[item.ecosystem];
  if (item.stackHint) return item.stackHint;
  const t = text(item);
  // STACKS order decides ties: specific stacks before broad ones like "GitHub" or "AWS"
  return STACKS.find((stack) => STACK_KEYWORDS[stack].some((re) => re.test(t)));
}

const registry = (item: Item) => (item.ecosystem && item.ecosystem !== 'core' ? item.ecosystem : undefined);

const isRce = (item: Item) =>
  SIGNALS.rce.test(text(item)) || (item.cwes ?? []).some((c) => SIGNALS.rceCwes.includes(c));

/** true / false when we can tell, undefined when popularity is unknown. */
function isPopular(item: Item): boolean | undefined {
  if (item.packages?.some((p) => MAJOR_PACKAGES.has(p.name))) return true;
  const eco = registry(item);
  if (item.downloads === undefined || !eco) return undefined;
  return item.downloads >= POPULARITY.popular[eco];
}

function belowFloor(item: Item): boolean {
  const eco = registry(item);
  if (item.downloads === undefined || !eco || item.packages?.some((p) => MAJOR_PACKAGES.has(p.name))) return false;
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
  if (stack && (isRce(item) || (item.feedKind === 'release' && SIGNALS.security.test(t)))) {
    return `vuln-${stack}`;
  }
  if (SIGNALS.breachMalware.test(t)) return 'breach-malware';
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
  return { ...item, priority, category };
}

/** Deterministic priority + category. Returns null when the item is irrelevant. */
export function scoreItem(item: Item): ScoredItem | null {
  return item.kind === 'vuln' ? scoreVuln(item) : scoreNews(item);
}
