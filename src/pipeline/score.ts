import { MAJOR_PACKAGES, POPULARITY, SIGNALS, STACK_KEYWORDS } from '../config/sources.js';
import type { Category, Ecosystem, Item, Priority, ScoredItem, Stack } from '../types.js';

const ECOSYSTEM_STACK: Record<Ecosystem, Stack> = {
  'npm': 'js',
  'composer': 'php',
  'php-core': 'php',
  'node-core': 'js',
  'mongodb': 'js',
};

const CORE: Ecosystem[] = ['php-core', 'node-core', 'mongodb'];

const text = (item: Item) => `${item.title}\n${item.snippet}`;

export function detectStack(item: Item): Stack | undefined {
  if (item.ecosystem) return ECOSYSTEM_STACK[item.ecosystem];
  if (item.feedStack) return item.feedStack;
  const t = text(item);
  // php first: "PHP" headlines often also mention JavaScript, rarely the other way round
  if (STACK_KEYWORDS.php.some((re) => re.test(t))) return 'php';
  if (STACK_KEYWORDS.js.some((re) => re.test(t))) return 'js';
  return undefined;
}

const isRce = (item: Item) =>
  SIGNALS.rce.test(text(item)) || (item.cwes ?? []).some((c) => SIGNALS.rceCwes.includes(c));

/** true / false when we can tell, undefined when popularity is unknown. */
function isPopular(item: Item): boolean | undefined {
  if (item.packages?.some((p) => MAJOR_PACKAGES.has(p.name))) return true;
  if (item.downloads === undefined) return undefined;
  const eco = item.ecosystem === 'composer' ? 'composer' : 'npm';
  return item.downloads >= POPULARITY.popular[eco];
}

function belowFloor(item: Item): boolean {
  if (item.downloads === undefined || item.packages?.some((p) => MAJOR_PACKAGES.has(p.name))) return false;
  const eco = item.ecosystem === 'composer' ? 'composer' : 'npm';
  return item.downloads < POPULARITY.floor[eco];
}

function scoreVuln(item: Item): ScoredItem | null {
  const stack = detectStack(item);
  if (!stack) {
    return item.kev ? { ...item, priority: 'high', category: 'exploited-in-wild' } : null;
  }
  if (!item.kev && belowFloor(item)) return null;

  const category: Category = stack === 'php' ? 'vuln-php' : 'vuln-js';
  const cvss = item.cvss ?? 0;
  const core = item.ecosystem !== undefined && CORE.includes(item.ecosystem);
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
  if (stack && SIGNALS.security.test(t) && (item.feedKind === 'release' || isRce(item))) {
    return stack === 'php' ? 'vuln-php' : 'vuln-js';
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
