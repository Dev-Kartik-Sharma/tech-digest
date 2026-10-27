// Sentinel brief page. Plain JS, no dependencies.
// Feed text only ever reaches the DOM as text nodes / attributes (never innerHTML).

const PRIORITIES = ['critical', 'high', 'medium', 'low'];
const PRIORITY_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };

const $ = (id) => document.getElementById(id);

/** Tiny element builder: strings become text nodes. */
function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null) continue;
    // ARIA states need literal "true"/"false"; other booleans are presence attributes (disabled, selected)
    if (k.startsWith('aria-')) el.setAttribute(k, String(v));
    else if (v === false) continue;
    else if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat(Infinity)) {
    if (c === undefined || c === null || c === false) continue;
    el.append(c instanceof Node ? c : String(c));
  }
  return el;
}

const state = {
  index: null,
  data: null,
  day: null,
  priorities: new Set(),
  categories: new Set(),
  q: '',
};

const labels = () => new Map((state.index?.categories ?? []).map((c) => [c.id, c.label]));

// ---------- URL state ----------

function readUrl() {
  const p = new URLSearchParams(location.search);
  state.day = p.get('day');
  state.priorities = new Set((p.get('p') ?? '').split(',').filter((x) => PRIORITIES.includes(x)));
  state.categories = new Set((p.get('c') ?? '').split(',').filter(Boolean));
  state.q = p.get('q') ?? '';
}

function writeUrl() {
  const p = new URLSearchParams();
  if (state.day && state.day !== state.index?.days[0]?.date) p.set('day', state.day);
  if (state.priorities.size) p.set('p', [...state.priorities].join(','));
  if (state.categories.size) p.set('c', [...state.categories].join(','));
  if (state.q) p.set('q', state.q);
  const qs = p.toString();
  history.replaceState(null, '', qs ? `?${qs}` : location.pathname);
}

// ---------- data ----------

async function getJson(path) {
  const res = await fetch(path, { cache: 'no-cache' });
  if (!res.ok) throw new Error(`${path}: ${res.status}`);
  return res.json();
}

async function loadDay(date) {
  state.day = date;
  $('status').textContent = 'Loading…';
  $('list').replaceChildren();
  try {
    state.data = await getJson(`data/${date}.json`);
    $('status').textContent = '';
  } catch {
    state.data = null;
    $('status').textContent = 'Could not load this day. Try again in a minute.';
  }
  render();
}

// ---------- formatting ----------

const dayTitle = (date) =>
  new Intl.DateTimeFormat(undefined, { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' }).format(
    new Date(`${date}T12:00:00Z`),
  );
const dayShort = (date) =>
  new Intl.DateTimeFormat(undefined, { weekday: 'short', day: 'numeric', month: 'short', timeZone: 'UTC' }).format(
    new Date(`${date}T12:00:00Z`),
  );
const timeOf = (iso) => new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' }).format(new Date(iso));
const shortDate = (iso) => new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short' }).format(new Date(iso));
const cvssClass = (s) => (s >= 9 ? 'cvss-critical' : s >= 7 ? 'cvss-high' : s >= 4 ? 'cvss-medium' : '');

// ---------- filtering ----------

function matches(item) {
  if (state.priorities.size && !state.priorities.has(item.priority)) return false;
  if (state.categories.size && !state.categories.has(item.category)) return false;
  if (!state.q) return true;
  const hay = [item.title, item.summary, item.source, item.fix, ...(item.ids ?? []), ...(item.affected ?? []).map((a) => a.name)]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
  return state.q
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .every((w) => hay.includes(w));
}

// ---------- rendering ----------

function renderHeader() {
  const days = state.index.days;
  const select = $('day');
  select.replaceChildren(...days.map((d) => h('option', { value: d.date, selected: d.date === state.day }, dayShort(d.date))));
  const i = days.findIndex((d) => d.date === state.day);
  $('prev').disabled = i < 0 || i >= days.length - 1;
  $('next').disabled = i <= 0;

  $('heading').textContent = dayTitle(state.day);
  const meta = days[i];
  const total = meta ? Object.values(meta.counts).reduce((a, b) => a + b, 0) : 0;
  $('updated').textContent = meta ? `${total} updates · published ${timeOf(meta.generatedAt)}` : '';
  document.title = `Sentinel brief · ${dayShort(state.day)}`;
}

function renderTiles(items) {
  const tiles = PRIORITIES.map((p) => {
    const ofP = items.filter((i) => i.priority === p);
    const alerted = ofP.filter((i) => i.alerted).length;
    return h(
      'button',
      {
        class: `tile p-${p}`,
        type: 'button',
        'aria-pressed': state.priorities.has(p),
        disabled: !ofP.length,
        onclick: () => toggle(state.priorities, p),
      },
      h('span', { class: 'count' }, ofP.length),
      h('span', { class: 'label' }, PRIORITY_LABEL[p]),
      p === 'critical' && alerted ? h('span', { class: 'note' }, 'alerted in Slack') : null,
    );
  });
  $('tiles').replaceChildren(...tiles);
}

function renderChips(items) {
  const counts = new Map();
  for (const i of items) counts.set(i.category, (counts.get(i.category) ?? 0) + 1);
  const chips = (state.index.categories ?? [])
    .filter((c) => counts.has(c.id))
    .map((c) =>
      h(
        'button',
        { class: 'chip', type: 'button', 'aria-pressed': state.categories.has(c.id), onclick: () => toggle(state.categories, c.id) },
        c.label,
        h('span', { class: 'n' }, counts.get(c.id)),
      ),
    );
  const filtered = state.priorities.size || state.categories.size || state.q;
  if (filtered) chips.push(h('button', { class: 'chip clear', type: 'button', onclick: clearFilters }, 'Clear filters'));
  $('chips').replaceChildren(...chips);
}

function card(item) {
  const fix = item.fix
    ? item.fix.startsWith('fix:')
      ? h('p', { class: 'fix' }, `✓ Fix available: ${item.fix.slice(4).trim()}`)
      : h('p', { class: 'fix nofix' }, '⚠ No fix released yet')
    : null;
  const affected = item.affected?.length
    ? h(
        'details',
        {},
        h('summary', {}, 'Affected versions'),
        h(
          'ul',
          {},
          item.affected.map((a) =>
            h('li', {}, h('code', {}, a.name), a.range ? ` ${a.range}` : '', a.patched ? ` → fixed in ${a.patched}` : ' → no fix yet'),
          ),
        ),
      )
    : null;
  const title = item.url
    ? h('a', { href: item.url, target: '_blank', rel: 'noopener noreferrer' }, item.title)
    : h('span', {}, item.title);

  return h(
    'article',
    { class: `card p-${item.priority}` },
    h(
      'div',
      { class: 'card-meta' },
      typeof item.cvss === 'number' ? h('span', { class: `badge ${cvssClass(item.cvss)}` }, `CVSS ${item.cvss.toFixed(1)}`) : null,
      item.kev ? h('span', { class: 'badge kev' }, 'Actively exploited') : null,
      item.alerted ? h('span', { class: 'badge alerted' }, 'Alerted in Slack') : null,
    ),
    h('h4', { class: 'card-title' }, title),
    item.summary ? h('p', { class: 'summary' }, item.summary) : null,
    fix,
    affected,
    h(
      'div',
      { class: 'card-foot' },
      h('span', {}, item.source),
      h('span', {}, shortDate(item.publishedAt)),
      item.ids?.length ? h('span', { class: 'ids' }, item.ids.join(' · ')) : null,
    ),
  );
}

function renderList(items) {
  const shown = items.filter(matches);
  const byLabel = labels();
  const order = (state.index.categories ?? []).map((c) => c.id);
  const sections = [];
  for (const p of PRIORITIES) {
    const ofP = shown.filter((i) => i.priority === p);
    if (!ofP.length) continue;
    const groups = order.filter((c) => ofP.some((i) => i.category === c));
    sections.push(
      h(
        'section',
        { class: `priority-section p-${p}`, 'aria-label': `${PRIORITY_LABEL[p]} priority` },
        h('h2', {}, h('span', { class: 'dot', 'aria-hidden': 'true' }), PRIORITY_LABEL[p], h('span', { class: 'n' }, ofP.length)),
        groups.map((c) => [
          h('h3', { class: 'cat-heading' }, byLabel.get(c) ?? c),
          ofP
            .filter((i) => i.category === c)
            .sort((a, b) => (b.cvss ?? 0) - (a.cvss ?? 0))
            .map(card),
        ]),
      ),
    );
  }
  if (!sections.length) {
    sections.push(
      h(
        'div',
        { class: 'empty' },
        items.length ? 'Nothing matches these filters. ' : 'No updates on this day.',
        items.length ? h('button', { class: 'chip clear', type: 'button', onclick: clearFilters }, 'Clear filters') : null,
      ),
    );
  }
  $('list').replaceChildren(...sections);
}

function render() {
  renderHeader();
  const items = state.data?.items ?? [];
  renderTiles(items);
  renderChips(items);
  renderList(items);
  writeUrl();
}

// ---------- interactions ----------

function toggle(set, value) {
  if (set.has(value)) set.delete(value);
  else set.add(value);
  render();
}

function clearFilters() {
  state.priorities.clear();
  state.categories.clear();
  state.q = '';
  $('search').value = '';
  render();
}

function step(delta) {
  const days = state.index.days;
  const i = days.findIndex((d) => d.date === state.day);
  const next = days[i + delta];
  if (next) loadDay(next.date);
}

let searchTimer;
$('search').addEventListener('input', (e) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    state.q = e.target.value.trim();
    renderChips(state.data?.items ?? []);
    renderList(state.data?.items ?? []);
    writeUrl();
  }, 120);
});
$('day').addEventListener('change', (e) => loadDay(e.target.value));
$('prev').addEventListener('click', () => step(1));
$('next').addEventListener('click', () => step(-1));

// ---------- start ----------

(async function start() {
  readUrl();
  $('search').value = state.q;
  try {
    state.index = await getJson('data/days.json');
  } catch {
    $('heading').textContent = 'Sentinel brief';
    $('status').textContent = 'Could not load the brief. Try again in a minute.';
    return;
  }
  if (!state.index.days.length) {
    $('heading').textContent = 'No briefs yet';
    $('status').textContent = 'The first brief appears after the next daily digest.';
    return;
  }
  const known = state.index.days.some((d) => d.date === state.day);
  await loadDay(known ? state.day : state.index.days[0].date);
})();
