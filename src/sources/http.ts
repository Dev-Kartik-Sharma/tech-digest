import { LIMITS } from '../config/sources.js';

const USER_AGENT = 'tech-updates-bot/0.1 (+https://github.com/Dev-Kartik-Sharma/tech-updates-for-slack)';

async function get(url: string, headers: Record<string, string>): Promise<Response> {
  const res = await fetch(url, {
    headers: { 'User-Agent': USER_AGENT, ...headers },
    signal: AbortSignal.timeout(LIMITS.fetchTimeoutMs),
  });
  if (!res.ok) throw new Error(`GET ${url} → ${res.status} ${res.statusText}`);
  return res;
}

export async function fetchText(url: string, headers: Record<string, string> = {}): Promise<string> {
  return (await get(url, headers)).text();
}

/** JSON body plus the `Link` header, for APIs that paginate with cursors. */
export async function fetchJsonPage<T>(url: string, headers: Record<string, string> = {}) {
  const res = await get(url, { Accept: 'application/json', ...headers });
  return { data: (await res.json()) as T, link: res.headers.get('link') };
}

export async function fetchJson<T = unknown>(url: string, headers: Record<string, string> = {}): Promise<T> {
  return JSON.parse(await fetchText(url, { Accept: 'application/json', ...headers })) as T;
}
