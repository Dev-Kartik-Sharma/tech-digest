import { createHash } from 'node:crypto';

const ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };

function decodeNumeric(entity: string): string | undefined {
  const code = /^#x[0-9a-f]+$/i.test(entity) ? parseInt(entity.slice(2), 16) : /^#\d+$/.test(entity) ? Number(entity.slice(1)) : NaN;
  return Number.isFinite(code) && code <= 0x10ffff ? String.fromCodePoint(code) : undefined;
}

export function stripHtml(html: string): string {
  return html
    .replace(/<(script|style)[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&(#?\w+);/g, (m, e: string) => ENTITIES[e] ?? decodeNumeric(e) ?? m)
    .replace(/\s+/g, ' ')
    .trim();
}

/** Drops markdown headings and bold/italic markers (GitHub advisory descriptions are markdown). */
export function stripMarkdown(md: string): string {
  return md.replace(/^#{1,6}\s+.*$/gm, ' ').replace(/(\*\*|__)(.*?)\1/g, '$2');
}

export function truncate(s: string, max: number): string {
  return s.length <= max ? s : `${s.slice(0, max - 1).trimEnd()}…`;
}

export function urlId(url: string): string {
  return `url-${createHash('sha256').update(url).digest('hex').slice(0, 16)}`;
}

export function extractCves(s: string): string[] {
  return [...new Set(s.match(/\bCVE-\d{4}-\d{4,}\b/gi)?.map((c) => c.toUpperCase()) ?? [])];
}

export function toIso(date: string | undefined): string {
  const d = date ? new Date(date) : new Date();
  return Number.isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString();
}

export const SNIPPET_MAX = 400;
