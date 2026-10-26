import { describe, expect, it } from 'vitest';
import { extractCves, stripHtml } from '../src/pipeline/normalize.js';

describe('stripHtml', () => {
  it('removes tags and decodes named, decimal and hex entities', () => {
    expect(stripHtml('<p>Tom&#39;s &amp; Jerry&#x27;s <b>fix</b></p>')).toBe("Tom's & Jerry's fix");
  });
});

describe('extractCves', () => {
  it('finds unique, upper-cased CVE ids', () => {
    expect(extractCves('cve-2026-1234 and CVE-2026-1234, CVE-2025-99999')).toEqual(['CVE-2026-1234', 'CVE-2025-99999']);
  });
});
