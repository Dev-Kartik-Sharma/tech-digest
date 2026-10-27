import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseArticle, parseSitemap } from '../src/sources/anthropic.js';

const fixture = (name: string) => readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8');

describe('parseSitemap', () => {
  it('returns news pages modified since the cutoff', () => {
    const urls = parseSitemap(fixture('anthropic-sitemap.xml'), '/news/', new Date('2026-10-25T00:00:00Z'));
    expect(urls).toEqual(['https://www.anthropic.com/news/new-model', 'https://www.anthropic.com/news/old-post-edited']);
  });
});

describe('parseArticle', () => {
  it('reads headline, description, publish date and body text from the page', () => {
    const a = parseArticle(fixture('anthropic-article.html'));
    expect(a).toMatchObject({ title: 'Introducing Claude Example 6', publishedAt: '2026-10-26T00:00:00.000Z' });
    expect(a?.text).toMatch(/^Claude Example 6 is our most capable model/);
    expect(a?.text).toContain("Today we're releasing Claude Example 6, which scores 81.2% on SWE-bench Verified");
    expect(a?.text).toContain('Amazon Bedrock');
    expect(a?.text).not.toContain('Skip to main content');
  });

  it('skips a first paragraph that restates the description', () => {
    const html = `<script type="application/ld+json">{"headline":"H","description":"We are donating Agent Skills, the open standard for agents.","datePublished":"2026-10-22"}</script>
      <article><p>Today, we are donating <a href="#">Agent Skills</a>, the open standard for agents, to the foundation.</p><p>More than 70 platforms have integrated it since December.</p></article>`;
    const a = parseArticle(html);
    expect(a?.text).toBe('We are donating Agent Skills, the open standard for agents. More than 70 platforms have integrated it since December.');
  });

  it('returns undefined for a page without article data', () => {
    expect(parseArticle('<html><body>nothing</body></html>')).toBeUndefined();
  });
});
