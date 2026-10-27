import { describe, expect, it } from 'vitest';
import { siteUrl } from '../src/env.js';

describe('siteUrl', () => {
  it('derives the GitHub Pages address from the repository, lower-casing the owner', () => {
    expect(siteUrl(undefined, 'Dev-Kartik-Sharma/tech-digest')).toBe('https://dev-kartik-sharma.github.io/tech-digest/');
  });

  it('prefers an explicit SITE_URL and adds a trailing slash', () => {
    expect(siteUrl('https://brief.example.com', 'a/b')).toBe('https://brief.example.com/');
  });

  it('falls back to a local preview address', () => {
    expect(siteUrl(undefined, undefined)).toBe('http://localhost:8080/');
  });
});
