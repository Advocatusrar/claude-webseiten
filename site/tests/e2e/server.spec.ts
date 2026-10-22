// Only for the production web server (Docker image): status codes, security headers,
// caching. Skipped against "astro preview", which does not set these headers.
import { expect, test } from '@playwright/test';

test.skip(!process.env.E2E_BASE_URL, 'nur gegen den Webserver im Docker-Image');

test('sends security headers', async ({ request }) => {
  const antwort = await request.get('');
  expect(antwort.status()).toBe(200);
  const h = antwort.headers();
  expect(h['content-security-policy']).toContain("default-src 'self'");
  expect(h['x-content-type-options']).toBe('nosniff');
  expect(h['referrer-policy']).toBe('strict-origin-when-cross-origin');
  expect(h['permissions-policy']).toBeTruthy();
  expect(h['server'] ?? '').not.toMatch(/\d/);
});

test('answers unknown paths with the 404 page', async ({ request }) => {
  const antwort = await request.get('gibt-es-nicht/');
  expect(antwort.status()).toBe(404);
  expect(await antwort.text()).toContain('<h1');
});

test('serves Markdown, llms.txt and the health check with the right types', async ({ request }) => {
  expect((await request.get('llms.txt')).headers()['content-type']).toMatch(/^text\/plain/);
  const artikel = (await (await request.get('llms.txt')).text()).match(/\((https?:\/\/[^)]+\.md)\)/);
  if (artikel) {
    const md = await request.get(new URL(artikel[1]).pathname);
    expect(md.headers()['content-type']).toMatch(/^text\/markdown/);
  }
  expect((await request.get('healthz')).status()).toBe(200);
});

test('caches fingerprinted assets for a long time and pages not', async ({ request }) => {
  const html = await (await request.get('')).text();
  const asset = html.match(/(?:href|src)="([^"]*\/_astro\/[^"]+)"/);
  test.skip(!asset, 'keine Assets unter /_astro/');
  const a = await request.get(asset![1]);
  expect(a.headers()['cache-control']).toContain('immutable');
  expect((await request.get('')).headers()['cache-control']).toContain('no-cache');
});
