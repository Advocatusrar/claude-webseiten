import type { APIRequestContext } from '@playwright/test';

/**
 * All page paths from the sitemap, relative to the base URL of the test run.
 * The sitemap contains absolute URLs with the configured SITE_URL; only the path counts.
 */
export async function seitenAusSitemap(request: APIRequestContext): Promise<string[]> {
  const index = await (await request.get('sitemap-index.xml')).text();
  const pfade: string[] = [];
  for (const [, sitemapUrl] of index.matchAll(/<loc>([^<]+)<\/loc>/g)) {
    const sitemap = await (await request.get(new URL(sitemapUrl).pathname)).text();
    for (const [, seite] of sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)) pfade.push(new URL(seite).pathname);
  }
  return pfade;
}
