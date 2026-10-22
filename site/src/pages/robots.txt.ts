// robots.txt with the sitemap address of the current build (SITE_URL, BASE_PATH).
// Crawlers only read it at the root of a domain. Everything is allowed, including AI crawlers.
import type { APIRoute } from 'astro';
import { absoluteUrl } from '../lib/url';

export const GET: APIRoute = () =>
  new Response(`User-agent: *\nAllow: /\n\nSitemap: ${absoluteUrl('sitemap-index.xml')}\n`, {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
