// @ts-check
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import { BASE_PATH, SITE_URL } from './adresse.mjs';

const DIST = fileURLToPath(new URL('./dist/', import.meta.url));

// Address and base path come from the environment (see adresse.mjs).
/** @type {import('astro').AstroUserConfig} */
const config = defineConfig({
  site: SITE_URL,
  base: BASE_PATH,
  trailingSlash: 'always',
  integrations: [
    sitemap({
      // Only indexable HTML pages: no .md/.txt endpoints, no 404 page, no page with
      // <meta name="robots" content="noindex"> (e.g. a target group without articles).
      filter: (page) =>
        !/\.(md|txt)$/.test(page) &&
        !/\/404\/?$/.test(page) &&
        !/<meta\s+name="robots"\s+content="[^"]*noindex/i.test(gebauteSeite(page)),
      // lastmod for articles: the date of the last content check (updatedDate ?? stand),
      // taken from article:modified_time of the page. Other pages get no lastmod.
      serialize: (eintrag) => {
        /** @type {RegExpMatchArray | null} */
        const m = gebauteSeite(eintrag.url).match(/<meta\s+property="article:modified_time"\s+content="([^"]+)"/i);
        return m ? { ...eintrag, lastmod: m[1] } : eintrag;
      },
    }),
  ],
});

export default config;

/**
 * The built HTML of a page. The sitemap is written after all pages exist, so it can
 * follow what the pages themselves say (noindex, article:modified_time).
 * @param {string} seite absolute URL of the page
 * @returns {string}
 */
function gebauteSeite(seite) {
  /** @type {string} */
  const base = (config.base ?? '/').replace(/\/+$/, '');
  const pfad = decodeURIComponent(new URL(seite).pathname).slice(base.length).replace(/^\/+/, '');
  const datei = `${DIST}${pfad}${pfad === '' || pfad.endsWith('/') ? 'index.html' : ''}`;
  return existsSync(datei) ? readFileSync(datei, 'utf8') : '';
}
