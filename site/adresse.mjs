// Public address of the site, shared by astro.config.mjs and scripts/check-site.mjs.
// Set at build time, e.g. SITE_URL=https://www.meine-domain.de npm run build
// (the Docker build gets it as build argument, the CI from the repository variable SITE_URL).
// BASE_PATH is only needed if the site does not live at the root of the domain.
// The default is a placeholder: with CHECK_LIVE=1 check-site refuses example.org.

export const SITE_URL = (process.env.SITE_URL || 'https://www.example.org').replace(/\/+$/, '');

const roh = process.env.BASE_PATH || '/';
export const BASE_PATH = `/${roh.replace(/^\/+|\/+$/g, '')}/`.replace(/^\/\/$/, '/');
