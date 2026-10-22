// Helpers for internal links. Every internal link goes through url() so the
// base path (BASE_PATH, see adresse.mjs) and trailingSlash: 'always'
// are respected.

const RAW_BASE = import.meta.env.BASE_URL || '/';
export const BASE = RAW_BASE.endsWith('/') ? RAW_BASE : `${RAW_BASE}/`;

/** True if the last path segment looks like a file name (has an extension). */
function istDatei(pfad: string): boolean {
  const letzter = pfad.split('/').pop() ?? '';
  return /\.[a-z0-9]+$/i.test(letzter);
}

/**
 * Internal path including the base path.
 * url('') -> '/'
 * url('blog') -> '/blog/'
 * url('vergleichstest/#rechner') -> '/vergleichstest/#rechner'
 * url('blog/artikel.md') -> '/blog/artikel.md'
 */
export function url(pfad = ''): string {
  const ankerPos = pfad.indexOf('#');
  let teil = ankerPos >= 0 ? pfad.slice(0, ankerPos) : pfad;
  const anker = ankerPos >= 0 ? pfad.slice(ankerPos) : '';
  teil = teil.replace(/^\/+/, '');
  if (teil && !teil.endsWith('/') && !istDatei(teil)) teil += '/';
  return `${BASE}${teil}${anker}`;
}

/** Absolute URL including domain, e.g. for canonical, JSON-LD and llms.txt. */
export function absoluteUrl(pfad = '', site: string | URL | undefined = import.meta.env.SITE): string {
  return new URL(url(pfad), site ?? 'http://localhost').href;
}

export const pfade = {
  start: '',
  vergleichstest: 'vergleichstest/',
  rechner: 'vergleichstest/#rechner',
  blog: 'blog/',
  kontakt: 'kontakt/',
  impressum: 'impressum/',
  datenschutz: 'datenschutz/',
  artikel: (id: string) => `blog/${id}/`,
  artikelMarkdown: (id: string) => `blog/${id}.md`,
  /** Folder of the target group pages (not an article). */
  zielgruppen: 'blog/zielgruppe/',
  zielgruppe: (z: string) => `blog/zielgruppe/${z}/`,
} as const;

/** Removes the base path from a pathname so pages can compare their location. */
export function ohneBasis(pathname: string): string {
  const p = pathname.endsWith('/') ? pathname : `${pathname}/`;
  return p.startsWith(BASE) ? p.slice(BASE.length) : p.replace(/^\/+/, '');
}
