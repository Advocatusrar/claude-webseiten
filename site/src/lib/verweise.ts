// Links from content to articles that are not published (drafts or not yet written).
// One rule for the HTML page (Ueberschriften.astro) and the Markdown version
// (markdown.ts): such a link becomes plain text with the note "(Artikel folgt)" and
// turns into a real link as soon as the article is published.
import { pfade, url } from './url';

export const FOLGT = 'Artikel folgt';

const BLOG = url(pfade.blog);
const ZIELGRUPPEN = url(pfade.zielgruppen);

/**
 * True if `href`, found on the page `seitenUrl` (absolute URL), points to an article
 * page /blog/<id>/ (or its Markdown version /blog/<id>.md) whose id is not in
 * `veroeffentlicht`. Never true for the blog index, the target group pages, other
 * files (images etc.) or other sites. Resolving with the page URL also handles
 * nested ids, "./../x/", missing trailing slashes and absolute own-site URLs.
 */
export function zeigtAufFehlendenArtikel(
  href: string,
  seitenUrl: string,
  veroeffentlicht: ReadonlySet<string>,
): boolean {
  let ziel: URL;
  try {
    ziel = new URL(href.trim(), seitenUrl);
  } catch {
    return false;
  }
  if (ziel.origin !== new URL(seitenUrl).origin) return false;
  let pfad: string;
  try {
    pfad = decodeURIComponent(ziel.pathname);
  } catch {
    return false;
  }
  if (!pfad.startsWith(BLOG) || pfad.startsWith(ZIELGRUPPEN)) return false;
  let id = pfad.slice(BLOG.length).replace(/\/+$/, '');
  if (id === '') return false;
  if (id.endsWith('.md')) id = id.slice(0, -'.md'.length);
  else if (/\.[a-z0-9]+$/i.test(id.split('/').pop() ?? '')) return false;
  return !veroeffentlicht.has(id);
}

// --- HTML ----------------------------------------------------------------------------

const ENTITAETEN: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };

function entitaeten(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) => {
    if (e[0] === '#') {
      const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(n) ? String.fromCodePoint(n) : m;
    }
    return ENTITAETEN[e.toLowerCase()] ?? m;
  });
}

/** Value of an attribute in the attribute part of a tag (any quoting), entities decoded. */
export function attribut(attrs: string, name: string): string | undefined {
  const m = attrs.match(new RegExp(`(?:^|\\s)${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'=<>\`]+))`, 'i'));
  return m ? entitaeten(m[1] ?? m[2] ?? m[3] ?? '') : undefined;
}

/** <a ...>text</a>, independent of attribute order and quoting (quoted values may contain ">"). */
const A_TAG = /<a\b((?:[^>"']|"[^"]*"|'[^']*')*)>([\s\S]*?)<\/a\s*>/gi;

/** Replaces links to unpublished articles in rendered HTML with a marked <span>. */
export function htmlOhneFehlendeArtikel(html: string, seitenUrl: string, veroeffentlicht: Iterable<string>): string {
  const ids = new Set(veroeffentlicht);
  return html.replace(A_TAG, (link: string, attrs: string, text: string) => {
    const href = attribut(attrs, 'href');
    if (href === undefined || !zeigtAufFehlendenArtikel(href, seitenUrl, ids)) return link;
    return `<span class="folgt">${text} (${FOLGT})</span>`;
  });
}

// --- Markdown ------------------------------------------------------------------------

/**
 * Applies `fn` to Markdown outside of fenced code blocks and inline code. Code is
 * swapped for placeholders first, so links whose text contains inline code still match.
 */
export function ausserhalbVonCode(md: string, fn: (text: string) => string): string {
  const code: string[] = [];
  const merken = (s: string) => `\uE000${code.push(s) - 1}\uE001`;
  const zeilen = md.split('\n');
  const ohneBloecke: string[] = [];
  let zaun: string | null = null;
  let block: string[] = [];
  for (const zeile of zeilen) {
    const m = zeile.match(/^ {0,3}(`{3,}|~{3,})/);
    if (zaun === null && m) {
      zaun = m[1];
      block = [zeile];
    } else if (zaun !== null) {
      block.push(zeile);
      const ende = zeile.match(/^ {0,3}(`{3,}|~{3,})\s*$/);
      if (ende && ende[1][0] === zaun[0] && ende[1].length >= zaun.length) {
        ohneBloecke.push(merken(block.join('\n')));
        zaun = null;
      }
    } else {
      ohneBloecke.push(zeile);
    }
  }
  if (zaun !== null) ohneBloecke.push(merken(block.join('\n')));
  const geschuetzt = ohneBloecke.join('\n').replace(/(`+)(?!`)[\s\S]*?[^`]\1(?!`)/g, merken);
  return fn(geschuetzt).replace(/\uE000(\d+)\uE001/g, (_, i: string) => code[Number(i)]);
}

const TITEL = String.raw`(?:\s+(?:"[^"]*"|'[^']*'|\([^)]*\)))?`;
/** Link destination: <in angle brackets> or without spaces, balanced parentheses allowed. */
const ZIEL = String.raw`<[^>\n]*>|[^\s()<>]*(?:\([^\s()]*\)[^\s()<>]*)*`;
/** Link text: no brackets, or one level of nested brackets (e.g. an image). */
const TEXT = String.raw`(?:[^\[\]\\]|\\.|\[[^\[\]]*\])*`;

const INLINE_LINK = new RegExp(String.raw`(?<!!)\[(${TEXT})\]\(\s*(${ZIEL})${TITEL}\s*\)`, 'g');
const REFERENZ = new RegExp(String.raw`^ {0,3}\[([^\]]+)\]:[ \t]*(${ZIEL})${TITEL}[ \t]*$`, 'gm');

const ohneKlammern = (ziel: string) => (ziel.startsWith('<') && ziel.endsWith('>') ? ziel.slice(1, -1) : ziel);
const marke = (s: string) => s.trim().replace(/\s+/g, ' ').toLowerCase();

/**
 * Turns Markdown links to unpublished articles into plain text with "(Artikel folgt)":
 * inline links, reference links with their definitions, and raw HTML <a> tags.
 */
export function markdownOhneFehlendeArtikel(md: string, seitenUrl: string, veroeffentlicht: Iterable<string>): string {
  const ids = new Set(veroeffentlicht);
  const fehlt = (ziel: string) => zeigtAufFehlendenArtikel(ohneKlammern(ziel), seitenUrl, ids);
  return ausserhalbVonCode(md, (text) => {
    const entfernt = new Set<string>();
    let ergebnis = text.replace(REFERENZ, (zeile: string, name: string, ziel: string) => {
      if (!fehlt(ziel)) return zeile;
      entfernt.add(marke(name));
      return '';
    });
    ergebnis = ergebnis.replace(INLINE_LINK, (link: string, linkText: string, ziel: string) =>
      fehlt(ziel) ? `${linkText} (${FOLGT})` : link,
    );
    if (entfernt.size > 0) {
      // [text][name], [name][] and [name]
      ergebnis = ergebnis.replace(
        new RegExp(String.raw`(?<!!)\[(${TEXT})\](?:\[([^\]]*)\])?(?![(:\[])`, 'g'),
        (link: string, linkText: string, name: string | undefined) =>
          entfernt.has(marke(name ? name : linkText)) ? `${linkText} (${FOLGT})` : link,
      );
    }
    return htmlOhneFehlendeArtikel(ergebnis, seitenUrl, ids);
  });
}
