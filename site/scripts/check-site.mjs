#!/usr/bin/env node
// Checks the built site in dist/ without any dependencies.
//  (a) every internal link (href, src, srcset, og:image, og:url) points to an existing file,
//      honouring the base path, trailingSlash 'always' and anchors (#id must exist on the
//      target page); the same for the own-site links in llms.txt and in the Markdown
//      versions (dist/**/*.md, absolute and relative links)
//  (b) no embedded external resources and no tracking: script, stylesheet, icon, preload,
//      preconnect, dns-prefetch, prerender, img, iframe, video, audio, source, track, embed,
//      object, SVG image/use/feImage, the ping attribute, CSS url()/image-set()/@import in
//      CSS files, <style> and style attributes; HTML and SVG files are checked.
//      External <a href> is fine. http(s) addresses in .js files are reported as a hint.
//  (c) every HTML page has exactly one <h1>, lang="de" and exactly one non-empty meta description
//  (d) every application/ld+json block is valid JSON
//  (e) sitemaps: every <loc> exists; page sitemaps only list HTML pages without noindex, no 404
//  (f) drafts (draft: true in src/content/blog) leave no trace: their slug appears in no file in dist
//  (g) placeholders such as [Vorname Nachname], example.org or mailto:[ are hints; with
//      CHECK_LIVE=1 (set by the GitHub Action for the deploy from main) they are errors
// Warnings only (exit code stays 0): skipped heading levels, hints from (b) and (g).
// Exit code 1 on errors.

import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { basename, dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DIST = join(ROOT, 'dist');

// --- site and base: same source as astro.config.mjs (overridable via env) ---
const { SITE_URL, BASE_PATH } = await import('../adresse.mjs');
const SITE = (process.env.CHECK_SITE ?? SITE_URL).replace(/\/+$/, '');
let BASE = process.env.CHECK_BASE ?? BASE_PATH;
BASE = `/${BASE.replace(/^\/+|\/+$/g, '')}/`.replace(/^\/\/$/, '/');
const ORIGIN = new URL(SITE).origin;
const LIVE = process.env.CHECK_LIVE === '1';

if (!existsSync(DIST)) {
  console.error(`dist/ fehlt (${DIST}). Erst "npm run build" ausführen.`);
  process.exit(1);
}

// --- helpers -----------------------------------------------------------------
function dateien(dir) {
  const out = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...dateien(p));
    else out.push(p);
  }
  return out;
}

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", '#39': "'", nbsp: ' ' };
function entities(s) {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+\d*);/gi, (m, e) => {
    if (e[0] === '#') {
      const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(n) ? String.fromCodePoint(n) : m;
    }
    return ENTITIES[e.toLowerCase()] ?? m;
  });
}

/** HTML without comments and without the bodies of script/style elements. */
function bereinigen(html) {
  return html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/(<script\b[^>]*>)[\s\S]*?(<\/script>)/gi, '$1$2')
    .replace(/(<style\b[^>]*>)[\s\S]*?(<\/style>)/gi, '$1$2');
}

/** All tags with their attributes (quoted values may contain ">"). */
function tags(html) {
  const bereinigt = bereinigen(html);
  const out = [];
  const tagRe = /<([a-zA-Z][a-zA-Z0-9-]*)((?:\s+[^\s=\/>"']+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?)*)\s*\/?>/g;
  let m;
  while ((m = tagRe.exec(bereinigt))) {
    const attrs = {};
    const attrRe = /([^\s=\/"'<>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
    let a;
    const rest = m[2] ?? '';
    while ((a = attrRe.exec(rest))) {
      attrs[a[1].toLowerCase()] = entities(a[2] ?? a[3] ?? a[4] ?? '');
    }
    out.push({ name: m[1].toLowerCase(), attrs });
  }
  return out;
}

function istExtern(u) {
  return /^(?:[a-z][a-z0-9+.-]*:)?\/\//i.test(u);
}

function istEigeneSeite(u) {
  try {
    const url = new URL(u, 'http://x');
    return istExtern(u) && url.origin === ORIGIN && url.pathname.startsWith(BASE);
  } catch {
    return false;
  }
}

/** URL path of a file in dist, e.g. dist/blog/a/index.html -> /base/blog/a/ */
function urlPfad(datei) {
  const rel = relative(DIST, datei).split(sep).join('/');
  if (rel === 'index.html') return BASE;
  if (rel.endsWith('/index.html')) return BASE + rel.slice(0, -'index.html'.length);
  return BASE + rel;
}

const idCache = new Map();
function ids(datei) {
  if (!idCache.has(datei)) {
    const set = new Set();
    if (datei.endsWith('.html')) {
      for (const t of tags(readFileSync(datei, 'utf8'))) {
        if (t.attrs.id) set.add(t.attrs.id);
        if (t.name === 'a' && t.attrs.name) set.add(t.attrs.name);
      }
    }
    idCache.set(datei, set);
  }
  return idCache.get(datei);
}

const noindexCache = new Map();
function hatNoindex(datei) {
  if (!noindexCache.has(datei)) {
    const robots = tags(readFileSync(datei, 'utf8')).filter(
      (t) => t.name === 'meta' && (t.attrs.name ?? '').toLowerCase() === 'robots',
    );
    noindexCache.set(
      datei,
      robots.some((t) => /noindex/i.test(t.attrs.content ?? '')),
    );
  }
  return noindexCache.get(datei);
}

/** Resolves an internal URL to a dist file. Returns { datei } or { fehler }. */
function aufloesen(href, seitenPfad) {
  let url;
  try {
    url = new URL(href, `${ORIGIN}${seitenPfad}`);
  } catch {
    return { fehler: 'ungültige URL' };
  }
  if (url.origin !== ORIGIN) return { extern: true };
  let pfad;
  try {
    pfad = decodeURIComponent(url.pathname);
  } catch {
    return { fehler: 'ungültige Kodierung' };
  }
  if (!pfad.startsWith(BASE)) return { fehler: `liegt außerhalb des Basis-Pfads ${BASE}` };
  const rel = pfad.slice(BASE.length);
  const ziel = join(DIST, ...rel.split('/').filter(Boolean));
  let datei;
  if (pfad.endsWith('/')) {
    datei = join(ziel, 'index.html');
    if (!existsSync(datei)) return { fehler: 'Ziel existiert nicht' };
  } else if (existsSync(ziel) && statSync(ziel).isFile()) {
    datei = ziel;
  } else if (existsSync(join(ziel, 'index.html'))) {
    return { fehler: 'Schrägstrich am Ende fehlt (trailingSlash: always)' };
  } else {
    return { fehler: 'Ziel existiert nicht' };
  }
  let anker = '';
  try {
    anker = decodeURIComponent(url.hash.slice(1));
  } catch {
    return { fehler: 'ungültiger Anker' };
  }
  if (anker && !ids(datei).has(anker)) return { fehler: `Anker #${anker} fehlt auf der Zielseite` };
  return { datei };
}

// --- checks --------------------------------------------------------------------
const fehler = [];
const hinweise = [];
const melde = (datei, text) => fehler.push(`${relative(DIST, datei) || datei}: ${text}`);
const hinweis = (datei, text) => hinweise.push(`${relative(DIST, datei) || datei}: ${text}`);

const alle = dateien(DIST);
const html = alle.filter((f) => f.endsWith('.html'));
const css = alle.filter((f) => f.endsWith('.css'));
const svg = alle.filter((f) => f.endsWith('.svg'));
const js = alle.filter((f) => /\.m?js$/.test(f));
const markdown = alle.filter((f) => f.endsWith('.md'));
const sitemaps = alle.filter((f) => /^sitemap[^/\\]*\.xml$/.test(basename(f)));
const TEXT_ENDUNGEN = /\.(html|md|txt|xml|json|js|mjs|css|svg|webmanifest)$/;
let linkAnzahl = 0;

const EINBETTEND_REL = new Set([
  'stylesheet',
  'preload',
  'modulepreload',
  'icon',
  'shortcut',
  'apple-touch-icon',
  'manifest',
  'mask-icon',
  'prefetch',
  'preconnect',
  'dns-prefetch',
  'prerender',
]);
const SRC_TAGS = new Set(['script', 'img', 'iframe', 'video', 'audio', 'source', 'track', 'embed', 'input']);
// SVG elements that load what href / xlink:href points to.
const HREF_LAEDT = new Set(['image', 'use', 'feimage', 'script']);

/**
 * External addresses loaded by CSS: url(), image-set() and friends (also with bare
 * strings) and @import with or without space or url(). data: URIs are fine.
 */
function externeCssAdressen(text) {
  const out = [];
  const ohneKommentare = text.replace(/\/\*[\s\S]*?\*\//g, '');
  for (const m of ohneKommentare.matchAll(/@import\s*(?:url\(\s*)?(?:"([^"]*)"|'([^']*)'|([^\s;'")]+))/gi)) {
    const u = (m[1] ?? m[2] ?? m[3] ?? '').trim();
    if (istExtern(u)) out.push(`@import ${u}`);
  }
  for (const m of ohneKommentare.matchAll(/\burl\(\s*(?:"([^"]*)"|'([^']*)'|([^)\s]*))/gi)) {
    const u = (m[1] ?? m[2] ?? m[3] ?? '').trim();
    if (istExtern(u)) out.push(`url(${u})`);
  }
  for (const m of ohneKommentare.matchAll(/(?:-webkit-)?(?:image-set|image|cross-fade)\(/gi)) {
    // arguments up to the matching parenthesis; strings in it are image addresses
    let tiefe = 1;
    let i = m.index + m[0].length;
    const anfang = i;
    while (i < ohneKommentare.length && tiefe > 0) {
      const z = ohneKommentare[i];
      if (z === '"' || z === "'") {
        const ende = ohneKommentare.indexOf(z, i + 1);
        i = ende < 0 ? ohneKommentare.length : ende + 1;
        continue;
      }
      if (z === '(') tiefe += 1;
      if (z === ')') tiefe -= 1;
      i += 1;
    }
    const argumente = ohneKommentare.slice(anfang, i - 1).replace(/\burl\([^)]*\)/gi, '');
    for (const s of argumente.matchAll(/"([^"]*)"|'([^']*)'/g)) {
      const u = (s[1] ?? s[2] ?? '').trim();
      if (istExtern(u)) out.push(`${m[0]}${u})`);
    }
  }
  return out;
}

/** Checks the tags of an HTML or SVG document for embedded external resources and tracking. */
function pruefeEinbettungen(datei, liste) {
  for (const t of liste) {
    if (t.name === 'link' && t.attrs.href) {
      const rels = (t.attrs.rel ?? '').toLowerCase().split(/\s+/);
      if (rels.some((r) => EINBETTEND_REL.has(r)) && istExtern(t.attrs.href)) {
        melde(datei, `externe Ressource eingebunden: <link rel="${t.attrs.rel}" href="${t.attrs.href}">`);
      }
    }
    if ((SRC_TAGS.has(t.name) || t.name === 'object') && (t.attrs.src || t.attrs.data)) {
      const src = t.attrs.src ?? t.attrs.data;
      if (istExtern(src)) melde(datei, `externe Ressource eingebunden: <${t.name} src="${src}">`);
    }
    if (HREF_LAEDT.has(t.name)) {
      for (const a of ['href', 'xlink:href']) {
        if (t.attrs[a] && istExtern(t.attrs[a]))
          melde(datei, `externe Ressource eingebunden: <${t.name} ${a}="${t.attrs[a]}">`);
      }
    }
    for (const a of ['srcset', 'imagesrcset']) {
      for (const teil of (t.attrs[a] ?? '').split(',')) {
        const u = teil.trim().split(/\s+/)[0];
        if (u && istExtern(u)) melde(datei, `externe Ressource eingebunden: <${t.name} ${a}="${u}">`);
      }
    }
    if (t.attrs.poster && istExtern(t.attrs.poster))
      melde(datei, `externe Ressource eingebunden: poster="${t.attrs.poster}"`);
    if (t.attrs.ping !== undefined) melde(datei, `Tracking: ping="${t.attrs.ping}" an <${t.name}>`);
    if (t.attrs.style) {
      for (const u of externeCssAdressen(t.attrs.style))
        melde(datei, `externe Ressource im style-Attribut von <${t.name}>: ${u}`);
    }
  }
  // <style> blocks
  for (const st of readFileSync(datei, 'utf8').matchAll(/<style\b[^>]*>([\s\S]*?)<\/style>/gi)) {
    for (const u of externeCssAdressen(st[1])) melde(datei, `externe Ressource in <style>: ${u}`);
  }
}

for (const datei of html) {
  const inhalt = readFileSync(datei, 'utf8');
  const seitenPfad = urlPfad(datei);
  const liste = tags(inhalt);

  // (c) structure
  const h1 = (bereinigen(inhalt).match(/<h1[\s>]/gi) ?? []).length;
  if (h1 !== 1) melde(datei, `${h1} <h1> statt genau einer`);
  const htmlTag = liste.find((t) => t.name === 'html');
  if (!htmlTag || htmlTag.attrs.lang !== 'de') melde(datei, 'lang="de" fehlt am <html>-Element');
  const beschreibungen = liste.filter((t) => t.name === 'meta' && (t.attrs.name ?? '').toLowerCase() === 'description');
  if (beschreibungen.length !== 1) melde(datei, `${beschreibungen.length} meta description statt genau einer`);
  else if (!beschreibungen[0].attrs.content?.trim()) melde(datei, 'meta description ist leer');

  // heading order (warning only): no skipped levels such as h2 -> h4
  let vorher = 0;
  for (const m of bereinigen(inhalt).matchAll(/<h([1-6])[\s>]/gi)) {
    const ebene = Number(m[1]);
    if (ebene > vorher + 1) hinweis(datei, `Überschriftenebene übersprungen: h${vorher || '-'} -> h${ebene}`);
    vorher = ebene;
  }

  // (d) JSON-LD
  const ldRe = /<script\b[^>]*type\s*=\s*["']?application\/ld\+json["']?[^>]*>([\s\S]*?)<\/script>/gi;
  let ld;
  while ((ld = ldRe.exec(inhalt))) {
    try {
      JSON.parse(ld[1]);
    } catch (e) {
      melde(datei, `ungültiges JSON-LD: ${e.message}`);
    }
  }

  // (b) embedded resources and tracking
  pruefeEinbettungen(datei, liste);

  // (a) internal links
  for (const t of liste) {
    const kandidaten = [];
    if (t.attrs.srcset) {
      for (const teil of t.attrs.srcset.split(',')) {
        const u = teil.trim().split(/\s+/)[0];
        if (u && !istExtern(u)) kandidaten.push(u);
      }
    }
    if (t.attrs.href !== undefined) kandidaten.push(t.attrs.href);
    if (t.attrs.src !== undefined) kandidaten.push(t.attrs.src);
    // absolute own-site addresses in Open Graph tags (preview image, page URL)
    if (t.name === 'meta' && /^og:(image|url)$/.test(t.attrs.property ?? '') && t.attrs.content) {
      if (istEigeneSeite(t.attrs.content)) kandidaten.push(t.attrs.content);
      else melde(datei, `<meta property="${t.attrs.property}">: "${t.attrs.content}" gehört nicht zur eigenen Seite`);
    }
    for (const ziel of kandidaten) {
      const u = ziel.trim();
      if (u === '' || u === '#') {
        melde(datei, `leerer Link in <${t.name}>`);
        continue;
      }
      if (/^(mailto|tel|data|javascript|sms):/i.test(u)) continue;
      if (istExtern(u) && !istEigeneSeite(u)) continue;
      linkAnzahl += 1;
      const r = aufloesen(u, seitenPfad);
      if (r.fehler) melde(datei, `Link "${u}" in <${t.name}>: ${r.fehler}`);
    }
  }
}

// (b) SVG files: same tag check (image, use, script, style ...)
for (const datei of svg) pruefeEinbettungen(datei, tags(readFileSync(datei, 'utf8')));

// (b) CSS files
for (const datei of css) {
  for (const u of externeCssAdressen(readFileSync(datei, 'utf8'))) melde(datei, `externe Ressource in CSS: ${u}`);
}

// (b) JavaScript: addresses are not necessarily loaded, so only a hint
for (const datei of js) {
  const adressen = new Set();
  for (const m of readFileSync(datei, 'utf8').matchAll(/https?:\/\/[^\s"'`)<>\\]+/g)) {
    if (!/^http:\/\/www\.w3\.org\//.test(m[0]) && !istEigeneSeite(m[0])) adressen.add(m[0]);
  }
  if (adressen.size > 0)
    hinweis(datei, `externe Adresse(n) im Skript, bitte prüfen: ${[...adressen].slice(0, 5).join(', ')}`);
}

// (a) Markdown versions and llms.txt: absolute own-site links, and relative links in .md
/** Markdown without fenced code blocks and inline code. */
function ohneCode(text) {
  return text
    .replace(/^ {0,3}(`{3,}|~{3,})[^\n]*\n[\s\S]*?(?:^ {0,3}\1[ \t]*$|(?![\s\S]))/gm, '')
    .replace(/(`+)[^`][\s\S]*?\1/g, '');
}
function pruefeTextLinks(datei, mitRelativen) {
  const inhalt = readFileSync(datei, 'utf8');
  const text = mitRelativen ? ohneCode(inhalt) : inhalt;
  const seitenPfad = urlPfad(datei);
  const ziele = new Set();
  for (const m of text.matchAll(/https?:\/\/[^\s)<>"'\]]+/g)) ziele.add(m[0].replace(/[.,;:]+$/, ''));
  if (mitRelativen) {
    for (const m of text.matchAll(/\]\(\s*(<[^>\n]*>|[^)\s]+)/g)) ziele.add(m[1]);
    for (const m of text.matchAll(/^ {0,3}\[[^\]]+\]:\s*(<[^>\n]*>|\S+)/gm)) ziele.add(m[1]);
    for (const t of tags(text)) {
      for (const a of ['href', 'src']) if (t.attrs[a] !== undefined) ziele.add(t.attrs[a]);
    }
  }
  for (const roh of ziele) {
    const u = roh.startsWith('<') && roh.endsWith('>') ? roh.slice(1, -1) : roh;
    if (u === '' || u.startsWith('#') || /^(mailto|tel|data|javascript|sms):/i.test(u)) continue;
    if (istExtern(u) && !istEigeneSeite(u)) continue;
    if (!istExtern(u) && /^[a-z][a-z0-9+.-]*:/i.test(u)) continue;
    linkAnzahl += 1;
    const r = aufloesen(u, seitenPfad);
    if (r.fehler) melde(datei, `Link "${u}": ${r.fehler}`);
  }
}

const llms = join(DIST, 'llms.txt');
if (existsSync(llms)) pruefeTextLinks(llms, false);
else melde(llms, 'llms.txt fehlt');
for (const datei of markdown) pruefeTextLinks(datei, true);

// (e) sitemaps
if (sitemaps.length === 0) melde(join(DIST, 'sitemap-index.xml'), 'keine Sitemap gefunden');
for (const datei of sitemaps) {
  const inhalt = readFileSync(datei, 'utf8');
  const istIndex = /<sitemapindex\b/.test(inhalt);
  for (const m of inhalt.matchAll(/<loc>\s*([^<]+?)\s*<\/loc>/g)) {
    const u = entities(m[1]);
    if (!istEigeneSeite(u)) {
      melde(datei, `<loc> ${u} gehört nicht zur eigenen Seite`);
      continue;
    }
    linkAnzahl += 1;
    const r = aufloesen(u, BASE);
    if (r.fehler) {
      melde(datei, `<loc> ${u}: ${r.fehler}`);
    } else if (istIndex) {
      if (!r.datei.endsWith('.xml')) melde(datei, `<loc> ${u} ist keine Sitemap`);
    } else if (basename(r.datei) !== 'index.html' || !u.endsWith('/')) {
      melde(datei, `<loc> ${u} ist keine HTML-Seite (nur Seiten mit Schrägstrich am Ende gehören in die Sitemap)`);
    } else if (hatNoindex(r.datei)) {
      melde(datei, `<loc> ${u}: Seite hat noindex und gehört nicht in die Sitemap`);
    }
  }
}
for (const datei of html) {
  if (basename(datei) === '404.html') continue;
  // reverse check as a hint: indexable pages that are missing from the sitemaps
  if (!hatNoindex(datei) && sitemaps.length > 0) {
    const adresse = `${ORIGIN}${urlPfad(datei)}`;
    if (!sitemaps.some((s) => readFileSync(s, 'utf8').includes(`<loc>${adresse}</loc>`))) {
      hinweis(datei, `indexierbare Seite fehlt in der Sitemap: ${adresse}`);
    }
  }
}

// (f) drafts must not leak into dist
const BLOG_QUELLE = join(ROOT, 'src', 'content', 'blog');
const entwuerfe = [];
if (existsSync(BLOG_QUELLE)) {
  for (const datei of dateien(BLOG_QUELLE)) {
    if (!datei.endsWith('.md') || basename(datei).startsWith('_')) continue;
    const kopf = readFileSync(datei, 'utf8').match(/^---\r?\n([\s\S]*?)\r?\n---/);
    if (!kopf || !/^draft:\s*['"]?(true|yes)['"]?\s*(#.*)?$/im.test(kopf[1])) continue;
    const eigenerSlug = kopf[1].match(/^slug:\s*['"]?([^'"\s#]+)/m);
    const slug = eigenerSlug
      ? eigenerSlug[1]
      : relative(BLOG_QUELLE, datei).split(sep).join('/').replace(/\.md$/, '').toLowerCase();
    entwuerfe.push({ datei, slug });
  }
}
if (entwuerfe.length > 0) {
  const muster = entwuerfe.map((e) => ({
    ...e,
    re: new RegExp(`(?<![A-Za-z0-9_-])${e.slug.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![A-Za-z0-9_-])`),
  }));
  for (const datei of alle.filter((f) => TEXT_ENDUNGEN.test(f))) {
    const inhalt = readFileSync(datei, 'utf8');
    for (const e of muster) {
      if (e.re.test(inhalt))
        melde(datei, `Entwurf "${e.slug}" (${relative(ROOT, e.datei)}, draft: true) wird erwähnt oder verlinkt`);
    }
  }
}

// (g) placeholders: hint while developing, error for the live site (CHECK_LIVE=1)
const PLATZHALTER = [
  // text in [eckigen Klammern] with at least one letter, not Markdown link syntax
  { re: /\[(?=[^\]\n]*\p{L})[^\[\]\n]{2,80}\](?![(\[:])/gu, nurText: true },
  { re: /[\w.+-]*@?\bexample\.(?:org|com|net)\b/gi },
  { re: /mailto:(?:\[|%5B)[^"'\s>]*/gi },
];
for (const datei of alle.filter((f) => /\.(html|md|txt|xml)$/.test(f))) {
  const roh = readFileSync(datei, 'utf8');
  const text = datei.endsWith('.html') ? entities(bereinigen(roh).replace(/<[^>]*>/g, '')) : roh;
  const funde = new Set();
  for (const p of PLATZHALTER) for (const m of (p.nurText ? text : roh).matchAll(p.re)) funde.add(m[0]);
  if (funde.size === 0) continue;
  const liste = [...funde].slice(0, 6).join(', ') + (funde.size > 6 ? ', …' : '');
  if (LIVE) melde(datei, `Platzhalter vor dem Livegang ersetzen: ${liste}`);
  else hinweis(datei, `Platzhalter (vor dem Livegang ersetzen, mit CHECK_LIVE=1 ein Fehler): ${liste}`);
}

// --- output ----------------------------------------------------------------------
if (hinweise.length > 0) {
  console.warn(`\n${hinweise.length} Hinweis(e), kein Fehler:`);
  for (const h of hinweise) console.warn(`  ! ${h}`);
  console.warn('');
}
console.log(
  `check-site: ${html.length} HTML-Seiten, ${markdown.length} Markdown-Dateien, ${css.length} CSS-Dateien, ${svg.length} SVG-Dateien, ${sitemaps.length} Sitemaps, ${linkAnzahl} interne Links geprüft (Basis ${BASE}${LIVE ? ', CHECK_LIVE' : ''}).`,
);
if (fehler.length > 0) {
  console.error(`\n${fehler.length} Fehler:`);
  for (const f of fehler) console.error(`  ✗ ${f}`);
  process.exit(1);
}
console.log('✓ Keine Fehler gefunden.');
