// The site name "Funken & Stahl" is the first name with a special character. It must appear
// decoded and escaped exactly once: start page <title>, header, footer, og:site_name, JSON-LD
// and llms.txt. The working title "Funkenschlag" is gone from the whole output; the verb
// "Funkenschlagen" stays allowed.
import { expect, test, type APIRequestContext, type Page } from '@playwright/test';
import { SEITENNAME, seitenAusSitemap } from './hilfen';

/** An entity reference that was escaped twice, e.g. "&amp;amp;" or "&amp;#39;". */
const DOPPELT_ESCAPED = /&amp;(?:[a-z][a-z0-9]*|#\d+|#x[0-9a-f]+);/gi;
/** Any HTML entity reference. JSON-LD and llms.txt are raw text and contain none. */
const ENTITAET = /&(?:[a-z][a-z0-9]*|#\d+|#x[0-9a-f]+);/i;
/** The working title as a name, also inflected or in addresses; not the verb "Funkenschlagen". */
const ARBEITSTITEL = /funkenschlag(?!en)/gi;
/** Path that does not exist: the server answers with the 404 page. */
const UNBEKANNT = 'seitenname-gibt-es-nicht/';

const regexText = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

interface Abruf {
  url: string;
  status: number;
  typ: string;
  /** Body of text responses (HTML, Markdown, XML, CSS, JS, SVG); null for binary files. */
  text: string | null;
}

/**
 * Fetches everything the site delivers and links to itself: start page, all sitemap pages,
 * the 404 page, llms.txt, robots.txt, sitemaps and every own-site link found in them (pages
 * without sitemap entry, Markdown versions, CSS, JS, SVG, images). Absolute links to the
 * configured site address (from the sitemap) are mapped to the test server.
 */
async function alleAbrufe(request: APIRequestContext, baseURL: string): Promise<Abruf[]> {
  const basis = new URL(baseURL.replace(/\/?$/, '/'));
  const index = await (await request.get('sitemap-index.xml')).text();
  const eigeneAdresse = new URL(index.match(/<loc>([^<]+)<\/loc>/)?.[1] ?? basis.href).origin;

  const offen: string[] = [];
  const bekannt = new Set<string>();
  const merke = (ziel: string, von: string) => {
    let u: URL;
    try {
      u = new URL(ziel.replace(/&amp;/g, '&'), von);
    } catch {
      return;
    }
    if (u.origin === eigeneAdresse) u = new URL(u.pathname + u.search, basis.origin);
    if (u.origin !== basis.origin) return;
    u.hash = '';
    if (!bekannt.has(u.href)) {
      bekannt.add(u.href);
      offen.push(u.href);
    }
  };

  for (const start of ['', 'llms.txt', 'robots.txt', 'sitemap-index.xml', UNBEKANNT]) merke(start, basis.href);
  for (const pfad of await seitenAusSitemap(request)) merke(pfad, basis.href);

  const abrufe: Abruf[] = [];
  while (offen.length > 0) {
    expect(abrufe.length, 'zu viele Adressen, Crawler läuft im Kreis?').toBeLessThan(500);
    const url = offen.shift()!;
    const antwort = await request.get(url);
    const typ = antwort.headers()['content-type'] ?? '';
    const istText = /^(text\/|application\/(json|xml|javascript|ld\+json)|image\/svg\+xml)/.test(typ);
    const text = istText ? await antwort.text() : null;
    abrufe.push({ url, status: antwort.status(), typ, text });
    if (text === null) continue;
    // absolute addresses everywhere (llms.txt, sitemaps, og:image, JSON-LD), relative ones by file type
    for (const m of text.matchAll(/https?:\/\/[^\s)<>"'\]]+/g)) merke(m[0].replace(/[.,;:]+$/, ''), url);
    if (typ.startsWith('text/html') || typ.includes('svg')) {
      for (const m of text.matchAll(/\s(?:href|src)\s*=\s*["']([^"']+)["']/gi)) merke(m[1], url);
    } else if (typ.includes('javascript')) {
      for (const m of text.matchAll(/(?:\bfrom\s*|\bimport\s*\(?\s*)["']([^"']+)["']/g)) merke(m[1], url);
    } else if (typ.startsWith('text/css')) {
      for (const m of text.matchAll(/url\(\s*["']?([^"')]+)/g)) merke(m[1], url);
    } else {
      for (const m of text.matchAll(/\]\(\s*([^)\s]+)/g)) merke(m[1], url);
    }
  }
  return abrufe;
}

/** HTML pages from the crawl (including pages without sitemap entry and the 404 page). */
const htmlSeiten = (abrufe: Abruf[]) => abrufe.filter((a) => a.typ.startsWith('text/html'));

/** All objects in a JSON-LD value, also nested ones (publisher, author ...). */
function knoten(wert: unknown): Record<string, unknown>[] {
  if (Array.isArray(wert)) return wert.flatMap(knoten);
  if (wert === null || typeof wert !== 'object') return [];
  return [wert as Record<string, unknown>, ...Object.values(wert).flatMap(knoten)];
}

/** All strings in a JSON-LD value. */
function texte(wert: unknown): string[] {
  if (typeof wert === 'string') return [wert];
  if (Array.isArray(wert)) return wert.flatMap(texte);
  if (wert !== null && typeof wert === 'object') return Object.values(wert).flatMap(texte);
  return [];
}

async function jsonLd(page: Page): Promise<unknown[]> {
  const bloecke = await page.locator('script[type="application/ld+json"]').allTextContents();
  return bloecke.map((b) => JSON.parse(b));
}

test.describe('Seitenname', () => {
  test('the start page title starts with the site name and has at most 60 characters', async ({ page }) => {
    await page.goto('');
    const titel = (await page.locator('head > title').textContent()) ?? '';
    expect(titel).toMatch(new RegExp(`^${regexText(SEITENNAME)}(?![\\p{L}\\p{N}])`, 'u'));
    expect([...titel].length, titel).toBeLessThanOrEqual(60);
  });

  test('header, footer and og:site_name show the name decoded, nothing is escaped twice', async ({
    page,
    request,
    baseURL,
  }) => {
    test.setTimeout(120_000);
    const seiten = htmlSeiten(await alleAbrufe(request, baseURL!));
    // every sitemap page and the 404 page come back as HTML and are checked (plus linked pages without sitemap entry)
    const geprueft = new Set(seiten.map((s) => new URL(s.url).pathname));
    const fehlend = (await seitenAusSitemap(request)).filter((p) => !geprueft.has(p));
    expect(fehlend, 'Sitemap-Seiten ohne HTML-Antwort').toEqual([]);
    expect(seiten.filter((s) => s.status === 404).length, '404-Seite').toBe(1);

    for (const seite of seiten) {
      await test.step(new URL(seite.url).pathname, async () => {
        const doppelt = [...(seite.text ?? '').matchAll(DOPPELT_ESCAPED)].map((m) => m[0]);
        expect(doppelt, `${seite.url}: doppelt escaped`).toEqual([]);

        await page.goto(seite.url);
        const kopf = page.getByRole('banner').locator('.site-name');
        await expect(kopf).toHaveText(SEITENNAME);
        await expect(page.getByRole('banner').getByRole('link', { name: SEITENNAME, exact: true })).toBeVisible();

        const copyright = page.getByRole('contentinfo').locator('p', { hasText: '©' });
        await expect(copyright).toHaveCount(1);
        const zeile = ((await copyright.textContent()) ?? '').replace(/\s+/g, ' ').trim();
        expect(zeile).toMatch(/^© \d{4} /);
        expect(zeile.replace(/^© \d{4} /, '')).toBe(SEITENNAME);

        const siteName = page.locator('meta[property="og:site_name"]');
        await expect(siteName).toHaveCount(1);
        await expect(siteName).toHaveAttribute('content', SEITENNAME);
      });
    }
  });

  test('JSON-LD on the start page names the site raw', async ({ page }) => {
    await page.goto('');
    const ld = await jsonLd(page);
    const website = knoten(ld).filter((k) => k['@type'] === 'WebSite');
    expect(website).toHaveLength(1);
    expect(website[0].name).toBe(SEITENNAME);
    expect((website[0].publisher as Record<string, unknown>)?.name).toBe(SEITENNAME);
    expect(texte(ld).filter((t) => ENTITAET.test(t))).toEqual([]);
  });

  test('JSON-LD on blog articles names the site raw as publisher and editorial author', async ({ page, request }) => {
    const artikel = (await seitenAusSitemap(request)).filter((p) => /\/blog\/(?!zielgruppe\/)[^/]+\/$/.test(p));
    expect(artikel.length).toBeGreaterThan(0);
    for (const pfad of artikel) {
      await test.step(pfad, async () => {
        await page.goto(pfad);
        const ld = await jsonLd(page);
        const article = knoten(ld).filter((k) => k['@type'] === 'Article');
        expect(article).toHaveLength(1);
        expect((article[0].publisher as Record<string, unknown>)?.name).toBe(SEITENNAME);
        const autor = article[0].author as Record<string, unknown>;
        if (autor?.['@type'] === 'Organization') expect(autor.name).toBe(`Redaktion ${SEITENNAME}`);
        expect(texte(ld).filter((t) => ENTITAET.test(t))).toEqual([]);
      });
    }
  });

  test('JSON-LD on all pages contains no HTML entities', async ({ request, baseURL }) => {
    const funde: string[] = [];
    let bloecke = 0;
    for (const seite of htmlSeiten(await alleAbrufe(request, baseURL!))) {
      const ldRe = /<script\b[^>]*type\s*=\s*["']?application\/ld\+json["']?[^>]*>([\s\S]*?)<\/script>/gi;
      for (const m of (seite.text ?? '').matchAll(ldRe)) {
        bloecke += 1;
        for (const t of texte(JSON.parse(m[1]))) if (ENTITAET.test(t)) funde.push(`${seite.url}: ${t}`);
      }
    }
    expect(bloecke).toBeGreaterThan(0);
    expect(funde).toEqual([]);
  });

  test('llms.txt starts with the site name as heading', async ({ request }) => {
    const antwort = await request.get('llms.txt');
    expect(antwort.status()).toBe(200);
    const erste = (await antwort.text()).split(/\r?\n/)[0];
    expect(erste).toBe(`# ${SEITENNAME}`);
  });

  test('the working-title pattern finds the name in any form but not the verb', () => {
    const funde = (s: string) => s.match(ARBEITSTITEL) ?? [];
    for (const s of ['Funkenschlag', 'des Funkenschlags', 'https://www.funkenschlag.de/', 'Redaktion FUNKENSCHLAG'])
      expect(funde(s), s).toHaveLength(1);
    for (const s of ['beim Funkenschlagen', 'id="wie-lernt-ein-kind-das-funkenschlagen"', 'funkenschlagende Kinder'])
      expect(funde(s), s).toEqual([]);
  });

  test('the working title no longer appears anywhere in the output', async ({ request, baseURL }) => {
    const abrufe = await alleAbrufe(request, baseURL!);
    const unerwartet = abrufe.filter((a) => a.status !== (a.url.endsWith(UNBEKANNT) ? 404 : 200));
    expect(unerwartet.map((a) => `${a.status} ${a.url}`)).toEqual([]);
    // the crawl reaches text files, their links (Markdown versions from llms.txt) and assets
    const llms = abrufe.find((a) => new URL(a.url).pathname.endsWith('/llms.txt'))?.text ?? '';
    const pflichten = ['llms.txt', 'robots.txt', '.css', '.svg', ...(/\.md\)/.test(llms) ? ['.md'] : [])];
    for (const pflicht of pflichten)
      expect(
        abrufe.some((a) => a.text !== null && new URL(a.url).pathname.endsWith(pflicht)),
        `nicht abgerufen: ${pflicht}`,
      ).toBe(true);

    const funde: string[] = [];
    for (const a of abrufe) {
      for (const m of (a.text ?? '').matchAll(ARBEITSTITEL)) {
        funde.push(`${new URL(a.url).pathname}: …${a.text!.slice(Math.max(0, m.index - 30), m.index + 40)}…`);
      }
    }
    expect(funde).toEqual([]);
  });
});
