// The site name "Funken & Stahl" is the first name with a special character. Wherever the site
// renders its name, it must be exactly this name, decoded and escaped exactly once: <title>,
// header, footer, og:site_name, og:image:alt, JSON-LD (name, publisher, author) and the llms.txt
// heading. That also rules out the working title "Funkenschlag" in these places. Elsewhere
// "Funkenschlag" stays allowed (a normal noun on this topic, also in compounds and source
// addresses); only the old domain form funkenschlag.de must appear nowhere.
import { expect, test as base, type APIRequestContext, type Page } from '@playwright/test';
import { SEITENNAME, seitenAusSitemap } from './hilfen';

/** An entity reference that was escaped twice, e.g. "&amp;amp;" or "&amp;#39;". */
const DOPPELT_ESCAPED = /&amp;(?:[a-z][a-z0-9]*|#\d+|#x[0-9a-f]+);/gi;
/** Any HTML entity reference. JSON-LD and llms.txt are raw text and contain none. */
const ENTITAET = /&(?:[a-z][a-z0-9]*|#\d+|#x[0-9a-f]+);/i;
/** The old domain of the working title, e.g. www.funkenschlag.de or kontakt@funkenschlag.de. */
const ALTE_DOMAIN = /\bfunkenschlag\.de\b/gi;
/** Absolute address in running text; ends at typographic quotes („so“, ‚so‘, »so«, see site/CLAUDE.md). */
const ADRESSE = /https?:\/\/[^\s)<>"'\]„“”‚‘’»«›‹]+/g;
/** Path that does not exist: the server answers with the 404 page. */
const UNBEKANNT = 'seitenname-gibt-es-nicht/';

const regexText = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const pfad = (url: string) => new URL(url).pathname;

interface Abruf {
  url: string;
  /** Where the address was found first (page, sitemap or start set), for error messages. */
  von: string;
  status: number;
  typ: string;
  /** Body of text responses (HTML, Markdown, XML, CSS, JS, SVG); null for binary files. */
  text: string | null;
}

interface Crawl {
  abrufe: Abruf[];
  /** Page paths from the sitemap. */
  sitemap: string[];
  /** Addresses of the start page and of the deliberately unknown path (404 page). */
  start: string;
  unbekannt: string;
}

/**
 * Fetches everything the site delivers and links to itself: start page, all sitemap pages,
 * the 404 page, llms.txt, robots.txt, sitemaps and every own-site link found in them (pages
 * without sitemap entry, Markdown versions, CSS, JS, SVG, images). Absolute links to the
 * configured site address (from the sitemap) are mapped to the test server. Every address is
 * fetched once; the crawl ends when no new own-site address turns up.
 */
async function crawlen(request: APIRequestContext, baseURL: string): Promise<Crawl> {
  const basis = new URL(baseURL.replace(/\/?$/, '/'));
  const index = await (await request.get('sitemap-index.xml')).text();
  const eigeneAdresse = new URL(index.match(/<loc>([^<]+)<\/loc>/)?.[1] ?? basis.href).origin;

  const offen: string[] = [];
  const bekannt = new Map<string, string>();
  const merke = (ziel: string, von: string): string | undefined => {
    let u: URL;
    try {
      u = new URL(ziel.replace(/&amp;/g, '&'), von.startsWith('http') ? von : basis.href);
    } catch {
      return undefined;
    }
    if (u.origin === eigeneAdresse) u = new URL(u.pathname + u.search, basis.origin);
    if (u.origin !== basis.origin) return undefined;
    u.hash = '';
    if (!bekannt.has(u.href)) {
      bekannt.set(u.href, von);
      offen.push(u.href);
    }
    return u.href;
  };

  const start = merke('', 'Startmenge')!;
  const unbekannt = merke(UNBEKANNT, 'Startmenge')!;
  for (const datei of ['llms.txt', 'robots.txt', 'sitemap-index.xml']) merke(datei, 'Startmenge');
  const sitemap = await seitenAusSitemap(request);
  for (const p of sitemap) merke(p, 'Sitemap');

  const abrufe: Abruf[] = [];
  while (offen.length > 0) {
    const url = offen.shift()!;
    const antwort = await request.get(url);
    const typ = antwort.headers()['content-type'] ?? '';
    const istText = /^(text\/|application\/(json|xml|javascript|ld\+json)|image\/svg\+xml)/.test(typ);
    const text = istText ? await antwort.text() : null;
    abrufe.push({ url, von: bekannt.get(url)!, status: antwort.status(), typ, text });
    if (text === null) continue;
    // absolute addresses everywhere (llms.txt, sitemaps, og:image, JSON-LD), relative ones by file type
    for (const m of text.matchAll(ADRESSE)) merke(m[0].replace(/[.,;:!?]+$/, ''), url);
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
  return { abrufe, sitemap, start, unbekannt };
}

// The crawl runs once per worker and is shared by all tests in it; it has its own timeout.
const test = base.extend<object, { crawl: Crawl }>({
  crawl: [
    async ({ playwright }, use, workerInfo) => {
      const baseURL = workerInfo.project.use.baseURL!;
      const request = await playwright.request.newContext({ baseURL });
      const crawl = await crawlen(request, baseURL).finally(() => request.dispose());
      await use(crawl);
    },
    { scope: 'worker', timeout: 60_000 },
  ],
});

/** Delivered HTML pages: every page answering 200 plus the 404 page (broken links are reported separately). */
const htmlSeiten = (c: Crawl) =>
  c.abrufe.filter((a) => a.typ.startsWith('text/html') && (a.status === 200 || a.url === c.unbekannt));

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

  test('every page shows the name decoded in title, header, footer and meta tags, nothing escaped twice', async ({
    page,
    crawl,
  }) => {
    test.setTimeout(120_000);
    const seiten = htmlSeiten(crawl);
    // every sitemap page and the 404 page are checked (plus linked pages without sitemap entry)
    const geprueft = new Set(seiten.map((s) => pfad(s.url)));
    expect(
      crawl.sitemap.filter((p) => !geprueft.has(p)),
      'Sitemap-Seiten ohne HTML-Antwort',
    ).toEqual([]);
    const seite404 = crawl.abrufe.find((a) => a.url === crawl.unbekannt);
    expect(seite404?.status, `404-Seite für ${crawl.unbekannt}`).toBe(404);
    expect(seite404?.typ, `404-Seite für ${crawl.unbekannt}`).toMatch(/^text\/html/);

    for (const seite of seiten) {
      await test.step(pfad(seite.url), async () => {
        const doppelt = [...(seite.text ?? '').matchAll(DOPPELT_ESCAPED)].map((m) => m[0]);
        expect(doppelt, `${seite.url}: doppelt escaped`).toEqual([]);

        await page.goto(seite.url);
        const titel = (await page.locator('head > title').textContent()) ?? '';
        if (seite.url === crawl.start) expect(titel, 'Titel').toMatch(new RegExp(`^${regexText(SEITENNAME)} `));
        else expect(titel, 'Titel').toMatch(new RegExp(` \\| ${regexText(SEITENNAME)}$`));

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
        await expect(page.locator('meta[property="og:image:alt"]')).toHaveAttribute(
          'content',
          new RegExp(`(^|\\s)${regexText(SEITENNAME)}(?![\\p{L}\\p{N}])`, 'u'),
        );
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

  test('JSON-LD on blog articles names the site raw as publisher and editorial author', async ({ page, crawl }) => {
    test.setTimeout(60_000);
    const artikel = crawl.sitemap.filter((p) => /\/blog\/(?!zielgruppe\/)[^/]+\/$/.test(p));
    test.skip(artikel.length === 0, 'Noch keine Artikel veröffentlicht: es gibt noch kein Article-JSON-LD zu prüfen.');
    for (const p of artikel) {
      await test.step(p, async () => {
        await page.goto(p);
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

  test('JSON-LD on all pages names the site raw as WebSite, publisher and author, without HTML entities', async ({
    crawl,
  }) => {
    const funde: string[] = [];
    let bloecke = 0;
    for (const seite of htmlSeiten(crawl)) {
      const ldRe = /<script\b[^>]*type\s*=\s*["']?application\/ld\+json["']?[^>]*>([\s\S]*?)<\/script>/gi;
      for (const m of (seite.text ?? '').matchAll(ldRe)) {
        bloecke += 1;
        const ld: unknown = JSON.parse(m[1]);
        const melde = (text: string) => funde.push(`${pfad(seite.url)}: ${text}`);
        for (const k of knoten(ld)) {
          if (k['@type'] === 'WebSite' && k.name !== SEITENNAME) melde(`WebSite.name ${JSON.stringify(k.name)}`);
          const publisher = k.publisher as Record<string, unknown> | undefined;
          if (publisher && publisher.name !== SEITENNAME) melde(`publisher.name ${JSON.stringify(publisher.name)}`);
          const autor = k.author as Record<string, unknown> | undefined;
          // the site as author: the organisation itself (Review) or its editorial team (Article)
          if (
            autor?.['@type'] === 'Organization' &&
            ![SEITENNAME, `Redaktion ${SEITENNAME}`].includes(String(autor.name))
          )
            melde(`author.name ${JSON.stringify(autor.name)}`);
        }
        for (const t of texte(ld)) if (ENTITAET.test(t)) melde(`HTML-Entität in ${JSON.stringify(t)}`);
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

  test('the patterns find the old domain and whole addresses, but leave the noun and quotes alone', () => {
    const domain = (s: string) => s.match(ALTE_DOMAIN) ?? [];
    for (const s of [
      'https://www.funkenschlag.de/',
      'kontakt@funkenschlag.de',
      'FUNKENSCHLAG.DE',
      'auf funkenschlag.de.',
    ])
      expect(domain(s), s).toHaveLength(1);
    for (const s of [
      'Der Funkenschlag ist hell.',
      'beim Funkenschlagen',
      'die Funkenschlag-Technik',
      'https://de.wikipedia.org/wiki/Funkenschlag',
      'https://www.funkenundstahl.de/',
      'https://funkenschlag.dev/',
    ])
      expect(domain(s), s).toEqual([]);

    const adressen = (s: string) => [...s.matchAll(ADRESSE)].map((m) => m[0]);
    expect(adressen('Siehe „https://www.example.org/blog/“ und ‚https://www.example.org/a/‘.')).toEqual([
      'https://www.example.org/blog/',
      'https://www.example.org/a/',
    ]);
    expect(adressen('»https://www.example.org/b/« oder “https://www.example.org/c/”')).toEqual([
      'https://www.example.org/b/',
      'https://www.example.org/c/',
    ]);
  });

  test('the crawl reaches every own-site address, no internal link is broken', async ({ crawl }) => {
    const kaputt = crawl.abrufe.filter((a) => a.url !== crawl.unbekannt && a.status !== 200);
    expect(
      kaputt.map((a) => `${a.status} ${pfad(a.url)} (verlinkt von ${a.von})`),
      'kaputte interne Links',
    ).toEqual([]);
    // text files must come back as text, or their content would escape the checks
    const ohneText = crawl.abrufe.filter(
      (a) => a.text === null && /(\/|\.(html|md|txt|xml|css|m?js|svg|json))$/.test(pfad(a.url)),
    );
    expect(
      ohneText.map((a) => `${pfad(a.url)} (${a.typ || 'ohne Content-Type'})`),
      'Textdateien nicht als Text ausgeliefert',
    ).toEqual([]);
    // Markdown versions linked from llms.txt are part of the crawl
    const llms = crawl.abrufe.find((a) => pfad(a.url).endsWith('/llms.txt'));
    expect(llms?.text, 'llms.txt').toBeTruthy();
    const mdLinks = [...(llms?.text ?? '').matchAll(/\((https?:\/\/[^)\s]+\.md)\)/g)].map((m) => pfad(m[1]));
    const abgerufen = new Set(crawl.abrufe.map((a) => pfad(a.url)));
    expect(
      mdLinks.filter((p) => !abgerufen.has(p)),
      'Markdown-Fassungen aus llms.txt nicht abgerufen',
    ).toEqual([]);
  });

  test('the old domain funkenschlag.de appears nowhere in the output', async ({ crawl }) => {
    const funde: string[] = [];
    for (const a of crawl.abrufe) {
      for (const m of (a.text ?? '').matchAll(ALTE_DOMAIN)) {
        funde.push(`${pfad(a.url)}: …${a.text!.slice(Math.max(0, m.index - 30), m.index + 40)}…`);
      }
    }
    expect(funde).toEqual([]);
  });
});
