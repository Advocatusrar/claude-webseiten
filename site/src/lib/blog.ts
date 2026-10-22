import { getCollection, type CollectionEntry } from 'astro:content';
import type { Thema, Zielgruppe } from './labels';

export type Artikel = CollectionEntry<'blog'>;

function neuesteZuerst(artikel: Artikel[]): Artikel[] {
  return artikel.sort(
    (a, b) => b.data.pubDate.getTime() - a.data.pubDate.getTime() || a.data.title.localeCompare(b.data.title, 'de'),
  );
}

/** All published articles (no drafts), newest first. Used for lists, llms.txt, sitemap and .md. */
export async function alleArtikel(): Promise<Artikel[]> {
  return neuesteZuerst(await getCollection('blog', ({ data }) => !data.draft));
}

/**
 * Articles that get an HTML page: in `astro dev` also drafts (so authors can
 * preview them, marked as draft and noindex), in the build only published ones.
 */
export async function artikelSeiten(): Promise<Artikel[]> {
  return import.meta.env.DEV ? neuesteZuerst(await getCollection('blog')) : alleArtikel();
}

export function mitThema(artikel: Artikel[], thema: Thema): Artikel[] {
  return artikel.filter((a) => a.data.themen.includes(thema));
}

export function fuerZielgruppe(artikel: Artikel[], zielgruppe: Zielgruppe): Artikel[] {
  return artikel.filter((a) => a.data.zielgruppen.includes(zielgruppe));
}

/** Date shown as "Stand" and used as dateModified. */
export function zuletztGeaendert(a: Artikel): Date {
  return a.data.updatedDate ?? a.data.stand;
}

/**
 * Related articles (up to 3): first those sharing a topic, sorted by the number of
 * shared topics, then shared target groups, then newest first. If fewer than 2
 * share a topic, the list is filled up to 2 with articles for the same target groups.
 */
export function verwandteArtikel(aktuell: Artikel, alle: Artikel[], anzahl = 3, mindestens = 2): Artikel[] {
  const gemeinsam = <T>(a: readonly T[], b: readonly T[]) => a.filter((x) => b.includes(x)).length;
  const bewertet = alle
    .filter((a) => a.id !== aktuell.id)
    .map((a) => ({
      a,
      themen: gemeinsam(a.data.themen, aktuell.data.themen),
      gruppen: gemeinsam(a.data.zielgruppen, aktuell.data.zielgruppen),
    }))
    .sort(
      (x, y) => y.themen - x.themen || y.gruppen - x.gruppen || y.a.data.pubDate.getTime() - x.a.data.pubDate.getTime(),
    );
  const gleichesThema = bewertet.filter((x) => x.themen > 0).slice(0, anzahl);
  const auffuellen = bewertet
    .filter((x) => x.themen === 0 && x.gruppen > 0)
    .slice(0, Math.max(0, mindestens - gleichesThema.length));
  return [...gleichesThema, ...auffuellen].map((x) => x.a);
}

/** Articles with a single-segment id get a Markdown version under /blog/<id>.md. */
export function hatMarkdownFassung(a: Artikel): boolean {
  return !a.id.includes('/');
}
