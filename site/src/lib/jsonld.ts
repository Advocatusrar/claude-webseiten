import { SITE } from '../site';
import { absoluteUrl } from './url';

/** Preview image for link previews and structured data (public/og-bild.png, 1200 × 630). */
export const VORSCHAUBILD = {
  pfad: 'og-bild.png',
  breite: 1200,
  hoehe: 630,
  alt: `Logo von ${SITE.name}: ein Feuerstahl, von dem Funken springen`,
} as const;

export const ORGANISATION = {
  '@type': 'Organization',
  name: SITE.name,
  url: absoluteUrl(''),
  logo: absoluteUrl('logo.png'),
} as const;

/**
 * Author for Article JSON-LD, matching the visible "Autor" line: the default
 * "Redaktion" is the editorial team of the site, any other name is a person.
 */
export function autorLd(autor: string) {
  return autor.trim() === 'Redaktion'
    ? { '@type': 'Organization', name: `Redaktion ${SITE.name}`, url: absoluteUrl('') }
    : { '@type': 'Person', name: autor.trim() };
}

export interface Krume {
  name: string;
  /** Internal path without base, e.g. 'blog/'. */
  pfad: string;
}

export function breadcrumbLd(krumen: Krume[]) {
  return {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: krumen.map((k, i) => ({
      '@type': 'ListItem',
      position: i + 1,
      name: k.name,
      item: absoluteUrl(k.pfad),
    })),
  };
}
