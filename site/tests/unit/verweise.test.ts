import { describe, expect, it } from 'vitest';
import {
  FOLGT,
  htmlOhneFehlendeArtikel,
  markdownOhneFehlendeArtikel,
  zeigtAufFehlendenArtikel,
} from '../../src/lib/verweise';
import { absoluteUrl, pfade, url } from '../../src/lib/url';

const SEITE = absoluteUrl(pfade.artikel('feuerstahl-worauf-achten'));
const VEROEFFENTLICHT = new Set(['feuerstahl-worauf-achten', 'feuerstahl-mit-kindern']);

describe('zeigtAufFehlendenArtikel', () => {
  it.each([
    ['../striker-worauf-achten/', true],
    ['../striker-worauf-achten', true],
    ['../striker-worauf-achten/#technik', true],
    ['../feuerstahl-mit-kindern/', false],
    ['../../vergleichstest/', false],
    ['../', false],
    ['../zielgruppe/linkshaender/', false],
    ['https://www.dwd.de/', false],
    ['../bild.png', false],
  ])('%s -> %s', (href, erwartet) => {
    expect(zeigtAufFehlendenArtikel(href, SEITE, VEROEFFENTLICHT)).toBe(erwartet);
  });
});

describe('link replacement', () => {
  it('turns HTML links to unpublished articles into marked text', () => {
    const html =
      '<p><a href="../striker-worauf-achten/">Striker</a> und <a href="../feuerstahl-mit-kindern/">Kinder</a></p>';
    const ergebnis = htmlOhneFehlendeArtikel(html, SEITE, VEROEFFENTLICHT);
    expect(ergebnis).toContain(`<span class="folgt">Striker (${FOLGT})</span>`);
    expect(ergebnis).toContain('<a href="../feuerstahl-mit-kindern/">Kinder</a>');
  });

  it('turns Markdown links into text but leaves code alone', () => {
    const md = 'Siehe [Striker](../striker-worauf-achten/) und `[x](../striker-worauf-achten/)`.';
    expect(markdownOhneFehlendeArtikel(md, SEITE, VEROEFFENTLICHT)).toBe(
      `Siehe Striker (${FOLGT}) und \`[x](../striker-worauf-achten/)\`.`,
    );
  });
});

describe('url', () => {
  it('adds the base path and a trailing slash', () => {
    expect(url('blog')).toBe(`${import.meta.env.BASE_URL.replace(/\/?$/, '/')}blog/`);
    expect(url('blog/a.md')).toMatch(/blog\/a\.md$/);
    expect(url('vergleichstest/#rechner')).toMatch(/vergleichstest\/#rechner$/);
  });
});
