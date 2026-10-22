// Builds the plain Markdown version of an article (for /blog/<id>.md and AI agents).
import type { Artikel } from './blog';
import { datumDeutsch } from './format';
import { THEMEN, ZIELGRUPPEN } from './labels';
import { absoluteUrl, pfade } from './url';
import { ausserhalbVonCode, markdownOhneFehlendeArtikel } from './verweise';

/**
 * Relative links in an article are written for the HTML page /blog/<id>/.
 * In the .md file they would resolve differently, so they become absolute URLs:
 * Markdown links and images (also with <angle brackets>), reference definitions
 * and href/src/poster attributes in raw HTML. Code stays untouched.
 */
function linksAbsolut(body: string, seitenUrl: string): string {
  const absolut = (ziel: string) => {
    if (/^(?:[a-z][a-z0-9+.-]*:|#|\/\/)/i.test(ziel)) return ziel;
    try {
      return new URL(ziel, seitenUrl).href;
    } catch {
      return ziel;
    }
  };
  const ersetzen = (anfang: string, ziel: string) =>
    ziel.startsWith('<') && ziel.endsWith('>')
      ? `${anfang}<${absolut(ziel.slice(1, -1))}>`
      : `${anfang}${absolut(ziel)}`;
  return ausserhalbVonCode(body, (text) =>
    text
      .replace(/(\]\(\s*)(<[^>\n]*>|[^)\s]+)/g, (_, anfang: string, ziel: string) => ersetzen(anfang, ziel))
      .replace(/^(\s{0,3}\[[^\]]+\]:\s*)(<[^>\n]*>|\S+)/gm, (_, anfang: string, ziel: string) => ersetzen(anfang, ziel))
      .replace(/<[a-zA-Z][a-zA-Z0-9-]*\b(?:[^>"']|"[^"]*"|'[^']*')*>/g, (tag: string) =>
        tag.replace(
          /(\s(?:href|src|poster)\s*=\s*)(?:"([^"]*)"|'([^']*)')/gi,
          (_, anfang: string, doppelt: string | undefined, einfach: string | undefined) =>
            doppelt !== undefined ? `${anfang}"${absolut(doppelt)}"` : `${anfang}'${absolut(einfach ?? '')}'`,
        ),
      ),
  );
}

/** Shifts ATX headings so the body starts at "##" (the title is the only "#"). Skips code fences. */
function ueberschriftenAb2(body: string): string {
  const zeilen = body.split('\n');
  let imCode = false;
  const ebenen: number[] = [];
  const istUeberschrift: boolean[] = zeilen.map((z) => {
    if (/^\s{0,3}(```|~~~)/.test(z)) imCode = !imCode;
    const m = !imCode && z.match(/^(#{1,6})\s/);
    if (m) ebenen.push(m[1].length);
    return Boolean(m);
  });
  const verschiebung = ebenen.length > 0 ? Math.max(0, 2 - Math.min(...ebenen)) : 0;
  if (verschiebung === 0) return body;
  return zeilen
    .map((z, i) =>
      istUeberschrift[i] ? z.replace(/^(#{1,6})/, (h) => '#'.repeat(Math.min(6, h.length + verschiebung))) : z,
    )
    .join('\n');
}

/**
 * @param veroeffentlicht ids of all published articles. Links to other articles
 *   (drafts, not yet written) become plain text, as on the HTML page.
 */
export function artikelAlsMarkdown(a: Artikel, veroeffentlicht: string[]): string {
  const d = a.data;
  const seitenUrl = absoluteUrl(pfade.artikel(a.id));
  const zeilen: string[] = [];
  zeilen.push(`# ${d.title}`, '');
  zeilen.push(`Stand: ${datumDeutsch(d.stand)}  `);
  if (d.updatedDate) zeilen.push(`Aktualisiert: ${datumDeutsch(d.updatedDate)}  `);
  zeilen.push(`Veröffentlicht: ${datumDeutsch(d.pubDate)}  `);
  zeilen.push(`Autor: ${d.autor}  `);
  zeilen.push(`Themen: ${d.themen.map((t) => THEMEN[t]?.name ?? t).join(', ')}  `);
  zeilen.push(`Zielgruppen: ${d.zielgruppen.map((z) => ZIELGRUPPEN[z]?.name ?? z).join(', ')}  `);
  zeilen.push(
    d.testbasiert
      ? 'Art: Mit eigenen Testergebnissen  '
      : 'Art: Grundlagenartikel, enthält keine eigenen Testergebnisse  ',
  );
  zeilen.push(`Originalseite: ${seitenUrl}`, '');
  zeilen.push(`> ${d.description}`, '');
  const text = markdownOhneFehlendeArtikel((a.body ?? '').trim(), seitenUrl, veroeffentlicht);
  zeilen.push(ueberschriftenAb2(linksAbsolut(text, seitenUrl)), '');

  if (d.faq.length > 0) {
    zeilen.push('## Häufige Fragen', '');
    for (const f of d.faq) zeilen.push(`### ${f.frage}`, '', f.antwort, '');
  }

  zeilen.push('## Quellen', '');
  d.quellen.forEach((q, i) => {
    zeilen.push(`${i + 1}. [${q.titel}](${q.url}), abgerufen am ${datumDeutsch(q.abgerufen)}`);
  });
  zeilen.push('');
  return zeilen.join('\n');
}
