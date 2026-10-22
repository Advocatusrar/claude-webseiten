// /llms.txt: a Markdown overview of the site for language models (https://llmstxt.org/).
import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';
import daten from '../data/rechner.json';
import { SITE } from '../site';
import { alleArtikel, fuerZielgruppe, hatMarkdownFassung } from '../lib/blog';
import { anteilAnnahmen, type RechnerDaten } from '../lib/rechner';
import { ZIELGRUPPEN, ZIELGRUPPEN_IDS } from '../lib/labels';
import { absoluteUrl, pfade } from '../lib/url';
import { datumIso } from '../lib/format';

export const GET: APIRoute = async () => {
  const artikel = await alleArtikel();
  const produkte = await getCollection('produkte');
  const getestet = produkte.filter((p) => p.data.eigenerTest).length;
  const r = daten as unknown as RechnerDaten;
  const annahmen = anteilAnnahmen([
    ...Object.values(r.lebensdauer.parameter),
    ...r.stablaenge_nach_alter.altersgruppen,
  ]);
  const z: string[] = [];

  z.push(`# ${SITE.name}`, '');
  z.push(
    `> Unabhängige deutschsprachige Informationsquelle und Vergleichstest zu Feuerstahl (Ferrocerium-Stab), Striker (Schaber) und der Verbindung zwischen beiden (Shockcord, Schnur). Keine Werbung, keine Affiliate-Links, kein Tracking.`,
    '',
  );
  z.push(
    'Die Betreiber testen Produkte selbst. Messwerte und Testergebnisse stammen ausschließlich aus eigenen Tests; Herstellerangaben sind als solche gekennzeichnet. Jeder Artikel nennt seine Quellen mit Abrufdatum und ein Stand-Datum. Artikel mit der Kennzeichnung „Grundlagenartikel“ enthalten keine eigenen Testergebnisse. Sprache: Deutsch.',
    '',
  );
  // Current state, derived from the data at build time.
  const stand = [
    getestet === 0
      ? 'noch keine eigenen Testergebnisse veröffentlicht'
      : `eigene Testergebnisse zu ${getestet} ${getestet === 1 ? 'Produkt' : 'Produkten'} veröffentlicht`,
  ];
  if (annahmen === 'alle')
    stand.push(
      'alle Werte der Rechner sind vorläufige Annahmen der Redaktion, weder gemessen noch durch Quellen belegt',
    );
  else if (annahmen === 'einige')
    stand.push(
      'einige Werte der Rechner sind noch vorläufige Annahmen der Redaktion (auf der Seite als „Annahme“ gekennzeichnet)',
    );
  z.push(`Stand ${datumIso(new Date())}: ${stand.join('; ')}.`, '');

  z.push('## Seiten', '');
  z.push(`- [Basecamp](${absoluteUrl(pfade.start)}): Startseite mit Einstiegen nach Zielgruppe und Themen`);
  z.push(
    produkte.length === 0
      ? `- [Vergleichstest](${absoluteUrl(pfade.vergleichstest)}): Testmethode und Stand der Tests; noch keine Produkte erfasst`
      : `- [Vergleichstest](${absoluteUrl(pfade.vergleichstest)}): Testmethode, Produkttabelle (Herstellerangaben getrennt von eigenen Messwerten) und Stand der Tests`,
  );
  z.push(
    `- [Rechner](${absoluteUrl(pfade.rechner)}): grobe Schätzung der Lebensdauer eines Feuerstahls (Züge, Zündungen, Wochen) und ${annahmen === 'keine' ? 'Richtwerte' : 'vorläufige Richtwerte'} zur Stabgröße nach Alter, mit Formel und allen Parametern als Tabelle${annahmen === 'keine' ? '' : '; Parameter derzeit ganz oder teilweise vorläufige Annahmen'}`,
  );
  z.push(`- [Blog](${absoluteUrl(pfade.blog)}): alle Artikel, neueste zuerst`);
  z.push(`- [Kontakt](${absoluteUrl(pfade.kontakt)}): E-Mail für Fehlerhinweise, Produktvorschläge und Fragen`);
  z.push('');

  z.push('## Artikel', '');
  if (artikel.length === 0) {
    z.push('Noch keine Artikel veröffentlicht.');
  }
  for (const a of artikel) {
    const html = absoluteUrl(pfade.artikel(a.id));
    const stand = datumIso(a.data.stand);
    const md = hatMarkdownFassung(a) ? ` [Markdown-Fassung](${absoluteUrl(pfade.artikelMarkdown(a.id))})` : '';
    const beschreibung = a.data.description.trim().replace(/([^.!?])$/, '$1.');
    z.push(`- [${a.data.title}](${html}): ${beschreibung} Stand: ${stand}.${md}`);
  }
  z.push('');

  // Only target groups with published articles (empty pages are noindex).
  const gruppen = ZIELGRUPPEN_IDS.filter((id) => fuerZielgruppe(artikel, id).length > 0);
  z.push('## Zielgruppen', '');
  if (gruppen.length === 0) z.push('Noch keine Artikel für einzelne Zielgruppen veröffentlicht.');
  for (const id of gruppen) {
    z.push(`- [${ZIELGRUPPEN[id].name}](${absoluteUrl(pfade.zielgruppe(id))}): ${ZIELGRUPPEN[id].text}`);
  }
  z.push('');

  z.push('## Optional', '');
  z.push(`- [Impressum](${absoluteUrl(pfade.impressum)}): Angaben zum Betreiber`);
  z.push(`- [Datenschutzerklärung](${absoluteUrl(pfade.datenschutz)}): welche Daten beim Besuch anfallen`);
  z.push(`- [Sitemap](${absoluteUrl('sitemap-index.xml')}): alle Seiten als XML`);
  z.push('');

  return new Response(z.join('\n'), {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
};
