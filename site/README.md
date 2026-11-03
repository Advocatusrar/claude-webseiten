# Website: Feuerstahl, Striker und Verbindung

Unabhängige deutschsprachige Informationsquelle und Vergleichstest zu Feuerstahl
(Ferrocerium-Stab), Striker (Schaber) und der Verbindung zwischen beiden
(Shockcord, Schnur). Die Betreiber testen selbst. Keine Werbung, keine
Affiliate-Links, kein Tracking, keine Cookies.

Gebaut mit [Astro](https://astro.build/) als statische Seite, ausgeliefert als
Docker-Image (nginx) hinter Traefik auf einem eigenen Server. Pipeline und Server:
[`../docs/ci-cd.md`](../docs/ci-cd.md), [`../docs/server.md`](../docs/server.md).

Regeln für KI-Agenten, die die Seite pflegen: [`CLAUDE.md`](CLAUDE.md).

## Lokale Entwicklung

Voraussetzung: Node.js 26 oder neuer (siehe `engines` in `package.json` und `.nvmrc`).

```sh
cd site
npm install        # einmalig (in CI: npm ci), richtet auch die Git-Hooks ein
npm run dev        # Entwicklungsserver, http://localhost:4321/ (zeigt auch Entwürfe)
npm test           # Unit-Tests, Build, Seitenprüfung, HTML-Validierung
npm run test:e2e   # Browsertests mit Barrierefreiheitsprüfung (einmalig: npx playwright install chromium)
npm run verify     # alles wie die CI: Format, Typen, npm test, Browsertests
npm run preview    # gebaute Seite lokal ansehen
```

`npm test` führt die Unit-Tests aus (`tests/unit/`, u. a. alle Rechnerformeln), baut die Seite, validiert das HTML und prüft mit `scripts/check-site.mjs`: interne Links und Anker (auch in `llms.txt` und den
Markdown-Fassungen `/blog/<slug>.md`), keine eingebundenen externen Ressourcen und
kein Tracking (auch in CSS, SVG und `<style>`), genau eine H1, `lang="de"` und eine
Meta-Description pro Seite, gültiges JSON-LD, die Sitemaps (nur indexierbare
HTML-Seiten), dass kein Entwurf (`draft: true`) in `dist/` auftaucht, und
Platzhalter wie `[Vorname Nachname]` oder `example.org`. Platzhalter sind lokal und
in Pull Requests nur ein Hinweis; mit `CHECK_LIVE=1` sind sie ein Fehler
(`CHECK_LIVE=1 npm test`).

Entwürfe (`draft: true`) zeigt nur `npm run dev`, mit dem Hinweis „Entwurf“ und
`noindex`. Im Build, in Listen, Sitemap, `llms.txt` und den Markdown-Fassungen
fehlen sie. Links aus anderen Artikeln auf einen Entwurf oder einen noch nicht
geschriebenen Artikel erscheinen als Text mit „(Artikel folgt)“ und werden zum Link,
sobald der Artikel veröffentlicht ist (`src/lib/verweise.ts`).

## Struktur

| Pfad                              | Inhalt                                                                                                                                                                                                                                                   |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `astro.config.mjs`                | Astro-Konfiguration, Sitemap; Adresse aus `adresse.mjs` (`SITE_URL`, `BASE_PATH`)                                                                                                                                                                        |
| `src/site.ts`                     | Seitenname, Claim, Betreiberdaten                                                                                                                                                                                                                        |
| `src/content.config.ts`           | Schema für Artikel (`blog`) und Produkte (`produkte`)                                                                                                                                                                                                    |
| `src/content/blog/`               | Artikel als Markdown, Vorlage `_vorlage.md`                                                                                                                                                                                                              |
| `src/content/produkte/`           | Produkte als JSON, Vorlage `_vorlage.json`                                                                                                                                                                                                               |
| `src/data/rechner.json`           | Parameter der beiden Rechner mit Status                                                                                                                                                                                                                  |
| `src/texte/`                      | Impressum, Datenschutz, Testmethodik (Markdown)                                                                                                                                                                                                          |
| `src/pages/`                      | Seiten: Basecamp, Vergleichstest, Blog, Kontakt, Impressum, Datenschutz, 404, `llms.txt`, Markdown-Fassungen der Artikel                                                                                                                                 |
| `src/components/`                 | Kopf, Fuß, Artikelliste, Rechner                                                                                                                                                                                                                         |
| `src/lib/`                        | Hilfsfunktionen: `url.ts` (Basis-Pfad), `rechner.ts` (Rechenlogik für Server und Browser), `regler.ts` (Eingabefelder der Rechner), `verweise.ts` (Links auf unveröffentlichte Artikel), `blog.ts`, `labels.ts`, `format.ts`, `jsonld.ts`, `markdown.ts` |
| `src/styles/global.css`           | Farben, Typografie, Hell/Dunkel                                                                                                                                                                                                                          |
| `public/`                         | `favicon.svg`, `og-bild.png` (Vorschaubild 1200 × 630 für geteilte Links), `logo.png` (Logo für strukturierte Daten)                                                                                                                                     |
| `scripts/check-site.mjs`          | Prüfskript ohne Abhängigkeiten                                                                                                                                                                                                                           |
| `tests/`, `Dockerfile`, `docker/` | Unit- und Browsertests; Produktions-Image (nginx-Konfiguration in `docker/nginx.conf`)                                                                                                                                                                   |

## Artikel anlegen

1. `src/content/blog/_vorlage.md` kopieren nach `src/content/blog/<slug>.md`.
2. Frontmatter ausfüllen (Pflichtfelder: `title`, `description`, `pubDate`,
   `stand`, `themen`, `zielgruppen`, `quellen`), Text schreiben.
3. `draft: false` setzen, `npm test` ausführen, Pull Request öffnen.

Der Artikel erscheint unter `/blog/<slug>/`, im Blog, auf den passenden
Zielgruppen-Seiten, im Basecamp unter seinen Themen, in der Sitemap, in
`llms.txt` und als Markdown unter `/blog/<slug>.md`.

## Produkt anlegen

1. `src/content/produkte/_vorlage.json` kopieren nach
   `src/content/produkte/<hersteller>-<modell>.json`.
2. Name, Hersteller, Kategorie und Herstellerangaben (mit Quelle) eintragen.
3. Den Block `eigenerTest` erst nach einem eigenen Test ausfüllen, sonst löschen.

## Deploy

Siehe [`../docs/ci-cd.md`](../docs/ci-cd.md). Kurz: Jeder Pull Request durchläuft
Qualitätsprüfung, Image-Build, Browsertests gegen das Image und Sicherheitsscan. Nach
dem Merge in `main` wird genau dieses Image veröffentlicht und auf den Server deployt,
sobald die Repository-Variable `DEPLOY_ENABLED` auf `true` steht. Dann gilt
`CHECK_LIVE=1`: Solange Platzhalter (Impressum, Datenschutz, `src/site.ts`,
`example.org`) übrig sind, bricht der Build ab und nichts geht online.

Die Adresse der Seite kommt aus `SITE_URL` (Repository-Variable, im Image als
Build-Argument). `BASE_PATH` braucht es nur, wenn die Seite nicht an der Wurzel der
Domain liegt. `robots.txt` und `llms.txt` werden mit dieser Adresse erzeugt.

## Offene Platzhalter

- `src/site.ts`: Seitenname „Funkenschlag“ ist ein Arbeitstitel; Betreiber-Name,
  Anschrift und E-Mail stehen noch in `[eckigen Klammern]`. Die Kontaktseite zeigt
  den E-Mail-Knopf erst, wenn dort eine echte Adresse steht.
- Der Claim in `src/site.ts` sagt „unabhängig erklärt“. „getestet“ erst wieder
  aufnehmen, wenn Produkte mit eigenem Test veröffentlicht sind.
- `src/texte/impressum.md`, `datenschutz.md`, `testmethodik.md`: Inhalte werden
  separat erstellt; Impressum und Datenschutz müssen vor dem Livegang vollständig
  sein.
- `src/data/rechner.json`: Parameter mit `status: "annahme"` durch Quellen oder
  eigene Messungen ersetzen.
- `src/content/produkte/`: noch keine Produkte und keine eigenen Testergebnisse.
  Bis zum ersten Produkt meldet jeder Build `[WARN] [glob-loader] No files found
matching "**/[^_]*.json" in directory "src/content/produkte"`. Diese Warnung ist
  erwartet und verschwindet mit dem ersten Produkt. Keine Scheindatei anlegen.
- Zielgruppen ohne veröffentlichten Artikel (zurzeit Linkshänder) bekommen
  `noindex` und fehlen in Sitemap und `llms.txt`, bis es einen Artikel gibt.
- Domain: `SITE_URL` ist noch nicht gesetzt, gebaut wird mit `https://www.example.org`.
