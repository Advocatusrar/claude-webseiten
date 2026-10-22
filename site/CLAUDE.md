# Regeln für Agenten, die die Website pflegen

Diese Regeln gelten für alles in `site/`. Die Website ist eine unabhängige,
deutschsprachige Informationsquelle und ein Vergleichstest zu Feuerstahl
(Ferrocerium-Stab), Striker (Schaber) und der Verbindung zwischen beiden
(Shockcord, Schnur). Keine Werbung, keine Affiliate-Links, kein Tracking.

## Wahrheit vor Vollständigkeit

- **Messwerte und Testergebnisse kommen nur von Menschen.** Die Betreiber testen
  selbst. Agenten erfinden niemals Messwerte, Testergebnisse, Erfahrungsberichte,
  Bewertungen oder Zitate. Fehlt ein Wert, bleibt das Feld leer oder steht als
  „Noch nicht getestet“ da.
- **Jede Faktenaussage braucht eine Quelle** im Frontmatter (`quellen`) mit
  `titel`, `url` und Abrufdatum `abgerufen`. Was sich nicht belegen lässt, wird
  weggelassen oder als offene Frage formuliert.
- **Herstellerangaben kennzeichnen**, im Text z. B. „laut Hersteller“, in
  Produktdateien nur unter `herstellerangaben` mit `quelle_url`. Herstellerangaben
  und eigene Messwerte nie vermischen.
- **`stand` bei jeder inhaltlichen Änderung aktualisieren** (Datum, an dem die
  Fakten zuletzt geprüft wurden). Bei Überarbeitung nach Veröffentlichung zusätzlich
  `updatedDate` setzen. Reine Tippfehler-Korrekturen ändern `stand` nicht.
- `testbasiert: true` nur, wenn der Artikel Ergebnisse aus eigenen Tests enthält.

## Stil

- Anrede: **du**.
- Antwort zuerst: Die ersten Sätze beantworten die Frage aus dem Titel. Klare
  Zwischenüberschriften, Fakten in Tabellen, Quellen mit Datum. So können Menschen
  und KI-Systeme die Inhalte gut auslesen.
- **Keine Gedankenstriche als Stilmittel** (weder – noch —). Lieber zwei Sätze,
  ein Komma oder einen Doppelpunkt. Spannen als „80 bis 100 mm“ schreiben.
- **Typografische Anführungszeichen**: „so“ und ‚so‘, nicht "so".
- Überschriften im Artikeltext beginnen bei `##`. Die H1 ist der Titel aus dem
  Frontmatter. (Die Seite verschiebt zu hohe Überschriften automatisch, darauf
  aber nicht verlassen.)
- FAQ und Quellen stehen im Frontmatter und werden automatisch unter den Artikel
  gesetzt. Nicht zusätzlich im Text wiederholen.

## Technik

- **Interne Links relativ** setzen, z. B. `[Vergleichstest](../../vergleichstest/)`
  oder `[anderer Artikel](../anderer-artikel/)` aus einem Artikel heraus. Immer mit
  Schrägstrich am Ende (`trailingSlash: 'always'`). In `.astro`-Dateien interne
  Links nur über `url()` aus `src/lib/url.ts` bilden (Basis-Pfad).
- **Links auf Artikel, die es noch nicht gibt** (Entwurf oder nicht geschrieben),
  erscheinen auf der Seite und in der Markdown-Fassung als Text mit „(Artikel folgt)“
  und werden zum Link, sobald der Artikel veröffentlicht ist (`src/lib/verweise.ts`).
  Listen, die ausdrücklich auf Artikel verweisen („steht in diesen Artikeln:“),
  nennen trotzdem nur veröffentlichte Artikel.
- **Tabellen** in Markdown bekommen automatisch einen Scrollbereich, `scope="col"`
  und auf kleinen Bildschirmen eine gestapelte Darstellung. Einen Tabellentitel
  setzt ein eigener Absatz direkt vor der Tabelle, der mit `Tabelle:` beginnt, z. B.
  `Tabelle: Stabgrößen im Überblick`. Er wird zur `<caption>`. Ohne ihn heißt der
  Bereich nach der Zwischenüberschrift davor.
- **Keine externen Ressourcen einbinden**: keine Web-Fonts, keine CDNs, keine
  Skripte, Stylesheets, Bilder, iframes oder Videos von fremden Servern. Bilder
  liegen im Repository. Externe Links (`<a href>`) zu Quellen sind erlaubt.
- Keine Tracker, keine Cookies, keine Analyse-Dienste, kein Kontaktformular.
- Neue Pakete nur nach Rücksprache mit den Betreibern.
- Rechenlogik der Rechner nur in `src/lib/rechner.ts` ändern (wird von Server und
  Browser gemeinsam genutzt).

## Arbeitsablauf

1. Jede Änderung auf einem **eigenen Branch** (z. B. `content/artikel-xyz`).
2. Vor dem Push in `site/` ausführen: **`npm test`** (der Git-Hook vor dem Push macht
   das automatisch, dazu die Typprüfung) (baut die Seite und prüft
   Links und Anker auch in `llms.txt` und den `.md`-Fassungen, externe Ressourcen und
   Tracking, H1, `lang`, Meta-Description, JSON-LD, Sitemaps, dass kein Entwurf in
   `dist/` auftaucht, und Platzhalter). Erst pushen, wenn der Test grün ist.
3. **Pull Request** gegen `main` öffnen. Die Pipeline prüft erneut, zusätzlich mit
   Browsertests und Sicherheitsscan (`docs/ci-cd.md`); nach dem Merge wird das getestete
   Image auf den Server deployt. Beim Deploy gilt
   `CHECK_LIVE=1`: Platzhalter wie `[Vorname Nachname]` oder `example.org` sind dann
   Fehler und verhindern die Veröffentlichung.

## Artikel anlegen

Vorlage: `src/content/blog/_vorlage.md` kopieren nach
`src/content/blog/<slug>.md` (Kleinbuchstaben, Bindestriche, keine Umlaute). Der
Slug wird Teil der URL: `/blog/<slug>/`, Markdown-Fassung unter `/blog/<slug>.md`.

Pflichtfelder (Schema: `src/content.config.ts`):

| Feld          | Regel                                                                                                      |
| ------------- | ---------------------------------------------------------------------------------------------------------- |
| `title`       | höchstens 70 Zeichen                                                                                       |
| `description` | 50 bis 160 Zeichen, enthält die Antwort                                                                    |
| `pubDate`     | Veröffentlichungsdatum, `JJJJ-MM-TT`                                                                       |
| `stand`       | Datum der letzten Faktenprüfung                                                                            |
| `themen`      | mindestens eins aus `feuerstahl`, `striker`, `verbindung`, `sicherheit`, `recht`                           |
| `zielgruppen` | mindestens eine aus `outdoor`, `bushcraft`, `selbstversorger`, `survival`, `eltern-kinder`, `linkshaender` |
| `quellen`     | mindestens eine, je `titel`, `url`, `abgerufen`                                                            |

Optional: `updatedDate`, `autor` (Standard „Redaktion“; ein anderer Name erscheint
in den strukturierten Daten als Person), `testbasiert` (Standard `false`), `faq`
(Liste aus `frage`/`antwort`), `draft` (`true` = wird nicht veröffentlicht; mit
`npm run dev` als „Entwurf“ ansehbar).

Neue Werte für `themen` oder `zielgruppen` erst im Schema ergänzen und dann in
`src/lib/labels.ts` einen Anzeigenamen eintragen.

## Produkt anlegen

Vorlage: `src/content/produkte/_vorlage.json` kopieren nach
`src/content/produkte/<hersteller>-<modell>.json`.

Pflichtfelder: `name`, `hersteller`, `kategorie` (`feuerstahl`, `striker`, `set`),
`herstellerangaben` (Objekt, darf leer sein; Werte nur mit `quelle_url`).
Optional: `preis_eur` (`wert`, `stand`), `linkshaender` und `kinderfreundlich`
(`ja`, `nein`, `eingeschraenkt`, `ungeprueft`; Standard `ungeprueft`).

Der Block `eigenerTest` (`getestet_am`, `tester`, `gemessen`, `bewertung`, optional
`notizen`) wird **nur von Menschen nach einem eigenen Test** eingetragen. Sobald ein
Produkt `eigenerTest` hat, erscheint es auf der Vergleichstest-Seite als getestet und
bekommt strukturierte Daten (Product/Review).

## Rechner-Parameter

Die Werte stehen in `src/data/rechner.json`. Jeder Parameter und jede Altersgruppe
hat einen `status`:

| Status     | Bedeutung                      | Anzeige                                                                                                                                                                               |
| ---------- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `annahme`  | Platzhalter, noch nicht belegt | „Annahme“, plus Hinweis „Vorläufige Werte“ über dem Rechner (sagt „Alle“ oder „Einige“); Ergebnis als „vorläufiger Richtwert“ bzw. „mit den vorläufigen Annahmen“, nie als Empfehlung |
| `quelle`   | belegter Literaturwert         | „Quelle“ mit Link; `quelle` als URL oder `{ "titel", "url", "abgerufen" }`                                                                                                            |
| `gemessen` | eigene Messung der Betreiber   | „Eigene Messung“                                                                                                                                                                      |

Optionale Felder wie `begruendung`, `hinweis`, `quelle`/`quellen` und `handmasse`
werden angezeigt, wenn sie vorhanden sind. `gemessen` setzen nur Menschen nach einer
eigenen Messung. `stand` oben in der Datei bei jeder Änderung anpassen.

## Werbung und Affiliate-Links

Zurzeit gibt es **keine Werbung und keine Affiliate-Links**. Das ändert sich nur nach
ausdrücklicher Entscheidung der Betreiber. Dann wird jede Werbung und jeder
Affiliate-Link klar als „Werbung“ / „Anzeige“ gekennzeichnet (§ 6 DDG), und die
Aussagen „Keine Werbung“ auf der Website (Fußzeile, Basecamp, Vergleichstest,
Kontakt, llms.txt) werden angepasst. Agenten fügen von sich aus nie Werbung,
Affiliate-Links oder Sponsoring-Hinweise ein.
