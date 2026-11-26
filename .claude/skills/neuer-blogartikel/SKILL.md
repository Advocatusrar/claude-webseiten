---
name: neuer-blogartikel
description: Legt einen neuen Blogartikel für die Website in site/ an, von der Leitfrage über Recherche und Frontmatter bis zum grünen npm test, danach seo-check und tester. Aktivieren bei "neuer Artikel", "Artikel anlegen", "schreib einen Artikel über", "Blogbeitrag zu", "Artikel für die Seite". Nicht für Produkte im Vergleichstest.
---

# Neuer Blogartikel

Verbindlich sind die Regeln in `site/CLAUDE.md`. Dieser Skill gibt nur die
Reihenfolge vor. Widerspricht etwas hier der `site/CLAUDE.md`, gilt die
`site/CLAUDE.md`. Übernommen aus dem Skill `artikel-anlegen` des Übungs-Repos.

## 1. Auftrag klären

Vor dem Schreiben müssen feststehen:

- **Leitfrage des Lesers**, die der Titel beantwortet (z. B. „Welcher Striker für
  Handschuhe?“)
- **themen** und **zielgruppen** aus den Werten in `site/src/content.config.ts`.
  Passt kein Wert, nachfragen. Neue Werte nur nach Zustimmung, dann Schema **und**
  `site/src/lib/labels.ts` ergänzen.
- **Autor**: Standard „Redaktion“, nur auf ausdrücklichen Wunsch ein Name.

Fehlt die Leitfrage oder ist die Zielgruppe offen, fragen statt raten.

Vorhandene Artikel in `site/src/content/blog/` überfliegen: Gibt es das Thema
schon, eher den bestehenden Artikel erweitern und das vorschlagen.

## 2. Zweig

Den Feature-Zweig legt der Orchestrator an, etwa `content/<slug>`. Slug:
Kleinbuchstaben, Bindestriche, keine Umlaute (ä → ae, ß → ss), kurz, aus der
Leitfrage abgeleitet, ohne Datum. Er wird Teil der URL `/blog/<slug>/` und bleibt
für immer.

## 3. Recherche

- Jede Faktenaussage braucht eine Quelle mit `titel`, `url` und `abgerufen`
  (heutiges Datum). Was sich nicht belegen lässt: weglassen oder als offene Frage
  formulieren.
- Herstellerangaben im Text als „laut Hersteller“ kennzeichnen.
- **Niemals** Messwerte, Testergebnisse, Erfahrungsberichte, Bewertungen oder Zitate
  erfinden. Wo eigene Tests fehlen: „Noch nicht getestet“.

## 4. Datei anlegen

```bash
cp site/src/content/blog/_vorlage.md site/src/content/blog/<slug>.md
```

Frontmatter füllen und die Kommentare der Vorlage entfernen:

| Feld | Prüfen |
| --- | --- |
| `title` | Ziel bis etwa 60 Zeichen (Schema erlaubt höchstens 70), beantwortet die Leitfrage |
| `description` | 50 bis 155 Zeichen (Schema: 50 bis 160), enthält die Antwort |
| `pubDate` | geplantes Veröffentlichungsdatum |
| `stand` | heute |
| `updatedDate` | nur bei Überarbeitung nach Veröffentlichung („aktualisiert am“) |
| `autor` | aus Schritt 1 |
| `testbasiert` | `false`, außer der Artikel enthält Ergebnisse eigener Tests |
| `quellen` | alle Quellen aus Schritt 3, keine `example.org` |
| `faq` | echte Leserfragen, Antworten in ein bis drei Sätzen |
| `draft` | `true` lassen, bis der Auftraggeber freigibt |

Zeichen zählen, nicht schätzen:
`node -e 'console.log([...process.argv[1]].length)' "<text>"`

**Titelbild:** Das Schema hat noch kein Feld dafür. Bis es eins gibt (AVIF oder
WebP mit Alt-Text), entfällt das Titelbild. Das im Bericht nennen.

Strukturierte Daten (`BlogPosting`, `BreadcrumbList`, `FAQPage`) erzeugt die Seite
aus dem Frontmatter selbst.

## 5. Text schreiben

- Die Leitfrage steht als Überschrift oder im Titel, die Antwort direkt danach in
  zwei, drei Sätzen.
- Zwischenüberschriften ab `##`, Fakten in Tabellen mit `Tabelle: …`-Absatz davor,
  Anleitungen mit nummerierten Schritten.
- Mindestens **zwei interne Links** auf verwandte Artikel oder Seiten, relativ und
  mit Schrägstrich am Ende, z. B. `../anderer-artikel/`.
- Anrede du, typografische Anführungszeichen „so“ und ‚so‘, keine Gedankenstriche
  (– oder —), Spannen als „80 bis 100 mm“.
- FAQ und Quellen nicht im Text wiederholen.

## 6. Prüfen

```bash
cd site && npm run format:check && npm run typecheck && npm test
```

Danach Skill `seo-check`, dann übernimmt der Agent `tester`.

## 7. Bericht

- Datei und Zweig
- welche Aussagen offen geblieben sind und warum
- dass `draft: true` noch gesetzt ist (falls ja) und Messwerte nur von Menschen
  eingetragen werden
- fehlendes Titelbild (siehe Schritt 4)
