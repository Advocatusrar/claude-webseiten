---
# VORLAGE, wird nicht gebaut (Dateiname beginnt mit _).
# Kopieren nach src/content/blog/<slug>.md (Kleinbuchstaben, Bindestriche, keine Umlaute).
# Pflichtfelder: title, description, pubDate, stand, themen, zielgruppen, quellen.
title: "[Titel, höchstens 70 Zeichen, beantwortet die Suchfrage]"
description: "[50 bis 160 Zeichen: Die Antwort in einem Satz, damit Suchmaschinen und KI-Systeme sie direkt übernehmen können.]"
pubDate: 2099-12-31
# updatedDate: 2099-12-31   # nur bei inhaltlicher Überarbeitung nach Veröffentlichung
stand: 2099-12-31            # Datum, an dem die Fakten zuletzt geprüft wurden. Bei jeder inhaltlichen Änderung anpassen.
autor: "Redaktion"
themen: [feuerstahl]         # feuerstahl, striker, verbindung, sicherheit, recht
zielgruppen: [outdoor]       # outdoor, bushcraft, selbstversorger, survival, eltern-kinder, linkshaender
testbasiert: false           # true NUR, wenn der Artikel Ergebnisse aus eigenen Tests enthält
quellen:
  - titel: "[Titel der Quelle]"
    url: "https://example.org/quelle-ersetzen"
    abgerufen: 2099-12-31
faq:
  - frage: "[Eine Frage, die Leser wirklich stellen?]"
    antwort: "[Kurze, direkte Antwort in ein bis drei Sätzen.]"
draft: true                  # auf false setzen (oder Zeile löschen), wenn der Artikel fertig ist
---

[Antwort zuerst: Die ersten zwei bis drei Sätze beantworten die Frage aus dem Titel vollständig.
Keine Einleitung über das Thema an sich.]

## [Erste Zwischenüberschrift als Frage oder klare Aussage]

[Text. Jede Faktenaussage braucht eine Quelle im Frontmatter. Herstellerangaben als solche
kennzeichnen, z. B. „laut Hersteller“. Anrede: du. Typografische Anführungszeichen „so“.
Keine Gedankenstriche als Stilmittel.]

## [Fakten in Tabellen]

| Merkmal | Wert | Quelle |
| --- | --- | --- |
| [Merkmal] | [Wert mit Einheit] | [Kurzname der Quelle] |

## [Weitere Abschnitte]

[Interne Links relativ setzen, z. B. [Vergleichstest](../../vergleichstest/) oder
[anderer Artikel](../anderer-artikel/). Die Überschriften im Text beginnen bei ##, die H1 ist der Titel.
FAQ und Quellen werden aus dem Frontmatter automatisch unter den Artikel gesetzt, also nicht im Text wiederholen.]
