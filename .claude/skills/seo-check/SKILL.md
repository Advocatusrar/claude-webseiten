---
name: seo-check
description: Prüft vor jedem Pull Request mit Inhalt jede neue oder geänderte Seite auf die SEO-Pflichten und meldet, was fehlt. Ändert nichts. Aktivieren bei "SEO prüfen", "seo-check", vor einem PR mit Artikel, Seite oder Produkt, auch nach neuer-blogartikel.
---

# SEO-Check

Prüft die gebauten Seiten in `site/dist/`, nicht nur die Quelle. Ändert nichts,
das macht der Worker.

## Vorbereitung

```bash
cd site && npm test   # baut die Seite und prüft H1, lang, Meta-Description, JSON-LD, Sitemaps
```

`npm test` deckt schon ab: genau eine H1, `lang`, nicht leere Meta-Description,
parsebares JSON-LD, Sitemaps, interne Links, keine fremden Ressourcen. Bei Rot zuerst
das melden.

## Je geänderter Seite prüfen

| Punkt | Erwartung |
| --- | --- |
| URL | Kleinbuchstaben, sprechend, ohne Datum, mit `/` am Ende |
| `<title>` | eigener Titel, bis etwa 60 Zeichen, keine Dublette |
| Meta-Description | eigene, bis etwa 155 Zeichen, enthält die Antwort, keine Dublette |
| Überschriften | genau eine H1, keine Sprünge (H2 nach H1, H3 nach H2) |
| canonical | `https`, Adresse ohne www |
| Open Graph | Titel, Beschreibung, Bild |
| JSON-LD | passender Typ (`BlogPosting` je Artikel, `BreadcrumbList`), Pflichtfelder nach schema.org |
| Bilder | AVIF oder WebP, `width`, `height`, Alt-Text, `loading="lazy"` unterhalb des ersten Bildschirms |
| interne Links | Artikel verlinkt mindestens zwei verwandte Seiten, Seite ist von der Startseite in wenigen Klicks erreichbar |
| Sitemap | Seite steht in der Sitemap (außer `noindex`) |
| Inhalt | Leitfrage als Überschrift, Antwort direkt danach in zwei, drei Sätzen |

Zeichen zählen, nicht schätzen:
`node -e 'console.log([...process.argv[1]].length)' "<text>"`

## Bericht

Je Seite eine Liste: was fehlt, mit Datei und Wert. Nichts fehlt: ein Satz.
