---
name: deploy-check
description: Beobachtet nach einem Merge die Pipeline und prüft die ausgelieferte Seite, also version.txt gegen den Commit, Zertifikat, Weiterleitungen und Sicherheits-Header. Aktivieren nach jedem Merge nach staging oder main, bei "ist es live", "prüf das Deployment", "hat der Deploy geklappt".
---

# Deploy-Check

## 1. Pipeline beobachten

- Mit `gh run list --branch <staging|main> --limit 3` und `gh run watch <id>`
  oder, ohne `gh`, mit den GitHub-Werkzeugen der Sitzung den Lauf zum Merge-Commit
  finden und bis zum Ende verfolgen.
- Bei Rot: Log des fehlgeschlagenen Jobs lesen und die Ursache mit dem
  Logauszug nennen. Nicht raten.
- Übersprungene Jobs („Publish image“, „Deploy to production“) heißen: nichts
  ausgeliefert. Den Grund nennen (etwa fehlendes `DEPLOY_ENABLED`).

## 2. Ausgelieferte Seite prüfen (nur nach grünem Deploy)

`<url>` ist die Zieladresse (Staging oder Live).

| Prüfung | Befehl | Erwartung |
| --- | --- | --- |
| Version | `curl -fsS <url>/version.txt` | gleich dem Merge-Commit (`git rev-parse origin/<zweig>`) |
| Zertifikat | `curl -sSI <url>` | kein TLS-Fehler, Status 200 |
| http auf https | `curl -sSI http://<domain>/` | 301 oder 308 auf `https://` |
| ohne www | `curl -sSI https://www.<domain>/` | Weiterleitung auf die Adresse ohne www |
| Header | `curl -sSI <url>` | `strict-transport-security`, `content-security-policy`, `x-content-type-options`, `referrer-policy`, `permissions-policy` |
| Indexierung | `curl -sSI <url>` | Staging mit `x-robots-tag: noindex`, Live ohne |

`version.txt` gibt es erst, wenn die Pipeline sie schreibt. Fehlt sie, das als
Befund melden.

## 3. Bericht

Je Prüfung: bestanden, fehlgeschlagen oder nicht ausgeführt mit Grund, jeweils mit
dem echten Ausgabeauszug. Eine nicht ausgeführte Prüfung gilt nie als bestanden.
