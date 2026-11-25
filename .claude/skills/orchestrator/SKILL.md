---
name: orchestrator
description: Ablauf je Aufgabe für die Hauptsitzung. Plant, zerlegt, startet Worker und Testagenten, prüft und berichtet, baut selbst nichts. Aktivieren bei jeder Änderung an der Website, an deploy/ oder an der Pipeline, auch bei "bau", "ändere", "füg hinzu", "mach das so".
---

# Orchestrator

Die Hauptsitzung plant und prüft. Gebaut wird von Workern, geprüft von
Testagenten, die den Code nicht geschrieben haben.

## Ablauf je Aufgabe

1. **Ziel und Abnahmekriterien** festhalten und dem Auftraggeber in eigenen Worten
   zurückgeben. Erst nach seinem Ja weiter.
2. **Worker wählen:**

   | Aufgabe | Agent |
   | --- | --- |
   | Tippfehler, Umbenennung, eine Zeile Konfiguration | `kleinkram` |
   | Komponente, Seite, Styles, Pipeline-Datei | `builder` |
   | Docker, Traefik, Deploy, Sicherheit, schwere Fehler | `builder-schwer` |

3. **Feature-Zweig** anlegen (`git checkout -b <art>/<kurzname> origin/main`), dann
   den Worker mit Ziel, Abnahmekriterien und Zweig starten.
4. **Testagent wählen:** `tester` bei geändertem Verhalten oder Aufbau, sonst
   `tester-check`. Verlangt `tester-check` neue Tests, übernimmt `tester`.
   Keine Änderung ohne Testagent. Der Testagent bekommt Ziel, Abnahmekriterien und
   Diff, nicht die Erklärung des Workers.
5. **`git diff --name-only`** prüfen: Testagenten haben nur unter `site/tests/`
   geschrieben (Konfiguration der Prüfwerkzeuge nur, wenn ausdrücklich beauftragt).
6. **Bei Rot** entscheiden, ob Code oder Test falsch ist, und den Richtigen
   beauftragen. Nie einen Test abschwächen, um grün zu werden.
7. **Bei Inhalt:** Skill `seo-check`.
8. **`reviewer`** liest den fertigen Diff.
9. **Pull Request** öffnen (Beschreibung: was, warum, Annahmen, offene Punkte,
   Risiken, Prüfergebnisse), nach dem Merge Skill `deploy-check`, dann Bericht an
   den Auftraggeber.

## Regeln

- Jede Rückmeldung mit Beleg: der Befehl und seine echte Ausgabe.
- Vor Änderungen an Server, DNS oder Kosten fragen und auf Ja warten.
- Was der Auftraggeber selbst tun muss, als nummerierte Schritte mit genauem Ort.
