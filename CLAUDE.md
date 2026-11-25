# Projektkontext für Claude Code

Website zu Feuerstahl, Striker und deren Verbindung (Shockcord): unabhängige
Informationsquelle und Vergleichstest für Outdoor-Leute, Bushcrafter, Selbstversorger,
Survival-Interessierte, Eltern und Linkshänder. Gepflegt mit Hilfe von KI-Agenten.

## Konventionen

- Sprache im Code und in Commit-Messages: Englisch. Diskussion und Website-Inhalte: Deutsch.
- Für alles in `site/` gelten die Regeln in `site/CLAUDE.md`, vor allem: Messwerte und
  Testergebnisse kommen nur von Menschen, jede Faktenaussage braucht eine Quelle.
- Jede Änderung auf einem eigenen Branch und als Pull Request gegen `main`. `main` ist
  geschützt und nimmt nur Pull Requests mit grünen Checks an (`docs/ci-cd.md`).
- Vor dem Push in `site/`: `npm test` (der Git-Hook macht das automatisch).
- Server-Konfiguration in `deploy/` ändert sich wie Code: per Pull Request, danach nach
  `docs/server.md` auf den Server übertragen.

## Befehle (in `site/`)

- `npm run dev`: lokaler Server
- `npm run build`: Build nach `dist/`
- `npm test`: Unit-Tests, Build, Seitenprüfung, HTML-Validierung
- `npm run test:e2e`: Browsertests mit Barrierefreiheitsprüfung

## Zweigmodell

Feature-Zweig → Pull Request nach `main`. Sobald Staging steht:
Feature-Zweig → Pull Request nach `staging` → Pull Request nach `main`.

## Regeln

- Jede Änderung geht durch den Agenten `tester` oder `tester-check`. Tests schreibt nie,
  wer den Code geschrieben hat. (Gilt, sobald die Agenten angelegt sind.)
- Nie direkt auf `staging` oder `main` pushen, nie per Hand auf dem Server deployen.
  Alles geht per Pull Request durch die Pipeline.
- „Fertig“ heißt: `npm test` lokal grün, Pipeline grün; sobald Staging steht, zeigt
  `version.txt` auf Staging den Commit.
- Versionen von Paketen, Actions und Images immer live prüfen.
- Keine Ressourcen von fremden Servern (Schriften, Skripte, CSS, Bilder). Bei jeder
  neuen Funktion prüfen, ob Impressum oder Datenschutzerklärung angepasst werden müssen.
- Jede neue oder geänderte Seite erfüllt die SEO-Pflichten (Skill `seo-check`, sobald
  angelegt).
- Sicherheits-Header und Content-Security-Policy nie ohne Rückfrage aufweichen.
- Keine Secrets in Repo, Logs oder Chat.
- Vor Änderungen an Server, DNS oder Kosten fragen.
- Was der Auftraggeber selbst tun muss, als nummerierte Schritte mit genauem Ort.
