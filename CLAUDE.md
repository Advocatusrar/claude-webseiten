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
