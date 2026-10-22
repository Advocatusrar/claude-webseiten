# Feuerstahl, Striker und Verbindung: Website

Unabhängige deutschsprachige Informationsquelle und Vergleichstest zu Feuerstahl
(Ferrocerium-Stab), Striker (Schaber) und der Verbindung zwischen beiden (Shockcord,
Schnur), mit zwei Rechnern (Lebensdauer eines Stabs, Stabgröße nach Alter).
Keine Werbung, keine Affiliate-Links, kein Tracking.

| Ordner     | Inhalt                                                                                  |
| ---------- | --------------------------------------------------------------------------------------- |
| `site/`    | Website (Astro, statisch), Tests, Dockerfile – siehe [`site/README.md`](site/README.md) |
| `deploy/`  | Server: Docker Compose mit Traefik, Deploy- und Einrichtungsskript                      |
| `docs/`    | [CI/CD](docs/ci-cd.md) und [Server](docs/server.md)                                     |
| `.github/` | Pipeline `workflows/ci-cd.yml`, Dependabot                                              |

```sh
cd site && npm install && npm run dev   # lokal entwickeln
cd site && npm run verify               # alle Prüfungen wie in der CI
```

Änderungen kommen nur per Pull Request nach `main`. Die Pipeline prüft jeden Pull
Request (Tests, Docker-Image, Browsertests, Sicherheitsscan); nach dem Merge wird das
getestete Image auf den Server deployt.
