# CI/CD: vom Commit bis zur Live-Seite

```
 lokal                    GitHub: Pull Request (CI)                 GitHub: main (CD)
┌───────────────┐        ┌──────────────────────────────┐         ┌──────────────────────────┐
│ commit        │        │ 1 Qualität                   │         │ dieselben Prüfungen, dann │
│  └ Format,    │ push   │   Format, Typen, Unit-Tests, │  Merge  │ 5 Image veröffentlichen   │
│    Unit-Tests ├───────►│   Build, Seitenprüfung, HTML ├────────►│   (GHCR, sha-<commit>)    │
│ push          │        │ 2 Docker-Image bauen (1×)    │  nur    │ 6 Deploy auf den Server   │
│  └ Typen,     │        │ 3 Browsertests gegen Image   │  grün   │   (Freigabe, Rollback)    │
│    npm test   │        │ 4 Sicherheitsscan des Images │         │ 7 Live-Prüfung            │
└───────────────┘        └──────────────────────────────┘         └──────────────────────────┘
   Frühwarnung              verbindliche Prüfung                     nur getestetes Image
```

Datei: [`.github/workflows/ci-cd.yml`](../.github/workflows/ci-cd.yml).

## Grundsätze

- **Committen darf man immer**, auch halbfertig. Verbindlich ist erst die Prüfung auf
  GitHub: Nach `main` kommt nur ein Pull Request mit grünen Checks (Ruleset, unten).
- **Einmal bauen, genau das ausliefern.** Das Docker-Image wird einmal gebaut, getestet,
  gescannt und dann unverändert veröffentlicht und deployt.
- **Nur `main` wird deployt**, und erst, wenn die Variable `DEPLOY_ENABLED` auf `true`
  steht. Dann gilt `CHECK_LIVE=1`: Platzhalter im Impressum oder `example.org` brechen
  den Build ab, ein unvollständiges Impressum geht nie online.
- **Rollback statt Hoffnung.** Wird das neue Image auf dem Server nicht gesund, startet
  `deploy.sh` automatisch das vorige.

## Lokal

| Befehl (in `site/`)       | Was passiert                                                            |
| ------------------------- | ----------------------------------------------------------------------- |
| `npm run dev`             | Entwicklungsserver                                                      |
| `npm run test:unit`       | Unit-Tests (Vitest), u. a. alle Rechnerformeln                          |
| `npm test`                | Unit-Tests, Build, Seitenprüfung (`check-site`), HTML-Validierung       |
| `npm run typecheck`       | Typprüfung (`astro check`)                                              |
| `npm run test:e2e`        | Browsertests mit Barrierefreiheitsprüfung (Playwright + axe)            |
| `npm run format`          | Code formatieren (Prettier)                                             |
| `npm run verify`          | alles zusammen, wie die CI                                              |

Git-Hooks (Lefthook, [`lefthook.yml`](../lefthook.yml)) richten sich bei `npm install`
selbst ein:

- **pre-commit:** Format der geänderten Dateien, Unit-Tests (wenige Sekunden).
- **pre-push:** Typprüfung und `npm test`.

Browsertests lokal brauchen einmal `npx playwright install chromium`.

## Die Jobs

| Job                                   | Prüft                                                                                              |
| ------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Quality                               | Format, Typen, Unit-Tests, Build, Links/Anker, keine externen Ressourcen, JSON-LD, Entwürfe, HTML |
| Build Docker image                    | baut das Produktions-Image (nginx) einmal                                                          |
| Browser tests against the image       | alle Seiten aus der Sitemap: Status, eine H1, kein Querscrollen, axe (WCAG 2.1 AA), Rechner, Security-Header, 404, Caching |
| Security scan of the image            | Trivy: bekannte kritische/hohe Lücken mit verfügbarem Fix                                          |
| Publish image                         | nur `main` + `DEPLOY_ENABLED`: Image nach `ghcr.io/<owner>/<repo>/website`                         |
| Deploy to production                  | SSH auf den Server, `deploy.sh` mit dem Image-Digest, danach Live-Prüfung                          |

Alle Actions sind auf Commit-Hashes gepinnt. Tags lassen sich verschieben; bei
`aquasecurity/trivy-action` wurden im März 2026 fast alle Tags auf Schadcode umgebogen
(CVE-2026-33634). Dependabot ([`.github/dependabot.yml`](../.github/dependabot.yml))
aktualisiert Hashes, npm-Pakete und Docker-Images wöchentlich per Pull Request, und
jeder davon läuft durch dieselbe Pipeline.

## Einmalige Einrichtung in GitHub

### 1. Ruleset für `main` (die eigentliche Sperre)

Settings → Rules → Rulesets → New ruleset → New branch ruleset:

- Name: `main schützen`, Enforcement: **Active**
- Target branches: **Include default branch**
- **Restrict deletions** und **Block force pushes**
- **Require a pull request before merging** (Approvals: 0, solange ihr allein seid;
  mit zwei Personen 1)
- **Require status checks to pass**, „Require branches to be up to date“ an, Checks:
  - `Quality (format, types, unit tests, build, checks)`
  - `Build Docker image`
  - `Browser tests against the image`
  - `Security scan of the image`

  (Die Checks erscheinen in der Auswahl, sobald die Pipeline einmal gelaufen ist.)

### 2. Variablen (Settings → Secrets and variables → Actions → Variables)

| Variable         | Beispiel                     | Zweck                                         |
| ---------------- | ---------------------------- | --------------------------------------------- |
| `SITE_URL`       | `https://www.meine-domain.de` | Adresse für Canonical, Sitemap, JSON-LD      |
| `DEPLOY_HOST`    | `203.0.113.10`               | Server                                        |
| `DEPLOY_USER`    | `deploy`                     | Benutzer auf dem Server                       |
| `DEPLOY_ENABLED` | `true`                       | schaltet Veröffentlichen und Deploy ein       |

### 3. Environment `production` (Settings → Environments → New environment)

- **Required reviewers:** euch selbst eintragen. Dann wartet jeder Deploy auf einen
  Freigabe-Klick. Ohne Reviewer geht es nach dem Merge direkt live.
- **Deployment branches:** nur `main`.
- **Environment secrets:**
  - `DEPLOY_SSH_KEY`: privater Schlüssel des Deploy-Schlüsselpaars (siehe
    [`server.md`](server.md))
  - `DEPLOY_KNOWN_HOSTS`: Ausgabe von `ssh-keyscan <server>`, damit sich die CI nur mit
    eurem echten Server verbindet

### 4. Paket-Sichtbarkeit

Nach dem ersten Veröffentlichen unter Packages → `website` → Package settings: Ist das
Repository privat, bleibt das Image privat, und der Server braucht einmal
`docker login ghcr.io` mit einem Token (Recht `read:packages`).

## Rollback

- **Automatisch:** `deploy.sh` startet das vorige Image, wenn das neue nicht gesund wird.
- **Von Hand:** auf dem Server `sudo -u deploy /opt/website/deploy.sh
  ghcr.io/<owner>/<repo>/website:sha-<älterer-commit>`.
- **Sauber über Git:** den fehlerhaften Commit mit `git revert` rückgängig machen und als
  Pull Request durch die Pipeline schicken.
