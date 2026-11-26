# CI/CD: vom Commit bis zur Live-Seite

```
 lokal              GitHub: Pull Request (CI)               GitHub: main (CD)
┌───────────────┐   ┌──────────────────────────────┐        ┌───────────────────────────┐
│ commit        │   │ 1 Qualität                   │        │ dieselben Prüfungen, dann │
│  └ Format,    │   │   Format, Typen, Unit-Tests, │        │ 5 Image veröffentlichen   │
│    Unit-Tests │──►│   Build, Seitenprüfung, HTML │──────► │   (GHCR, sha-<commit>)    │
│ push          │   │ 2 Docker-Image bauen (1×)    │ Merge  │   mit PUBLISH_ENABLED     │
│  └ Typen,     │   │ 3 Browsertests gegen Image   │ nur    │   oder DEPLOY_ENABLED     │
│    npm test   │   │ 4 Sicherheitsscan des Images │ grün   │ 6 Deploy auf den Server   │
│               │   │                              │        │   nur mit DEPLOY_ENABLED  │
│               │   │                              │        │   (Freigabe, Rollback)    │
│               │   │                              │        │ 7 Live-Prüfung            │
└───────────────┘   └──────────────────────────────┘        └───────────────────────────┘
   Frühwarnung           verbindliche Prüfung                  nur getestetes Image
```

Datei: [`.github/workflows/ci-cd.yml`](../.github/workflows/ci-cd.yml).

## Grundsätze

- **Committen darf man immer**, auch halbfertig. Verbindlich ist erst die Prüfung auf
  GitHub: Nach `main` kommt nur ein Pull Request mit grünen Checks (Ruleset, unten).
- **Einmal bauen, genau das ausliefern.** Das Docker-Image wird einmal gebaut, getestet,
  gescannt und dann unverändert veröffentlicht und deployt.
- **Nur `main` wird veröffentlicht oder deployt**, und erst, wenn eine der Variablen
  `PUBLISH_ENABLED` (nur veröffentlichen) oder `DEPLOY_ENABLED` (veröffentlichen und
  deployen) auf `true` steht. Dann gilt für jedes Release-Image (Veröffentlichen und
  Deploy) `CHECK_LIVE=1`: Platzhalter im Impressum oder `example.org` brechen den Build
  ab, ein unvollständiges Impressum geht nie online. Außerdem muss `SITE_URL` gesetzt
  sein, sonst bricht die Pipeline mit einer klaren Fehlermeldung ab, bevor das Image
  gebaut wird.
- **Kein Start von Hand.** Auch der erste Start auf dem Server läuft über die Pipeline:
  `DEPLOY_ENABLED` und die Freigabe des Environments `production` in GitHub. `deploy.sh`
  prüft den Zustand und rollt bei Fehlern zurück.
- **`DEPLOY_ENABLED` bis zum Aufbau von Live und Staging nicht setzen.** Auf dem Server
  liegen noch kein `deploy.sh` und keine Website (`setup-server.sh` legt sie nicht mehr
  an). Der Deploy-Job würde nach jedem Merge nach `main` fehlschlagen. Wer vorher einen
  grünen Lauf mit veröffentlichtem Image sehen will, setzt nur `PUBLISH_ENABLED` (siehe
  Abschnitt 3).
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
| Publish image                         | nur `main` + (`PUBLISH_ENABLED` oder `DEPLOY_ENABLED`): Image nach `ghcr.io/<owner>/<repo>/website` |
| Deploy to production                  | nur `main` + `DEPLOY_ENABLED`: SSH auf den Server, `deploy.sh` mit dem Image-Digest, danach Live-Prüfung |

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
| `SITE_URL`       | `https://www.meine-domain.de` | Adresse für Canonical, Sitemap, JSON-LD: genau `https://` plus `DOMAIN` aus der `.env` des Servers (siehe Abschnitt 3) |
| `DEPLOY_HOST`    | `203.0.113.10`               | Server                                        |
| `DEPLOY_USER`    | `deploy`                     | Benutzer auf dem Server                       |
| `PUBLISH_ENABLED` | `true`                      | schaltet nur das Veröffentlichen des getesteten Images nach GHCR ein, ohne Deploy (Abschnitt 3) |
| `DEPLOY_ENABLED` | `true`                       | schaltet Veröffentlichen und Deploy ein (setzt `PUBLISH_ENABLED` nicht voraus); **erst nach dem Aufbau von Live und Staging setzen**, sonst schlägt der Deploy-Job fehl |

Das Veröffentlichen läuft nie bei Pull Requests und nie bei Aktionen von Dependabot
(`github.actor`), nur nach einem Push auf `main` oder einem manuellen Start auf `main`. `SITE_URL` ist Pflicht, sobald
eine der beiden Variablen `true` ist.

| Ereignis                | `PUBLISH_ENABLED` | `DEPLOY_ENABLED` | Ergebnis                                  |
| ----------------------- | ----------------- | ---------------- | ----------------------------------------- |
| Pull Request            | egal              | egal             | weder Veröffentlichen noch Deploy         |
| Push auf `main` durch `dependabot[bot]` | egal      | egal             | weder Veröffentlichen noch Deploy         |
| Push auf `main`         | nicht `true`      | nicht `true`     | weder Veröffentlichen noch Deploy         |
| Push auf `main`         | `true`            | nicht `true`     | nur Veröffentlichen                       |
| Push auf `main`         | nicht `true`      | `true`           | Veröffentlichen, dann Deploy              |
| Push auf `main`         | `true`            | `true`           | Veröffentlichen, dann Deploy              |

### 3. Erster Release: SITE_URL, veröffentlichen prüfen, dann deployen

Kein Schritt hier startet etwas von Hand auf dem Server. Der erste Start läuft über die
Pipeline und die Freigabe in GitHub.

1. **`SITE_URL` setzen** (Abschnitt 2): genau `https://` plus der Wert `DOMAIN` aus der
   `.env` des Servers, ohne Schrägstrich am Ende. Beim Hostinger-Aufbau ist
   `DOMAIN=funkenundstahl.de` (ohne `www`), also `SITE_URL=https://funkenundstahl.de`.
   Nutzt die `.env` eine andere Schreibweise (die Vorlage `deploy/.env.example` nimmt
   `www.meine-domain.de`), muss `SITE_URL` dieser Schreibweise folgen, sonst zeigen
   Canonical, Sitemap und JSON-LD auf eine Adresse, die auf die andere weiterleitet.
2. **Optional: `PUBLISH_ENABLED=true` setzen**, um vor dem Deploy einen grünen Lauf zu
   sehen. Nach dem nächsten Merge nach `main` (oder einem manuellen Start unter Actions →
   CI/CD auf `main`) baut die Pipeline das Image mit der echten `SITE_URL` und
   `CHECK_LIVE=1`, testet es, scannt es mit Trivy und veröffentlicht es nach GHCR. „Publish
   image“ ist dann grün, „Deploy to production“ wird übersprungen, auf dem Server ändert
   sich nichts. Das Image liegt unter Packages → `website`
   (`ghcr.io/<owner>/<repo>/website:sha-<commit>`, Sichtbarkeit: Abschnitt 5).
3. **`DEPLOY_ENABLED=true` setzen**, sobald Server, Deploy-Schlüssel und Environment
   `production` (Abschnitt 4, mit Required reviewers) stehen. Der nächste Lauf auf `main`
   veröffentlicht das Image und wartet dann beim Job „Deploy to production“ auf eure
   Freigabe (Actions → Lauf → „Review deployments“ → `production` → Approve).
4. Nach der Freigabe ruft die CI `deploy.sh` mit dem Image-Digest auf. `deploy.sh` trägt
   den Digest als `WEBSITE_IMAGE` in die `.env` ein, startet das Image, wartet auf den
   Gesundheitscheck und startet bei einem Fehler automatisch das vorige Image. Danach
   prüft die CI die Live-Seite.
5. `PUBLISH_ENABLED` kann danach gelöscht werden; `DEPLOY_ENABLED` schließt das
   Veröffentlichen ein.

`WEBSITE_IMAGE` in der `.env` setzt allein `deploy.sh`, mit dem Digest. Nie von Hand auf
`:latest` (oder einen anderen Tag) stellen: Das würde die Freigabe umgehen.

Ist `SITE_URL` nicht gesetzt, schlägt der Job „Build Docker image“ gleich im ersten
Schritt mit „SITE_URL is not set“ fehl. Enthält `SITE_URL` `example.org`, bricht der
Build mit `CHECK_LIVE=1` ab. Zum Ausschalten `PUBLISH_ENABLED` löschen oder auf etwas
anderes als `true` setzen.

### 4. Environment `production` (Settings → Environments → New environment)

- **Required reviewers:** euch selbst eintragen. Dann wartet jeder Deploy auf einen
  Freigabe-Klick. Ohne Reviewer geht es nach dem Merge direkt live.
- **Deployment branches:** nur `main`.
- **Environment secrets:**
  - `DEPLOY_SSH_KEY`: privater Schlüssel des Deploy-Schlüsselpaars (siehe
    [`server.md`](server.md))
  - `DEPLOY_KNOWN_HOSTS`: Ausgabe von `ssh-keyscan <server>`, damit sich die CI nur mit
    eurem echten Server verbindet

### 5. Paket-Sichtbarkeit

Nach dem ersten Veröffentlichen unter Packages → `website` → Package settings: Ist das
Repository privat, bleibt das Image privat, und der Server braucht einmal
`docker login ghcr.io` mit einem Token (Recht `read:packages`).

## Rollback

- **Automatisch:** `deploy.sh` startet das vorige Image, wenn das neue nicht gesund wird.
- **Über die Pipeline (der Weg):** den fehlerhaften Commit mit `git revert` rückgängig
  machen (oder im gemergten Pull Request auf „Revert“ klicken) und als Pull Request
  nach `main` schicken. Nach dem Merge läuft der normale Ablauf: Prüfungen, Image,
  Veröffentlichen, Deploy mit Freigabe von `production`. Es gibt keinen Rollback von
  Hand auf dem Server.
