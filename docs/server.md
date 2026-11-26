# Server einrichten

Was auf dem Server läuft, steht vollständig in [`deploy/`](../deploy):

| Datei                   | Inhalt                                                                                                            |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `setup-server.sh`       | Absicherung eines frischen Servers: Updates, SSH nur mit Schlüssel, fail2ban, Firewall, Docker, Benutzer `deploy` |
| `compose.yml`           | Traefik (HTTPS, Let's Encrypt, Weiterleitung HTTP → HTTPS) und die Website (nginx)                                |
| `traefik/dynamic.yml`   | Routen, HSTS, Weiterleitung der Zweitdomain, TLS ab Version 1.2                                                   |
| `compose.hostinger.yml` | Nur die Website, mit Labels für den Traefik von Hostinger (siehe „Variante Hostinger-VPS“)                        |
| `.env.example`          | Domain, E-Mail für Let's Encrypt, aktuelles Image, Auswahl der Variante                                           |
| `deploy.sh`             | Deploy mit Gesundheitsprüfung und automatischem Rollback                                                          |

`setup-server.sh` richtet die Website nicht mehr ein. Wie `compose.yml`, `traefik/`,
`.env` und `deploy.sh` auf den Server kommen, folgt mit dem Aufbau von Live und Staging
(neue Struktur: `/opt/traefik`, `/opt/site-live`, `/opt/site-staging`, `/opt/deploy`).
Für den Hostinger-VPS steht das schon unter „Variante Hostinger-VPS“ (`/opt/website`).

Traefik liest seine Routen aus einer Datei und braucht keinen Zugriff auf den
Docker-Socket. Weder Traefik noch nginx schreiben Zugriffsprotokolle mit IP-Adressen.
Das gilt für die eigene Traefik-Instanz aus `compose.yml`. Auf dem Hostinger-VPS läuft
stattdessen der Traefik von Hostinger, siehe [Variante Hostinger-VPS](#variante-hostinger-vps-traefik-von-hostinger).

## Was ihr braucht

1. **Einen Server bei Oracle Cloud:** Instanz mit Shape `VM.Standard.A1.Flex` (Arm,
   aarch64) und Image **Ubuntu 24.04 LTS**, Region in der EU, öffentliche IPv4-Adresse.
   Login als Benutzer `ubuntu` mit SSH-Schlüssel (Oracle erlaubt keinen Root-Login).
2. **Ports 80 und 443 im Netz von Oracle freigeben:** Oracle filtert zusätzlich vor dem
   Server. In der Oracle Console unter Networking → Virtual Cloud Networks → euer VCN →
   Security List (oder Network Security Group der Instanz) je eine Ingress-Regel für
   TCP 80 und TCP 443 aus `0.0.0.0/0` anlegen. Port 22 ist dort schon offen.
3. **Eine Domain** mit Zugriff auf die DNS-Einträge:
   - `A`-Eintrag (und ggf. `AAAA`) für `www.meine-domain.de` auf die Server-IP
   - dasselbe für `meine-domain.de`, falls die Domain ohne `www` weiterleiten soll
4. **Einen SSH-Schlüssel** auf eurem Rechner (`ssh-keygen -t ed25519`), dessen
   öffentlichen Teil ihr beim Anlegen der Instanz hinterlegt.
5. **Einen Vertrag zur Auftragsverarbeitung** mit dem Anbieter (im Kundenkonto). Den
   Anbieter in der Datenschutzerklärung eintragen.

## Einrichten

```sh
# Ersteinrichtung (einmalig, als ubuntu)
scp deploy/setup-server.sh ubuntu@SERVER:
ssh ubuntu@SERVER 'sudo bash setup-server.sh'
```

Das Skript lässt sich gefahrlos ein zweites Mal ausführen und meldet dann 0 Änderungen.

**Abbruch ohne jede Änderung**, wenn eine dieser Prüfungen scheitert:

- Es läuft nicht als root (Aufruf ohne `sudo`).
- Das System ist kein Ubuntu (eine andere Ubuntu-Version als 24.04 oder eine andere
  Architektur als aarch64 gibt nur eine Warnung).
- `DRY_RUN` hat einen anderen Wert als `0` oder `1`.
- `ADMIN_USER` ist kein gültiger Benutzername (nur Kleinbuchstaben, Ziffern, `_` und
  `-`), der Benutzer existiert nicht, oder er heißt `root` oder `deploy`.
- Das Skript wurde per `sudo` von einem anderen Benutzer als `ADMIN_USER` aufgerufen
  (Variable `SUDO_USER`), oder die Audit-Login-UID (`/proc/self/loginuid`, bleibt auch
  nach `sudo -i` oder `su` erhalten) gehört weder root noch `ADMIN_USER`. Danach dürfte
  nur noch `ADMIN_USER` per SSH herein, der angemeldete Benutzer wäre ausgesperrt.
  Abhilfe: `ADMIN_USER` auf deinen Benutzer setzen, z. B.
  `sudo ADMIN_USER=name bash setup-server.sh`. Eine nicht gesetzte Login-UID
  (4294967295) zählt nicht.
- In der Schlüsseldatei von `ADMIN_USER` steht kein Schlüssel (fehlt, leer oder nur
  Kommentare). Geprüft wird die Datei, die sshd für diesen Benutzer liest
  (`AuthorizedKeysFile` laut `sshd -T`, relativ zum Home-Verzeichnis aus
  `getent passwd`), im Normalfall `~/.ssh/authorized_keys`, beim Standardbenutzer also
  `/home/ubuntu/.ssh/authorized_keys`. Weicht `AuthorizedKeysFile` vom Standard ab,
  warnt das Skript.
- `sshd -T` liefert für `ADMIN_USER` keine wirksame Konfiguration. Ohne sie lässt sich
  die Schlüsseldatei nicht sicher bestimmen; das Skript rät dann nicht.
- Die bestehende Konfiguration erlaubt keine Anmeldung nur mit Schlüssel (`sshd -T`
  global und `sshd -T -C user=ADMIN_USER,…`): `PubkeyAuthentication` ist nicht `yes`,
  oder `AuthenticationMethods` ist nicht `any` und keine seiner Listen besteht nur aus
  `publickey` (z. B. `publickey,password`). Nach dem Abschalten der Passwörter wäre
  `ADMIN_USER` sonst ausgesperrt.
- Eines der Pakete `docker.io`, `docker-compose`, `docker-compose-v2`, `docker-doc`
  oder `podman-docker` ist installiert. Sie kollidieren mit Docker aus dem offiziellen
  Repository; erst mit `sudo apt-get remove <paket>` entfernen.
- UFW ist aktiv (`ufw status` zeigt `Status: active`) oder sein Status lässt sich nicht
  ermitteln. `ufw` verträgt sich nicht mit `iptables-persistent`
  (`Breaks: iptables-persistent, netfilter-persistent`); apt würde UFW bei der
  Installation entfernen. Ist UFW installiert, aber nicht aktiv (Normalfall bei
  Oracle), warnt das Skript nur: apt entfernt es dann.

Einzige Ausnahme von „ohne jede Änderung“: Fehlt das Laufzeitverzeichnis `/run/sshd`
(tmpfs, bei Socket-Aktivierung nicht immer vorhanden), legt das Skript es schon in der
Prüfung an, weil `sshd -T` es braucht. sshd legt es bei jedem Start ohnehin selbst an.

**Abbruch während des Laufs** (was bis dahin eingerichtet wurde, bleibt; nach der
Ursache einfach erneut starten):

- Eine Konfigurationsdatei lässt sich nicht schreiben. Die bisherige Datei bleibt.
- Die Paketinstallation hat die Firewall verändert und die Wiederherstellung hilft
  nicht: In `INPUT` (IPv4 oder IPv6) fehlt danach die abschließende `REJECT`- oder
  `DROP`-Regel, die vorher da war, die Policy ist von `DROP` auf `ACCEPT` gewechselt,
  oder `INPUT` lässt sich nicht mehr lesen. Das kann passieren, wenn apt UFW entfernt
  (dessen `prerm` ruft `ufw-init stop`). Vor der Paketinstallation sichert das Skript
  deshalb die Tabelle `filter` (darin liegt `INPUT`) mit `iptables-save -t filter` und
  `ip6tables-save -t filter` in eine temporäre Datei (nur für root lesbar, am Ende
  gelöscht). Erkennt es danach eine solche Abweichung, spielt es die Sicherung mit
  `iptables-restore` bzw. `ip6tables-restore` zurück (die Tabelle `filter` als Ganzes in
  einem Schritt, keine einzelne Regel gelöscht; andere Tabellen wie `nat` bleiben
  unberührt) und prüft erneut.
  Stimmt `INPUT` dann wieder, warnt es („Firewall nach Paketinstallation
  wiederhergestellt“) und macht weiter. Abgebrochen wird, wenn es keine Sicherung gibt,
  die Wiederherstellung scheitert oder `INPUT` danach weiter abweicht. Gespeichert wird
  dabei nichts: `iptables-persistent` ist so vorbelegt, dass es bei der Installation
  nicht speichert (`autosave_v4` und `autosave_v6` `false`), `/etc/iptables/rules.v4`
  und `rules.v6` enthalten also noch die bisherigen Regeln. Ein Neustart lädt sie
  wieder, sofort von Hand mit `sudo iptables-restore < /etc/iptables/rules.v4` (IPv6
  entsprechend).
- `sshd -t` meldet einen Fehler, `sshd -T` scheitert, oder die wirksame Konfiguration
  (`sshd -T` global und `sshd -T -C user=ADMIN_USER,…` nach `Match`-Blöcken) erfüllt
  eine dieser Bedingungen nicht: `ADMIN_USER` steht in `AllowUsers`;
  `PasswordAuthentication`, `KbdInteractiveAuthentication`, `PermitRootLogin`,
  `GSSAPIAuthentication` und `HostbasedAuthentication` sind `no`;
  `PubkeyAuthentication` ist `yes`; `AuthenticationMethods` ist `any` oder hat
  eine Liste nur aus `publickey`; `DenyUsers` nennt `ADMIN_USER` nicht; ist
  `AllowGroups` gesetzt, ist `ADMIN_USER` in einer dieser Gruppen; `DenyGroups` nennt
  keine seiner Gruppen. Geprüft wird bei jedem Lauf, auch wenn
  `/etc/ssh/sshd_config.d/10-haertung.conf` unverändert bleibt. Hat dieser Lauf die
  Datei geändert, wird sie zurückgesetzt; ist sie unverändert, bleibt sie, und die
  Meldung sagt je nach Ursache, was zu tun ist: `/run/sshd` ließ sich nicht anlegen
  (dann ist die Konfiguration ungeprüft), `sshd -t` oder `sshd -T` meldet einen Fehler,
  oder die bestehende Konfiguration erfüllt eine Prüfung nicht (eine andere Datei hat
  sich seit dem letzten Lauf geändert, oder die Prüfung ist neu). SSH wird in allen
  Fällen nicht neu geladen. Die Meldung
  nennt die Dateien, die den Wert vermutlich vorher setzen (sshd nimmt den ersten Wert;
  Dateien in `sshd_config.d` mit früher sortiertem Namen werden zuerst gelesen).
- `fail2ban-client -t` meldet einen Fehler in `/etc/fail2ban/fail2ban.local` oder
  `/etc/fail2ban/jail.local`.
- Die wirksamen Werte von fail2ban laut `fail2ban-client -d` weichen von denen der
  Datenschutzerklärung ab, oder der Jail `sshd` ist nicht aktiv. Sollwerte:
  `logtarget` `SYSLOG[facility=AUTHPRIV]`, `dbpurgeage` 86400 Sekunden, im Jail `sshd`
  `maxretry` 5, `findtime` und `bantime` je 600 Sekunden (Zeiten mit dem Parser von
  fail2ban umgerechnet, `10m` gilt also wie `600`) und `bantime.increment` aus (aktiv
  würde es wiederholte Sperren verlängern). Geprüft wird bei jedem Lauf, vor dem
  Neustart von fail2ban.
  fail2ban liest `jail.d/*.local` nach `jail.local` und `fail2ban.d/*.local` nach
  `fail2ban.local`, der zuletzt gelesene Wert gilt; eine fremde Datei dort kann die Werte
  also überstimmen. Die Meldung nennt die Dateien, die den Wert vermutlich setzen. Das
  Skript ändert sie nicht und startet fail2ban nicht neu; die Datei anpassen oder
  entfernen und das Skript erneut starten.
- Außer `sshd` ist in fail2ban ein weiterer Jail aktiv (z. B. `recidive`, laut
  `fail2ban-client -d`). Dessen Sperrdauer und Werte prüft das Skript nicht, sie
  entsprechen nicht der Datenschutzerklärung. Die Meldung nennt jeden Jail und die
  Dateien mit seinem Abschnitt; fail2ban wird weder neu gestartet noch gestartet. Den
  Jail abschalten (`enabled = false`) oder die Datei entfernen und das Skript erneut
  starten; soll er bleiben, zuerst Datenschutzerklärung und Skript anpassen. Ein
  Testlauf (`DRY_RUN=1`) meldet das schon, wenn fail2ban installiert ist.
- Der Signaturschlüssel von Docker hat nicht den erwarteten Fingerabdruck
  `9DC8 5822 9FC7 DD38 854A E2D8 8D81 803C 0EBF CD88`. Dann wird nichts von Docker
  installiert.
- iptables lässt sich nicht lesen.
- Das Home-Verzeichnis von `deploy` lässt sich nicht ermitteln (`getent passwd deploy`).

Was es einrichtet:

- System-Updates (`apt-get full-upgrade`), automatische Sicherheitsupdates, bei Bedarf
  Neustart um 04:00
  (Zeitzone des Servers: Europe/Berlin)
- SSH nur mit Schlüssel (auch ohne GSSAPI und hostbasierte Anmeldung), kein
  Root-Login, nur die Benutzer `ADMIN_USER` und `deploy`
  (`/etc/ssh/sshd_config.d/10-haertung.conf`). Für `deploy` prüft das Skript (mit
  `sshd -T -C user=deploy,…`) `AllowUsers`, `DenyUsers`, `AllowGroups` und `DenyGroups`
  (auf einem frischen Server, wo das Skript `deploy` erst danach anlegt, mit den Gruppen
  `deploy` und `docker`, die er dann bekommt) und ob eine Anmeldung nur mit Schlüssel
  möglich ist (`PubkeyAuthentication`, `AuthenticationMethods`); die noch leere
  `authorized_keys` von `deploy` prüft es nicht. Scheitert eine dieser Prüfungen, gibt
  das Skript nur eine Warnung: Der Zugang von `ADMIN_USER` ist nicht betroffen, das
  Deploy der CI würde aber scheitern.
- fail2ban für SSH mit den Werten der Datenschutzerklärung, ausdrücklich gesetzt:
  `maxretry = 5`, `findtime = 10m`, `bantime = 10m` (`/etc/fail2ban/jail.local`) und
  `dbpurgeage = 1d`; fail2ban schreibt sein Protokoll statt nach
  `/var/log/fail2ban.log` über syslog mit der Facility `authpriv` ins Journal und, falls
  rsyslog installiert ist, nach `/var/log/auth.log`, nicht nach `/var/log/syslog`
  (`logtarget = SYSLOG[facility=AUTHPRIV]` in `/etc/fail2ban/fail2ban.local`). Ob diese
  Werte auch wirken, prüft das Skript mit `fail2ban-client -d` (siehe oben). Sind außer
  `sshd` weitere Jails aktiv (z. B. `recidive`), bricht es ab (siehe oben).
- Protokolle mit IP-Adressen werden nach etwa 7 Tagen gelöscht, wie in der
  Datenschutzerklärung angegeben: im Journal
  (`/etc/systemd/journald.conf.d/10-aufbewahrung.conf`) und, falls logrotate vorhanden
  ist, in `/var/log/btmp` und `/var/log/wtmp` (`/etc/logrotate.d/00-login-logs`), in
  `/var/log/fail2ban.log` (`/etc/logrotate.d/00-fail2ban-log`; enthält nur noch
  Einträge von vor dem Wechsel auf syslog) und, falls zusätzlich rsyslog installiert
  ist, in `/var/log/auth.log` (`/etc/logrotate.d/00-auth-log`). logrotate gilt als
  vorhanden, wenn das Paket laut dpkg installiert ist und das Programm `logrotate`
  gefunden wird. Sonst legt das Skript keine der drei `00-*`-Dateien an und warnt.
  Die Dateien der Pakete in `/etc/logrotate.d` bleiben unverändert.
- Firewall über die iptables-Regeln des Oracle-Images (kein UFW; ein installiertes,
  inaktives UFW entfernt apt mit `iptables-persistent`): Ports 22, 80 und 443
  für IPv4 und IPv6, wenn `INPUT` andere Verbindungen abweist (`REJECT`-Regel,
  abschließende Regel `-j DROP` ohne Bedingung oder Policy `DROP`); die ACCEPT-Regeln
  kommen vor die `REJECT`- bzw. `DROP`-Regel. Das Skript fügt nur Regeln ein und löscht
  keine (das Zurückspielen der Sicherung nach einer Änderung durch die
  Paketinstallation, siehe oben, ersetzt die ganze Tabelle `filter` durch den Stand von
  vorher). Eine wirkungslose Kopie hinter `REJECT` bleibt stehen, das Skript warnt bei
  jedem Lauf; entfernen von Hand (Nummer mit `sudo iptables -L INPUT --line-numbers -n`).
  Gespeichert (`netfilter-persistent save`) wird nur nach diesen Prüfungen und nur, wenn
  das Skript eine Regel eingefügt hat. Hat `INPUT` schon vor der Installation weder eine
  abschließende `REJECT`- oder `DROP`-Regel noch die Policy `DROP`, warnt das Skript (auf
  Oracle unerwartet).
- Docker aus dem offiziellen Repository (Signaturschlüssel per Fingerabdruck geprüft)
  mit begrenzten Logs, ohne TCP-Socket
- Benutzer `deploy` in der Gruppe `docker`, mit leerer `authorized_keys` (im
  Home-Verzeichnis laut `getent passwd`, im Normalfall `/home/deploy/.ssh`)

Optionen: `sudo DRY_RUN=1 bash setup-server.sh` zeigt nur, was geschehen würde.
`sudo ADMIN_USER=name bash setup-server.sh`, falls euer Login-Benutzer nicht `ubuntu` ist.

**Danach prüfen** (das Skript gibt die Befehle am Ende auch aus):

1. In einem zweiten Fenster einloggen, bevor ihr das erste schließt: `ssh ubuntu@SERVER`
2. Auf dem Server: `sudo docker run --rm hello-world` zeigt „Hello from Docker!“.
3. Auf dem Server: `sudo fail2ban-client status sshd` zeigt den Jail `sshd`.
4. Auf eurem Rechner:
   `ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password ubuntu@SERVER`
   wird mit „Permission denied (publickey)“ abgewiesen.
5. Auf eurem Rechner: `curl -I http://SERVER` meldet sofort „Connection refused“
   (noch kein Webserver). Ein Timeout heißt: Port 80 ist gesperrt, auf dem Server oder
   in der Security List (siehe „Was ihr braucht“, Punkt 2).

### Skript testen

Jede Änderung an `deploy/setup-server.sh` braucht vor dem Pull Request einen grünen
Lauf der Tests, das Ergebnis gehört in die PR-Beschreibung:

```sh
sudo bash site/tests/server/setup-server.test.sh
```

Der Test spielt das Skript in Wegwerf-Umgebungen durch (eigener Mount- und
Netz-Namespace mit `unshare`, Overlay über `/etc`, `/home` und weitere Verzeichnisse,
iptables-Regeln wie im Oracle-Image). Auf dem Rechner selbst ändert sich nichts.

Voraussetzungen auf dem Testrechner. Root, die Werkzeuge und die Benutzer und Gruppen
prüft der Test vorab; fehlt etwas davon, endet er mit Exit-Code 2.

- Aufruf als root.
- Mount- und Netz-Namespaces (`unshare -m -n`) und Overlay-Dateisysteme; `/proc/self/ns`
  muss lesbar sein.
- Die Werkzeuge `unshare`, `setpriv`, `iptables`, `ip6tables`, `iptables-save`,
  `ip6tables-save`, `iptables-restore`, `ip6tables-restore`, `/usr/sbin/sshd`,
  `fail2ban-client`, `apt-config`, `shellcheck`, `python3` (mit dem Python-Modul von
  fail2ban), `diff`, `gpg`, `gpgconf`, `/usr/sbin/useradd`, `/usr/sbin/groupadd`,
  `/usr/sbin/groupdel`, `mount`, `readlink` und `cmp`.
- Die Benutzer `ubuntu` und `claude` müssen existieren.
- Der Benutzer `srvadmin` und die Gruppen `sshlogin` und `sshdeny` dürfen **nicht**
  existieren; die Testfälle legen sie selbst an.
- Das Arbeitsverzeichnis (`TMPDIR`, Standard `/tmp`) darf nicht unter `/etc`, `/home`,
  `/run`, `/var`, `/usr`, `/opt`, `/root` oder `/srv` liegen, die der Test überlagert.
- Die Datei `site/tests/server/fixtures/docker.asc` muss vorhanden sein, und `gpg` muss
  einen Testschlüssel erzeugen können.

Exit-Code 0 heißt bestanden, 1 mindestens ein Fehler, 2 der Test kann hier nicht laufen
(dann gilt er als nicht ausgeführt, nicht als bestanden). In der CI läuft er nicht
(dort ist er nicht eingerichtet); er ist deshalb lokal Pflicht.

**Hinweis Docker und Firewall:** Docker leitet veröffentlichte Container-Ports an der
INPUT-Kette vorbei. Deshalb veröffentlicht nur Traefik Ports (80, 443). Eigene Regeln
für Container gehören in die Kette `DOCKER-USER`.

## Website einrichten (folgt mit dem Aufbau von Live und Staging)

Dieser Teil wird mit der neuen Struktur neu geschrieben.

> **Wichtig:** Die Variable `DEPLOY_ENABLED` in GitHub erst auf `true` setzen, wenn
> Live und Staging aufgebaut sind. `setup-server.sh` legt weder `deploy.sh` noch die
> Verzeichnisse der Website an. Mit `DEPLOY_ENABLED=true` würde jeder Merge nach `main`
> den Deploy-Job starten, und der schlägt dann fehl (siehe [`ci-cd.md`](ci-cd.md)).
> Für den Hostinger-VPS gilt stattdessen die „Offene Entscheidung (erstes Image)“ unter
> „Variante Hostinger-VPS“.

Erhalten bleibt:

- **Deploy-Schlüssel nur für die CI** auf eurem Rechner erzeugen
  (`ssh-keygen -t ed25519 -f github-deploy -N '' -C github-deploy`) und den öffentlichen
  Teil in `/home/deploy/.ssh/authorized_keys` eintragen, beschränkt auf einen Befehl
  (`command="…",restrict`). Den privaten Teil als Secret `DEPLOY_SSH_KEY` in GitHub
  eintragen, `ssh-keyscan SERVER` als Secret `DEPLOY_KNOWN_HOSTS`, danach die lokale
  Datei löschen. `DEPLOY_ENABLED=true` erst danach und erst nach dem Aufbau von Live
  und Staging setzen (siehe oben und [`ci-cd.md`](ci-cd.md)).
- **Tipp für den ersten Start:** In `.env` die Zeile `ACME_CA_SERVER=...staging...`
  aktivieren. Let's Encrypt begrenzt fehlgeschlagene Versuche; mit der Staging-CA lässt
  sich gefahrlos testen. Wenn alles läuft, die Zeile entfernen, das Zertifikats-Volume
  löschen und Traefik neu starten.
- **Konfiguration ändern:** Änderungen an `compose.yml` oder `traefik/dynamic.yml`
  laufen wie Code über einen Pull Request und werden danach mit eurem eigenen Schlüssel
  (nicht dem Deploy-Schlüssel) als `ubuntu` übertragen.

## Variante Hostinger-VPS (Traefik von Hostinger)

**Warum:** Der Projektauftrag (Brief, Abschnitt 7) sieht einen eigenen Traefik vor, so wie
in `compose.yml`. Auf dem Hostinger-VPS läuft aber schon ein von Hostinger verwalteter
Traefik auf den Ports 80 und 443. Ein zweiter Traefik bekäme diese Ports nicht. Deshalb
bringt `compose.hostinger.yml` nur die Website mit und meldet sie über Docker-Labels beim
vorhandenen Traefik an. `compose.yml` und `traefik/dynamic.yml` bleiben unverändert als
Variante mit eigenem Traefik.

**Was unberührt bleibt:** der Traefik von Hostinger (Container, Image, Einstellungen), die
App „Hermes“ (Router `hermes-agent-fjbe`, Netz `hermes-agent-fjbe_default`) und Port 32768.
Die Website veröffentlicht keine Ports und nutzt ein eigenes Netz `funkenundstahl-web`.
Alle Namen beim Traefik beginnen mit `funkenundstahl-`. Das Compose-Projekt heißt
`funkenundstahl`: `deploy.sh` ruft `docker compose up --remove-orphans` auf, und das
betrifft nur Container desselben Projekts. Ein allgemeiner Name wie `website` könnte auf
einem geteilten Server mit einem fremden Projekt zusammenfallen.

Vor diesem Stack wird der VPS mit `deploy/setup-server.sh` im Profil `hostinger`
abgesichert (siehe Abschnitt „Hostinger-VPS (Profil hostinger)“). Das legt unter anderem
den Benutzer `deploy` an, der `deploy.sh` ausführt.

Was der Traefik von Hostinger laut `docker inspect` bietet und `compose.hostinger.yml`
voraussetzt:

| Einstellung | Wert                                                     |
| ----------- | -------------------------------------------------------- |
| Image       | `traefik:latest` (von Hostinger gepflegt, nicht gepinnt) |
| Netz        | Host-Netz                                                |
| Provider    | Docker, `exposedbydefault=false`, kein File-Provider     |
| Entrypoints | `web` (:80, leitet auf HTTPS um), `websecure` (:443)     |
| Zertifikate | Resolver `letsencrypt`, HTTP-Challenge über `web`        |

So setzt `compose.hostinger.yml` das um:

| Router / Middleware / Service      | Aufgabe                                                                                                                  |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `funkenundstahl-website`           | `Host(DOMAIN)` auf `websecure`, Zertifikat über `letsencrypt`, mit HSTS                                                  |
| `funkenundstahl-www`               | `Host(REDIRECT_DOMAIN)`, dauerhafte Weiterleitung (301) auf `https://DOMAIN` mit Pfad und Query, Service `noop@internal` |
| `funkenundstahl-hsts`              | HSTS wie `traefik/dynamic.yml`: 31536000 Sekunden, ohne Subdomains, ohne Preload                                         |
| `funkenundstahl-to-apex`           | Weiterleitung per `redirectRegex`                                                                                        |
| `funkenundstahl-website` (Service) | Port 8080, Gesundheitsprüfung `/healthz` alle 10 s, Timeout 3 s (wie `dynamic.yml`)                                      |

Unterschiede zur eigenen Traefik-Instanz:

- **Netz:** Traefik läuft im Host-Netz und erreicht den Container über dessen Adresse im
  Netz `funkenundstahl-web`. Das Label `traefik.docker.network` legt dieses Netz fest,
  damit Traefik nicht raten muss, falls einmal ein zweites Netz dazukommt.
- **TLS-Mindestversion:** Ohne File-Provider lassen sich keine TLS-Optionen setzen. Es gilt
  der Standard von Traefik (TLS 1.2 und neuer, lokal mit `traefik:latest` 3.8.0 geprüft:
  TLS 1.1 wird abgelehnt).
- **Neustart:** Der Docker-Provider von Traefik übernimmt einen Container erst, wenn er
  gesund ist. Damit ein Deploy nicht etwa 30 Sekunden lang 404 liefert (Prüfintervall im
  Image), prüft Docker in den ersten 30 Sekunden alle 2 Sekunden (`start_interval`).
  Lokal gemessen: etwa 3 Sekunden 404 je Deploy. `start_interval` setzt **Docker Engine
  25 oder neuer** voraus; Schritt 2 prüft das.
- **www-Weiterleitung hängt am Container:** Die Labels beider Router sitzen am
  Website-Container. Startet er, ist er ungesund oder gestoppt, entfernt Traefik alle
  seine Router, auch die Weiterleitung von `www`. `noop@internal` heißt nur, dass die
  Weiterleitung kein Backend fragt.
- **Container-Logs:** Treiber `local`, höchstens 3 × 10 MB (Datenschutzerklärung:
  höchstens 30 MB je Dienst).
- **www über HTTP:** `http://www.…` geht in zwei Schritten: erst auf `https://www.…`
  (Entrypoint `web`), dann auf `https://funkenundstahl.de/…`.
- **Keine `ACME_EMAIL`:** Zertifikate holt der Traefik von Hostinger.
- **Zugriffsprotokolle:** Ob der Traefik von Hostinger IP-Adressen protokolliert, legt
  Hostinger fest. Seine Konfiguration liegt nicht im Repository (Schritt 2 unten prüft
  sie, Schritt 3 klärt die Datenschutzerklärung).

**Offene Entscheidung (erstes Image):** `deploy.sh` braucht ein Image in GHCR. Das
veröffentlicht nur der CI-Job „Publish image“, und der läuft nur mit
`DEPLOY_ENABLED=true`. Damit startet nach jedem Merge nach `main` aber auch der Job
„Deploy to production“ (siehe [`ci-cd.md`](ci-cd.md)). Wie das erste Image entsteht
(etwa: Deploy-Schlüssel und Server vorher fertig einrichten, dann `DEPLOY_ENABLED=true`
setzen), ist noch nicht entschieden. Die CI bleibt dafür vorerst unverändert.

### Einrichten

Voraussetzungen: Der VPS ist mit `setup-server.sh` im Profil `hostinger` eingerichtet
(Benutzer `deploy` in der Gruppe `docker`), und es gibt ein veröffentlichtes Image in
GHCR, gebaut mit `SITE_URL=https://funkenundstahl.de` (siehe „Offene Entscheidung“ oben).
Die Befehle auf dem Server laufen mit eurem eigenen Admin-Benutzer, nicht mit dem
Deploy-Schlüssel.

1. **DNS bei Strato** (Strato-Kundenlogin → Domains → Domainverwaltung →
   `funkenundstahl.de` → DNS-Einstellungen):
   - `A`-Eintrag für `funkenundstahl.de` und für `www.funkenundstahl.de` auf die
     IPv4-Adresse des VPS.
   - Vorhandene `AAAA`-Einträge für beide Namen **löschen**. Sie zeigen sonst weiter auf
     Strato, und IPv6-Besucher sowie Let's Encrypt landen dort.
   - `MX`- und `TXT`-Einträge (E-Mail, Verifizierungen) unverändert lassen.

   Prüfen auf eurem Rechner: `dig +short A funkenundstahl.de` und
   `dig +short A www.funkenundstahl.de` zeigen beide die Server-IP,
   `dig +short AAAA funkenundstahl.de` und `dig +short AAAA www.funkenundstahl.de` sind
   leer. Erst dann weiter, sonst scheitert die HTTP-Challenge von Let's Encrypt.

2. **Server prüfen** (nur lesen), auf dem Server. `<traefik>` und `<hermes>` sind die
   Containernamen aus der ersten Ausgabe.

   ```sh
   docker ps --format '{{.Names}}  {{.Image}}  {{.Ports}}'
   docker version --format '{{.Server.Version}}'
   docker ps -a --format '{{.Names}} {{.Label "com.docker.compose.project"}}'
   docker inspect <traefik> --format '{{json .Args}}'
   docker inspect <traefik> --format '{{range .Config.Env}}{{println .}}{{end}}' \
     | grep -E '^TRAEFIK_(ACCESSLOG|ENTRYPOINTS_[A-Z0-9_]+_MIDDLEWARES)'
   docker inspect <traefik> --format '{{range .Mounts}}{{println .Source "->" .Destination}}{{end}}'
   docker inspect $(docker ps -q) \
     --format '{{.Name}}{{range $k, $v := .Config.Labels}}{{"\n  "}}{{$k}}={{$v}}{{end}}' \
     | grep -E '^/|\.rule='
   ```

   Erwartet:
   - Docker Engine **25 oder neuer**. Ältere Versionen kennen `start_interval` nicht,
     Compose kann die Datei dann ablehnen. In diesem Fall nicht weitermachen.
   - Kein Compose-Projekt `funkenundstahl` vorhanden.
   - Die Argumente passen zur Tabelle oben (`exposedbydefault=false`, Entrypoints `web`
     und `websecure`, Resolver `letsencrypt`). Keine Middlewares auf Entrypoint-Ebene
     (`--entrypoints.*.http.middlewares` oder `TRAEFIK_ENTRYPOINTS_*_MIDDLEWARES`), die
     auf alle Seiten wirken würden.
   - Zugriffsprotokoll: weder `--accesslog` in den Argumenten noch `TRAEFIK_ACCESSLOG*`
     in der Umgebung. Ist eine statische Konfigurationsdatei eingebunden (`traefik.yml`
     oder `traefik.toml` unter den Mounts), darin nach `accessLog` suchen. Ist ein
     Zugriffsprotokoll aktiv, vor dem Start Schritt 3 klären.
   - Keine Router-Regel eines anderen Containers (vor allem `<hermes>`) erfasst
     `funkenundstahl.de` oder `www.funkenundstahl.de`, auch nicht als Sammelregel
     (`HostRegexp`, `PathPrefix` ohne `Host`) mit eigener `priority`.

3. **Datenschutzerklärung klären** (der Text selbst kommt in einem eigenen Pull Request):
   - Hostinger als Auftragsverarbeiter: Vertrag zur Auftragsverarbeitung (AVV) im
     hPanel-Kundenkonto abschließen und Hostinger als Hosting-Anbieter eintragen.
   - Land des Rechenzentrums: im hPanel beim VPS ablesen und eintragen.
   - Die Datenschutzerklärung sagt, der vorgeschaltete Proxy speichere keine
     IP-Adressen. Hier ist das der Traefik von Hostinger, dessen Konfiguration nicht im
     Repository liegt. Das Ergebnis aus Schritt 2 festhalten und den Text danach richten.

4. **Verzeichnis anlegen**, auf dem Server:

   ```sh
   sudo install -d -m 750 -o deploy -g deploy /opt/website
   ```

5. **Dateien übertragen**, auf eurem Rechner im Repository:

   ```sh
   scp deploy/compose.hostinger.yml deploy/deploy.sh deploy/.env.example <admin>@SERVER:/tmp/
   ```

   Dann auf dem Server:

   ```sh
   sudo install -m 644 -o deploy -g deploy /tmp/compose.hostinger.yml /opt/website/
   sudo install -m 755 -o deploy -g deploy /tmp/deploy.sh /opt/website/
   sudo install -m 600 -o deploy -g deploy /tmp/.env.example /opt/website/.env
   rm /tmp/compose.hostinger.yml /tmp/deploy.sh /tmp/.env.example
   ```

6. **`.env` ausfüllen:** `sudo -u deploy nano /opt/website/.env`, Inhalt:

   ```sh
   COMPOSE_FILE=compose.hostinger.yml
   DOMAIN=funkenundstahl.de
   REDIRECT_DOMAIN=www.funkenundstahl.de
   WEBSITE_IMAGE=ghcr.io/advocatusrar/claude-webseiten/website:latest
   ```

   `ACME_EMAIL` und `ACME_CA_SERVER` entfallen. `WEBSITE_IMAGE` überschreibt `deploy.sh`
   bei jedem Deploy mit dem Digest.

7. **Konfiguration prüfen**, auf dem Server. Euer Admin-Benutzer kann `/opt/website`
   nicht betreten (Rechte 750, Besitzer `deploy`), deshalb läuft alles als `deploy`.
   `--project-directory` reicht nicht: Compose sucht die Datei aus `COMPOSE_FILE` im
   aktuellen Verzeichnis.

   ```sh
   sudo -u deploy sh -c 'cd /opt/website && docker compose config --services'
   sudo -u deploy sh -c 'cd /opt/website && docker compose config' | grep -E '^name:|traefik.http.routers'
   ```

   Die erste Ausgabe ist genau `website` (kein `traefik`). Die zweite zeigt
   `name: funkenundstahl` und die Router `funkenundstahl-website` und
   `funkenundstahl-www` mit euren Domains. Fehlt `DOMAIN`, `REDIRECT_DOMAIN` oder
   `WEBSITE_IMAGE`, bricht Compose mit „… fehlt in .env“ ab.

8. **Bei privatem Paket** einmal anmelden (Token mit Recht `read:packages`):
   `sudo -u deploy docker login ghcr.io`.

9. **Erster Start** mit Gesundheitsprüfung und Rollback:

   ```sh
   sudo -u deploy /opt/website/deploy.sh ghcr.io/advocatusrar/claude-webseiten/website:sha-<commit>
   ```

10. **Prüfen**, auf eurem Rechner. Mit GET (`-o /dev/null -D -`), nicht mit `curl -I`:
    Auf HEAD antwortet die Weiterleitung von Traefik mit `308` statt `301`. Beides ist
    eine dauerhafte Weiterleitung.

    ```sh
    curl -s -o /dev/null -D - https://funkenundstahl.de/ \
      | grep -iE '^HTTP|^(content-security-policy|x-content-type-options|referrer-policy|permissions-policy|cross-origin-opener-policy|strict-transport-security):'
    curl -s -o /dev/null -D - 'https://www.funkenundstahl.de/vergleichstest/?a=1' | grep -iE '^HTTP|^location'
    curl -s -o /dev/null -D - http://funkenundstahl.de/ | grep -iE '^HTTP|^location'
    ```

    Erwartet beim ersten Aufruf `200` und alle sechs Header:
    - `content-security-policy: default-src 'self'; …; frame-ancestors 'none'`
    - `x-content-type-options: nosniff`
    - `referrer-policy: strict-origin-when-cross-origin`
    - `permissions-policy: camera=(), microphone=(), geolocation=(), interest-cohort=()`
    - `cross-origin-opener-policy: same-origin`
    - `strict-transport-security: max-age=31536000`

    Danach `301` mit `location: https://funkenundstahl.de/vergleichstest/?a=1`, dann
    eine Weiterleitung auf `https://funkenundstahl.de/`. Hermes danach wie gewohnt
    aufrufen und mit `docker ps` prüfen, dass sein Container weiterläuft.

11. **In GitHub** die Variable `SITE_URL` auf `https://funkenundstahl.de` setzen (siehe
    [`ci-cd.md`](ci-cd.md)). `DEPLOY_ENABLED` erst setzen, wenn die offene Entscheidung
    oben getroffen ist.

**Entfernen:** `sudo -u deploy sh -c 'cd /opt/website && docker compose down'` stoppt nur
die Website und löscht das Netz `funkenundstahl-web`. Traefik nimmt die Routen von selbst
heraus.

## Laufender Betrieb

- **Sicherheitsupdates** des Systems installieren sich automatisch; braucht ein Update
  einen Neustart (z. B. neuer Kernel), startet der Server um 04:00 deutscher Zeit neu.
  Traefik- und nginx-Versionen kommen als Dependabot-Pull-Requests.
- **Zertifikate** erneuert Traefik selbst. Let's Encrypt verkürzt die Laufzeit ab
  10.02.2027 auf 64 und ab 16.02.2028 auf 45 Tage; dafür ist nichts zu tun, aber ein
  externes Monitoring sollte melden, wenn eine Erneuerung scheitert.
- **Monitoring:** einen externen Dienst `https://www.meine-domain.de/healthz` und das
  Zertifikatsablaufdatum prüfen lassen.
- **Backup:** Inhalt und Konfiguration liegen im Repository. Auf dem Server sind nur
  `.env` und das Zertifikats-Volume; beide lassen sich neu erzeugen.
- **Hostinger-VPS:** Dort gilt Folgendes abweichend:
  - Den Traefik (`traefik:latest`) pflegt Hostinger. Dependabot aktualisiert ihn nicht,
    und er kann sich ohne Pull Request ändern. Nach einem Update von Hostinger die
    Prüfungen aus Schritt 10 der Einrichtung wiederholen. nginx-Versionen kommen weiter
    über Dependabot (Image der Website).
  - Monitoring auf `https://funkenundstahl.de/healthz` und das Ablaufdatum der
    Zertifikate für `funkenundstahl.de` und `www.funkenundstahl.de`.
  - Kein Zertifikats-Volume in `/opt/website`: Die Zertifikate liegen beim Traefik von
    Hostinger. Auf dem Server gehört nur `.env` zum Stack, sie lässt sich nach
    Schritt 6 neu anlegen.
