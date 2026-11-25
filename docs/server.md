# Server einrichten

Was auf dem Server läuft, steht vollständig in [`deploy/`](../deploy):

| Datei                 | Inhalt                                                                                                            |
| --------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `setup-server.sh`     | Absicherung eines frischen Servers: Updates, SSH nur mit Schlüssel, fail2ban, Firewall, Docker, Benutzer `deploy` |
| `compose.yml`         | Traefik (HTTPS, Let's Encrypt, Weiterleitung HTTP → HTTPS) und die Website (nginx)                                |
| `traefik/dynamic.yml` | Routen, HSTS, Weiterleitung der Zweitdomain, TLS ab Version 1.2                                                   |
| `.env.example`        | Domain, E-Mail für Let's Encrypt, aktuelles Image                                                                 |
| `deploy.sh`           | Deploy mit Gesundheitsprüfung und automatischem Rollback                                                          |

`setup-server.sh` richtet die Website nicht mehr ein. Wie `compose.yml`, `traefik/`,
`.env` und `deploy.sh` auf den Server kommen, folgt mit dem Aufbau von Live und Staging
(neue Struktur: `/opt/traefik`, `/opt/site-live`, `/opt/site-staging`, `/opt/deploy`).

Traefik liest seine Routen aus einer Datei und braucht keinen Zugriff auf den
Docker-Socket. Weder Traefik noch nginx schreiben Zugriffsprotokolle mit IP-Adressen.

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
  (Variable `SUDO_USER`). Danach dürfte nur noch `ADMIN_USER` per SSH herein, der
  aufrufende Benutzer wäre ausgesperrt. Abhilfe: `ADMIN_USER` auf deinen Benutzer
  setzen, z. B. `sudo ADMIN_USER=name bash setup-server.sh`.
- In der Schlüsseldatei von `ADMIN_USER` steht kein Schlüssel (fehlt, leer oder nur
  Kommentare). Geprüft wird die Datei, die sshd für diesen Benutzer liest
  (`AuthorizedKeysFile` laut `sshd -T`, relativ zum Home-Verzeichnis aus
  `getent passwd`), im Normalfall `~/.ssh/authorized_keys`, beim Standardbenutzer also
  `/home/ubuntu/.ssh/authorized_keys`. Weicht `AuthorizedKeysFile` vom Standard ab,
  warnt das Skript.
- `sshd -T` liefert für `ADMIN_USER` keine wirksame Konfiguration. Ohne sie lässt sich
  die Schlüsseldatei nicht sicher bestimmen; das Skript rät dann nicht.
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
- `sshd -t` meldet einen Fehler, `sshd -T` scheitert, oder die wirksame Konfiguration
  (`sshd -T` global und `sshd -T -C user=ADMIN_USER,…` nach `Match`-Blöcken) erfüllt
  eine dieser Bedingungen nicht: `ADMIN_USER` steht in `AllowUsers`;
  `PasswordAuthentication`, `KbdInteractiveAuthentication` und `PermitRootLogin` sind
  `no`; `DenyUsers` nennt `ADMIN_USER` nicht; ist `AllowGroups` gesetzt, ist
  `ADMIN_USER` in einer dieser Gruppen; `DenyGroups` nennt keine seiner Gruppen. Dann
  wird `/etc/ssh/sshd_config.d/10-haertung.conf` zurückgesetzt und SSH nicht neu
  geladen. Die Meldung nennt die Dateien, die den Wert vermutlich vorher setzen (sshd
  nimmt den ersten Wert; Dateien in `sshd_config.d` mit früher sortiertem Namen werden
  zuerst gelesen).
- `fail2ban-client -t` meldet einen Fehler in `/etc/fail2ban/fail2ban.local` oder
  `/etc/fail2ban/jail.local`.
- Der Signaturschlüssel von Docker hat nicht den erwarteten Fingerabdruck
  `9DC8 5822 9FC7 DD38 854A E2D8 8D81 803C 0EBF CD88`. Dann wird nichts von Docker
  installiert.
- iptables lässt sich nicht lesen.

Was es einrichtet:

- System-Updates (`apt-get full-upgrade`), automatische Sicherheitsupdates, bei Bedarf
  Neustart um 04:00
  (Zeitzone des Servers: Europe/Berlin)
- SSH nur mit Schlüssel, kein Root-Login, nur die Benutzer `ubuntu` und `deploy`
  (`/etc/ssh/sshd_config.d/10-haertung.conf`)
- fail2ban für SSH mit den Werten der Datenschutzerklärung, ausdrücklich gesetzt:
  `maxretry = 5`, `findtime = 10m`, `bantime = 10m` (`/etc/fail2ban/jail.local`) und
  `dbpurgeage = 1d`; fail2ban schreibt sein Protokoll statt nach
  `/var/log/fail2ban.log` über syslog mit der Facility `authpriv` ins Journal und, falls
  rsyslog installiert ist, nach `/var/log/auth.log`, nicht nach `/var/log/syslog`
  (`logtarget = SYSLOG[facility=AUTHPRIV]` in `/etc/fail2ban/fail2ban.local`).
- Protokolle mit IP-Adressen werden nach etwa 7 Tagen gelöscht, wie in der
  Datenschutzerklärung angegeben: im Journal
  (`/etc/systemd/journald.conf.d/10-aufbewahrung.conf`), falls rsyslog installiert ist
  in `/var/log/auth.log` (`/etc/logrotate.d/00-auth-log`), und falls logrotate
  installiert ist in `/var/log/btmp` und `/var/log/wtmp`
  (`/etc/logrotate.d/00-login-logs`) sowie in `/var/log/fail2ban.log`
  (`/etc/logrotate.d/00-fail2ban-log`; enthält nur noch Einträge von vor dem Wechsel
  auf syslog). Die Dateien der Pakete in `/etc/logrotate.d` bleiben unverändert.
- Firewall über die iptables-Regeln des Oracle-Images (kein UFW; ein installiertes,
  inaktives UFW entfernt apt mit `iptables-persistent`): Ports 22, 80 und 443
  für IPv4 und IPv6, wenn `INPUT` andere Verbindungen abweist (`REJECT`-Regel oder
  Policy `DROP`). Das Skript fügt nur Regeln ein und löscht keine. Eine wirkungslose
  Kopie hinter `REJECT` bleibt stehen, das Skript warnt bei jedem Lauf; entfernen von
  Hand (Nummer mit `sudo iptables -L INPUT --line-numbers -n`).
- Docker aus dem offiziellen Repository (Signaturschlüssel per Fingerabdruck geprüft)
  mit begrenzten Logs, ohne TCP-Socket
- Benutzer `deploy` in der Gruppe `docker`, mit leerer `authorized_keys`

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
iptables-Regeln wie im Oracle-Image). Auf dem Rechner selbst ändert sich nichts. Er
braucht root, Netz-Namespaces und die Werkzeuge `unshare`, `setpriv`, iptables,
`sshd`, `fail2ban-client`, `apt-config`, `shellcheck` und `python3`; außerdem müssen
die Benutzer `ubuntu` und `claude` existieren. Exit-Code 0 heißt bestanden, 1 mindestens
ein Fehler, 2 der Test kann hier nicht laufen (dann gilt er als nicht ausgeführt, nicht
als bestanden). In der CI läuft er nicht (dort ist er nicht eingerichtet); er ist deshalb
lokal Pflicht.

**Hinweis Docker und Firewall:** Docker leitet veröffentlichte Container-Ports an der
INPUT-Kette vorbei. Deshalb veröffentlicht nur Traefik Ports (80, 443). Eigene Regeln
für Container gehören in die Kette `DOCKER-USER`.

## Website einrichten (folgt mit dem Aufbau von Live und Staging)

Dieser Teil wird mit der neuen Struktur neu geschrieben.

> **Wichtig:** Die Variable `DEPLOY_ENABLED` in GitHub erst auf `true` setzen, wenn
> Live und Staging aufgebaut sind. `setup-server.sh` legt weder `deploy.sh` noch die
> Verzeichnisse der Website an. Mit `DEPLOY_ENABLED=true` würde jeder Merge nach `main`
> den Deploy-Job starten, und der schlägt dann fehl (siehe [`ci-cd.md`](ci-cd.md)).

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
