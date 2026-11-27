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

`setup-server.sh` kennt zwei Profile (Variable `PROFIL`): `oracle` ist der Standard und
in den Abschnitten „Was ihr braucht“ bis „Skript testen“ beschrieben. Für einen
Hostinger-VPS gilt `PROFIL=hostinger`, siehe
[Hostinger-VPS (Profil `hostinger`)](#hostinger-vps-profil-hostinger).

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
für Container gehören in die Kette `DOCKER-USER`. Auf Hostinger veröffentlichen auch
andere Container Ports (z. B. 32768), siehe den Abschnitt zum Profil `hostinger`.

## Hostinger-VPS (Profil `hostinger`)

`setup-server.sh` hat zwei Profile, gewählt mit der Variablen `PROFIL`: `oracle`
(Standard, alles oben) und `hostinger`. Ein anderer Wert bricht ab, bevor etwas
geändert wird. Das Profil `hostinger` ist für einen Hostinger-VPS mit Ubuntu 24.04
geschrieben, auf dem schon läuft, was Hostinger mitbringt: Docker (`docker-ce`,
`containerd.io`, Compose-Plugin aus dem offiziellen Repository), Traefik von Hostinger
im Host-Netz auf 80 und 443 und weitere Container (z. B. eine App mit dem
veröffentlichten Port `0.0.0.0:32768`).

### Ausgangslage und was das Profil anders macht

| Thema     | Hostinger vorher                                                          | Nach dem Skript                                                                                                                       |
| --------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Anmeldung | nur root (Web-Konsole im hPanel oder SSH), root mit Passwort              | `ADMIN_USER` mit Schlüssel und sudo-Passwort, `deploy` für die CI, root nur noch von der Web-Konsole (`169.254.0.1`) mit Passwort     |
| SSH       | `PermitRootLogin yes`, `PasswordAuthentication yes`                       | global `PermitRootLogin no`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`; Ausnahme `Match User root Address 169.254.0.1` |
| Firewall  | `INPUT` offen (Policy `ACCEPT`, keine Regeln, IPv4 und IPv6), UFW inaktiv | `INPUT` endet mit `REJECT`; davor Loopback, Antworten, ICMP/ICMPv6, DHCP-Client, SSH-Port, 80, 443, Ports von docker-proxy; UFW entfernt |
| fail2ban  | nicht eingerichtet                                                        | wie bei Oracle, zusätzlich `ignoreip = 127.0.0.1/8 ::1 169.254.0.1`                                                                   |
| Docker    | installiert, läuft                                                        | läuft weiter, wird nie neu gestartet und in den apt-Läufen des Skripts nicht aktualisiert; `daemon.json` ergänzt (`live-restore`, Log-Grenzen) |

Alles andere (Updates mit Neustart um 04:00, Aufbewahrung der Protokolle, Benutzer
`deploy`, die Prüfungen gegen das Aussperren, `DRY_RUN=1`) ist wie im Profil `oracle`.

**Eingaben, nur beim Aufruf, nie im Repository:**

- `ADMIN_USER`: euer neuer Login-Benutzer. Pflicht, kein Standard. Nur Kleinbuchstaben,
  Ziffern, `_` und `-`, höchstens 32 Zeichen, nicht `root` oder `deploy`. Gibt es den
  Benutzer schon, muss er ein normaler Login-Benutzer sein (UID ab `UID_MIN`,
  Login-Shell); ein Systembenutzer wie `www-data` bricht ab. Gibt es nur eine Gruppe
  dieses Namens, bricht das Skript ebenfalls ab.
- `ADMIN_PUBKEY`: genau eine Zeile `TYP BASE64 [Kommentar]`, also der Inhalt eurer
  `.pub`-Datei. Erlaubt: `ssh-ed25519` (empfohlen), `ecdsa-sha2-nistp256`, `-nistp384`,
  `-nistp521`, `ssh-rsa` ab 2048 Bit. Abgelehnt: private Schlüssel, mehrere Zeilen,
  Steuerzeichen, Optionen vor dem Schlüssel (`command=`, `from=`, `restrict` …), andere
  Typen, alles, was `ssh-keygen -l` nicht als öffentlichen Schlüssel genau dieses Typs
  erkennt. Der Schlüssel erscheint in keiner Ausgabe, auch nicht im Testlauf, nur sein
  Fingerabdruck.
- `ONLY_SAVE_FIREWALL=1` (optional, später): speichert nur die Regeln von `INPUT`
  (siehe „Firewall-Regeln ändern“) und tut sonst nichts.

**sudo mit Passwort, Pflicht vor jeder Änderung an SSH.** Das Skript legt `ADMIN_USER`
ohne Passwort an und trägt kein `NOPASSWD` ein. Bei jedem Lauf, nach dem Eintragen des
Schlüssels und bevor es die SSH-Datei schreibt, verlangt es ein Passwort für
`ADMIN_USER` (`passwd -S` zeigt `P`), damit `sudo` ein zweiter Weg zu root ist (nach dem
Lauf kommt root nur noch über die Web-Konsole herein). Läuft das Skript in einem
Terminal (Web-Konsole), fragt es mit `passwd` danach. Ohne Terminal bricht es ab, SSH
bleibt unverändert; dann als root `passwd ADMIN_USER` und das Skript erneut starten
(Benutzer und Schlüssel bleiben). Wird der Lauf unterbrochen (Strg-C, Tab der
Web-Konsole geschlossen, SIGTERM), nachdem die SSH-Datei geschrieben, aber bevor SSH neu
geladen wurde, setzt das Skript die Datei zurück. Nach bestandenen Prüfungen lädt es SSH
bei jedem Lauf neu, auch wenn die Datei unverändert ist. Die Anmeldung mit dem Schlüssel
klappt auch ohne Passwort (das Skript prüft `UsePAM yes`). Ein gestohlener Schlüssel
allein gibt so noch keine Root-Rechte.

### Ablauf (für den Betreiber)

1. **Schlüssel auf eurem Rechner** (falls noch keiner da ist):
   `ssh-keygen -t ed25519 -C "name@rechner"`. Den öffentlichen Teil anzeigen:
   `cat ~/.ssh/id_ed25519.pub`. Nur diese eine Zeile kommt auf den Server, nie die
   Datei ohne `.pub`.
2. **Commit wählen und Prüfsumme auf eurem Rechner berechnen.** Im Repository auf
   GitHub den Commit von `main` nehmen, der das Skript in der geprüften Fassung enthält
   (40-stelliger Hash). In eurem Klon:
   `git fetch origin && git cat-file -p COMMIT:deploy/setup-server.sh | sha256sum`
   (das ist genau der Inhalt der Datei in diesem Commit, wie ihn `curl` in Schritt 5
   lädt).
   Die Prüfsumme notieren.
3. **hPanel absichern:** Zwei-Faktor-Anmeldung für das hPanel einschalten, und das
   root-Passwort (für die Web-Konsole) im hPanel auf ein langes, nur hier verwendetes
   Passwort setzen. Das root-Passwort später immer im hPanel ändern, nicht mit `passwd`
   auf dem Server, damit hPanel und Server übereinstimmen.
4. **Web-Konsole öffnen:** im hPanel den VPS wählen und das Browser-Terminal öffnen
   (Login als root). Das Skript in dieser Konsole starten, nicht über SSH von eurem
   Rechner (sonst warnt es). Diese Konsole bleibt offen, bis Schritt 11 geklappt hat.
   Darin zuerst `tmux` starten, damit ein geschlossener oder abgestürzter Browser-Tab
   den Lauf (und damit apt und dpkg) nicht mittendrin abbricht:

   ```sh
   command -v tmux || apt-get install -y tmux   # auf Ubuntu 24.04 Server meist schon da
   tmux new -s haertung
   ```

   Ist der Tab weg: Web-Konsole neu öffnen und `tmux attach -t haertung`. Alle
   folgenden Befehle auf dem Server laufen in dieser tmux-Sitzung. (`screen` geht
   genauso: `screen -S haertung`, zurück mit `screen -r haertung`.)
5. **Skript auf den Server holen** (in der Web-Konsole, als root):

   ```sh
   cd /root
   COMMIT=0123456789abcdef0123456789abcdef01234567   # euer Commit aus Schritt 2
   curl -fsSLo setup-server.sh "https://raw.githubusercontent.com/Advocatusrar/claude-webseiten/$COMMIT/deploy/setup-server.sh"
   sha256sum setup-server.sh
   ```

   Die Prüfsumme muss genau der aus Schritt 2 entsprechen, sonst nicht ausführen. Statt
   `curl` geht auch `git clone https://github.com/Advocatusrar/claude-webseiten.git`
   und `git -C claude-webseiten checkout COMMIT`, oder vor dem ersten Lauf
   `scp deploy/setup-server.sh root@SERVER:/root/` von eurem Rechner (root darf sich bis
   zum Lauf noch mit Passwort anmelden). Immer einen festen Commit nehmen, nie `main`.
6. **Anmeldungen der letzten 30 Tage ansehen** (nur lesend):

   ```sh
   journalctl -q --since "-30 days" -t sshd -t sshd-session | grep ' Accepted ' |
     awk '{ for (i = 1; i <= NF; i++) if ($i == "Accepted") print $(i + 3), $(i + 5), $(i + 1) }' |
     sort | uniq -c
   ```

   Spalten: Anzahl, Benutzer, Absenderadresse, Verfahren. Erwartet ist root von
   `169.254.0.1` mit `password` (Web-Konsole). Jede andere Zeile (root von einer anderen
   Adresse, etwa mit `publickey`, oder ein anderer Benutzer) ist nach dem Lauf
   gesperrt. Funktionen im hPanel wie der Docker-Manager könnten sich so anmelden;
   vorher klären, wer das ist. Der Testlauf in Schritt 7 meldet dasselbe als Warnung
   (nur Anzahl und Adressen).
7. **Testlauf** (ändert nichts):

   ```sh
   PROFIL=hostinger ADMIN_USER=name ADMIN_PUBKEY='ssh-ed25519 AAAA... name@rechner' DRY_RUN=1 bash setup-server.sh
   ```

   Den Schlüssel in einfachen Anführungszeichen einfügen, in einer Zeile. Die Ausgabe
   lesen: Zeilen mit „Ein echter Lauf würde hier abbrechen“ zuerst beheben. Außerdem:
   - „Diese Dienste lauschen auf weiteren Ports …“: Dienste des Servers, die nach dem
     Lauf von außen nicht mehr erreichbar sind.
   - „Von Docker veröffentlichte Ports …“: diese Ports erlaubt das Skript in `INPUT`
     (siehe unten).
   - „Diese laufenden Container haben keine Neustart-Regel …“: Sie starten nach dem
     automatischen Neustart um 04:00 nicht von selbst wieder. Vorher klären (z. B. in
     der Compose-Datei `restart: unless-stopped`).
   - „Journal: Keine Anmeldung von root … gefunden“: Erst prüfen, dass die Web-Konsole
     wirklich funktioniert.
   - „Journal: … Anmeldungen als root NICHT von 169.254.0.1 …“ oder „… anderer
     Benutzer …“: siehe Schritt 6.
8. **Echter Lauf:** derselbe Befehl ohne `DRY_RUN=1`. Bevor er SSH ändert, fragt er
   nach dem Passwort für `ADMIN_USER` (für sudo). Er endet mit „Änderungen in diesem
   Lauf: …“ und der Abnahmeliste.
9. **Zweite Anmeldung testen, bevor ihr irgendetwas schließt.** Auf eurem Rechner in
   einem neuen Fenster: `ssh name@SERVER`, dann `sudo -v` (fragt nach dem Passwort aus
   Schritt 8). Gegenproben: `ssh root@SERVER` und
   `ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password name@SERVER`
   werden mit „Permission denied“ abgewiesen.
   Klappt der Login mit dem Schlüssel nicht: in der noch offenen Web-Konsole
   `rm /etc/ssh/sshd_config.d/10-haertung.conf && systemctl reload ssh`. Damit gilt
   wieder die SSH-Konfiguration von Hostinger; Ursache suchen und das Skript erneut
   starten.
10. **Dienste prüfen** (auf eurem Rechner): `curl -I http://SERVER` und
   `curl -I http://SERVER:32768` antworten wie vor dem Lauf (Traefik bzw. die andere
   App), über IPv6 ebenso (`curl -6 -I …`, falls der VPS IPv6 hat). Auf dem Server:
   `sudo iptables -S INPUT`, `sudo ip6tables -S INPUT`, `sudo fail2ban-client status sshd`,
   `sudo docker info | grep -i 'live restore'` (zeigt `Live Restore Enabled: true`).
11. **Zweite Web-Konsole öffnen**, die erste noch nicht schließen: Der Login als root
    muss weiter klappen. Erst wenn Schritt 9 (einschließlich `sudo -v`) und dieser
    Schritt geklappt haben, die erste Konsole schließen.
12. **Funktionen im hPanel prüfen:** den Docker-Manager und die anderen Funktionen
    des VPS, die ihr nutzt, einmal aufrufen (Container anzeigen, Logs). Gehen sie nicht
    mehr, melden sie sich vermutlich per SSH an (siehe Schritt 6); dann im Journal
    nachsehen (`journalctl -t sshd -t sshd-session --since "-1 hour"`) und klären.
13. **Firewall im hPanel** zusätzlich einrichten: eingehend TCP 22 (bzw. euren SSH-Port),
    80 und 443 erlauben (und 32768, solange die andere App von außen erreichbar sein
    soll), den Rest verwerfen. Sie filtert vor dem Server und ist die einzige Stelle, an
    der sich Docker-Ports wie 32768 ohne Eingriff in Docker beschränken lassen. Prüfen,
    dass sie Antworten auf Verbindungen des Servers durchlässt (zustandsbehaftet, sonst
    scheitern apt und DNS), ICMP nicht sperrt und die Web-Konsole (`169.254.0.1`) nicht
    betrifft. Danach Schritt 9 bis 12 wiederholen.
14. **Optional, in einer ruhigen Stunde:** einmal `sudo reboot` und danach Schritt 9 bis
    12 wiederholen. Das prüft, dass die Firewall-Regeln beim Start geladen werden und die
    Container wieder starten. Ein zweiter Lauf des Skripts meldet „Änderungen in diesem
    Lauf: 0“.

**Letzter Ausweg**, wenn weder SSH noch die Web-Konsole gehen: im hPanel den
Wiederherstellungsmodus (Recovery) oder die Notfall-Konsole (VNC) des VPS starten,
`/etc/ssh/sshd_config.d/10-haertung.conf` entfernen und die Firewall-Regeln prüfen.

### Was das Profil im Einzelnen tut

**Prüfungen vor jeder Änderung** (Abbruch ohne Änderung), zusätzlich zu denen des
Profils `oracle`, soweit sie gelten: Aufruf als root (ohne `sudo` erlaubt; mit `sudo`
gilt wie bei Oracle, dass der aufrufende und der angemeldete Benutzer `ADMIN_USER`
sein müssen); `ADMIN_USER` und `ADMIN_PUBKEY` wie oben; sshd liest für `ADMIN_USER`
die Datei `~/.ssh/authorized_keys` (`AuthorizedKeysFile` laut `sshd -T`), in die das
Skript den Schlüssel legt; `iptables` und `ip6tables` lassen sich lesen; SSH lauscht
nur auf den Ports, die `sshd -T` nennt (geprüft an `ssh.socket` und am laufenden sshd
laut `ss`), denn genau diese öffnet die Firewall. UFW aktiv bricht ab wie bei Oracle;
ein installiertes, inaktives UFW (Normalfall bei Hostinger) entfernt apt mit
`iptables-persistent`, das Skript sagt das deutlich und prüft am Ende, ob es geschehen
ist. UFW danach nicht wieder installieren. Abbruch auch, wenn `/etc/iptables/rules.v4`
oder `rules.v6` schon existiert, `iptables-persistent` aber noch nicht installiert ist
(netfilter-persistent würde die Datei bei seiner Installation laden und dabei die
Ketten von Docker löschen; die Datei erst beiseitelegen; eigene Dateien des Skripts
zusammen mit seinem Drop-in, siehe unten, sind ausgenommen), und wenn das Laden mit
`--noflush` nicht greifen würde (siehe „Laden ohne Docker zu stören“). Nur Hinweise,
kein Abbruch: Start über SSH
statt über die Web-Konsole, keine Anmeldung der Web-Konsole im Journal, Container ohne
Neustart-Regel `always` oder `unless-stopped`, weitere lauschende Dienste.

**Docker** (vor den Paket-Updates): Das Skript startet Docker nie neu, denn das würde
Traefik von Hostinger und alle anderen Container stoppen.

- Ist Docker Teil eines Swarm, bricht es ab (`live-restore` schützt Swarm-Dienste
  nicht).
- Es führt seine Werte in `/etc/docker/daemon.json` zusammen, statt die Datei zu
  ersetzen: vorhandene Schlüssel bleiben, ergänzt werden nur fehlende
  (`"live-restore": true`; `"log-driver": "local"` mit `max-size` 10m und `max-file` 3,
  bzw. nur `max-size` und `max-file`, wenn schon `json-file` oder `local` gesetzt ist).
  Vorher legt es eine Kopie `daemon.json.bak-DATUM` an und prüft das Ergebnis mit
  `dockerd --validate`. Danach `systemctl reload docker` (SIGHUP): `live-restore` wirkt
  sofort, laufende Container bleiben unberührt. Zeigt `docker info` danach
  `live-restore` nicht als aktiv, bricht das Skript vor den Paket-Updates ab.
- Log-Treiber und Log-Grenzen liest dockerd erst bei seinem nächsten Start (Neustart des
  Servers, Paket-Update), und sie gelten nur für danach neu erstellte Container.
- Ist `live-restore` ausdrücklich auf `false` gesetzt oder ein anderer Log-Treiber
  eingetragen, bleibt das so und das Skript warnt. Ein ungültiges `daemon.json` bricht
  ab, bevor etwas geändert wird.
- **Docker-Pakete werden in den apt-Läufen des Skripts nicht aktualisiert.** `docker-ce`,
  `docker-ce-cli`, `containerd.io`, `docker-buildx-plugin`, `docker-compose-plugin` und
  `docker-ce-rootless-extras` (soweit installiert) bleiben auf ihrer Version: apt-get
  bekommt für diese Läufe eine Pin-Datei (`Dir::Etc::Preferences`, Priorität 1001 auf die
  installierte Version) im temporären Verzeichnis des Laufs. Anders als `apt-mark hold`
  bleibt danach nichts zurück, auch nicht nach einem Abbruch. Ein Update von Docker
  startet dockerd neu, und `live-restore` hält Container laut Docker nur über
  Patch-Versionen hinweg am Laufen. Docker-Updates spielt ihr deshalb selbst ein, in
  einem Wartungsfenster: `sudo apt-get update && sudo apt-get install --only-upgrade
  docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin`,
  danach Traefik, die anderen Apps und die Website prüfen. Die automatischen Updates
  (unattended-upgrades) nehmen nur Pakete von Ubuntu, nicht aus dem Repository von Docker.
- needrestart startet nach Updates weder Docker noch containerd neu
  (`/etc/needrestart/conf.d/50-setup-server-docker.conf`; Docker nimmt Ubuntu schon von
  sich aus aus).
- Docker wird nicht neu installiert und kein Repository-Eintrag angelegt; das Skript
  meldet nur die Versionen.

**Neustart um 04:00:** Braucht ein Sicherheitsupdate einen Neustart, startet der Server
um 04:00 neu. Danach startet Docker nur Container mit der Neustart-Regel `always` oder
`unless-stopped` wieder; die Prüfung listet laufende Container ohne sie auf. Traefik von
Hostinger und die anderen Apps sind für die Dauer des Neustarts nicht erreichbar.

**Firewall:** Das Skript hängt an `INPUT` (IPv4 und IPv6) an, was fehlt, in dieser
Reihenfolge: `-i lo`, `RELATED,ESTABLISHED` (ohne sie bräche die laufende SSH-Sitzung ab
und keine Antwort auf apt, DNS oder NTP käme an), ICMP bzw. alles von ICMPv6 (Neighbor
Discovery und Router Advertisements; ohne sie funktioniert IPv6 nicht), den DHCP-Client
(wie in den Standardregeln von UFW: UDP 67 → 68, bei IPv6 UDP 547 → 546 zwischen
link-lokalen Adressen), TCP für die SSH-Ports laut `sshd -T`, 80 und 443, die Ports, auf
denen docker-proxy lauscht, und erst wenn alle diese Regeln da sind, als letzte Regel
`REJECT`. Als Ende von `INPUT` zählt nur ein `REJECT` oder `DROP` ohne Bedingung an
letzter Stelle. Neue ACCEPT-Regeln kommen direkt davor, nie über eine vorhandene
`REJECT`- oder `DROP`-Regel mit Bedingung (etwa eine Sperre für eine Adresse), damit
die weiter wirkt. Die Policy bleibt `ACCEPT`. Es fügt nur ein und hängt an, es löscht
keine Regel; ein zweiter Lauf erzeugt keine Kopien. `FORWARD`, die Ketten `DOCKER*` und
die Tabelle `nat` bleiben unberührt. Verändert die Paketinstallation die Struktur, die
Docker in der Tabelle `filter` anlegt (Policy von `FORWARD`, die Sprünge von `FORWARD` in
`DOCKER-USER`, `DOCKER-FORWARD` und Co., welche Ketten `DOCKER*` es gibt; etwa durch
`ufw-init stop`, das `FORWARD` auf `ACCEPT` setzen kann), bricht das Skript ab und
nennt Vorher und Nachher. Es spielt dann nichts zurück: Die Regeln in den Ketten von Docker
ändern sich mit jedem Start eines Containers, eine alte Kopie könnte einem inzwischen
neu gestarteten Container die Ports nehmen. Die Regeln einzelner Container vergleicht
es deshalb nicht.

- **Port 32768 und andere Docker-Ports:** Über IPv4 von außen leitet Docker sie mit DNAT
  in der Tabelle `nat` über die Kette `FORWARD` an den Container, an `INPUT` vorbei.
  Beschränken lässt sich das nur in der Kette `DOCKER-USER` oder in der Firewall im
  hPanel; das Skript lässt beides in Ruhe. Über IPv6 (docker-proxy lauscht auf `[::]`,
  der Container hat kein IPv6) und von Containern zur eigenen Adresse des Servers
  (Hairpin) nimmt dagegen docker-proxy die Verbindung an, und die läuft durch `INPUT`.
  Deshalb erlaubt das Skript jeden Port, auf dem beim Lauf docker-proxy lauscht, in
  `INPUT` und nennt ihn in der Ausgabe: bei `0.0.0.0`, `::` oder `*` in IPv4 und IPv6,
  bei einer bestimmten Adresse nur in deren Familie und mit `-d ADRESSE`. **Später veröffentlichte Ports**
  brauchen dasselbe: das Skript erneut starten (oder die Regel von Hand einfügen und
  speichern, siehe unten).
- **Traefik von Hostinger** (Host-Netz, 80 und 443) läuft durch `INPUT` und ist durch
  die Regeln für 80 und 443 abgedeckt. Seine Verbindungen zu Containern gehen über
  `OUTPUT` hinaus; die Antworten kommen über `docker0` bzw. `br-*` zurück und sind
  `RELATED,ESTABLISHED`.
- **Verbindungen von Containern zum Server selbst** (nicht zu einem veröffentlichten
  Port) laufen ebenfalls durch `INPUT`: zu SSH, 80 und 443 erlaubt, zu jedem anderen
  Port des Servers abgewiesen. Es gibt bewusst kein `-i docker0 -j ACCEPT` oder
  `-i br-+ -j ACCEPT`; das würde jedem Container alle Dienste des Servers öffnen.
  Health-Checks von Docker laufen im Container und sind nicht betroffen.
- **Gespeichert** wird in `/etc/iptables/rules.v4` und `rules.v6` (Modus 0640) nur die
  Tabelle `filter` mit den Policies, der Zeile `-F INPUT` und den Regeln von `INPUT`,
  deren Ziel eingebaut ist (`ACCEPT`, `DROP`, `REJECT`, `RETURN`, `LOG`), vorher geprüft
  mit `iptables-restore --test`. Eine vorhandene Datei mit anderem Inhalt sichert das
  Skript vorher als `rules.v4.bak-DATUM` bzw. `rules.v6.bak-DATUM`. Die Sprungregel von
  fail2ban fehlt; fail2ban legt Kette und Sprungregel selbst an, bei der ersten Sperre
  nach seinem Start.
- **Laden ohne Docker zu stören:** netfilter-persistent lädt die Dateien beim Start
  (vor Docker), aber auch bei jedem `start`, `restart` oder `reload` des Dienstes, und
  das Paket `netfilter-persistent` startet den Dienst bei jedem Paket-Update neu
  (postinst: `deb-systemd-invoke restart`). Ohne Vorkehrung würde `iptables-restore` dabei
  die ganze Tabelle `filter` ersetzen und die Ketten von Docker löschen, während die Container
  laufen. Das Skript legt deshalb
  `/etc/systemd/system/netfilter-persistent.service.d/10-noflush.conf` an
  (`IPTABLES_RESTORE_NOFLUSH=yes`, `IP6TABLES_RESTORE_NOFLUSH=yes`): Geladen wird mit
  `--noflush`, und `-F INPUT` ersetzt nur `INPUT`. Das gilt nur für den Dienst über
  systemd (Boot, `systemctl restart netfilter-persistent`, Paket-Updates). Vor dem
  ersten Speichern prüft das Skript, dass die Plugins `15-ip4tables` und `25-ip6tables`
  von iptables-persistent diese Variablen auswerten (in Version 1.0.20 von Ubuntu 24.04
  der Fall) und `/etc/default/netfilter-persistent` sie nicht auf etwas anderes als
  `yes` setzt (dort sind sie in der Grundeinstellung auskommentiert; die Datei ändert
  das Skript nicht); sonst bricht es ab.
- **fail2ban nach einem Neuladen der Regeln:** Beim Start des Servers lädt
  netfilter-persistent die Regeln vor fail2ban; fail2ban legt seine Kette und die
  Sprungregel in `INPUT` danach selbst an, bei der ersten Sperre (bei den
  iptables-Aktionen von fail2ban 1.0.2 startet die Aktion erst bei Bedarf). Wird netfilter-persistent dagegen im laufenden Betrieb neu
  gestartet (`systemctl restart netfilter-persistent`, Paket-Update), entfernt
  `-F INPUT` die Sprungregel von fail2ban (`-p tcp -m multiport --dports 22 -j f2b-sshd`).
  fail2ban stellt sie nicht von selbst wieder her: In fail2ban 1.0.2 läuft die Prüfung
  `actioncheck` (und damit die Reparatur) nur, nachdem ein Befehl gescheitert ist, und
  eine neue Sperre in seine eigene Kette `f2b-sshd` einzutragen scheitert nicht
  (nachgelesen in `fail2ban/server/action.py` und `action.d/iptables.conf`). Die Sperren
  wirken dann nicht, bis fail2ban neu startet. Deshalb danach
  `sudo systemctl restart fail2ban`; die Sprungregel steht dann ab der nächsten Sperre
  wieder oben in `INPUT` (prüfen mit `sudo iptables -S INPUT`, solange
  `sudo fail2ban-client status sshd` eine Sperre zeigt).

**Firewall-Regeln ändern:** Auf diesem Server **nie** `netfilter-persistent save`,
`netfilter-persistent reload` oder `netfilter-persistent restart` von Hand aufrufen.
`save` schriebe die Ketten und NAT-Regeln von Docker mit den Container-Adressen von heute in
die Dateien, `reload`/`restart` aus der Shell laufen ohne die Umgebung des Dienstes und
ersetzen die ganze Tabelle `filter`. Stattdessen eine eigene Regel vor das `REJECT`
einfügen, z. B. für einen Dienst des Servers, den ein Container braucht:
`sudo iptables -I INPUT <Nummer des REJECT> -i br-xxxx -p tcp --dport PORT -j ACCEPT`
(Nummer mit `sudo iptables -L INPUT --line-numbers -n`), und nur die Regeln von `INPUT`
speichern:

```sh
sudo PROFIL=hostinger ONLY_SAVE_FIREWALL=1 bash /root/setup-server.sh
```

Das prüft, dass `INPUT` noch mit `REJECT` endet, davor die nötigen Regeln stehen und
das Laden mit `--noflush` greift, und schreibt die beiden Dateien wie oben (mit
Sicherung); sonst ändert es nichts. Ports, die Docker inzwischen neu veröffentlicht,
erlaubt dieser Modus nicht von selbst; dafür das ganze Skript erneut starten.

**SSH:** `/etc/ssh/sshd_config.d/10-haertung.conf` mit `PasswordAuthentication no`,
`KbdInteractiveAuthentication no`, `PermitRootLogin no`, `GSSAPIAuthentication no`,
`HostbasedAuthentication no`, `AllowUsers ADMIN_USER deploy root@169.254.0.1` und am
Ende `Match User root Address 169.254.0.1` mit `PermitRootLogin yes` und
`PasswordAuthentication yes`, abgeschlossen mit `Match all`. Die Ausnahme gilt nur für
root; `ADMIN_USER` und `deploy` brauchen auch von `169.254.0.1` aus den Schlüssel. sshd
nimmt den ersten Wert, den es liest, und liest `sshd_config.d` am Anfang von
`sshd_config` in Namensreihenfolge; `10-` kommt vor `50-cloud-init.conf` (dort
`PasswordAuthentication yes`) und `60-cloudimg-settings.conf`. Ein `Match`-Block in einer
per `Include` gelesenen Datei endet mit dieser Datei (OpenSSH 9.6, nachgeprüft mit
`sshd -T`: Einstellungen aus `60-cloudimg-settings.conf` und dem Rest von `sshd_config`
gelten weiter für alle Verbindungen); `Match all` schließt ihn trotzdem ausdrücklich.
Bei jedem echten Lauf prüft das Skript mit `sshd -t` und `sshd -T -C`:

| Verbindung                                  | Erwartung                                                                                                  |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `ADMIN_USER` von `203.0.113.10` (Internet)  | wie bei Oracle: nur Schlüssel, in `AllowUsers`, kein Passwort; zusätzlich `UsePAM yes`                     |
| root von `203.0.113.10`                     | `PermitRootLogin no`, `PasswordAuthentication no`, kein `AllowUsers`-Eintrag für root von dort             |
| root von `169.254.0.1` (Web-Konsole)        | `PermitRootLogin yes`, `PasswordAuthentication yes`, `AllowUsers root@169.254.0.1`, `AuthenticationMethods` erlaubt das Passwort allein |
| `deploy` von `203.0.113.10`                 | `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `PubkeyAuthentication yes`                 |
| `ADMIN_USER` und `deploy` von `169.254.0.1` | ebenso nur Schlüssel: `PasswordAuthentication no`, `KbdInteractiveAuthentication no`                       |

Dazu muss der Schlüssel aus `ADMIN_PUBKEY` in `~ADMIN_USER/.ssh/authorized_keys` als
eigene Zeile stehen (nicht auskommentiert, ohne Optionen davor; eine Zeile mit `from=`
oder `command=` zählt nicht, dann ergänzt das Skript den Schlüssel), mit Besitzer
`ADMIN_USER`, Verzeichnis 700 und Datei 600, und `ADMIN_USER` muss ein Passwort haben,
bevor sshd neu geladen wird. Die Datei schreibt das Skript über eine mit `mktemp` im
Verzeichnis angelegte Datei, `chown -h` und `mv -T`, nachdem es geprüft hat, dass weder
`~/.ssh` noch die Datei ein symbolischer Link ist. Scheitert eine Prüfung, setzt das
Skript die SSH-Datei zurück, lädt SSH nicht neu und bricht ab. `203.0.113.10` ist eine
Dokumentationsadresse (RFC 5737) und steht für jede Adresse aus dem Internet.

**fail2ban** wie bei Oracle, zusätzlich `ignoreip = 127.0.0.1/8 ::1 169.254.0.1` im Jail
`sshd` (geprüft mit `fail2ban-client -d`, genau diese Liste). Grund: Die Web-Konsole
meldet sich von `169.254.0.1` mit dem root-Passwort an. Fünf Tippfehler in 10 Minuten
würden sonst diese Adresse sperren und damit die Web-Konsole, den einzigen Zugang, der
nicht vom SSH-Schlüssel abhängt (etwa nachdem man sich ausgesperrt hat). `169.254.0.0/16`
ist link-lokal: Pakete mit dieser Absenderadresse kommen nur von Hostingers eigener
Seite des Netzes, nicht aus dem Internet. Versuche von dort werden weiter protokolliert.
Lauscht sshd nicht auf 22, überwacht der Jail die Ports laut `sshd -T`.

### Risiken und Grenzen

- **fail2ban vor Schritt 5 des Skripts:** apt installiert fail2ban in Schritt 1 und
  startet es mit den Voreinstellungen von Ubuntu (Jail `sshd` aktiv, ohne
  `169.254.0.1` in `ignoreip`). Bis das Skript in Schritt 5 seine `jail.local` schreibt,
  und dauerhaft, wenn es vorher abbricht (z. B. in Schritt 4a, weil `ADMIN_USER` kein
  Passwort hat), kann fail2ban die Web-Konsole nach fünf Fehlversuchen für zehn Minuten
  sperren. Deshalb das root-Passwort beim Login in die Web-Konsole nicht mehrfach falsch
  eingeben und ein abgebrochenes Skript zügig erneut starten. Entsperren von Hand:
  `sudo fail2ban-client set sshd unbanip 169.254.0.1`.

- **Die Ausnahme für `169.254.0.1` verlässt sich auf das interne Netz von Hostinger.**
  Wer diese Adresse im Netz des VPS verwenden kann (Hostinger selbst, oder ein Fehler
  in dessen Netztrennung), darf sich als root mit Passwort anmelden, ohne Sperre durch
  fail2ban. Deshalb: ein langes, nur hier verwendetes root-Passwort und
  Zwei-Faktor-Anmeldung für das hPanel, denn wer ins hPanel kommt, kommt über die
  Web-Konsole als root auf den Server. Ändert Hostinger die Adresse der Web-Konsole,
  funktioniert sie nicht mehr; der Zugang über `ADMIN_USER` mit sudo bleibt.
- Docker-Updates bleiben liegen, bis ihr sie selbst einspielt (siehe „Docker“); dabei
  startet dockerd neu, und bei mehr als einem Patch-Sprung können die Container kurz
  stoppen.
- Dienste des Servers auf anderen Ports als SSH, 80, 443 und den Ports von docker-proxy
  sind von außen und aus Containern nicht mehr erreichbar (die Prüfung listet sie
  vorher auf). Später veröffentlichte Docker-Ports sind über IPv6 und per Hairpin erst
  nach einem erneuten Lauf erreichbar.
- Ein `netfilter-persistent reload` von Hand würde die Ketten von Docker löschen (siehe
  „Firewall-Regeln ändern“).
- Die Datenschutzerklärung (`site/src/texte/datenschutz.md`, Abschnitt „Schutz des
  Servers vor Angriffen“) sagt „Wartungszugriffe nur über SSH mit Schlüssel“ und nennt
  die Sperre durch fail2ban ohne Ausnahme. Für Hostinger stimmt das nicht mehr (root
  mit Passwort über die Web-Konsole, `169.254.0.1` nie gesperrt). Text und Angaben zum
  Hosting-Anbieter vor dem Umzug anpassen, in einem eigenen Pull Request.

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
