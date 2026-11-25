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

Das Skript bricht ohne jede Änderung ab, wenn `/home/ubuntu/.ssh/authorized_keys` fehlt
oder leer ist, wenn es nicht als root läuft oder wenn das System kein Ubuntu ist. Es
lässt sich gefahrlos ein zweites Mal ausführen und meldet dann 0 Änderungen.

Was es einrichtet:

- System-Updates, automatische Sicherheitsupdates, bei Bedarf Neustart um 04:00
  (Zeitzone des Servers: Europe/Berlin)
- SSH nur mit Schlüssel, kein Root-Login, nur die Benutzer `ubuntu` und `deploy`
  (`/etc/ssh/sshd_config.d/10-haertung.conf`)
- fail2ban für SSH
- Firewall über die iptables-Regeln des Oracle-Images (kein UFW): Ports 22, 80 und 443
- Docker aus dem offiziellen Repository mit begrenzten Logs, ohne TCP-Socket
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

**Hinweis Docker und Firewall:** Docker leitet veröffentlichte Container-Ports an der
INPUT-Kette vorbei. Deshalb veröffentlicht nur Traefik Ports (80, 443). Eigene Regeln
für Container gehören in die Kette `DOCKER-USER`.

## Website einrichten (folgt mit dem Aufbau von Live und Staging)

Dieser Teil wird mit der neuen Struktur neu geschrieben. Erhalten bleibt:

- **Deploy-Schlüssel nur für die CI** auf eurem Rechner erzeugen
  (`ssh-keygen -t ed25519 -f github-deploy -N '' -C github-deploy`) und den öffentlichen
  Teil in `/home/deploy/.ssh/authorized_keys` eintragen, beschränkt auf einen Befehl
  (`command="…",restrict`). Den privaten Teil als Secret `DEPLOY_SSH_KEY` in GitHub
  eintragen, `ssh-keyscan SERVER` als Secret `DEPLOY_KNOWN_HOSTS`, danach die lokale
  Datei löschen. Dann in GitHub `DEPLOY_ENABLED=true` setzen (siehe
  [`ci-cd.md`](ci-cd.md)).
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
