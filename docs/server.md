# Server einrichten

Was auf dem Server läuft, steht vollständig in [`deploy/`](../deploy):

| Datei                       | Inhalt                                                                              |
| --------------------------- | ----------------------------------------------------------------------------------- |
| `compose.yml`               | Traefik (HTTPS, Let's Encrypt, Weiterleitung HTTP → HTTPS) und die Website (nginx)   |
| `traefik/dynamic.yml`       | Routen, HSTS, Weiterleitung der Zweitdomain, TLS ab Version 1.2                      |
| `.env.example`              | Domain, E-Mail für Let's Encrypt, aktuelles Image                                    |
| `deploy.sh`                 | Deploy mit Gesundheitsprüfung und automatischem Rollback                             |
| `setup-server.sh`           | Ersteinrichtung: Updates, Firewall, SSH nur mit Schlüssel, Docker, Benutzer `deploy` |

Traefik liest seine Routen aus einer Datei und braucht keinen Zugriff auf den
Docker-Socket. Weder Traefik noch nginx schreiben Zugriffsprotokolle mit IP-Adressen.

## Was ihr braucht

1. **Einen kleinen Linux-Server (VPS)** mit Debian 13 oder Ubuntu 24.04, Standort in der
   EU, öffentliche IPv4-Adresse. 2 vCPU, 2 bis 4 GB RAM und 20 GB SSD reichen für eine
   statische Seite (geschätzt).
2. **Eine Domain** mit Zugriff auf die DNS-Einträge:
   - `A`-Eintrag (und ggf. `AAAA`) für `www.meine-domain.de` auf die Server-IP
   - dasselbe für `meine-domain.de`, falls die Domain ohne `www` weiterleiten soll
3. **Einen SSH-Schlüssel** auf eurem Rechner (`ssh-keygen -t ed25519`), dessen
   öffentlichen Teil ihr beim Anbieter für den Server hinterlegt.
4. **Einen Vertrag zur Auftragsverarbeitung** mit dem Anbieter (bieten die großen
   Anbieter im Kundenkonto an). Den Anbieter in der Datenschutzerklärung eintragen.

## Einrichten

```sh
# 1. Ersteinrichtung (als root, einmalig)
scp -r deploy root@SERVER:/root/
ssh root@SERVER 'bash /root/deploy/setup-server.sh'

# 2. .env ausfüllen
ssh root@SERVER 'nano /opt/website/.env'

# 3. Deploy-Schlüssel nur für die CI erzeugen (auf eurem Rechner)
ssh-keygen -t ed25519 -f github-deploy -N '' -C github-deploy
#    öffentlichen Teil auf dem Server eintragen, beschränkt auf deploy.sh:
echo "command=\"/opt/website/deploy.sh\",restrict $(cat github-deploy.pub)" \
  | ssh root@SERVER 'cat >> /home/deploy/.ssh/authorized_keys'
#    privaten Teil (Datei github-deploy) als Secret DEPLOY_SSH_KEY in GitHub eintragen,
#    ssh-keyscan SERVER als Secret DEPLOY_KNOWN_HOSTS, danach die lokale Datei löschen.
```

Dann in GitHub `DEPLOY_ENABLED=true` setzen (siehe [`ci-cd.md`](ci-cd.md)). Der nächste
Merge nach `main` veröffentlicht das Image und deployt es.

**Tipp für den ersten Start:** In `.env` die Zeile `ACME_CA_SERVER=...staging...`
aktivieren. Let's Encrypt begrenzt fehlgeschlagene Versuche; mit der Staging-CA lässt
sich gefahrlos testen. Wenn alles läuft, die Zeile entfernen, das Volume
`website_letsencrypt` löschen und `docker compose up -d` ausführen.

## Konfiguration ändern

Änderungen an `compose.yml` oder `traefik/dynamic.yml` laufen wie Code über einen Pull
Request. Danach mit eurem eigenen Schlüssel (nicht dem Deploy-Schlüssel) übertragen:

```sh
scp deploy/compose.yml deploy/deploy.sh root@SERVER:/opt/website/
scp deploy/traefik/dynamic.yml root@SERVER:/opt/website/traefik/
ssh root@SERVER 'cd /opt/website && docker compose up -d'
```

## Laufender Betrieb

- **Sicherheitsupdates** des Systems installieren sich automatisch. Traefik- und
  nginx-Versionen kommen als Dependabot-Pull-Requests.
- **Zertifikate** erneuert Traefik selbst. Let's Encrypt verkürzt die Laufzeit ab
  10.02.2027 auf 64 und ab 16.02.2028 auf 45 Tage; dafür ist nichts zu tun, aber ein
  externes Monitoring sollte melden, wenn eine Erneuerung scheitert.
- **Monitoring:** einen externen Dienst `https://www.meine-domain.de/healthz` und das
  Zertifikatsablaufdatum prüfen lassen.
- **Backup:** Inhalt und Konfiguration liegen im Repository. Auf dem Server sind nur
  `.env` und das Zertifikats-Volume; beide lassen sich neu erzeugen.
