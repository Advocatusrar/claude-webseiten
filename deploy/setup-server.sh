#!/usr/bin/env bash
# One-time setup of a fresh Debian 13 / Ubuntu 24.04 server for the website.
# Run as root after logging in with an SSH key:
#   scp -r deploy root@SERVER:/root/ && ssh root@SERVER 'bash /root/deploy/setup-server.sh'
#
# What it does: system updates and automatic security updates, firewall (22, 80, 443),
# SSH login only with keys, Docker from the official repository, user "deploy" and
# /opt/website with compose.yml, traefik/ and deploy.sh.
# It is idempotent: running it again changes nothing that is already set up.
set -euo pipefail

ZIEL=/opt/website
QUELLE="$(dirname "$(readlink -f "$0")")"

[[ $EUID -eq 0 ]] || { echo "Bitte als root ausführen." >&2; exit 1; }
# Do not lock yourself out: password login is only switched off if a key is present.
[[ -s /root/.ssh/authorized_keys ]] || { echo "Kein SSH-Schlüssel in /root/.ssh/authorized_keys, Abbruch." >&2; exit 1; }

# shellcheck source=/dev/null
. /etc/os-release
case "$ID" in debian | ubuntu) ;; *) echo "Nur Debian oder Ubuntu werden unterstützt." >&2; exit 1 ;; esac

echo "== System aktualisieren"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get upgrade -y -q
apt-get install -y -q ca-certificates curl gnupg ufw unattended-upgrades

echo "== Automatische Sicherheitsupdates"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'CONF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
CONF

echo "== SSH nur mit Schlüssel"
cat > /etc/ssh/sshd_config.d/10-haertung.conf <<'CONF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
CONF
sshd -t
systemctl reload ssh 2>/dev/null || systemctl reload sshd

echo "== Firewall"
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

echo "== Docker"
if ! command -v docker >/dev/null; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/$ID/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$ID $VERSION_CODENAME stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -q
  apt-get install -y -q docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi
# Limit container logs so the disk does not fill up.
if [[ ! -f /etc/docker/daemon.json ]]; then
  echo '{ "log-driver": "local", "log-opts": { "max-size": "10m", "max-file": "3" } }' > /etc/docker/daemon.json
  systemctl restart docker
fi
# Note: Docker publishes ports past ufw. compose.yml only publishes 80 and 443.

echo "== Benutzer deploy und $ZIEL"
id deploy >/dev/null 2>&1 || useradd --create-home --shell /bin/bash deploy
# Membership in "docker" equals root rights on this server. The deploy key is therefore
# restricted to deploy.sh (see docs/ci-cd.md).
usermod -aG docker deploy
install -d -o deploy -g deploy -m 750 "$ZIEL" "$ZIEL/traefik"
install -o deploy -g deploy -m 640 "$QUELLE/compose.yml" "$ZIEL/compose.yml"
install -o deploy -g deploy -m 640 "$QUELLE/traefik/dynamic.yml" "$ZIEL/traefik/dynamic.yml"
install -o deploy -g deploy -m 750 "$QUELLE/deploy.sh" "$ZIEL/deploy.sh"
if [[ ! -f "$ZIEL/.env" ]]; then
  install -o deploy -g deploy -m 600 "$QUELLE/.env.example" "$ZIEL/.env"
  echo "   $ZIEL/.env angelegt: jetzt ausfüllen (DOMAIN, ACME_EMAIL, WEBSITE_IMAGE)."
fi
install -d -o deploy -g deploy -m 700 /home/deploy/.ssh
touch /home/deploy/.ssh/authorized_keys
chown deploy:deploy /home/deploy/.ssh/authorized_keys
chmod 600 /home/deploy/.ssh/authorized_keys

cat <<TEXT

Fertig. Nächste Schritte (Details in docs/server.md):
1. $ZIEL/.env ausfüllen.
2. Deploy-Schlüssel für GitHub eintragen, beschränkt auf deploy.sh:
   echo 'command="$ZIEL/deploy.sh",restrict ssh-ed25519 AAAA... github-deploy' >> /home/deploy/.ssh/authorized_keys
3. Falls das Image privat ist: als deploy einmal "docker login ghcr.io" mit einem Token (read:packages).
4. Erster Start: sudo -u deploy $ZIEL/deploy.sh ghcr.io/<owner>/<repo>/website:latest
TEXT
