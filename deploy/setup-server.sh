#!/usr/bin/env bash
# One-time hardening of a fresh Ubuntu 24.04 LTS server on Oracle Cloud (A1, aarch64).
# Copy it to the server and run it as the default user "ubuntu" (Oracle has no root login):
#   scp deploy/setup-server.sh ubuntu@SERVER:
#   ssh ubuntu@SERVER 'sudo bash setup-server.sh'
#
# What it does: system updates, automatic security updates with a reboot at 04:00
# (Europe/Berlin), SSH login only with keys and only for ${ADMIN_USER} and deploy,
# fail2ban for SSH, ports 22/80/443 in the iptables rules of the Oracle image (no UFW),
# Docker from the official repository with log limits, and the user "deploy" (member of
# the group docker, empty authorized_keys).
# It does not set up the website; that follows with the layout for live and staging.
#
# Variables:
#   ADMIN_USER  user that keeps SSH access (default: ubuntu); needs a key in
#               /home/${ADMIN_USER}/.ssh/authorized_keys, otherwise nothing is changed.
#   DRY_RUN=1   only print what would be done; changes nothing and needs no root.
#
# It is idempotent: a second run changes nothing and does not fail.
set -euo pipefail

ADMIN_USER="${ADMIN_USER:-ubuntu}"
DRY_RUN="${DRY_RUN:-0}"
DEPLOY_USER=deploy
CHANGES=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

dry() { [[ $DRY_RUN == 1 ]]; }
step() { printf '\n== %s\n' "$*"; }
info() { printf '   %s\n' "$*"; }
warn() { printf '   WARNUNG: %s\n' "$*" >&2; }
changed() { CHANGES=$((CHANGES + 1)); }

# Run a command that changes the system, or only print it in a dry run.
run() {
  if dry; then
    printf '   [Testlauf]'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

# put_file PATH MODE, content on stdin. Writes only if content or mode differ.
# Returns 0 if the file was (or in a dry run would be) changed, 1 if it is unchanged.
put_file() {
  local path=$1 mode=$2 content line
  content=$(cat)
  if [[ -f $path ]] && [[ "$(cat "$path" 2>/dev/null)" == "$content" ]]; then
    if [[ "$(stat -c %a "$path")" == "${mode#0}" ]]; then
      info "unverändert: $path"
      return 1
    fi
    run chmod "$mode" "$path"
    changed
    return 0
  fi
  changed
  if dry; then
    info "[Testlauf] würde $path schreiben (Modus $mode):"
    while IFS= read -r line; do printf '      | %s\n' "$line"; done <<<"$content"
    return 0
  fi
  install -d -m 0755 "$(dirname "$path")"
  printf '%s\n' "$content" >"$path.tmp.$$"
  chmod "$mode" "$path.tmp.$$"
  mv -f "$path.tmp.$$" "$path"
  info "geschrieben: $path"
}

# Precondition failed: stop before any change. A dry run only reports it.
PRE_FAILED=0
precondition_failed() {
  if dry; then
    printf '   [Testlauf] Ein echter Lauf würde hier abbrechen: %s\n' "$*" >&2
    PRE_FAILED=1
  else
    printf 'Abbruch, nichts geändert: %s\n' "$*" >&2
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# 0. Checks. Nothing is changed before all of them have passed.
# ---------------------------------------------------------------------------

step "Prüfungen"
[[ $DRY_RUN == 0 || $DRY_RUN == 1 ]] || { echo "DRY_RUN muss 0 oder 1 sein." >&2; exit 1; }
dry && info "Testlauf (DRY_RUN=1): es wird nichts geändert."

[[ $EUID -eq 0 ]] || precondition_failed "Bitte mit sudo als root ausführen: sudo bash setup-server.sh"

OS_ID=unknown OS_VERSION=unknown OS_CODENAME=""
if [[ -r /etc/os-release ]]; then
  # shellcheck source=/dev/null
  . /etc/os-release
  OS_ID="${ID:-unknown}"
  OS_VERSION="${VERSION_ID:-unknown}"
  OS_CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"
fi
if [[ $OS_ID != ubuntu ]]; then
  precondition_failed "Nur Ubuntu wird unterstützt (gefunden: $OS_ID)."
elif [[ $OS_VERSION != 24.04 ]]; then
  warn "Geschrieben für Ubuntu 24.04 LTS, gefunden: $OS_VERSION. Paket- und Dienstnamen können abweichen."
fi
[[ "$(uname -m)" == aarch64 ]] || warn "Geschrieben für Oracle A1 (aarch64), gefunden: $(uname -m)."

# The user name ends up in sshd_config, so allow only plain user names.
if [[ ! $ADMIN_USER =~ ^[a-z_][a-z0-9_-]*$ ]]; then
  precondition_failed "ADMIN_USER '$ADMIN_USER' ist kein gültiger Benutzername."
elif [[ $ADMIN_USER == root || $ADMIN_USER == "$DEPLOY_USER" ]]; then
  precondition_failed "ADMIN_USER darf nicht root oder $DEPLOY_USER sein (Root-Login wird gesperrt, $DEPLOY_USER ist für die CI)."
elif ! id "$ADMIN_USER" >/dev/null 2>&1; then
  precondition_failed "Benutzer $ADMIN_USER existiert nicht."
fi

# Do not lock yourself out: only harden SSH if the admin user can log in with a key.
ADMIN_KEYS="/home/${ADMIN_USER}/.ssh/authorized_keys"
# Without root (only possible in a dry run) the file may exist behind a directory
# that cannot be entered (e.g. /home/ubuntu with mode 750). Then it is unknown.
keys_checkable() {
  local home="/home/${ADMIN_USER}"
  [[ $EUID -eq 0 || -r $ADMIN_KEYS ]] && return 0
  [[ -x $home ]] || return 1
  [[ -d $home/.ssh ]] || return 0
  [[ -x $home/.ssh ]] || return 1
  [[ ! -e $ADMIN_KEYS ]]
}
if ! keys_checkable; then
  warn "SSH-Schlüssel in $ADMIN_KEYS kann ohne root nicht geprüft werden (kein Zugriff). Ein echter Lauf mit sudo prüft ihn."
elif [[ ! -s $ADMIN_KEYS ]] || ! grep -qvE '^[[:space:]]*(#|$)' "$ADMIN_KEYS" 2>/dev/null; then
  precondition_failed "Kein SSH-Schlüssel in $ADMIN_KEYS. Sonst sperrst du dich aus."
fi

# Docker's own packages conflict with the unofficial ones from Ubuntu.
for pkg in docker.io docker-compose docker-compose-v2 docker-doc podman-docker; do
  if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep 'install ok installed' >/dev/null; then
    precondition_failed "Paket $pkg ist installiert und kollidiert mit Docker aus dem offiziellen Repository. Erst entfernen: sudo apt-get remove $pkg"
  fi
done

if [[ $PRE_FAILED == 0 ]]; then
  info "in Ordnung: root, Ubuntu $OS_VERSION, Schlüssel für $ADMIN_USER vorhanden"
fi

# ---------------------------------------------------------------------------
# 1. System updates and packages
# ---------------------------------------------------------------------------

step "System aktualisieren und Pakete installieren"
export DEBIAN_FRONTEND=noninteractive
# needrestart only lists services instead of asking or restarting them.
export NEEDRESTART_MODE=l
APT_OPTS=(-y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)

# Answer the questions of iptables-persistent in advance: save the current rules
# (the Oracle image rules) on installation.
if dry; then
  info "[Testlauf] debconf-set-selections: iptables-persistent/autosave_v4 und autosave_v6 = true"
else
  debconf-set-selections <<'SEL'
iptables-persistent iptables-persistent/autosave_v4 boolean true
iptables-persistent iptables-persistent/autosave_v6 boolean true
SEL
fi
run apt-get update -q
run apt-get "${APT_OPTS[@]}" upgrade
run apt-get "${APT_OPTS[@]}" install ca-certificates curl gnupg unattended-upgrades \
  fail2ban iptables iptables-persistent netfilter-persistent

# ---------------------------------------------------------------------------
# 2. Time zone and automatic updates
# ---------------------------------------------------------------------------

step "Zeitzone Europe/Berlin"
current_tz=$(timedatectl show -p Timezone --value 2>/dev/null || echo unbekannt)
if [[ $current_tz == Europe/Berlin ]]; then
  info "unverändert: Europe/Berlin"
else
  info "bisher: $current_tz"
  run timedatectl set-timezone Europe/Berlin
  changed
fi

step "Automatische Updates mit Neustart um 04:00"
put_file /etc/apt/apt.conf.d/20auto-upgrades 0644 <<'CONF' || true
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
CONF
# Own file instead of editing 50unattended-upgrades; later files override earlier ones.
# Reboot only if an update needs it (e.g. a new kernel), at 04:00 local time.
put_file /etc/apt/apt.conf.d/52unattended-upgrades-local 0644 <<'CONF' || true
// Managed by deploy/setup-server.sh
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
CONF

# ---------------------------------------------------------------------------
# 3. Firewall (iptables of the Oracle image, no UFW)
# ---------------------------------------------------------------------------
# Oracle's Ubuntu images ship iptables rules (/etc/iptables/rules.v4) that end INPUT
# with "REJECT --reject-with icmp-host-prohibited". New ACCEPT rules must go before it.
# UFW is not used: it manages the same INPUT chain and would conflict with these rules.
#
# Docker bypasses the INPUT chain for published container ports (DNAT, then FORWARD).
# Therefore only Traefik publishes ports (80 and 443). Own rules for containers belong
# in the DOCKER-USER chain, not in INPUT.
#
# Ports are also filtered outside the server by the Security List or Network Security
# Group of the VCN in the Oracle Console; 80 and 443 must be allowed there as well.

step "Firewall: Ports 22, 80 und 443"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep '^Status: active' >/dev/null; then
  warn "UFW ist aktiv. Das Skript fasst UFW nicht an, aber UFW und die Oracle-Regeln vertragen sich nicht. Prüfe, ob du UFW wirklich brauchst."
fi

FW_CHANGED=0
DRY_SHIFT=0
DRY_DELETED=()

# Line number of the first REJECT rule in INPUT, empty if there is none.
reject_pos() {
  "$1" -L INPUT --line-numbers -n | awk 'NR > 2 && $2 == "REJECT" && !found { print $1; found = 1 }'
}

# rule_numbers TOOL RULE...: numbers of the rules in INPUT that equal RULE exactly.
rule_numbers() {
  local tool=$1
  shift
  "$tool" -S INPUT | awk -v want="-A INPUT $*" '$1 == "-A" { n++; if ($0 == want) print n }'
}

# remove_behind_reject TOOL PORT RULE...: delete exact copies of RULE that sit behind
# the first REJECT in INPUT. They have no effect (typical after "iptables -A" on Oracle).
# Called only once an effective copy sits before the REJECT.
remove_behind_reject() {
  local tool=$1 port=$2 pos n d shown
  shift 2
  pos=$(reject_pos "$tool")
  [[ -n $pos ]] || return 0
  # Highest number first, so the lower numbers stay valid.
  for n in $(rule_numbers "$tool" "$@" | sort -rn); do
    ((n > pos)) || continue
    shown=$n
    if dry; then
      # Nothing was inserted or deleted, so shift the number like a real run would.
      shown=$((n + DRY_SHIFT))
      for d in "${DRY_DELETED[@]}"; do
        if ((d < n)); then shown=$((shown - 1)); fi
      done
      DRY_DELETED+=("$n")
    fi
    run "$tool" -D INPUT "$shown"
    if dry; then
      info "[Testlauf] $tool: würde die wirkungslose ACCEPT-Regel für Port $port hinter REJECT entfernen"
    else
      warn "$tool: wirkungslose ACCEPT-Regel für Port $port hinter REJECT entfernt (war Regel $shown)"
    fi
    FW_CHANGED=1
    changed
  done
}

# allow_port TOOL PORT: accept new TCP connections to PORT, before the REJECT rule.
# A rule only counts if it sits before the first REJECT; one behind it has no effect
# and is removed once an effective one is in place.
allow_port() {
  local tool=$1 port=$2 pos n before=0 after=0
  local rule=(-p tcp -m state --state NEW -m tcp --dport "$port" -j ACCEPT)
  pos=$(reject_pos "$tool")
  if "$tool" -C INPUT "${rule[@]}" 2>/dev/null; then
    if [[ -z $pos ]]; then
      info "$tool: Port $port ist schon offen"
      return
    fi
    for n in $(rule_numbers "$tool" "${rule[@]}"); do
      if ((n < pos)); then before=1; else after=1; fi
    done
    if ((before == 0 && after == 0)); then
      # -C finds the rule, but iptables -S prints it differently: do not guess.
      warn "$tool: Position der ACCEPT-Regel für Port $port nicht ermittelbar, nichts geändert. Prüfen mit: sudo $tool -L INPUT --line-numbers -n"
      return
    fi
  fi
  if ((before == 1)); then
    info "$tool: Port $port ist schon offen"
  else
    if [[ -n $pos ]]; then
      # In a dry run nothing is inserted, so count the rules that would be.
      run "$tool" -I INPUT "$((pos + DRY_SHIFT))" "${rule[@]}"
    else
      run "$tool" -A INPUT "${rule[@]}"
    fi
    dry && DRY_SHIFT=$((DRY_SHIFT + 1))
    FW_CHANGED=1
    changed
  fi
  if ((after == 1)); then
    remove_behind_reject "$tool" "$port" "${rule[@]}"
  fi
}

if ! iptables -L INPUT -n >/dev/null 2>&1; then
  if dry; then
    info "[Testlauf] iptables nicht lesbar (kein root). Ein echter Lauf ermittelt die REJECT-Regel in INPUT und fügt davor ACCEPT für tcp 22, 80, 443 ein, falls sie fehlen."
  else
    echo "Abbruch: iptables lässt sich nicht lesen." >&2
    exit 1
  fi
else
  DRY_SHIFT=0
  DRY_DELETED=()
  policy=$(iptables -S INPUT | awk '$1 == "-P" { print $3 }')
  if [[ -n "$(reject_pos iptables)" || $policy != ACCEPT ]]; then
    for port in 22 80 443; do allow_port iptables "$port"; done
  else
    info "iptables: keine REJECT-Regel in INPUT und Policy ACCEPT, keine Regel nötig"
  fi
  # IPv6 only if the image rejects there as well.
  DRY_SHIFT=0
  DRY_DELETED=()
  if ip6tables -L INPUT -n >/dev/null 2>&1 && [[ -n "$(reject_pos ip6tables)" ]]; then
    for port in 22 80 443; do allow_port ip6tables "$port"; done
  else
    info "ip6tables: keine REJECT-Regel in INPUT, nichts zu tun"
  fi
fi

if [[ $FW_CHANGED == 1 ]]; then
  # Save only after a change, so a second run does not write the rules file again.
  # On a fresh server this runs before Docker and fail2ban add their own chains.
  if iptables -S 2>/dev/null | grep -E '^-N (DOCKER|f2b-)' >/dev/null; then
    warn "Docker- oder fail2ban-Ketten sind aktiv und werden mitgespeichert. Prüfe danach /etc/iptables/rules.v4."
  fi
  run netfilter-persistent save
fi
if ! dry && ! systemctl is-enabled --quiet netfilter-persistent 2>/dev/null; then
  run systemctl enable netfilter-persistent
  changed
fi

# ---------------------------------------------------------------------------
# 4. SSH
# ---------------------------------------------------------------------------

step "SSH: nur Schlüssel, kein root, nur $ADMIN_USER und $DEPLOY_USER"
SSHD_CONF=/etc/ssh/sshd_config.d/10-haertung.conf
# sshd uses the first value it reads; files in sshd_config.d are read in name order
# before the rest of sshd_config, so "10-" wins over 50-cloud-init.conf and others.
SSHD_OLD=""
SSHD_HAD_FILE=0
if [[ -f $SSHD_CONF ]]; then
  SSHD_HAD_FILE=1
  SSHD_OLD=$(cat "$SSHD_CONF" 2>/dev/null || true)
fi
if put_file "$SSHD_CONF" 0644 <<CONF; then
# Managed by deploy/setup-server.sh
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers ${ADMIN_USER} ${DEPLOY_USER}
CONF
  # With socket activation (default on 24.04) /run/sshd may be missing, then sshd -t fails.
  run install -d -m 0755 /run/sshd
  if ! dry; then
    if ! sshd -t; then
      # Leave the old, working configuration in place.
      if [[ $SSHD_HAD_FILE == 1 ]]; then
        printf '%s\n' "$SSHD_OLD" >"$SSHD_CONF"
      else
        rm -f "$SSHD_CONF"
      fi
      echo "Abbruch: sshd -t meldet einen Fehler. $SSHD_CONF wurde zurückgesetzt, SSH nicht neu geladen." >&2
      exit 1
    fi
    effective=$(sshd -T 2>/dev/null || true)
    for setting in "passwordauthentication no" "kbdinteractiveauthentication no" "permitrootlogin no"; do
      grep -qx "$setting" <<<"$effective" || warn "sshd verwendet nicht '$setting'. Eine andere Datei in /etc/ssh/sshd_config.d setzt den Wert vorher."
    done
  else
    info "[Testlauf] sshd -t"
  fi
  cat <<'TEXT'

   ################################################################
   #  WICHTIG: SSH wird jetzt neu geladen.                        #
   #  Login in einem zweiten Fenster testen, bevor du dieses      #
   #  schließt. Die laufende Verbindung bleibt bestehen.          #
   ################################################################

TEXT
  if dry || systemctl is-active --quiet ssh; then
    run systemctl reload ssh
  else
    info "ssh.service läuft gerade nicht (Socket-Aktivierung); die Einstellungen gelten beim nächsten Start."
  fi
fi

# ---------------------------------------------------------------------------
# 5. fail2ban
# ---------------------------------------------------------------------------

step "fail2ban für SSH"
# Ubuntu 24.04 sets banaction = nftables in jail.d/defaults-debian.conf. Docker does not
# support rules created with nft next to its own, so fail2ban uses iptables here.
if put_file /etc/fail2ban/jail.local 0644 <<'CONF'; then
# Managed by deploy/setup-server.sh
[sshd]
enabled = true
backend = systemd
port = ssh
banaction = iptables-multiport
banaction_allports = iptables-allports
CONF
  if ! dry; then
    fail2ban-client -t >/dev/null || { echo "Abbruch: fail2ban-client -t meldet einen Fehler in /etc/fail2ban/jail.local." >&2; exit 1; }
  fi
  run systemctl restart fail2ban
fi
if dry || ! systemctl is-enabled --quiet fail2ban || ! systemctl is-active --quiet fail2ban; then
  run systemctl enable --now fail2ban
fi

# ---------------------------------------------------------------------------
# 6. Docker
# ---------------------------------------------------------------------------

step "Docker"
# Limit container logs so the disk does not fill up. No "hosts" entry: Docker only
# listens on its Unix socket. Written before the installation, so Docker starts with it.
DAEMON_JSON=/etc/docker/daemon.json
DAEMON_CONTENT='{
  "log-driver": "local",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}'
DAEMON_CHANGED=0
if [[ -f $DAEMON_JSON ]] && [[ "$(cat "$DAEMON_JSON" 2>/dev/null)" != "$DAEMON_CONTENT" ]]; then
  # Someone changed it by hand: keep it, but check the important parts.
  info "$DAEMON_JSON existiert mit eigenem Inhalt und bleibt unverändert."
  if ! grep -q '"max-size"' "$DAEMON_JSON" || ! grep -q '"max-file"' "$DAEMON_JSON"; then
    warn "$DAEMON_JSON enthält keine Log-Grenzen (max-size, max-file)."
  fi
  if grep -q '"hosts"' "$DAEMON_JSON"; then
    warn "$DAEMON_JSON enthält einen hosts-Eintrag. Docker soll nicht über TCP erreichbar sein."
  fi
elif put_file "$DAEMON_JSON" 0644 <<<"$DAEMON_CONTENT"; then
  DAEMON_CHANGED=1
fi

if command -v docker >/dev/null 2>&1; then
  info "Docker ist schon installiert: $(docker --version 2>/dev/null || echo unbekannt)"
  if [[ $DAEMON_CHANGED == 1 ]]; then
    run systemctl restart docker
  fi
else
  # Repository as in https://docs.docker.com/engine/install/ubuntu/ (deb822 format).
  run install -m 0755 -d /etc/apt/keyrings
  run curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  run chmod a+r /etc/apt/keyrings/docker.asc
  arch=$(dpkg --print-architecture 2>/dev/null || echo arm64)
  put_file /etc/apt/sources.list.d/docker.sources 0644 <<SRC || true
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: ${OS_CODENAME:-noble}
Components: stable
Architectures: ${arch}
Signed-By: /etc/apt/keyrings/docker.asc
SRC
  run apt-get update -q
  run apt-get "${APT_OPTS[@]}" install docker-ce docker-ce-cli containerd.io docker-compose-plugin
  changed
fi
if dry || ! systemctl is-enabled --quiet docker || ! systemctl is-active --quiet docker; then
  run systemctl enable --now docker
fi

# The Docker API over TCP equals root access without a password: warn if it is set up.
if ! dry; then
  if systemctl cat docker.service 2>/dev/null | grep -E '^[[:space:]]*ExecStart=.*(-H|--host)[[:space:]=]*tcp://' >/dev/null; then
    warn "In der systemd-Unit von Docker steht ein '-H tcp://'. Docker ist damit über das Netz erreichbar. Entfernen!"
  fi
  if ss -Hltn 2>/dev/null | awk '{ print $4 }' | grep -E ':(2375|2376)$' >/dev/null; then
    warn "Auf Port 2375 oder 2376 lauscht ein Dienst (Docker-API über TCP?)."
  fi
fi

# ---------------------------------------------------------------------------
# 7. User deploy
# ---------------------------------------------------------------------------

step "Benutzer $DEPLOY_USER"
if id "$DEPLOY_USER" >/dev/null 2>&1; then
  info "unverändert: Benutzer $DEPLOY_USER existiert"
else
  # Without a password: login only with a key, which the CI gets later.
  run useradd --create-home --shell /bin/bash "$DEPLOY_USER"
  changed
fi
# Membership in "docker" equals root rights on this server. The deploy key is therefore
# restricted to one command (command="...",restrict, see docs/server.md).
if id -nG "$DEPLOY_USER" 2>/dev/null | tr ' ' '\n' | grep -x docker >/dev/null; then
  info "unverändert: $DEPLOY_USER ist in der Gruppe docker"
else
  run usermod -aG docker "$DEPLOY_USER"
  changed
fi
DEPLOY_SSH="/home/$DEPLOY_USER/.ssh"
if [[ -f $DEPLOY_SSH/authorized_keys ]]; then
  info "unverändert: $DEPLOY_SSH/authorized_keys existiert (Inhalt bleibt erhalten)"
else
  run install -d -o "$DEPLOY_USER" -g "$DEPLOY_USER" -m 700 "$DEPLOY_SSH"
  run install -o "$DEPLOY_USER" -g "$DEPLOY_USER" -m 600 /dev/null "$DEPLOY_SSH/authorized_keys"
  changed
fi

# ---------------------------------------------------------------------------
# 8. Result and acceptance checks
# ---------------------------------------------------------------------------

step "Fertig"
if dry; then
  info "Testlauf beendet, nichts wurde geändert. Ein echter Lauf hätte $CHANGES Änderung(en) vorgenommen (ohne Paket-Updates)."
else
  info "Änderungen in diesem Lauf: $CHANGES (ohne Paket-Updates). Ein zweiter Lauf sollte 0 melden."
fi
if [[ -f /var/run/reboot-required ]]; then
  info "Ein Neustart ist nötig (z. B. neuer Kernel): sudo reboot, oder automatisch um 04:00."
fi

cat <<TEXT

Abnahme: bitte prüfen und das Ergebnis melden.

Auf dem Server (als $ADMIN_USER):
1. sudo docker run --rm hello-world
   Erwartung: "Hello from Docker!"
2. sudo fail2ban-client status sshd
   Erwartung: Jail sshd mit "Currently failed" und "Currently banned".

Auf deinem eigenen Rechner (<ip> = öffentliche IP des Servers):
3. Login in einem zweiten Fenster: ssh $ADMIN_USER@<ip>
   Erwartung: klappt mit deinem Schlüssel.
4. ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password $ADMIN_USER@<ip>
   Erwartung: "Permission denied (publickey)", keine Passwortabfrage.
5. curl -I http://<ip>
   Erwartung: sofort "Connection refused" (noch kein Webserver).
   Ein Timeout heißt: eine Firewall blockt Port 80, auf dem Server oder in der
   Security List bzw. Network Security Group des VCN in der Oracle Console.
TEXT
