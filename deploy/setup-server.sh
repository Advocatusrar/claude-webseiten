#!/usr/bin/env bash
# One-time hardening of a fresh Ubuntu 24.04 LTS server on Oracle Cloud (A1, aarch64).
# Copy it to the server and run it as the default user "ubuntu" (Oracle has no root login):
#   scp deploy/setup-server.sh ubuntu@SERVER:
#   ssh ubuntu@SERVER 'sudo bash setup-server.sh'
#
# What it does: system updates, automatic security updates with a reboot at 04:00
# (Europe/Berlin), SSH login only with keys and only for ${ADMIN_USER} and deploy,
# fail2ban for SSH, ports 22/80/443 in the iptables rules of the Oracle image (no UFW),
# SSH logs (journal and /var/log/auth.log) kept for 7 days, Docker from the official
# repository with log limits, and the user "deploy" (member of the group docker, empty
# authorized_keys).
# It does not set up the website; that follows with the layout for live and staging.
#
# Variables:
#   ADMIN_USER  user that keeps SSH access (default: ubuntu); needs a key in its
#               AuthorizedKeysFile (normally ~/.ssh/authorized_keys, home directory
#               from getent passwd), otherwise nothing is changed. When run with sudo,
#               it must be the user who called sudo (SUDO_USER), otherwise nothing is
#               changed either: AllowUsers would lock that user out.
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

# pkg_installed NAME: true if dpkg has the package installed. Checks only the state
# field of dpkg's status: "${Status}" is "WANT ERROR STATE", and WANT can be "hold" or
# "deinstall" for a package that is still installed.
pkg_installed() {
  local state
  state=$(dpkg-query -W -f='${db:Status-Status}' "$1" 2>/dev/null) || return 1
  [[ $state == installed ]]
}

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

# Temporary directory of this run, created on demand, removed on exit.
TMP_DIR=""
cleanup() { if [[ -n $TMP_DIR ]]; then rm -rf -- "$TMP_DIR"; fi; }
trap cleanup EXIT
ensure_tmp_dir() { [[ -n $TMP_DIR ]] || TMP_DIR=$(mktemp -d); }

# put_file PATH MODE, content on stdin. Writes only if content or mode differ.
# Returns 0 if the file was (or in a dry run would be) changed, 1 if it is unchanged,
# 2 if writing failed. It runs as an "if" condition, where set -e has no effect, so
# every step checks its own result. Call it through put, which stops on 2.
put_file() {
  local path=$1 mode=$2 content line cur_mode tmp
  content=$(cat) || return 2
  if [[ -f $path ]] && [[ "$(cat "$path" 2>/dev/null)" == "$content" ]]; then
    cur_mode=$(stat -c %a "$path") || return 2
    if [[ $cur_mode == "${mode#0}" ]]; then
      info "unverändert: $path"
      return 1
    fi
    run chmod "$mode" "$path" || return 2
    changed
    return 0
  fi
  changed
  if dry; then
    info "[Testlauf] würde $path schreiben (Modus $mode):"
    while IFS= read -r line; do printf '      | %s\n' "$line"; done <<<"$content"
    return 0
  fi
  tmp="$path.tmp.$$"
  install -d -m 0755 "$(dirname "$path")" || return 2
  printf '%s\n' "$content" >"$tmp" || { rm -f -- "$tmp"; return 2; }
  chmod "$mode" "$tmp" || { rm -f -- "$tmp"; return 2; }
  mv -f "$tmp" "$path" || { rm -f -- "$tmp"; return 2; }
  info "geschrieben: $path"
}

# put PATH MODE: put_file, but a failed write stops the script (also inside "if").
# Returns 0 if changed, 1 if unchanged.
put() {
  local rc=0
  put_file "$@" || rc=$?
  if ((rc >= 2)); then
    echo "Abbruch: $1 ließ sich nicht schreiben. Die bisherige Datei bleibt, wie sie war." >&2
    exit 1
  fi
  return "$rc"
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
ADMIN_OK=0
if [[ ! $ADMIN_USER =~ ^[a-z_][a-z0-9_-]*$ ]]; then
  precondition_failed "ADMIN_USER '$ADMIN_USER' ist kein gültiger Benutzername."
elif [[ $ADMIN_USER == root || $ADMIN_USER == "$DEPLOY_USER" ]]; then
  precondition_failed "ADMIN_USER darf nicht root oder $DEPLOY_USER sein (Root-Login wird gesperrt, $DEPLOY_USER ist für die CI)."
elif ! id "$ADMIN_USER" >/dev/null 2>&1; then
  precondition_failed "Benutzer $ADMIN_USER existiert nicht."
else
  ADMIN_OK=1
fi

# AllowUsers lets in only ADMIN_USER and deploy. Whoever called sudo must be one of
# them, otherwise the next SSH login of that user fails.
if [[ -n ${SUDO_USER:-} && $SUDO_USER != root && $SUDO_USER != "$ADMIN_USER" ]]; then
  precondition_failed "Du hast sudo als '$SUDO_USER' aufgerufen, SSH erlaubt danach aber nur '$ADMIN_USER' und $DEPLOY_USER. Damit sperrst du '$SUDO_USER' aus. Aufruf mit passendem Benutzer: sudo ADMIN_USER=$SUDO_USER bash setup-server.sh"
fi

# key_file_state FILE: prints "yes" if FILE holds at least one key line, "no" if not,
# "unknown" if it cannot be read. Without root (only possible in a dry run) the file
# may exist behind a directory that cannot be entered (e.g. /home/ubuntu with mode 750).
key_file_state() {
  local f=$1 d
  if [[ $EUID -ne 0 && ! -r $f ]]; then
    d=$(dirname "$f")
    while [[ $d != / && $d != . ]]; do
      if [[ -d $d && ! -x $d ]]; then
        echo unknown
        return 0
      fi
      d=$(dirname "$d")
    done
    if [[ -e $f ]]; then
      echo unknown
      return 0
    fi
  fi
  if [[ -s $f ]] && grep -qvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null; then
    echo yes
  else
    echo no
  fi
}

# Do not lock yourself out: only harden SSH if the admin user can log in with a key.
# The files come from AuthorizedKeysFile as sshd sees it for ADMIN_USER (sshd -T),
# relative to the real home directory from getent passwd.
if [[ $ADMIN_OK == 1 ]]; then
  ADMIN_HOME=$(getent passwd "$ADMIN_USER" | cut -d: -f6) || ADMIN_HOME=""
  if [[ $ADMIN_HOME != /* ]]; then
    precondition_failed "Home-Verzeichnis von $ADMIN_USER nicht ermittelbar (getent passwd $ADMIN_USER)."
  else
    AKF_DEFAULT=".ssh/authorized_keys .ssh/authorized_keys2"
    akf=""
    if sshd_eff=$(sshd -T -C "user=$ADMIN_USER,host=localhost,addr=127.0.0.1" 2>/dev/null); then
      akf=$(awk '$1 == "authorizedkeysfile" { $1 = ""; sub(/^ +/, ""); print }' <<<"$sshd_eff")
      if [[ -n "$(awk '$1 == "authorizedkeyscommand" && $2 != "none"' <<<"$sshd_eff")" ]]; then
        warn "sshd verwendet ein AuthorizedKeysCommand. Geprüft werden nur die Schlüsseldateien."
      fi
    fi
    if [[ -z $akf ]]; then
      if [[ $EUID -eq 0 ]]; then
        warn "AuthorizedKeysFile ließ sich nicht mit sshd -T ermitteln. Geprüft wird der Standard ~/.ssh/authorized_keys."
      fi
      akf=".ssh/authorized_keys"
    elif [[ $akf != "$AKF_DEFAULT" ]]; then
      warn "AuthorizedKeysFile ist nicht der Standard ($AKF_DEFAULT), sondern: $akf"
    fi
    ADMIN_KEY_FILES=()
    if [[ $akf != none ]]; then
      read -r -a akf_tokens <<<"$akf"
      for tok in "${akf_tokens[@]}"; do
        tok=${tok//%%/$'\x01'}
        tok=${tok//%h/$ADMIN_HOME}
        tok=${tok//%u/$ADMIN_USER}
        if [[ $tok == *%* ]]; then
          warn "AuthorizedKeysFile-Eintrag '$tok' enthält ein nicht unterstütztes %-Kürzel und wird nicht geprüft."
          continue
        fi
        tok=${tok//$'\x01'/%}
        [[ $tok == /* ]] || tok="$ADMIN_HOME/$tok"
        ADMIN_KEY_FILES+=("$tok")
      done
    fi
    key_found=0 key_unknown=0
    for f in "${ADMIN_KEY_FILES[@]}"; do
      case $(key_file_state "$f") in
        yes) key_found=1 ;;
        unknown) key_unknown=1 ;;
      esac
    done
    if ((${#ADMIN_KEY_FILES[@]} == 0)); then
      precondition_failed "sshd liest für $ADMIN_USER keine Schlüsseldatei (AuthorizedKeysFile: $akf). Sonst sperrst du dich aus."
    elif ((key_found == 0 && key_unknown == 1)); then
      warn "SSH-Schlüssel in ${ADMIN_KEY_FILES[*]} kann ohne root nicht geprüft werden (kein Zugriff). Ein echter Lauf mit sudo prüft ihn."
    elif ((key_found == 0)); then
      precondition_failed "Kein SSH-Schlüssel in ${ADMIN_KEY_FILES[*]}. Sonst sperrst du dich aus."
    fi
  fi
fi

# Docker's own packages conflict with the unofficial ones from Ubuntu.
for pkg in docker.io docker-compose docker-compose-v2 docker-doc podman-docker; do
  if pkg_installed "$pkg"; then
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
# full-upgrade: on a fresh server also take updates that add or remove packages
# (e.g. a new kernel package). Not interactive, see APT_OPTS.
run apt-get "${APT_OPTS[@]}" full-upgrade
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
put /etc/apt/apt.conf.d/20auto-upgrades 0644 <<'CONF' || true
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
CONF
# Own file instead of editing 50unattended-upgrades; later files override earlier ones.
# Reboot only if an update needs it (e.g. a new kernel), at 04:00 local time.
put /etc/apt/apt.conf.d/52unattended-upgrades-local 0644 <<'CONF' || true
// Managed by deploy/setup-server.sh
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
CONF

# ---------------------------------------------------------------------------
# 3. Firewall (iptables of the Oracle image, no UFW)
# ---------------------------------------------------------------------------
# Oracle's Ubuntu images ship iptables rules (/etc/iptables/rules.v4) that end INPUT
# with "REJECT --reject-with icmp-host-prohibited". New ACCEPT rules must go before it.
# The script only inserts rules and never deletes one (reason at allow_port).
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

# allow_port TOOL PORT: accept new TCP connections to PORT, before the REJECT rule.
# A rule only counts if it sits before the first REJECT; one behind it has no effect.
#
# The script never deletes or replaces firewall rules (no -D, no -R), it only inserts.
# iptables deletes and replaces by rule number, and other programs (fail2ban, Docker)
# may insert rules into INPUT at any time. Between reading the number and deleting,
# the number can then point to another rule, e.g. the REJECT, and the server would be
# open. A copy behind the REJECT therefore stays; the script only warns about it.
allow_port() {
  local tool=$1 port=$2 pos n before=0 after=0 open_note
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
    # Comes on every run as long as the copy is there; it is no change.
    # In a dry run a rule the script would insert is not there yet.
    if ((before == 0)) && dry; then
      open_note="der Port wäre durch die eingefügte Regel davor offen"
    else
      open_note="der Port ist durch die Regel davor offen"
    fi
    warn "$tool: Hinter der REJECT-Regel steht eine ACCEPT-Regel für Port $port. Sie ist wirkungslos ($open_note) und kann von Hand entfernt werden. Das Skript löscht keine Firewall-Regeln. Regelnummer anzeigen mit: sudo $tool -L INPUT --line-numbers -n (danach speichern: sudo netfilter-persistent save)"
  fi
}

# open_ports TOOL: open 22/80/443 if INPUT rejects (REJECT rule) or drops (policy not
# ACCEPT) other traffic; otherwise everything is open anyway.
open_ports() {
  local tool=$1 policy port
  DRY_SHIFT=0
  policy=$("$tool" -S INPUT | awk '$1 == "-P" { print $3 }')
  if [[ -n "$(reject_pos "$tool")" || $policy != ACCEPT ]]; then
    for port in 22 80 443; do allow_port "$tool" "$port"; done
  else
    info "$tool: keine REJECT-Regel in INPUT und Policy ACCEPT, keine Regel nötig"
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
  open_ports iptables
  # IPv6 like IPv4: REJECT rule (Oracle image) or policy DROP.
  if ip6tables -L INPUT -n >/dev/null 2>&1; then
    open_ports ip6tables
  else
    warn "ip6tables lässt sich nicht lesen, IPv6-Regeln bleiben unverändert."
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
# Restores the saved rules at boot. A dry run shows it as well; on a fresh server the
# package is only installed in step 1, so it is not enabled yet.
if ! systemctl is-enabled --quiet netfilter-persistent 2>/dev/null; then
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
SSHD_HAD_FILE=0
if [[ -f $SSHD_CONF ]] && ! dry; then
  # Exact copy, to put the old, working file back if the new one fails a check.
  SSHD_HAD_FILE=1
  ensure_tmp_dir
  cp -p -- "$SSHD_CONF" "$TMP_DIR/sshd.old"
fi
# restore_sshd_conf REASON: put the previous file back (or remove the new one), stop.
restore_sshd_conf() {
  local ok=1
  if [[ $SSHD_HAD_FILE == 1 ]]; then
    cp -p -- "$TMP_DIR/sshd.old" "$SSHD_CONF" || ok=0
  else
    rm -f -- "$SSHD_CONF" || ok=0
  fi
  if ((ok)); then
    echo "Abbruch: $1 $SSHD_CONF wurde zurückgesetzt, SSH nicht neu geladen." >&2
  else
    echo "Abbruch: $1 $SSHD_CONF ließ sich NICHT zurücksetzen. SSH wurde nicht neu geladen; die Datei vor dem nächsten Neustart von ssh von Hand prüfen!" >&2
  fi
  exit 1
}
if put "$SSHD_CONF" 0644 <<CONF; then
# Managed by deploy/setup-server.sh
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers ${ADMIN_USER} ${DEPLOY_USER}
CONF
  # With socket activation (default on 24.04) /run/sshd may be missing, then sshd -t fails.
  run install -d -m 0755 /run/sshd
  if ! dry; then
    sshd -t || restore_sshd_conf "sshd -t meldet einen Fehler."
    effective=$(sshd -T 2>/dev/null) || restore_sshd_conf "sshd -T meldet einen Fehler, die wirksame Konfiguration ist unbekannt."
    # Without ADMIN_USER in AllowUsers the next login fails: never reload like that.
    if ! grep -qx "allowusers $ADMIN_USER" <<<"$effective"; then
      allowed=$(awk '$1 == "allowusers" { printf "%s%s", sep, $2; sep = " " }' <<<"$effective")
      restore_sshd_conf "sshd würde $ADMIN_USER nicht einlassen (AllowUsers laut sshd -T: ${allowed:-kein Eintrag}; wird $SSHD_CONF überhaupt gelesen?)."
    fi
    for setting in "passwordauthentication no" "kbdinteractiveauthentication no" "permitrootlogin no"; do
      grep -qx "$setting" <<<"$effective" || warn "sshd verwendet nicht '$setting'. Eine andere Datei in /etc/ssh/sshd_config.d setzt den Wert vorher."
    done
  else
    info "[Testlauf] sshd -t, danach Prüfung mit sshd -T (AllowUsers enthält $ADMIN_USER)"
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
if put /etc/fail2ban/jail.local 0644 <<'CONF'; then
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
# 6. Log retention: 7 days
# ---------------------------------------------------------------------------
# The privacy policy (site/src/texte/datenschutz.md, "Schutz des Servers vor
# Angriffen") says: the server stores IP address, time and user name of SSH login
# attempts, the SSH logs are deleted after 7 days; fail2ban reads them, bans whoever
# fails 5 times within 10 minutes for 10 minutes, and deletes stored addresses after
# one day. Change these values only together with the privacy policy.
#
# fail2ban: the values are the package defaults of Ubuntu 24.04 (fail2ban 1.0.2,
# /etc/fail2ban/jail.conf: bantime = 10m, findtime = 10m, maxretry = 5;
# /etc/fail2ban/fail2ban.conf: dbpurgeage = 1d) and are deliberately not set in
# jail.local. fail2ban reads the journal (backend = systemd), not /var/log/auth.log.
#
# journald: MaxRetentionSec only deletes archived journal files (systemd 255,
# journal-vacuum.c), the file being written is archived after MaxFileSec, by default
# one month. Entries could then stay for a month. MaxFileSec=1day archives the file
# daily. An archived file is deleted once its first entry is older than
# MaxRetentionSec, but only when journald cleans up, which it does when it archives,
# that is about once a day. With 7day entries could therefore reach about 8 days;
# MaxRetentionSec=6day plus at most one day until the next cleanup keeps them at
# about 7 days at most, like "rotate 6" for /var/log/auth.log below.
#
# rsyslog: Ubuntu server and cloud images have it (priority important, recommended by
# ubuntu-minimal). journald forwards to it (/usr/lib/systemd/journald.conf.d/syslog.conf
# of the systemd package: ForwardToSyslog=yes), and /etc/rsyslog.d/50-default.conf
# writes auth and authpriv, among them the messages of sshd, to /var/log/auth.log.
# /etc/logrotate.d/rsyslog rotates that file weekly and keeps 4 old ones, about five
# weeks. Own file instead of editing /etc/logrotate.d/rsyslog: that is a conffile of
# the package, a change there makes dpkg ask about it on updates of rsyslog. logrotate
# reads /etc/logrotate.d in name order, so 00-auth-log comes before rsyslog. Its
# "ignoreduplicates" makes logrotate skip the later entry for /var/log/auth.log in
# /etc/logrotate.d/rsyslog without an error (logrotate 3.21, config.c); without it the
# duplicate entry would be an error. "daily" with "rotate 6": the current file plus 6
# old ones, so the oldest entries are 7 days old when deleted. "ifempty" keeps the
# daily rotation going on a day without entries; otherwise old files would stay longer.

step "Protokolle: Aufbewahrung 7 Tage"
if put /etc/systemd/journald.conf.d/10-aufbewahrung.conf 0644 <<'CONF'; then
# Managed by deploy/setup-server.sh
[Journal]
MaxRetentionSec=6day
MaxFileSec=1day
CONF
  run systemctl restart systemd-journald
fi
if pkg_installed rsyslog; then
  put /etc/logrotate.d/00-auth-log 0644 <<'CONF' || true
# Managed by deploy/setup-server.sh
/var/log/auth.log {
  daily
  rotate 6
  ifempty
  missingok
  compress
  delaycompress
  ignoreduplicates
  postrotate
    if [ -x /usr/lib/rsyslog/rsyslog-rotate ]; then /usr/lib/rsyslog/rsyslog-rotate; fi
  endscript
}
CONF
  if ! command -v logrotate >/dev/null 2>&1; then
    warn "rsyslog schreibt /var/log/auth.log, aber logrotate ist nicht installiert. Die Datei wird nicht nach 7 Tagen gelöscht: sudo apt-get install logrotate"
  fi
else
  info "rsyslog ist nicht installiert, es gibt kein /var/log/auth.log"
fi

# ---------------------------------------------------------------------------
# 7. Docker
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
# Signing key of the Docker apt repository and its fingerprint. Source of the
# fingerprint: Docker's official installation guide for Ubuntu in the repository
# docker/docs, file engine/install/ubuntu.md, e.g. commit be718ce24184 (2020-12-09):
# "Verify that you now have the key with the fingerprint 9DC8 5822 9FC7 DD38 854A
# E2D8 8D81 803C 0EBF CD88" (pub rsa4096 2017-02-22, "Docker Release (CE deb)").
# The current guide no longer prints it (removed with apt-key in commit 760bb64,
# 2021-03-02). The key served at DOCKER_KEY_URL on 2026-11-25 has this fingerprint.
DOCKER_KEY_URL=https://download.docker.com/linux/ubuntu/gpg
DOCKER_KEY_FPR=9DC858229FC7DD38854AE2D88D81803C0EBFCD88
DOCKER_KEY=/etc/apt/keyrings/docker.asc
if [[ -f $DAEMON_JSON ]] && [[ "$(cat "$DAEMON_JSON" 2>/dev/null)" != "$DAEMON_CONTENT" ]]; then
  # Someone changed it by hand: keep it, but check the important parts.
  info "$DAEMON_JSON existiert mit eigenem Inhalt und bleibt unverändert."
  if ! grep -q '"max-size"' "$DAEMON_JSON" || ! grep -q '"max-file"' "$DAEMON_JSON"; then
    warn "$DAEMON_JSON enthält keine Log-Grenzen (max-size, max-file)."
  fi
  if grep -q '"hosts"' "$DAEMON_JSON"; then
    warn "$DAEMON_JSON enthält einen hosts-Eintrag. Docker soll nicht über TCP erreichbar sein."
  fi
elif put "$DAEMON_JSON" 0644 <<<"$DAEMON_CONTENT"; then
  DAEMON_CHANGED=1
fi

if command -v docker >/dev/null 2>&1; then
  info "Docker ist schon installiert: $(docker --version 2>/dev/null || echo unbekannt)"
  if [[ $DAEMON_CHANGED == 1 ]]; then
    run systemctl restart docker
  fi
else
  # Repository as in https://docs.docker.com/engine/install/ubuntu/ (deb822 format).
  # The key is fetched to a temporary file and installed only if its fingerprint is the
  # one Docker publishes. Otherwise nothing is written and the script stops.
  if dry; then
    run curl -fsSL "$DOCKER_KEY_URL" -o "<temporäre Datei>"
    info "[Testlauf] würde den Fingerabdruck prüfen (erwartet: $DOCKER_KEY_FPR) und bei Abweichung abbrechen"
    run install -m 0755 -d /etc/apt/keyrings
    run install -m 0644 "<temporäre Datei>" "$DOCKER_KEY"
  else
    command -v gpg >/dev/null 2>&1 || { echo "Abbruch: gpg fehlt, der Docker-Schlüssel lässt sich nicht prüfen (Paket gnupg)." >&2; exit 1; }
    ensure_tmp_dir
    curl -fsSL "$DOCKER_KEY_URL" -o "$TMP_DIR/docker.asc" ||
      { echo "Abbruch: Docker-Schlüssel ließ sich nicht von $DOCKER_KEY_URL laden." >&2; exit 1; }
    # Fingerprints of the primary keys in the file; exactly one, the expected one.
    mkdir -m 0700 "$TMP_DIR/gnupg"
    key_fprs=$(GNUPGHOME="$TMP_DIR/gnupg" gpg --batch --quiet --with-colons --show-keys "$TMP_DIR/docker.asc" 2>/dev/null |
      awk -F: '$1 == "pub" { p = 1; next } p && $1 == "fpr" { print $10; p = 0 }') || key_fprs=""
    if [[ $key_fprs != "$DOCKER_KEY_FPR" ]]; then
      printf 'Abbruch: Der Docker-Schlüssel von %s hat nicht den erwarteten Fingerabdruck.\n  erwartet: %s\n  gefunden: %s\nNichts installiert. Fingerabdruck in der Docker-Dokumentation prüfen.\n' \
        "$DOCKER_KEY_URL" "$DOCKER_KEY_FPR" "${key_fprs:-keiner (keine gültige Schlüsseldatei)}" >&2
      exit 1
    fi
    info "Fingerabdruck des Docker-Schlüssels stimmt: $DOCKER_KEY_FPR"
    install -m 0755 -d /etc/apt/keyrings
    install -m 0644 "$TMP_DIR/docker.asc" "$DOCKER_KEY"
  fi
  arch=$(dpkg --print-architecture 2>/dev/null || echo arm64)
  put /etc/apt/sources.list.d/docker.sources 0644 <<SRC || true
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: ${OS_CODENAME:-noble}
Components: stable
Architectures: ${arch}
Signed-By: ${DOCKER_KEY}
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
# 8. User deploy
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
# 9. Result and acceptance checks
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
