#!/usr/bin/env bash
# One-time hardening of a fresh Ubuntu 24.04 LTS server on Oracle Cloud (A1, aarch64).
# Copy it to the server and run it as the default user "ubuntu" (Oracle has no root login):
#   scp deploy/setup-server.sh ubuntu@SERVER:
#   ssh ubuntu@SERVER 'sudo bash setup-server.sh'
#
# What it does: system updates, automatic security updates with a reboot at 04:00
# (Europe/Berlin), SSH login only with keys and only for ${ADMIN_USER} and deploy,
# fail2ban for SSH, ports 22/80/443 in the iptables rules of the Oracle image (no UFW),
# logs with IP addresses (journal, /var/log/auth.log, btmp, wtmp, fail2ban.log) kept for
# about 7 days, Docker from the official repository with log limits, and the user
# "deploy" (member of the group docker, empty authorized_keys).
# It does not set up the website; that follows with the layout for live and staging.
#
# Variables:
#   ADMIN_USER  user that keeps SSH access (default: ubuntu); needs a key in its
#               AuthorizedKeysFile (normally ~/.ssh/authorized_keys, home directory
#               from getent passwd), otherwise nothing is changed. When run with sudo,
#               it must be the user who called sudo (SUDO_USER) and the user who logged
#               in (audit login UID, /proc/self/loginuid), otherwise nothing is changed
#               either: AllowUsers would lock that user out.
#   DRY_RUN=1   only print what would be done; changes nothing and needs no root.
#
# It is idempotent: a second run changes nothing and does not fail.
set -euo pipefail

ADMIN_USER="${ADMIN_USER:-ubuntu}"
DRY_RUN="${DRY_RUN:-0}"
DEPLOY_USER=deploy
CHANGES=0
# Drop-in of this script; sshd reads it before 50-cloud-init.conf and the like (step 4).
SSHD_CONF=/etc/ssh/sshd_config.d/10-haertung.conf
# Connection that sshd -T -C evaluates Match blocks for (used once ADMIN_USER is checked).
SSHD_TEST_SPEC="user=$ADMIN_USER,host=localhost,addr=127.0.0.1"
# The same for the user deploy of the CI (only warnings, see check_sshd_deploy).
SSHD_DEPLOY_SPEC="user=$DEPLOY_USER,host=localhost,addr=127.0.0.1"

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

# sshd_candidates KEYWORD: config files that mention KEYWORD (case-insensitive), apart
# from the drop-in of this script. Only a hint for the abort message.
sshd_candidates() {
  local f found=()
  for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
    [[ -f $f && $f != "$SSHD_CONF" ]] || continue
    if grep -qiE "^[[:space:]]*$1([[:space:]]|=)" "$f" 2>/dev/null; then found+=("$f"); fi
  done
  if ((${#found[@]} > 0)); then printf '%s' "${found[*]}"; else printf 'keine gefunden'; fi
}
# sshd_auth_problem VIEW OUTPUT: OUTPUT is what sshd -T (as VIEW) prints. Prints why a
# login with a key alone would fail once PasswordAuthentication and
# KbdInteractiveAuthentication are off, nothing if it works: PubkeyAuthentication must
# be yes, and AuthenticationMethods "any" or at least one of its lists made up only of
# "publickey" (a list like "publickey,password" also needs a password).
sshd_auth_problem() {
  local view=$1 eff=$2 pub methods list m only_key
  local -a lists items
  pub=$(awk '$1 == "pubkeyauthentication" { print $2; exit }' <<<"$eff")
  if [[ $pub != yes ]]; then
    printf '%s' "sshd erlaubt keine Anmeldung mit Schlüssel (PubkeyAuthentication laut $view: ${pub:-kein Eintrag}). Dateien mit PubkeyAuthentication: $(sshd_candidates pubkeyauthentication)."
    return 0
  fi
  methods=$(awk '$1 == "authenticationmethods" { $1 = ""; sub(/^ +/, ""); print; exit }' <<<"$eff")
  [[ $methods == any ]] && return 0
  read -r -a lists <<<"$methods"
  for list in "${lists[@]}"; do
    IFS=, read -r -a items <<<"$list"
    only_key=1
    for m in "${items[@]}"; do [[ $m == publickey ]] || only_key=0; done
    ((only_key)) && return 0
  done
  printf '%s' "AuthenticationMethods verlangt außer dem Schlüssel ein weiteres Verfahren (laut $view: ${methods:-kein Eintrag}), ohne password und keyboard-interactive ist keine der Listen erfüllbar. Dateien mit AuthenticationMethods: $(sshd_candidates authenticationmethods)."
}

# fw_state TOOL: prints "POLICY FINAL" for the chain INPUT of TOOL (iptables or
# ip6tables): its policy, and 1 if it has an unconditional REJECT or DROP rule
# ("-A INPUT -j REJECT ..." or "-A INPUT -j DROP", like the last rule of the Oracle
# image), else 0. Fails if the rules cannot be read.
fw_state() {
  local rules
  rules=$("$1" -S INPUT 2>/dev/null) || return 1
  awk '$1 == "-P" { p = $3 }
       $1 == "-A" && $3 == "-j" && ($4 == "REJECT" || ($4 == "DROP" && NF == 4)) { f = 1 }
       END { printf "%s %d\n", p, f }' <<<"$rules"
}

# ---------------------------------------------------------------------------
# 0. Checks. Nothing is changed before all of them have passed, except the runtime
#    directory /run/sshd (see below).
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

# AllowUsers lets in only ADMIN_USER and deploy. Whoever called sudo must be ADMIN_USER,
# otherwise the next SSH login of that user fails.
lockout_failed() { # USER
  precondition_failed "Du hast sudo als '$1' aufgerufen, SSH erlaubt danach aber nur '$ADMIN_USER' und $DEPLOY_USER. Damit sperrst du '$1' aus. Aufruf mit passendem Benutzer: sudo ADMIN_USER=$1 bash setup-server.sh"
}
if [[ -n ${SUDO_USER:-} && $SUDO_USER != root && $SUDO_USER != "$ADMIN_USER" ]]; then
  lockout_failed "$SUDO_USER"
else
  # SUDO_USER is root or missing after "sudo -i", "sudo su" or a root shell. The audit
  # login UID still names the user who logged in (set by pam_loginuid at login, kept
  # by sudo and su); 4294967295 means not set (e.g. started by a service).
  login_uid=""
  if [[ -r /proc/self/loginuid ]]; then
    login_uid=$(</proc/self/loginuid) || login_uid=""
  fi
  if [[ $login_uid =~ ^[0-9]+$ && $login_uid != 4294967295 && $login_uid != 0 ]]; then
    login_user=$(getent passwd "$login_uid" | cut -d: -f1) || login_user=""
    if [[ -z $login_user ]]; then
      precondition_failed "Du bist mit der UID $login_uid angemeldet (Audit-Login-UID, /proc/self/loginuid), zu der es keinen Benutzer gibt. SSH erlaubt danach nur '$ADMIN_USER' und $DEPLOY_USER. Bitte als $ADMIN_USER anmelden und das Skript mit sudo starten."
    elif [[ $login_user != "$ADMIN_USER" ]]; then
      lockout_failed "$login_user"
    fi
  fi
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
    # sshd -T and -t fail without the privilege separation directory /run/sshd. With
    # socket activation (default on 24.04) it only exists while ssh.service has run.
    # It lies on tmpfs and sshd creates it at every start (RuntimeDirectory of
    # ssh.service), so creating it here changes nothing that lasts.
    if [[ ! -d /run/sshd ]]; then
      run install -d -m 0755 /run/sshd || precondition_failed "/run/sshd ließ sich nicht anlegen (nötig für sshd -T)."
    fi
    akf=""
    sshd_eff=""
    if sshd_eff=$(sshd -T -C "$SSHD_TEST_SPEC" 2>&1); then
      akf=$(awk '$1 == "authorizedkeysfile" { $1 = ""; sub(/^ +/, ""); print }' <<<"$sshd_eff")
      if [[ -n "$(awk '$1 == "authorizedkeyscommand" && $2 != "none"' <<<"$sshd_eff")" ]]; then
        warn "sshd verwendet ein AuthorizedKeysCommand. Geprüft werden nur die Schlüsseldateien."
      fi
      # The hardening turns passwords off. If the current configuration needs more than
      # a key (PubkeyAuthentication no, AuthenticationMethods publickey,password), the
      # admin would be locked out afterwards: stop now, before any change, instead of
      # only after writing the drop-in. Globally and for ADMIN_USER after Match blocks.
      auth_problem=$(sshd_auth_problem "sshd -T -C $SSHD_TEST_SPEC" "$sshd_eff")
      if [[ -z $auth_problem ]]; then
        if sshd_glob=$(sshd -T 2>&1); then
          auth_problem=$(sshd_auth_problem "sshd -T" "$sshd_glob")
        else
          precondition_failed "sshd -T meldet einen Fehler, ob eine Anmeldung nur mit Schlüssel möglich ist, ist ungeprüft. Ausgabe: $(tail -n 3 <<<"$sshd_glob")"
        fi
      fi
      if [[ -n $auth_problem ]]; then
        precondition_failed "$auth_problem Ohne Passwort wäre $ADMIN_USER danach ausgesperrt."
      fi
    fi
    if [[ -z $akf ]] && dry && [[ $EUID -ne 0 || ! -d /run/sshd ]]; then
      # Only a dry run gets here without root or without /run/sshd; a real run has both.
      warn "sshd -T ist im Testlauf gescheitert (ohne root oder ohne /run/sshd). Ein echter Lauf bricht ab, wenn sshd -T dann auch scheitert. Hier geprüft wird nur der Standard ~/.ssh/authorized_keys."
      akf=".ssh/authorized_keys"
    elif [[ -z $akf ]]; then
      # Without the effective AuthorizedKeysFile the key check would guess. Stop instead.
      precondition_failed "sshd -T -C $SSHD_TEST_SPEC liefert keine wirksame Konfiguration (AuthorizedKeysFile unbekannt), der Schlüssel lässt sich nicht sicher prüfen. Ausgabe: $(tail -n 3 <<<"$sshd_eff")"
      # Only a dry run continues here; it goes on with the default file.
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

# ufw (0.36.2-6 on 24.04) has "Breaks: iptables-persistent, netfilter-persistent", so
# installing iptables-persistent in step 1 makes apt remove ufw. An active ufw holds the
# firewall rules of this server; removing it under the running rules must not happen
# unattended. On Oracle ufw is normally installed but inactive (the firewall there is
# the iptables rule set of the image). LC_ALL=C: ufw translates its output.
if pkg_installed ufw || command -v ufw >/dev/null 2>&1; then
  ufw_status=$(LC_ALL=C ufw status 2>&1) || true
  ufw_line=$(grep -m 1 '^Status: ' <<<"$ufw_status") || ufw_line=""
  case $ufw_line in
    "Status: active")
      precondition_failed "UFW ist aktiv. apt würde ufw bei der Installation von iptables-persistent entfernen (ufw: Breaks iptables-persistent, netfilter-persistent). Dieses Skript ist für die iptables-Regeln des Oracle-Images geschrieben. Erst klären, ob UFW gebraucht wird; UFW nicht einfach abschalten, solange keine anderen Regeln greifen, sonst ist der Server offen."
      ;;
    "Status: inactive")
      warn "ufw ist installiert, aber nicht aktiv. apt entfernt ufw bei der Installation von iptables-persistent (ufw: Breaks iptables-persistent, netfilter-persistent)."
      ;;
    *)
      if [[ $EUID -eq 0 ]]; then
        precondition_failed "Status von UFW nicht ermittelbar (ufw status: $(head -n 1 <<<"$ufw_status"))."
      else
        warn "Status von UFW ohne root nicht ermittelbar. Ein echter Lauf bricht ab, wenn UFW aktiv ist."
      fi
      ;;
  esac
fi

# State of the firewall before the packages: removing ufw in step 1 runs its prerm,
# which calls "ufw-init stop" and can reset the rules in INPUT. Step 1 compares
# against this state. Only read here; without root (dry run) it cannot be read.
FW_BEFORE_V4="" FW_BEFORE_V6=""
FW_BEFORE_V4=$(fw_state iptables) || FW_BEFORE_V4=""
FW_BEFORE_V6=$(fw_state ip6tables) || FW_BEFORE_V6=""
for fw_tool in iptables ip6tables; do
  if [[ $fw_tool == iptables ]]; then fw_before=$FW_BEFORE_V4; else fw_before=$FW_BEFORE_V6; fi
  if [[ -z $fw_before && $EUID -ne 0 ]]; then
    info "$fw_tool: INPUT ohne root nicht lesbar, ein echter Lauf hält den Zustand vor der Paketinstallation fest"
  elif [[ -z $fw_before ]]; then
    warn "$fw_tool: INPUT nicht lesbar, ob die Paketinstallation die Firewall verändert, bleibt ungeprüft"
  elif [[ $fw_before == "ACCEPT 0" ]]; then
    warn "$fw_tool: INPUT hat weder eine abschließende REJECT- oder DROP-Regel noch die Policy DROP, eingehende Verbindungen sind nicht gefiltert. Auf Oracle ist das unerwartet (das Image beendet INPUT mit REJECT)."
  fi
done

if [[ $PRE_FAILED == 0 ]]; then
  info "in Ordnung: root, Ubuntu $OS_VERSION, Schlüssel für $ADMIN_USER vorhanden, Anmeldung nur mit Schlüssel möglich"
fi

# ---------------------------------------------------------------------------
# 1. System updates and packages
# ---------------------------------------------------------------------------

step "System aktualisieren und Pakete installieren"
export DEBIAN_FRONTEND=noninteractive
# needrestart only lists services instead of asking or restarting them.
export NEEDRESTART_MODE=l
APT_OPTS=(-y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)

# Answer the questions of iptables-persistent in advance: do not save the rules on
# installation. Removing ufw in the same apt run can change them first (see below);
# saving then would make that permanent. The script saves only itself, with
# netfilter-persistent save in step 3, after its checks.
if dry; then
  info "[Testlauf] debconf-set-selections: iptables-persistent/autosave_v4 und autosave_v6 = false"
else
  debconf-set-selections <<'SEL'
iptables-persistent iptables-persistent/autosave_v4 boolean false
iptables-persistent iptables-persistent/autosave_v6 boolean false
SEL
fi
run apt-get update -q
# full-upgrade: on a fresh server also take updates that add or remove packages
# (e.g. a new kernel package). Not interactive, see APT_OPTS.
run apt-get "${APT_OPTS[@]}" full-upgrade
run apt-get "${APT_OPTS[@]}" install ca-certificates curl gnupg unattended-upgrades \
  fail2ban iptables iptables-persistent netfilter-persistent

# apt removes ufw for iptables-persistent (see the checks); the prerm of ufw calls
# "ufw-init stop", which can flush INPUT and set its policy to ACCEPT. Compare with the
# state before the installation: if the final REJECT or DROP rule is gone, or the
# policy went from DROP to ACCEPT, the server is open. Stop then; nothing has been saved
# (autosave false above), the rules files still hold the previous rules.
# fw_after_packages TOOL BEFORE RULES_FILE
fw_after_packages() {
  local tool=$1 before=$2 file=$3 now p0 f0 p1="" f1="" what=""
  [[ -n $before ]] || return 0
  read -r p0 f0 <<<"$before"
  if now=$(fw_state "$tool"); then
    read -r p1 f1 <<<"$now"
    if [[ $f0 == 1 && $f1 != 1 ]]; then what="die abschließende REJECT- oder DROP-Regel in INPUT fehlt jetzt"; fi
    if [[ $p0 == DROP && $p1 == ACCEPT ]]; then what="${what:+$what; }die Policy von INPUT ist von DROP auf ACCEPT gewechselt"; fi
  else
    what="INPUT lässt sich nicht mehr lesen"
  fi
  [[ -n $what ]] || return 0
  {
    echo "Abbruch: Die Firewall wurde durch die Paketinstallation verändert ($tool: $what). Vermutlich hat apt beim Entfernen von ufw dessen Regeln zurückgesetzt (ufw-init stop). Eingehende Verbindungen sind damit womöglich nicht mehr gefiltert."
    echo "Gespeichert wurde nichts: $file enthält, falls vorhanden, noch die bisherigen Regeln. Ein Neustart lädt sie wieder (netfilter-persistent), sofort von Hand: sudo ${tool}-restore < $file"
    echo "Danach mit sudo $tool -L INPUT --line-numbers -n prüfen und das Skript erneut starten."
  } >&2
  exit 1
}
if dry; then
  info "[Testlauf] Nach der Paketinstallation prüft ein echter Lauf, ob INPUT (IPv4 und IPv6) noch die abschließende REJECT- oder DROP-Regel und die Policy von vorher hat; sonst Abbruch ohne Speichern."
else
  fw_after_packages iptables "$FW_BEFORE_V4" /etc/iptables/rules.v4
  fw_after_packages ip6tables "$FW_BEFORE_V6" /etc/iptables/rules.v6
fi

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
# with "REJECT --reject-with icmp-host-prohibited". New ACCEPT rules must go before it;
# the same for an unconditional "-j DROP" at the end of INPUT.
# The script only inserts rules and never deletes one (reason at allow_port).
# UFW is not used: it manages the same INPUT chain and would conflict with these rules.
# It cannot stay installed either: ufw breaks iptables-persistent, so apt removed an
# inactive ufw in step 1, and an active ufw stopped the script in the checks.
#
# Docker bypasses the INPUT chain for published container ports (DNAT, then FORWARD).
# Therefore only Traefik publishes ports (80 and 443). Own rules for containers belong
# in the DOCKER-USER chain, not in INPUT.
#
# Ports are also filtered outside the server by the Security List or Network Security
# Group of the VCN in the Oracle Console; 80 and 443 must be allowed there as well.

step "Firewall: Ports 22, 80 und 443"
FW_CHANGED=0
DRY_SHIFT=0

# Number of the first rule in INPUT that turns other traffic away, empty if there is
# none: a REJECT rule, or an unconditional DROP rule ("-A INPUT -j DROP"; a DROP with
# conditions, e.g. a ban of fail2ban for one address, does not count). The target is
# the last "-j" of the line (a comment comes before it). No early exit in awk: with
# pipefail, iptables could otherwise fail on a closed pipe.
reject_pos() {
  "$1" -S INPUT | awk '$1 == "-A" && !found { n++; t = ""
      for (i = 3; i < NF; i++) if ($i == "-j") t = $(i + 1)
      if (t == "REJECT" || $0 == "-A INPUT -j DROP") { print n; found = 1 } }'
}

# rule_numbers TOOL RULE...: numbers of the rules in INPUT that equal RULE exactly.
rule_numbers() {
  local tool=$1
  shift
  "$tool" -S INPUT | awk -v want="-A INPUT $*" '$1 == "-A" { n++; if ($0 == want) print n }'
}

# allow_port TOOL PORT: accept new TCP connections to PORT, before the REJECT rule (or
# the unconditional DROP rule, see reject_pos; "REJECT" below stands for both).
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
    warn "$tool: Hinter der abweisenden Regel (REJECT oder DROP) steht eine ACCEPT-Regel für Port $port. Sie ist wirkungslos ($open_note) und kann von Hand entfernt werden. Das Skript löscht keine Firewall-Regeln. Regelnummer anzeigen mit: sudo $tool -L INPUT --line-numbers -n (danach speichern: sudo netfilter-persistent save)"
  fi
}

# open_ports TOOL: open 22/80/443 if INPUT rejects (REJECT rule), drops (unconditional
# DROP rule) or drops by policy (not ACCEPT) other traffic; otherwise everything is
# open anyway.
open_ports() {
  local tool=$1 policy port
  DRY_SHIFT=0
  policy=$("$tool" -S INPUT | awk '$1 == "-P" { print $3 }')
  if [[ -n "$(reject_pos "$tool")" || $policy != ACCEPT ]]; then
    for port in 22 80 443; do allow_port "$tool" "$port"; done
  else
    info "$tool: keine REJECT- oder abschließende DROP-Regel in INPUT und Policy ACCEPT, keine Regel nötig"
  fi
}

if ! iptables -L INPUT -n >/dev/null 2>&1; then
  if dry; then
    info "[Testlauf] iptables nicht lesbar (kein root). Ein echter Lauf ermittelt die REJECT- oder abschließende DROP-Regel in INPUT und fügt davor ACCEPT für tcp 22, 80, 443 ein, falls sie fehlen."
  else
    echo "Abbruch: iptables lässt sich nicht lesen." >&2
    exit 1
  fi
else
  open_ports iptables
  # IPv6 like IPv4: REJECT rule (Oracle image), unconditional DROP rule or policy DROP.
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
# sshd uses the first value it reads; files in sshd_config.d are read in name order
# before the rest of sshd_config, so "10-" wins over 50-cloud-init.conf and others.
SSHD_HAD_FILE=0
if [[ -f $SSHD_CONF ]] && ! dry; then
  # Exact copy, to put the old, working file back if the new one fails a check.
  SSHD_HAD_FILE=1
  ensure_tmp_dir
  cp -p -- "$SSHD_CONF" "$TMP_DIR/sshd.old"
fi
# 1 once this run has written the drop-in (put below).
SSHD_CHANGED=0
# sshd_check_failed REASON: a check of the sshd configuration failed; stop without
# reloading ssh. If this run wrote the drop-in, put the previous file back (or remove
# the new one). If the drop-in is unchanged (from an earlier run), it stays: then
# another file changed since, and only the abort message says what to do.
sshd_check_failed() {
  local ok=1
  if [[ $SSHD_CHANGED != 1 ]]; then
    {
      echo "Abbruch: $1"
      echo "$SSHD_CONF ist unverändert (dieser Lauf hat sie nicht geändert) und bleibt, wie sie ist; SSH wurde nicht neu geladen. Die Konfiguration von sshd hat sich seit dem letzten Lauf an anderer Stelle geändert."
      echo "Was zu tun ist: die genannte Ursache beheben, mit sudo sshd -t und sudo sshd -T -C $SSHD_TEST_SPEC prüfen und das Skript erneut starten. Bis dahin ssh nicht neu starten oder neu laden; auch ein Neustart des Servers (etwa der automatische um 04:00) übernimmt die geänderte Konfiguration."
    } >&2
    exit 1
  fi
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
# sshd_allowusers_problem VIEW OUTPUT USER: OUTPUT is what sshd -T (as VIEW) prints.
# Prints why AllowUsers does not let USER in, nothing if it does.
sshd_allowusers_problem() {
  local view=$1 eff=$2 user=$3 allowed
  if ! grep -qx "allowusers $user" <<<"$eff"; then
    allowed=$(awk '$1 == "allowusers" { printf "%s%s", sep, $2; sep = " " }' <<<"$eff")
    printf '%s' "sshd würde $user nicht einlassen (AllowUsers laut $view: ${allowed:-kein Eintrag}; wird $SSHD_CONF überhaupt gelesen?)."
  fi
}
# sshd_deny_problem VIEW OUTPUT USER GROUPS [SOURCE]: prints why DenyUsers, DenyGroups
# or AllowGroups keep USER (member of GROUPS, separated by spaces; SOURCE says where they
# come from, default "id -nG") out, nothing if they do not. DenyUsers, AllowGroups and DenyGroups add up over all files. Patterns as in sshd
# (* and ?); "user@host" entries count for every host here.
sshd_deny_problem() {
  local view=$1 eff=$2 user=$3 groups=$4 source=${5:-id -nG} pat g hit
  while read -r pat; do
    # shellcheck disable=SC2053 # the right side is a pattern on purpose
    if [[ $user == ${pat%%@*} ]]; then
      printf '%s' "DenyUsers schließt $user aus (Eintrag '$pat' laut $view). Dateien mit DenyUsers: $(sshd_candidates denyusers)."
      return 0
    fi
  done < <(awk '$1 == "denyusers" { print $2 }' <<<"$eff")
  while read -r pat; do
    for g in $groups; do
      # shellcheck disable=SC2053 # the right side is a pattern on purpose
      if [[ $g == $pat ]]; then
        printf '%s' "DenyGroups schließt $user aus (Gruppe $g, Eintrag '$pat' laut $view). Dateien mit DenyGroups: $(sshd_candidates denygroups)."
        return 0
      fi
    done
  done < <(awk '$1 == "denygroups" { print $2 }' <<<"$eff")
  if grep -q '^allowgroups ' <<<"$eff"; then
    hit=0
    while read -r pat; do
      for g in $groups; do
        # shellcheck disable=SC2053 # the right side is a pattern on purpose
        if [[ $g == $pat ]]; then hit=1; fi
      done
    done < <(awk '$1 == "allowgroups" { print $2 }' <<<"$eff")
    if ((hit == 0)); then
      printf '%s' "AllowGroups ist gesetzt ($(awk '$1 == "allowgroups" { printf "%s%s", sep, $2; sep = " " }' <<<"$eff") laut $view), $user ist in keiner dieser Gruppen ($source: ${groups:-keine}). Dateien mit AllowGroups: $(sshd_candidates allowgroups)."
    fi
  fi
}
# check_sshd_effective VIEW OUTPUT: OUTPUT is what sshd -T (as VIEW) prints. Stops
# (sshd_check_failed: the previous drop-in back if this run wrote it) if the hardening
# does not take effect or ADMIN_USER would be locked out. sshd takes the first value it reads for PasswordAuthentication
# and the like.
check_sshd_effective() {
  local view=$1 eff=$2 setting key problem admin_groups
  # Without ADMIN_USER in AllowUsers the next login fails: never reload like that.
  problem=$(sshd_allowusers_problem "$view" "$eff" "$ADMIN_USER")
  [[ -z $problem ]] || sshd_check_failed "$problem"
  for setting in "passwordauthentication no" "kbdinteractiveauthentication no" "permitrootlogin no"; do
    if ! grep -qx "$setting" <<<"$eff"; then
      key=${setting%% *}
      sshd_check_failed "sshd verwendet nicht '$setting' (laut $view: '$(awk -v k="$key" '$1 == k' <<<"$eff")'). Vermutlich setzt eine Datei, die vor $SSHD_CONF gelesen wird (Name sortiert früher), oder ein Match-Block den Wert zuerst. Dateien mit $key: $(sshd_candidates "$key")."
    fi
  done
  # Passwords are off now: a key alone must be enough (PubkeyAuthentication,
  # AuthenticationMethods).
  problem=$(sshd_auth_problem "$view" "$eff")
  [[ -z $problem ]] || sshd_check_failed "$problem Ohne Passwort wäre $ADMIN_USER ausgesperrt."
  admin_groups=$(id -nG "$ADMIN_USER" 2>/dev/null) || admin_groups=""
  problem=$(sshd_deny_problem "$view" "$eff" "$ADMIN_USER" "$admin_groups")
  [[ -z $problem ]] || sshd_check_failed "$problem"
}
# check_sshd_deploy VIEW OUTPUT: the same access checks for the user deploy of the CI,
# but only as a warning: the admin login is not affected, the deploy of the CI would
# fail. On a fresh server deploy is created only in step 8, with its own group and in
# the group docker; those are the groups checked then.
check_sshd_deploy() {
  local view=$1 eff=$2 groups source="id -nG" problem
  if ! groups=$(id -nG "$DEPLOY_USER" 2>/dev/null); then
    groups=$DEPLOY_USER
    source="Gruppen nach dem Anlegen in Schritt 8"
  fi
  [[ " $groups " == *" docker "* ]] || groups="$groups docker"
  problem=$(sshd_allowusers_problem "$view" "$eff" "$DEPLOY_USER")
  [[ -n $problem ]] || problem=$(sshd_deny_problem "$view" "$eff" "$DEPLOY_USER" "$groups" "$source")
  if [[ -n $problem ]]; then
    warn "$problem Der Zugang für $ADMIN_USER ist nicht betroffen, aber das Deploy der CI als $DEPLOY_USER würde scheitern."
  fi
}
if put "$SSHD_CONF" 0644 <<CONF; then
# Managed by deploy/setup-server.sh
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers ${ADMIN_USER} ${DEPLOY_USER}
CONF
  SSHD_CHANGED=1
fi
# The checks only read and run on every real run, also when the drop-in is unchanged:
# another file (a later drop-in, a Match block, a package update) can have changed the
# effective configuration since the last run.
if ! dry; then
  # The checks created /run/sshd; a package update in step 1 may have stopped ssh since,
  # which removes it again. Without it sshd -t fails.
  [[ -d /run/sshd ]] || install -d -m 0755 /run/sshd ||
    sshd_check_failed "/run/sshd ließ sich nicht anlegen (nötig für sshd -t)."
  sshd -t || sshd_check_failed "sshd -t meldet einen Fehler."
  effective=$(sshd -T 2>/dev/null) || sshd_check_failed "sshd -T meldet einen Fehler, die wirksame Konfiguration ist unbekannt."
  effective_admin=$(sshd -T -C "$SSHD_TEST_SPEC" 2>/dev/null) ||
    sshd_check_failed "sshd -T -C $SSHD_TEST_SPEC meldet einen Fehler, die wirksame Konfiguration für $ADMIN_USER ist unbekannt."
  # Global values, and the values for ADMIN_USER after Match blocks.
  check_sshd_effective "sshd -T" "$effective"
  check_sshd_effective "sshd -T -C $SSHD_TEST_SPEC" "$effective_admin"
  # The same for deploy, only as a warning (check_sshd_deploy).
  if effective_deploy=$(sshd -T -C "$SSHD_DEPLOY_SPEC" 2>/dev/null); then
    check_sshd_deploy "sshd -T" "$effective"
    check_sshd_deploy "sshd -T -C $SSHD_DEPLOY_SPEC" "$effective_deploy"
  else
    warn "sshd -T -C $SSHD_DEPLOY_SPEC meldet einen Fehler, ob $DEPLOY_USER (CI) sich anmelden kann, ist ungeprüft."
  fi
  if [[ $SSHD_CHANGED == 0 ]]; then
    info "in Ordnung: sshd -t und sshd -T (global, für $ADMIN_USER und $DEPLOY_USER) ohne Befund"
  fi
else
  [[ -d /run/sshd ]] || run install -d -m 0755 /run/sshd
  info "[Testlauf] sshd -t, danach Prüfung mit sshd -T und sshd -T -C $SSHD_TEST_SPEC (bei jedem echten Lauf, auch wenn $SSHD_CONF unverändert bleibt): AllowUsers enthält $ADMIN_USER, PasswordAuthentication, KbdInteractiveAuthentication und PermitRootLogin sind no, PubkeyAuthentication ist yes, AuthenticationMethods ist any oder hat eine Liste nur mit publickey, DenyUsers, AllowGroups und DenyGroups schließen $ADMIN_USER nicht aus; dasselbe für $DEPLOY_USER mit sshd -T -C $SSHD_DEPLOY_SPEC, dort nur als Warnung"
fi
if [[ $SSHD_CHANGED == 1 ]]; then
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
# maxretry, findtime, bantime and dbpurgeage are named in the privacy policy (see
# step 6), so they are set here instead of relying on the package defaults.
# fail2ban logs bans with IP addresses. By default it writes them to
# /var/log/fail2ban.log, which /etc/logrotate.d/fail2ban keeps for about five weeks.
# logtarget = SYSLOG[facility=AUTHPRIV] (fail2ban 1.0.2, server/server.py) sends them
# to syslog instead; syslogsocket = auto (package default) is /dev/log on Linux, the
# socket of journald (systemd-journald-dev-log.socket). They end up in the journal and,
# with rsyslog, in /var/log/auth.log (50-default.conf: auth,authpriv.*), both deleted
# after 7 days (step 6). Not SYSTEMD-JOURNAL: its messages carry no facility, journald
# forwards them to rsyslog as "user", and rsyslog writes them to /var/log/syslog, which
# /etc/logrotate.d/rsyslog keeps for about five weeks. authpriv is left out there
# (*.*;auth,authpriv.none).
F2B_CHANGED=0
if put /etc/fail2ban/fail2ban.local 0644 <<'CONF'; then
# Managed by deploy/setup-server.sh
[Definition]
logtarget = SYSLOG[facility=AUTHPRIV]
dbpurgeage = 1d
CONF
  F2B_CHANGED=1
fi
if put /etc/fail2ban/jail.local 0644 <<'CONF'; then
# Managed by deploy/setup-server.sh
[sshd]
enabled = true
backend = systemd
port = ssh
maxretry = 5
findtime = 10m
bantime = 10m
banaction = iptables-multiport
banaction_allports = iptables-allports
CONF
  F2B_CHANGED=1
fi
if [[ $F2B_CHANGED == 1 ]] && ! dry; then
  fail2ban-client -t >/dev/null || { echo "Abbruch: fail2ban-client -t meldet einen Fehler in /etc/fail2ban/fail2ban.local oder /etc/fail2ban/jail.local." >&2; exit 1; }
fi
# The values must also take effect. fail2ban reads jail.conf, jail.d/*.conf, jail.local
# and then jail.d/*.local (the same for fail2ban.conf, fail2ban.d/ and fail2ban.local),
# and the last value wins. A file in jail.d/*.local or fail2ban.d/*.local can therefore
# override the values above without a trace. fail2ban-client -d prints the commands
# fail2ban would load, e.g. ['set', 'sshd', 'bantime', '10m'] and
# ['set', 'dbpurgeage', '1d'] (fail2ban 1.0.2), times as written in the files. They
# are converted to seconds with fail2ban's own parser (MyTime.str2seconds), so "600"
# counts the same as "10m". Checked on every run, before fail2ban is (re)started;
# foreign files are not touched.
F2B_WANT=(
  "logtarget=SYSLOG[facility=AUTHPRIV]"
  "dbpurgeage=86400"
  "sshd.maxretry=5"
  "sshd.findtime=600"
  "sshd.bantime=600"
  "sshd.bantime.increment=false"
)
# Prints "key=value" for logtarget, dbpurgeage and maxretry, findtime, bantime and
# bantime.increment of the jail sshd, read from the output of fail2ban-client -d on
# stdin; times in seconds. "jails" lists the names of all jails fail2ban would start
# (['add', 'sshd', 'systemd'] in the dump), separated by spaces. A time fail2ban's parser does not accept is printed as it is
# (and then differs). bantime.increment would make repeated bans longer than bantime;
# the dump shows it only if it is set, as a boolean (['set', 'sshd',
# 'bantime.increment', True], fail2ban 1.0.2), so a missing value counts as false.
F2B_VALUES_PY=$(
  cat <<'PY'
import ast
import sys

from fail2ban.server.mytime import MyTime

vals = {}
jails = set()
for line in sys.stdin:
    line = line.strip()
    if not line.startswith("["):
        continue
    try:
        c = ast.literal_eval(line)
    except (ValueError, SyntaxError):
        continue  # not a command line of the dump
    if not isinstance(c, list):
        continue
    if len(c) >= 2 and c[0] == "add":
        jails.add(str(c[1]))
    if len(c) == 3 and c[0] == "set" and c[1] in ("logtarget", "dbpurgeage"):
        vals[c[1]] = str(c[2])
    elif len(c) == 4 and c[:2] == ["set", "sshd"] and c[2] in ("maxretry", "findtime", "bantime"):
        vals["sshd." + c[2]] = str(c[3])
    elif len(c) == 4 and c[:3] == ["set", "sshd", "bantime.increment"]:
        vals["sshd.bantime.increment"] = str(c[3]).lower()
vals.setdefault("sshd.bantime.increment", "false")
vals["jails"] = " ".join(sorted(jails))
for k in ("dbpurgeage", "sshd.findtime", "sshd.bantime"):
    if k in vals:
        try:
            vals[k] = str(int(MyTime.str2seconds(vals[k])))
        except Exception:  # any parse error: keep the text, so the value differs
            vals[k] = "unlesbar: " + vals[k]
for k in sorted(vals):
    print("%s=%s" % (k, vals[k]))
PY
)
# f2b_candidates DIR KEY: files DIR/*.local that set KEY. Only a hint for the abort
# message.
f2b_candidates() {
  local f found=()
  for f in "$1"/*.local; do
    [[ -f $f ]] || continue
    if grep -qiE "^[[:space:]]*${2//./\\.}[[:space:]]*[=:]" "$f" 2>/dev/null; then found+=("$f"); fi
  done
  if ((${#found[@]} > 0)); then printf '%s' "${found[*]}"; else printf 'keine gefunden'; fi
}
if dry; then
  info "[Testlauf] Prüfung mit fail2ban-client -d: logtarget = SYSLOG[facility=AUTHPRIV], dbpurgeage 1d, Jail sshd mit maxretry 5, findtime 10m, bantime 10m, ohne bantime.increment; bei Abweichung Abbruch ohne Neustart von fail2ban"
else
  f2b_dump=$(fail2ban-client -d 2>/dev/null) ||
    { echo "Abbruch: fail2ban-client -d meldet einen Fehler, die wirksamen Werte von fail2ban sind unbekannt. fail2ban wurde nicht neu gestartet." >&2; exit 1; }
  f2b_got=$(python3 -I -c "$F2B_VALUES_PY" <<<"$f2b_dump") ||
    { echo "Abbruch: Die Ausgabe von fail2ban-client -d ließ sich nicht auswerten (python3 mit dem Modul fail2ban). fail2ban wurde nicht neu gestartet." >&2; exit 1; }
  f2b_bad=()
  for want in "${F2B_WANT[@]}"; do
    key=${want%%=*}
    got=$(awk -v k="$key" 'index($0, k "=") == 1 { print substr($0, length(k) + 2) }' <<<"$f2b_got")
    [[ $got == "${want#*=}" ]] && continue
    case $key in
      sshd.*)
        # No value at all: the jail sshd is not enabled; look for "enabled" then.
        if [[ -z $got ]]; then
          where=$(f2b_candidates /etc/fail2ban/jail.d enabled)
        else
          where=$(f2b_candidates /etc/fail2ban/jail.d "${key#sshd.}")
        fi
        ;;
      *) where=$(f2b_candidates /etc/fail2ban/fail2ban.d "$key") ;;
    esac
    f2b_bad+=("$key: erwartet ${want#*=}, wirksam ${got:-nicht gesetzt (Jail sshd nicht aktiv?)}; Dateien, die den Wert vermutlich überstimmen: $where")
  done
  if ((${#f2b_bad[@]} > 0)); then
    {
      echo "Abbruch: fail2ban verwendet nicht die Werte der Datenschutzerklärung (laut fail2ban-client -d, Zeiten in Sekunden):"
      printf '  %s\n' "${f2b_bad[@]}"
      echo "fail2ban liest jail.d/*.local nach jail.local und fail2ban.d/*.local nach fail2ban.local; der zuletzt gelesene Wert gilt. Die eigenen Dateien fail2ban.local und jail.local bleiben, wie sie sind; fail2ban wurde nicht neu gestartet. Die genannte Datei anpassen oder entfernen und das Skript erneut starten."
    } >&2
    exit 1
  fi
  info "in Ordnung: fail2ban-client -d zeigt logtarget SYSLOG[facility=AUTHPRIV], dbpurgeage 86400 s, sshd maxretry 5, findtime 600 s, bantime 600 s, bantime.increment aus"
  # The privacy policy names only the jail sshd. Other jails (e.g. recidive, which bans
  # for a week by default) ban with their own values; the script does not check them.
  f2b_other=$(awk 'index($0, "jails=") == 1 { n = split(substr($0, 7), j, " "); for (i = 1; i <= n; i++) if (j[i] != "sshd") { printf "%s%s", sep, j[i]; sep = " " } }' <<<"$f2b_got")
  if [[ -n $f2b_other ]]; then
    warn "In fail2ban sind außer sshd weitere Jails aktiv: $f2b_other. Ihre Sperrdauer und Werte prüft das Skript nicht, sie entsprechen nicht der Datenschutzerklärung (dort nur: Sperre für 10 Minuten nach 5 Fehlversuchen in 10 Minuten). Jail abschalten (enabled = false) oder die Datenschutzerklärung anpassen. Anzeigen mit: sudo fail2ban-client status"
  fi
fi
if [[ $F2B_CHANGED == 1 ]]; then
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
# attempts; fail2ban reads them, bans whoever fails 5 times within 10 minutes for
# 10 minutes, and deletes its list of banned addresses after one day; the logs of SSH
# login attempts, those of fail2ban included, are deleted after 7 days. Change these
# values only together with the privacy policy.
#
# fail2ban: the values equal the package defaults of Ubuntu 24.04 (fail2ban 1.0.2,
# /etc/fail2ban/jail.conf: bantime = 10m, findtime = 10m, maxretry = 5;
# /etc/fail2ban/fail2ban.conf: dbpurgeage = 1d), but step 5 sets them explicitly in
# jail.local and fail2ban.local, so a changed default cannot change them unnoticed.
# fail2ban reads the journal (backend = systemd), not /var/log/auth.log, and logs to
# syslog with facility authpriv (fail2ban.local), that is to the journal and, with
# rsyslog, to /var/log/auth.log.
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
#
# btmp and wtmp: /var/log/btmp holds failed logins, /var/log/wtmp logins, both with the
# remote address. The logrotate package (3.21.0-2build1) rotates them in its conffiles
# /etc/logrotate.d/btmp (monthly, rotate 1) and /etc/logrotate.d/wtmp (monthly,
# minsize 1M, rotate 1), so entries stay up to two months. 00-login-logs comes first
# and overrides them with the same logic as 00-auth-log (without minsize, which would
# delay the daily rotation); "create" keeps the modes and owners of the package files.
#
# fail2ban.log: with logtarget = SYSLOG fail2ban no longer writes it, but the
# file stays: entries from before the switch (on a fresh server: from the installation
# in step 1 until the restart in step 5), and the postinst of the package recreates it
# on every update (touch). /etc/logrotate.d/fail2ban has "notifempty": after one more
# rotation the new file stays empty, so it is never rotated again and fail2ban.log.1
# with the old entries would never be deleted. 00-fail2ban-log rotates it daily with
# "ifempty" and "rotate 6", so old entries are gone after 7 days. Nothing is deleted
# directly.

step "Protokolle: Aufbewahrung 7 Tage"
if put /etc/systemd/journald.conf.d/10-aufbewahrung.conf 0644 <<'CONF'; then
# Managed by deploy/setup-server.sh
[Journal]
MaxRetentionSec=6day
MaxFileSec=1day
CONF
  run systemctl restart systemd-journald
fi
# logrotate counts as there only if dpkg has the package installed and the program is
# there; the same test for all three 00-* files. Without it none of them is written,
# they would have no effect.
HAVE_RSYSLOG=0
if pkg_installed rsyslog; then HAVE_RSYSLOG=1; fi
LR_MISSING="" LR_FIX=""
if ! pkg_installed logrotate; then
  LR_MISSING="das Paket logrotate ist nicht installiert"
  LR_FIX="sudo apt-get install logrotate"
elif ! command -v logrotate >/dev/null 2>&1; then
  LR_MISSING="das Paket logrotate ist installiert, aber das Programm logrotate fehlt"
  LR_FIX="sudo apt-get install --reinstall logrotate"
fi
if [[ -z $LR_MISSING ]]; then
  if [[ $HAVE_RSYSLOG == 1 ]]; then
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
  else
    info "rsyslog ist nicht installiert, es gibt kein /var/log/auth.log"
  fi
  put /etc/logrotate.d/00-login-logs 0644 <<'CONF' || true
# Managed by deploy/setup-server.sh
/var/log/btmp {
  daily
  rotate 6
  ifempty
  missingok
  ignoreduplicates
  create 0660 root utmp
}
/var/log/wtmp {
  daily
  rotate 6
  ifempty
  missingok
  ignoreduplicates
  create 0664 root utmp
}
CONF
  put /etc/logrotate.d/00-fail2ban-log 0644 <<'CONF' || true
# Managed by deploy/setup-server.sh
/var/log/fail2ban.log {
  daily
  rotate 6
  ifempty
  missingok
  compress
  delaycompress
  ignoreduplicates
  create 640 root adm
  postrotate
    fail2ban-client flushlogs >/dev/null 2>&1 || true
  endscript
}
CONF
  if [[ -s /var/log/fail2ban.log ]]; then
    info "/var/log/fail2ban.log enthält Einträge von vor dem Wechsel auf syslog; sie sind nach spätestens 7 Tagen gelöscht (00-fail2ban-log). Sofort löschen von Hand: sudo truncate -s 0 /var/log/fail2ban.log; sudo rm -f /var/log/fail2ban.log.*"
  fi
else
  if [[ $HAVE_RSYSLOG == 1 ]]; then
    lr_logs="/var/log/auth.log, /var/log/btmp, /var/log/wtmp und /var/log/fail2ban.log"
  else
    info "rsyslog ist nicht installiert, es gibt kein /var/log/auth.log"
    lr_logs="/var/log/btmp, /var/log/wtmp und /var/log/fail2ban.log"
  fi
  warn "logrotate fehlt ($LR_MISSING): $lr_logs werden nicht nach 7 Tagen gelöscht, die Dateien in /etc/logrotate.d (00-auth-log, 00-login-logs, 00-fail2ban-log) werden nicht angelegt. Abhilfe: $LR_FIX, danach das Skript erneut starten."
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
# Home directory from getent passwd. In a dry run on a fresh server deploy does not
# exist yet; useradd then creates /home/deploy.
DEPLOY_HOME=$(getent passwd "$DEPLOY_USER" | cut -d: -f6) || DEPLOY_HOME=""
if [[ -z $DEPLOY_HOME ]] && dry; then
  DEPLOY_HOME="/home/$DEPLOY_USER"
elif [[ $DEPLOY_HOME != /* ]]; then
  echo "Abbruch: Home-Verzeichnis von $DEPLOY_USER nicht ermittelbar (getent passwd $DEPLOY_USER)." >&2
  exit 1
fi
DEPLOY_SSH="$DEPLOY_HOME/.ssh"
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
