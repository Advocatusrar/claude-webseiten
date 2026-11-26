#!/usr/bin/env bash
# One-time hardening of a fresh Ubuntu 24.04 LTS server. Two profiles (PROFIL):
#
#   oracle (default)  Oracle Cloud (A1, aarch64). Run it as the default user "ubuntu"
#                     (Oracle has no root login):
#                       scp deploy/setup-server.sh ubuntu@SERVER:
#                       ssh ubuntu@SERVER 'sudo bash setup-server.sh'
#   hostinger         Hostinger VPS, run as root (hPanel web console or SSH as root):
#                       PROFIL=hostinger ADMIN_USER=name ADMIN_PUBKEY='ssh-ed25519 AAAA... x' \
#                         bash setup-server.sh
#                     docs/server.md has the full runbook (download, checksum, dry run).
#
# What it does: system updates, automatic security updates with a reboot at 04:00
# (Europe/Berlin), SSH login only with keys and only for ${ADMIN_USER} and deploy,
# fail2ban for SSH, ports 22/80/443 in iptables (no UFW), logs with IP addresses
# (journal, /var/log/auth.log, btmp, wtmp, fail2ban.log) kept for about 7 days, Docker
# from the official repository with log limits, and the user "deploy" (member of the
# group docker, empty authorized_keys).
# Profile oracle: the ACCEPT rules go before the final REJECT of the Oracle image.
# Profile hostinger: INPUT is open there (policy ACCEPT, no rules); the script adds
# ACCEPT rules for loopback, replies, ICMP/ICMPv6, the DHCP client and tcp 22/80/443,
# then a final REJECT (IPv4 and IPv6). It creates ADMIN_USER (group sudo) with
# ADMIN_PUBKEY, and keeps root login with password only for the web console of
# Hostinger (SSH from 169.254.0.1). An existing Docker installation is kept.
# It does not set up the website; that follows with the layout for live and staging.
#
# Variables:
#   PROFIL      oracle (default) or hostinger; any other value stops the script.
#   ADMIN_USER  user that keeps SSH access.
#               Profile oracle: default ubuntu; must exist and needs a key in its
#               AuthorizedKeysFile (normally ~/.ssh/authorized_keys, home directory
#               from getent passwd), otherwise nothing is changed. When run with sudo,
#               it must be the user who called sudo (SUDO_USER) and the user who logged
#               in (audit login UID, /proc/self/loginuid, checked in both cases),
#               otherwise nothing is changed either: AllowUsers would lock that user out.
#               Profile hostinger: required, no default. Created if missing (home
#               /home/NAME, shell bash, group sudo); an existing user must be a normal
#               login user (UID from UID_MIN in /etc/login.defs, login shell).
#   ADMIN_PUBKEY  profile hostinger only, required: exactly one public key line,
#               "TYPE BASE64 [comment]", TYPE one of ssh-ed25519, ecdsa-sha2-nistp256,
#               ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, ssh-rsa (at least 2048 bits).
#               No options in front, no private key. Installed in
#               ~ADMIN_USER/.ssh/authorized_keys (700/600) before sshd is reloaded.
#               Only given at runtime, never stored in the repository.
#   DRY_RUN=1   only print what would be done; changes nothing and needs no root.
#
# It is idempotent: a second run changes nothing and does not fail.
set -euo pipefail

PROFIL="${PROFIL:-oracle}"
ADMIN_USER="${ADMIN_USER-}"
ADMIN_PUBKEY="${ADMIN_PUBKEY-}"
DRY_RUN="${DRY_RUN:-0}"
DEPLOY_USER=deploy
CHANGES=0
# Drop-in of this script; sshd reads it before 50-cloud-init.conf and the like (step 4).
SSHD_CONF=/etc/ssh/sshd_config.d/10-haertung.conf
# Address the web console of Hostinger connects from (SSH as root with password).
CONSOLE_ADDR=169.254.0.1
# A public address for the sshd -T -C checks of the profile hostinger (TEST-NET-3,
# RFC 5737): stands for any login from the internet.
PUBLIC_TEST_ADDR=203.0.113.10

case $PROFIL in
  oracle) ADMIN_USER="${ADMIN_USER:-ubuntu}" ;;
  hostinger) ;;
  *)
    echo "Abbruch, nichts geändert: PROFIL '$PROFIL' ist unbekannt (erlaubt: oracle, hostinger)." >&2
    exit 1
    ;;
esac
hostinger() { [[ $PROFIL == hostinger ]]; }

# Connection that sshd -T -C evaluates Match blocks for (used once ADMIN_USER is checked).
# Profile hostinger: a login from a public address, so that the Match block for the web
# console (Match User root Address 169.254.0.1) does not apply.
if hostinger; then
  SSHD_TEST_SPEC="user=$ADMIN_USER,host=client.invalid,addr=$PUBLIC_TEST_ADDR"
  SSHD_DEPLOY_SPEC="user=$DEPLOY_USER,host=client.invalid,addr=$PUBLIC_TEST_ADDR"
else
  SSHD_TEST_SPEC="user=$ADMIN_USER,host=localhost,addr=127.0.0.1"
  # The same for the user deploy of the CI (only warnings, see check_sshd_deploy).
  SSHD_DEPLOY_SPEC="user=$DEPLOY_USER,host=localhost,addr=127.0.0.1"
fi
# Profile hostinger: root from the internet (must be denied) and from the web console
# (password allowed), see check_sshd_hostinger.
SSHD_ROOT_PUBLIC_SPEC="user=root,host=client.invalid,addr=$PUBLIC_TEST_ADDR"
SSHD_ROOT_CONSOLE_SPEC="user=root,host=console.invalid,addr=$CONSOLE_ADDR"
# ADMIN_USER and deploy from the address of the web console: still only the key.
SSHD_ADMIN_CONSOLE_SPEC="user=$ADMIN_USER,host=console.invalid,addr=$CONSOLE_ADDR"
SSHD_DEPLOY_CONSOLE_SPEC="user=$DEPLOY_USER,host=console.invalid,addr=$CONSOLE_ADDR"

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

# FINAL_RULE_AWK: awk function final_rule(LINE) for a rule line of "iptables -S INPUT"
# (or ip6tables): 1 if the rule turns other traffic away, else 0. That is any REJECT
# rule, or an unconditional DROP rule ("-A INPUT -j DROP"; a DROP with conditions,
# e.g. a ban of fail2ban for one address, does not count). A comment
# ("-m comment --comment TEXT", TEXT in quotes if it has blanks, \" and \\ escaped)
# is no condition: it is removed first, so "-A INPUT -m comment --comment x -j DROP"
# counts as unconditional. The target is the last "-j" of what remains.
# fw_state and reject_pos both use it, so they always agree on the final rule.
FINAL_RULE_AWK='
function final_rule(r,   f, n, i, t) {
  gsub(/ -m comment --comment ("([^"\\]|\\.)*"|[^ "]+)/, "", r)
  n = split(r, f, " ")
  t = ""
  for (i = 3; i < n; i++) if (f[i] == "-j") t = f[i + 1]
  return t == "REJECT" || r == "-A INPUT -j DROP"
}'

# fw_state TOOL: prints "POLICY FINAL" for the chain INPUT of TOOL (iptables or
# ip6tables): its policy, and 1 if it has a rule that turns other traffic away (a
# REJECT rule or an unconditional DROP rule, see FINAL_RULE_AWK; like the last rule of
# the Oracle image), else 0. Fails if the rules cannot be read.
fw_state() {
  local rules
  rules=$("$1" -S INPUT 2>/dev/null) || return 1
  awk "$FINAL_RULE_AWK"'
       $1 == "-P" { p = $3 }
       $1 == "-A" && final_rule($0) { f = 1 }
       END { printf "%s %d\n", p, f }' <<<"$rules"
}

# ---------------------------------------------------------------------------
# 0. Checks. Nothing is changed before all of them have passed, except the runtime
#    directory /run/sshd (see below).
# ---------------------------------------------------------------------------

step "Prüfungen"
[[ $DRY_RUN == 0 || $DRY_RUN == 1 ]] || { echo "DRY_RUN muss 0 oder 1 sein." >&2; exit 1; }
dry && info "Testlauf (DRY_RUN=1): es wird nichts geändert."
info "Profil: $PROFIL"

if hostinger; then
  [[ $EUID -eq 0 ]] || precondition_failed "Bitte als root ausführen (Web-Konsole im hPanel oder SSH als root): PROFIL=hostinger ADMIN_USER=name ADMIN_PUBKEY='ssh-ed25519 AAAA... kommentar' bash setup-server.sh"
else
  [[ $EUID -eq 0 ]] || precondition_failed "Bitte mit sudo als root ausführen: sudo bash setup-server.sh"
fi

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
if ! hostinger; then
  [[ "$(uname -m)" == aarch64 ]] || warn "Geschrieben für Oracle A1 (aarch64), gefunden: $(uname -m)."
fi

# The user name ends up in sshd_config, so allow only plain user names.
# ADMIN_EXISTS: 1 if the user exists already. Profile hostinger: if not, step 4 creates
# it (home /home/NAME); it must not clash with an existing group of that name, and an
# existing user must be a normal login user (not a system account like www-data).
ADMIN_OK=0
ADMIN_EXISTS=0
if hostinger && [[ -z $ADMIN_USER ]]; then
  precondition_failed "ADMIN_USER fehlt. Im Profil hostinger gibt es keinen Standard: PROFIL=hostinger ADMIN_USER=name ADMIN_PUBKEY='ssh-ed25519 AAAA... kommentar' bash setup-server.sh"
elif [[ ! $ADMIN_USER =~ ^[a-z_][a-z0-9_-]*$ ]] || ((${#ADMIN_USER} > 32)); then
  precondition_failed "ADMIN_USER '$ADMIN_USER' ist kein gültiger Benutzername."
elif [[ $ADMIN_USER == root || $ADMIN_USER == "$DEPLOY_USER" ]]; then
  precondition_failed "ADMIN_USER darf nicht root oder $DEPLOY_USER sein (Root-Login wird gesperrt, $DEPLOY_USER ist für die CI)."
elif id "$ADMIN_USER" >/dev/null 2>&1; then
  ADMIN_EXISTS=1
  ADMIN_OK=1
  if hostinger; then
    uid_min=$(awk '$1 == "UID_MIN" { print $2 }' /etc/login.defs 2>/dev/null) || uid_min=""
    [[ $uid_min =~ ^[0-9]+$ ]] || uid_min=1000
    admin_uid=$(id -u "$ADMIN_USER")
    admin_shell=$(getent passwd "$ADMIN_USER" | cut -d: -f7) || admin_shell=""
    if ((admin_uid < uid_min)); then
      ADMIN_OK=0
      precondition_failed "Benutzer $ADMIN_USER existiert schon als Systembenutzer (UID $admin_uid, unter UID_MIN $uid_min). Bitte einen anderen Namen für ADMIN_USER wählen."
    elif [[ $admin_shell == */nologin || $admin_shell == */false ]]; then
      ADMIN_OK=0
      precondition_failed "Benutzer $ADMIN_USER existiert schon, hat aber keine Login-Shell ($admin_shell). Bitte einen anderen Namen für ADMIN_USER wählen."
    fi
  fi
elif hostinger; then
  if getent group "$ADMIN_USER" >/dev/null 2>&1; then
    precondition_failed "Es gibt schon eine Gruppe $ADMIN_USER, aber keinen Benutzer dieses Namens. Das Anlegen mit eigener Gruppe würde scheitern. Bitte einen anderen Namen für ADMIN_USER wählen."
  else
    ADMIN_OK=1
  fi
else
  precondition_failed "Benutzer $ADMIN_USER existiert nicht."
fi

# check_admin_pubkey KEY: checks ADMIN_PUBKEY (profile hostinger). On success it sets
# ADMIN_KEY_LINE (the line for authorized_keys: "TYPE BASE64 [comment]", blanks at both
# ends removed), ADMIN_KEY_ID ("TYPE BASE64", to find the key again whatever the
# comment) and ADMIN_KEY_FPR (SHA256 fingerprint); otherwise PUBKEY_PROBLEM says why.
# The key itself never appears in a message (it could be a private key by mistake).
# Rejected: empty, a private key, more than one line, control characters, options in
# front of the key (command=, from=, restrict, ...: the first field must be the type),
# other types (also sk-* keys, DSA), a base64 part that ssh-keygen does not accept as
# a public key of exactly that type, ECDSA with a size other than the curve, RSA under
# 2048 bits.
ADMIN_KEY_LINE="" ADMIN_KEY_ID="" ADMIN_KEY_FPR="" PUBKEY_PROBLEM=""
check_admin_pubkey() {
  local k=$1 type blob comment out bits fpr kind want want_bits=""
  PUBKEY_PROBLEM=""
  if [[ -z ${k//[[:space:]]/} ]]; then
    PUBKEY_PROBLEM="ADMIN_PUBKEY fehlt. Im Profil hostinger wird der öffentliche Schlüssel für $ADMIN_USER beim Aufruf übergeben: ADMIN_PUBKEY='ssh-ed25519 AAAA... kommentar' (Inhalt der Datei ~/.ssh/id_ed25519.pub auf deinem Rechner)."
    return
  fi
  if [[ $k == *"PRIVATE KEY"* || $k == *"-----BEGIN"* ]]; then
    PUBKEY_PROBLEM="ADMIN_PUBKEY sieht aus wie ein privater Schlüssel (-----BEGIN ...). Nur den öffentlichen Teil übergeben (Datei mit der Endung .pub). Der private Schlüssel gehört nie auf den Server; er steht jetzt womöglich in der Shell-History, deshalb einen neuen Schlüssel erzeugen und den alten nicht mehr verwenden."
    return
  fi
  if [[ $k == *$'\n'* || $k == *$'\r'* ]]; then
    PUBKEY_PROBLEM="ADMIN_PUBKEY hat mehrere Zeilen. Erlaubt ist genau ein öffentlicher Schlüssel in einer Zeile."
    return
  fi
  k=${k#"${k%%[![:blank:]]*}"}
  k=${k%"${k##*[![:blank:]]}"}
  if [[ $k =~ [[:cntrl:]] ]]; then
    PUBKEY_PROBLEM="ADMIN_PUBKEY enthält Steuerzeichen (z. B. einen Tabulator). Erlaubt ist eine Zeile \"TYP BASE64 [Kommentar]\" mit Leerzeichen."
    return
  fi
  if ((${#k} > 16384)); then
    PUBKEY_PROBLEM="ADMIN_PUBKEY ist länger als 16384 Zeichen, das ist kein einzelner öffentlicher Schlüssel."
    return
  fi
  read -r type blob comment <<<"$k"
  case $type in
    ssh-ed25519) want=ED25519 ;;
    ecdsa-sha2-nistp256) want=ECDSA want_bits=256 ;;
    ecdsa-sha2-nistp384) want=ECDSA want_bits=384 ;;
    ecdsa-sha2-nistp521) want=ECDSA want_bits=521 ;;
    ssh-rsa) want=RSA ;;
    *)
      PUBKEY_PROBLEM="ADMIN_PUBKEY beginnt nicht mit einem erlaubten Schlüsseltyp (ssh-ed25519, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, ssh-rsa). Optionen vor dem Schlüssel (z. B. command=..., from=..., restrict) sind nicht erlaubt."
      return
      ;;
  esac
  if [[ ! $blob =~ ^[A-Za-z0-9+/]+={0,2}$ ]]; then
    PUBKEY_PROBLEM="ADMIN_PUBKEY: Auf den Typ $type folgt kein Base64-Teil."
    return
  fi
  if ! command -v ssh-keygen >/dev/null 2>&1; then
    PUBKEY_PROBLEM="ssh-keygen fehlt (Paket openssh-client), ADMIN_PUBKEY lässt sich nicht prüfen."
    return
  fi
  if ! out=$(ssh-keygen -l -f - <<<"$type $blob" 2>/dev/null) || [[ -z $out ]]; then
    PUBKEY_PROBLEM="ADMIN_PUBKEY ist kein gültiger öffentlicher Schlüssel (ssh-keygen -l erkennt ihn nicht)."
    return
  fi
  read -r bits fpr _ <<<"$out"
  kind=${out##*(}
  kind=${kind%)}
  if [[ $kind != "$want" ]]; then
    PUBKEY_PROBLEM="ADMIN_PUBKEY: Typ $type passt nicht zum Schlüssel selbst (ssh-keygen: $kind)."
  elif [[ -n $want_bits && $bits != "$want_bits" ]]; then
    PUBKEY_PROBLEM="ADMIN_PUBKEY: Typ $type passt nicht zur Schlüssellänge $bits."
  elif [[ $want == RSA ]] && ! ((bits >= 2048)); then
    PUBKEY_PROBLEM="ADMIN_PUBKEY: RSA-Schlüssel mit $bits Bit ist zu kurz (mindestens 2048, besser ssh-ed25519)."
  fi
  [[ -z $PUBKEY_PROBLEM ]] || return 0
  ADMIN_KEY_LINE="$type $blob${comment:+ $comment}"
  ADMIN_KEY_ID="$type $blob"
  ADMIN_KEY_FPR=$fpr
}
if hostinger; then
  check_admin_pubkey "$ADMIN_PUBKEY"
  if [[ -n $PUBKEY_PROBLEM ]]; then
    precondition_failed "$PUBKEY_PROBLEM"
  else
    info "ADMIN_PUBKEY: gültiger öffentlicher Schlüssel, $ADMIN_KEY_FPR (${ADMIN_KEY_ID%% *})"
  fi
elif [[ -n $ADMIN_PUBKEY ]]; then
  warn "ADMIN_PUBKEY ist gesetzt, wird im Profil oracle aber nicht verwendet (dort muss der Schlüssel schon in der Schlüsseldatei von $ADMIN_USER stehen)."
fi

# AllowUsers lets in only ADMIN_USER and deploy. Whoever called sudo must be ADMIN_USER,
# otherwise the next SSH login of that user fails.
# lockout_failed USER HOW: HOW says where USER comes from, as the start of the message
# (SUDO_USER: called sudo as USER; audit login UID: logged in as USER).
lockout_failed() { # USER HOW
  precondition_failed "$2, SSH erlaubt danach aber nur '$ADMIN_USER' und $DEPLOY_USER. Damit sperrst du '$1' aus. Aufruf mit passendem Benutzer: sudo ADMIN_USER=$1 bash setup-server.sh"
}
if [[ -n ${SUDO_USER:-} && $SUDO_USER != root && $SUDO_USER != "$ADMIN_USER" ]]; then
  lockout_failed "$SUDO_USER" "Du hast sudo als '$SUDO_USER' aufgerufen"
else
  # Runs whenever SUDO_USER does not already stop the script: SUDO_USER is missing or
  # root (after "sudo -i", "sudo su" or in a root shell), or it equals ADMIN_USER. The
  # latter is checked as well: SUDO_USER only names whoever called sudo, e.g. ubuntu
  # after "su ubuntu" in a session that someone else opened over SSH. The audit login
  # UID names the user who logged in (set by pam_loginuid at login, kept by sudo and
  # su); 4294967295 means not set (e.g. started by a service).
  login_uid=""
  if [[ -r /proc/self/loginuid ]]; then
    login_uid=$(</proc/self/loginuid) || login_uid=""
  fi
  if [[ $login_uid =~ ^[0-9]+$ && $login_uid != 4294967295 && $login_uid != 0 ]]; then
    login_user=$(getent passwd "$login_uid" | cut -d: -f1) || login_user=""
    if [[ -z $login_user ]]; then
      precondition_failed "Du bist mit der UID $login_uid angemeldet (Audit-Login-UID, /proc/self/loginuid), zu der es keinen Benutzer gibt. SSH erlaubt danach nur '$ADMIN_USER' und $DEPLOY_USER. Bitte als $ADMIN_USER anmelden und das Skript mit sudo starten."
    elif [[ $login_user != "$ADMIN_USER" ]]; then
      lockout_failed "$login_user" "Du bist als '$login_user' angemeldet (Audit-Login-UID, /proc/self/loginuid)"
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
# Profile hostinger: the key is not there yet; step 4 installs ADMIN_PUBKEY in
# ~/.ssh/authorized_keys (home from getent passwd, /home/NAME for a user the script
# creates). That file must be one sshd reads for ADMIN_USER, otherwise nothing is changed.
ADMIN_HOME="" ADMIN_AUTH_KEYS=""
if [[ $ADMIN_OK == 1 ]]; then
  if [[ $ADMIN_EXISTS == 1 ]]; then
    ADMIN_HOME=$(getent passwd "$ADMIN_USER" | cut -d: -f6) || ADMIN_HOME=""
  else
    ADMIN_HOME="/home/$ADMIN_USER"
  fi
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
    ADMIN_AUTH_KEYS="$ADMIN_HOME/.ssh/authorized_keys"
    akf_has_target=0
    for f in "${ADMIN_KEY_FILES[@]}"; do
      [[ $f == "$ADMIN_AUTH_KEYS" ]] && akf_has_target=1
    done
    if ((${#ADMIN_KEY_FILES[@]} == 0)); then
      precondition_failed "sshd liest für $ADMIN_USER keine Schlüsseldatei (AuthorizedKeysFile: $akf). Sonst sperrst du dich aus."
    elif hostinger; then
      if ((akf_has_target == 0)); then
        precondition_failed "Das Skript legt den Schlüssel in $ADMIN_AUTH_KEYS ab, sshd liest für $ADMIN_USER aber nur ${ADMIN_KEY_FILES[*]} (AuthorizedKeysFile: $akf). Sonst sperrst du dich aus."
      elif ((key_found == 1)); then
        info "In ${ADMIN_KEY_FILES[*]} stehen schon Schlüssel; ADMIN_PUBKEY wird ergänzt, falls er fehlt."
      fi
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
# the iptables rule set of the image). On Hostinger ufw is installed but inactive too,
# INPUT is open there; step 3 adds the rules. LC_ALL=C: ufw translates its output.
if hostinger; then
  UFW_SCOPE="Dieses Skript setzt eigene iptables-Regeln (Schritt 3) und braucht dafür iptables-persistent."
else
  UFW_SCOPE="Dieses Skript ist für die iptables-Regeln des Oracle-Images geschrieben."
fi
UFW_INACTIVE=0
if pkg_installed ufw || command -v ufw >/dev/null 2>&1; then
  ufw_status=$(LC_ALL=C ufw status 2>&1) || true
  ufw_line=$(grep -m 1 '^Status: ' <<<"$ufw_status") || ufw_line=""
  case $ufw_line in
    "Status: active")
      precondition_failed "UFW ist aktiv. apt würde ufw bei der Installation von iptables-persistent entfernen (ufw: Breaks iptables-persistent, netfilter-persistent). $UFW_SCOPE Erst klären, ob UFW gebraucht wird; UFW nicht einfach abschalten, solange keine anderen Regeln greifen, sonst ist der Server offen."
      ;;
    "Status: inactive")
      UFW_INACTIVE=1
      warn "ufw ist installiert, aber nicht aktiv. apt entfernt ufw bei der Installation von iptables-persistent (ufw: Breaks iptables-persistent, netfilter-persistent)."
      if hostinger; then
        info "HINWEIS ufw: Das ist so gewollt. Die Firewall auf dem Server sind danach die iptables-Regeln aus Schritt 3 (gespeichert in /etc/iptables/rules.v4 und rules.v6, beim Start geladen von netfilter-persistent), dazu die Firewall im hPanel. ufw nicht wieder installieren oder aktivieren: apt würde dafür iptables-persistent entfernen, und ufw verwaltet dieselbe Kette INPUT."
      fi
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
  elif [[ -z $fw_before ]] && hostinger; then
    # Profile hostinger: INPUT is open, step 3 must be able to close it in both families.
    precondition_failed "$fw_tool: INPUT lässt sich nicht lesen. Im Profil hostinger ist INPUT offen und Schritt 3 muss Regeln setzen können (IPv4 und IPv6)."
  elif [[ -z $fw_before ]]; then
    warn "$fw_tool: INPUT nicht lesbar, ob die Paketinstallation die Firewall verändert, bleibt ungeprüft"
  elif [[ $fw_before == "ACCEPT 0" ]] && hostinger; then
    info "$fw_tool: INPUT ist offen (Policy ACCEPT, keine abschließende REJECT- oder DROP-Regel); auf Hostinger erwartet, Schritt 3 schließt INPUT bis auf die nötigen Ausnahmen."
  elif [[ $fw_before == "ACCEPT 0" ]]; then
    warn "$fw_tool: INPUT hat weder eine abschließende REJECT- oder DROP-Regel noch die Policy DROP, eingehende Verbindungen sind nicht gefiltert. Auf Oracle ist das unerwartet (das Image beendet INPUT mit REJECT)."
  fi
done

# Profile hostinger: services that listen on other ports than 22, 80 and 443 (not only
# on loopback) are no longer reachable from outside once step 3 ends INPUT with REJECT.
# Only a hint. docker-proxy is the exception: Docker forwards published ports (DNAT in
# the table nat, then the chain FORWARD), they never pass INPUT.
if hostinger && command -v ss >/dev/null 2>&1; then
  blocked="" via_docker=""
  while read -r proto addr procs; do
    port=${addr##*:}
    host=${addr%:*}
    case $host in 127.* | "[::1]" | "[::ffff:127."*) continue ;; esac
    if [[ $proto == tcp ]]; then
      case $port in 22 | 80 | 443) continue ;; esac
    else
      # Replies to own requests (DNS, NTP) pass as ESTABLISHED; 68 and 546 are the
      # DHCP clients (allowed in step 3).
      case $port in 68 | 546) continue ;; esac
    fi
    if [[ $procs == *'"docker-proxy"'* ]]; then
      [[ ", $via_docker, " == *", $proto/$port, "* ]] || via_docker+="${via_docker:+, }$proto/$port"
    else
      blocked+="${blocked:+, }$proto/$port ($addr${procs:+ $procs})"
    fi
  done < <(
    {
      ss -Hltnp 2>/dev/null | awk '{ print "tcp", $4, $6 }'
      ss -Hlunp 2>/dev/null | awk '{ print "udp", $4, $6 }'
    } | sort -u
  )
  if [[ -n $via_docker ]]; then
    info "Von Docker veröffentlichte Ports ($via_docker) laufen über DNAT und die Kette FORWARD, nicht über INPUT; Schritt 3 ändert für sie nichts."
  fi
  if [[ -n $blocked ]]; then
    warn "Diese Dienste lauschen auf weiteren Ports und sind nach Schritt 3 von außen nicht mehr erreichbar (INPUT endet mit REJECT, offen bleiben nur tcp 22, 80 und 443): $blocked"
  fi
fi

if [[ $PRE_FAILED == 0 ]]; then
  if hostinger; then
    info "in Ordnung: root, Ubuntu $OS_VERSION, ADMIN_USER $ADMIN_USER und ADMIN_PUBKEY gültig, Anmeldung nur mit Schlüssel möglich"
  else
    info "in Ordnung: root, Ubuntu $OS_VERSION, Schlüssel für $ADMIN_USER vorhanden, Anmeldung nur mit Schlüssel möglich"
  fi
fi

# ---------------------------------------------------------------------------
# Docker on Hostinger: daemon.json merged, live-restore, no restart
# ---------------------------------------------------------------------------
# On Hostinger Docker is already installed and runs containers that must not stop:
# Hostinger's Traefik (host network, 80 and 443) and other apps. Restarting dockerd
# stops every container unless live-restore is on. In the profile hostinger the script
# therefore never restarts dockerd. It merges its settings into /etc/docker/daemon.json
# (keys that are there stay as they are, nothing is removed; a copy of the previous
# file is kept as daemon.json.bak-DATE) and reloads dockerd (systemctl reload docker,
# SIGHUP; Docker's documentation on live restore: "you can avoid a restart (and avoid
# any downtime for your containers) by reloading the Docker daemon"). Added if missing:
#   live-restore: true   takes effect with the reload; from then on containers keep
#                        running when dockerd restarts (package update, apt-get
#                        full-upgrade below, manual restart).
#   log-driver: local, log-opts max-size 10m, max-file 3   (max-size and max-file
#                        also when log-driver is json-file or local already). dockerd
#                        reads them only at its next start (reboot, package update),
#                        and they apply only to containers created after that;
#                        existing containers keep their log settings until they are
#                        recreated.
# This runs before apt-get full-upgrade in step 1, so that an update of docker-ce there
# (which restarts dockerd) already finds live-restore on. The merged file is checked
# with dockerd --validate before it is written.
DAEMON_JSON=/etc/docker/daemon.json
DAEMON_MERGE_PY=$(
  cat <<'PY'
import json
import sys

path = sys.argv[1]
try:
    with open(path, encoding="utf-8") as f:
        text = f.read()
except FileNotFoundError:
    text = ""
if text.strip():
    try:
        cfg = json.loads(text)
    except ValueError as e:
        print("ERROR %s ist kein gültiges JSON (%s)." % (path, e))
        sys.exit(3)
    if not isinstance(cfg, dict):
        print("ERROR %s enthält kein JSON-Objekt." % path)
        sys.exit(3)
else:
    cfg = {}
before = json.loads(json.dumps(cfg))
notes = []
drv = cfg.get("log-driver")
if drv is None:
    cfg["log-driver"] = drv = "local"
if drv in ("local", "json-file"):
    opts = cfg.setdefault("log-opts", {})
    if isinstance(opts, dict):
        opts.setdefault("max-size", "10m")
        opts.setdefault("max-file", "3")
    else:
        notes.append("log-opts ist kein Objekt, Log-Grenzen nicht ergänzt.")
else:
    notes.append("log-driver ist %s; das Skript ergänzt keine Log-Grenzen (max-size, max-file)." % drv)
lr = cfg.get("live-restore")
if lr is None:
    cfg["live-restore"] = True
elif lr is not True:
    notes.append("live-restore ist auf %s gesetzt und bleibt so. Ein Neustart von Docker (auch durch ein Paket-Update) stoppt dann alle Container." % json.dumps(lr))
if "hosts" in cfg:
    notes.append("Es gibt einen hosts-Eintrag. Docker soll nicht über TCP erreichbar sein.")
for n in notes:
    print("NOTE " + n)
print("---")
if cfg == before and text.strip():
    sys.stdout.write(text.rstrip("\n") + "\n")
else:
    print(json.dumps(cfg, indent=2, ensure_ascii=False))
PY
)
# docker_daemon_hostinger: merge DAEMON_JSON as described above and reload dockerd if
# the file changed and dockerd runs. Stops the script before any change if the file is
# no valid JSON object or dockerd --validate rejects the result.
docker_daemon_hostinger() {
  local out merged notes rc=0 backup line
  out=$(python3 -I -B -c "$DAEMON_MERGE_PY" "$DAEMON_JSON") || rc=$?
  if ((rc != 0)); then
    echo "Abbruch: $(sed -n 's/^ERROR //p' <<<"$out" | head -n 1) $DAEMON_JSON bleibt, wie es ist; Docker wurde nicht angefasst." >&2
    exit 1
  fi
  notes=$(sed -n '/^---$/q; s/^NOTE //p' <<<"$out")
  merged=$(sed '0,/^---$/d' <<<"$out")
  while IFS= read -r line; do
    [[ -n $line ]] && warn "$DAEMON_JSON: $line"
  done <<<"$notes"
  if [[ -f $DAEMON_JSON ]] && [[ "$(cat "$DAEMON_JSON")" == "$merged" ]]; then
    info "unverändert: $DAEMON_JSON (live-restore und Log-Grenzen gesetzt oder bewusst anders)"
    return 0
  fi
  if ! dry && command -v dockerd >/dev/null 2>&1 && dockerd --help 2>/dev/null | grep -q -- '--validate'; then
    ensure_tmp_dir
    printf '%s
' "$merged" >"$TMP_DIR/daemon.json"
    if ! dockerd --validate --config-file="$TMP_DIR/daemon.json" >/dev/null 2>&1; then
      echo "Abbruch: dockerd --validate lehnt die zusammengeführte Konfiguration ab: $(dockerd --validate --config-file="$TMP_DIR/daemon.json" 2>&1 | tail -n 1). $DAEMON_JSON bleibt, wie es ist." >&2
      exit 1
    fi
  fi
  if [[ -f $DAEMON_JSON ]]; then
    backup="$DAEMON_JSON.bak-$(date +%Y%m%d-%H%M%S)"
    run cp -p -- "$DAEMON_JSON" "$backup"
    info "Sicherung der bisherigen Datei: $backup"
  fi
  put "$DAEMON_JSON" 0644 <<<"$merged" || true
  if dry || systemctl is-active --quiet docker; then
    # SIGHUP: dockerd rereads daemon.json; live-restore takes effect, running
    # containers are not touched.
    run systemctl reload docker
    if ! dry && command -v docker >/dev/null 2>&1; then
      if [[ "$(docker info --format '{{.LiveRestoreEnabled}}' 2>/dev/null)" == true ]]; then
        info "live-restore ist aktiv (docker info): Container laufen bei einem Neustart von Docker weiter."
      else
        warn "live-restore ist laut docker info nicht aktiv. Ein Neustart von Docker (auch durch ein Paket-Update) würde alle Container stoppen. Prüfen: sudo docker info | grep -i 'live restore'"
      fi
    fi
  fi
  info "Log-Treiber und Log-Grenzen aus $DAEMON_JSON liest dockerd erst bei seinem nächsten Start (Neustart des Servers, Paket-Update) und nur für danach neu erstellte Container. Docker startet das Skript nicht neu."
}
DOCKER_DAEMON_DONE=0
if hostinger && command -v docker >/dev/null 2>&1; then
  step "Docker: live-restore vor den Updates (ohne Neustart von Docker)"
  docker_daemon_hostinger
  DOCKER_DAEMON_DONE=1
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
# Table filter of both tools before any package operation (iptables-save -t filter;
# INPUT lives there, and that is what "ufw-init stop" resets), in the temporary
# directory of this run (mode 700, removed on exit), each file only readable by root.
# nat, mangle and raw are left out on purpose: TOOL-restore applies only the tables in
# its input, so they stay as they are (e.g. chains Docker set up meanwhile). Used only if fw_after_packages finds INPUT changed. Only taken if
# fw_state could read INPUT before; without a copy a change still stops the script.
FW_SAVED_V4="" FW_SAVED_V6=""
if ! dry; then
  for fw_tool in iptables ip6tables; do
    if [[ $fw_tool == iptables ]]; then fw_before=$FW_BEFORE_V4; else fw_before=$FW_BEFORE_V6; fi
    [[ -n $fw_before ]] || continue
    ensure_tmp_dir
    fw_file="$TMP_DIR/fw-before.$fw_tool"
    if (umask 077 && "${fw_tool}-save" -t filter >"$fw_file") 2>/dev/null && [[ -s $fw_file ]]; then
      if [[ $fw_tool == iptables ]]; then FW_SAVED_V4=$fw_file; else FW_SAVED_V6=$fw_file; fi
    else
      warn "$fw_tool: ${fw_tool}-save -t filter ist gescheitert, die Regeln vor der Paketinstallation sind nicht gesichert. Verändert die Paketinstallation INPUT, bricht das Skript ab, statt sie wiederherzustellen."
    fi
  done
fi
run apt-get update -q
# full-upgrade: on a fresh server also take updates that add or remove packages
# (e.g. a new kernel package). Not interactive, see APT_OPTS.
run apt-get "${APT_OPTS[@]}" full-upgrade
APT_PKGS=(ca-certificates curl gnupg unattended-upgrades
  fail2ban iptables iptables-persistent netfilter-persistent)
# Profile hostinger: ADMIN_USER gets its root rights through the group sudo.
if hostinger; then APT_PKGS+=(sudo); fi
run apt-get "${APT_OPTS[@]}" install "${APT_PKGS[@]}"

# apt removes ufw for iptables-persistent (see the checks); the prerm of ufw calls
# "ufw-init stop", which can flush INPUT and set its policy to ACCEPT. Compare with the
# state before the installation: if the final REJECT or DROP rule is gone, or the
# policy went from DROP to ACCEPT, the server is open.
# fw_deviation TOOL BEFORE: prints how INPUT of TOOL differs from BEFORE (output of
# fw_state before the packages) in a way that opens the server, nothing if it does not.
fw_deviation() {
  local tool=$1 before=$2 now p0 f0 p1="" f1="" what=""
  read -r p0 f0 <<<"$before"
  if now=$(fw_state "$tool"); then
    read -r p1 f1 <<<"$now"
    if [[ $f0 == 1 && $f1 != 1 ]]; then what="die abschließende REJECT- oder DROP-Regel in INPUT fehlt jetzt"; fi
    if [[ $p0 == DROP && $p1 == ACCEPT ]]; then what="${what:+$what; }die Policy von INPUT ist von DROP auf ACCEPT gewechselt"; fi
  else
    what="INPUT lässt sich nicht mehr lesen"
  fi
  printf '%s' "$what"
}
# fw_after_packages TOOL BEFORE RULES_FILE SAVED: if INPUT of TOOL deviates, load SAVED
# (the copy of the table filter from before the packages, may be empty) with
# TOOL-restore and check again. That is no exception to "never delete rules" (see
# allow_port): no single rule is deleted by number, TOOL-restore (without --noflush)
# replaces the table filter as a whole in one commit and leaves every table that is not
# in the copy (nat, mangle, raw) untouched, and the result is a state the script read
# and found closed before the packages. It runs only after a deviation was found. If the copy is missing, the
# restore fails or INPUT still deviates afterwards: stop. Nothing has been saved
# (autosave false above), the rules files still hold the previous rules.
fw_after_packages() {
  local tool=$1 before=$2 file=$3 saved=$4 what after="" how
  [[ -n $before ]] || return 0
  what=$(fw_deviation "$tool" "$before")
  [[ -n $what ]] || return 0
  if [[ -z $saved ]]; then
    how="Eine Sicherung von vor der Paketinstallation gibt es nicht, nichts wiederhergestellt."
  elif ! "${tool}-restore" <"$saved"; then
    how="Die Wiederherstellung der vor der Paketinstallation gesicherten Tabelle filter mit ${tool}-restore ist gescheitert."
  else
    after=$(fw_deviation "$tool" "$before")
    if [[ -z $after ]]; then
      warn "Firewall nach Paketinstallation wiederhergestellt ($tool: $what). Vermutlich hat apt beim Entfernen von ufw dessen Regeln zurückgesetzt (ufw-init stop). Die vor der Paketinstallation gesicherte Tabelle filter (${tool}-save -t filter) wurde mit ${tool}-restore als Ganzes zurückgespielt, andere Tabellen (nat) blieben unberührt; INPUT hat wieder die abschließende Regel und die Policy von vorher. Prüfen mit: sudo $tool -L INPUT --line-numbers -n"
      return 0
    fi
    how="Die vor der Paketinstallation gesicherte Tabelle filter wurde mit ${tool}-restore zurückgespielt, INPUT weicht danach aber weiter ab ($after)."
  fi
  {
    echo "Abbruch: Die Firewall wurde durch die Paketinstallation verändert ($tool: $what). Vermutlich hat apt beim Entfernen von ufw dessen Regeln zurückgesetzt (ufw-init stop). Eingehende Verbindungen sind damit womöglich nicht mehr gefiltert. $how"
    echo "Gespeichert wurde nichts: $file enthält, falls vorhanden, noch die bisherigen Regeln. Ein Neustart lädt sie wieder (netfilter-persistent), sofort von Hand: sudo ${tool}-restore < $file"
    echo "Danach mit sudo $tool -L INPUT --line-numbers -n prüfen und das Skript erneut starten."
  } >&2
  exit 1
}
if dry; then
  info "[Testlauf] Vor der Paketinstallation sichert ein echter Lauf die Tabelle filter (iptables-save -t filter, ip6tables-save -t filter) in eine temporäre Datei. Danach prüft er, ob INPUT (IPv4 und IPv6) noch die abschließende REJECT- oder DROP-Regel und die Policy von vorher hat; sonst spielt er sie mit iptables-restore bzw. ip6tables-restore zurück (nur filter, nat bleibt unberührt) und prüft erneut. Hilft das nicht: Abbruch ohne Speichern."
else
  fw_after_packages iptables "$FW_BEFORE_V4" /etc/iptables/rules.v4 "$FW_SAVED_V4"
  fw_after_packages ip6tables "$FW_BEFORE_V6" /etc/iptables/rules.v6 "$FW_SAVED_V6"
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
# 3. Firewall (iptables: rules of the Oracle image, or own rules on Hostinger; no UFW)
# ---------------------------------------------------------------------------
# Oracle's Ubuntu images ship iptables rules (/etc/iptables/rules.v4) that end INPUT
# with "REJECT --reject-with icmp-host-prohibited". New ACCEPT rules must go before it;
# the same for an unconditional "-j DROP" at the end of INPUT.
# The script only inserts rules and never deletes one (reason at allow_port). Putting
# back the copy from before the packages in step 1 is no deletion (fw_after_packages).
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
#
# Profile hostinger: INPUT is open there (policy ACCEPT, no rules, IPv4 and IPv6). The
# script appends, in this order and only if missing: loopback, replies to own
# connections (RELATED,ESTABLISHED; without it the running SSH session and every
# reply to apt, DNS and NTP would be cut), ICMP (IPv6: all of ICMPv6, which neighbour
# discovery and router advertisements need; without them IPv6 stops working), the DHCP
# client (as in ufw's before.rules: udp 67 -> 68, and for DHCPv6 udp 547 -> 546 between
# link-local addresses; replies to a DHCPv6 request sent to a multicast address are not
# seen as ESTABLISHED), tcp 22, 80 and 443, and as the last rule a REJECT. The REJECT
# is appended only after every ACCEPT rule is in place. The policy stays ACCEPT.
# FORWARD, the DOCKER* chains and the table nat stay untouched: ports that Docker
# publishes (e.g. 0.0.0.0:32768 of another container) are forwarded with DNAT and
# FORWARD and never pass INPUT, so they stay reachable; they can only be restricted in
# the chain DOCKER-USER, which this script leaves alone. Traefik of Hostinger (host
# network, 80 and 443) passes INPUT and is covered by the rules for 80 and 443. Its
# connections to containers leave through OUTPUT; the replies come in over docker0 or
# br-* and pass as RELATED,ESTABLISHED. Connections that containers open to the host
# itself (not to a published port) pass INPUT as well: to 22, 80 and 443 they are
# accepted, to any other port of the host they are rejected. There is deliberately no
# "-i docker0 -j ACCEPT" or "-i br-+ -j ACCEPT": that would open every service of the
# host to every container. Health checks of Docker run inside the container and are
# not affected. A service of the host that containers need gets its own rule before
# the REJECT (interface and port), see docs/server.md.
# Saved: only the table filter with the policies and the INPUT rules whose target is a
# built-in one (see save_filter_input), not with netfilter-persistent save: that would
# also save Docker's chains and nat rules with the container addresses of today, which
# would come back at boot before Docker sets up its own.
# The hPanel of Hostinger has its own firewall in front of the server as well.

step "Firewall: Ports 22, 80 und 443"
FW_CHANGED=0
DRY_SHIFT=0

# Number of the first rule in INPUT that turns other traffic away, empty if there is
# none: a REJECT rule, or an unconditional DROP rule (comments do not count as a
# condition); the same test as fw_state, see FINAL_RULE_AWK. No early exit in awk: with
# pipefail, iptables could otherwise fail on a closed pipe.
reject_pos() {
  "$1" -S INPUT | awk "$FINAL_RULE_AWK"'
      $1 == "-A" && !found { n++; if (final_rule($0)) { print n; found = 1 } }'
}

# rule_numbers TOOL RULE...: numbers of the rules in INPUT that equal RULE exactly.
rule_numbers() {
  local tool=$1
  shift
  "$tool" -S INPUT | awk -v want="-A INPUT $*" '$1 == "-A" { n++; if ($0 == want) print n }'
}

# ensure_accept TOOL DESC RULE...: make sure the ACCEPT rule RULE (as iptables -S
# prints it, without "-A INPUT") sits in INPUT before the REJECT rule (or the
# unconditional DROP rule, see reject_pos; "REJECT" below stands for both). DESC names
# the rule in messages, e.g. "Port 22". allow_port uses it for the ports.
# A rule only counts if it sits before the first REJECT; one behind it has no effect.
#
# The script never deletes or replaces firewall rules (no -D, no -R), it only inserts.
# iptables deletes and replaces by rule number, and other programs (fail2ban, Docker)
# may insert rules into INPUT at any time. Between reading the number and deleting,
# the number can then point to another rule, e.g. the REJECT, and the server would be
# open. A copy behind the REJECT therefore stays; the script only warns about it.
ensure_accept() {
  local tool=$1 desc=$2 pos n before=0 after=0 open_note
  shift 2
  local rule=("$@")
  pos=$(reject_pos "$tool")
  if "$tool" -C INPUT "${rule[@]}" 2>/dev/null; then
    if [[ -z $pos ]]; then
      info "$tool: $desc ist schon offen"
      return
    fi
    for n in $(rule_numbers "$tool" "${rule[@]}"); do
      if ((n < pos)); then before=1; else after=1; fi
    done
    if ((before == 0 && after == 0)); then
      # -C finds the rule, but iptables -S prints it differently: do not guess.
      warn "$tool: Position der ACCEPT-Regel für $desc nicht ermittelbar, nichts geändert. Prüfen mit: sudo $tool -L INPUT --line-numbers -n"
      return
    fi
  fi
  if ((before == 1)); then
    info "$tool: $desc ist schon offen"
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
    local subject="der Port" save_hint="sudo netfilter-persistent save"
    [[ $desc == "Port "* ]] || subject="der Verkehr"
    # Profile hostinger: saved by the script itself (only the table filter, step 3).
    if hostinger; then save_hint="das Skript erneut starten"; fi
    if ((before == 0)) && dry; then
      open_note="$subject wäre durch die eingefügte Regel davor offen"
    else
      open_note="$subject ist durch die Regel davor offen"
    fi
    warn "$tool: Hinter der abweisenden Regel (REJECT oder DROP) steht eine ACCEPT-Regel für $desc. Sie ist wirkungslos ($open_note) und kann von Hand entfernt werden. Das Skript löscht keine Firewall-Regeln. Regelnummer anzeigen mit: sudo $tool -L INPUT --line-numbers -n (danach speichern: $save_hint)"
  fi
}

# allow_port TOOL PORT: accept new TCP connections to PORT (ensure_accept).
allow_port() {
  ensure_accept "$1" "Port $2" -p tcp -m state --state NEW -m tcp --dport "$2" -j ACCEPT
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

# Profile hostinger: the rules INPUT needs before its final REJECT, per family, as
# iptables -S prints them (without "-A INPUT"), each with a name for the messages. One
# rule per line, the name before the first "|".
hostinger_rules() {
  if [[ $1 == iptables ]]; then
    cat <<'RULES'
Loopback (lo)|-i lo -j ACCEPT
Antworten auf eigene Verbindungen (RELATED,ESTABLISHED)|-m state --state RELATED,ESTABLISHED -j ACCEPT
ICMP|-p icmp -j ACCEPT
DHCP-Client (udp 67 -> 68)|-p udp -m udp --sport 67 --dport 68 -j ACCEPT
RULES
  else
    cat <<'RULES'
Loopback (lo)|-i lo -j ACCEPT
Antworten auf eigene Verbindungen (RELATED,ESTABLISHED)|-m state --state RELATED,ESTABLISHED -j ACCEPT
ICMPv6 (mit Neighbor Discovery)|-p ipv6-icmp -j ACCEPT
DHCPv6-Client (udp 547 -> 546, link-local)|-s fe80::/10 -d fe80::/10 -p udp -m udp --sport 547 --dport 546 -j ACCEPT
RULES
  fi
}
# hostinger_reject TOOL: the final rule the profile hostinger appends.
hostinger_reject() {
  if [[ $1 == iptables ]]; then
    echo "-j REJECT --reject-with icmp-port-unreachable"
  else
    echo "-j REJECT --reject-with icmp6-port-unreachable"
  fi
}
# hostinger_missing TOOL: names of the needed ACCEPT rules (hostinger_rules and tcp
# 22/80/443) that are not in INPUT before the first REJECT; nothing if all are. Without
# a REJECT rule a rule anywhere in INPUT counts.
hostinger_missing() {
  local tool=$1 desc spec pos n found missing="" port
  local -a rule
  pos=$(reject_pos "$tool")
  while IFS='|' read -r desc spec; do
    [[ -n $desc ]] || continue
    read -r -a rule <<<"$spec"
    found=0
    for n in $(rule_numbers "$tool" "${rule[@]}"); do
      if [[ -z $pos ]] || ((n < pos)); then found=1; fi
    done
    ((found)) || missing+="${missing:+, }$desc"
  done < <(
    hostinger_rules "$tool"
    for port in 22 80 443; do echo "Port $port|-p tcp -m state --state NEW -m tcp --dport $port -j ACCEPT"; done
  )
  printf '%s' "$missing"
}
# close_input TOOL (profile hostinger): append the missing ACCEPT rules (ensure_accept,
# allow_port), then the final REJECT, unless INPUT has a REJECT or unconditional DROP
# rule already (then the ACCEPT rules go before it, as on Oracle). Only inserts and
# appends, never deletes. Before the REJECT is appended, every ACCEPT rule must be
# there (hostinger_missing), otherwise the script stops without appending it.
close_input() {
  local tool=$1 desc spec port missing final
  local -a rule
  DRY_SHIFT=0
  while IFS='|' read -r desc spec; do
    [[ -n $desc ]] || continue
    read -r -a rule <<<"$spec"
    ensure_accept "$tool" "$desc" "${rule[@]}"
  done < <(hostinger_rules "$tool")
  for port in 22 80 443; do allow_port "$tool" "$port"; done
  if [[ -n "$(reject_pos "$tool")" ]]; then
    info "$tool: INPUT endet schon mit einer abweisenden Regel (REJECT oder DROP, Regel $(reject_pos "$tool"))"
  else
    read -r -a final <<<"$(hostinger_reject "$tool")"
    if ! dry; then
      missing=$(hostinger_missing "$tool")
      if [[ -n $missing ]]; then
        echo "Abbruch: $tool: In INPUT fehlen vor dem abschließenden REJECT noch: $missing. REJECT nicht angehängt, INPUT bleibt offen. Prüfen mit: sudo $tool -S INPUT" >&2
        exit 1
      fi
    fi
    run "$tool" -A INPUT "${final[@]}"
    FW_CHANGED=1
    changed
  fi
  if ! dry; then
    missing=$(hostinger_missing "$tool")
    if [[ -n $missing ]]; then
      echo "Abbruch: $tool: Vor der abweisenden Regel in INPUT fehlen: $missing. Prüfen mit: sudo $tool -L INPUT --line-numbers -n" >&2
      exit 1
    fi
    info "in Ordnung: $tool: vor der abweisenden Regel in INPUT stehen $(hostinger_rules "$tool" | cut -d'|' -f1 | paste -sd, - | sed 's/,/, /g'), tcp 22, 80 und 443"
  fi
}

# save_filter_input TOOL (profile hostinger): prints the rules file for TOOL: the table
# filter with the policies of INPUT, FORWARD and OUTPUT as they are and the rules of
# INPUT whose target is built in (ACCEPT, DROP, REJECT, RETURN, LOG). Jumps into other
# chains (fail2ban's f2b-sshd, which fail2ban sets up again at its start) and every
# other chain (Docker's FORWARD rules and DOCKER* chains, which Docker sets up at its
# start) are left out, as are the other tables (nat): at boot netfilter-persistent
# loads this file before Docker and fail2ban start, and TOOL-restore replaces only the
# table filter. Counters are set to 0, so the file only changes with the rules.
save_filter_input() {
  local tool=$1
  echo "# Managed by deploy/setup-server.sh (profile hostinger): table filter, rules of INPUT only."
  echo "# Docker and fail2ban set up their own chains when they start."
  "${tool}-save" -t filter | awk '
    $1 == "*filter" { print; next }
    $1 == ":INPUT" || $1 == ":FORWARD" || $1 == ":OUTPUT" { print $1, $2, "[0:0]"; next }
    $1 == "-A" && $2 == "INPUT" {
      t = ""
      for (i = 3; i < NF; i++) if ($i == "-j") t = $(i + 1)
      if (t == "ACCEPT" || t == "DROP" || t == "REJECT" || t == "RETURN" || t == "LOG") print
      next
    }
    $1 == "COMMIT" { print }'
}

if ! iptables -L INPUT -n >/dev/null 2>&1; then
  if dry && hostinger; then
    info "[Testlauf] iptables nicht lesbar (kein root). Ein echter Lauf hängt an INPUT (IPv4 und IPv6) an, was fehlt: ACCEPT für Loopback, RELATED,ESTABLISHED, ICMP bzw. ICMPv6, den DHCP-Client, tcp 22, 80 und 443, danach REJECT."
  elif dry; then
    info "[Testlauf] iptables nicht lesbar (kein root). Ein echter Lauf ermittelt die REJECT- oder abschließende DROP-Regel in INPUT und fügt davor ACCEPT für tcp 22, 80, 443 ein, falls sie fehlen."
  else
    echo "Abbruch: iptables lässt sich nicht lesen." >&2
    exit 1
  fi
elif hostinger; then
  close_input iptables
  if ip6tables -L INPUT -n >/dev/null 2>&1; then
    close_input ip6tables
  else
    echo "Abbruch: ip6tables lässt sich nicht lesen, IPv6 bliebe offen." >&2
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

if hostinger; then
  # Written on every run if the content differs (put), checked first with TOOL-restore
  # --test, which loads nothing. An earlier rules file (e.g. from netfilter-persistent
  # save) is replaced by this one, after a copy FILE.bak-DATE.
  if dry || ! iptables -L INPUT -n >/dev/null 2>&1; then
    info "[Testlauf] würde /etc/iptables/rules.v4 und rules.v6 schreiben (Modus 0640): Tabelle filter mit den Policies und den Regeln von INPUT (ohne Sprünge in andere Ketten), ohne Docker-Ketten und ohne Tabelle nat. Vorher Prüfung mit iptables-restore --test bzw. ip6tables-restore --test; eine vorhandene Datei mit anderem Inhalt wird vorher als .bak-DATUM gesichert."
  else
    for fw_tool in iptables ip6tables; do
      if [[ $fw_tool == iptables ]]; then fw_file=/etc/iptables/rules.v4; else fw_file=/etc/iptables/rules.v6; fi
      fw_rules=$(save_filter_input "$fw_tool") ||
        { echo "Abbruch: ${fw_tool}-save -t filter ist gescheitert, die Regeln sind nicht gespeichert (sie gelten bis zum nächsten Neustart)." >&2; exit 1; }
      if ! grep -qE -- "^-A INPUT .*-j (REJECT|DROP)( |$)" <<<"$fw_rules"; then
        echo "Abbruch: $fw_tool: Die zu speichernden Regeln enthalten keine abweisende Regel in INPUT, nichts gespeichert." >&2
        exit 1
      fi
      # Checked only when the file is to be written (a second run only reads). An
      # existing file with other content is kept as FILE.bak-DATE first.
      if [[ ! -f $fw_file || "$(cat "$fw_file")" != "$fw_rules" ]]; then
        "${fw_tool}-restore" --test <<<"$fw_rules" ||
          { echo "Abbruch: ${fw_tool}-restore --test lehnt die zu speichernden Regeln ab, $fw_file bleibt unverändert." >&2; exit 1; }
        if [[ -f $fw_file ]]; then
          fw_backup="$fw_file.bak-$(date +%Y%m%d-%H%M%S)"
          cp -p -- "$fw_file" "$fw_backup" ||
            { echo "Abbruch: Sicherung $fw_backup ließ sich nicht anlegen, $fw_file bleibt unverändert." >&2; exit 1; }
          info "Sicherung der bisherigen Datei: $fw_backup"
        fi
      fi
      put "$fw_file" 0640 <<<"$fw_rules" || true
    done
  fi
elif [[ $FW_CHANGED == 1 ]]; then
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
# 4a. Admin user (profile hostinger)
# ---------------------------------------------------------------------------
# On Hostinger the operator logs in as root; there is no other user yet. The script
# creates ADMIN_USER (home /home/NAME, bash, own group), adds it to the group sudo and
# puts ADMIN_PUBKEY into ~/.ssh/authorized_keys (directory 700, file 600, owned by the
# user), all before the SSH step reloads sshd. Idempotent: an existing user, membership
# and key (same type and base64 part, whatever the comment) stay as they are; other
# keys in the file are kept.
# sudo asks for the user's password (no NOPASSWD). The script sets no password: the
# operator sets one as root with "passwd ADMIN_USER" (shown at the end). Until then the
# account has no usable password; with UsePAM yes (checked in step 4) that does not
# stop the login with the key, only sudo. root keeps its password for the web console.

if hostinger && dry && [[ -z $ADMIN_AUTH_KEYS || -z $ADMIN_KEY_ID ]]; then
  step "Admin-Benutzer (Gruppe sudo, SSH-Schlüssel)"
  info "[Testlauf] übersprungen: ADMIN_USER, ADMIN_PUBKEY oder die Schlüsseldatei sind nicht geprüft (siehe Prüfungen). Ein echter Lauf bricht vorher ab."
elif hostinger; then
  step "Admin-Benutzer $ADMIN_USER (Gruppe sudo, SSH-Schlüssel)"
  if ! getent group sudo >/dev/null 2>&1; then
    echo "Abbruch: Die Gruppe sudo fehlt (sonst bekäme $ADMIN_USER keine Root-Rechte)." >&2
    exit 1
  fi
  if id "$ADMIN_USER" >/dev/null 2>&1; then
    info "unverändert: Benutzer $ADMIN_USER existiert"
  else
    run useradd --create-home --home-dir "$ADMIN_HOME" --shell /bin/bash --user-group "$ADMIN_USER"
    dry || info "angelegt: Benutzer $ADMIN_USER (Home $ADMIN_HOME, Shell /bin/bash, ohne Passwort)"
    changed
  fi
  if id -nG "$ADMIN_USER" 2>/dev/null | tr ' ' '\n' | grep -qx sudo; then
    info "unverändert: $ADMIN_USER ist in der Gruppe sudo"
  else
    run usermod -aG sudo "$ADMIN_USER"
    dry || info "$ADMIN_USER ist jetzt in der Gruppe sudo"
    changed
  fi
  if id "$ADMIN_USER" >/dev/null 2>&1; then
    ADMIN_GROUP=$(id -gn "$ADMIN_USER")
  else
    ADMIN_GROUP=$ADMIN_USER # dry run: useradd --user-group would create it
  fi
  ADMIN_SSH="$ADMIN_HOME/.ssh"
  # sshd (StrictModes) ignores the key if the home directory, ~/.ssh or the file can be
  # written by others, and a symlink here could make root write elsewhere.
  if [[ -d $ADMIN_HOME ]]; then
    home_mode=$(stat -c %a "$ADMIN_HOME")
    if (((8#$home_mode & 8#022) != 0)); then
      echo "Abbruch: $ADMIN_HOME ist für Gruppe oder andere beschreibbar (Modus $home_mode); sshd würde den Schlüssel ignorieren. Erst korrigieren, z. B. chmod 750 $ADMIN_HOME." >&2
      exit 1
    fi
  fi
  for f in "$ADMIN_SSH" "$ADMIN_AUTH_KEYS"; do
    if [[ -L $f ]]; then
      echo "Abbruch: $f ist ein symbolischer Link. Das Skript schreibt dort nicht hinein; bitte prüfen." >&2
      exit 1
    fi
  done
  # fix_owner_mode PATH MODE: owner ADMIN_USER:ADMIN_GROUP and MODE, only if different.
  fix_owner_mode() {
    local path=$1 mode=$2 cur
    cur=$(stat -c '%U:%G %a' "$path")
    if [[ $cur != "$ADMIN_USER:$ADMIN_GROUP ${mode#0}" ]]; then
      run chown "$ADMIN_USER:$ADMIN_GROUP" "$path"
      run chmod "$mode" "$path"
      changed
    fi
  }
  if [[ -d $ADMIN_SSH ]]; then
    fix_owner_mode "$ADMIN_SSH" 0700
  else
    run install -d -o "$ADMIN_USER" -g "$ADMIN_GROUP" -m 700 "$ADMIN_SSH"
    changed
  fi
  key_present=0
  if [[ -f $ADMIN_AUTH_KEYS ]] && awk -v t="${ADMIN_KEY_ID%% *}" -v b="${ADMIN_KEY_ID#* }" '
      { for (i = 1; i < NF; i++) if ($i == t && $(i + 1) == b) f = 1 }
      END { exit !f }' "$ADMIN_AUTH_KEYS"; then
    key_present=1
  fi
  if ((key_present)); then
    info "unverändert: Schlüssel $ADMIN_KEY_FPR steht in $ADMIN_AUTH_KEYS"
    fix_owner_mode "$ADMIN_AUTH_KEYS" 0600
  elif dry; then
    info "[Testlauf] würde $ADMIN_AUTH_KEYS ${ADMIN_KEY_FPR:+um den Schlüssel $ADMIN_KEY_FPR }ergänzen (Besitzer $ADMIN_USER:$ADMIN_GROUP, Modus 600, Verzeichnis 700):"
    printf '      | %s\n' "$ADMIN_KEY_LINE"
    changed
  else
    old_keys=""
    if [[ -f $ADMIN_AUTH_KEYS ]]; then old_keys=$(cat "$ADMIN_AUTH_KEYS"); fi
    tmp="$ADMIN_AUTH_KEYS.tmp.$$"
    if ! { if [[ -n $old_keys ]]; then printf '%s\n' "$old_keys"; fi; printf '%s\n' "$ADMIN_KEY_LINE"; } >"$tmp" ||
      ! chown "$ADMIN_USER:$ADMIN_GROUP" "$tmp" || ! chmod 600 "$tmp" || ! mv -f "$tmp" "$ADMIN_AUTH_KEYS"; then
      rm -f -- "$tmp"
      echo "Abbruch: $ADMIN_AUTH_KEYS ließ sich nicht schreiben. SSH wurde nicht geändert." >&2
      exit 1
    fi
    info "Schlüssel $ADMIN_KEY_FPR in $ADMIN_AUTH_KEYS eingetragen"
    changed
  fi
fi

# ---------------------------------------------------------------------------
# 4. SSH
# ---------------------------------------------------------------------------

if hostinger; then
  step "SSH: nur Schlüssel, kein root (außer Web-Konsole von $CONSOLE_ADDR), nur $ADMIN_USER, $DEPLOY_USER und root@$CONSOLE_ADDR"
else
  step "SSH: nur Schlüssel, kein root, nur $ADMIN_USER und $DEPLOY_USER"
fi
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
# sshd_check_failed REASON [CAUSE]: a check of the sshd configuration failed; stop
# without reloading ssh. If this run wrote the drop-in, put the previous file back (or
# remove the new one). If the drop-in is unchanged (from an earlier run), it stays, and
# the abort message says what to do, by CAUSE:
#   rundir  /run/sshd could not be created; the configuration was not checked at all.
#   error   sshd -t or sshd -T failed (syntax error, missing host key, ...).
#   config  (default) the configuration sshd reads, with the unchanged drop-in, fails
#           a check: another file changed since the last run (a later drop-in, a Match
#           block, a package update), or the check is new in this version of the script.
sshd_check_failed() {
  local ok=1 why
  if [[ $SSHD_CHANGED != 1 ]]; then
    case ${2:-config} in
      rundir) why="Die Konfiguration von sshd wurde nicht geprüft: ohne das Laufzeitverzeichnis /run/sshd scheitern sshd -t und sshd -T. Ursache ist das System (z. B. /run nicht beschreibbar oder voll), nicht die Konfiguration." ;;
      error) why="sshd selbst meldet einen Fehler (z. B. Syntaxfehler in einer Datei von sshd_config oder sshd_config.d, fehlender Host-Schlüssel); die Meldung von sshd steht darüber bzw. zeigt sudo sshd -t." ;;
      *) why="Die bestehende Konfiguration von sshd (mit dieser unveränderten Datei) erfüllt eine Prüfung nicht. Entweder hat sich seit dem letzten Lauf eine andere Datei geändert (ein späteres Drop-in, ein Match-Block, ein Paket-Update), oder die Prüfung ist in dieser Fassung des Skripts neu." ;;
    esac
    {
      echo "Abbruch: $1"
      echo "$SSHD_CONF ist unverändert (dieser Lauf hat sie nicht geändert) und bleibt, wie sie ist; SSH wurde nicht neu geladen. $why"
      echo "Was zu tun ist: die genannte Ursache beheben, mit sudo sshd -t und sudo sshd -T -C $SSHD_TEST_SPEC prüfen und das Skript erneut starten. Bis dahin ssh nicht neu starten oder neu laden; auch ein Neustart des Servers (etwa der automatische um 04:00) übernimmt die Konfiguration, wie sie jetzt ist."
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
# does not take effect or ADMIN_USER would be locked out. sshd takes the first value it
# reads for PasswordAuthentication and the like. GSSAPIAuthentication and
# HostbasedAuthentication are checked like PasswordAuthentication: both are further
# ways to log in without the key (Kerberos, a trusted host).
check_sshd_effective() {
  local view=$1 eff=$2 setting key problem admin_groups
  # Without ADMIN_USER in AllowUsers the next login fails: never reload like that.
  problem=$(sshd_allowusers_problem "$view" "$eff" "$ADMIN_USER")
  [[ -z $problem ]] || sshd_check_failed "$problem"
  for setting in "passwordauthentication no" "kbdinteractiveauthentication no" "permitrootlogin no" \
    "gssapiauthentication no" "hostbasedauthentication no"; do
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
# check_sshd_deploy VIEW OUTPUT: checks for the user deploy of the CI, only as warnings:
# the admin login is not affected, the deploy of the CI would fail. Checked: AllowUsers
# lets deploy in; DenyUsers, AllowGroups and DenyGroups do not keep it out; a key alone
# is enough to log in (PubkeyAuthentication yes, AuthenticationMethods any or a list of
# only publickey; sshd_auth_problem). Not checked: deploy's authorized_keys, which stays
# empty until the CI key is added by hand (docs/server.md). On a fresh server deploy is
# created only in step 8, with its own group and in the group docker; those are the
# groups checked then.
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
  problem=$(sshd_auth_problem "$view" "$eff")
  if [[ -n $problem ]]; then
    warn "$problem Das gilt für $DEPLOY_USER (Anmeldung der CI nur mit Schlüssel). Der Zugang für $ADMIN_USER ist nicht betroffen, aber das Deploy der CI als $DEPLOY_USER würde scheitern."
  fi
}
# sshd_expect VIEW OUTPUT SETTING...: stop (sshd_check_failed) unless OUTPUT (what
# sshd -T, as VIEW, prints) has every SETTING ("keyword value") as a line.
sshd_expect() {
  local view=$1 eff=$2 setting key
  shift 2
  for setting in "$@"; do
    if ! grep -qx "$setting" <<<"$eff"; then
      key=${setting%% *}
      sshd_check_failed "sshd verwendet nicht '$setting' (laut $view: '$(awk -v k="$key" '$1 == k' <<<"$eff" | tr '\n' ' ')'). Dateien mit $key: $(sshd_candidates "$key")."
    fi
  done
}
# check_sshd_hostinger: the checks only the profile hostinger needs (each failure stops
# and puts the previous drop-in back):
#   root from the internet ($SSHD_ROOT_PUBLIC_SPEC): PermitRootLogin, PasswordAuthentication
#     and KbdInteractiveAuthentication no, and no AllowUsers entry for root from there;
#   root from the web console ($SSHD_ROOT_CONSOLE_SPEC): PermitRootLogin and
#     PasswordAuthentication yes, AllowUsers root@$CONSOLE_ADDR;
#   deploy from the internet ($SSHD_DEPLOY_SPEC): only the key (PasswordAuthentication and
#     KbdInteractiveAuthentication no, PubkeyAuthentication yes);
#   ADMIN_USER and deploy from the web console's address ($SSHD_ADMIN_CONSOLE_SPEC,
#     $SSHD_DEPLOY_CONSOLE_SPEC): only the key (PasswordAuthentication and
#     KbdInteractiveAuthentication no, PubkeyAuthentication yes); the exception is for
#     root only;
#   ADMIN_USER from the internet: UsePAM yes (the account has no password until the
#     operator sets one; without PAM sshd refuses a locked account even with a key).
# ADMIN_USER from the internet is checked like on Oracle (check_sshd_effective).
check_sshd_hostinger() {
  local eff pat spec
  eff=$(sshd -T -C "$SSHD_ROOT_PUBLIC_SPEC" 2>/dev/null) ||
    sshd_check_failed "sshd -T -C $SSHD_ROOT_PUBLIC_SPEC meldet einen Fehler." error
  sshd_expect "sshd -T -C $SSHD_ROOT_PUBLIC_SPEC" "$eff" "permitrootlogin no" \
    "passwordauthentication no" "kbdinteractiveauthentication no"
  while read -r pat; do
    [[ -n $pat ]] || continue
    # shellcheck disable=SC2053 # the right side is a pattern on purpose
    if [[ root == ${pat%%@*} ]] && [[ $pat != *@* || ${pat#*@} != "$CONSOLE_ADDR" ]]; then
      sshd_check_failed "AllowUsers lässt root nicht nur von der Web-Konsole herein (Eintrag '$pat' laut sshd -T -C $SSHD_ROOT_PUBLIC_SPEC). Dateien mit AllowUsers: $(sshd_candidates allowusers)."
    fi
  done < <(awk '$1 == "allowusers" { print $2 }' <<<"$eff")
  eff=$(sshd -T -C "$SSHD_ROOT_CONSOLE_SPEC" 2>/dev/null) ||
    sshd_check_failed "sshd -T -C $SSHD_ROOT_CONSOLE_SPEC meldet einen Fehler." error
  sshd_expect "sshd -T -C $SSHD_ROOT_CONSOLE_SPEC" "$eff" "permitrootlogin yes" \
    "passwordauthentication yes" "allowusers root@$CONSOLE_ADDR"
  eff=$(sshd -T -C "$SSHD_DEPLOY_SPEC" 2>/dev/null) ||
    sshd_check_failed "sshd -T -C $SSHD_DEPLOY_SPEC meldet einen Fehler." error
  sshd_expect "sshd -T -C $SSHD_DEPLOY_SPEC" "$eff" "passwordauthentication no" \
    "kbdinteractiveauthentication no" "pubkeyauthentication yes"
  eff=$(sshd -T -C "$SSHD_TEST_SPEC" 2>/dev/null) ||
    sshd_check_failed "sshd -T -C $SSHD_TEST_SPEC meldet einen Fehler." error
  sshd_expect "sshd -T -C $SSHD_TEST_SPEC" "$eff" "usepam yes"
  for spec in "$SSHD_ADMIN_CONSOLE_SPEC" "$SSHD_DEPLOY_CONSOLE_SPEC"; do
    eff=$(sshd -T -C "$spec" 2>/dev/null) ||
      sshd_check_failed "sshd -T -C $spec meldet einen Fehler." error
    sshd_expect "sshd -T -C $spec" "$eff" "passwordauthentication no" \
      "kbdinteractiveauthentication no" "pubkeyauthentication yes"
  done
}
# Profile hostinger: an exception for the web console (SSH from CONSOLE_ADDR as root
# with password). sshd takes the first value it reads; this file comes first (10-), so
# its global values win over 50-cloud-init.conf (PasswordAuthentication yes) and
# 60-cloudimg-settings.conf. Inside Match blocks the first value of the matching blocks
# wins, also here the one from this file. A Match block in a file read by Include ends
# with that file (OpenSSH 9.6: the files after it, e.g. 50-cloud-init.conf and the rest
# of sshd_config, still apply to all connections; check_sshd_hostinger and the global
# sshd -T verify the result). "Match all" closes the block explicitly anyway.
if hostinger; then
  SSHD_CONTENT="# Managed by deploy/setup-server.sh (profile hostinger)
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
GSSAPIAuthentication no
HostbasedAuthentication no
AllowUsers ${ADMIN_USER} ${DEPLOY_USER} root@${CONSOLE_ADDR}
# Web console of Hostinger (hPanel): SSH from ${CONSOLE_ADDR} as root with password.
# Only root; ${ADMIN_USER} and ${DEPLOY_USER} keep the key only, also from there.
Match User root Address ${CONSOLE_ADDR}
    PermitRootLogin yes
    PasswordAuthentication yes
Match all"
else
  SSHD_CONTENT="# Managed by deploy/setup-server.sh
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
GSSAPIAuthentication no
HostbasedAuthentication no
AllowUsers ${ADMIN_USER} ${DEPLOY_USER}"
fi
if put "$SSHD_CONF" 0644 <<<"$SSHD_CONTENT"; then
  SSHD_CHANGED=1
fi
# The checks only read and run on every real run, also when the drop-in is unchanged:
# another file (a later drop-in, a Match block, a package update) can have changed the
# effective configuration since the last run.
if ! dry; then
  # The checks created /run/sshd; a package update in step 1 may have stopped ssh since,
  # which removes it again. Without it sshd -t fails.
  [[ -d /run/sshd ]] || install -d -m 0755 /run/sshd ||
    sshd_check_failed "/run/sshd ließ sich nicht anlegen (nötig für sshd -t)." rundir
  sshd -t || sshd_check_failed "sshd -t meldet einen Fehler." error
  effective=$(sshd -T 2>/dev/null) || sshd_check_failed "sshd -T meldet einen Fehler, die wirksame Konfiguration ist unbekannt." error
  effective_admin=$(sshd -T -C "$SSHD_TEST_SPEC" 2>/dev/null) ||
    sshd_check_failed "sshd -T -C $SSHD_TEST_SPEC meldet einen Fehler, die wirksame Konfiguration für $ADMIN_USER ist unbekannt." error
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
  if hostinger; then
    check_sshd_hostinger
    # Do not lock yourself out: the key of ADMIN_USER must be in place before sshd is
    # reloaded (step 4a wrote it; checked again here, on every run).
    if [[ $(key_file_state "$ADMIN_AUTH_KEYS") != yes ]] ||
      ! awk -v t="${ADMIN_KEY_ID%% *}" -v b="${ADMIN_KEY_ID#* }" '
          { for (i = 1; i < NF; i++) if ($i == t && $(i + 1) == b) f = 1 }
          END { exit !f }' "$ADMIN_AUTH_KEYS"; then
      sshd_check_failed "Der Schlüssel aus ADMIN_PUBKEY steht nicht in $ADMIN_AUTH_KEYS. Ohne ihn wäre $ADMIN_USER ausgesperrt."
    fi
    if [[ "$(stat -c '%U %a' "$ADMIN_HOME/.ssh" "$ADMIN_AUTH_KEYS" | tr '\n' ' ')" != "$ADMIN_USER 700 $ADMIN_USER 600 " ]]; then
      sshd_check_failed "Besitzer oder Modus von $ADMIN_HOME/.ssh (erwartet $ADMIN_USER, 700) oder $ADMIN_AUTH_KEYS (erwartet $ADMIN_USER, 600) stimmen nicht: $(stat -c '%n %U %a' "$ADMIN_HOME/.ssh" "$ADMIN_AUTH_KEYS" | tr '\n' ' ')"
    fi
  fi
  if [[ $SSHD_CHANGED == 0 ]]; then
    info "in Ordnung: sshd -t und sshd -T (global, für $ADMIN_USER und $DEPLOY_USER) ohne Befund"
  fi
else
  [[ -d /run/sshd ]] || run install -d -m 0755 /run/sshd
  info "[Testlauf] sshd -t, danach Prüfung mit sshd -T und sshd -T -C $SSHD_TEST_SPEC (bei jedem echten Lauf, auch wenn $SSHD_CONF unverändert bleibt): AllowUsers enthält $ADMIN_USER, PasswordAuthentication, KbdInteractiveAuthentication, PermitRootLogin, GSSAPIAuthentication und HostbasedAuthentication sind no, PubkeyAuthentication ist yes, AuthenticationMethods ist any oder hat eine Liste nur mit publickey, DenyUsers, AllowGroups und DenyGroups schließen $ADMIN_USER nicht aus (sonst Abbruch); für $DEPLOY_USER mit sshd -T und sshd -T -C $SSHD_DEPLOY_SPEC nur als Warnung: AllowUsers enthält $DEPLOY_USER, DenyUsers, AllowGroups und DenyGroups schließen $DEPLOY_USER nicht aus, PubkeyAuthentication ist yes, AuthenticationMethods ist any oder hat eine Liste nur mit publickey (die leere authorized_keys von $DEPLOY_USER wird nicht geprüft)"
  if hostinger; then
    info "[Testlauf] Profil hostinger, zusätzlich (sonst Abbruch und $SSHD_CONF zurückgesetzt): sshd -T -C $SSHD_ROOT_PUBLIC_SPEC: PermitRootLogin, PasswordAuthentication und KbdInteractiveAuthentication no, AllowUsers lässt root von dort nicht herein; sshd -T -C $SSHD_ROOT_CONSOLE_SPEC: PermitRootLogin yes, PasswordAuthentication yes, AllowUsers root@$CONSOLE_ADDR; sshd -T -C $SSHD_DEPLOY_SPEC: PasswordAuthentication und KbdInteractiveAuthentication no, PubkeyAuthentication yes; sshd -T -C $SSHD_ADMIN_CONSOLE_SPEC und $SSHD_DEPLOY_CONSOLE_SPEC: ebenso nur Schlüssel (die Ausnahme gilt nur für root); sshd -T -C $SSHD_TEST_SPEC: UsePAM yes; der Schlüssel aus ADMIN_PUBKEY steht in $ADMIN_AUTH_KEYS (Besitzer $ADMIN_USER, ~/.ssh 700, Datei 600), bevor SSH neu geladen wird"
  fi
fi
if [[ $SSHD_CHANGED == 1 ]] && hostinger; then
  cat <<TEXT

   ################################################################
   #  WICHTIG: SSH wird jetzt neu geladen.                        #
   #  Web-Konsole im hPanel offen lassen. Von deinem Rechner in   #
   #  einem zweiten Fenster testen: ssh $ADMIN_USER@<ip>
   #  root kommt ab jetzt nur noch über die Web-Konsole herein.   #
   ################################################################

TEXT
elif [[ $SSHD_CHANGED == 1 ]]; then
  cat <<'TEXT'

   ################################################################
   #  WICHTIG: SSH wird jetzt neu geladen.                        #
   #  Login in einem zweiten Fenster testen, bevor du dieses      #
   #  schließt. Die laufende Verbindung bleibt bestehen.          #
   ################################################################

TEXT
fi
if [[ $SSHD_CHANGED == 1 ]]; then
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
# Profile hostinger: ignoreip = 127.0.0.1/8 ::1 169.254.0.1. The web console of
# Hostinger logs in over SSH from 169.254.0.1 with the root password. Five typos within
# 10 minutes would ban that address, and with it the web console, for 10 minutes, the
# one way in that does not depend on the SSH key (e.g. after locking yourself out).
# 169.254.0.0/16 is link-local: packets from 169.254.0.1 can only come from the
# hypervisor side of Hostinger's network, not from the internet, so no attacker on the
# internet is exempted. Logins from there are still logged (journal, auth.log) and are
# limited by the hPanel login. 127.0.0.1/8 and ::1 are fail2ban's usual entries
# (commented out in jail.conf); ignoreself stays on.
JAIL_LOCAL="# Managed by deploy/setup-server.sh
[sshd]
enabled = true
backend = systemd
port = ssh
maxretry = 5
findtime = 10m
bantime = 10m"
if hostinger; then
  JAIL_LOCAL+="
ignoreip = 127.0.0.1/8 ::1 $CONSOLE_ADDR"
fi
JAIL_LOCAL+="
banaction = iptables-multiport
banaction_allports = iptables-allports"
if put /etc/fail2ban/jail.local 0644 <<<"$JAIL_LOCAL"; then
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
# Profile hostinger: exactly these addresses are never banned (see jail.local above);
# a foreign file that adds more (e.g. 0.0.0.0/0) would exempt others as well.
if hostinger; then F2B_WANT+=("sshd.ignoreip=127.0.0.1/8 ::1 $CONSOLE_ADDR"); fi
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
    elif len(c) >= 3 and c[:3] == ["set", "sshd", "addignoreip"]:
        vals["sshd.ignoreip"] = " ".join(str(x) for x in c[3:])
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
# f2b_jail_files JAIL: config files of fail2ban with a section [JAIL]. Only a hint for
# the abort message.
f2b_jail_files() {
  local f found=()
  for f in /etc/fail2ban/jail.conf /etc/fail2ban/jail.d/*.conf /etc/fail2ban/jail.local /etc/fail2ban/jail.d/*.local; do
    [[ -f $f ]] || continue
    if awk -v j="[$1]" '{ l = $0; gsub(/^[ \t]+|[ \t]+$/, "", l); if (l == j) f = 1 } END { exit !f }' "$f" 2>/dev/null; then
      found+=("$f")
    fi
  done
  if ((${#found[@]} > 0)); then printf '%s' "${found[*]}"; else printf 'keine gefunden'; fi
}
# f2b_other_jails VALUES: VALUES is the output of F2B_VALUES_PY. Prints why jails other
# than sshd are a problem, naming each with the files that define it, nothing if only
# sshd is enabled. The privacy policy names only the jail sshd; other jails (e.g.
# recidive, which bans for a week by default) ban with their own values, which the
# script does not check.
f2b_other_jails() {
  local jail list="" jails
  read -r -a jails <<<"$(awk 'index($0, "jails=") == 1 { print substr($0, 7) }' <<<"$1")"
  for jail in "${jails[@]}"; do
    [[ $jail == sshd ]] && continue
    list+="${list:+; }$jail (Abschnitt [$jail] in: $(f2b_jail_files "$jail"))"
  done
  [[ -n $list ]] || return 0
  printf '%s' "In fail2ban sind außer sshd weitere Jails aktiv: $list. Ihre Sperrdauer und Werte prüft das Skript nicht, sie entsprechen nicht der Datenschutzerklärung (dort nur: Sperre für 10 Minuten nach 5 Fehlversuchen in 10 Minuten)."
}
F2B_OTHER_FIX="Den Jail in der Datei, die ihn einschaltet, mit enabled = false abschalten oder die Datei entfernen und das Skript erneut starten. Soll er bleiben, zuerst Datenschutzerklärung und Skript anpassen. Anzeigen mit: sudo fail2ban-client -d | grep \"'add'\""
if dry; then
  info "[Testlauf] Prüfung mit fail2ban-client -d: logtarget = SYSLOG[facility=AUTHPRIV], dbpurgeage 1d, Jail sshd mit maxretry 5, findtime 10m, bantime 10m, ohne bantime.increment, außer sshd kein weiterer Jail aktiv$(if hostinger; then printf ', ignoreip genau 127.0.0.1/8 ::1 %s' "$CONSOLE_ADDR"; fi); bei Abweichung Abbruch ohne Neustart von fail2ban"
  # Other jails do not depend on the two own files (jail.local only has [sshd]), so the
  # dry run can tell already, if fail2ban is installed and its configuration readable.
  # Read only; PYTHONDONTWRITEBYTECODE and -B: no bytecode files are written.
  f2b_other=""
  if command -v fail2ban-client >/dev/null 2>&1 &&
    f2b_dump=$(PYTHONDONTWRITEBYTECODE=1 fail2ban-client -d 2>/dev/null) &&
    f2b_got=$(python3 -I -B -c "$F2B_VALUES_PY" <<<"$f2b_dump" 2>/dev/null); then
    f2b_other=$(f2b_other_jails "$f2b_got")
    if [[ -n $f2b_other ]]; then
      printf '   [Testlauf] Ein echter Lauf würde hier abbrechen: %s %s\n' "$f2b_other" "$F2B_OTHER_FIX" >&2
    else
      info "[Testlauf] fail2ban-client -d: außer sshd ist kein Jail aktiv"
    fi
  else
    info "[Testlauf] Ob außer sshd weitere Jails aktiv sind, ist nicht ermittelbar (fail2ban noch nicht installiert, ohne root nicht lesbar oder fail2ban-client -d gescheitert). Ein echter Lauf bricht ab, falls ja."
  fi
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
        if [[ -z $got && $key != sshd.ignoreip ]]; then
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
  # Other jails stop the script like differing values of sshd: before fail2ban is
  # (re)started, foreign files untouched.
  f2b_other=$(f2b_other_jails "$f2b_got")
  if [[ -n $f2b_other ]]; then
    {
      echo "Abbruch: $f2b_other"
      echo "Die eigenen Dateien fail2ban.local und jail.local bleiben, wie sie sind; fail2ban wurde weder neu gestartet noch gestartet. $F2B_OTHER_FIX"
    } >&2
    exit 1
  fi
  info "in Ordnung: fail2ban-client -d zeigt logtarget SYSLOG[facility=AUTHPRIV], dbpurgeage 86400 s, sshd maxretry 5, findtime 600 s, bantime 600 s, bantime.increment aus, außer sshd kein Jail aktiv"
  if hostinger; then info "in Ordnung: fail2ban sperrt nie 127.0.0.1/8, ::1 und $CONSOLE_ADDR (Web-Konsole), sonst alle Adressen (ignoreip)"; fi
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
if hostinger && [[ $DOCKER_DAEMON_DONE == 1 ]]; then
  info "$DAEMON_JSON: siehe Schritt \"Docker: live-restore vor den Updates\""
elif hostinger; then
  # Merged, not overwritten, and never a restart of Docker (see "Docker on Hostinger"
  # before step 1). Without Docker the file is written here, before the installation.
  docker_daemon_hostinger
elif [[ -f $DAEMON_JSON ]] && [[ "$(cat "$DAEMON_JSON" 2>/dev/null)" != "$DAEMON_CONTENT" ]]; then
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
  if hostinger; then
    # Accepted as it is (e.g. docker-ce from Docker's repository, set up by Hostinger):
    # no new repository entry, no reinstallation. Only reported.
    for pkg in docker-ce docker-ce-cli containerd.io docker-compose-plugin; do
      if pkg_installed "$pkg"; then
        info "installiert: $pkg $(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)"
      else
        warn "Paket $pkg ist nicht installiert (Docker stammt womöglich nicht aus dem offiziellen Repository). Das Skript installiert Docker nicht neu."
      fi
    done
  elif [[ $DAEMON_CHANGED == 1 ]]; then
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

if hostinger; then
  # passwd -S: field 2 is P (usable password), L (locked) or NP (none).
  pw_state=$(passwd -S "$ADMIN_USER" 2>/dev/null | awk '{ print $2 }') || pw_state=""
  if [[ $pw_state != P ]]; then
    cat <<TEXT

   ################################################################
   #  NOCH ZU TUN: Passwort für sudo setzen (als root, jetzt):
   #    passwd $ADMIN_USER
   #  Ohne Passwort klappt der SSH-Login mit dem Schlüssel, aber
   #  sudo nicht. root bleibt über die Web-Konsole erreichbar.
   ################################################################
TEXT
  fi
  if [[ $UFW_INACTIVE == 1 ]] && dry; then
    info "ufw: Ein echter Lauf entfernt das inaktive ufw (apt, mit der Installation von iptables-persistent; gewollt). Firewall sind danach die iptables-Regeln (/etc/iptables/rules.v4, rules.v6) und die Firewall im hPanel."
  elif [[ $UFW_INACTIVE == 1 ]]; then
    info "ufw: apt hat das inaktive ufw mit der Installation von iptables-persistent entfernt (gewollt). Firewall sind jetzt die iptables-Regeln (/etc/iptables/rules.v4, rules.v6) und die Firewall im hPanel."
  fi
  cat <<TEXT

Abnahme: bitte prüfen und das Ergebnis melden. Die Web-Konsole im hPanel bleibt
dabei offen, bis Punkt 3 geklappt hat.

Auf deinem eigenen Rechner (<ip> = öffentliche IP des Servers):
1. Login in einem zweiten Fenster: ssh $ADMIN_USER@<ip>
   Erwartung: klappt mit deinem Schlüssel.
2. ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password $ADMIN_USER@<ip>
   Erwartung: "Permission denied (publickey)", keine Passwortabfrage.
3. ssh root@<ip>
   Erwartung: "Permission denied", kein Login als root aus dem Internet.

Auf dem Server (als $ADMIN_USER, nach "passwd $ADMIN_USER" als root):
4. sudo -v
   Erwartung: fragt nach dem Passwort von $ADMIN_USER und klappt.
5. sudo fail2ban-client status sshd
   Erwartung: Jail sshd mit "Currently failed" und "Currently banned".
6. sudo iptables -S INPUT; sudo ip6tables -S INPUT
   Erwartung: ACCEPT für lo, RELATED,ESTABLISHED, ICMP bzw. ICMPv6, DHCP-Client,
   tcp 22, 80 und 443, als letzte Regel REJECT.

Im hPanel:
7. Web-Konsole (Browser-Terminal) neu öffnen.
   Erwartung: Login als root klappt wie vorher.

Auf deinem eigenen Rechner:
8. curl -I http://<ip> und curl -I http://<ip>:32768
   Erwartung: Antworten von Traefik bzw. der anderen App wie vor dem Lauf.
   Ein Timeout auf 80 heißt: eine Firewall blockt Port 80, auf dem Server
   oder in der Firewall im hPanel.
TEXT
  exit 0
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
