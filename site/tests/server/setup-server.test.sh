#!/usr/bin/env bash
# Tests for deploy/setup-server.sh without a real server.
#
# Every scenario runs in its own mount and network namespace (unshare -m -n):
# - /etc, /home, /run, /var, /usr, /opt, /root and /srv are overlays whose upper
#   layer lives in a temporary directory. Whatever the script writes ends up there,
#   so "nothing changed" means: the upper layers are byte for byte, inode for inode
#   the same as before the run.
# - The firewall rules live in an empty network namespace, loaded with rules like
#   those of Oracle's Ubuntu image (REJECT at the end of INPUT).
# - Commands that would reach the host or the network (apt-get, systemctl,
#   timedatectl, curl, netfilter-persistent, ...) are stubs that log their
#   arguments. iptables, sshd, fail2ban-client, useradd and usermod are the real
#   tools (inside the sandbox), wrapped so that their calls are logged too.
# Nothing on the host changes; the temporary directory is removed at the end.
#
# Usage (as root): bash site/tests/server/setup-server.test.sh
#   SETUP_SCRIPT=path  test another copy of setup-server.sh
#   KEEP_WORK=1        keep the temporary directory for debugging
# Exit code: 0 all tests passed, 1 at least one FAIL, 2 the tests cannot run here.
set -uo pipefail

SELF=$(readlink -f "${BASH_SOURCE[0]}")
HERE=$(dirname "$SELF")
SETUP=$(readlink -f "${SETUP_SCRIPT:-$HERE/../../../deploy/setup-server.sh}")
OVERLAY_DIRS=(etc home run var usr opt root srv)
# Synthetic test key, not a real one.
TEST_KEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTestsOnly000000000000000000000 test@example.invalid'
SANDBOX_PATH_TAIL=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# ===========================================================================
# Inside the sandbox (called as: unshare -m -n ... bash THIS __inner ARTDIR)
# ===========================================================================

# Oracle-like rules: INPUT ends with REJECT, port 22 is already open.
oracle_v4() {
  cat <<'RULES'
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:InstanceServices - [0:0]
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p udp -m udp --sport 123 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
-A FORWARD -j REJECT --reject-with icmp-host-prohibited
-A OUTPUT -d 169.254.0.0/16 -j InstanceServices
-A InstanceServices -d 169.254.0.2/32 -p tcp -m owner --uid-owner 0 -m tcp --dport 3260 -j ACCEPT
-A InstanceServices -d 169.254.0.0/16 -p tcp -m tcp -j REJECT --reject-with tcp-reset
COMMIT
RULES
}

oracle_v6() {
  cat <<'RULES'
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p ipv6-icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp6-adm-prohibited
-A FORWARD -j REJECT --reject-with icmp6-adm-prohibited
COMMIT
RULES
}

drop_policy_v4() {
  cat <<'RULES'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
COMMIT
RULES
}

put_key() { # USER CONTENT
  local user=$1 content=$2 group
  group=$(id -gn "$user")
  install -d -o "$user" -g "$group" -m 700 "/home/$user/.ssh"
  printf '%b' "$content" >"/home/$user/.ssh/authorized_keys"
  chown "$user:$group" "/home/$user/.ssh/authorized_keys"
  chmod 600 "/home/$user/.ssh/authorized_keys"
}

fixture() {
  local art=$1 key_user=${SC_KEY_USER:-ubuntu} u

  # Service and time zone state of a fresh server, used by the stubs.
  mkdir -p "$art/state"
  echo "Etc/UTC" >"$art/state/timezone"
  touch "$art/state/enabled.ssh" "$art/state/active.ssh"
  chmod -R a+rwX "$art/state"

  # No authorized_keys of the host leaks into a scenario.
  for u in ubuntu claude; do rm -f "/home/$u/.ssh/authorized_keys"; done
  case ${SC_KEY:-valid} in
    valid) put_key "$key_user" "$TEST_KEY\n" ;;
    empty) put_key "$key_user" "" ;;
    comments) put_key "$key_user" "# no key here\n\n   \n# ssh-ed25519 commented out\n" ;;
    none) ;;
  esac

  # Cloud images ship drop-ins that enable passwords; the hardening must win.
  mkdir -p /etc/ssh/sshd_config.d
  printf 'PasswordAuthentication yes\n' >/etc/ssh/sshd_config.d/50-cloud-init.conf
  # A default that differs from the wanted values; the script's values must win.
  mkdir -p /etc/apt/apt.conf.d
  printf 'Unattended-Upgrade::Automatic-Reboot "false";\nUnattended-Upgrade::Automatic-Reboot-Time "02:00";\n' \
    >/etc/apt/apt.conf.d/50unattended-upgrades

  if [[ ${SC_OS:-ubuntu} == debian ]]; then
    rm -f /etc/os-release
    printf 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n' >/etc/os-release
  fi

  # Fresh server: Docker is not installed yet.
  if [[ ${SC_HIDE_DOCKER:-1} == 1 ]]; then rm -f /usr/bin/docker; fi

  case ${SC_FW:-oracle} in
    oracle) oracle_v4 | iptables-restore ;;
    accept_after_reject)
      oracle_v4 | iptables-restore
      # Classic mistake on Oracle: rule appended after the REJECT, so it has no effect.
      iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT
      ;;
    drop_policy) drop_policy_v4 | iptables-restore ;;
  esac
  if [[ ${SC_V6:-reject} == reject ]]; then oracle_v6 | ip6tables-restore; fi
}

snapshot() {
  local art=$1
  (
    cd "$art/ovl" || exit 1
    find . -mindepth 1 -regextype posix-extended -regex '\./[^/]+/w' -prune \
      -o -printf '%p|%y|%i|%m|%U:%G|%s|%T@|%C@\n' | LC_ALL=C sort
    find . -regextype posix-extended -regex '\./[^/]+/w' -prune -o -type f -print0 |
      LC_ALL=C sort -z | xargs -0 -r sha256sum
  )
}

dump_fw() {
  { iptables-save; ip6tables-save; } | grep -v '^#' | sed -E 's/\[[0-9]+:[0-9]+\]/[0:0]/g'
}

run_setup() {
  local art=$1 n=$2 rc=0
  local -a envs pre=()
  : >"$art/log$n"
  chmod 666 "$art/log$n"
  envs=(
    PATH="$STUBS:$SANDBOX_PATH_TAIL" HOME=/root LANG=C.UTF-8
    STUB_LOG="$art/log$n" STUB_STATE="$art/state"
    SSHD_T_FAIL="${SC_SSHD_T_FAIL:-0}"
  )
  if [[ -n ${SC_DRY_RUN+x} ]]; then envs+=(DRY_RUN="$SC_DRY_RUN"); fi
  if [[ -n ${SC_ADMIN_USER+x} ]]; then envs+=(ADMIN_USER="$SC_ADMIN_USER"); fi
  if [[ ${SC_AS:-root} == nobody ]]; then
    pre=(setpriv --reuid=nobody --regid=nogroup --clear-groups --)
  fi
  "${pre[@]}" env -i "${envs[@]}" bash "$art/setup-server.sh" >"$art/out$n" 2>"$art/err$n" || rc=$?
  echo "$rc" >"$art/rc$n"
}

post_checks() {
  local art=$1
  /usr/sbin/sshd -T >"$art/sshd_T" 2>&1 || true
  apt-config dump >"$art/aptconf" 2>&1 || true
  fail2ban-client -d >"$art/f2b_dump" 2>/dev/null || true
  getent passwd deploy >"$art/deploy_passwd" || true
  id -nG deploy >"$art/deploy_groups" 2>/dev/null || true
  stat -c '%n %U %G %a %s' /home/deploy/.ssh /home/deploy/.ssh/authorized_keys >"$art/deploy_stat" 2>&1 || true
  ls -1 /etc/ssh/sshd_config.d >"$art/sshd_dir" 2>&1 || true
  if command -v dockerd >/dev/null 2>&1 && [[ -f /etc/docker/daemon.json ]]; then
    dockerd --validate --config-file=/etc/docker/daemon.json >"$art/dockerd_validate" 2>&1
    echo "rc=$?" >>"$art/dockerd_validate"
  fi
}

# What happens on a real server between the first and a later run: the CI key is
# added for deploy, fail2ban and Docker create their iptables chains.
between_runs() {
  printf 'command="/bin/true",restrict %s\n' "$TEST_KEY" >>/home/deploy/.ssh/authorized_keys
  iptables -N f2b-sshd
  iptables -A f2b-sshd -j RETURN
  iptables -I INPUT 1 -p tcp -m multiport --dports 22 -j f2b-sshd
  iptables -N DOCKER-USER
  iptables -A DOCKER-USER -j RETURN
  iptables -I FORWARD 1 -j DOCKER-USER
}

inner() {
  local art=$1 d i
  set -e
  for d in "${OVERLAY_DIRS[@]}"; do
    mkdir -p "$art/ovl/$d/u" "$art/ovl/$d/w"
    mount -t overlay overlay -o "lowerdir=/$d,upperdir=$art/ovl/$d/u,workdir=$art/ovl/$d/w" "/$d"
  done
  fixture "$art"
  snapshot "$art" >"$art/snap0"
  dump_fw >"$art/fw0"
  for ((i = 1; i <= ${SC_RUNS:-1}; i++)); do
    run_setup "$art" "$i"
    snapshot "$art" >"$art/snap$i"
    dump_fw >"$art/fw$i"
    iptables -S INPUT >"$art/v4_$i"
    ip6tables -S INPUT >"$art/v6_$i"
    if ((i == 1)) && [[ ${SC_BETWEEN:-0} == 1 ]]; then
      between_runs
      # State before the second run, including these changes.
      snapshot "$art" >"$art/snap$i"
      dump_fw >"$art/fw$i"
    fi
  done
  post_checks "$art"
  echo ok >"$art/inner_ok"
}

# ===========================================================================
# Outside: stubs, scenarios, assertions
# ===========================================================================

write_stubs() {
  local dir=$1 name
  mkdir -p "$dir"
  # shellcheck disable=SC2016 # expanded later, inside the stubs
  local log='{ printf "%s" "${0##*/}"; printf " %s" "$@"; printf "\n"; } >>"${STUB_LOG:-/dev/null}"'

  cat >"$dir/apt-get" <<EOF
#!/bin/bash
$log
# Installing docker-ce provides the docker command (inside the sandbox).
for a in "\$@"; do
  if [[ \$a == docker-ce ]]; then
    printf '#!/bin/sh\necho "Docker version 0.0.0-test"\n' >/usr/bin/docker
    chmod 755 /usr/bin/docker
  fi
done
exit 0
EOF
  cat >"$dir/debconf-set-selections" <<EOF
#!/bin/bash
$log
cat >/dev/null
EOF
  cat >"$dir/timedatectl" <<EOF
#!/bin/bash
$log
case \$1 in
  show) cat "\$STUB_STATE/timezone" ;;
  set-timezone) echo "\$2" >"\$STUB_STATE/timezone" ;;
esac
EOF
  cat >"$dir/systemctl" <<EOF
#!/bin/bash
$log
verb=\$1; shift
now=0; units=()
for a in "\$@"; do
  case \$a in
    --now) now=1 ;;
    -*) ;;
    *) units+=("\${a%.service}") ;;
  esac
done
case \$verb in
  is-enabled) [[ -e \$STUB_STATE/enabled.\${units[0]} ]] ;;
  is-active) [[ -e \$STUB_STATE/active.\${units[0]} ]] ;;
  enable) for u in "\${units[@]}"; do touch "\$STUB_STATE/enabled.\$u"; [[ \$now == 1 ]] && touch "\$STUB_STATE/active.\$u"; done; exit 0 ;;
  start|restart) for u in "\${units[@]}"; do touch "\$STUB_STATE/active.\$u"; done ;;
  reload) [[ -e \$STUB_STATE/active.\${units[0]} ]] ;;
  *) exit 0 ;;
esac
EOF
  cat >"$dir/curl" <<EOF
#!/bin/bash
$log
out=""
while [[ \$# -gt 0 ]]; do
  if [[ \$1 == -o ]]; then out=\$2; shift; fi
  shift
done
[[ -n \$out ]] && echo "-----BEGIN PGP PUBLIC KEY BLOCK----- (test stub)" >"\$out"
exit 0
EOF
  cat >"$dir/netfilter-persistent" <<EOF
#!/bin/bash
$log
if [[ \${1:-} == save ]]; then
  mkdir -p /etc/iptables
  /usr/sbin/iptables-save >/etc/iptables/rules.v4
  /usr/sbin/ip6tables-save >/etc/iptables/rules.v6
fi
exit 0
EOF
  cat >"$dir/dpkg" <<EOF
#!/bin/bash
$log
if [[ \${1:-} == --print-architecture ]]; then echo arm64; exit 0; fi
exec /usr/bin/dpkg "\$@"
EOF
  # No conflicting package (docker.io, podman-docker, ...) is installed.
  cat >"$dir/dpkg-query" <<EOF
#!/bin/bash
$log
exit 1
EOF
  cat >"$dir/uname" <<EOF
#!/bin/bash
$log
if [[ \${1:-} == -m ]]; then echo aarch64; exit 0; fi
exec /usr/bin/uname "\$@"
EOF
  # Oracle's Ubuntu image has ufw installed but inactive.
  cat >"$dir/ufw" <<EOF
#!/bin/bash
$log
if [[ \${1:-} == status ]]; then echo "Status: inactive"; fi
exit 0
EOF
  cat >"$dir/ss" <<EOF
#!/bin/bash
$log
exit 0
EOF
  cat >"$dir/sshd" <<EOF
#!/bin/bash
$log
if [[ \${SSHD_T_FAIL:-0} == 1 && \${1:-} == -t ]]; then
  echo "test stub: forced sshd -t failure" >&2
  exit 255
fi
exec /usr/sbin/sshd "\$@"
EOF
  for name in iptables ip6tables useradd usermod groupadd; do
    cat >"$dir/$name" <<EOF
#!/bin/bash
$log
exec /usr/sbin/$name "\$@"
EOF
  done
  cat >"$dir/fail2ban-client" <<EOF
#!/bin/bash
$log
exec /usr/bin/fail2ban-client "\$@"
EOF
  chmod 755 "$dir"/*
}

# scenario NAME [VAR=value ...]: run setup-server.sh in a fresh sandbox.
scenario() {
  local name=$1 kv
  shift
  local art="$WORK/$name"
  mkdir -p "$art"
  chmod 755 "$art"
  install -m 0644 "$SETUP" "$art/setup-server.sh"
  (
    export STUBS="$WORK/stubs"
    for kv in "$@"; do export "${kv?}"; done
    unshare -m -n --propagation private -- bash "$SELF" __inner "$art"
  ) >"$art/inner.log" 2>&1
  if [[ ! -f $art/inner_ok ]]; then
    echo "SANDBOX ERROR in scenario $name:"
    sed 's/^/      /' "$art/inner.log"
  fi
}

PASS=0
FAILS=0
check() { # NAME FUNCTION [ARGS...]
  local name=$1 out rc
  shift
  out=$("$@" 2>&1)
  rc=$?
  if [[ $rc -eq 0 ]]; then
    echo "PASS: $name"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $name"
    [[ -n $out ]] && printf '%s\n' "$out" | sed 's/^/      /'
    FAILS=$((FAILS + 1))
  fi
}

# Inside test functions: "ok=1" at the start, "no MESSAGE" for every problem,
# "return $((1 - ok))" at the end.
no() {
  echo "$*"
  ok=0
}

art() { echo "$WORK/$1"; }
upper() { echo "$WORK/$1/ovl/$2/u"; } # upper layer: SCENARIO DIR

# Artifacts of run N must exist, otherwise a missing sandbox would look like success.
have_run() { # SCENARIO N
  local a f
  a=$(art "$1")
  for f in inner_ok "rc$2" snap0 "snap$2" fw0 "fw$2" "log$2" "out$2" "err$2"; do
    [[ -f $a/$f ]] || {
      no "artifact $f of scenario $1 is missing (sandbox failed)"
      return 1
    }
  done
  [[ -s $a/snap0 ]] || {
    no "snapshot before the run is empty (fixture missing)"
    return 1
  }
}

rc_of() { cat "$(art "$1")/rc$2" 2>/dev/null || echo missing; }

# Log lines of calls that change something. Mode "strict": everything except reads.
# Mode "rerun": additionally allows package updates (apt-get, debconf answers),
# which the script runs on every call by design.
modifying_calls() { # LOGFILE MODE
  awk -v mode="$2" '
    { c = $1; ro = 0
      if (c == "systemctl" && ($2 == "is-enabled" || $2 == "is-active" || $2 == "cat" || $2 == "show" || $2 == "status")) ro = 1
      else if (c == "timedatectl" && $2 == "show") ro = 1
      else if ((c == "iptables" || c == "ip6tables") && ($2 == "-L" || $2 == "-S" || $2 == "-C" || $2 == "-n")) ro = 1
      else if (c == "dpkg" && $2 == "--print-architecture") ro = 1
      else if (c == "dpkg-query" || c == "uname" || c == "ss") ro = 1
      else if (c == "ufw" && $2 == "status" && NF == 2) ro = 1
      else if (c == "sshd" && ($2 == "-t" || $2 == "-T")) ro = 1
      else if (c == "fail2ban-client" && ($2 == "-t" || $2 == "-d")) ro = 1
      else if (mode == "rerun" && (c == "apt-get" || c == "debconf-set-selections")) ro = 1
      if (!ro) print }' "$1"
}

# Common assertions: nothing changed by run N of a scenario.
assert_unchanged() { # SCENARIO N
  local a d calls
  a=$(art "$1")
  d=$(diff "$a/snap0" "$a/snap$2") || no "files changed:" "$d"
  d=$(diff "$a/fw0" "$a/fw$2") || no "firewall rules changed:" "$d"
  calls=$(modifying_calls "$a/log$2" strict)
  [[ -z $calls ]] || no "modifying commands were run:" "$calls"
}

# --- tests: shellcheck ------------------------------------------------------

t_shellcheck() {
  local ok=1 out
  out=$(LC_ALL=C.UTF-8 shellcheck "$SETUP" 2>&1) || no "shellcheck reports:" "$out"
  [[ -z $out ]] || no "shellcheck output is not empty:" "$out"
  return $((1 - ok))
}

# --- tests: preconditions ---------------------------------------------------

t_aborts_unchanged() { # SCENARIO
  local ok=1 rc a
  have_run "$1" 1 || return 1
  a=$(art "$1")
  rc=$(rc_of "$1" 1)
  [[ $rc =~ ^[0-9]+$ && $rc -ne 0 ]] || no "expected exit code != 0, got: $rc"
  [[ -s $a/err1 ]] || no "no error message on stderr"
  assert_unchanged "$1" 1
  return $((1 - ok))
}

# --- tests: dry run ---------------------------------------------------------

t_dry_exit0_unchanged() {
  local ok=1 rc
  have_run dry 1 || return 1
  rc=$(rc_of dry 1)
  [[ $rc == 0 ]] || no "expected exit code 0, got: $rc"
  assert_unchanged dry 1
  return $((1 - ok))
}

t_dry_nobody_unchanged() {
  local ok=1
  have_run dry_nobody 1 || return 1
  assert_unchanged dry_nobody 1
  grep -qiE 'abbr|abort' "$(art dry_nobody)/out1" "$(art dry_nobody)/err1" ||
    no "dry run as non-root does not say that a real run would abort"
  return $((1 - ok))
}

# dry_shows LABEL REGEX...: every regex appears in the dry-run output.
t_dry_shows() {
  local ok=1 re all
  have_run dry 1 || return 1
  all=$(cat "$(art dry)/out1" "$(art dry)/err1")
  for re in "$@"; do
    grep -qE -- "$re" <<<"$all" || no "dry-run output lacks: $re"
  done
  return $((1 - ok))
}

# Insert positions printed by the dry run equal the positions a real run produces.
t_dry_positions_match_real_run() {
  local ok=1 out p80 p443
  have_run dry 1 || return 1
  have_run fresh 1 || return 1
  out=$(cat "$(art dry)/out1")
  p80=$(grep -n -- '-A INPUT -p tcp .*--dport 80 .*-j ACCEPT' "$(art fresh)/v4_1" | head -1 | cut -d: -f1)
  p443=$(grep -n -- '-A INPUT -p tcp .*--dport 443 .*-j ACCEPT' "$(art fresh)/v4_1" | head -1 | cut -d: -f1)
  # iptables -S starts with the policy line, so the rule number is line - 1.
  [[ -n $p80 && -n $p443 ]] || {
    no "real run has no ACCEPT rules for 80/443"
    return 1
  }
  grep -qE -- "iptables -I INPUT $((p80 - 1)) .*--dport 80 .*-j ACCEPT" <<<"$out" ||
    no "dry run does not show insert position $((p80 - 1)) for port 80 (real run puts it there)"
  grep -qE -- "iptables -I INPUT $((p443 - 1)) .*--dport 443 .*-j ACCEPT" <<<"$out" ||
    no "dry run does not show insert position $((p443 - 1)) for port 443 (real run puts it there)"
  return $((1 - ok))
}

# --- tests: content of a real run -----------------------------------------

t_first_run_ok() {
  local ok=1 rc d
  have_run fresh 1 || return 1
  rc=$(rc_of fresh 1)
  [[ $rc == 0 ]] || no "expected exit code 0, got: $rc" "$(tail -5 "$(art fresh)/err1")"
  grep -qE 'Änderungen in diesem Lauf: [1-9]' "$(art fresh)/out1" || no "first run does not report changes"
  d=$(diff -q "$(art fresh)/snap0" "$(art fresh)/snap1") && no "first run changed no file"
  return $((1 - ok))
}

new_sshd_files() { # SCENARIO
  local d
  d="$(upper "$1" etc)/ssh/sshd_config.d"
  [[ -d $d ]] && find "$d" -maxdepth 1 -type f ! -name 50-cloud-init.conf | sort
}

t_sshd_dropin() { # SCENARIO ADMIN
  local ok=1 files content line
  have_run "$1" 1 || return 1
  files=$(new_sshd_files "$1")
  [[ -n $files ]] || {
    no "no new file in /etc/ssh/sshd_config.d"
    return 1
  }
  # shellcheck disable=SC2086 # file names without spaces, written by the script
  content=$(cat $files)
  for line in "PasswordAuthentication no" "KbdInteractiveAuthentication no" \
    "PermitRootLogin no" "AllowUsers $2 deploy"; do
    grep -qxE "[[:space:]]*${line// /[[:space:]]+}[[:space:]]*" <<<"$content" || no "drop-in lacks line: $line"
  done
  return $((1 - ok))
}

t_sshd_effective() { # SCENARIO ADMIN
  local ok=1 eff s
  have_run "$1" 1 || return 1
  eff=$(cat "$(art "$1")/sshd_T")
  for s in "passwordauthentication no" "kbdinteractiveauthentication no" \
    "permitrootlogin no" "allowusers $2" "allowusers deploy"; do
    grep -qx "$s" <<<"$eff" || no "sshd -T does not contain: $s"
  done
  [[ $2 == ubuntu ]] || ! grep -qx "allowusers ubuntu" <<<"$eff" || no "sshd -T still allows ubuntu"
  [[ $(grep -c '^allowusers ' <<<"$eff") -eq 2 ]] || no "expected exactly 2 allowusers entries:" "$(grep '^allowusers ' <<<"$eff")"
  return $((1 - ok))
}

t_sshd_t_before_reload() {
  local ok=1 log t r
  have_run fresh 1 || return 1
  log="$(art fresh)/log1"
  t=$(grep -nE '^sshd -t( |$)' "$log" | head -1 | cut -d: -f1)
  r=$(grep -nE '^systemctl (reload|restart|reload-or-restart|try-reload-or-restart) ssh(\.service)?$' "$log" | head -1 | cut -d: -f1)
  [[ -n $t ]] || no "sshd -t was not run"
  [[ -n $r ]] || no "ssh was not reloaded"
  if [[ -n $t && -n $r ]] && ((t > r)); then no "sshd -t (log line $t) ran after the reload (log line $r)"; fi
  return $((1 - ok))
}

t_sshd_t_failure() {
  local ok=1 rc log files
  have_run sshd_t_fail 1 || return 1
  rc=$(rc_of sshd_t_fail 1)
  log="$(art sshd_t_fail)/log1"
  [[ $rc =~ ^[0-9]+$ && $rc -ne 0 ]] || no "expected exit code != 0 after failing sshd -t, got: $rc"
  grep -qE '^sshd -t( |$)' "$log" || no "sshd -t was not run"
  ! grep -qE '^systemctl [a-z-]*(reload|restart)[a-z-]* ssh' "$log" || no "ssh was reloaded although sshd -t failed:" "$(grep -E '^systemctl .* ssh' "$log")"
  files=$(new_sshd_files sshd_t_fail)
  [[ -z $files ]] || no "failed configuration stays in sshd_config.d:" "$files"
  return $((1 - ok))
}

t_fail2ban() {
  local ok=1 jail a
  have_run fresh 1 || return 1
  a=$(art fresh)
  jail="$(upper fresh etc)/fail2ban/jail.local"
  if [[ -f $jail ]]; then
    awk '/^[[:space:]]*\[/ { s = $0; gsub(/[[:space:]]/, "", s) }
         s == "[sshd]" && /^[[:space:]]*enabled[[:space:]]*=[[:space:]]*true[[:space:]]*$/ { f = 1 }
         END { exit !f }' "$jail" || no "jail.local has no [sshd] section with enabled = true:" "$(cat "$jail")"
  else
    no "/etc/fail2ban/jail.local was not written"
  fi
  grep -qF "['add', 'sshd'" "$a/f2b_dump" || no "fail2ban-client -d shows no jail sshd"
  grep -qE '^apt-get .* install .*fail2ban' "$a/log1" || no "fail2ban is not installed"
  [[ -e $a/state/enabled.fail2ban && -e $a/state/active.fail2ban ]] || no "fail2ban is not enabled and started"
  return $((1 - ok))
}

t_unattended() {
  local ok=1 a s
  have_run fresh 1 || return 1
  a=$(art fresh)
  for s in 'APT::Periodic::Update-Package-Lists "1";' 'APT::Periodic::Unattended-Upgrade "1";' \
    'Unattended-Upgrade::Automatic-Reboot "true";' 'Unattended-Upgrade::Automatic-Reboot-Time "04:00";'; do
    grep -qxF "$s" "$a/aptconf" || no "effective APT configuration lacks: $s" \
      "found: $(grep -F "${s%% *}" "$a/aptconf" | tr '\n' ' ')"
  done
  grep -qE '^apt-get .* install .*unattended-upgrades' "$a/log1" || no "unattended-upgrades is not installed"
  return $((1 - ok))
}

t_timezone() {
  local ok=1 a
  have_run fresh 1 || return 1
  a=$(art fresh)
  grep -qx 'timedatectl set-timezone Europe/Berlin' "$a/log1" || no "time zone was not set to Europe/Berlin"
  [[ $(cat "$a/state/timezone") == Europe/Berlin ]] || no "time zone is $(cat "$a/state/timezone")"
  return $((1 - ok))
}

# Rule number of the first ACCEPT for tcp PORT, of the first REJECT, and the count.
fw_facts() { # FILE(iptables -S INPUT) PORT
  awk -v port="$2" '
    /^-A INPUT/ { n++
      if (!rej && / -j REJECT/) rej = n
      if ($0 ~ ("-p tcp .*--dport " port "( |$)") && / -j ACCEPT/) { cnt++; if (!acc) acc = n } }
    END { printf "%d %d %d\n", acc, rej, cnt }' "$1"
}

t_fw_ports_before_reject() { # SCENARIO FAMILY(v4|v6)
  local ok=1 f port acc rej cnt
  have_run "$1" 1 || return 1
  f="$(art "$1")/$2_1"
  for port in 22 80 443; do
    read -r acc rej cnt < <(fw_facts "$f" "$port")
    if ((acc == 0)); then
      no "$2: no ACCEPT for tcp $port"
    elif ((rej > 0 && acc > rej)); then
      no "$2: ACCEPT for tcp $port is rule $acc, after REJECT (rule $rej)"
    fi
    ((cnt <= 1)) || no "$2: $cnt ACCEPT rules for tcp $port (duplicate)"
  done
  ((ok)) || no "INPUT now:" "$(cat "$f")"
  return $((1 - ok))
}

t_fw_saved_after_insert() {
  local ok=1 log s last
  have_run fresh 1 || return 1
  log="$(art fresh)/log1"
  s=$(grep -nx 'netfilter-persistent save' "$log" | tail -1 | cut -d: -f1)
  last=$(grep -nE '^ip6?tables -[IA] ' "$log" | tail -1 | cut -d: -f1)
  [[ -n $last ]] || no "no iptables rule was inserted"
  [[ -n $s ]] || no "netfilter-persistent save was not run"
  if [[ -n $s && -n $last ]] && ((s < last)); then no "save (log line $s) before the last insert (log line $last)"; fi
  return $((1 - ok))
}

t_daemon_json() {
  local ok=1 f out
  have_run fresh 1 || return 1
  f="$(upper fresh etc)/docker/daemon.json"
  [[ -f $f ]] || {
    no "/etc/docker/daemon.json was not written"
    return 1
  }
  out=$(python3 -I - "$f" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except ValueError as e:
    print("invalid JSON: %s" % e)
    sys.exit(1)
problems = []
opts = d.get("log-opts") or {}
if not opts.get("max-size"):
    problems.append("log-opts.max-size missing")
if not opts.get("max-file"):
    problems.append("log-opts.max-file missing")
if "hosts" in d:
    problems.append("hosts entry present: %r" % d["hosts"])
print("\n".join(problems))
sys.exit(1 if problems else 0)
PY
  ) || no "$out"
  if [[ -f $(art fresh)/dockerd_validate ]]; then
    grep -qx 'rc=0' "$(art fresh)/dockerd_validate" || no "dockerd --validate rejects it:" "$(cat "$(art fresh)/dockerd_validate")"
  else
    echo "      (info: dockerd not installed, dockerd --validate skipped)" >&2
  fi
  return $((1 - ok))
}

t_docker_no_tcp() {
  local ok=1 hits
  have_run fresh 1 || return 1
  hits=$(grep -rlE 'tcp://|:237[56]' "$(upper fresh etc)" 2>/dev/null)
  [[ -z $hits ]] || no "files with a TCP endpoint for Docker:" "$hits"
  [[ ! -d $(upper fresh etc)/systemd/system/docker.service.d ]] || no "systemd drop-in for docker.service created"
  return $((1 - ok))
}

t_docker_official_repo() {
  local ok=1 a src s
  have_run fresh 1 || return 1
  a=$(art fresh)
  src=$(cat "$(upper fresh etc)"/apt/sources.list.d/* 2>/dev/null)
  for s in 'https://download.docker.com/linux/ubuntu' 'noble' 'stable' 'arm64' '/etc/apt/keyrings/docker'; do
    grep -qF "$s" <<<"$src" || no "Docker source list lacks: $s"
  done
  grep -qE '^curl .*https://download\.docker\.com/linux/ubuntu/gpg' "$a/log1" || no "Docker key not fetched from download.docker.com"
  [[ -f $(upper fresh etc)/apt/keyrings/docker.asc ]] || no "keyring /etc/apt/keyrings/docker.asc missing"
  grep -qE '^apt-get .* install .*docker-ce( |$)' "$a/log1" || no "docker-ce not installed"
  ! grep -qE '^apt-get .* install .* docker\.io( |$)' "$a/log1" || no "Ubuntu's docker.io installed"
  [[ -e $a/state/enabled.docker && -e $a/state/active.docker ]] || no "docker is not enabled and started"
  return $((1 - ok))
}

t_deploy_user() {
  local ok=1 a
  have_run fresh 1 || return 1
  a=$(art fresh)
  [[ -s $a/deploy_passwd ]] || no "user deploy does not exist"
  tr ' ' '\n' <"$a/deploy_groups" | grep -qx docker || no "deploy is not in group docker: $(cat "$a/deploy_groups")"
  grep -qx '/home/deploy/.ssh deploy deploy 700 [0-9]*' "$a/deploy_stat" || no "wrong /home/deploy/.ssh:" "$(cat "$a/deploy_stat")"
  grep -qx '/home/deploy/.ssh/authorized_keys deploy deploy 600 0' "$a/deploy_stat" ||
    no "authorized_keys of deploy is not an empty file deploy:deploy 600:" "$(cat "$a/deploy_stat")"
  return $((1 - ok))
}

t_no_website_setup() {
  local ok=1 hits
  have_run fresh 1 || return 1
  hits=$(find "$(upper fresh opt)" -mindepth 1 2>/dev/null)
  [[ -z $hits ]] || no "files created under /opt:" "$hits"
  return $((1 - ok))
}

# --- tests: second run ------------------------------------------------------

t_rerun_exit0_zero_changes() {
  local ok=1 rc
  have_run fresh 2 || return 1
  rc=$(rc_of fresh 2)
  [[ $rc == 0 ]] || no "expected exit code 0, got: $rc"
  grep -qE 'Änderungen in diesem Lauf: 0([^0-9]|$)' "$(art fresh)/out2" ||
    no "second run does not report 0 changes:" "$(grep 'Änderungen' "$(art fresh)/out2")"
  return $((1 - ok))
}

t_rerun_files_unchanged() {
  local ok=1 d
  have_run fresh 2 || return 1
  d=$(diff "$(art fresh)/snap1" "$(art fresh)/snap2") || no "second run changed files:" "$d"
  return $((1 - ok))
}

t_rerun_firewall_unchanged() {
  local ok=1 d
  have_run fresh 2 || return 1
  d=$(diff "$(art fresh)/fw1" "$(art fresh)/fw2") || no "second run changed firewall rules:" "$d"
  return $((1 - ok))
}

t_rerun_no_modifying_calls() {
  local ok=1 calls
  have_run fresh 2 || return 1
  calls=$(modifying_calls "$(art fresh)/log2" rerun)
  [[ -z $calls ]] || no "second run ran modifying commands:" "$calls"
  return $((1 - ok))
}

t_no_ufw() {
  local ok=1 calls
  have_run fresh 2 || return 1
  calls=$(cat "$(art fresh)/log1" "$(art fresh)/log2" | grep -E '^ufw( |$)' | grep -vx 'ufw status')
  [[ -z $calls ]] || no "ufw was used:" "$calls"
  return $((1 - ok))
}

t_rerun_real_server() {
  local ok=1 a rc d calls keys
  have_run rerun_real 2 || return 1
  a=$(art rerun_real)
  rc=$(rc_of rerun_real 2)
  [[ $rc == 0 ]] || no "expected exit code 0, got: $rc"
  d=$(diff "$a/snap1" "$a/snap2") || no "second run changed files:" "$d"
  d=$(diff "$a/fw1" "$a/fw2") || no "second run changed firewall rules (with f2b and Docker chains):" "$d"
  calls=$(modifying_calls "$a/log2" rerun)
  [[ -z $calls ]] || no "second run ran modifying commands:" "$calls"
  keys="$(upper rerun_real home)/deploy/.ssh/authorized_keys"
  grep -qF "$TEST_KEY" "$keys" 2>/dev/null || no "CI key in /home/deploy/.ssh/authorized_keys was lost"
  return $((1 - ok))
}

# --- tests: host untouched --------------------------------------------------

host_state() {
  {
    getent passwd deploy || echo "no user deploy"
    sha256sum /etc/passwd /etc/group /etc/shadow /etc/ssh/sshd_config
    ls -la --time-style=full-iso /etc/ssh/sshd_config.d /etc/fail2ban /etc/apt/apt.conf.d \
      /etc/apt/sources.list.d /home /usr/bin/docker /opt 2>&1
    ls -la --time-style=full-iso /etc/docker /etc/iptables /home/ubuntu 2>&1
    readlink /etc/localtime
    dump_fw
  } 2>&1
}

t_host_untouched() {
  local ok=1 d
  d=$(diff "$WORK/host_before" <(host_state)) || no "host changed:" "$d"
  return $((1 - ok))
}

# ===========================================================================
# Main
# ===========================================================================

main() {
  local missing=() c
  if [[ $EUID -ne 0 ]]; then
    echo "CANNOT RUN: needs root (sandbox with unshare, overlayfs and network namespace)."
    exit 2
  fi
  for c in unshare setpriv iptables ip6tables iptables-save ip6tables-save iptables-restore \
    ip6tables-restore /usr/sbin/sshd fail2ban-client apt-config shellcheck python3 diff; do
    command -v "$c" >/dev/null 2>&1 || missing+=("$c")
  done
  if ((${#missing[@]})); then
    echo "CANNOT RUN: missing ${missing[*]}"
    exit 2
  fi
  [[ -f $SETUP ]] || {
    echo "CANNOT RUN: $SETUP not found"
    exit 2
  }
  if ! id ubuntu >/dev/null 2>&1 || ! id claude >/dev/null 2>&1; then
    echo "CANNOT RUN: users ubuntu and claude must exist (fixtures)"
    exit 2
  fi

  WORK=$(mktemp -d "${TMPDIR:-/tmp}/setup-server-test.XXXXXX")
  case $WORK in
    /etc/* | /home/* | /run/* | /var/* | /usr/* | /opt/* | /root/* | /srv/*)
      echo "CANNOT RUN: work directory $WORK lies inside an overlaid directory; set TMPDIR=/tmp"
      rm -rf "$WORK"
      exit 2
      ;;
  esac
  chmod 755 "$WORK"
  if [[ ${KEEP_WORK:-0} == 1 ]]; then
    echo "work directory: $WORK"
  else
    trap 'rm -rf "$WORK"' EXIT
  fi
  write_stubs "$WORK/stubs"
  host_state >"$WORK/host_before"

  echo "Testing $SETUP"
  scenario fresh SC_RUNS=2
  scenario dry SC_DRY_RUN=1
  scenario dry_nobody SC_DRY_RUN=1 SC_AS=nobody
  scenario dry_invalid SC_DRY_RUN=yes
  scenario pre_nokey SC_KEY=none
  scenario pre_emptykey SC_KEY=empty
  scenario pre_commentkey SC_KEY=comments
  scenario pre_nonroot SC_AS=nobody
  scenario pre_debian SC_OS=debian
  scenario pre_admin_space "SC_ADMIN_USER=bad user"
  scenario pre_admin_newline "SC_ADMIN_USER=ubuntu
PermitRootLogin yes"
  scenario pre_admin_meta "SC_ADMIN_USER=ubuntu;id"
  scenario pre_admin_root SC_ADMIN_USER=root
  scenario pre_admin_deploy SC_ADMIN_USER=deploy
  scenario pre_admin_missing SC_ADMIN_USER=nosuchuser
  scenario pre_admin_nokey SC_ADMIN_USER=claude SC_KEY_USER=ubuntu
  scenario alt_admin SC_ADMIN_USER=claude SC_KEY_USER=claude
  scenario sshd_t_fail SC_SSHD_T_FAIL=1
  scenario fw_after_reject SC_FW=accept_after_reject
  scenario fw_drop_policy SC_FW=drop_policy SC_V6=none
  scenario rerun_real SC_RUNS=2 SC_BETWEEN=1
  echo

  check "shellcheck: no findings" t_shellcheck

  check "precondition: no authorized_keys for ADMIN_USER aborts, nothing changed" t_aborts_unchanged pre_nokey
  check "precondition: empty authorized_keys aborts, nothing changed" t_aborts_unchanged pre_emptykey
  check "precondition: authorized_keys with only comments aborts, nothing changed" t_aborts_unchanged pre_commentkey
  check "precondition: not root aborts, nothing changed" t_aborts_unchanged pre_nonroot
  check "precondition: not Ubuntu aborts, nothing changed" t_aborts_unchanged pre_debian
  check "precondition: ADMIN_USER with space aborts, nothing changed" t_aborts_unchanged pre_admin_space
  check "precondition: ADMIN_USER with newline (config injection) aborts, nothing changed" t_aborts_unchanged pre_admin_newline
  check "precondition: ADMIN_USER with shell metacharacter aborts, nothing changed" t_aborts_unchanged pre_admin_meta
  check "precondition: ADMIN_USER=root aborts, nothing changed" t_aborts_unchanged pre_admin_root
  check "precondition: ADMIN_USER=deploy aborts, nothing changed" t_aborts_unchanged pre_admin_deploy
  check "precondition: nonexistent ADMIN_USER aborts, nothing changed" t_aborts_unchanged pre_admin_missing
  check "precondition: key only for ubuntu, ADMIN_USER=claude aborts, nothing changed" t_aborts_unchanged pre_admin_nokey
  check "precondition: DRY_RUN=yes (invalid value) aborts, nothing changed" t_aborts_unchanged dry_invalid

  check "dry run: exit 0, no file, firewall or command change" t_dry_exit0_unchanged
  check "dry run as non-root: nothing changed, says a real run would abort" t_dry_nobody_unchanged
  check "dry run shows step: packages" t_dry_shows \
    'apt-get .*update' 'apt-get .*upgrade' 'apt-get .*install .*unattended-upgrades' 'apt-get .*install .*fail2ban' \
    'apt-get .*install .*netfilter-persistent'
  check "dry run shows step: time zone" t_dry_shows 'timedatectl set-timezone Europe/Berlin'
  check "dry run shows step: automatic updates" t_dry_shows '/etc/apt/apt\.conf\.d/' \
    'Unattended-Upgrade::Automatic-Reboot "true";' 'Unattended-Upgrade::Automatic-Reboot-Time "04:00";'
  check "dry run shows step: firewall" t_dry_shows \
    'iptables -I INPUT [0-9]+ .*--dport 80 .*-j ACCEPT' 'iptables -I INPUT [0-9]+ .*--dport 443 .*-j ACCEPT' \
    'ip6tables -I INPUT [0-9]+ .*--dport 80 .*-j ACCEPT' 'ip6tables -I INPUT [0-9]+ .*--dport 443 .*-j ACCEPT' \
    'netfilter-persistent save'
  check "dry run shows step: SSH" t_dry_shows '/etc/ssh/sshd_config\.d/' 'PasswordAuthentication no' \
    'KbdInteractiveAuthentication no' 'PermitRootLogin no' 'AllowUsers ubuntu deploy' 'sshd -t' 'systemctl reload ssh'
  check "dry run shows step: fail2ban" t_dry_shows '/etc/fail2ban/jail\.local' '\[sshd\]' 'systemctl .*fail2ban'
  check "dry run shows step: Docker" t_dry_shows '/etc/docker/daemon\.json' '"max-size"' '"max-file"' \
    'curl .*https://download\.docker\.com/linux/ubuntu/gpg' 'download\.docker\.com/linux/ubuntu' \
    'apt-get .*install .*docker-ce' 'systemctl enable --now docker'
  check "dry run shows step: user deploy" t_dry_shows 'useradd .*deploy' 'usermod -aG docker deploy' \
    '/home/deploy/\.ssh/authorized_keys'
  check "dry run shows the same insert positions as the real run" t_dry_positions_match_real_run

  check "first run: exit 0 and reports changes" t_first_run_ok
  check "SSH: drop-in in sshd_config.d has the four settings" t_sshd_dropin fresh ubuntu
  check "SSH: effective (sshd -T) despite 50-cloud-init.conf with PasswordAuthentication yes" t_sshd_effective fresh ubuntu
  check "SSH: sshd -t runs before ssh is reloaded" t_sshd_t_before_reload
  check "SSH: failing sshd -t aborts, no reload, drop-in removed" t_sshd_t_failure
  check "SSH: ADMIN_USER=claude gives AllowUsers claude deploy (file)" t_sshd_dropin alt_admin claude
  check "SSH: ADMIN_USER=claude gives AllowUsers claude deploy (sshd -T)" t_sshd_effective alt_admin claude
  check "fail2ban: jail.local enables jail sshd, service enabled" t_fail2ban
  check "automatic updates: effective APT config, reboot at 04:00" t_unattended
  check "time zone: Europe/Berlin" t_timezone
  check "firewall IPv4 (Oracle rules): 22/80/443 ACCEPT before REJECT, no duplicates" t_fw_ports_before_reject fresh v4
  check "firewall IPv6 (Oracle rules): 22/80/443 ACCEPT before REJECT, no duplicates" t_fw_ports_before_reject fresh v6
  check "firewall: netfilter-persistent save after the inserts" t_fw_saved_after_insert
  check "firewall: ACCEPT 80 that sits after REJECT gets one before REJECT" t_fw_ports_before_reject fw_after_reject v4
  check "firewall: policy DROP without REJECT still opens 22/80/443" t_fw_ports_before_reject fw_drop_policy v4
  check "Docker: daemon.json valid, max-size and max-file, no hosts" t_daemon_json
  check "Docker: no TCP socket configured" t_docker_no_tcp
  check "Docker: official repository (arm64, noble, signed key)" t_docker_official_repo
  check "user deploy: group docker, empty authorized_keys 600" t_deploy_user
  check "website setup removed: nothing under /opt" t_no_website_setup

  check "second run: exit 0 and reports 0 changes" t_rerun_exit0_zero_changes
  check "second run: no file changed (content, inode, mode, owner, times)" t_rerun_files_unchanged
  check "second run: firewall rules unchanged" t_rerun_firewall_unchanged
  check "second run: no modifying commands (package updates excepted)" t_rerun_no_modifying_calls

  check "second run on a used server (CI key, f2b and Docker chains): no change, key kept" t_rerun_real_server
  check "firewall: UFW not used (at most ufw status)" t_no_ufw

  check "host untouched after all scenarios" t_host_untouched

  echo
  echo "Result: $PASS passed, $FAILS failed"
  ((FAILS == 0))
}

if [[ ${1:-} == __inner ]]; then
  inner "$2"
  exit
fi
main "$@"
