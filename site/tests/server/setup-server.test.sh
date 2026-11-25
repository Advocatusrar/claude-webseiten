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
# - The curl stub serves Docker's real public apt key (fixtures/docker.asc), or for
#   the negative tests a key generated for this run with another fingerprint.
# - A fresh server has no group docker; the apt-get stub creates it when docker-ce
#   is installed, like the real package. The host's group docker does not matter.
# Nothing on the host changes; the temporary directory is removed at the end.
#
# Usage (as root): bash site/tests/server/setup-server.test.sh
#   SETUP_SCRIPT=path  test another copy of setup-server.sh
#   KEEP_WORK=1        keep the temporary directory for debugging
# Exit code: 0 all tests passed, 1 at least one FAIL, 2 the tests cannot run here.
set -uo pipefail

SELF=$(readlink -f "${BASH_SOURCE[0]}")
HERE=$(dirname "$SELF")
FIXTURES="$HERE/fixtures"
SETUP=$(readlink -f "${SETUP_SCRIPT:-$HERE/../../../deploy/setup-server.sh}")
OVERLAY_DIRS=(etc home run var usr opt root srv)
# Synthetic test key, not a real one.
TEST_KEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTestsOnly000000000000000000000 test@example.invalid'
SANDBOX_PATH_TAIL=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# Fingerprint of Docker's apt signing key ("Docker Release (CE deb)", rsa4096,
# 2017-02-22). fixtures/docker.asc was fetched on 2026-11-25 from
# https://download.docker.com/linux/ubuntu/gpg and checked with gpg --show-keys.
DOCKER_FPR=9DC858229FC7DD38854AE2D88D81803C0EBFCD88
# The ineffective rule the firewall race tests revolve around (fixture accept_after_reject).
RACE_WANT='-A INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT'

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

drop_policy_v6() {
  cat <<'RULES'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p ipv6-icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
COMMIT
RULES
}

# put_key USER CONTENT [WHERE]: WHERE is "home" (home directory from getent passwd,
# default), "legacy_home" (/home/USER, whatever passwd says) or "etc"
# (/etc/ssh/authorized_keys/USER, owned by root).
put_key() {
  local user=$1 content=$2 at=${3:-home} group dir file
  group=$(id -gn "$user")
  case $at in
    home) dir="$(getent passwd "$user" | cut -d: -f6)/.ssh" ;;
    legacy_home) dir="/home/$user/.ssh" ;;
    etc) dir=/etc/ssh/authorized_keys ;;
    *)
      echo "fixture: unknown key location $at" >&2
      return 1
      ;;
  esac
  if [[ $at == etc ]]; then
    install -d -m 755 "$dir"
    file="$dir/$user"
    printf '%b' "$content" >"$file"
    chmod 644 "$file"
  else
    install -d -o "$user" -g "$group" -m 700 "$dir"
    file="$dir/authorized_keys"
    printf '%b' "$content" >"$file"
    chown "$user:$group" "$file"
    chmod 600 "$file"
  fi
}

# Name, mode, owner and content of every file in /etc/ssh/sshd_config.d.
sshd_state() {
  local f
  for f in /etc/ssh/sshd_config.d/*; do
    [[ -e $f ]] || continue
    printf '%s %s\n' "$(stat -c '%n %a %U:%G' "$f")" "$(sha256sum <"$f" | cut -d' ' -f1)"
  done
}

fixture() {
  local art=$1 key_user=${SC_KEY_USER:-ubuntu} u d g members

  # Service and time zone state of a fresh server, used by the stubs.
  mkdir -p "$art/state"
  echo "Etc/UTC" >"$art/state/timezone"
  touch "$art/state/enabled.ssh" "$art/state/active.ssh"
  chmod -R a+rwX "$art/state"

  # An admin user whose home directory is not /home/NAME.
  if [[ -n ${SC_EXTRA_USER:-} ]]; then
    useradd --create-home --home-dir "/srv/$SC_EXTRA_USER" --shell /bin/bash "$SC_EXTRA_USER"
  fi

  # No authorized_keys of the host leaks into a scenario.
  for u in ubuntu claude; do rm -f "/home/$u/.ssh/authorized_keys" "/home/$u/.ssh/authorized_keys2"; done
  case ${SC_KEY:-valid} in
    valid) put_key "$key_user" "$TEST_KEY\n" "${SC_KEY_AT:-home}" ;;
    empty) put_key "$key_user" "" ;;
    comments) put_key "$key_user" "# no key here\n\n   \n# ssh-ed25519 commented out\n" ;;
    none) ;;
  esac

  # Cloud images ship drop-ins that enable passwords; the hardening must win.
  mkdir -p /etc/ssh/sshd_config.d
  printf 'PasswordAuthentication yes\n' >/etc/ssh/sshd_config.d/50-cloud-init.conf
  # AuthorizedKeysFile other than the default.
  case ${SC_AKF:-default} in
    default) ;;
    none) printf 'AuthorizedKeysFile none\n' >/etc/ssh/sshd_config.d/05-test-akf.conf ;;
    custom) printf 'AuthorizedKeysFile /etc/ssh/authorized_keys/%%u\n' >/etc/ssh/sshd_config.d/05-test-akf.conf ;;
  esac
  # Only for ubuntu, via Match (at the end of sshd_config, where Match belongs).
  if [[ ${SC_AKF_MATCH:-0} == 1 ]]; then
    printf '\n# test fixture\nMatch User ubuntu\n    AuthorizedKeysFile /etc/ssh/authorized_keys/%%u\n' >>/etc/ssh/sshd_config
  fi
  # sshd_config without "Include sshd_config.d": the hardening drop-in is not read.
  if [[ ${SC_SSHD_NOINCLUDE:-0} == 1 ]]; then
    sed -i -E '/^[[:space:]]*Include[[:space:]]/d' /etc/ssh/sshd_config
    if grep -qiE '^[[:space:]]*Include' /etc/ssh/sshd_config; then
      echo "fixture: Include still in sshd_config" >&2
      return 1
    fi
  fi
  # A hardening drop-in from an earlier run, with its own content and mode.
  if [[ ${SC_SSHD_OLD:-0} == 1 ]]; then
    printf '# Older version (test fixture)\nPasswordAuthentication no\nAllowUsers ubuntu\n' \
      >/etc/ssh/sshd_config.d/10-haertung.conf
    chmod 640 /etc/ssh/sshd_config.d/10-haertung.conf
  fi
  # Groups for AllowGroups and DenyGroups: "NAME[:MEMBER,MEMBER] ..." (only in the sandbox).
  for g in ${SC_GROUPS:-}; do
    groupadd "${g%%:*}"
    if [[ $g == *:* ]]; then
      IFS=, read -r -a members <<<"${g#*:}"
      for u in "${members[@]}"; do usermod -aG "${g%%:*}" "$u"; done
    fi
  done
  # A drop-in whose name sorts before 10-haertung.conf (sshd reads it first, so its
  # PasswordAuthentication and the like win), one that sorts after it, and a Match block
  # for ubuntu at the end of sshd_config. "\n" separates lines.
  if [[ -n ${SC_SSHD_EARLY:-} ]]; then
    printf '%b\n' "# test fixture" "$SC_SSHD_EARLY" >/etc/ssh/sshd_config.d/00-test.conf
  fi
  if [[ -n ${SC_SSHD_LATE:-} ]]; then
    printf '%b\n' "# test fixture" "$SC_SSHD_LATE" >/etc/ssh/sshd_config.d/60-test.conf
  fi
  if [[ -n ${SC_SSHD_MATCH:-} ]]; then
    printf '\n# test fixture\nMatch User ubuntu\n    %b\n' "$SC_SSHD_MATCH" >>/etc/ssh/sshd_config
  fi
  # No sshd privilege separation directory (socket activation, ssh.service not started).
  if [[ ${SC_RUN_SSHD:-} == missing ]]; then
    rm -rf /run/sshd
    if [[ ! -e /run/sshd ]]; then touch "$art/run_sshd_absent"; fi
  fi
  # A default that differs from the wanted values; the script's values must win.
  mkdir -p /etc/apt/apt.conf.d
  printf 'Unattended-Upgrade::Automatic-Reboot "false";\nUnattended-Upgrade::Automatic-Reboot-Time "02:00";\n' \
    >/etc/apt/apt.conf.d/50unattended-upgrades

  if [[ ${SC_OS:-ubuntu} == debian ]]; then
    rm -f /etc/os-release
    printf 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm\n' >/etc/os-release
  fi

  # Fresh server: Docker is not installed yet, so there is no group docker either
  # (the docker-ce package creates it; here the apt-get stub does).
  if [[ ${SC_HIDE_DOCKER:-1} == 1 ]]; then
    rm -f /usr/bin/docker
    if getent group docker >/dev/null; then groupdel docker; fi
  elif ! getent group docker >/dev/null; then
    groupadd --system docker
  fi

  case ${SC_FW:-oracle} in
    oracle) oracle_v4 | iptables-restore ;;
    accept_after_reject)
      oracle_v4 | iptables-restore
      # Classic mistake on Oracle: rule appended after the REJECT, so it has no effect.
      iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT
      ;;
    drop_policy) drop_policy_v4 | iptables-restore ;;
  esac
  case ${SC_V6:-reject} in
    reject) oracle_v6 | ip6tables-restore ;;
    drop_policy) drop_policy_v6 | ip6tables-restore ;;
    copies_after_reject)
      oracle_v6 | ip6tables-restore
      # Copies appended after the REJECT: 22 is open before it anyway, 443 is not.
      ip6tables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
      ip6tables -A INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT
      ;;
  esac

  # No log retention or fail2ban file of the host leaks into a scenario.
  rm -f /etc/logrotate.d/00-auth-log /etc/systemd/journald.conf.d/10-aufbewahrung.conf \
    /etc/logrotate.d/00-login-logs /etc/logrotate.d/00-fail2ban-log \
    /etc/fail2ban/fail2ban.local /etc/fail2ban/jail.local
  # rsyslog's logrotate file as shipped by Ubuntu's rsyslog package (a conffile, here
  # a synthetic copy): the script must leave it as it is.
  if [[ ${SC_LOGROTATE_RSYSLOG:-0} == 1 ]]; then
    mkdir -p /etc/logrotate.d
    cat >/etc/logrotate.d/rsyslog <<'CONF'
/var/log/syslog
/var/log/mail.log
/var/log/kern.log
/var/log/auth.log
/var/log/user.log
/var/log/cron.log
{
	rotate 4
	weekly
	missingok
	notifempty
	compress
	delaycompress
	sharedscripts
	postrotate
		/usr/lib/rsyslog/rsyslog-rotate
	endscript
}
CONF
    chmod 644 /etc/logrotate.d/rsyslog
  fi
  # The logrotate files of the packages logrotate (3.21.0-2build1: btmp, wtmp) and
  # fail2ban (1.0.2-3ubuntu0.1), as synthetic copies: the script must leave them as they are.
  if [[ ${SC_LOGROTATE_PKG:-0} == 1 ]]; then
    mkdir -p /etc/logrotate.d
    cat >/etc/logrotate.d/btmp <<'CONF'
# no packages own btmp -- we'll rotate it here
/var/log/btmp {
    missingok
    monthly
    create 0660 root utmp
    rotate 1
}
CONF
    cat >/etc/logrotate.d/wtmp <<'CONF'
# no packages own wtmp -- we'll rotate it here
/var/log/wtmp {
    missingok
    monthly
    create 0664 root utmp
    minsize 1M
    rotate 1
}
CONF
    cat >/etc/logrotate.d/fail2ban <<'CONF'
/var/log/fail2ban.log {

    weekly
    rotate 4
    compress
    # Do not rotate if empty
    notifempty

    delaycompress
    missingok
    postrotate
	fail2ban-client flushlogs 1>/dev/null
    endscript

    # If fail2ban runs as non-root it still needs to have write access
    # to logfiles.
    # create 640 fail2ban adm
    create 640 root adm
}
CONF
    chmod 644 /etc/logrotate.d/btmp /etc/logrotate.d/wtmp /etc/logrotate.d/fail2ban
  fi
  # Package defaults that differ from the values in the privacy policy (as after a
  # changed default), in files fail2ban reads before fail2ban.local and jail.local.
  # fail2ban-client -d before the run shows that they take effect.
  if [[ ${SC_F2B_DEFAULTS:-0} == 1 ]]; then
    mkdir -p /etc/fail2ban/fail2ban.d /etc/fail2ban/jail.d
    printf '# Changed defaults (test fixture)\n[Definition]\nlogtarget = /var/log/fail2ban.log\ndbpurgeage = 7d\n' \
      >/etc/fail2ban/fail2ban.d/50-test-defaults.conf
    printf '# Changed defaults (test fixture)\n[DEFAULT]\nbantime = 1h\nfindtime = 1h\nmaxretry = 3\n\n[sshd]\nbantime = 2h\nfindtime = 30m\nmaxretry = 2\n' \
      >/etc/fail2ban/jail.d/50-test-defaults.conf
    fail2ban-client -d >"$art/f2b_dump0" 2>/dev/null || true
  fi
  # A journald drop-in from an earlier version, with other content and mode.
  if [[ ${SC_JOURNALD_OLD:-0} == 1 ]]; then
    mkdir -p /etc/systemd/journald.conf.d
    printf '# Older version (test fixture)\n[Journal]\nMaxRetentionSec=1month\n' \
      >/etc/systemd/journald.conf.d/10-aufbewahrung.conf
    chmod 600 /etc/systemd/journald.conf.d/10-aufbewahrung.conf
  fi

  # Directories that cannot be written (read-only bind mount inside the sandbox).
  for d in ${SC_RO:-}; do
    mount --bind "$d" "$d"
    mount -o remount,bind,ro "$d"
  done
  # Single files that cannot be replaced while their directory stays writable: with a
  # bind mount on the file itself, renaming another file onto it fails (EBUSY).
  for f in ${SC_BUSY:-}; do
    printf '// placeholder (test fixture)\n' >"$f"
    mount --bind "$f" "$f"
  done
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
  local art=$1 n=$2 rc=0 stubs=$STUBS
  local -a envs pre=()
  : >"$art/log$n"
  chmod 666 "$art/log$n"
  # Own TMPDIR per scenario: the script's temporary files stay out of the host's /tmp
  # and the tests can see whether they are removed.
  install -d -m 1777 "$art/tmp"
  # SC_UFW=absent: no ufw command at all (stubs without ufw).
  if [[ ${SC_UFW:-} == absent ]]; then stubs="$STUBS-noufw"; fi
  envs=(
    PATH="$stubs:$SANDBOX_PATH_TAIL" HOME=/root LANG=C.UTF-8 TMPDIR="$art/tmp"
    STUB_LOG="$art/log$n" STUB_STATE="$art/state"
    SSHD_T_FAIL="${SC_SSHD_T_FAIL:-0}"
    STUB_DOCKER_KEY="$KEYS/${SC_DOCKER_KEY:-docker}.asc"
    STUB_IPT_RACE="${SC_IPT_RACE:-}"
    STUB_DPKG="${SC_DPKG:-}"
    STUB_UFW="${SC_UFW:-inactive}"
  )
  if [[ -n ${SC_DRY_RUN+x} ]]; then envs+=(DRY_RUN="$SC_DRY_RUN"); fi
  if [[ -n ${SC_ADMIN_USER+x} ]]; then envs+=(ADMIN_USER="$SC_ADMIN_USER"); fi
  if [[ -n ${SC_SUDO_USER+x} ]]; then envs+=(SUDO_USER="$SC_SUDO_USER"); fi
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
  sshd_state >"$art/sshd_state_end"
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

# f2b_edit local|jail: between run 1 and run 2, someone puts an older version of
# fail2ban.local or jail.local in place (same inode, other content). snap1_pre keeps the
# state right after run 1.
f2b_edit() {
  case $1 in
    local) printf '# Older version (test fixture)\n[Definition]\nlogtarget = /var/log/fail2ban.log\n' >/etc/fail2ban/fail2ban.local ;;
    jail) printf '# Older version (test fixture)\n[sshd]\nenabled = true\nbackend = systemd\n' >/etc/fail2ban/jail.local ;;
    *)
      echo "fixture: unknown SC_F2B_EDIT $1" >&2
      return 1
      ;;
  esac
}

# inner_guard ARTDIR: refuse to run outside a sandbox. Called directly (for example
# "sudo bash THIS __inner /tmp/x"), inner would lay overlays over the host's /etc and
# others and replace the host's firewall rules. scenario() passes the namespaces it
# runs in (SANDBOX_CALLER_NET, SANDBOX_CALLER_MNT); inner must run in other ones, and
# not in those of PID 1 either (where /proc/1 is readable; in some containers it is not).
inner_guard() {
  local art=$1 kind var caller self ref
  for kind in net mnt; do
    var="SANDBOX_CALLER_${kind^^}"
    caller=${!var:-}
    self=$(readlink "/proc/self/ns/$kind" 2>/dev/null) || self=""
    ref=$(readlink "/proc/1/ns/$kind" 2>/dev/null) || ref=""
    if [[ -z $caller || -z $self ]]; then
      echo "REFUSED: __inner is internal, run the tests without arguments ($var or /proc/self/ns/$kind missing)." >&2
      return 1
    fi
    if [[ $self == "$caller" ]]; then
      echo "REFUSED: __inner runs in the $kind namespace of its caller ($self), not in a sandbox." >&2
      return 1
    fi
    if [[ -n $ref && $self == "$ref" ]]; then
      echo "REFUSED: __inner runs in the $kind namespace of PID 1 ($self), not in a sandbox." >&2
      return 1
    fi
  done
  if [[ $art != /* || ! -f $art/setup-server.sh ]]; then
    echo "REFUSED: '$art' is not a scenario directory." >&2
    return 1
  fi
}

inner() {
  local art=$1 d i
  inner_guard "$art" || exit 3
  set -e
  for d in "${OVERLAY_DIRS[@]}"; do
    mkdir -p "$art/ovl/$d/u" "$art/ovl/$d/w"
    mount -t overlay overlay -o "lowerdir=/$d,upperdir=$art/ovl/$d/u,workdir=$art/ovl/$d/w" "/$d"
  done
  fixture "$art"
  snapshot "$art" >"$art/snap0"
  dump_fw >"$art/fw0"
  iptables -S INPUT >"$art/v4_0"
  ip6tables -S INPUT >"$art/v6_0"
  sshd_state >"$art/sshd_state0"
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
    if ((i == 1)) && [[ -n ${SC_F2B_EDIT:-} ]]; then
      cp "$art/snap1" "$art/snap1_pre"
      f2b_edit "$SC_F2B_EDIT"
      snapshot "$art" >"$art/snap1"
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
# Installing docker-ce provides the docker command and, like the real package, the
# group docker (inside the sandbox).
for a in "\$@"; do
  if [[ \$a == docker-ce ]]; then
    printf '#!/bin/sh\necho "Docker version 0.0.0-test"\n' >/usr/bin/docker
    chmod 755 /usr/bin/docker
    getent group docker >/dev/null || /usr/sbin/groupadd --system docker
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
  # Serves the key file STUB_DOCKER_KEY for Docker's key URL; anything else fails
  # like "curl -f" on an HTTP error.
  {
    printf '#!/bin/bash\n%s\n' "$log"
    cat <<'EOF'
out="" url=""
while [[ $# -gt 0 ]]; do
  case $1 in
    -o | --output) out=$2; shift ;;
    http://* | https://*) url=$1 ;;
  esac
  shift
done
if [[ $url != https://download.docker.com/linux/ubuntu/gpg ]]; then
  echo "curl (test stub): unexpected URL '$url'" >&2
  exit 22
fi
if [[ -z ${STUB_DOCKER_KEY:-} || ! -f $STUB_DOCKER_KEY ]]; then
  echo "curl (test stub): no key file configured" >&2
  exit 22
fi
if [[ -n $out ]]; then cat -- "$STUB_DOCKER_KEY" >"$out"; else cat -- "$STUB_DOCKER_KEY"; fi
EOF
  } >"$dir/curl"
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
  # Package states from STUB_DPKG, lines "PACKAGE=STATUS" (for example
  # "rsyslog=install ok installed"). Every other package is unknown, so no conflicting
  # package (docker.io, podman-docker, ...) is installed.
  {
    printf '#!/bin/bash\n%s\n' "$log"
    cat <<'EOF'
fmt="" pkg=""
while [[ $# -gt 0 ]]; do
  case $1 in
    -f | --showformat) fmt=$2; shift ;;
    -f=* | --showformat=*) fmt=${1#*=} ;;
    -*) ;;
    *) pkg=$1 ;;
  esac
  shift
done
status=""
while IFS= read -r line; do
  if [[ -n $line && ${line%%=*} == "$pkg" ]]; then status=${line#*=}; fi
done <<<"${STUB_DPKG:-}"
if [[ -z $status ]]; then
  echo "dpkg-query: no packages found matching $pkg" >&2
  exit 1
fi
if [[ -n $fmt ]]; then
  # STATUS is "WANT ERROR STATE", e.g. "hold ok installed".
  read -r want _ state <<<"$status"
  out=${fmt//'${Status}'/$status}
  out=${out//'${db:Status-Want}'/$want}
  out=${out//'${db:Status-Status}'/$state}
  printf '%s' "${out//'${Package}'/$pkg}"
else
  printf '%s\t%s\n' "$pkg" "0.0-test"
fi
EOF
  } >"$dir/dpkg-query"
  cat >"$dir/uname" <<EOF
#!/bin/bash
$log
if [[ \${1:-} == -m ]]; then echo aarch64; exit 0; fi
exec /usr/bin/uname "\$@"
EOF
  # Oracle's Ubuntu image has ufw installed but inactive (STUB_UFW=inactive, default).
  # STUB_UFW=active: ufw holds the firewall rules; STUB_UFW=unclear: "ufw status"
  # fails without a status line. A server without ufw: PATH with stubs-noufw instead.
  cat >"$dir/ufw" <<EOF
#!/bin/bash
$log
if [[ \${1:-} == status ]]; then
  case \${STUB_UFW:-inactive} in
    inactive) echo "Status: inactive" ;;
    active) printf 'Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW       Anywhere\n' ;;
    unclear) echo "ERROR: Couldn't determine iptables version" >&2; exit 1 ;;
    *) echo "ufw (test stub): unknown STUB_UFW '\$STUB_UFW'" >&2; exit 99 ;;
  esac
fi
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
  for name in ip6tables useradd usermod groupadd; do
    cat >"$dir/$name" <<EOF
#!/bin/bash
$log
exec /usr/sbin/$name "\$@"
EOF
  done
  # Logged so that the tests see a restored (replaced) rule set.
  for name in iptables-restore ip6tables-restore; do
    cat >"$dir/$name" <<EOF
#!/bin/bash
$log
exec /usr/sbin/$name "\$@"
EOF
  done
  # iptables, optionally with a simulated concurrent writer (like fail2ban's
  # "iptables -I INPUT 1 ..."), which inserts a foreign rule at the top of INPUT:
  #   STUB_IPT_RACE=insert  right before "iptables -I INPUT <n> ..." is carried out
  #                         (the script read the REJECT position before).
  # Once per run. STUB_STATE/race_count counts the inserted rules.
  {
    printf '#!/bin/bash\n%s\n' "$log"
    cat <<'EOF'
real=/usr/sbin/iptables
mode=${STUB_IPT_RACE:-}
count_file=${STUB_STATE:-/nonexistent}/race_count
inject() {
  local n=0
  if [[ -f $count_file ]]; then n=$(<"$count_file"); fi
  n=$((n + 1))
  echo "$n" >"$count_file"
  "$real" -I INPUT 1 -s "192.0.2.$n/32" -p tcp -j DROP
}
if [[ $mode == insert && $# -gt 3 && $1 == -I && $2 == INPUT && $3 =~ ^[0-9]+$ && ! -f $count_file ]]; then
  inject
fi
exec "$real" "$@"
EOF
  } >"$dir/iptables"
  cat >"$dir/fail2ban-client" <<EOF
#!/bin/bash
$log
exec /usr/bin/fail2ban-client "\$@"
EOF
  chmod 755 "$dir"/*
}

# Environment of the inner entry point: stubs, key files, namespaces of the caller.
export_sandbox_env() {
  export STUBS="$WORK/stubs" KEYS="$WORK/keys"
  export SANDBOX_CALLER_NET="$CALLER_NET" SANDBOX_CALLER_MNT="$CALLER_MNT"
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
    export_sandbox_env
    for kv in "$@"; do export "${kv?}"; done
    unshare -m -n --propagation private -- bash "$SELF" __inner "$art"
  ) >"$art/inner.log" 2>&1
  if [[ ! -f $art/inner_ok ]]; then
    echo "SANDBOX ERROR in scenario $name:"
    sed 's/^/      /' "$art/inner.log"
  fi
}

# guard_case NAME MODE: call the inner entry point the wrong way. Always inside a
# protective sandbox of its own (new mount and network namespace), so that a missing
# guard runs the scenario there and cannot touch the host.
#   no_markers  as if called directly: SANDBOX_CALLER_* not set
#   caller_ns   SANDBOX_CALLER_* name the namespaces inner itself runs in
#   pid1        inner is PID 1 of a new PID namespace (with its own /proc), so it
#               shares its namespaces with PID 1; the markers are right
guard_case() {
  local name=$1 mode=$2 art="$WORK/$1"
  mkdir -p "$art"
  chmod 755 "$art"
  install -m 0644 "$SETUP" "$art/setup-server.sh"
  (
    export_sandbox_env
    rc=0
    case $mode in
      no_markers)
        unset SANDBOX_CALLER_NET SANDBOX_CALLER_MNT
        unshare -m -n --propagation private -- bash "$SELF" __inner "$art" || rc=$?
        ;;
      caller_ns)
        # shellcheck disable=SC2016 # expanded inside the sandbox
        unshare -m -n --propagation private -- bash -c \
          'export SANDBOX_CALLER_NET=$(readlink /proc/self/ns/net) SANDBOX_CALLER_MNT=$(readlink /proc/self/ns/mnt); exec bash "$0" __inner "$1"' \
          "$SELF" "$art" || rc=$?
        ;;
      pid1)
        unshare -m -n -p --fork --mount-proc --propagation private -- bash "$SELF" __inner "$art" || rc=$?
        ;;
    esac
    echo "rc=$rc" >"$art/guard_rc"
  ) >"$art/inner.log" 2>&1
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

# --- tests: who may log in afterwards (SUDO_USER, key files) -----------------

# Aborts without any change, and for the expected reason: REGEX must appear on
# stderr. Without it, a scenario that aborts for another reason (e.g. a broken
# fixture without key) would pass as well.
t_aborts_because() { # SCENARIO REGEX
  local ok=1
  t_aborts_unchanged "$1" || ok=0
  grep -qE -- "$2" "$(art "$1")/err1" 2>/dev/null ||
    no "stderr does not name the reason (/$2/):" "$(cat "$(art "$1")/err1" 2>/dev/null)"
  return $((1 - ok))
}

t_runs_ok() { # SCENARIO
  local ok=1 rc
  have_run "$1" 1 || return 1
  rc=$(rc_of "$1" 1)
  [[ $rc == 0 ]] || no "expected exit code 0, got: $rc" "$(tail -5 "$(art "$1")/err1")"
  return $((1 - ok))
}

# After writing the drop-in, sshd -T has no "allowusers ADMIN_USER": the SSH
# directory must be as before (file removed or old file back, same mode and
# content), ssh not reloaded, and the script stops there.
t_sshd_rollback() { # SCENARIO
  local ok=1 a rc d t
  have_run "$1" 1 || return 1
  a=$(art "$1")
  rc=$(rc_of "$1" 1)
  [[ $rc =~ ^[0-9]+$ && $rc -ne 0 ]] || no "expected exit code != 0 (sshd -T has no 'allowusers ubuntu'), got: $rc"
  t=$(grep -nE '^sshd -t( |$)' "$a/log1" | head -1 | cut -d: -f1)
  if [[ -z $t ]]; then
    no "sshd -t was not run (the new drop-in was never checked)"
  elif ! tail -n "+$t" "$a/log1" | grep -qE '^sshd -T( |$)'; then
    no "no sshd -T after sshd -t: the effective AllowUsers were not checked"
  fi
  ! grep -qE '^systemctl [a-z-]*(reload|restart)[a-z-]* ssh' "$a/log1" ||
    no "ssh was reloaded:" "$(grep -E '^systemctl .* ssh' "$a/log1")"
  d=$(diff "$a/sshd_state0" "$a/sshd_state_end") ||
    no "/etc/ssh/sshd_config.d is not as before the run (name mode owner sha256):" "$d"
  [[ ! -e $(upper "$1" etc)/fail2ban/jail.local ]] || no "the script went on after the failed check (jail.local written)"
  ! grep -qE '^useradd ' "$a/log1" || no "the script went on after the failed check (useradd ran)"
  return $((1 - ok))
}

# --- tests: write errors ----------------------------------------------------------

# PATH (under /etc) cannot be written: exit != 0, error names PATH, no "geschrieben"
# for it, PATH as before, no temporary file left next to it, nothing matching LATER
# (calls of later steps) in the log.
t_write_error() { # SCENARIO PATH LATER_REGEX
  local ok=1 a rc later rel left
  have_run "$1" 1 || return 1
  a=$(art "$1")
  rel=${2#/etc/}
  rc=$(rc_of "$1" 1)
  [[ $rc =~ ^[0-9]+$ && $rc -ne 0 ]] || no "expected exit code != 0 when $2 cannot be written, got: $rc"
  grep -qF -- "$2" "$a/err1" || no "stderr does not name $2:" "$(cat "$a/err1")"
  ! grep -qE -- "geschrieben:? +$2" "$a/out1" || no "output reports $2 as written:" "$(grep -F -- "$2" "$a/out1")"
  [[ "$(grep -F "./etc/u/$rel" "$a/snap0")" == "$(grep -F "./etc/u/$rel" "$a/snap1")" ]] ||
    no "$2 changed:" "$(diff <(grep -F "./etc/u/$rel" "$a/snap0") <(grep -F "./etc/u/$rel" "$a/snap1"))"
  left=$(find "$(upper "$1" etc)/$(dirname "$rel")" -maxdepth 1 -name "$(basename "$rel").tmp*" 2>/dev/null)
  [[ -z $left ]] || no "temporary file left:" "$left"
  later=$(grep -E -- "$3" "$a/log1")
  [[ -z $later ]] || no "the script went on after the failed write:" "$later"
  return $((1 - ok))
}

# --- tests: firewall (IPv6 policy DROP, concurrent changes) -------------------

t_fw_v6_drop_policy() { # SCENARIO
  local ok=1 f
  have_run "$1" 1 || return 1
  t_fw_ports_before_reject "$1" v6 || ok=0
  f="$(art "$1")/v6_1"
  grep -qx -- '-P INPUT DROP' "$f" || no "ip6tables INPUT policy is no longer DROP:" "$(head -1 "$f")"
  return $((1 - ok))
}

t_fw_family_unchanged() { # SCENARIO FAMILY(v4|v6)
  local ok=1 d
  have_run "$1" 1 || return 1
  d=$(diff "$(art "$1")/$2_0" "$(art "$1")/$2_1") || no "$2 INPUT changed:" "$d"
  return $((1 - ok))
}

t_rerun_fw_unchanged() { # SCENARIO
  local ok=1 rc d
  have_run "$1" 2 || return 1
  rc=$(rc_of "$1" 2)
  [[ $rc == 0 ]] || no "second run: expected exit code 0, got: $rc"
  d=$(diff "$(art "$1")/fw1" "$(art "$1")/fw2") || no "second run changed firewall rules:" "$d"
  return $((1 - ok))
}

# The ACCEPT rule the script uses for tcp PORT, as iptables -S prints it.
fw_rule() { echo "-A INPUT -p tcp -m state --state NEW -m tcp --dport $1 -j ACCEPT"; }

# ACCEPT rules for tcp PORT before and behind the first REJECT, and the number of the
# first REJECT (0 if there is none).
fw_split() { # FILE(iptables -S INPUT) PORT
  awk -v port="$2" '
    /^-A INPUT/ { n++
      if (!rej && / -j REJECT/) { rej = n; next }
      if ($0 ~ ("-p tcp .*--dport " port "( |$)") && / -j ACCEPT/) { if (rej) behind++; else before++ } }
    END { printf "%d %d %d\n", before, behind, rej }' "$1"
}

# Exact copies of RULE behind the first REJECT.
fw_behind_reject() { # FILE(iptables -S INPUT) RULE
  awk -v want="$2" '/^-A INPUT/ { if (!rej && / -j REJECT/) { rej = 1; next } if (rej && $0 == want) c++ }
    END { print c + 0 }' "$1"
}

# Warnings in FILE (stderr of a run) about an ineffective ACCEPT for tcp PORT behind
# the REJECT: lines that name TOOL, REJECT, the port and the command that shows the
# rule numbers ("TOOL -L INPUT --line-numbers -n").
copy_warnings() { # FILE TOOL PORT
  grep -F "WARNUNG: $2:" "$1" | grep -F 'REJECT' | grep -E "Port $3([^0-9]|$)" |
    grep -cF "$2 -L INPUT --line-numbers -n"
}

# Calls that delete, replace or flush firewall rules or chains (short or long option).
FW_DELETE_RE='ip6?tables( [^ ]+)* (-D|--delete|-R|--replace|-F|--flush|-X|--delete-chain)( |$)'

# INPUT of FAMILY had an ACCEPT for each PORT behind the REJECT (no effect there). The
# script never deletes or replaces firewall rules (a rule number can point to the
# REJECT by the time it is used), so after run 1: exactly one ACCEPT per port 22/80/443
# before the REJECT, the copies behind it still there, no rule lost, only the missing
# ACCEPT rules added. Run 1 and run 2 each warn once per copy and name
# "TOOL -L INPUT --line-numbers -n", and no other port. No -D/-R in either run.
# Run 2 reports 0 changes and changes no rule, file or service.
t_fw_copy_behind_reject() { # SCENARIO FAMILY(v4|v6) TOOL PORT...
  local ok=1 s=$1 fam=$2 tool=$3 a f0 f1 r port before behind rej before0 behind0 want w lost added exp calls d
  shift 3
  have_run "$s" 2 || return 1
  a=$(art "$s")
  f0="$a/${fam}_0" f1="$a/${fam}_1"
  for port in "$@"; do
    [[ $(fw_behind_reject "$f0" "$(fw_rule "$port")") == 1 ]] ||
      no "fixture: $fam INPUT before the run has no copy of the ACCEPT for tcp $port behind REJECT"
  done
  ((ok)) || return 1
  for r in 1 2; do
    [[ $(rc_of "$s" "$r") == 0 ]] || no "run $r: expected exit code 0, got: $(rc_of "$s" "$r")" "$(tail -3 "$a/err$r")"
  done
  exp=""
  for port in 22 80 443; do
    read -r before0 behind0 _ < <(fw_split "$f0" "$port")
    read -r before behind rej < <(fw_split "$f1" "$port")
    ((rej > 0)) || no "$fam: no REJECT in INPUT after run 1"
    ((before == 1)) || no "$fam: $before ACCEPT rules for tcp $port before REJECT after run 1 (expected exactly 1)"
    ((behind == behind0)) || no "$fam: ACCEPT rules for tcp $port behind REJECT: $behind0 before the run, $behind after run 1 (the copy must stay)"
    if ((before0 == 0)); then exp+="$(fw_rule "$port")"$'\n'; fi
    want=0
    [[ " $* " == *" $port "* ]] && want=1
    for r in 1 2; do
      w=$(copy_warnings "$a/err$r" "$tool" "$port")
      ((w == want)) || no "run $r: $w warnings about an ACCEPT for tcp $port behind REJECT naming '$tool -L INPUT --line-numbers -n' (expected $want)"
    done
  done
  for port in "$@"; do
    [[ $(fw_behind_reject "$f1" "$(fw_rule "$port")") == 1 ]] ||
      no "$fam: the copy '$(fw_rule "$port")' behind REJECT is gone or changed after run 1"
  done
  lost=$(comm -23 <(LC_ALL=C sort "$f0") <(LC_ALL=C sort "$f1"))
  [[ -z $lost ]] || no "$fam: rules lost in run 1:" "$lost"
  added=$(comm -13 <(LC_ALL=C sort "$f0") <(LC_ALL=C sort "$f1"))
  [[ $added == "$(printf '%s' "$exp" | LC_ALL=C sort)" ]] ||
    no "$fam: run 1 added other rules than the missing ACCEPT rules."$'\n'"added:"$'\n'"$added"$'\n'"expected:"$'\n'"$exp"
  calls=$(cat "$a/log1" "$a/log2" | grep -E "^$FW_DELETE_RE")
  [[ -z $calls ]] || no "rules deleted or replaced:" "$calls"
  grep -qE 'Änderungen in diesem Lauf: 0([^0-9]|$)' "$a/out2" ||
    no "run 2 does not report 0 changes:" "$(grep 'Änderungen' "$a/out2")"
  d=$(diff "$a/fw1" "$a/fw2") || no "run 2 changed firewall rules:" "$d"
  d=$(diff "$a/snap1" "$a/snap2") || no "run 2 changed files:" "$d"
  calls=$(modifying_calls "$a/log2" rerun)
  [[ -z $calls ]] || no "run 2 ran modifying commands:" "$calls"
  if ((ok == 0)); then
    no "$fam INPUT before the run:"$'\n'"$(cat "$f0")"
    no "$fam INPUT after run 1:"$'\n'"$(cat "$f1")"
  fi
  return $((1 - ok))
}

# No scenario, real or dry run, deletes, replaces or flushes firewall rules or chains,
# or restores a whole rule set: no "ip(6)tables -D/-R/-F/-X" (short or long option), no
# ip(6)tables-restore and no netfilter-persistent other than "save" in the call logs,
# none of them in the dry-run output either.
t_fw_never_deletes() {
  local ok=1 f logs=0 v4=0 v6=0 dry=0 hits
  for f in "$WORK"/*/log[0-9]*; do
    [[ -f $f ]] || continue
    logs=$((logs + 1))
    if grep -qE '^iptables -I INPUT [0-9]+ ' "$f"; then v4=$((v4 + 1)); fi
    if grep -qE '^ip6tables -I INPUT [0-9]+ ' "$f"; then v6=$((v6 + 1)); fi
    hits=$(grep -E "^($FW_DELETE_RE|ip6?tables-restore( |\$)|netfilter-persistent( |\$))" "$f" | grep -vx 'netfilter-persistent save')
    [[ -z $hits ]] || no "${f#"$WORK"/}:" "$hits"
  done
  for f in "$WORK"/*/out[0-9]* "$WORK"/*/err[0-9]*; do
    [[ -f $f ]] || continue
    if grep -qE '\[Testlauf\] iptables -I INPUT [0-9]+ ' "$f"; then dry=$((dry + 1)); fi
    hits=$(grep -E "\[Testlauf\] ($FW_DELETE_RE|ip6?tables-restore( |\$)|netfilter-persistent( |\$))" "$f" |
      grep -vE '\[Testlauf\] netfilter-persistent save$')
    [[ -z $hits ]] || no "${f#"$WORK"/}:" "$hits"
  done
  # Otherwise this test would look at nothing.
  ((logs >= 20 && v4 >= 3 && v6 >= 3 && dry >= 1)) ||
    no "too little to check: $logs call logs, $v4 with iptables -I, $v6 with ip6tables -I, $dry dry runs with iptables -I"
  return $((1 - ok))
}

# --- tests: Docker key ------------------------------------------------------------

key_fprs() { # FILE: fingerprints of the primary keys in FILE, one per line
  local g
  g=$(mktemp -d "$WORK/gpg-show.XXXXXX") || return 1
  GNUPGHOME=$g gpg --batch --quiet --with-colons --show-keys "$1" 2>/dev/null |
    awk -F: '$1 == "pub" { p = 1; next } p && $1 == "fpr" { print $10; p = 0 }'
  rm -rf -- "$g"
}

t_fixture_docker_key() {
  local ok=1 f
  f=$(key_fprs "$FIXTURES/docker.asc")
  [[ $f == "$DOCKER_FPR" ]] || no "fixtures/docker.asc: expected exactly one key $DOCKER_FPR, found:" "${f:-none}"
  return $((1 - ok))
}

t_docker_keyring_is_checked_key() {
  local ok=1 k
  have_run fresh 1 || return 1
  k="$(upper fresh etc)/apt/keyrings/docker.asc"
  if [[ ! -f $k ]]; then
    no "/etc/apt/keyrings/docker.asc was not installed"
  elif ! cmp -s "$k" "$FIXTURES/docker.asc"; then
    no "/etc/apt/keyrings/docker.asc differs from the key served for $DOCKER_FPR"
  fi
  return $((1 - ok))
}

# The served key is not (only) the expected one: stop, Docker not set up.
t_docker_key_rejected() { # SCENARIO
  local ok=1 a rc calls files
  have_run "$1" 1 || return 1
  a=$(art "$1")
  rc=$(rc_of "$1" 1)
  [[ $rc =~ ^[0-9]+$ && $rc -ne 0 ]] || no "expected exit code != 0, got: $rc"
  [[ -s $a/err1 ]] || no "no error message on stderr"
  grep -qE '^curl .*https://download\.docker\.com/linux/ubuntu/gpg' "$a/log1" ||
    no "the key was never fetched; the script stopped earlier for another reason:" "$(tail -5 "$a/err1")"
  files=$(find "$(upper "$1" etc)/apt/keyrings" "$(upper "$1" etc)/apt/sources.list.d" -mindepth 1 2>/dev/null)
  [[ -z $files ]] || no "key or apt source installed:" "$files"
  calls=$(grep -E '^apt-get .*install.* docker|^systemctl .*docker|^useradd |^usermod ' "$a/log1")
  [[ -z $calls ]] || no "Docker set up anyway, or the script went on:" "$calls"
  # -f: removing /usr/bin/docker in the fixture leaves a whiteout (character device).
  [[ ! -f $(upper "$1" usr)/bin/docker ]] || no "docker command installed"
  return $((1 - ok))
}

t_tmp_cleaned() { # SCENARIO
  local ok=1 left
  have_run "$1" 1 || return 1
  left=$(find "$(art "$1")/tmp" -mindepth 1 2>/dev/null)
  [[ -z $left ]] || no "temporary files of the script left behind:" "$left"
  return $((1 - ok))
}

# --- tests: dry run and packages -------------------------------------------------

t_full_upgrade() {
  local ok=1 calls
  have_run fresh 1 || return 1
  have_run dry 1 || return 1
  grep -qE '^apt-get .* full-upgrade( |$)' "$(art fresh)/log1" || no "real run: no 'apt-get ... full-upgrade'"
  calls=$(grep -E '^apt-get( .*)? upgrade( |$)' "$(art fresh)/log1")
  [[ -z $calls ]] || no "real run still runs plain upgrade:" "$calls"
  grep -qE 'apt-get .* full-upgrade( |$)' "$(art dry)/out1" || no "dry run does not show 'apt-get ... full-upgrade'"
  calls=$(grep -E 'apt-get( [^ ]+)* upgrade( |$)' "$(art dry)/out1")
  [[ -z $calls ]] || no "dry run shows plain upgrade:" "$calls"
  return $((1 - ok))
}

# --- tests: firewall copies behind REJECT (dry run, concurrent insert) -----------

# Dry run with copies behind REJECT in both families (iptables: 80; ip6tables: 22 and
# 443): exit 0, nothing changed, one warning per copy as in a real run and none for
# other ports, no insert for ip6tables 22 (open before REJECT already), and the insert
# positions a real run produces (REAL_V4 and REAL_V6 have the same fixtures).
t_dry_copy_behind_reject() { # DRY_SCENARIO REAL_V4_SCENARIO REAL_V6_SCENARIO
  local ok=1 a out tool port want w f s sc fam p
  have_run "$1" 1 || return 1
  have_run "$2" 1 || return 1
  have_run "$3" 1 || return 1
  a=$(art "$1")
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)"
  assert_unchanged "$1" 1
  for tool in iptables ip6tables; do
    for port in 22 80 443; do
      case "$tool $port" in
        "iptables 80" | "ip6tables 22" | "ip6tables 443") want=1 ;;
        *) want=0 ;;
      esac
      w=$(copy_warnings "$a/err1" "$tool" "$port")
      ((w == want)) || no "$w warnings about an ACCEPT for tcp $port behind REJECT naming '$tool -L INPUT --line-numbers -n' (expected $want)"
    done
  done
  out=$(cat "$a/out1")
  ! grep -qE -- '\[Testlauf\] ip6tables -I INPUT [0-9]+ .*--dport 22 ' <<<"$out" ||
    no "dry run inserts an ACCEPT for ip6tables tcp 22, which is open before REJECT already"
  for s in "iptables $2 v4" "ip6tables $3 v6"; do
    read -r tool sc fam <<<"$s"
    f="$(art "$sc")/${fam}_1"
    for port in 80 443; do
      # iptables -S starts with the policy line, so the rule number is line - 1.
      p=$(grep -nxF -- "$(fw_rule "$port")" "$f" | head -1 | cut -d: -f1)
      if [[ -z $p ]]; then
        no "real run ($f) has no ACCEPT for tcp $port"
        continue
      fi
      grep -qE -- "\[Testlauf\] $tool -I INPUT $((p - 1)) -p tcp .*--dport $port -j ACCEPT" <<<"$out" ||
        no "dry run does not show '$tool -I INPUT $((p - 1))' for tcp $port (a real run puts it there):" "$(grep -E "\[Testlauf\] $tool " <<<"$out")"
    done
  done
  return $((1 - ok))
}

# Another program inserts a rule at the top of INPUT between the script reading the
# REJECT position and "iptables -I INPUT <n>" (see the iptables stub). The ACCEPT
# rules must still end up before the REJECT, no rule is lost (also not the copy
# behind the REJECT), the foreign rule stays.
t_fw_insert_race() { # SCENARIO
  local ok=1 a n port before behind rej lost
  have_run "$1" 1 || return 1
  a=$(art "$1")
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)"
  n=$(cat "$a/state/race_count" 2>/dev/null || echo 0)
  ((n >= 1)) || no "the simulated concurrent insert did not fire (no 'iptables -I INPUT <n>' call); this test checks nothing"
  grep -qxF -- '-A INPUT -s 192.0.2.1/32 -p tcp -j DROP' "$a/v4_1" || no "the foreign rule inserted concurrently is gone"
  for port in 22 80 443; do
    read -r before behind rej < <(fw_split "$a/v4_1" "$port")
    ((before == 1)) || no "$before ACCEPT rules for tcp $port before REJECT (expected exactly 1)"
  done
  lost=$(comm -23 <(LC_ALL=C sort "$a/v4_0") <(LC_ALL=C sort "$a/v4_1"))
  [[ -z $lost ]] || no "rules lost:" "$lost"
  # Same text as the inserted rule, so the comparison above does not see it go.
  [[ $(fw_behind_reject "$a/v4_1" "$RACE_WANT") == 1 ]] || no "the copy '$RACE_WANT' behind REJECT is gone"
  ((ok)) || no "INPUT before the run:"$'\n'"$(cat "$a/v4_0")" "INPUT after the run:"$'\n'"$(cat "$a/v4_1")"
  return $((1 - ok))
}

# --- tests: log retention (7 days) ---------------------------------------------

JOURNALD_DROPIN=/etc/systemd/journald.conf.d/10-aufbewahrung.conf
AUTH_LOGROTATE=/etc/logrotate.d/00-auth-log
RSYSLOG_LOGROTATE=/etc/logrotate.d/rsyslog

# Stat line and sha256 line of PATH (under /etc) in snapshot N of SCENARIO; empty if
# the file is not in the upper layer.
snap_of() { # SCENARIO N PATH
  awk -v p="./etc/u${3#/etc}" '{ split($0, f, "|") } f[1] == p || substr($0, 67) == p' "$(art "$1")/snap$2"
}

# Effective MaxRetentionSec and MaxFileSec in section [Journal] of a journald drop-in
# (the last assignment wins; comments and other sections do not count), "-" if unset.
journald_values() { # FILE
  awk '
    /^[[:space:]]*[#;]/ || /^[[:space:]]*$/ { next }
    /^[[:space:]]*\[/ { sec = $0; gsub(/[[:space:]]/, "", sec); next }
    sec == "[Journal]" && /=/ {
      k = $0; sub(/=.*/, "", k); gsub(/[[:space:]]/, "", k)
      v = $0; sub(/^[^=]*=/, "", v); gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
      val[k] = v }
    END {
      r = ("MaxRetentionSec" in val) ? val["MaxRetentionSec"] : "-"
      f = ("MaxFileSec" in val) ? val["MaxFileSec"] : "-"
      print r, f }' "$1"
}

# The journald drop-in of SCENARIO after its run 1: [Journal] with MaxRetentionSec=6day
# and MaxFileSec=1day, mode 644, owner root, directory mode 755; systemd-journald
# restarted exactly once in run 1.
journald_written() { # SCENARIO
  local f r
  f="$(upper "$1" etc)${JOURNALD_DROPIN#/etc}"
  if [[ ! -f $f ]]; then
    no "$JOURNALD_DROPIN was not written"
    return
  fi
  [[ $(journald_values "$f") == "6day 1day" ]] ||
    no "[Journal] of $JOURNALD_DROPIN: MaxRetentionSec MaxFileSec = '$(journald_values "$f")', expected '6day 1day':" "$(cat "$f")"
  [[ $(stat -c '%a %U:%G' "$f") == "644 root:root" ]] || no "$JOURNALD_DROPIN: mode and owner $(stat -c '%a %U:%G' "$f"), expected 644 root:root"
  [[ $(stat -c %a "$(dirname "$f")") == 755 ]] || no "$(dirname "$JOURNALD_DROPIN"): mode $(stat -c %a "$(dirname "$f")"), expected 755"
  r=$(grep -E '^systemctl .*journald' "$(art "$1")/log1")
  [[ $r =~ ^systemctl\ restart\ systemd-journald(\.service)?$ ]] ||
    no "run 1 (drop-in written): expected exactly one 'systemctl restart systemd-journald', got:" "${r:-nothing}"
}

# Fresh server: journald keeps entries with IP addresses for about 7 days at most (see
# journald_written). Run 2 leaves the drop-in as it is (inode, times, content) and does
# not restart systemd-journald.
t_journald_dropin() { # SCENARIO
  local ok=1 a s1 d r
  have_run "$1" 2 || return 1
  a=$(art "$1")
  [[ $(rc_of "$1" 1) == 0 ]] || no "run 1: expected exit code 0, got: $(rc_of "$1" 1)"
  journald_written "$1"
  s1=$(snap_of "$1" 1 "$JOURNALD_DROPIN")
  if [[ -z $s1 ]]; then
    no "$JOURNALD_DROPIN is not in the snapshot after run 1"
  else
    d=$(diff <(printf '%s\n' "$s1") <(snap_of "$1" 2 "$JOURNALD_DROPIN")) || no "run 2 changed $JOURNALD_DROPIN:" "$d"
  fi
  r=$(grep -E '^systemctl .*journald' "$a/log2")
  [[ -z $r ]] || no "run 2 (drop-in unchanged) touched systemd-journald:" "$r"
  return $((1 - ok))
}

# A drop-in from an earlier version (other values, mode 600) is replaced (see
# journald_written), and systemd-journald restarted once.
t_journald_old_replaced() { # SCENARIO
  local ok=1 s0
  have_run "$1" 1 || return 1
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)"
  s0=$(snap_of "$1" 0 "$JOURNALD_DROPIN")
  grep -q '|600|' <<<"$s0" || no "fixture: no old $JOURNALD_DROPIN with mode 600 before the run:" "$s0"
  journald_written "$1"
  return $((1 - ok))
}

# Items of a logrotate file: "path P" for every log file named before "{", "dir D" for
# every directive inside the block (words joined by one space); scripts (postrotate
# ... endscript and the like) only by their first word.
logrotate_items() { # FILE
  awk '
    /^[[:space:]]*#/ || NF == 0 { next }
    script { if ($1 == "endscript") script = 0; next }
    !block { for (i = 1; i <= NF; i++) { if ($i == "{") block = 1; else if (!block) print "path " $i }; next }
    $1 == "}" { block = 0; next }
    $1 ~ /^(prerotate|postrotate|firstaction|lastaction|preremove)$/ { script = 1; print "dir " $1; next }
    { $1 = $1; print "dir " $0 }' "$1"
}

# rsyslog installed: /etc/logrotate.d/00-auth-log rotates only /var/log/auth.log, with
# daily, rotate 6, ignoreduplicates, ifempty, missingok and nothing that keeps it
# longer; mode 644, owner root. The package file /etc/logrotate.d/rsyslog stays as it
# is (inode, times, content) in both runs; run 2 leaves 00-auth-log as it is.
t_auth_logrotate() { # SCENARIO
  local ok=1 a f items d bad r s0
  have_run "$1" 2 || return 1
  a=$(art "$1")
  for r in 1 2; do
    [[ $(rc_of "$1" "$r") == 0 ]] || no "run $r: expected exit code 0, got: $(rc_of "$1" "$r")"
  done
  f="$(upper "$1" etc)${AUTH_LOGROTATE#/etc}"
  if [[ -f $f ]]; then
    items=$(logrotate_items "$f")
    [[ $(grep '^path ' <<<"$items") == "path /var/log/auth.log" ]] ||
      no "$AUTH_LOGROTATE must name /var/log/auth.log and nothing else, names:" "$(grep '^path ' <<<"$items")"
    for d in daily "rotate 6" ignoreduplicates ifempty missingok; do
      grep -qxF "dir $d" <<<"$items" || no "$AUTH_LOGROTATE lacks: $d"
    done
    bad=$(grep -E '^dir (hourly|weekly|monthly|yearly|notifempty|size|minsize|minage)( |$)' <<<"$items")
    [[ -z $bad ]] || no "$AUTH_LOGROTATE has directives that rotate less often or keep it longer:" "$bad"
    [[ $(grep -c '^dir rotate ' <<<"$items") == 1 ]] || no "$AUTH_LOGROTATE: expected exactly one rotate, found:" "$(grep '^dir rotate ' <<<"$items")"
    [[ $(stat -c '%a %U:%G' "$f") == "644 root:root" ]] || no "$AUTH_LOGROTATE: mode and owner $(stat -c '%a %U:%G' "$f"), expected 644 root:root"
    d=$(diff <(snap_of "$1" 1 "$AUTH_LOGROTATE") <(snap_of "$1" 2 "$AUTH_LOGROTATE")) || no "run 2 changed $AUTH_LOGROTATE:" "$d"
    ((ok)) || no "$AUTH_LOGROTATE:"$'\n'"$(cat "$f")"
  else
    no "$AUTH_LOGROTATE was not written although rsyslog is installed"
  fi
  s0=$(snap_of "$1" 0 "$RSYSLOG_LOGROTATE")
  [[ -n $s0 ]] || no "fixture: no $RSYSLOG_LOGROTATE before the run"
  for r in 1 2; do
    d=$(diff <(printf '%s\n' "$s0") <(snap_of "$1" "$r" "$RSYSLOG_LOGROTATE")) || no "run $r changed $RSYSLOG_LOGROTATE:" "$d"
  done
  return $((1 - ok))
}

# rsyslog not installed (unknown to dpkg, or removed with only its conffiles left):
# no 00-auth-log and no other new file in /etc/logrotate.d; a leftover
# /etc/logrotate.d/rsyslog stays as it is. The run reached the log retention step and
# asked dpkg-query about rsyslog.
t_no_auth_logrotate() { # SCENARIO
  local ok=1 a dir new s0 d
  have_run "$1" 1 || return 1
  a=$(art "$1")
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)"
  [[ -f "$(upper "$1" etc)${JOURNALD_DROPIN#/etc}" ]] || no "the run did not reach the log retention step (no $JOURNALD_DROPIN)"
  grep -qE '^dpkg-query( .*)? rsyslog$' "$a/log1" || no "the script did not ask dpkg-query whether rsyslog is installed"
  dir="$(upper "$1" etc)/logrotate.d"
  [[ ! -f $dir/00-auth-log ]] || no "$AUTH_LOGROTATE written although rsyslog is not installed:" "$(cat "$dir/00-auth-log")"
  new=$(find "$dir" -mindepth 1 -type f ! -name rsyslog 2>/dev/null)
  [[ -z $new ]] || no "new files in /etc/logrotate.d:" "$new"
  s0=$(snap_of "$1" 0 "$RSYSLOG_LOGROTATE")
  if [[ -n $s0 ]]; then
    d=$(diff <(printf '%s\n' "$s0") <(snap_of "$1" 1 "$RSYSLOG_LOGROTATE")) || no "run changed $RSYSLOG_LOGROTATE:" "$d"
  fi
  return $((1 - ok))
}

# Dry run: exit 0, nothing changed; it shows the journald drop-in with its content and
# the restart, and the auth.log rotation with its content if WITH_AUTH is 1, or not at
# all if WITH_AUTH is 0 (rsyslog not installed). /etc/logrotate.d/rsyslog never shows
# up as written.
t_dry_log_retention() { # SCENARIO WITH_AUTH(0|1)
  local ok=1 all re
  have_run "$1" 1 || return 1
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)"
  assert_unchanged "$1" 1
  all=$(cat "$(art "$1")/out1" "$(art "$1")/err1")
  for re in "würde $JOURNALD_DROPIN schreiben" '\|[[:space:]]+\[Journal\]$' '\|[[:space:]]+MaxRetentionSec=6day$' \
    '\|[[:space:]]+MaxFileSec=1day$' '\[Testlauf\] systemctl restart systemd-journald$'; do
    grep -qE -- "$re" <<<"$all" || no "dry-run output lacks: $re"
  done
  if [[ $2 == 1 ]]; then
    for re in "würde $AUTH_LOGROTATE schreiben" '\|[[:space:]]+/var/log/auth\.log \{$' '\|[[:space:]]+daily$' \
      '\|[[:space:]]+rotate 6$' '\|[[:space:]]+ignoreduplicates$' '\|[[:space:]]+ifempty$' '\|[[:space:]]+missingok$'; do
      grep -qE -- "$re" <<<"$all" || no "dry-run output lacks: $re"
    done
  else
    ! grep -qF -- "$AUTH_LOGROTATE" <<<"$all" || no "dry run shows $AUTH_LOGROTATE although rsyslog is not installed:" "$(grep -F -- "$AUTH_LOGROTATE" <<<"$all")"
  fi
  ! grep -qE -- "würde $RSYSLOG_LOGROTATE|\[Testlauf\] .*$RSYSLOG_LOGROTATE" <<<"$all" ||
    no "dry run would change $RSYSLOG_LOGROTATE:" "$(grep -F -- "$RSYSLOG_LOGROTATE" <<<"$all")"
  return $((1 - ok))
}

# --- tests: fail2ban values of the privacy policy ------------------------------

F2B_LOCAL=/etc/fail2ban/fail2ban.local
F2B_JAIL=/etc/fail2ban/jail.local
# Effective values the privacy policy names (times in seconds), plus backend and ban
# action of the jail sshd, as f2b_values prints them.
F2B_WANT='dbpurgeage=86400
logtarget=SYSLOG[facility=AUTHPRIV]
sshd.addaction=iptables-multiport
sshd.backend=systemd
sshd.bantime=600
sshd.findtime=600
sshd.maxretry=5'

# f2b_values FILE: from the output of "fail2ban-client -d" (the commands fail2ban would
# load), the values of logtarget and dbpurgeage, and of the jail sshd maxretry,
# findtime, bantime, backend and actions; times converted to seconds with fail2ban's
# own parser. One "key=value" per line, sorted.
f2b_values() { # FILE
  python3 -I - "$1" <<'PY'
import ast
import sys

from fail2ban.server.mytime import MyTime

out = {}
actions = []
with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.strip()
        if not line.startswith("["):
            continue
        try:
            c = ast.literal_eval(line)
        except (ValueError, SyntaxError):
            continue
        if not isinstance(c, list):
            continue
        if len(c) == 3 and c[0] == "set" and c[1] in ("logtarget", "dbpurgeage"):
            out[c[1]] = c[2]
        elif len(c) == 3 and c[:2] == ["add", "sshd"]:
            out["sshd.backend"] = c[2]
        elif len(c) == 4 and c[:2] == ["set", "sshd"] and c[2] in ("maxretry", "findtime", "bantime"):
            out["sshd." + c[2]] = c[3]
        elif len(c) >= 4 and c[:3] == ["set", "sshd", "addaction"]:
            actions.append(c[3])
for k in ("dbpurgeage", "sshd.findtime", "sshd.bantime"):
    if k in out:
        out[k] = int(MyTime.str2seconds(str(out[k])))
if actions:
    out["sshd.addaction"] = ",".join(actions)
for k in sorted(out):
    print("%s=%s" % (k, out[k]))
PY
}

# After the last run of SCENARIO, fail2ban-client -d has the values of F2B_WANT, so
# they are what fail2ban loads, not only text in a file; fail2ban.local and jail.local
# are 644 root:root. If the fixture changed the package defaults (f2b_dump0), each of
# these values was different before the run.
t_f2b_effective() { # SCENARIO RUNS
  local ok=1 a r got k v0 f p
  have_run "$1" "$2" || return 1
  a=$(art "$1")
  for ((r = 1; r <= $2; r++)); do
    [[ $(rc_of "$1" "$r") == 0 ]] || no "run $r: expected exit code 0, got: $(rc_of "$1" "$r")" "$(tail -3 "$a/err$r")"
  done
  if [[ ! -s $a/f2b_dump ]]; then
    no "fail2ban-client -d after the run printed nothing (configuration invalid?)"
  else
    got=$(f2b_values "$a/f2b_dump")
    [[ $got == "$F2B_WANT" ]] ||
      no "effective fail2ban values (fail2ban-client -d), expected < got >:" "$(diff <(printf '%s\n' "$F2B_WANT") <(printf '%s\n' "$got"))"
  fi
  if [[ -f $a/f2b_dump0 ]]; then
    for k in dbpurgeage logtarget sshd.bantime sshd.findtime sshd.maxretry; do
      v0=$(f2b_values "$a/f2b_dump0" | awk -F= -v k="$k" '$1 == k')
      if [[ -z $v0 ]] || grep -qxF -- "$v0" <<<"$F2B_WANT"; then
        no "fixture: changed default for $k not in effect before the run (${v0:-not set})"
      fi
    done
  fi
  for f in "$F2B_LOCAL" "$F2B_JAIL"; do
    p="$(upper "$1" etc)${f#/etc}"
    if [[ ! -f $p ]]; then
      no "$f was not written"
    elif [[ $(stat -c '%a %U:%G' "$p") != "644 root:root" ]]; then
      no "$f: mode and owner $(stat -c '%a %U:%G' "$p"), expected 644 root:root"
    fi
  done
  return $((1 - ok))
}

# Lines of a call log that restart or reload fail2ban.
F2B_RESTART_RE='^systemctl (restart|try-restart|reload-or-restart|try-reload-or-restart|reload|force-reload) fail2ban(\.service)?$'

# sha256 line of PATH in snapshot N of SCENARIO (content only, no inode or times).
snap_sha() { snap_of "$@" | grep -v '|'; }

# fail2ban is restarted in exactly the runs that change fail2ban.local or jail.local,
# once, and after fail2ban-client -t:
#   none   fresh server: run 1 writes both files and restarts, run 2 does not restart.
#   local  between run 1 and 2 an older fail2ban.local was put in place: run 2 writes
#          it back (content as after run 1), leaves jail.local as it is (inode, times,
#          content) and restarts.
#   jail   the same with jail.local.
t_f2b_restart() { # SCENARIO none|local|jail
  local ok=1 a r n t s changed kept d
  local -a want
  have_run "$1" 2 || return 1
  a=$(art "$1")
  for r in 1 2; do
    [[ $(rc_of "$1" "$r") == 0 ]] || no "run $r: expected exit code 0, got: $(rc_of "$1" "$r")" "$(tail -3 "$a/err$r")"
  done
  if [[ $2 == none ]]; then want=(1 0); else want=(1 1); fi
  for r in 1 2; do
    n=$(grep -cE "$F2B_RESTART_RE" "$a/log$r")
    ((n == want[r - 1])) ||
      no "run $r: $n fail2ban restarts, expected ${want[r - 1]}:" "$(grep -E '^(systemctl .*fail2ban|fail2ban-client)' "$a/log$r")"
    if ((n >= 1)); then
      t=$(grep -nE '^fail2ban-client -t( |$)' "$a/log$r" | head -1 | cut -d: -f1)
      s=$(grep -nE "$F2B_RESTART_RE" "$a/log$r" | head -1 | cut -d: -f1)
      if [[ -z $t ]] || ((t > s)); then no "run $r: fail2ban restarted without fail2ban-client -t before it"; fi
    fi
  done
  if [[ $2 != none ]]; then
    if [[ $2 == local ]]; then changed=$F2B_LOCAL kept=$F2B_JAIL; else changed=$F2B_JAIL kept=$F2B_LOCAL; fi
    [[ $(snap_sha "$1" 1_pre "$changed") != "$(snap_sha "$1" 1 "$changed")" ]] ||
      no "fixture: $changed was not changed between run 1 and run 2"
    [[ -n $(snap_sha "$1" 2 "$changed") && $(snap_sha "$1" 2 "$changed") == "$(snap_sha "$1" 1_pre "$changed")" ]] ||
      no "run 2 did not put back the content of run 1 in $changed"
    [[ -n $(snap_of "$1" 1 "$kept") ]] || no "$kept is not there after run 1"
    d=$(diff <(snap_of "$1" 1 "$kept") <(snap_of "$1" 2 "$kept")) || no "run 2 changed $kept:" "$d"
  fi
  return $((1 - ok))
}

# --- tests: logrotate for btmp, wtmp and fail2ban.log -----------------------------

LOGIN_LOGROTATE=/etc/logrotate.d/00-login-logs
F2B_LOGROTATE=/etc/logrotate.d/00-fail2ban-log
LOGROTATE_PKG_FILES="/etc/logrotate.d/btmp /etc/logrotate.d/wtmp /etc/logrotate.d/fail2ban"

# Directives per log file of a logrotate file: "PATH<TAB>DIRECTIVE" for every path
# named before "{" and every directive in its block (words joined by one space);
# scripts (postrotate ... endscript and the like) only by their first word.
logrotate_blocks() { # FILE
  awk '
    /^[[:space:]]*#/ || NF == 0 { next }
    script { if ($1 == "endscript") script = 0; next }
    !block { for (i = 1; i <= NF; i++) { if ($i == "{") block = 1; else if (!block) paths[++np] = $i }; next }
    $1 == "}" { block = 0; np = 0; split("", paths); next }
    { if ($1 ~ /^(prerotate|postrotate|firstaction|lastaction|preremove)$/) { script = 1; d = $1 } else { $1 = $1; d = $0 }
      for (i = 1; i <= np; i++) print paths[i] "\t" d }' "$1"
}

# lr_block_ok ITEMS FILE "PATH MODE OWNER GROUP": in ITEMS (logrotate_blocks of FILE)
# PATH has daily, exactly one rotate (rotate 6), ifempty, missingok, ignoreduplicates,
# exactly one create (create MODE OWNER GROUP, mode with or without leading 0), and
# nothing that rotates it less often or keeps it longer.
lr_block_ok() {
  local items=$1 file=$2 path mode owner group b d bad
  read -r path mode owner group <<<"$3"
  b=$(awk -F'\t' -v p="$path" '$1 == p { print $2 }' <<<"$items")
  if [[ -z $b ]]; then
    no "$file has no block for $path"
    return
  fi
  for d in daily "rotate 6" ifempty missingok ignoreduplicates; do
    grep -qxF -- "$d" <<<"$b" || no "$file, $path: lacks $d"
  done
  [[ $(grep -c '^rotate ' <<<"$b") == 1 ]] || no "$file, $path: expected exactly one rotate, found:" "$(grep '^rotate ' <<<"$b")"
  if [[ $(grep -cE '^(no)?create( |$)' <<<"$b") != 1 ]] || ! grep -qxE -- "create 0?${mode#0} $owner $group" <<<"$b"; then
    no "$file, $path: expected exactly one 'create $mode $owner $group', found:" "$(grep -E '^(no)?create( |$)' <<<"$b")"
  fi
  bad=$(grep -E '^(hourly|weekly|monthly|yearly|notifempty|size|minsize|minage)( |$)' <<<"$b")
  [[ -z $bad ]] || no "$file, $path: directives that rotate less often or keep it longer:" "$bad"
}

# logrotate installed: FILE names exactly the paths of the SPECs ("PATH MODE OWNER
# GROUP") and each block is as lr_block_ok wants it; mode 644 root:root; later runs
# leave FILE as it is. The package files PKG ("/etc/logrotate.d/NAME ...") stay as
# they are (inode, times, content) in every run.
t_lr_file() { # SCENARIO RUNS FILE "PKG..." SPEC...
  local ok=1 s=$1 runs=$2 file=$3 pkgs=$4 a f r d s0 pkg spec want paths
  shift 4
  have_run "$s" "$runs" || return 1
  a=$(art "$s")
  for ((r = 1; r <= runs; r++)); do
    [[ $(rc_of "$s" "$r") == 0 ]] || no "run $r: expected exit code 0, got: $(rc_of "$s" "$r")" "$(tail -3 "$a/err$r")"
  done
  f="$(upper "$s" etc)${file#/etc}"
  if [[ ! -f $f ]]; then
    no "$file was not written although logrotate is installed"
  else
    want=$(for spec in "$@"; do echo "${spec%% *}"; done | LC_ALL=C sort)
    paths=$(logrotate_items "$f" | sed -n 's/^path //p' | LC_ALL=C sort)
    [[ $paths == "$want" ]] || no "$file must name exactly these log files:" "$want" "it names:" "$paths"
    for spec in "$@"; do lr_block_ok "$(logrotate_blocks "$f")" "$file" "$spec"; done
    [[ $(stat -c '%a %U:%G' "$f") == "644 root:root" ]] || no "$file: mode and owner $(stat -c '%a %U:%G' "$f"), expected 644 root:root"
    for ((r = 2; r <= runs; r++)); do
      d=$(diff <(snap_of "$s" 1 "$file") <(snap_of "$s" "$r" "$file")) || no "run $r changed $file:" "$d"
    done
    ((ok)) || no "$file:"$'\n'"$(cat "$f")"
  fi
  for pkg in $pkgs; do
    s0=$(snap_of "$s" 0 "$pkg")
    if [[ -z $s0 ]]; then
      no "fixture: no $pkg before the run"
      continue
    fi
    for ((r = 1; r <= runs; r++)); do
      d=$(diff <(printf '%s\n' "$s0") <(snap_of "$s" "$r" "$pkg")) || no "run $r changed $pkg:" "$d"
    done
  done
  return $((1 - ok))
}

t_no_warning() { # SCENARIO REGEX: no warning on stderr of run 1 matches REGEX
  local ok=1 w
  have_run "$1" 1 || return 1
  w=$(grep -E 'WARNUNG:' "$(art "$1")/err1" | grep -E -- "$2")
  [[ -z $w ]] || no "unexpected warning:" "$w"
  return $((1 - ok))
}

# logrotate not installed (unknown to dpkg, or removed with only its conffiles left):
# no 00-login-logs and no 00-fail2ban-log, a warning that names logrotate; package
# files left in /etc/logrotate.d stay as they are. The run reached the log retention
# step and asked dpkg-query about logrotate.
t_no_lr() { # SCENARIO
  local ok=1 a dir pkg s0 d
  have_run "$1" 1 || return 1
  a=$(art "$1")
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)"
  [[ -f "$(upper "$1" etc)${JOURNALD_DROPIN#/etc}" ]] || no "the run did not reach the log retention step (no $JOURNALD_DROPIN)"
  grep -qE '^dpkg-query( .*)? logrotate$' "$a/log1" || no "the script did not ask dpkg-query whether logrotate is installed"
  dir="$(upper "$1" etc)/logrotate.d"
  [[ ! -e $dir/00-login-logs ]] || no "$LOGIN_LOGROTATE written although logrotate is not installed"
  [[ ! -e $dir/00-fail2ban-log ]] || no "$F2B_LOGROTATE written although logrotate is not installed"
  grep -E 'WARNUNG:' "$a/err1" | grep -q 'logrotate' || no "no warning that names logrotate:" "$(grep 'WARNUNG' "$a/err1")"
  for pkg in $LOGROTATE_PKG_FILES; do
    s0=$(snap_of "$1" 0 "$pkg")
    [[ -n $s0 ]] || continue
    d=$(diff <(printf '%s\n' "$s0") <(snap_of "$1" 1 "$pkg")) || no "run changed $pkg:" "$d"
  done
  return $((1 - ok))
}

# Dry run with logrotate installed: exit 0, nothing changed; it shows 00-login-logs and
# 00-fail2ban-log with their blocks, and none of the package files as written.
t_dry_lr() { # SCENARIO
  local ok=1 all re
  have_run "$1" 1 || return 1
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)"
  assert_unchanged "$1" 1
  all=$(cat "$(art "$1")/out1" "$(art "$1")/err1")
  for re in "würde $LOGIN_LOGROTATE schreiben" "würde $F2B_LOGROTATE schreiben" '\|[[:space:]]+/var/log/btmp \{$' \
    '\|[[:space:]]+/var/log/wtmp \{$' '\|[[:space:]]+/var/log/fail2ban\.log \{$'; do
    grep -qE -- "$re" <<<"$all" || no "dry-run output lacks: $re"
  done
  ! grep -qE -- 'würde /etc/logrotate\.d/(btmp|wtmp|fail2ban|rsyslog) ' <<<"$all" ||
    no "dry run would write a package file:" "$(grep -E 'würde /etc/logrotate\.d/' <<<"$all")"
  return $((1 - ok))
}

# --- tests: UFW -------------------------------------------------------------------

# ufw installed and inactive (Oracle's image): a warning that names ufw, and the run
# goes on to the end with exit 0.
t_ufw_inactive_warns() { # SCENARIO
  local ok=1 a
  have_run "$1" 1 || return 1
  a=$(art "$1")
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)" "$(tail -3 "$a/err1")"
  grep -qx 'ufw status' "$a/log1" || no "the script did not ask 'ufw status'"
  grep -E 'WARNUNG:' "$a/err1" | grep -qE 'ufw|UFW' || no "no warning that names ufw:" "$(grep 'WARNUNG' "$a/err1")"
  grep -qE 'Änderungen in diesem Lauf: [0-9]' "$a/out1" || no "the run did not reach the end"
  return $((1 - ok))
}

# No ufw on the server (unknown to dpkg, no command): the script does not call ufw,
# does not warn about it and runs through.
t_ufw_absent() { # SCENARIO
  local ok=1 a
  have_run "$1" 1 || return 1
  a=$(art "$1")
  if PATH=$SANDBOX_PATH_TAIL command -v ufw >/dev/null 2>&1; then
    no "fixture: the host has a ufw command in $SANDBOX_PATH_TAIL, this scenario cannot hide it"
  fi
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)" "$(tail -3 "$a/err1")"
  ! grep -qE '^ufw( |$)' "$a/log1" || no "ufw was called although it is not there:" "$(grep -E '^ufw' "$a/log1")"
  t_no_warning "$1" 'ufw|UFW' || ok=0
  return $((1 - ok))
}

# Dry run: exit 0, nothing changed, and stderr says that a real run would abort, for
# the reason REGEX.
t_dry_would_abort() { # SCENARIO REGEX
  local ok=1 a
  have_run "$1" 1 || return 1
  a=$(art "$1")
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)"
  assert_unchanged "$1" 1
  grep -E '\[Testlauf\].*abbrechen' "$a/err1" | grep -qE -- "$2" ||
    no "dry run does not say that a real run would abort (/$2/):" "$(cat "$a/err1")"
  return $((1 - ok))
}

# --- tests: SSH settings that do not take effect, admin locked out ----------------

# As t_sshd_rollback (drop-in as before, no reload, abort right there), and the abort
# message names the reason REGEX.
t_sshd_rollback_because() { # SCENARIO REGEX
  local ok=1
  t_sshd_rollback "$1" || ok=0
  grep -E '^Abbruch' "$(art "$1")/err1" | grep -qE -- "$2" ||
    no "the abort message does not name the reason (/$2/):" "$(cat "$(art "$1")/err1")"
  return $((1 - ok))
}

# DenyUsers, AllowGroups and DenyGroups that do not exclude ubuntu, and an earlier
# drop-in that agrees: the run goes through, ssh is reloaded, sshd -T has the hardening
# and every LINE (the fixture is in effect).
t_sshd_accepts() { # SCENARIO LINE...
  local ok=1 s=$1 a eff l
  shift
  have_run "$s" 1 || return 1
  a=$(art "$s")
  [[ $(rc_of "$s" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$s" 1)" "$(grep -E '^Abbruch' "$a/err1")"
  grep -qE '^systemctl reload ssh(\.service)?$' "$a/log1" || no "ssh was not reloaded"
  t_sshd_effective "$s" ubuntu || ok=0
  eff=$(cat "$a/sshd_T")
  for l in "$@"; do
    grep -qxF -- "$l" <<<"$eff" || no "fixture not in effect: sshd -T lacks '$l'"
  done
  return $((1 - ok))
}

# --- tests: /run/sshd -------------------------------------------------------------

t_run_sshd_fixture() { # SCENARIO: /run/sshd was missing before the run
  [[ -f $(art "$1")/run_sshd_absent ]] || no "fixture: /run/sshd was there before the run"
}

# /run/sshd was missing: the run creates it and goes through. sshd accepts it only owned
# by root and not writable by group or others.
t_run_sshd_created() { # SCENARIO
  local ok=1 p
  have_run "$1" 1 || return 1
  t_run_sshd_fixture "$1"
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)" "$(grep -E '^Abbruch' "$(art "$1")/err1")"
  p="$(upper "$1" run)/sshd"
  if [[ ! -d $p ]]; then
    no "/run/sshd was not created"
  elif [[ $(stat -c %U "$p") != root ]] || (($(stat -c '0%a' "$p") & 022)); then
    no "/run/sshd: mode and owner $(stat -c '%a %U:%G' "$p"), expected owner root, not writable by group or others"
  fi
  return $((1 - ok))
}

# /run/sshd was missing and the checks stop the run (reason REGEX in the abort
# message). The only change is /run/sshd, created in the checks: all other files as
# before (content, inode, mode, owner, times), firewall unchanged, no modifying command.
t_aborts_only_run_sshd() { # SCENARIO REGEX
  local ok=1 a rc d calls
  have_run "$1" 1 || return 1
  a=$(art "$1")
  t_run_sshd_fixture "$1"
  rc=$(rc_of "$1" 1)
  [[ $rc =~ ^[0-9]+$ && $rc -ne 0 ]] || no "expected exit code != 0, got: $rc"
  grep -E '^Abbruch' "$a/err1" | grep -qE -- "$2" || no "the abort message does not name the reason (/$2/):" "$(cat "$a/err1")"
  [[ -d $(upper "$1" run)/sshd ]] || no "/run/sshd was not created in the checks"
  d=$(diff <(grep -vE '^\./run/u(/sshd)?\|' "$a/snap0") <(grep -vE '^\./run/u(/sshd)?\|' "$a/snap1")) ||
    no "files changed apart from /run/sshd:" "$d"
  d=$(diff "$a/fw0" "$a/fw1") || no "firewall rules changed:" "$d"
  calls=$(modifying_calls "$a/log1" strict)
  [[ -z $calls ]] || no "modifying commands were run:" "$calls"
  return $((1 - ok))
}

# Dry run without /run/sshd: exit 0, nothing changed (/run/sshd not created either),
# and it shows that a real run creates /run/sshd.
t_dry_run_sshd() { # SCENARIO
  local ok=1
  have_run "$1" 1 || return 1
  t_run_sshd_fixture "$1"
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)"
  assert_unchanged "$1" 1
  [[ ! -d $(upper "$1" run)/sshd ]] || no "dry run created /run/sshd"
  grep -qE '\[Testlauf\] install .*/run/sshd' "$(art "$1")/out1" || no "dry run does not show that /run/sshd would be created"
  return $((1 - ok))
}

# --- tests: the test sandbox itself -------------------------------------------

t_guard_refuses() { # GUARD_CASE
  local ok=1 a
  a=$(art "$1")
  [[ -f $a/guard_rc ]] || {
    no "guard case $1 did not run"
    return 1
  }
  ! grep -qx 'rc=0' "$a/guard_rc" || no "the inner entry point exited with 0"
  [[ ! -e $a/inner_ok ]] || no "the inner entry point ran the scenario (inner_ok written)"
  [[ ! -e $a/ovl ]] || no "the inner entry point prepared overlays before refusing ($a/ovl exists)"
  grep -q 'REFUSED' "$a/inner.log" || no "no REFUSED message:" "$(cat "$a/inner.log")"
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

# prepare_keys DIR: key files the curl stub serves (SC_DOCKER_KEY=NAME -> DIR/NAME.asc):
#   docker   Docker's key (fixture)
#   wrong    a valid key with another fingerprint, generated for this run
#   two      Docker's key followed by the wrong one in one file
#   invalid  armor lines around something that is no key
prepare_keys() {
  local dir=$1 g rc=0 f
  mkdir -p "$dir"
  install -m 0644 "$FIXTURES/docker.asc" "$dir/docker.asc" || return 1
  g=$(mktemp -d "$WORK/gpg-gen.XXXXXX") || return 1
  GNUPGHOME=$g gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
    --quick-gen-key 'Test key with a wrong fingerprint <test@example.invalid>' ed25519 sign never \
    >/dev/null 2>&1 || rc=1
  if ((rc == 0)); then
    GNUPGHOME=$g gpg --batch --armor --export >"$dir/wrong.asc" 2>/dev/null || rc=1
  fi
  # Stop the agent the key generation started and drop the secret key.
  GNUPGHOME=$g gpgconf --kill all >/dev/null 2>&1
  rm -rf -- "$g"
  ((rc == 0)) || return 1
  cat "$dir/docker.asc" "$dir/wrong.asc" >"$dir/two.asc"
  printf '%s\n' '-----BEGIN PGP PUBLIC KEY BLOCK-----' '' 'not a key (test)' \
    '-----END PGP PUBLIC KEY BLOCK-----' >"$dir/invalid.asc"
  # Otherwise the negative tests would not test the fingerprint comparison.
  f=$(key_fprs "$dir/wrong.asc")
  [[ $f =~ ^[0-9A-F]{40}$ && $f != "$DOCKER_FPR" ]] || return 1
  [[ $(key_fprs "$dir/two.asc" | wc -l) -eq 2 ]] || return 1
  [[ -z $(key_fprs "$dir/invalid.asc") ]] || return 1
}

main() {
  local missing=() c
  if [[ $EUID -ne 0 ]]; then
    echo "CANNOT RUN: needs root (sandbox with unshare, overlayfs and network namespace)."
    exit 2
  fi
  for c in unshare setpriv iptables ip6tables iptables-save ip6tables-save iptables-restore \
    ip6tables-restore /usr/sbin/sshd fail2ban-client apt-config shellcheck python3 diff \
    gpg gpgconf /usr/sbin/useradd /usr/sbin/groupadd /usr/sbin/groupdel mount readlink cmp; do
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
  [[ -f $FIXTURES/docker.asc ]] || {
    echo "CANNOT RUN: $FIXTURES/docker.asc not found"
    exit 2
  }
  if ! id ubuntu >/dev/null 2>&1 || ! id claude >/dev/null 2>&1; then
    echo "CANNOT RUN: users ubuntu and claude must exist (fixtures)"
    exit 2
  fi
  if id srvadmin >/dev/null 2>&1; then
    echo "CANNOT RUN: user srvadmin exists on this host (the fixtures create it)"
    exit 2
  fi
  for c in sshlogin sshdeny; do
    if getent group "$c" >/dev/null; then
      echo "CANNOT RUN: group $c exists on this host (the fixtures create it)"
      exit 2
    fi
  done
  # Namespaces of this process; inner refuses to run in them (inner_guard).
  CALLER_NET=$(readlink /proc/self/ns/net) || CALLER_NET=""
  CALLER_MNT=$(readlink /proc/self/ns/mnt) || CALLER_MNT=""
  if [[ -z $CALLER_NET || -z $CALLER_MNT ]]; then
    echo "CANNOT RUN: /proc/self/ns not readable"
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
  # The same stubs without ufw, for a server without ufw (SC_UFW=absent).
  cp -a "$WORK/stubs" "$WORK/stubs-noufw" && rm -f "$WORK/stubs-noufw/ufw"
  if ! prepare_keys "$WORK/keys"; then
    echo "CANNOT RUN: test keys could not be prepared (gpg)"
    exit 2
  fi
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
  scenario fw_after_reject SC_FW=accept_after_reject SC_RUNS=2
  scenario fw_drop_policy SC_FW=drop_policy SC_V6=none
  scenario rerun_real SC_RUNS=2 SC_BETWEEN=1
  # Who may log in afterwards
  scenario sudo_other SC_SUDO_USER=claude
  scenario sudo_admin SC_SUDO_USER=ubuntu
  scenario sudo_root SC_SUDO_USER=root
  scenario sudo_alt SC_SUDO_USER=claude SC_ADMIN_USER=claude SC_KEY_USER=claude
  scenario akf_none SC_AKF=none
  scenario akf_custom_nokey SC_AKF=custom
  scenario akf_custom_key SC_AKF=custom SC_KEY_AT=etc
  scenario akf_match_nokey SC_AKF_MATCH=1
  scenario home_getent SC_EXTRA_USER=srvadmin SC_ADMIN_USER=srvadmin SC_KEY_USER=srvadmin
  scenario home_getent_nokey SC_EXTRA_USER=srvadmin SC_ADMIN_USER=srvadmin SC_KEY_USER=srvadmin SC_KEY_AT=legacy_home
  scenario sshd_noinclude SC_SSHD_NOINCLUDE=1
  scenario sshd_noinclude_old SC_SSHD_NOINCLUDE=1 SC_SSHD_OLD=1
  # Write errors
  scenario ro_apt SC_RO=/etc/apt/apt.conf.d
  scenario ro_sshd SC_RO=/etc/ssh/sshd_config.d
  scenario busy_apt SC_BUSY=/etc/apt/apt.conf.d/20auto-upgrades
  # Firewall
  scenario v6_drop SC_V6=drop_policy SC_RUNS=2
  scenario fw_after_reject_v6 SC_V6=copies_after_reject SC_RUNS=2
  scenario dry_after_reject SC_DRY_RUN=1 SC_FW=accept_after_reject SC_V6=copies_after_reject
  scenario race_insert SC_FW=accept_after_reject SC_V6=none SC_IPT_RACE=insert
  # Log retention
  scenario rsyslog "SC_DPKG=rsyslog=install ok installed" SC_LOGROTATE_RSYSLOG=1 SC_RUNS=2
  scenario rsyslog_removed "SC_DPKG=rsyslog=deinstall ok config-files" SC_LOGROTATE_RSYSLOG=1
  scenario rsyslog_hold "SC_DPKG=rsyslog=hold ok installed" SC_LOGROTATE_RSYSLOG=1 SC_RUNS=2
  scenario dry_rsyslog SC_DRY_RUN=1 "SC_DPKG=rsyslog=install ok installed" SC_LOGROTATE_RSYSLOG=1
  scenario journald_old SC_JOURNALD_OLD=1
  scenario lr "SC_DPKG=logrotate=install ok installed" SC_LOGROTATE_PKG=1 SC_RUNS=2
  scenario lr_rsyslog "SC_DPKG=$(printf '%s\n' 'rsyslog=install ok installed' 'logrotate=hold ok installed')" \
    SC_LOGROTATE_PKG=1 SC_LOGROTATE_RSYSLOG=1
  scenario lr_removed "SC_DPKG=logrotate=deinstall ok config-files" SC_LOGROTATE_PKG=1
  scenario dry_lr SC_DRY_RUN=1 "SC_DPKG=logrotate=install ok installed" SC_LOGROTATE_PKG=1
  # fail2ban values of the privacy policy
  scenario f2b_defaults SC_F2B_DEFAULTS=1
  scenario f2b_edit_local SC_RUNS=2 SC_F2B_EDIT=local
  scenario f2b_edit_jail SC_RUNS=2 SC_F2B_EDIT=jail
  # UFW
  scenario ufw_active "SC_DPKG=ufw=install ok installed" SC_UFW=active
  scenario ufw_unclear "SC_DPKG=ufw=install ok installed" SC_UFW=unclear
  scenario ufw_absent SC_UFW=absent
  scenario dry_ufw_active SC_DRY_RUN=1 "SC_DPKG=ufw=install ok installed" SC_UFW=active
  # SSH settings that do not take effect, admin locked out
  scenario ssh_early_pw "SC_SSHD_EARLY=PasswordAuthentication yes"
  scenario ssh_early_kbd "SC_SSHD_EARLY=KbdInteractiveAuthentication yes"
  scenario ssh_early_root "SC_SSHD_EARLY=PermitRootLogin prohibit-password"
  scenario ssh_match_pw "SC_SSHD_MATCH=PasswordAuthentication yes"
  scenario ssh_denyusers_star "SC_SSHD_LATE=DenyUsers ub*"
  scenario ssh_denyusers_qmark "SC_SSHD_EARLY=DenyUsers ?buntu" SC_SSHD_OLD=1
  scenario ssh_allowgroups_none SC_GROUPS=sshlogin "SC_SSHD_LATE=AllowGroups sshlogin"
  scenario ssh_denygroups SC_GROUPS=sshdeny:ubuntu "SC_SSHD_LATE=DenyGroups sshdeny"
  scenario ssh_groups_ok "SC_GROUPS=sshlogin:ubuntu sshdeny" "SC_SSHD_EARLY=PasswordAuthentication no" \
    'SC_SSHD_LATE=AllowGroups sshlogin\nDenyGroups sshdeny\nDenyUsers ub? root'
  # /run/sshd missing
  scenario run_sshd_missing SC_RUN_SSHD=missing
  scenario run_sshd_abort SC_RUN_SSHD=missing "SC_DPKG=ufw=install ok installed" SC_UFW=active
  scenario run_sshd_ro SC_RUN_SSHD=missing SC_RO=/run
  scenario run_sshd_broken SC_RUN_SSHD=missing "SC_SSHD_EARLY=ThisIsNotAnSshdOption yes"
  scenario dry_run_sshd SC_DRY_RUN=1 SC_RUN_SSHD=missing
  # Docker key
  scenario key_wrong SC_DOCKER_KEY=wrong
  scenario key_two SC_DOCKER_KEY=two
  scenario key_invalid SC_DOCKER_KEY=invalid
  # The sandbox itself
  guard_case guard_no_markers no_markers
  guard_case guard_caller_ns caller_ns
  guard_case guard_pid1 pid1
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
  check "firewall: ACCEPT 80 only after REJECT: one inserted before REJECT, copy behind stays, warning on every run, no -D/-R, second run 0 changes" \
    t_fw_copy_behind_reject fw_after_reject v4 iptables 80
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

  check "precondition: sudo called by claude, ADMIN_USER=ubuntu aborts, nothing changed" \
    t_aborts_because sudo_other 'claude'
  check "SUDO_USER=ubuntu (= ADMIN_USER) runs" t_runs_ok sudo_admin
  check "SUDO_USER=root runs" t_runs_ok sudo_root
  check "SUDO_USER=claude with ADMIN_USER=claude runs" t_runs_ok sudo_alt
  check "precondition: AuthorizedKeysFile none aborts, nothing changed" t_aborts_because akf_none 'none'
  check "precondition: AuthorizedKeysFile /etc/ssh/authorized_keys/%u without key there aborts, nothing changed" \
    t_aborts_because akf_custom_nokey '/etc/ssh/authorized_keys/ubuntu'
  check "AuthorizedKeysFile /etc/ssh/authorized_keys/%u with key there runs" t_runs_ok akf_custom_key
  check "precondition: AuthorizedKeysFile via Match User ubuntu without key there aborts, nothing changed" \
    t_aborts_because akf_match_nokey '/etc/ssh/authorized_keys/ubuntu'
  check "home directory from getent passwd (/srv/srvadmin) with key there runs" t_runs_ok home_getent
  check "home directory from getent passwd: AllowUsers srvadmin deploy (sshd -T)" t_sshd_effective home_getent srvadmin
  check "precondition: key only in /home/srvadmin, home is /srv/srvadmin aborts, nothing changed" \
    t_aborts_because home_getent_nokey '/srv/srvadmin'
  check "SSH: sshd -T without allowusers ubuntu: drop-in removed, no reload, abort" t_sshd_rollback sshd_noinclude
  check "SSH: sshd -T without allowusers ubuntu: previous drop-in back (content, mode), no reload, abort" \
    t_sshd_rollback sshd_noinclude_old
  check "SSH: temporary copy of the previous drop-in removed" t_tmp_cleaned sshd_noinclude_old

  check "write error in /etc/apt/apt.conf.d: abort, no 'geschrieben', no later step" t_write_error ro_apt \
    /etc/apt/apt.conf.d/20auto-upgrades '^(ip6?tables -[IAD] |netfilter-persistent|sshd -t|systemctl |useradd |usermod |curl )'
  check "write error only for 20auto-upgrades (directory writable): abort, no 'geschrieben', no later step" \
    t_write_error busy_apt /etc/apt/apt.conf.d/20auto-upgrades \
    '^(ip6?tables -[IAD] |netfilter-persistent|sshd -t|systemctl |useradd |usermod |curl )'
  check "write error in /etc/ssh/sshd_config.d: abort, no 'geschrieben', no reload, no later step" t_write_error ro_sshd \
    /etc/ssh/sshd_config.d/10-haertung.conf '^(sshd -t|systemctl .*(ssh|fail2ban|docker)|fail2ban-client|useradd |usermod |curl )'

  check "firewall IPv6 policy DROP without REJECT: 22/80/443 opened, policy stays DROP" t_fw_v6_drop_policy v6_drop
  check "firewall IPv6 policy DROP: second run changes nothing" t_rerun_fw_unchanged v6_drop
  check "firewall IPv6 policy ACCEPT without REJECT: no rule added" t_fw_family_unchanged fw_drop_policy v6
  check "firewall: no rule deleted, replaced, flushed or restored in any scenario (call logs and dry-run output)" t_fw_never_deletes

  check "firewall IPv6: ACCEPT 443 only after REJECT, copy of 22 after REJECT too: one 443 inserted before REJECT, both copies stay, warning on every run, no -D/-R, second run 0 changes" \
    t_fw_copy_behind_reject fw_after_reject_v6 v6 ip6tables 22 443
  check "dry run with copies behind REJECT (IPv4 and IPv6): nothing changed, same warnings and insert positions as a real run" \
    t_dry_copy_behind_reject dry_after_reject fw_after_reject fw_after_reject_v6
  check "firewall: INPUT changes right before iptables -I: ACCEPT still before REJECT, no rule lost" t_fw_insert_race race_insert

  check "log retention: journald drop-in [Journal] MaxRetentionSec=6day MaxFileSec=1day, 644, restart only in the run that writes it" \
    t_journald_dropin fresh
  check "log retention: older journald drop-in (other values, mode 600) replaced, journald restarted once" \
    t_journald_old_replaced journald_old
  check "log retention: rsyslog installed: 00-auth-log daily, rotate 6, ignoreduplicates, ifempty, missingok; logrotate.d/rsyslog unchanged" \
    t_auth_logrotate rsyslog
  check "log retention: rsyslog installed and held (hold ok installed): 00-auth-log as above, logrotate.d/rsyslog unchanged" \
    t_auth_logrotate rsyslog_hold
  check "log retention: rsyslog not installed: no 00-auth-log" t_no_auth_logrotate fresh
  check "log retention: rsyslog removed, conffiles left (deinstall ok config-files): no 00-auth-log, logrotate.d/rsyslog unchanged" \
    t_no_auth_logrotate rsyslog_removed
  check "dry run with rsyslog: shows journald drop-in and 00-auth-log with their content, changes nothing" \
    t_dry_log_retention dry_rsyslog 1
  check "dry run without rsyslog: shows journald drop-in, no 00-auth-log" t_dry_log_retention dry 0

  check "log retention: logrotate installed: 00-login-logs for btmp (create 0660 root utmp) and wtmp (create 0664 root utmp), each daily, rotate 6, ifempty, missingok, ignoreduplicates; logrotate.d/btmp and wtmp unchanged; run 2 unchanged" \
    t_lr_file lr 2 /etc/logrotate.d/00-login-logs "/etc/logrotate.d/btmp /etc/logrotate.d/wtmp" \
    "/var/log/btmp 0660 root utmp" "/var/log/wtmp 0664 root utmp"
  check "log retention: logrotate installed: 00-fail2ban-log daily, rotate 6, ifempty, missingok, ignoreduplicates, create 640 root adm; logrotate.d/fail2ban unchanged; run 2 unchanged" \
    t_lr_file lr 2 /etc/logrotate.d/00-fail2ban-log /etc/logrotate.d/fail2ban "/var/log/fail2ban.log 640 root adm"
  check "log retention: logrotate installed: no warning about logrotate" t_no_warning lr logrotate
  check "log retention: logrotate held, rsyslog installed: 00-login-logs as above, logrotate.d/btmp, wtmp, rsyslog unchanged" \
    t_lr_file lr_rsyslog 1 /etc/logrotate.d/00-login-logs "/etc/logrotate.d/btmp /etc/logrotate.d/wtmp /etc/logrotate.d/rsyslog" \
    "/var/log/btmp 0660 root utmp" "/var/log/wtmp 0664 root utmp"
  check "log retention: logrotate held, rsyslog installed: 00-fail2ban-log as above, logrotate.d/fail2ban unchanged" \
    t_lr_file lr_rsyslog 1 /etc/logrotate.d/00-fail2ban-log /etc/logrotate.d/fail2ban "/var/log/fail2ban.log 640 root adm"
  check "log retention: logrotate not installed: no 00-login-logs, no 00-fail2ban-log, warning" t_no_lr fresh
  check "log retention: logrotate removed, conffiles left: no 00-login-logs, no 00-fail2ban-log, warning, package files unchanged" \
    t_no_lr lr_removed
  check "dry run with logrotate: shows 00-login-logs and 00-fail2ban-log, changes nothing" t_dry_lr dry_lr

  check "fail2ban: effective values (fail2ban-client -d): logtarget SYSLOG[facility=AUTHPRIV], dbpurgeage 1d, sshd maxretry 5, findtime 10m, bantime 10m, systemd, iptables-multiport; files 644" \
    t_f2b_effective fresh 2
  check "fail2ban: package defaults changed (other dbpurgeage, logtarget, maxretry, findtime, bantime): effective values as in the privacy policy" \
    t_f2b_effective f2b_defaults 1
  check "fail2ban: restarted once in run 1 (after fail2ban-client -t), not in run 2 (files unchanged)" t_f2b_restart fresh none
  check "fail2ban: only fail2ban.local changed before run 2: written back, jail.local untouched, restarted once" \
    t_f2b_restart f2b_edit_local local
  check "fail2ban: only jail.local changed before run 2: written back, fail2ban.local untouched, restarted once" \
    t_f2b_restart f2b_edit_jail jail
  check "dry run shows step: fail2ban.local and the values of the privacy policy" t_dry_shows \
    '/etc/fail2ban/fail2ban\.local' '\|[[:space:]]+\[Definition\]$' '\|[[:space:]]+logtarget = SYSLOG\[facility=AUTHPRIV\]$' \
    '\|[[:space:]]+dbpurgeage = 1d$' '\|[[:space:]]+maxretry = 5$' '\|[[:space:]]+findtime = 10m$' '\|[[:space:]]+bantime = 10m$'

  check "UFW installed and active: abort before any change" t_aborts_because ufw_active '^Abbruch.*(UFW|ufw)'
  check "UFW status unclear (ufw status fails) as root: abort before any change" t_aborts_because ufw_unclear '^Abbruch.*(UFW|ufw)'
  check "UFW installed and inactive: warning, the run goes on" t_ufw_inactive_warns fresh
  check "UFW not installed: no ufw call, no warning, the run goes on" t_ufw_absent ufw_absent
  check "dry run with active UFW: nothing changed, says a real run would abort" t_dry_would_abort dry_ufw_active 'UFW|ufw'

  check "SSH: earlier drop-in 00-test.conf with PasswordAuthentication yes: drop-in reset, no reload, abort" \
    t_sshd_rollback_because ssh_early_pw 'passwordauthentication'
  check "SSH: earlier drop-in with KbdInteractiveAuthentication yes: drop-in reset, no reload, abort" \
    t_sshd_rollback_because ssh_early_kbd 'kbdinteractiveauthentication'
  check "SSH: earlier drop-in with PermitRootLogin prohibit-password: drop-in reset, no reload, abort" \
    t_sshd_rollback_because ssh_early_root 'permitrootlogin'
  check "SSH: Match User ubuntu with PasswordAuthentication yes (only sshd -T -C sees it): drop-in reset, no reload, abort" \
    t_sshd_rollback_because ssh_match_pw 'passwordauthentication'
  check "SSH: DenyUsers ub* in a later drop-in: drop-in reset, no reload, abort" \
    t_sshd_rollback_because ssh_denyusers_star 'DenyUsers'
  check "SSH: DenyUsers ?buntu: previous drop-in back (content, mode), no reload, abort" \
    t_sshd_rollback_because ssh_denyusers_qmark 'DenyUsers'
  check "SSH: AllowGroups sshlogin, ubuntu in no such group: drop-in reset, no reload, abort" \
    t_sshd_rollback_because ssh_allowgroups_none 'AllowGroups'
  check "SSH: DenyGroups sshdeny, ubuntu is a member: drop-in reset, no reload, abort" \
    t_sshd_rollback_because ssh_denygroups 'DenyGroups'
  check "SSH: AllowGroups with ubuntu's group, DenyGroups and DenyUsers ub? without ubuntu, earlier drop-in with PasswordAuthentication no: runs, reloads" \
    t_sshd_accepts ssh_groups_ok "allowgroups sshlogin" "denygroups sshdeny" "denyusers ub?" "denyusers root"

  check "/run/sshd missing: created in the checks (owner root, not group or world writable), the run goes through" \
    t_run_sshd_created run_sshd_missing
  check "/run/sshd missing, checks abort (UFW active): /run/sshd is the only change" \
    t_aborts_only_run_sshd run_sshd_abort 'UFW|ufw'
  check "/run/sshd missing and cannot be created: abort, nothing changed, no fallback to ~/.ssh/authorized_keys" \
    t_aborts_because run_sshd_ro '/run/sshd'
  check "/run/sshd missing, sshd -T fails afterwards (bad option): abort, only /run/sshd changed, no fallback to ~/.ssh/authorized_keys" \
    t_aborts_only_run_sshd run_sshd_broken 'sshd -T'
  check "dry run without /run/sshd: nothing changed, /run/sshd not created, shows that it would be" t_dry_run_sshd dry_run_sshd

  check "dry run shows: systemctl enable netfilter-persistent" t_dry_shows 'systemctl enable netfilter-persistent'
  check "packages: apt-get full-upgrade instead of upgrade (real and dry run)" t_full_upgrade

  check "fixture: docker.asc is Docker's key ($DOCKER_FPR)" t_fixture_docker_key
  check "Docker: installed keyring is exactly the checked key" t_docker_keyring_is_checked_key
  check "Docker: temporary files (key download) removed" t_tmp_cleaned fresh
  check "Docker: key with another fingerprint aborts, Docker not set up" t_docker_key_rejected key_wrong
  check "Docker: Docker's key plus another key in the file aborts, Docker not set up" t_docker_key_rejected key_two
  check "Docker: download that is no key aborts, Docker not set up" t_docker_key_rejected key_invalid
  check "Docker: temporary files removed after the abort" t_tmp_cleaned key_wrong

  check "sandbox: inner entry point without caller markers refuses, mounts nothing" t_guard_refuses guard_no_markers
  check "sandbox: inner entry point in its caller's namespaces refuses, mounts nothing" t_guard_refuses guard_caller_ns
  check "sandbox: inner entry point in the namespaces of PID 1 refuses, mounts nothing" t_guard_refuses guard_pid1

  check "host untouched after all scenarios" t_host_untouched

  echo
  echo "Result: $PASS passed, $FAILS failed"
  ((FAILS == 0))
}

if [[ ${1:-} == __inner ]]; then
  inner "${2:-}"
  exit
fi
main "$@"
