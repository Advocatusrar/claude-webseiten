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
#   tools (inside the sandbox), wrapped so that their calls are logged too; so are
#   ip(6)tables-save and ip(6)tables-restore, whose output and input are kept.
# - logrotate: the package state comes from the dpkg-query stub (SC_DPKG), the program
#   from the fixture (SC_LOGROTATE_BIN=1: a stub at /usr/sbin/logrotate inside the
#   sandbox; otherwise there is no logrotate in the PATH of the script).
# - The curl stub serves Docker's real public apt key (fixtures/docker.asc), or for
#   the negative tests a key generated for this run with another fingerprint.
# - A fresh server has no group docker; the apt-get stub creates it when docker-ce
#   is installed, like the real package. The host's group docker does not matter.
# - Every run of the script gets a defined audit login UID (/proc/self/loginuid, which
#   the script compares with ADMIN_USER): "not set" unless the scenario sets one. The
#   session the tests are started from does not matter; if the kernel does not allow
#   setting it, the tests do not run (exit code 2).
# - Profile hostinger (PROFIL=hostinger, scenarios h_*): hostinger_fixture and
#   hostinger_v4/v6 build a Hostinger VPS (Docker running, docker is a stub that never
#   talks to a daemon, dockerd only answers --help and --validate; INPUT open, Docker's
#   chains and a DNAT for 32768; root with password). ADMIN_PUBKEY gets throwaway keys made
#   with ssh-keygen for this run (prepare_ssh_keys).
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
# Audit login UID (/proc/self/loginuid) of the runs: "not set" unless a scenario sets
# SC_LOGINUID (see run_setup). LOGINUID_NOUSER is a UID without a user.
LOGINUID_UNSET=4294967295
LOGINUID_NOUSER=3999999999
# Profile hostinger (PROFIL=hostinger). H_ADMIN is the admin user the script creates;
# the fixtures create H_SYSUSER (system user), H_NOLOGIN (normal UID, shell nologin) and
# the group H_GROUP (no user of that name). None of them may exist on the host.
# H_CONSOLE is the address of Hostinger's web console; H_PUBLIC stands for any address
# on the internet in the sshd -T -C checks of the tests (TEST-NET-2, RFC 5737; on
# purpose not the address the script uses for its own checks).
H_ADMIN=hadmin
H_SYSUSER=hsys
H_NOLOGIN=hnolog
H_GROUP=hgrp
H_CONSOLE=169.254.0.1
H_PUBLIC=198.51.100.7
# The fail2ban addresses that are never banned in the profile hostinger, exactly these.
H_IGNOREIP='127.0.0.1/8 ::1 169.254.0.1'

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

# Like the Oracle rules, but INPUT ends with an unconditional DROP instead of REJECT. A
# conditional DROP at the top (a ban of one address, like fail2ban's) must not count as
# the rule that turns other traffic away.
drop_rule_v4() {
  cat <<'RULES'
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -s 192.0.2.99/32 -j DROP
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -j DROP
COMMIT
RULES
}

drop_rule_v6() {
  cat <<'RULES'
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -s 2001:db8::99/128 -j DROP
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p ipv6-icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -j DROP
COMMIT
RULES
}

# Policy ACCEPT and only conditional DROP rules: nothing turns other traffic away.
cond_drop_v4() {
  cat <<'RULES'
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -s 192.0.2.99/32 -j DROP
-A INPUT -p tcp -m tcp --dport 23 -j DROP
-A INPUT -i lo -j ACCEPT
COMMIT
RULES
}

# Hostinger VPS: INPUT open (policy ACCEPT, no rules), Docker's chains in the table
# filter and a published port 32768 of another app's container (DNAT in the table nat).
hostinger_v4() {
  cat <<'RULES'
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER - [0:0]
:DOCKER-ISOLATION-STAGE-1 - [0:0]
:DOCKER-ISOLATION-STAGE-2 - [0:0]
:DOCKER-USER - [0:0]
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER-ISOLATION-STAGE-1
-A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -o docker0 -j DOCKER
-A FORWARD -i docker0 ! -o docker0 -j ACCEPT
-A FORWARD -i docker0 -o docker0 -j ACCEPT
-A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 80 -j ACCEPT
-A DOCKER-ISOLATION-STAGE-1 -i docker0 ! -o docker0 -j DOCKER-ISOLATION-STAGE-2
-A DOCKER-ISOLATION-STAGE-1 -j RETURN
-A DOCKER-ISOLATION-STAGE-2 -o docker0 -j DROP
-A DOCKER-ISOLATION-STAGE-2 -j RETURN
-A DOCKER-USER -j RETURN
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:DOCKER - [0:0]
-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
-A OUTPUT ! -d 127.0.0.0/8 -m addrtype --dst-type LOCAL -j DOCKER
-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
-A POSTROUTING -s 172.17.0.2/32 -d 172.17.0.2/32 -p tcp -m tcp --dport 80 -j MASQUERADE
-A DOCKER -i docker0 -j RETURN
-A DOCKER ! -i docker0 -p tcp -m tcp --dport 32768 -j DNAT --to-destination 172.17.0.2:80
COMMIT
RULES
}

hostinger_v6() {
  cat <<'RULES'
*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:DOCKER - [0:0]
:DOCKER-USER - [0:0]
-A FORWARD -j DOCKER-USER
-A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -o docker0 -j DOCKER
-A FORWARD -i docker0 ! -o docker0 -j ACCEPT
-A DOCKER -d fd00:dead:beef::2/128 ! -i docker0 -o docker0 -p tcp -m tcp --dport 80 -j ACCEPT
-A DOCKER-USER -j RETURN
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
:DOCKER - [0:0]
-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER
-A POSTROUTING -s fd00:dead:beef::/64 ! -o docker0 -j MASQUERADE
-A DOCKER ! -i docker0 -p tcp -m tcp --dport 32768 -j DNAT --to-destination [fd00:dead:beef::2]:80
COMMIT
RULES
}

# hostinger_fixture ARTDIR: the rest of a Hostinger VPS (SC_HOSTINGER=1), see the
# scenarios of the profile hostinger in main.
# - sshd: root logs in with a password (PermitRootLogin yes in sshd_config and in
#   60-cloudimg-settings.conf, PasswordAuthentication yes there and in 50-cloud-init.conf);
#   root's authorized_keys is empty.
# - Docker is installed and runs (systemctl stub state), /usr/bin/docker is a stub that
#   never talks to a daemon: "docker info" reports live-restore as daemon.json has it
#   (as after "systemctl reload docker"). SC_DAEMON_JSON: content of daemon.json ("\n"
#   separates lines), else there is none; ARTDIR/daemon.json.orig keeps it.
# - A system user H_SYSUSER, a user H_NOLOGIN with shell nologin and a group H_GROUP.
# - SC_H_EXISTING=1: H_ADMIN exists already (bash, not in sudo), with ~/.ssh mode
#   SC_H_SSH_MODE (default 755) and authorized_keys (content SC_H_OLDKEYS, "\n" separates
#   lines; mode SC_H_KEYS_MODE, default 644); ARTDIR/h_keys0 keeps the file.
# - SC_SS=hostinger: ss lists sshd on 22, Hostinger's Traefik on 80 and 443 (host
#   network), docker-proxy on 32768, systemd-resolved on loopback and the DHCP client;
#   SC_SS=other: the same and a service on 0.0.0.0:8080.
hostinger_fixture() {
  local art=$1
  printf '%s\n' '# Hostinger image (test fixture)' 'PermitRootLogin yes' 'PasswordAuthentication yes' \
    >/etc/ssh/sshd_config.d/60-cloudimg-settings.conf
  chmod 644 /etc/ssh/sshd_config.d/50-cloud-init.conf /etc/ssh/sshd_config.d/60-cloudimg-settings.conf
  sed -i -E 's|^(Include /etc/ssh/sshd_config\.d/\*\.conf)$|\1\nPermitRootLogin yes|' /etc/ssh/sshd_config
  grep -qx 'PermitRootLogin yes' /etc/ssh/sshd_config || {
    echo "fixture: PermitRootLogin yes not in sshd_config" >&2
    return 1
  }
  install -d -m 700 /root/.ssh
  : >/root/.ssh/authorized_keys
  chmod 600 /root/.ssh/authorized_keys

  rm -f /usr/bin/docker
  cat >/usr/bin/docker <<'EOF'
#!/bin/bash
# docker (test stub): logs its calls, never talks to a daemon.
{ printf 'docker'; printf ' %s' "$@"; printf '\n'; } >>"${STUB_LOG:-/dev/null}"
case ${1:-} in
  --version) echo "Docker version 27.0.0-test, build test" ;;
  info)
    python3 -I -c 'import json
try:
    v = json.load(open("/etc/docker/daemon.json")).get("live-restore") is True
except (OSError, ValueError, AttributeError):
    v = False
print("true" if v else "false")'
    ;;
  *) echo "docker (test stub): unexpected call: $*" >&2; exit 99 ;;
esac
EOF
  chmod 755 /usr/bin/docker
  touch "$art/state/enabled.docker" "$art/state/active.docker"
  if [[ -n ${SC_DAEMON_JSON:-} ]]; then
    mkdir -p /etc/docker
    printf '%b\n' "$SC_DAEMON_JSON" >/etc/docker/daemon.json
    chmod 644 /etc/docker/daemon.json
    cp -p /etc/docker/daemon.json "$art/daemon.json.orig"
  else
    rm -f /etc/docker/daemon.json
  fi

  useradd --system --shell /usr/sbin/nologin "$H_SYSUSER"
  useradd --create-home --shell /usr/sbin/nologin "$H_NOLOGIN"
  groupadd "$H_GROUP"
  if [[ ${SC_H_EXISTING:-0} == 1 ]]; then
    useradd --create-home --shell /bin/bash "$H_ADMIN"
    install -d -o "$H_ADMIN" -g "$H_ADMIN" -m "${SC_H_SSH_MODE:-755}" "/home/$H_ADMIN/.ssh"
    printf '%b' "${SC_H_OLDKEYS:-}" >"/home/$H_ADMIN/.ssh/authorized_keys"
    chown "$H_ADMIN:$H_ADMIN" "/home/$H_ADMIN/.ssh/authorized_keys"
    chmod "${SC_H_KEYS_MODE:-644}" "/home/$H_ADMIN/.ssh/authorized_keys"
    cp -p "/home/$H_ADMIN/.ssh/authorized_keys" "$art/h_keys0"
  fi

  case ${SC_SS:-} in
    "") ;;
    hostinger | other)
      printf '%s\n' \
        'LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=801,fd=3))' \
        'LISTEN 0 4096 [::]:22 [::]:* users:(("sshd",pid=801,fd=4))' \
        'LISTEN 0 4096 0.0.0.0:80 0.0.0.0:* users:(("traefik",pid=1201,fd=7))' \
        'LISTEN 0 4096 [::]:80 [::]:* users:(("traefik",pid=1201,fd=8))' \
        'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("traefik",pid=1201,fd=9))' \
        'LISTEN 0 4096 [::]:443 [::]:* users:(("traefik",pid=1201,fd=10))' \
        'LISTEN 0 4096 0.0.0.0:32768 0.0.0.0:* users:(("docker-proxy",pid=1302,fd=4))' \
        'LISTEN 0 4096 [::]:32768 [::]:* users:(("docker-proxy",pid=1303,fd=4))' \
        'LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=501,fd=15))' \
        >"$art/state/ss_tcp"
      if [[ $SC_SS == other ]]; then
        echo 'LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("python3",pid=1500,fd=3))' >>"$art/state/ss_tcp"
      fi
      printf '%s\n' \
        'UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=501,fd=14))' \
        'UNCONN 0 0 203.0.113.20%eth0:68 0.0.0.0:* users:(("systemd-network",pid=480,fd=22))' \
        >"$art/state/ss_udp"
      chmod 644 "$art/state/ss_tcp" "$art/state/ss_udp"
      ;;
    *)
      echo "fixture: unknown SC_SS $SC_SS" >&2
      return 1
      ;;
  esac
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
  # The same for deploy (the CI) only.
  if [[ -n ${SC_SSHD_MATCH_DEPLOY:-} ]]; then
    printf '\n# test fixture\nMatch User deploy\n    %b\n' "$SC_SSHD_MATCH_DEPLOY" >>/etc/ssh/sshd_config
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
    drop_rule) drop_rule_v4 | iptables-restore ;;
    cond_drop) cond_drop_v4 | iptables-restore ;;
    # Policy ACCEPT, nothing that turns traffic away (one rule: dump_fw needs a line).
    open) printf '%s\n' '*filter' ':INPUT ACCEPT [0:0]' '-A INPUT -i lo -j ACCEPT' 'COMMIT' | iptables-restore ;;
    # The final REJECT of the Oracle rules with a comment in front of the target.
    oracle_comment) oracle_v4 | sed -E 's/^-A INPUT -j REJECT/-A INPUT -m comment --comment final-reject -j REJECT/' | iptables-restore ;;
    hostinger) hostinger_v4 | iptables-restore ;;
  esac
  case ${SC_V6:-reject} in
    reject) oracle_v6 | ip6tables-restore ;;
    drop_policy) drop_policy_v6 | ip6tables-restore ;;
    drop_rule) drop_rule_v6 | ip6tables-restore ;;
    open) printf '%s\n' '*filter' ':INPUT ACCEPT [0:0]' '-A INPUT -i lo -j ACCEPT' 'COMMIT' | ip6tables-restore ;;
    copies_after_reject)
      oracle_v6 | ip6tables-restore
      # Copies appended after the REJECT: 22 is open before it anyway, 443 is not.
      ip6tables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
      ip6tables -A INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT
      ;;
    hostinger) hostinger_v6 | ip6tables-restore ;;
  esac
  # NAT rules in both families (like Docker's masquerading): restoring the table filter
  # must leave them as they are. $art/nat_fixture records that they were set.
  if [[ ${SC_NAT:-0} == 1 ]]; then
    iptables -t nat -A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE
    ip6tables -t nat -A POSTROUTING -s 2001:db8:17::/64 ! -o docker0 -j MASQUERADE
    touch "$art/nat_fixture"
  fi
  # Rules saved earlier (netfilter-persistent), as on a server where they were saved
  # before: a run that aborts must leave these files as they are.
  if [[ ${SC_RULES_SAVED:-0} == 1 ]]; then
    mkdir -p /etc/iptables
    iptables-save >/etc/iptables/rules.v4
    ip6tables-save >/etc/iptables/rules.v6
    # Copies to compare with later (backups of the profile hostinger).
    cp -p /etc/iptables/rules.v4 "$art/rules.v4.orig"
    cp -p /etc/iptables/rules.v6 "$art/rules.v6.orig"
  fi
  # deploy exists already, with a home directory other than /home/deploy.
  if [[ -n ${SC_DEPLOY_HOME:-} ]]; then
    useradd --create-home --home-dir "$SC_DEPLOY_HOME" --shell /bin/bash deploy
  fi

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
  # The program logrotate, which the package installs as /usr/sbin/logrotate. The
  # script counts logrotate as there only if the package is installed (SC_DPKG) and the
  # program is in its PATH. SC_LOGROTATE_BIN=1: a stub at /usr/sbin/logrotate that only
  # logs its calls; otherwise no logrotate in the PATH of the script, even if the host
  # has one. $art/lr_bin: what "command -v logrotate" finds there ("none": nothing).
  for d in ${SANDBOX_PATH_TAIL//:/ }; do
    if [[ -e $d/logrotate || -L $d/logrotate ]]; then rm -f "$d/logrotate"; fi
  done
  if [[ ${SC_LOGROTATE_BIN:-0} == 1 ]]; then
    cat >/usr/sbin/logrotate <<'EOF'
#!/bin/sh
# logrotate (test stub): only logs its calls.
{ printf 'logrotate'; printf ' %s' "$@"; printf '\n'; } >>"${STUB_LOG:-/dev/null}"
EOF
    chmod 755 /usr/sbin/logrotate
  fi
  PATH="$STUBS:$SANDBOX_PATH_TAIL" bash -c 'command -v logrotate || echo none' >"$art/lr_bin"
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
  # Foreign files in jail.d/ and fail2ban.d/ (see f2b_foreign), unless they come only
  # between run 1 and run 2.
  if [[ ${SC_F2B_FOREIGN_AT:-fixture} != between ]]; then f2b_foreign; fi
  # A journald drop-in from an earlier version, with other content and mode.
  if [[ ${SC_JOURNALD_OLD:-0} == 1 ]]; then
    mkdir -p /etc/systemd/journald.conf.d
    printf '# Older version (test fixture)\n[Journal]\nMaxRetentionSec=1month\n' \
      >/etc/systemd/journald.conf.d/10-aufbewahrung.conf
    chmod 600 /etc/systemd/journald.conf.d/10-aufbewahrung.conf
  fi

  # The rest of a Hostinger VPS (profile hostinger).
  if [[ ${SC_HOSTINGER:-0} == 1 ]]; then hostinger_fixture "$art"; fi

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

# save_family TOOL: all tables of one family (TOOL-save), without comments and counters.
# Empty if the family has no table (grep finds nothing then, which is no error here).
save_family() {
  "$1-save" | { grep -v '^#' || true; } | sed -E 's/\[[0-9]+:[0-9]+\]/[0:0]/g'
}

# set_loginuid UID: give the calling process the audit login UID UID (inherited by
# everything it starts). Only writes if it differs: the kernel can refuse any change of
# a login UID that is set (loginuid immutable, no CAP_AUDIT_CONTROL), even to the same
# value. Call it in a subshell; /proc/self is that process then.
set_loginuid() {
  local cur
  cur=$(loginuid_now) || return 1
  [[ $cur == "$1" ]] && return 0
  printf '%s' "$1" >/proc/self/loginuid || return 1
  [[ $(loginuid_now) == "$1" ]]
}

# loginuid_now: the audit login UID of this process (the file ends without a newline).
loginuid_now() {
  local v=""
  read -r v </proc/self/loginuid 2>/dev/null || true
  [[ -n $v ]] && printf '%s\n' "$v"
}

# loginuid_of VALUE: VALUE as a UID: a number as it is, else the UID of the user VALUE.
loginuid_of() {
  if [[ $1 =~ ^[0-9]+$ ]]; then echo "$1"; else id -u -- "$1"; fi
}

run_setup() {
  local art=$1 n=$2 rc=0 stubs=$STUBS lu
  local -a envs pre=()
  : >"$art/log$n"
  chmod 666 "$art/log$n"
  # Own TMPDIR per scenario: the script's temporary files stay out of the host's /tmp
  # and the tests can see whether they are removed.
  install -d -m 1777 "$art/tmp"
  # SC_UFW=absent: no ufw command at all (stubs without ufw).
  if [[ ${SC_UFW:-} == absent ]]; then stubs="$STUBS-noufw"; fi
  # Only in run N: SC_SSHD_T_FAIL_RUN=N makes sshd -t fail, SC_APT_RUNDIR_RUN=N lets the
  # apt-get stub replace /run/sshd by a file (STUB_APT_RUNDIR).
  local t_fail=${SC_SSHD_T_FAIL:-0} rundir=""
  if [[ ${SC_SSHD_T_FAIL_RUN:-} == "$n" ]]; then t_fail=1; fi
  if [[ ${SC_APT_RUNDIR_RUN:-} == "$n" ]]; then rundir="file"; fi
  envs=(
    PATH="$stubs:$SANDBOX_PATH_TAIL" HOME=/root LANG=C.UTF-8 TMPDIR="$art/tmp"
    STUB_LOG="$art/log$n" STUB_STATE="$art/state" STUB_RUN="$n"
    SSHD_T_FAIL="$t_fail"
    STUB_IPT_SAVE="${SC_IPT_SAVE:-}"
    STUB_RESTORE="${SC_RESTORE:-}"
    STUB_APT_RUNDIR="$rundir"
    STUB_DOCKER_KEY="$KEYS/${SC_DOCKER_KEY:-docker}.asc"
    STUB_IPT_RACE="${SC_IPT_RACE:-}"
    STUB_DPKG="${SC_DPKG:-}"
    STUB_UFW="${SC_UFW:-inactive}"
    STUB_APT_FW="${SC_APT_FW:-}"
    STUB_APT_SSHD_MATCH="${SC_APT_SSHD_MATCH:-}"
  )
  if [[ -n ${SC_DRY_RUN+x} ]]; then envs+=(DRY_RUN="$SC_DRY_RUN"); fi
  if [[ -n ${SC_ADMIN_USER+x} ]]; then envs+=(ADMIN_USER="$SC_ADMIN_USER"); fi
  if [[ -n ${SC_SUDO_USER+x} ]]; then envs+=(SUDO_USER="$SC_SUDO_USER"); fi
  if [[ -n ${SC_PROFIL+x} ]]; then envs+=(PROFIL="$SC_PROFIL"); fi
  if [[ -n ${SC_ADMIN_PUBKEY+x} ]]; then envs+=(ADMIN_PUBKEY="$SC_ADMIN_PUBKEY"); fi
  if [[ ${SC_AS:-root} == nobody ]]; then
    pre=(setpriv --reuid=nobody --regid=nogroup --clear-groups --)
  fi
  # The script compares the audit login UID (/proc/self/loginuid) with ADMIN_USER. Every
  # process inherits it from the login session the tests were started in, so without
  # this the result would depend on that session (e.g. "sudo su -" as claude). Each run
  # gets a defined value instead: SC_LOGINUID (number or user name inside the sandbox),
  # default "not set". loginuidN is what the run really had; without it (value could not
  # be set) the script is not started and rcN is not written, so have_run fails.
  lu=$(loginuid_of "${SC_LOGINUID:-$LOGINUID_UNSET}") || lu=""
  echo "$lu" >"$art/loginuid_want$n"
  getent passwd "$lu" | cut -d: -f1 >"$art/loginuid_user$n" || true
  rm -f "$art/loginuid$n"
  (
    if [[ -z $lu ]] || ! set_loginuid "$lu" || ! got=$(loginuid_now); then
      echo "test fixture: audit login UID '$lu' could not be set" >&2
      exit 99
    fi
    echo "$got" >"$art/loginuid$n"
    exec "${pre[@]}" env -i "${envs[@]}" bash "$art/setup-server.sh"
  ) >"$art/out$n" 2>"$art/err$n" || rc=$?
  if [[ -f $art/loginuid$n ]]; then echo "$rc" >"$art/rc$n"; fi
}

post_checks() {
  local art=$1 dh rc
  /usr/sbin/sshd -T >"$art/sshd_T" 2>&1 || true
  /usr/sbin/sshd -T -C user=ubuntu,host=localhost,addr=127.0.0.1 >"$art/sshd_T_admin" 2>&1 || true
  /usr/sbin/sshd -T -C user=deploy,host=localhost,addr=127.0.0.1 >"$art/sshd_T_deploy" 2>&1 || true
  apt-config dump >"$art/aptconf" 2>&1 || true
  fail2ban-client -d >"$art/f2b_dump" 2>/dev/null || true
  getent passwd deploy >"$art/deploy_passwd" || true
  id -nG deploy >"$art/deploy_groups" 2>/dev/null || true
  stat -c '%n %U %G %a %s' /home/deploy/.ssh /home/deploy/.ssh/authorized_keys >"$art/deploy_stat" 2>&1 || true
  # The same in deploy's home directory from getent passwd (SC_DEPLOY_HOME).
  dh=$(getent passwd deploy | cut -d: -f6) || dh=""
  if [[ -n $dh ]]; then
    stat -c '%n %U %G %a %s' "$dh/.ssh" "$dh/.ssh/authorized_keys" >"$art/deploy_home_stat" 2>&1 || true
  fi
  ls -1 /etc/ssh/sshd_config.d >"$art/sshd_dir" 2>&1 || true
  sshd_state >"$art/sshd_state_end"
  if command -v dockerd >/dev/null 2>&1 && [[ -f /etc/docker/daemon.json ]]; then
    # set -e: a rejected file (fixtures of the profile hostinger) must not end inner here.
    rc=0
    dockerd --validate --config-file=/etc/docker/daemon.json >"$art/dockerd_validate" 2>&1 || rc=$?
    echo "rc=$rc" >>"$art/dockerd_validate"
  fi
  if [[ ${SC_HOSTINGER:-0} == 1 ]]; then h_post_checks "$art"; fi
}

# h_post_checks ARTDIR (profile hostinger): sshd -T -C for the admin user (SC_ADMIN_USER,
# default H_ADMIN), root and deploy, each from the internet (sshdT_WHO_pub) and from the
# web console (sshdT_WHO_con); sshd -t; account, groups, ~/.ssh and authorized_keys of the
# admin user; sudo -l for it; iptables-restore --test of the saved rules files.
h_post_checks() {
  local art=$1 who u rc h f
  for who in admin root deploy; do
    if [[ $who == admin ]]; then u=${SC_ADMIN_USER:-$H_ADMIN}; else u=$who; fi
    /usr/sbin/sshd -T -C "user=$u,host=public.invalid,addr=$H_PUBLIC" >"$art/sshdT_${who}_pub" 2>&1 || true
    /usr/sbin/sshd -T -C "user=$u,host=console.invalid,addr=$H_CONSOLE" >"$art/sshdT_${who}_con" 2>&1 || true
  done
  rc=0
  /usr/sbin/sshd -t >"$art/sshd_t" 2>&1 || rc=$?
  echo "rc=$rc" >>"$art/sshd_t"
  u=${SC_ADMIN_USER:-$H_ADMIN}
  getent passwd "$u" >"$art/h_passwd" || true
  id -nG "$u" >"$art/h_groups" 2>/dev/null || true
  h=$(getent passwd "$u" | cut -d: -f6) || h=""
  if [[ -n $h ]]; then
    stat -c '%n %U %G %a' "$h/.ssh" "$h/.ssh/authorized_keys" >"$art/h_stat" 2>&1 || true
    cp "$h/.ssh/authorized_keys" "$art/h_keys" 2>/dev/null || true
  fi
  # shellcheck disable=SC2024 # runs as root already; sudo only lists the rights of $u
  sudo -n -l -U "$u" >"$art/h_sudo" 2>&1 || true
  for f in v4 v6; do
    if [[ -f /etc/iptables/rules.$f ]]; then
      rc=0
      if [[ $f == v4 ]]; then
        iptables-restore --test </etc/iptables/rules.$f >"$art/rules_test_$f" 2>&1 || rc=$?
      else
        ip6tables-restore --test </etc/iptables/rules.$f >"$art/rules_test_$f" 2>&1 || rc=$?
      fi
      echo "rc=$rc" >>"$art/rules_test_$f"
    fi
  done
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

# Profile hostinger, between the first and a later run on a real server: the CI key is
# added for deploy, fail2ban (started by run 1) puts its chain and a jump to it at the
# top of INPUT, in both families.
h_between_runs() {
  local dh tool
  dh=$(getent passwd deploy | cut -d: -f6)
  printf 'command="/bin/true",restrict %s\n' "$TEST_KEY" >>"$dh/.ssh/authorized_keys"
  for tool in iptables ip6tables; do
    "$tool" -N f2b-sshd
    "$tool" -A f2b-sshd -j RETURN
    "$tool" -I INPUT 1 -p tcp -m multiport --dports 22 -j f2b-sshd
  done
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

# f2b_foreign: files of someone else that fail2ban reads after jail.local and
# fail2ban.local (the last value wins). SC_F2B_JAIL_D is the content of
# /etc/fail2ban/jail.d/zz.local, SC_F2B_MAIN_D that of /etc/fail2ban/fail2ban.d/zz.local
# ("\n" separates lines), each 644 root:root. Put in place by the fixture, or with
# SC_F2B_FOREIGN_AT=between only between run 1 and run 2 (snap1_pre keeps the state
# right after run 1).
f2b_foreign() {
  if [[ -n ${SC_F2B_JAIL_D:-} ]]; then
    mkdir -p /etc/fail2ban/jail.d
    printf '%b\n' "# Foreign file (test fixture)" "$SC_F2B_JAIL_D" >/etc/fail2ban/jail.d/zz.local
    chmod 644 /etc/fail2ban/jail.d/zz.local
  fi
  if [[ -n ${SC_F2B_MAIN_D:-} ]]; then
    mkdir -p /etc/fail2ban/fail2ban.d
    printf '%b\n' "# Foreign file (test fixture)" "$SC_F2B_MAIN_D" >/etc/fail2ban/fail2ban.d/zz.local
    chmod 644 /etc/fail2ban/fail2ban.d/zz.local
  fi
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
  save_family iptables >"$art/save4_0"
  save_family ip6tables >"$art/save6_0"
  iptables -S INPUT >"$art/v4_0"
  ip6tables -S INPUT >"$art/v6_0"
  sshd_state >"$art/sshd_state0"
  # Profile hostinger: root from the internet before the run (fixture in effect).
  if [[ ${SC_HOSTINGER:-0} == 1 ]]; then
    /usr/sbin/sshd -T -C "user=root,host=public.invalid,addr=$H_PUBLIC" >"$art/sshdT0_root_pub" 2>&1 || true
  fi
  for ((i = 1; i <= ${SC_RUNS:-1}; i++)); do
    run_setup "$art" "$i"
    snapshot "$art" >"$art/snap$i"
    dump_fw >"$art/fw$i"
    save_family iptables >"$art/save4_$i"
    save_family ip6tables >"$art/save6_$i"
    iptables -S INPUT >"$art/v4_$i"
    ip6tables -S INPUT >"$art/v6_$i"
    if ((i == 1)) && [[ ${SC_BETWEEN:-0} == 1 ]]; then
      between_runs
      # State before the second run, including these changes.
      snapshot "$art" >"$art/snap$i"
      dump_fw >"$art/fw$i"
    fi
    if ((i == 1)) && [[ ${SC_H_BETWEEN:-0} == 1 ]]; then
      h_between_runs
      snapshot "$art" >"$art/snap$i"
      dump_fw >"$art/fw$i"
    fi
    if ((i == 1)) && [[ -n ${SC_F2B_EDIT:-} ]]; then
      cp "$art/snap1" "$art/snap1_pre"
      f2b_edit "$SC_F2B_EDIT"
      snapshot "$art" >"$art/snap1"
    fi
    if ((i == 1)) && [[ ${SC_F2B_FOREIGN_AT:-} == between ]]; then
      cp "$art/snap1" "$art/snap1_pre"
      f2b_foreign
      snapshot "$art" >"$art/snap1"
    fi
    # Someone changes the sshd configuration elsewhere between run 1 and run 2: a later
    # drop-in (60-test.conf) or a Match block for ubuntu at the end of sshd_config. "\n"
    # separates lines. snap1_pre keeps the state right after run 1.
    if ((i == 1)) && [[ -n ${SC_BETWEEN_SSHD_LATE:-}${SC_BETWEEN_SSHD_MATCH:-} ]]; then
      cp "$art/snap1" "$art/snap1_pre"
      if [[ -n ${SC_BETWEEN_SSHD_LATE:-} ]]; then
        printf '%b\n' "# test fixture (between runs)" "$SC_BETWEEN_SSHD_LATE" >/etc/ssh/sshd_config.d/60-test.conf
        chmod 644 /etc/ssh/sshd_config.d/60-test.conf
      fi
      if [[ -n ${SC_BETWEEN_SSHD_MATCH:-} ]]; then
        printf '\n# test fixture (between runs)\nMatch User ubuntu\n    %b\n' "$SC_BETWEEN_SSHD_MATCH" >>/etc/ssh/sshd_config
      fi
      snapshot "$art" >"$art/snap1"
      sshd_state >"$art/sshd_state1"
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
# The installation of iptables-persistent (step 1) removes ufw, whose prerm runs
# "ufw-init stop". STUB_APT_FW simulates what that can do to INPUT, with the real
# tools (not the logged wrappers: these are not calls of the script):
#   flush_v4, flush_v6    all rules gone, policy ACCEPT
#   policy_v4, policy_v6  only the policy set to ACCEPT
#   del_final_v4          the final "-A INPUT -j DROP" deleted
#   flush_v4_nat          as flush_v4, and a new nat chain DOCKER with a MASQUERADE rule
#                         for 172.18.0.0/16 in POSTROUTING (as if Docker set it up
#                         meanwhile)
#   unreadable_v4         from now on the iptables stub fails to read rules (-S, -L,
#                         -C), as if iptables were broken after the package update
# STUB_STATE/after_apt.v4 and .v6 then hold all tables of each family as they are right
# after this change (without comments and counters).
# STUB_APT_SSHD_MATCH: the same apt run (a package update) adds a Match block for ubuntu
# to sshd_config. STUB_APT_RUNDIR=file: it replaces /run/sshd by an empty file, so that
# the directory cannot be created again (as if a package update stopped ssh and /run
# could not be written). STUB_STATE/apt_hooks records what was done.
case " \$* " in
  *" install "*" iptables-persistent "*)
    case \${STUB_APT_FW:-} in
      "") ;;
      flush_v4) /usr/sbin/iptables -F INPUT && /usr/sbin/iptables -P INPUT ACCEPT ;;
      flush_v6) /usr/sbin/ip6tables -F INPUT && /usr/sbin/ip6tables -P INPUT ACCEPT ;;
      policy_v4) /usr/sbin/iptables -P INPUT ACCEPT ;;
      policy_v6) /usr/sbin/ip6tables -P INPUT ACCEPT ;;
      del_final_v4) /usr/sbin/iptables -D INPUT -j DROP ;;
      flush_v4_nat)
        /usr/sbin/iptables -F INPUT && /usr/sbin/iptables -P INPUT ACCEPT &&
          /usr/sbin/iptables -t nat -N DOCKER &&
          /usr/sbin/iptables -t nat -A POSTROUTING -s 172.18.0.0/16 ! -o br-test -j MASQUERADE
        ;;
      unreadable_v4) : >"\$STUB_STATE/ipt_unreadable" ;;
      *) echo "apt-get (test stub): unknown STUB_APT_FW '\$STUB_APT_FW'" >&2; exit 99 ;;
    esac
    if [[ \${STUB_APT_RUNDIR:-} == file ]]; then
      rm -rf /run/sshd && : >/run/sshd && echo "rundir file" >>"\$STUB_STATE/apt_hooks"
    fi
    if [[ -n \${STUB_APT_FW:-} ]]; then
      echo "fw \$STUB_APT_FW" >>"\$STUB_STATE/apt_hooks"
      /usr/sbin/iptables-save | grep -v '^#' | sed -E 's/\[[0-9]+:[0-9]+\]/[0:0]/g' >"\$STUB_STATE/after_apt.v4"
      /usr/sbin/ip6tables-save | grep -v '^#' | sed -E 's/\[[0-9]+:[0-9]+\]/[0:0]/g' >"\$STUB_STATE/after_apt.v6"
    fi
    if [[ -n \${STUB_APT_SSHD_MATCH:-} ]]; then
      printf '\n# test fixture (package update)\nMatch User ubuntu\n    %s\n' "\$STUB_APT_SSHD_MATCH" >>/etc/ssh/sshd_config
      echo "sshd \$STUB_APT_SSHD_MATCH" >>"\$STUB_STATE/apt_hooks"
    fi
    ;;
esac
exit 0
EOF
  # Records the answers (stdin) in STUB_STATE/debconf.
  cat >"$dir/debconf-set-selections" <<EOF
#!/bin/bash
$log
cat >>"\${STUB_STATE:-/dev/null}/debconf"
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
  # STUB_STATE/ss_tcp and ss_udp (fixture SC_SS, profile hostinger): what "ss -H...t..."
  # and "ss -H...u..." print (listening sockets); without them nothing.
  cat >"$dir/ss" <<EOF
#!/bin/bash
$log
case \${1:-} in
  -*u*) f=ss_udp ;;
  *) f=ss_tcp ;;
esac
if [[ -f \${STUB_STATE:-/nonexistent}/\$f ]]; then cat "\$STUB_STATE/\$f"; fi
exit 0
EOF
  # Only the read-only calls (--help, --validate) reach the real dockerd; anything else,
  # such as starting the daemon, fails.
  cat >"$dir/dockerd" <<EOF
#!/bin/bash
$log
case \${1:-} in
  --help | --validate)
    [[ -x /usr/bin/dockerd ]] || exit 127
    exec /usr/bin/dockerd "\$@"
    ;;
  *) echo "dockerd (test stub): refused: \$*" >&2; exit 99 ;;
esac
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
  # Logged so that the tests see a restored (replaced) rule set. The input is appended to
  # STUB_STATE/NAME.in.RUN (RUN: number of the run), so that the tests can compare it
  # with what the script saved before. STUB_RESTORE (both families):
  #   fail  the restore fails (exit 1) and changes nothing
  #   noop  it reports success (exit 0) but changes nothing, so INPUT stays as it is
  for name in iptables-restore ip6tables-restore; do
    cat >"$dir/$name" <<EOF
#!/bin/bash
$log
keep=/dev/null
if [[ -n \${STUB_STATE:-} ]]; then keep="\$STUB_STATE/$name.in.\${STUB_RUN:-0}"; fi
input=\$(cat; echo .)
input=\${input%.}
printf '%s' "\$input" >>"\$keep"
case \${STUB_RESTORE:-} in
  "") ;;
  fail) echo "$name (test stub): forced failure, nothing restored" >&2; exit 1 ;;
  noop) exit 0 ;;
  *) echo "$name (test stub): unknown STUB_RESTORE '\$STUB_RESTORE'" >&2; exit 99 ;;
esac
printf '%s' "\$input" | /usr/sbin/$name "\$@"
EOF
  done
  # Logged as well; the output is appended to STUB_STATE/NAME.out.RUN. STUB_IPT_SAVE
  # (both families): "fail" fails (exit 1, no output), "empty" prints nothing (exit 0).
  for name in iptables-save ip6tables-save; do
    cat >"$dir/$name" <<EOF
#!/bin/bash
$log
case \${STUB_IPT_SAVE:-} in
  "") ;;
  fail) echo "$name (test stub): forced failure" >&2; exit 1 ;;
  empty) exit 0 ;;
  *) echo "$name (test stub): unknown STUB_IPT_SAVE '\$STUB_IPT_SAVE'" >&2; exit 99 ;;
esac
set -o pipefail
keep=/dev/null
if [[ -n \${STUB_STATE:-} ]]; then keep="\$STUB_STATE/$name.out.\${STUB_RUN:-0}"; fi
/usr/sbin/$name "\$@" | tee -a "\$keep"
EOF
  done
  # iptables, optionally with a simulated concurrent writer (like fail2ban's
  # "iptables -I INPUT 1 ..."), which inserts a foreign rule at the top of INPUT:
  #   STUB_IPT_RACE=insert  right before "iptables -I INPUT <n> ..." is carried out
  #                         (the script read the REJECT position before).
  # Once per run. STUB_STATE/race_count counts the inserted rules.
  # STUB_STATE/ipt_unreadable (set by the apt-get stub, unreadable_v4): reading rules
  # (-S, -L, -C) fails.
  {
    printf '#!/bin/bash\n%s\n' "$log"
    cat <<'EOF'
real=/usr/sbin/iptables
if [[ -f ${STUB_STATE:-/nonexistent}/ipt_unreadable && ${1:-} =~ ^-(S|L|C)$ ]]; then
  echo "iptables (test stub): forced read error" >&2
  exit 4
fi
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
# Run N must also have had the audit login UID the scenario defines (run_setup), so that
# the result does not depend on the session the tests were started from.
have_run() { # SCENARIO N
  local a f
  a=$(art "$1")
  for f in inner_ok "rc$2" snap0 "snap$2" fw0 "fw$2" "log$2" "out$2" "err$2" "loginuid$2" "loginuid_want$2"; do
    [[ -f $a/$f ]] || {
      no "artifact $f of scenario $1 is missing (sandbox failed)"
      return 1
    }
  done
  [[ -s $a/snap0 ]] || {
    no "snapshot before the run is empty (fixture missing)"
    return 1
  }
  [[ -s $a/loginuid$2 && $(cat "$a/loginuid$2") == "$(cat "$a/loginuid_want$2")" ]] || {
    no "run $2 of scenario $1 had the audit login UID '$(cat "$a/loginuid$2")', expected '$(cat "$a/loginuid_want$2")'"
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
      else if (c == "iptables-save" || c == "ip6tables-save") ro = 1
      else if (c == "dpkg" && $2 == "--print-architecture") ro = 1
      else if (c == "dpkg-query" || c == "uname" || c == "ss") ro = 1
      else if (c == "ufw" && $2 == "status" && NF == 2) ro = 1
      else if (c == "sshd" && ($2 == "-t" || $2 == "-T")) ro = 1
      else if (c == "fail2ban-client" && ($2 == "-t" || $2 == "-d")) ro = 1
      else if (c == "docker" && ($2 == "--version" || $2 == "info")) ro = 1
      else if (c == "dockerd" && ($2 == "--help" || $2 == "--validate")) ro = 1
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

# Family of the INPUT a hook of the apt-get stub changes (STUB_APT_FW, e.g. flush_v4):
# the tool whose rules it changed, empty if none.
hook_tool() { # HOOK
  case $1 in
    *_v4*) echo iptables ;;
    *_v6*) echo ip6tables ;;
  esac
}

# No scenario, real or dry run, deletes, replaces or flushes firewall rules or chains:
# no "ip(6)tables -D/-R/-F/-X" (short or long option) and no netfilter-persistent other
# than "save" in the call logs, none of them in the dry-run output either. A whole rule
# set is restored (TOOL-restore) only in runs in which the package installation changed
# INPUT of TOOL (apt-get stub: "fw HOOK" in STUB_STATE/apt_hooks, HOOK names the family),
# never in any other scenario or run and never in a dry run; then at most once per run,
# after "apt-get ... install ... iptables-persistent", not with --noflush, and only from
# the copy of the table filter taken in the same run before that apt-get
# ("TOOL-save -t filter"): the input of the restore is exactly what that save printed,
# and it holds only the table filter. A restore with --test loads nothing and does not
# count here.
t_fw_never_deletes() {
  local ok=1 f a n logs=0 v4=0 v6=0 dry=0 restored=0 hits tool hook dev cnt inst rl sl input saved
  for f in "$WORK"/*/log[0-9]*; do
    [[ -f $f ]] || continue
    logs=$((logs + 1))
    a=${f%/*}
    n=${f##*/log}
    if grep -qE '^iptables -I INPUT [0-9]+ ' "$f"; then v4=$((v4 + 1)); fi
    if grep -qE '^ip6tables -I INPUT [0-9]+ ' "$f"; then v6=$((v6 + 1)); fi
    hits=$(grep -E "^($FW_DELETE_RE|netfilter-persistent( |\$))" "$f" | grep -vx 'netfilter-persistent save')
    [[ -z $hits ]] || no "${f#"$WORK"/}:" "$hits"
    for tool in iptables ip6tables; do
      # A restore with --test (-t) only checks its input and loads nothing (profile
      # hostinger, before writing /etc/iptables/rules.v*); t_h_rules_files checks those.
      cnt=$(grep -E "^${tool}-restore( |\$)" "$f" | grep -cvE "^${tool}-restore( [^ ]+)* (--test|-t)( |\$)")
      ((cnt > 0)) || continue
      restored=$((restored + cnt))
      dev=0
      while read -r _ hook; do
        [[ $(hook_tool "$hook") == "$tool" ]] && dev=1
      done < <(grep -E '^fw ' "$a/state/apt_hooks" 2>/dev/null)
      if ((dev == 0)); then
        no "${f#"$WORK"/}: $tool-restore although the package installation did not change INPUT of $tool:" "$(grep -E "^${tool}-restore" "$f")"
        continue
      fi
      ((cnt == 1)) || no "${f#"$WORK"/}: $cnt calls of $tool-restore in one run (expected at most 1)"
      ! grep -qE "^${tool}-restore( .*)? (-n|--noflush)( |\$)" "$f" ||
        no "${f#"$WORK"/}: $tool-restore with --noflush (adds to the table instead of putting back the copy)"
      inst=$(grep -nE '^apt-get .* install .*iptables-persistent' "$f" | head -1 | cut -d: -f1)
      rl=$(grep -nE "^${tool}-restore( |\$)" "$f" | head -1 | cut -d: -f1)
      sl=$(grep -nE "^${tool}-save -t filter\$" "$f" | head -1 | cut -d: -f1)
      if [[ -z $inst ]] || ((rl < inst)); then no "${f#"$WORK"/}: $tool-restore (log line $rl) not after installing iptables-persistent (line ${inst:-none})"; fi
      if [[ -z $sl || -z $inst ]] || ((sl > inst)); then
        no "${f#"$WORK"/}: no '$tool-save -t filter' before installing iptables-persistent (save in line ${sl:-none}, install in line ${inst:-none})"
      fi
      input=$(cat "$a/state/$tool-restore.in.$n" 2>/dev/null)
      saved=$(cat "$a/state/$tool-save.out.$n" 2>/dev/null)
      if [[ -z $input ]]; then
        no "${f#"$WORK"/}: input of $tool-restore not recorded or empty"
      elif [[ $input != "$saved" ]]; then
        no "${f#"$WORK"/}: input of $tool-restore is not what '$tool-save -t filter' printed in this run (< saved, > restored):" \
          "$(diff <(printf '%s\n' "$saved") <(printf '%s\n' "$input"))"
      fi
      [[ $(grep -E '^\*' <<<"$input" | tr '\n' ' ') == '*filter ' ]] ||
        no "${f#"$WORK"/}: input of $tool-restore holds the tables '$(grep -E '^\*' <<<"$input" | tr '\n' ' ')', expected only *filter"
    done
  done
  for f in "$WORK"/*/out[0-9]* "$WORK"/*/err[0-9]*; do
    [[ -f $f ]] || continue
    if grep -qE '\[Testlauf\] iptables -I INPUT [0-9]+ ' "$f"; then dry=$((dry + 1)); fi
    hits=$(grep -E "\[Testlauf\] ($FW_DELETE_RE|ip6?tables-restore( |\$)|netfilter-persistent( |\$))" "$f" |
      grep -vE '\[Testlauf\] netfilter-persistent save$')
    [[ -z $hits ]] || no "${f#"$WORK"/}:" "$hits"
  done
  # Otherwise this test would look at nothing (the restore part: one restore in each of
  # the six fw_apt_* scenarios at least).
  ((logs >= 20 && v4 >= 3 && v6 >= 3 && dry >= 1 && restored >= 6)) ||
    no "too little to check: $logs call logs, $v4 with iptables -I, $v6 with ip6tables -I, $dry dry runs with iptables -I, $restored calls of ip(6)tables-restore"
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
# no 00-auth-log and no other new file in /etc/logrotate.d apart from 00-login-logs and
# 00-fail2ban-log (written when logrotate is there; t_lr_file and t_no_lr check them);
# a leftover /etc/logrotate.d/rsyslog stays as it is. The run reached the log retention
# step and asked dpkg-query about rsyslog.
t_no_auth_logrotate() { # SCENARIO
  local ok=1 a dir new f s0 d
  have_run "$1" 1 || return 1
  a=$(art "$1")
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)"
  [[ -f "$(upper "$1" etc)${JOURNALD_DROPIN#/etc}" ]] || no "the run did not reach the log retention step (no $JOURNALD_DROPIN)"
  grep -qE '^dpkg-query( .*)? rsyslog$' "$a/log1" || no "the script did not ask dpkg-query whether rsyslog is installed"
  dir="$(upper "$1" etc)/logrotate.d"
  [[ ! -f $dir/00-auth-log ]] || no "$AUTH_LOGROTATE written although rsyslog is not installed:" "$(cat "$dir/00-auth-log")"
  new=""
  for f in "$dir"/*; do
    [[ -f $f ]] || continue
    case ${f##*/} in 00-login-logs | 00-fail2ban-log) continue ;; esac
    [[ -n $(snap_of "$1" 0 "/etc/logrotate.d/${f##*/}") ]] || new+="$f"$'\n'
  done
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

# Lines of snapshot N of SCENARIO for /etc/fail2ban/jail.d, /etc/fail2ban/fail2ban.d
# and everything in them (stat and sha256 lines).
f2b_d_lines() { # SCENARIO N
  grep -E '(^|  )\./etc/u/fail2ban/(jail|fail2ban)\.d(/|\||$)' "$(art "$1")/snap$2"
}

# Lines of a call log that start or enable fail2ban.
F2B_START_RE='^systemctl (start|enable|reenable)( .*)? fail2ban(\.service)?( |$)'

# A foreign FILE (/etc/fail2ban/jail.d/zz.local or fail2ban.d/zz.local) that overrides a
# value of the privacy policy is there before run RUN. Run RUN asks fail2ban-client -d,
# aborts (exit != 0, "Abbruch") and names FILE on stderr; it neither restarts nor
# starts fail2ban (after run 1 fail2ban is not active); FILE and everything else in
# jail.d and fail2ban.d stay as they were (inode, mode, times, content); the run stops
# there (no summary). Earlier runs exit 0. fail2ban-client -d after the run contains
# DUMP_LINE: the foreign value is the one in effect.
t_f2b_foreign_abort() { # SCENARIO RUN FILE DUMP_LINE
  local ok=1 s=$1 n=$2 file=$3 a r rc calls d
  have_run "$s" "$n" || return 1
  a=$(art "$s")
  for ((r = 1; r < n; r++)); do
    [[ $(rc_of "$s" "$r") == 0 ]] || no "run $r: expected exit code 0, got: $(rc_of "$s" "$r")" "$(tail -3 "$a/err$r")"
  done
  rc=$(rc_of "$s" "$n")
  [[ $rc =~ ^[0-9]+$ && $rc -ne 0 ]] || no "run $n: expected exit code != 0, got: $rc"
  grep -q '^Abbruch' "$a/err$n" || no "run $n: no abort message on stderr:" "$(cat "$a/err$n")"
  grep -qF -- "$file" "$a/err$n" || no "run $n: stderr does not name $file:" "$(cat "$a/err$n")"
  grep -qE '^fail2ban-client -d( |$)' "$a/log$n" || no "run $n did not call fail2ban-client -d"
  calls=$(grep -E "$F2B_RESTART_RE|$F2B_START_RE" "$a/log$n")
  [[ -z $calls ]] || no "run $n restarted or started fail2ban:" "$calls"
  if ((n == 1)) && [[ -e $a/state/active.fail2ban ]]; then no "fail2ban is active after the aborted run 1"; fi
  [[ -n $(snap_of "$s" $((n - 1)) "$file") ]] || no "fixture: $file is not there before run $n"
  d=$(diff <(f2b_d_lines "$s" $((n - 1))) <(f2b_d_lines "$s" "$n")) || no "run $n changed jail.d or fail2ban.d:" "$d"
  ! grep -q 'Änderungen in diesem Lauf' "$a/out$n" || no "run $n went on to the end after the abort"
  grep -qxF -- "$4" "$a/f2b_dump" || no "fixture not in effect: fail2ban-client -d after the run lacks $4:" \
    "$(grep -E "dbpurgeage|logtarget|'sshd', '(bantime|findtime|maxretry)" "$a/f2b_dump")"
  return $((1 - ok))
}

# Foreign jail.d/zz.local and fail2ban.d/zz.local whose values equal those of the
# privacy policy in another notation: both runs exit 0 with the effective values of
# t_f2b_effective, fail2ban is restarted once in run 1 and not in run 2 (t_f2b_restart)
# and is enabled and active, both runs ask fail2ban-client -d, the foreign files stay as
# they were. fail2ban-client -d shows every DUMP_LINE: the foreign values are the ones in
# effect.
t_f2b_equiv() { # SCENARIO DUMP_LINE...
  local ok=1 s=$1 a r f d l
  shift
  t_f2b_effective "$s" 2 || ok=0
  t_f2b_restart "$s" none || ok=0
  a=$(art "$s")
  [[ -e $a/state/enabled.fail2ban && -e $a/state/active.fail2ban ]] || no "fail2ban is not enabled and active"
  for r in 1 2; do
    grep -qE '^fail2ban-client -d( |$)' "$a/log$r" || no "run $r did not call fail2ban-client -d"
    ! grep -q '^Abbruch' "$a/err$r" || no "run $r: abort message:" "$(grep '^Abbruch' -A3 "$a/err$r")"
  done
  for f in /etc/fail2ban/jail.d/zz.local /etc/fail2ban/fail2ban.d/zz.local; do
    [[ -n $(snap_of "$s" 0 "$f") ]] || no "fixture: $f is not there before run 1"
  done
  d=$(diff <(f2b_d_lines "$s" 0) <(f2b_d_lines "$s" 2)) || no "the runs changed jail.d or fail2ban.d:" "$d"
  for l in "$@"; do
    grep -qxF -- "$l" "$a/f2b_dump" || no "fixture not in effect: fail2ban-client -d after the runs lacks $l"
  done
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

# logrotate counts as missing although half of it is there (package installed without
# program, or program without package), rsyslog is installed: as t_no_lr (no
# 00-login-logs, no 00-fail2ban-log, a warning that names logrotate, package files
# unchanged), no 00-auth-log either, and the warning about logrotate matches REGEX and
# not NOT_REGEX (it says which half is missing). BIN is what the fixture provides:
# "none" (no program in the PATH of the script) or "present".
t_lr_half() { # SCENARIO BIN REGEX NOT_REGEX
  local ok=1 a bin w
  have_run "$1" 1 || return 1
  a=$(art "$1")
  bin=$(cat "$a/lr_bin" 2>/dev/null)
  case $2 in
    none) [[ $bin == none ]] || no "fixture: logrotate program in the PATH of the script: ${bin:-lr_bin missing}" ;;
    present) [[ $bin == /* ]] || no "fixture: no logrotate program in the PATH of the script: ${bin:-lr_bin missing}" ;;
  esac
  t_no_lr "$1" || ok=0
  [[ ! -e "$(upper "$1" etc)${AUTH_LOGROTATE#/etc}" ]] || no "$AUTH_LOGROTATE written although logrotate counts as missing"
  w=$(grep -E 'WARNUNG:' "$a/err1" | grep -F logrotate)
  grep -qE -- "$3" <<<"$w" || no "the warning about logrotate does not match /$3/:" "${w:-no such warning}"
  ! grep -qE -- "$4" <<<"$w" || no "the warning about logrotate matches /$4/:" "$w"
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

# A rule that keeps out deploy (the CI), but not ubuntu: as t_sshd_accepts (exit 0, ssh
# reloaded, hardening and every LINE in effect), plus a warning that names deploy and
# matches REGEX (the rule), no abort message, the run goes on to the end and creates
# deploy.
t_sshd_deploy_warns() { # SCENARIO REGEX LINE...
  local ok=1 s=$1 re=$2 a w
  shift 2
  t_sshd_accepts "$s" "$@" || ok=0
  a=$(art "$s")
  w=$(grep -E 'WARNUNG:' "$a/err1" | grep -wF deploy)
  grep -qE -- "$re" <<<"$w" || no "no warning that names deploy and /$re/:" "$(grep 'WARNUNG' "$a/err1")"
  ! grep -q '^Abbruch' "$a/err1" || no "abort message:" "$(grep '^Abbruch' "$a/err1")"
  grep -qE 'Änderungen in diesem Lauf: [0-9]' "$a/out1" || no "the run did not reach the end"
  grep -qE '^useradd( .*)? deploy$' "$a/log1" || no "user deploy was not created"
  return $((1 - ok))
}

# A Match block only for deploy (SC_SSHD_MATCH_DEPLOY) needs more than a key there: the
# login of ubuntu is not affected, so only a warning (t_sshd_deploy_warns: exit 0, ssh
# reloaded, hardening in effect, warning naming deploy and REGEX, no abort, the run goes
# on and creates deploy). The fixture is in effect: after the run sshd -T -C for deploy
# has LINE, sshd -T -C for ubuntu does not.
t_sshd_deploy_auth_warns() { # SCENARIO REGEX LINE
  local ok=1 a
  t_sshd_deploy_warns "$1" "$2" || ok=0
  a=$(art "$1")
  grep -qxF -- "$3" "$a/sshd_T_deploy" || no "fixture not in effect: sshd -T -C for deploy lacks '$3'"
  ! grep -qxF -- "$3" "$a/sshd_T_admin" || no "fixture: sshd -T -C for ubuntu has '$3' as well"
  return $((1 - ok))
}

# The drop-in /etc/ssh/sshd_config.d/10-haertung.conf has every LINE (a line of its own;
# blanks around and between the words do not matter), and sshd -T after the run has each
# of them (in lower case, as sshd -T prints it).
t_sshd_dropin_lines() { # SCENARIO LINE...
  local ok=1 s=$1 f line
  shift
  have_run "$s" 1 || return 1
  f="$(upper "$s" etc)${SSHD_DROPIN#/etc}"
  if [[ ! -f $f ]]; then
    no "$SSHD_DROPIN was not written"
    return 1
  fi
  for line in "$@"; do
    grep -qxE "[[:space:]]*${line// /[[:space:]]+}[[:space:]]*" "$f" || no "$SSHD_DROPIN lacks the line: $line" "$(cat "$f")"
    grep -qxF -- "${line,,}" "$(art "$s")/sshd_T" || no "sshd -T after the run lacks: ${line,,}"
  done
  return $((1 - ok))
}

# As t_sshd_rollback_because (drop-in as before, no reload, abort naming REGEX), and the
# fixture is in effect after the run: sshd -T (VIEW global) or sshd -T -C for ubuntu (VIEW
# admin; then not the global view, only the Match block sets it) has LINE.
t_sshd_rollback_fixture() { # SCENARIO REGEX VIEW LINE
  local ok=1 a
  t_sshd_rollback_because "$1" "$2" || ok=0
  a=$(art "$1")
  if [[ $3 == global ]]; then
    grep -qxF -- "$4" "$a/sshd_T" || no "fixture not in effect: sshd -T lacks '$4'"
  else
    grep -qxF -- "$4" "$a/sshd_T_admin" || no "fixture not in effect: sshd -T -C for ubuntu lacks '$4'"
    ! grep -qxF -- "$4" "$a/sshd_T" || no "fixture: global sshd -T has '$4' as well (only the Match block should set it)"
  fi
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

# --- tests: login with a key alone (PubkeyAuthentication, AuthenticationMethods) ---

SSHD_DROPIN=/etc/ssh/sshd_config.d/10-haertung.conf

# The checks stop the run before any change (t_aborts_because: exit != 0, nothing
# changed, no modifying command, REGEX on stderr), with the abort message of the checks
# ("Abbruch, nichts geändert") naming REGEX. The fixture is in effect: after the run
# sshd -T (VIEW global) or sshd -T -C for ubuntu (VIEW admin; then the global view must
# not have it, only the Match block sets it) has LINE.
t_auth_precheck_abort() { # SCENARIO REGEX VIEW LINE
  local ok=1 a
  t_aborts_because "$1" "$2" || ok=0
  a=$(art "$1")
  grep -E '^Abbruch, nichts geändert' "$a/err1" | grep -qE -- "$2" ||
    no "no abort of the checks ('Abbruch, nichts geändert') naming /$2/:" "$(cat "$a/err1")"
  if [[ $3 == global ]]; then
    grep -qxF -- "$4" "$a/sshd_T" || no "fixture not in effect: sshd -T lacks '$4'"
  else
    grep -qxF -- "$4" "$a/sshd_T_admin" || no "fixture not in effect: sshd -T -C for ubuntu lacks '$4'"
    ! grep -qxF -- "$4" "$a/sshd_T" || no "fixture: global sshd -T has '$4' as well (only the Match block should set it)"
  fi
  return $((1 - ok))
}

# A package update in step 1 adds "Match User ubuntu / PubkeyAuthentication no" (apt-get
# stub), after the checks before the packages passed. The check after writing the drop-in
# catches it; this run wrote the drop-in, so it is removed again, ssh is not reloaded and
# the run stops (t_sshd_rollback_because). The hook ran and is in effect.
t_auth_after_packages() { # SCENARIO
  local ok=1 a
  t_sshd_rollback_because "$1" 'PubkeyAuthentication' || ok=0
  a=$(art "$1")
  grep -qx 'sshd PubkeyAuthentication no' "$a/state/apt_hooks" 2>/dev/null ||
    no "fixture: the apt-get stub did not add the Match block"
  grep -qx 'pubkeyauthentication no' "$a/sshd_T_admin" ||
    no "fixture not in effect: sshd -T -C for ubuntu lacks 'pubkeyauthentication no'"
  ! grep -q '^Abbruch, nichts geändert' "$a/err1" ||
    no "the checks before the packages aborted already (this test is about the check after the drop-in):" "$(cat "$a/err1")"
  return $((1 - ok))
}

# --- tests: sshd checks on every run --------------------------------------------

# Run 2 leaves the drop-in unchanged and still runs the read-only checks of step 4:
# sshd -t, after it sshd -T, sshd -T -C for ubuntu and for deploy (only step 4 asks for
# deploy); exit 0.
t_sshd_checks_every_run() { # SCENARIO
  local ok=1 a t d after
  have_run "$1" 2 || return 1
  a=$(art "$1")
  [[ $(rc_of "$1" 2) == 0 ]] || no "run 2: expected exit code 0, got: $(rc_of "$1" 2)"
  [[ -n $(snap_of "$1" 1 "$SSHD_DROPIN") ]] || no "fixture: $SSHD_DROPIN is not there after run 1"
  d=$(diff <(snap_of "$1" 1 "$SSHD_DROPIN") <(snap_of "$1" 2 "$SSHD_DROPIN")) || no "fixture: run 2 changed $SSHD_DROPIN:" "$d"
  t=$(grep -nxF 'sshd -t' "$a/log2" | head -1 | cut -d: -f1)
  if [[ -z $t ]]; then
    no "run 2 (drop-in unchanged) did not run sshd -t"
  else
    after=$(tail -n "+$t" "$a/log2")
    grep -qxF 'sshd -T' <<<"$after" || no "run 2: no sshd -T after sshd -t"
    grep -qxF 'sshd -T -C user=ubuntu,host=localhost,addr=127.0.0.1' <<<"$after" || no "run 2: no sshd -T -C for ubuntu after sshd -t"
    grep -qxF 'sshd -T -C user=deploy,host=localhost,addr=127.0.0.1' <<<"$after" || no "run 2: no sshd -T -C for deploy after sshd -t"
  fi
  return $((1 - ok))
}

# Between run 1 and run 2 the sshd configuration changed elsewhere (SC_BETWEEN_SSHD_*), so
# that ubuntu would be locked out. Run 2 leaves its drop-in unchanged, runs the checks
# anyway (sshd -t) and aborts naming REGEX. The drop-in stays exactly as it was (inode,
# mode, times, content: no rollback), so does everything else in sshd_config.d and all
# other files; ssh is not reloaded; the run stops there. The change is in effect: FILE
# (sshd_T or sshd_T_admin, after the runs) has LINE.
t_sshd_rerun_abort() { # SCENARIO REGEX FILE LINE
  local ok=1 a rc s1 d
  have_run "$1" 2 || return 1
  a=$(art "$1")
  [[ $(rc_of "$1" 1) == 0 ]] || no "run 1: expected exit code 0, got: $(rc_of "$1" 1)" "$(tail -3 "$a/err1")"
  rc=$(rc_of "$1" 2)
  [[ $rc =~ ^[0-9]+$ && $rc -ne 0 ]] || no "run 2: expected exit code != 0, got: $rc"
  grep -E '^Abbruch' "$a/err2" | grep -qE -- "$2" ||
    no "run 2: the abort message does not name the reason (/$2/):" "$(cat "$a/err2")"
  grep -qxF 'sshd -t' "$a/log2" || no "run 2 did not run sshd -t"
  s1=$(snap_of "$1" 1 "$SSHD_DROPIN")
  [[ -n $s1 ]] || no "$SSHD_DROPIN is not there after run 1"
  d=$(diff <(printf '%s\n' "$s1") <(snap_of "$1" 2 "$SSHD_DROPIN")) || no "run 2 changed, reset or removed $SSHD_DROPIN:" "$d"
  d=$(diff "$a/sshd_state1" "$a/sshd_state_end") || no "run 2 changed /etc/ssh/sshd_config.d (name mode owner sha256):" "$d"
  d=$(diff "$a/snap1" "$a/snap2") || no "run 2 changed files:" "$d"
  ! grep -qE '^systemctl [a-z-]*(reload|restart)[a-z-]* ssh' "$a/log2" ||
    no "run 2 reloaded ssh:" "$(grep -E '^systemctl .* ssh' "$a/log2")"
  ! grep -qE '^fail2ban-client ' "$a/log2" || no "run 2 went on after the failed check (fail2ban-client ran)"
  ! grep -q 'Änderungen in diesem Lauf' "$a/out2" || no "run 2 went on to the end"
  grep -qxF -- "$4" "$a/$3" || no "fixture not in effect: $3 after run 2 lacks '$4'"
  return $((1 - ok))
}

# What the abort message of step 4 says about the cause when the drop-in is unchanged:
#   rundir  /run/sshd could not be created, so sshd was not checked at all
#   error   sshd itself reports an error (sshd -t or sshd -T fails)
#   config  the configuration fails a check: another file changed (or the check is new)
declare -A SSHD_CAUSE_RE=(
  [rundir]='nicht geprüft|ungeprüft'
  [error]='meldet einen Fehler|Syntaxfehler'
  [config]='andere(n)? Datei|an anderer Stelle'
)

# Run 2 leaves the drop-in unchanged (as written by run 1), and a check of step 4 fails
# for CAUSE: rundir (the package installation replaced /run/sshd by a file, so it cannot
# be created again), error (sshd -t fails in run 2) or config (a later drop-in with
# DenyUsers ubuntu before run 2). Run 1 exit 0; run 2 exit != 0 with an abort message,
# the drop-in exactly as after run 1 (inode, mode, times, content), no other file changed
# (apart from /run/sshd for rundir), ssh not reloaded, fail2ban not touched, no summary.
# The abort message matches SSHD_CAUSE_RE of CAUSE and none of the other two causes (so
# rundir and error do not say that another file changed, config does not say that sshd
# was not checked or reported an error); for rundir it names /run/sshd.
t_sshd_unchanged_cause() { # SCENARIO rundir|error|config
  local ok=1 s=$1 cause=$2 a rc s1 d ab c ex
  have_run "$s" 2 || return 1
  a=$(art "$s")
  case $cause in
    rundir) grep -qx 'rundir file' "$a/state/apt_hooks" 2>/dev/null || no "fixture: the apt-get stub did not replace /run/sshd in run 2" ;;
    error)
      grep -qF 'test stub: forced sshd -t failure' "$a/err2" || no "fixture: sshd -t did not fail in run 2"
      ! grep -qF 'test stub: forced sshd -t failure' "$a/err1" || no "fixture: sshd -t failed in run 1 already"
      ;;
    config) grep -qx 'denyusers ubuntu' "$a/sshd_T" || no "fixture not in effect: sshd -T after run 2 lacks 'denyusers ubuntu'" ;;
  esac
  [[ $(rc_of "$s" 1) == 0 ]] || no "run 1: expected exit code 0, got: $(rc_of "$s" 1)" "$(tail -3 "$a/err1")"
  rc=$(rc_of "$s" 2)
  [[ $rc =~ ^[0-9]+$ && $rc -ne 0 ]] || no "run 2: expected exit code != 0, got: $rc"
  ab=$(sed -n '/^Abbruch/,$p' "$a/err2")
  [[ -n $ab ]] || no "run 2: no abort message:" "$(cat "$a/err2")"
  s1=$(snap_of "$s" 1 "$SSHD_DROPIN")
  [[ -n $s1 ]] || no "$SSHD_DROPIN is not there after run 1"
  d=$(diff <(printf '%s\n' "$s1") <(snap_of "$s" 2 "$SSHD_DROPIN")) || no "run 2 changed, reset or removed $SSHD_DROPIN:" "$d"
  # For rundir the fixture itself changes /run/sshd and so /run (their snapshot lines left out).
  if [[ $cause == rundir ]]; then ex='(^|  )\./run/u(/sshd)?(\||$)'; else ex='^$'; fi
  d=$(diff <(grep -vE -- "$ex" "$a/snap1") <(grep -vE -- "$ex" "$a/snap2")) || no "run 2 changed files:" "$d"
  ! grep -qE '^systemctl [a-z-]*(reload|restart)[a-z-]* ssh' "$a/log2" ||
    no "run 2 reloaded ssh:" "$(grep -E '^systemctl .* ssh' "$a/log2")"
  ! grep -qE '^fail2ban-client ' "$a/log2" || no "run 2 went on after the failed check (fail2ban-client ran)"
  ! grep -q 'Änderungen in diesem Lauf' "$a/out2" || no "run 2 went on to the end"
  grep -qE -- "${SSHD_CAUSE_RE[$cause]}" <<<"$ab" ||
    no "the abort message does not give the cause $cause (/${SSHD_CAUSE_RE[$cause]}/):" "$ab"
  for c in rundir error config; do
    [[ $c == "$cause" ]] && continue
    ! grep -qE -- "${SSHD_CAUSE_RE[$c]}" <<<"$ab" ||
      no "the abort message for cause $cause gives the cause $c as well (/${SSHD_CAUSE_RE[$c]}/):" "$ab"
  done
  if [[ $cause == rundir ]]; then
    grep -qF '/run/sshd' <<<"$ab" || no "the abort message does not name /run/sshd:" "$ab"
  fi
  return $((1 - ok))
}

# --- tests: audit login UID (sudo su -, sudo -i) -----------------------------------

# Fixture: run 1 of SCENARIO had the audit login UID of USER ("-": a UID without user).
loginuid_fixture() { # SCENARIO USER
  local a u
  a=$(art "$1")
  u=$(cat "$a/loginuid_user1" 2>/dev/null)
  if [[ $2 == - ]]; then
    [[ -z $u ]] || no "fixture: the audit login UID $(cat "$a/loginuid1") of the run belongs to $u, expected a UID without user"
  else
    [[ $u == "$2" ]] || no "fixture: the run had the audit login UID $(cat "$a/loginuid1" 2>/dev/null) (user '${u}'), expected that of $2"
  fi
}

t_loginuid_aborts() { # SCENARIO USER REGEX: login UID of USER; aborts like t_aborts_because
  local ok=1
  t_aborts_because "$1" "$3" || ok=0
  loginuid_fixture "$1" "$2"
  return $((1 - ok))
}

t_loginuid_runs() { # SCENARIO USER: login UID of USER; the run goes through (exit 0)
  local ok=1
  t_runs_ok "$1" || ok=0
  loginuid_fixture "$1" "$2"
  grep -qE 'Änderungen in diesem Lauf: [0-9]' "$(art "$1")/out1" || no "the run did not reach the end"
  return $((1 - ok))
}

# --- tests: firewall changed by the package installation ------------------------------

# Calls of the script that change or save firewall rules.
FW_WRITE_RE='^(ip6?tables( [^ ]+)* -[IAPDRFX] |ip6?tables-restore( |$)|netfilter-persistent( |$))'

# The package installation (apt-get stub, STUB_APT_FW=HOOK) changed INPUT of TOOL so that
# it no longer turns other traffic away, and putting back the copy from before does not
# help (STUB_IPT_SAVE: no copy; STUB_RESTORE: the restore fails or changes nothing). The
# run aborts right after step 1: the abort message names TOOL and REGEX (what changed),
# not the other tool, and WHY (why it was not restored); TOOL-restore was called RESTORES
# times ("-": 0 or 1), the other tool's never; iptables-persistent was installed, but no
# later step ran (no modifying command apart from apt-get, the debconf answers and that
# restore), no rule was inserted and nothing saved (no netfilter-persistent, all files as
# before, also /etc/iptables/rules.v* if SAVED is "saved").
t_fw_apt_abort() { # SCENARIO HOOK TOOL REGEX RESTORES WHY [saved]
  local ok=1 s=$1 a rc other ab calls d f n
  have_run "$s" 1 || return 1
  a=$(art "$s")
  if [[ $3 == iptables ]]; then other=ip6tables; else other=iptables; fi
  grep -qx "fw $2" "$a/state/apt_hooks" 2>/dev/null || no "fixture: the apt-get stub did not change the firewall ($2)"
  rc=$(rc_of "$s" 1)
  [[ $rc =~ ^[0-9]+$ && $rc -ne 0 ]] || no "expected exit code != 0, got: $rc"
  ab=$(grep -E '^Abbruch' "$a/err1")
  grep -qE "(^|[ (])${3}[ :]" <<<"$ab" || no "the abort message does not name $3:" "$(cat "$a/err1")"
  ! grep -qE "(^|[ (])${other}[ :]" <<<"$ab" || no "the abort message names $other, whose INPUT did not change:" "$ab"
  grep -qE -- "$4" <<<"$ab" || no "the abort message does not say what changed (/$4/):" "${ab:-no abort message}"
  grep -qE -- "$6" <<<"$ab" || no "the abort message does not say why the firewall was not restored (/$6/):" "${ab:-no abort message}"
  grep -qE '^apt-get .* install .*iptables-persistent' "$a/log1" || no "step 1 did not install iptables-persistent"
  n=$(grep -cE "^${3}-restore( |\$)" "$a/log1")
  if [[ $5 == - ]]; then
    ((n <= 1)) || no "$n calls of $3-restore (expected at most 1)"
  else
    ((n == $5)) || no "$n calls of $3-restore (expected $5)"
  fi
  calls=$(grep -E "$FW_WRITE_RE" "$a/log1" | grep -vE "^${3}-restore( |\$)")
  [[ -z $calls ]] || no "the script changed or saved firewall rules:" "$calls"
  calls=$(modifying_calls "$a/log1" rerun | grep -vE "^${3}-restore( |\$)")
  [[ -z $calls ]] || no "the run went on after step 1 (modifying commands):" "$calls"
  d=$(diff "$a/snap0" "$a/snap1") || no "files changed (nothing may be saved or written):" "$d"
  if [[ ${7:-} == saved ]]; then
    for f in /etc/iptables/rules.v4 /etc/iptables/rules.v6; do
      [[ -n $(snap_of "$s" 0 "$f") ]] || no "fixture: no saved $f before the run"
    done
  fi
  ! grep -q 'Änderungen in diesem Lauf' "$a/out1" || no "the run went on to the end"
  return $((1 - ok))
}

# Tables other than filter (nat, mangle, raw, security) of a TOOL-save dump, as they are.
fw_other_tables() { # FILE
  awk '/^\*/ { t = substr($0, 2) } t != "" && t != "filter" { print } /^COMMIT$/ { t = "" }' "$1"
}

# ACCEPT rules for tcp PORT before and behind the first rule that turns other traffic
# away (a REJECT rule, also with a comment, or "-A INPUT -j DROP"), and the number of that
# rule (0 if there is none).
fw_final_split() { # FILE(iptables -S INPUT) PORT
  awk -v port="$2" '
    /^-A INPUT/ { n++
      if (!fin && (/ -j REJECT/ || $0 == "-A INPUT -j DROP")) { fin = n; next }
      if ($0 ~ ("-p tcp .*--dport " port "( |$)") && / -j ACCEPT/) { if (fin) behind++; else before++ } }
    END { printf "%d %d %d\n", before, behind, fin }' "$1"
}

# INPUT of the table filter in a rules file (iptables-save format), in the form of
# "iptables -S INPUT": "-P INPUT POLICY", then the rules.
saved_input() { # FILE
  awk '/^\*/ { t = substr($0, 2) }
       t == "filter" && $1 == ":INPUT" { print "-P INPUT " $2 }
       t == "filter" && $1 == "-A" && $2 == "INPUT" { print }' "$1"
}

# The package installation (apt-get stub, STUB_APT_FW=HOOK) changed INPUT of TOOL so that
# it no longer turns other traffic away. Before the package installation the run saved
# the table filter of both tools ("iptables-save -t filter", "ip6tables-save -t filter",
# before the first apt-get that installs or upgrades). After it, it put back exactly that
# copy for TOOL (TOOL-restore once, after installing iptables-persistent, before any
# rule is inserted or saved; nothing restored for the other tool), warned that the
# firewall was restored (one warning naming TOOL, "wiederhergestellt" and REGEX, what had
# changed; none for the other tool) and went on: exit 0, no abort, the run reaches the
# end. Afterwards INPUT of both tools is closed again: no rule of before lost (policy and
# final REJECT/DROP included), only the missing ACCEPT rules added, 22/80/443 exactly
# once before the final rule; and it is saved (netfilter-persistent save after the
# restore and the inserts; the saved INPUT equals INPUT after the run). The other tables
# (nat) are after the run as right after the package installation (and, with the nat
# fixture, still have its rules).
t_fw_apt_restored() { # SCENARIO HOOK TOOL REGEX
  local ok=1 s=$1 tool=$3 a other w first inst rl r_other ins sv sl fam t f0 f1 port before behind fin exp added lost rules d
  have_run "$s" 1 || return 1
  a=$(art "$s")
  if [[ $tool == iptables ]]; then other=ip6tables; else other=iptables; fi
  grep -qx "fw $2" "$a/state/apt_hooks" 2>/dev/null || no "fixture: the apt-get stub did not change the firewall ($2)"
  [[ $(rc_of "$s" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$s" 1)" "$(grep -E '^Abbruch' -A2 "$a/err1")"
  ! grep -q '^Abbruch' "$a/err1" || no "abort message:" "$(grep '^Abbruch' "$a/err1")"
  grep -qE 'Änderungen in diesem Lauf: [0-9]' "$a/out1" || no "the run did not reach the end"
  w=$(grep -E 'WARNUNG:' "$a/err1" | grep -F 'wiederhergestellt')
  [[ $(grep -cE "(^|[ (])${tool}[ :]" <<<"$w") == 1 ]] ||
    no "expected exactly one warning that the firewall was restored naming $tool:" "$(grep 'WARNUNG' "$a/err1")"
  grep -E "(^|[ (])${tool}[ :]" <<<"$w" | grep -qE -- "$4" || no "the warning does not say what changed (/$4/):" "${w:-no such warning}"
  ! grep -qE "(^|[ (])${other}[ :]" <<<"$w" || no "a warning says the firewall of $other was restored, whose INPUT did not change:" "$w"
  first=$(grep -nE '^apt-get .* (install|upgrade|full-upgrade|dist-upgrade)( |$)' "$a/log1" | head -1 | cut -d: -f1)
  inst=$(grep -nE '^apt-get .* install .*iptables-persistent' "$a/log1" | head -1 | cut -d: -f1)
  if [[ -z $first || -z $inst ]]; then
    no "no apt-get that installs, or no installation of iptables-persistent"
    return 1
  fi
  for t in iptables ip6tables; do
    sl=$(grep -nxF "$t-save -t filter" "$a/log1" | head -1 | cut -d: -f1)
    if [[ -z $sl ]] || ((sl > first)); then
      no "the table filter of $t was not saved ($t-save -t filter) before the package installation (log line ${sl:-none}, first apt-get that installs: $first)"
    fi
  done
  [[ $(grep -cE "^${tool}-restore( |\$)" "$a/log1") == 1 ]] ||
    no "expected exactly one call of $tool-restore, got $(grep -cE "^${tool}-restore( |\$)" "$a/log1")"
  r_other=$(grep -E "^${other}-restore( |\$)" "$a/log1")
  [[ -z $r_other ]] || no "$other-restore was called, whose INPUT did not change:" "$r_other"
  rl=$(grep -nE "^${tool}-restore( |\$)" "$a/log1" | head -1 | cut -d: -f1)
  if [[ -n $rl ]]; then
    ((rl > inst)) || no "$tool-restore (log line $rl) before installing iptables-persistent (line $inst)"
    ins=$(grep -nE '^ip6?tables -[IA] INPUT' "$a/log1" | head -1 | cut -d: -f1)
    if [[ -n $ins ]] && ((ins < rl)); then no "a rule was inserted (log line $ins) before the restore (line $rl)"; fi
    sv=$(grep -nx 'netfilter-persistent save' "$a/log1" | head -1 | cut -d: -f1)
    if [[ -n $sv ]] && ((sv < rl)); then no "the rules were saved (log line $sv) before the restore (line $rl)"; fi
    [[ $(cat "$a/state/$tool-restore.in.1" 2>/dev/null) == "$(cat "$a/state/$tool-save.out.1" 2>/dev/null)" &&
      -s $a/state/$tool-restore.in.1 ]] ||
      no "the input of $tool-restore is not the copy '$tool-save -t filter' printed before the package installation"
  fi
  # Closed again and saved, in both families.
  for fam in v4 v6; do
    if [[ $fam == v4 ]]; then t=iptables; else t=ip6tables; fi
    f0="$a/${fam}_0" f1="$a/${fam}_1"
    lost=$(comm -23 <(LC_ALL=C sort "$f0") <(LC_ALL=C sort "$f1"))
    [[ -z $lost ]] || no "$t: rules (or the policy) of INPUT from before the run are gone after it:" "$lost"
    exp=""
    for port in 22 80 443; do
      grep -qxF -- "$(fw_rule "$port")" "$f0" || exp+="$(fw_rule "$port")"$'\n'
      read -r before behind fin < <(fw_final_split "$f1" "$port")
      ((before == 1)) || no "$t: $before ACCEPT rules for tcp $port before the final REJECT/DROP after the run (expected exactly 1)"
    done
    if ! grep -qxF -- '-P INPUT DROP' "$f1"; then
      read -r _ _ fin < <(fw_final_split "$f1" 22)
      ((fin > 0)) || no "$t: INPUT is open after the run (neither policy DROP nor a final REJECT/DROP)"
    fi
    added=$(comm -13 <(LC_ALL=C sort "$f0") <(LC_ALL=C sort "$f1"))
    [[ $added == "$(printf '%s' "$exp" | LC_ALL=C sort)" ]] ||
      no "$t: the run added other rules than the missing ACCEPT rules."$'\n'"added:"$'\n'"$added"$'\n'"expected:"$'\n'"$exp"
    rules="$(upper "$s" etc)/iptables/rules.$fam"
    if [[ ! -f $rules ]]; then
      no "$t: /etc/iptables/rules.$fam was not saved"
    else
      d=$(diff <(saved_input "$rules") "$f1") || no "$t: INPUT in /etc/iptables/rules.$fam is not INPUT after the run (< saved, > live):" "$d"
    fi
  done
  if ((ok == 0)); then
    for fam in v4 v6; do
      no "$fam INPUT before the run:"$'\n'"$(cat "$a/${fam}_0")" "$fam INPUT after the run:"$'\n'"$(cat "$a/${fam}_1")"
    done
  fi
  sv=$(grep -nx 'netfilter-persistent save' "$a/log1" | tail -1 | cut -d: -f1)
  ins=$(grep -nE '^ip6?tables -[IA] INPUT' "$a/log1" | tail -1 | cut -d: -f1)
  if [[ -z $sv ]]; then
    no "netfilter-persistent save was not run"
  elif [[ -n $ins ]] && ((sv < ins)); then
    no "saved (log line $sv) before the last insert (line $ins)"
  fi
  # Other tables: as right after the package installation (the restore leaves them alone).
  for fam in 4 6; do
    if [[ ! -f $a/state/after_apt.v$fam ]]; then
      no "fixture: the apt-get stub did not record the tables after the package installation (after_apt.v$fam)"
      continue
    fi
    d=$(diff <(fw_other_tables "$a/state/after_apt.v$fam") <(fw_other_tables "$a/save${fam}_1")) ||
      no "IPv$fam: tables other than filter changed after the package installation (< right after apt, > after the run):" "$d"
    if [[ -f $a/nat_fixture ]]; then
      grep -qE -- '^-A POSTROUTING .*-j MASQUERADE' <(fw_other_tables "$a/save${fam}_0") ||
        no "fixture: IPv$fam nat has no MASQUERADE rule before the run"
      grep -qE -- '^-A POSTROUTING .*-j MASQUERADE' <(fw_other_tables "$a/save${fam}_1") ||
        no "IPv$fam: the MASQUERADE rule of the nat fixture is gone after the run"
    fi
  done
  return $((1 - ok))
}

# The package installation flushed INPUT of iptables and in the same apt run added a nat
# chain DOCKER with a MASQUERADE rule for 172.18.0.0/16 (apt-get stub, flush_v4_nat).
# Restoring the table filter leaves nat alone: after the run nat still has that chain and
# rule, and the rule of the nat fixture. (t_fw_apt_restored checks the rest.)
t_fw_apt_nat_kept() { # SCENARIO
  local ok=1 a nat0 nat1
  have_run "$1" 1 || return 1
  a=$(art "$1")
  nat0=$(fw_other_tables "$a/save4_0")
  nat1=$(fw_other_tables "$a/save4_1")
  ! grep -qF -- '172.18.0.0/16' <<<"$nat0" || no "fixture: the nat rule for 172.18.0.0/16 was there before the run"
  grep -qE -- '^-A POSTROUTING -s 172\.18\.0\.0/16 .*-j MASQUERADE' "$a/state/after_apt.v4" 2>/dev/null ||
    no "fixture: the apt-get stub did not add the nat rule for 172.18.0.0/16"
  grep -qE '^iptables-restore( |$)' "$a/log1" || no "fixture: iptables-restore was not called, nothing was restored"
  grep -qE -- '^-A POSTROUTING -s 172\.18\.0\.0/16 .*-j MASQUERADE' <<<"$nat1" ||
    no "the nat rule added during the package installation is gone after the run:" "$nat1"
  grep -qxF ':DOCKER - [0:0]' <<<"$nat1" || no "the nat chain DOCKER added during the package installation is gone after the run:" "$nat1"
  grep -qE -- '^-A POSTROUTING -s 172\.17\.0\.0/16 .*-j MASQUERADE' <<<"$nat1" || no "the nat rule of the fixture is gone after the run:" "$nat1"
  return $((1 - ok))
}

# The copy of the table filter cannot be taken (STUB_IPT_SAVE=fail: iptables-save and
# ip6tables-save fail), but the package installation leaves INPUT as it was. Nothing to
# restore, so the run goes through as usual: exit 0, no abort, no ip(6)tables-restore,
# 22/80/443 before the REJECT in both families, netfilter-persistent save, the run reaches
# the end.
t_fw_nosave_ok() { # SCENARIO
  local ok=1 a r
  have_run "$1" 1 || return 1
  a=$(art "$1")
  grep -qxF 'iptables-save -t filter' "$a/log1" || no "fixture: the run did not try iptables-save -t filter"
  [[ ! -s $a/state/iptables-save.out.1 ]] || no "fixture: iptables-save printed rules although the stub should fail"
  ! grep -qE '^fw ' "$a/state/apt_hooks" 2>/dev/null || no "fixture: the apt-get stub changed the firewall: $(cat "$a/state/apt_hooks")"
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)" "$(grep -E '^Abbruch' -A2 "$a/err1")"
  r=$(grep -E '^ip6?tables-restore( |$)' "$a/log1")
  [[ -z $r ]] || no "restored although INPUT did not change:" "$r"
  grep -qE 'Änderungen in diesem Lauf: [0-9]' "$a/out1" || no "the run did not reach the end"
  t_fw_ports_before_reject "$1" v4 || ok=0
  t_fw_ports_before_reject "$1" v6 || ok=0
  grep -qx 'netfilter-persistent save' "$a/log1" || no "netfilter-persistent save was not run"
  return $((1 - ok))
}

# Warnings in run 1 of SCENARIO that INPUT of TOOL does not filter incoming connections.
open_warnings() { # SCENARIO TOOL
  grep -E "WARNUNG: $2: " "$(art "$1")/err1" | grep -E 'INPUT' | grep -cE 'gefiltert'
}

# Before the run INPUT of each of the TOOLS ("iptables", "ip6tables", both separated by a
# space, or "" for none) has neither a final REJECT or DROP rule nor policy DROP: one
# warning that it does not filter for each of them, none for the other tool; exit 0 and
# the run reaches the end.
t_fw_open_warns() { # SCENARIO TOOLS
  local ok=1 a tool want w
  have_run "$1" 1 || return 1
  a=$(art "$1")
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)" "$(grep -E '^Abbruch' -A2 "$a/err1")"
  for tool in iptables ip6tables; do
    want=0
    [[ " $2 " == *" $tool "* ]] && want=1
    w=$(open_warnings "$1" "$tool")
    ((w == want)) || no "$w warnings that $tool INPUT does not filter, expected $want:" "$(grep 'WARNUNG' "$a/err1")"
  done
  grep -qE 'Änderungen in diesem Lauf: [0-9]' "$a/out1" || no "the run did not reach the end"
  return $((1 - ok))
}

# Step 1 answers the questions of iptables-persistent before installing it, with
# autosave_v4 and autosave_v6 false (never true), and the checks read INPUT of both tools
# before the first apt-get.
t_fw_before_packages() { # SCENARIO
  local ok=1 a deb fam first i4 i6 dcs inst
  have_run "$1" 1 || return 1
  a=$(art "$1")
  deb=$(cat "$a/state/debconf" 2>/dev/null)
  for fam in v4 v6; do
    grep -qxE "iptables-persistent[[:space:]]+iptables-persistent/autosave_${fam}[[:space:]]+boolean[[:space:]]+false" <<<"$deb" ||
      no "debconf answers lack 'iptables-persistent/autosave_$fam boolean false':" "${deb:-none}"
  done
  ! grep -qiE 'autosave_v[46][[:space:]]+boolean[[:space:]]+true' <<<"$deb" || no "debconf answers contain autosave true:" "$deb"
  first=$(grep -nE '^apt-get ' "$a/log1" | head -1 | cut -d: -f1)
  i4=$(grep -nxF 'iptables -S INPUT' "$a/log1" | head -1 | cut -d: -f1)
  i6=$(grep -nxF 'ip6tables -S INPUT' "$a/log1" | head -1 | cut -d: -f1)
  dcs=$(grep -nE '^debconf-set-selections' "$a/log1" | head -1 | cut -d: -f1)
  inst=$(grep -nE '^apt-get .* install .*iptables-persistent' "$a/log1" | head -1 | cut -d: -f1)
  if [[ -z $first || -z $inst ]]; then
    no "no apt-get call or no installation of iptables-persistent"
    return 1
  fi
  if [[ -z $i4 ]] || ((i4 > first)); then no "iptables INPUT not read before the first apt-get (log line ${i4:-none}, apt-get in line $first)"; fi
  if [[ -z $i6 ]] || ((i6 > first)); then no "ip6tables INPUT not read before the first apt-get (log line ${i6:-none}, apt-get in line $first)"; fi
  if [[ -z $dcs ]] || ((dcs > inst)); then no "debconf answers (log line ${dcs:-none}) not given before installing iptables-persistent (line $inst)"; fi
  return $((1 - ok))
}

# --- tests: final unconditional DROP like REJECT --------------------------------------

# INPUT of FAMILY ends with "-A INPUT -j DROP" and has a conditional DROP (one address) at
# the top. Run 1 inserts the missing ACCEPT rules for 22/80/443 right before the final
# DROP: INPUT afterwards is INPUT before with exactly these rules there (nothing before the
# conditional DROP, nothing lost or moved). Run 2: exit 0, 0 changes, rules unchanged.
t_fw_final_drop() { # SCENARIO FAMILY(v4|v6)
  local ok=1 a f0 f1 port ins want line done=0 d r
  have_run "$1" 2 || return 1
  a=$(art "$1")
  f0="$a/$2_0" f1="$a/$2_1"
  grep -qxF -- '-A INPUT -j DROP' "$f0" || no "fixture: $2 INPUT has no final '-A INPUT -j DROP' before the run"
  grep -qE -- '^-A INPUT -s [^ ]+ -j DROP$' "$f0" || no "fixture: $2 INPUT has no conditional DROP before the run"
  ! grep -qF -- '-j REJECT' "$f0" || no "fixture: $2 INPUT has a REJECT rule"
  ((ok)) || return 1
  for r in 1 2; do
    [[ $(rc_of "$1" "$r") == 0 ]] || no "run $r: expected exit code 0, got: $(rc_of "$1" "$r")" "$(tail -3 "$a/err$r")"
  done
  ins=""
  for port in 22 80 443; do
    grep -qxF -- "$(fw_rule "$port")" "$f0" || ins+="$(fw_rule "$port")"$'\n'
  done
  [[ -n $ins ]] || no "fixture: no ACCEPT rule missing before the run"
  want=""
  while IFS= read -r line; do
    if [[ $line == "-A INPUT -j DROP" && $done == 0 ]]; then
      want+=$ins
      done=1
    fi
    want+="$line"$'\n'
  done <"$f0"
  d=$(diff <(printf '%s' "$want") "$f1") ||
    no "$2 INPUT after run 1 is not INPUT before with the missing ACCEPT rules right before the final DROP (< expected, > got):" "$d"
  d=$(diff "$a/fw1" "$a/fw2") || no "run 2 changed firewall rules:" "$d"
  grep -qE 'Änderungen in diesem Lauf: 0([^0-9]|$)' "$a/out2" ||
    no "run 2 does not report 0 changes:" "$(grep 'Änderungen' "$a/out2")"
  return $((1 - ok))
}

# --- tests: other fail2ban jails ----------------------------------------------------

# Names of the jails in a fail2ban-client -d dump (['add', NAME, BACKEND]), sorted.
f2b_jails() { # FILE
  grep -oE "^\['add', '[^']+'" "$1" | sed -E "s/^\['add', '//; s/'$//" | LC_ALL=C sort
}

# A jail other than sshd is enabled (fixture: /etc/fail2ban/jail.d/zz.local with a section
# [JAIL]): run 1 aborts before fail2ban is restarted or started, like a foreign value of
# the privacy policy (t_f2b_foreign_abort: exit != 0, abort message naming zz.local,
# fail2ban neither restarted nor started nor active, jail.d and fail2ban.d unchanged, no
# summary). The abort message names JAIL, and the package's jail.conf as well if that has
# a section [JAIL]. fail2ban-client -d after the run shows JAIL next to sshd.
t_f2b_other_jail_aborts() { # SCENARIO JAIL
  local ok=1 a ab add
  have_run "$1" 1 || return 1
  a=$(art "$1")
  add=$(grep -E "^\['add', '$2', " "$a/f2b_dump" | head -1)
  [[ -n $add && $(f2b_jails "$a/f2b_dump" | tr '\n' ' ') == *"sshd "* ]] ||
    no "fixture not in effect: fail2ban-client -d shows the jails: $(f2b_jails "$a/f2b_dump" | tr '\n' ' ')"
  if [[ -n $add ]]; then
    t_f2b_foreign_abort "$1" 1 /etc/fail2ban/jail.d/zz.local "$add" || ok=0
  fi
  ab=$(sed -n '/^Abbruch/,$p' "$a/err1")
  grep -qw -- "$2" <<<"$ab" || no "the abort message does not name the jail $2:" "${ab:-no abort message}"
  if grep -qxE "[[:space:]]*\[$2\][[:space:]]*" /etc/fail2ban/jail.conf 2>/dev/null; then
    grep -qF /etc/fail2ban/jail.conf <<<"$ab" || no "the abort message does not name /etc/fail2ban/jail.conf, which has a section [$2]:" "$ab"
  fi
  return $((1 - ok))
}

# Dry run with another jail enabled (fixture jail.d/zz.local): exit 0, nothing changed
# (t_dry_would_abort), the dry run asked fail2ban-client -d, and the line saying that a
# real run would abort names JAIL and FILE.
t_dry_f2b_other_jail() { # SCENARIO JAIL FILE
  local ok=1 a l
  t_dry_would_abort "$1" "$2" || ok=0
  a=$(art "$1")
  grep -qE '^fail2ban-client -d( |$)' "$a/log1" || no "the dry run did not ask fail2ban-client -d"
  l=$(grep -E '\[Testlauf\].*abbrechen' "$a/err1" | grep -wF -- "$2")
  grep -qF -- "$3" <<<"$l" || no "the dry run does not name $3 with the jail $2:" "${l:-$(cat "$a/err1")}"
  return $((1 - ok))
}

# Only the jail sshd is enabled (fail2ban-client -d after the run): exit 0 and no warning
# about other jails (none that names "Jail" or any jail of the DISABLED list).
t_f2b_only_sshd() { # SCENARIO [DISABLED_JAIL...]
  local ok=1 s=$1 a j
  shift
  have_run "$s" 1 || return 1
  a=$(art "$s")
  [[ $(rc_of "$s" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$s" 1)"
  [[ $(f2b_jails "$a/f2b_dump") == sshd ]] || no "fixture: fail2ban-client -d shows the jails: $(f2b_jails "$a/f2b_dump" | tr '\n' ' ')"
  t_no_warning "$s" 'Jail' || ok=0
  for j in "$@"; do t_no_warning "$s" "$j" || ok=0; done
  return $((1 - ok))
}

# --- tests: home directory of deploy from getent passwd ------------------------------

# deploy exists already with the home directory HOME (fixture). Run 1 creates HOME/.ssh
# (700) with an empty authorized_keys (600), both deploy:deploy, and nothing under
# /home/deploy; run 2: exit 0, 0 changes, no file changed.
t_deploy_home() { # SCENARIO HOME
  local ok=1 a r d
  have_run "$1" 2 || return 1
  a=$(art "$1")
  for r in 1 2; do
    [[ $(rc_of "$1" "$r") == 0 ]] || no "run $r: expected exit code 0, got: $(rc_of "$1" "$r")" "$(tail -3 "$a/err$r")"
  done
  [[ $(cut -d: -f6 "$a/deploy_passwd") == "$2" ]] || no "fixture: home directory of deploy is '$(cut -d: -f6 "$a/deploy_passwd")', expected $2"
  grep -qxF "$2/.ssh deploy deploy 700" <(sed -E 's/ [0-9]+$//' "$a/deploy_home_stat" 2>/dev/null) ||
    no "$2/.ssh is not a directory deploy:deploy 700:" "$(cat "$a/deploy_home_stat" 2>/dev/null)"
  grep -qxF "$2/.ssh/authorized_keys deploy deploy 600 0" "$a/deploy_home_stat" 2>/dev/null ||
    no "$2/.ssh/authorized_keys is not an empty file deploy:deploy 600:" "$(cat "$a/deploy_home_stat" 2>/dev/null)"
  [[ ! -e $(upper "$1" home)/deploy ]] || no "/home/deploy was created:" "$(find "$(upper "$1" home)/deploy" | head -5)"
  grep -qE 'Änderungen in diesem Lauf: 0([^0-9]|$)' "$a/out2" || no "run 2 does not report 0 changes:" "$(grep 'Änderungen' "$a/out2")"
  d=$(diff "$a/snap1" "$a/snap2") || no "run 2 changed files:" "$d"
  return $((1 - ok))
}

# Dry run with deploy's home directory HOME: exit 0, nothing changed, it shows the
# authorized_keys in HOME/.ssh and does not name /home/deploy.
t_dry_deploy_home() { # SCENARIO HOME
  local ok=1 a
  have_run "$1" 1 || return 1
  a=$(art "$1")
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)"
  assert_unchanged "$1" 1
  grep -qE -- "\[Testlauf\] install .* $2/\.ssh/authorized_keys$" "$a/out1" ||
    no "dry run does not show $2/.ssh/authorized_keys:" "$(grep -F 'authorized_keys' "$a/out1")"
  ! grep -qF '/home/deploy' "$a/out1" "$a/err1" || no "dry run names /home/deploy:" "$(grep -hF '/home/deploy' "$a/out1" "$a/err1")"
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

# Every run of every scenario had a defined audit login UID: SC_LOGINUID or, without it,
# 4294967295 (not set), whatever the session the tests were started from has (CALLER_LOGINUID).
t_loginuid_defined() {
  local ok=1 f n=0 want got sc
  for f in "$WORK"/*/loginuid_want[0-9]*; do
    [[ -f $f ]] || continue
    n=$((n + 1))
    want=$(cat "$f")
    got=$(cat "${f/loginuid_want/loginuid}" 2>/dev/null) || got="missing"
    sc=${f#"$WORK"/}
    [[ $got == "$want" ]] || no "${sc%%/*}: run had audit login UID '$got', expected '$want'"
  done
  # Otherwise this test would look at nothing.
  ((n >= 50)) || no "too little to check: $n runs with a recorded audit login UID"
  # The default is "not set", not the caller's UID; a scenario without SC_LOGINUID must
  # have had it (fresh has none).
  [[ $(cat "$WORK/fresh/loginuid1" 2>/dev/null) == "$LOGINUID_UNSET" ]] ||
    no "fresh: run 1 had audit login UID '$(cat "$WORK/fresh/loginuid1" 2>/dev/null)', expected $LOGINUID_UNSET (the caller's is $CALLER_LOGINUID)"
  return $((1 - ok))
}

# --- tests: profile hostinger ----------------------------------------------------

# Path of the absolute PATH in the upper layer of SCENARIO (PATH under an overlaid
# directory).
upper_path() { # SCENARIO PATH
  local top=${2#/}
  top=${top%%/*}
  echo "$(upper "$1" "$top")${2#/"$top"}"
}

# Stat line and sha256 line of the absolute PATH (under an overlaid directory) in
# snapshot N of SCENARIO; empty if PATH is not in the upper layer.
snap_path() { # SCENARIO N PATH
  local top=${3#/}
  top=${top%%/*}
  awk -v p="./$top/u${3#/"$top"}" '{ split($0, f, "|") } f[1] == p || substr($0, 67) == p' "$(art "$1")/snap$2"
}

# Lines of FILE that hold the type and the base64 part of the key line KEY (whatever the
# comment and options in front).
h_key_count() { # FILE KEY
  local t b
  read -r t b _ <<<"$2"
  [[ -f $1 ]] || {
    echo 0
    return
  }
  awk -v t="$t" -v b="$b" '{ for (i = 1; i < NF; i++) if ($i == t && $(i + 1) == b) { n++; break } }
    END { print n + 0 }' "$1"
}

# h_rule_class FAMILY LINE: class of one line of "iptables -S INPUT" (FAMILY v4) or
# "ip6tables -S INPUT" (v6) in the profile hostinger: lo, est (RELATED,ESTABLISHED), icmp
# (all of ICMP or ICMPv6), dhcp (DHCP client: udp 67 -> 68; IPv6 udp 547 -> 546 from a
# link-local address), tcp22, tcp80, tcp443 (new connections from anywhere, on any
# interface), reject (unconditional REJECT), f2b (jump into a chain of fail2ban), other.
# Nothing for a line that is no rule.
h_rule_class() { # FAMILY LINE
  local fam=$1 l=$2
  local re_est='^-A INPUT -m (state|conntrack) --(state|ctstate) (RELATED,ESTABLISHED|ESTABLISHED,RELATED) -j ACCEPT$'
  local re_icmp6='^-A INPUT -p (ipv6-icmp|icmpv6) -j ACCEPT$'
  local re_dhcp4='^-A INPUT( .*)? -p udp (.* )?--sport 67 (.* )?--dport 68 -j ACCEPT$'
  local re_dhcp6='^-A INPUT -s fe80::/10( .*)? -p udp (.* )?--sport 547 (.* )?--dport 546 -j ACCEPT$'
  local re_tcp='^-A INPUT -p tcp (.* )?--dport (22|80|443) -j ACCEPT$'
  local re_reject='^-A INPUT( -m comment --comment [^ ]+)? -j REJECT( --reject-with [^ ]+)?$'
  [[ $l == "-A INPUT "* ]] || return 0
  if [[ $l == "-A INPUT -i lo -j ACCEPT" ]]; then
    echo lo
  elif [[ $l =~ $re_est ]]; then
    echo est
  elif [[ $fam == v4 && $l == "-A INPUT -p icmp -j ACCEPT" ]] || [[ $fam == v6 && $l =~ $re_icmp6 ]]; then
    echo icmp
  elif [[ $fam == v4 && $l =~ $re_dhcp4 && $l != *" -i "* ]] || [[ $fam == v6 && $l =~ $re_dhcp6 ]]; then
    echo dhcp
  elif [[ $l =~ $re_tcp && $l != *" -s "* && $l != *" -i "* ]]; then
    echo "tcp${BASH_REMATCH[2]}"
  elif [[ $l =~ $re_reject ]]; then
    echo reject
  elif [[ $l == *" -j f2b-"* ]]; then
    echo f2b
  else
    echo other
  fi
}

# INPUT of FAMILY (v4, v6) after run RUN of SCENARIO; before run 1 it was open and empty
# (policy ACCEPT, no rule). Afterwards: policy still ACCEPT, the rules lo, est, icmp,
# dhcp, tcp22, tcp80, tcp443 (h_rule_class) in this order, each exactly once, and an
# unconditional REJECT as the very last rule; nothing else (no "-i docker0 -j ACCEPT" or
# the like). With "f2b" a jump into fail2ban's chain at the top is expected as well (put
# there between the runs). Run RUN exited with 0.
t_h_fw_input() { # SCENARIO FAMILY RUN [f2b]
  local ok=1 a f l classes want="lo est icmp dhcp tcp22 tcp80 tcp443 reject"
  have_run "$1" "$3" || return 1
  a=$(art "$1")
  f="$a/$2_0"
  if [[ $(grep -c '^-A INPUT' "$f") != 0 ]] || ! grep -qx -- '-P INPUT ACCEPT' "$f"; then
    no "fixture: $2 INPUT before the run is not open and empty:" "$(cat "$f")"
  fi
  [[ $(rc_of "$1" "$3") == 0 ]] || no "run $3: expected exit code 0, got: $(rc_of "$1" "$3")" "$(grep '^Abbruch' "$a/err$3")"
  f="$a/$2_$3"
  grep -qx -- '-P INPUT ACCEPT' "$f" || no "$2: INPUT policy is no longer ACCEPT: $(head -1 "$f")"
  classes=$(while IFS= read -r l; do h_rule_class "$2" "$l"; done <"$f" | tr '\n' ' ')
  classes=${classes% }
  if [[ ${4:-} == f2b ]]; then want="f2b $want"; fi
  [[ $classes == "$want" ]] || no "$2: classes of the INPUT rules after run $3: '$classes', expected '$want'" "$(cat "$f")"
  return $((1 - ok))
}

# h_table FILE TABLE: the lines of TABLE (from "*TABLE" to its COMMIT) in an
# ip(6)tables-save dump.
h_table() { # FILE TABLE
  awk -v t="*$2" '$0 == t { p = 1 } p { print } p && $0 == "COMMIT" { p = 0 }' "$1"
}

# Runs 1 to RUN of SCENARIO changed nothing in the firewall apart from the rules of INPUT
# in the table filter, in both families: the table nat (with Docker's DNAT for port
# 32768) byte for byte as before, in the table filter the policies, FORWARD and Docker's
# chains as before, no table added or removed.
t_h_fw_others_untouched() { # SCENARIO RUN
  local ok=1 a fam s0 s1 d
  have_run "$1" "$2" || return 1
  a=$(art "$1")
  for fam in 4 6; do
    s0="$a/save${fam}_0" s1="$a/save${fam}_$2"
    grep -q -- '--dport 32768 -j DNAT' <(h_table "$s0" nat) || no "fixture: IPv$fam nat has no DNAT for port 32768"
    grep -q '^:DOCKER-USER ' <(h_table "$s0" filter) || no "fixture: IPv$fam filter has no chain DOCKER-USER"
    d=$(diff <(h_table "$s0" nat) <(h_table "$s1" nat)) || no "IPv$fam: table nat changed (< before, > after run $2):" "$d"
    d=$(diff <(h_table "$s0" filter | grep -v '^-A INPUT ') <(h_table "$s1" filter | grep -v '^-A INPUT ')) ||
      no "IPv$fam: table filter changed outside the rules of INPUT (< before, > after run $2):" "$d"
    d=$(diff <(grep '^\*' "$s0") <(grep '^\*' "$s1")) || no "IPv$fam: tables added or removed:" "$d"
  done
  return $((1 - ok))
}

# /etc/iptables/rules.v4 and rules.v6 after run RUN of SCENARIO: mode 640 root:root, only
# the table filter, no chain apart from INPUT, FORWARD and OUTPUT (no Docker or fail2ban
# chain), rules only in INPUT, and exactly the rules INPUT has after the run (jumps into
# fail2ban's chain left out), the last one a REJECT; ip(6)tables-restore --test accepts
# the file. In no run did the script call ip(6)tables-restore without --test (loading
# rules), and every input of ip(6)tables-restore --test held only the table filter.
t_h_rules_files() { # SCENARIO RUN
  local ok=1 a fam f live saved chains other tool n inp
  have_run "$1" "$2" || return 1
  a=$(art "$1")
  for fam in v4 v6; do
    f="$(upper "$1" etc)/iptables/rules.$fam"
    if [[ ! -f $f ]]; then
      no "/etc/iptables/rules.$fam was not written"
      continue
    fi
    [[ $(stat -c '%a %U:%G' "$f") == "640 root:root" ]] || no "rules.$fam: mode and owner $(stat -c '%a %U:%G' "$f"), expected 640 root:root"
    [[ $(grep '^\*' "$f" | tr '\n' ' ') == '*filter ' ]] || no "rules.$fam holds the tables '$(grep '^\*' "$f" | tr '\n' ' ')', expected only *filter"
    chains=$(grep '^:' "$f" | awk '{ print $1 }' | LC_ALL=C sort | tr '\n' ' ')
    [[ $chains == ':FORWARD :INPUT :OUTPUT ' ]] || no "rules.$fam declares the chains '$chains', expected only :FORWARD :INPUT :OUTPUT"
    ! grep -qE 'DOCKER|f2b-' "$f" || no "rules.$fam mentions chains of Docker or fail2ban:" "$(grep -E 'DOCKER|f2b-' "$f")"
    other=$(grep '^-A ' "$f" | grep -v '^-A INPUT ')
    [[ -z $other ]] || no "rules.$fam has rules outside INPUT:" "$other"
    live=$(grep '^-A INPUT ' "$a/${fam}_$2" | grep -v -- ' -j f2b-')
    saved=$(grep '^-A INPUT ' "$f")
    [[ $saved == "$live" ]] ||
      no "rules.$fam: rules of INPUT differ from those in effect after run $2 (< in effect, > saved):" "$(diff <(printf '%s\n' "$live") <(printf '%s\n' "$saved"))"
    [[ $(tail -n 1 <<<"$saved") == *" -j REJECT"* ]] || no "rules.$fam: the last rule of INPUT is no REJECT"
    grep -qx 'COMMIT' "$f" || no "rules.$fam has no COMMIT"
    grep -qx 'rc=0' "$a/rules_test_$fam" 2>/dev/null || no "rules.$fam: ip(6)tables-restore --test rejects it:" "$(cat "$a/rules_test_$fam" 2>/dev/null)"
  done
  for tool in iptables ip6tables; do
    n=$(cat "$a"/log[0-9]* | grep -E "^${tool}-restore( |\$)" | grep -cvE "^${tool}-restore( [^ ]+)* (--test|-t)( |\$)")
    ((n == 0)) || no "$tool-restore without --test (rules loaded):" "$(cat "$a"/log[0-9]* | grep -E "^${tool}-restore")"
    for inp in "$a/state/$tool-restore.in."*; do
      [[ -f $inp ]] || continue
      [[ $(grep '^\*' "$inp" | LC_ALL=C sort -u | tr '\n' ' ') == '*filter ' ]] ||
        no "$tool-restore --test got the tables '$(grep '^\*' "$inp" | LC_ALL=C sort -u | tr '\n' ' ')', expected only *filter"
    done
  done
  return $((1 - ok))
}

# Exactly one copy PATH.bak-YYYYMMDD-HHMMSS next to PATH after the runs of SCENARIO, with
# the content of ORIG (PATH before run 1, kept by the fixture); PATH itself has another
# content now.
t_h_backup() { # SCENARIO PATH ORIG
  local ok=1 f
  local -a baks
  have_run "$1" 1 || return 1
  f=$(upper_path "$1" "$2")
  [[ -s $3 ]] || {
    no "fixture: no copy of $2 from before the run ($3)"
    return 1
  }
  mapfile -t baks < <(find "$(dirname "$f")" -maxdepth 1 -name "$(basename "$f").bak-*" 2>/dev/null | LC_ALL=C sort)
  if ((${#baks[@]} != 1)); then
    no "expected exactly one backup $2.bak-*, found ${#baks[@]}:" "${baks[@]##*/}"
  else
    [[ ${baks[0]##*/} =~ \.bak-[0-9]{8}-[0-9]{6}$ ]] || no "backup name is not $(basename "$2").bak-YYYYMMDD-HHMMSS: ${baks[0]##*/}"
    cmp -s "${baks[0]}" "$3" || no "backup ${baks[0]##*/} differs from $2 before the run"
  fi
  if [[ ! -f $f ]] || cmp -s "$f" "$3"; then no "fixture: $2 was not replaced, so there was nothing to back up"; fi
  return $((1 - ok))
}

# No copy PATH.bak-* after the runs of SCENARIO.
t_h_no_backup() { # SCENARIO PATH
  local ok=1 f left
  have_run "$1" 1 || return 1
  f=$(upper_path "$1" "$2")
  left=$(find "$(dirname "$f")" -maxdepth 1 -name "$(basename "$f").bak-*" 2>/dev/null)
  [[ -z $left ]] || no "backup made although there was nothing to back up:" "$left"
  return $((1 - ok))
}

# /etc/docker/daemon.json after the runs of SCENARIO is exactly the JSON object WANT (no
# key lost, none added, same values); mode 644; dockerd --validate accepts it (if dockerd
# is installed on the host).
t_h_daemon_json() { # SCENARIO WANT
  local ok=1 f out
  have_run "$1" 1 || return 1
  f="$(upper "$1" etc)/docker/daemon.json"
  [[ -f $f ]] || {
    no "/etc/docker/daemon.json missing after the run"
    return 1
  }
  out=$(
    python3 -I - "$f" "$2" <<'PY'
import json
import sys

try:
    got = json.load(open(sys.argv[1], encoding="utf-8"))
except ValueError as e:
    print("invalid JSON: %s" % e)
    sys.exit(1)
want = json.loads(sys.argv[2])
if got != want:
    print("got:      " + json.dumps(got, sort_keys=True))
    print("expected: " + json.dumps(want, sort_keys=True))
    sys.exit(1)
PY
  ) || no "daemon.json is not as expected:" "$out"
  [[ $(stat -c %a "$f") == 644 ]] || no "daemon.json: mode $(stat -c %a "$f"), expected 644"
  if [[ -f $(art "$1")/dockerd_validate ]]; then
    grep -qx 'rc=0' "$(art "$1")/dockerd_validate" || no "dockerd --validate rejects it:" "$(cat "$(art "$1")/dockerd_validate")"
  else
    echo "      (info: dockerd not installed, dockerd --validate skipped)" >&2
  fi
  return $((1 - ok))
}

# h_docker_hits LOGFILE: calls that restart, stop, start or reinstall Docker: systemctl
# with docker/containerd and any verb other than is-active, is-enabled, cat, show,
# status and reload (SIGHUP); dockerd other than --help or --validate; apt-get install
# of Docker's packages; the Docker key fetched.
h_docker_hits() { # LOGFILE
  awk '
    $1 == "systemctl" {
      d = 0
      for (i = 3; i <= NF; i++) if ($i ~ /^(docker|containerd)(\.service|\.socket)?$/) d = 1
      if (d && $2 != "is-active" && $2 != "is-enabled" && $2 != "cat" && $2 != "show" && $2 != "status" && $2 != "reload") print
      next }
    $1 == "dockerd" && $2 != "--help" && $2 != "--validate" { print; next }
    $1 == "apt-get" && / install / && / (docker-ce|docker-ce-cli|containerd\.io|docker\.io)( |$)/ { print; next }
    $1 == "curl" && /download\.docker\.com/ { print }' "$1"
}

# Docker in SCENARIO: no run restarted, stopped, started or reinstalled it (h_docker_hits),
# no apt source or key added; "systemctl reload docker" exactly RELOADS times in run 1 and
# never in later runs; in run 1 the reload comes before "apt-get ... full-upgrade" (an
# update of docker-ce there restarts dockerd, live-restore must be on by then).
t_h_docker_calls() { # SCENARIO RELOADS
  local ok=1 a f r n hits u
  have_run "$1" 1 || return 1
  a=$(art "$1")
  for f in "$a"/log[0-9]*; do
    r=${f##*/log}
    hits=$(h_docker_hits "$f")
    [[ -z $hits ]] || no "run $r restarted, stopped, started or reinstalled Docker:" "$hits"
    n=$(grep -cxE 'systemctl reload docker(\.service)?' "$f")
    if [[ $r == 1 ]]; then
      ((n == $2)) || no "run 1: $n reloads of docker, expected $2"
    else
      ((n == 0)) || no "run $r: $n reloads of docker, expected 0"
    fi
  done
  if (($2 > 0)); then
    r=$(grep -nxE 'systemctl reload docker(\.service)?' "$a/log1" | head -1 | cut -d: -f1)
    u=$(grep -nE '^apt-get .* full-upgrade( |$)' "$a/log1" | head -1 | cut -d: -f1)
    if [[ -z $r || -z $u ]] || ((r > u)); then
      no "run 1: reload of docker (log line ${r:-none}) not before apt-get full-upgrade (line ${u:-none})"
    fi
  fi
  [[ -z $(find "$(upper "$1" etc)/apt/sources.list.d" "$(upper "$1" etc)/apt/keyrings" -mindepth 1 2>/dev/null) ]] ||
    no "apt source or key for Docker added"
  return $((1 - ok))
}

# No run of any scenario of the profile hostinger (h_*) restarted, stopped, started or
# reinstalled Docker (h_docker_hits). Enough logs, and some with a reload, otherwise this
# test would look at nothing.
t_h_docker_never_restarted() {
  local ok=1 f n=0 reloads=0 hits
  for f in "$WORK"/h_*/log[0-9]*; do
    [[ -f $f ]] || continue
    n=$((n + 1))
    hits=$(h_docker_hits "$f")
    [[ -z $hits ]] || no "${f#"$WORK"/}:" "$hits"
    if grep -qxE 'systemctl reload docker(\.service)?' "$f"; then reloads=$((reloads + 1)); fi
  done
  ((n >= 20 && reloads >= 3)) || no "too little to check: $n call logs, $reloads with a reload of docker"
  return $((1 - ok))
}

# daemon.json with "live-restore": false and another log driver (syslog): exit 0, the
# file stays as it is (inode, mode, times, content), no backup, Docker neither reloaded nor
# restarted, a warning about live-restore and one about the log driver.
t_h_dj_keep() { # SCENARIO
  local ok=1 a w d p=/etc/docker/daemon.json
  have_run "$1" 1 || return 1
  a=$(art "$1")
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)" "$(grep '^Abbruch' "$a/err1")"
  [[ -n $(snap_path "$1" 0 "$p") ]] || no "fixture: no $p before the run"
  d=$(diff <(snap_path "$1" 0 "$p") <(snap_path "$1" 1 "$p")) || no "$p changed:" "$d"
  w=$(grep 'WARNUNG:' "$a/err1" | grep -F 'daemon.json')
  grep -q 'live-restore' <<<"$w" || no "no warning about live-restore:" "$(grep 'WARNUNG' "$a/err1")"
  grep -qE 'log-driver|syslog' <<<"$w" || no "no warning about the log driver:" "$(grep 'WARNUNG' "$a/err1")"
  t_h_no_backup "$1" "$p" || ok=0
  t_h_docker_calls "$1" 0 || ok=0
  return $((1 - ok))
}

# Run 1 of SCENARIO created the admin user H_ADMIN (it did not exist before): home
# /home/H_ADMIN, shell /bin/bash, member of sudo; ~/.ssh 700 and authorized_keys 600, both
# H_ADMIN:H_ADMIN; KEY exactly once in it; no NOPASSWD (t_h_no_nopasswd); the user was
# created before ssh was reloaded.
t_h_admin_created() { # SCENARIO KEY
  local ok=1 a u=$H_ADMIN n r1 r2
  have_run "$1" 1 || return 1
  a=$(art "$1")
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)" "$(grep '^Abbruch' "$a/err1")"
  [[ -z $(snap_path "$1" 0 "/home/$u") ]] || no "fixture: /home/$u existed before the run"
  [[ $(cut -d: -f1,6,7 "$a/h_passwd") == "$u:/home/$u:/bin/bash" ]] ||
    no "account: '$(cat "$a/h_passwd")', expected home /home/$u and shell /bin/bash"
  grep -qx sudo <<<"$(tr ' ' '\n' <"$a/h_groups")" || no "$u is not in group sudo: $(cat "$a/h_groups")"
  grep -qxF "/home/$u/.ssh $u $u 700" "$a/h_stat" || no "/home/$u/.ssh is not $u:$u 700:" "$(cat "$a/h_stat")"
  grep -qxF "/home/$u/.ssh/authorized_keys $u $u 600" "$a/h_stat" || no "authorized_keys is not $u:$u 600:" "$(cat "$a/h_stat")"
  n=$(h_key_count "$a/h_keys" "$2")
  ((n == 1)) || no "the key is $n times in authorized_keys, expected once:" "$(cat "$a/h_keys" 2>/dev/null)"
  t_h_no_nopasswd "$1" || ok=0
  r1=$(grep -nE "^useradd( .*)? $u\$" "$a/log1" | head -1 | cut -d: -f1)
  r2=$(grep -nxE 'systemctl reload ssh(\.service)?' "$a/log1" | head -1 | cut -d: -f1)
  if [[ -z $r1 || -z $r2 ]] || ((r1 > r2)); then
    no "useradd for $u (log line ${r1:-none}) not before the reload of ssh (line ${r2:-none})"
  fi
  return $((1 - ok))
}

# H_ADMIN existed before (fixture SC_H_EXISTING: not in sudo, ~/.ssh 755, authorized_keys
# 644 with the lines of h_keys0): not created again, now in sudo, ~/.ssh 700 and
# authorized_keys 600 (owner H_ADMIN), the lines from before kept in their order at the
# start of the file, then KEY, once; nothing else added; no NOPASSWD.
t_h_admin_existing() { # SCENARIO KEY
  local ok=1 a u=$H_ADMIN n0 d
  have_run "$1" 1 || return 1
  a=$(art "$1")
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)" "$(grep '^Abbruch' "$a/err1")"
  [[ -s $a/h_keys0 ]] || no "fixture: no authorized_keys before the run"
  ! grep -qE "^useradd( .*)? $u\$" "$a/log1" || no "useradd ran for the existing user $u"
  grep -qx sudo <<<"$(tr ' ' '\n' <"$a/h_groups")" || no "$u is not in group sudo: $(cat "$a/h_groups")"
  grep -qxF "/home/$u/.ssh $u $u 700" "$a/h_stat" || no "/home/$u/.ssh is not $u:$u 700:" "$(cat "$a/h_stat")"
  grep -qxF "/home/$u/.ssh/authorized_keys $u $u 600" "$a/h_stat" || no "authorized_keys is not $u:$u 600:" "$(cat "$a/h_stat")"
  n0=$(grep -c '' "$a/h_keys0")
  d=$(diff "$a/h_keys0" <(head -n "$n0" "$a/h_keys" 2>/dev/null)) || no "the lines from before are not kept at the start of authorized_keys:" "$d"
  [[ $(h_key_count "$a/h_keys" "$2") == 1 ]] || no "the key is not exactly once in authorized_keys:" "$(cat "$a/h_keys" 2>/dev/null)"
  [[ $(grep -c '' "$a/h_keys" 2>/dev/null) == $((n0 + 1)) ]] ||
    no "authorized_keys has $(grep -c '' "$a/h_keys" 2>/dev/null) lines, expected $((n0 + 1)) (those from before and the key)"
  t_h_no_nopasswd "$1" || ok=0
  return $((1 - ok))
}

# The key was in authorized_keys before, with another comment (fixture: ~/.ssh 700, file
# 600): exit 0, authorized_keys exactly as before (inode, mode, times, content).
t_h_key_kept() { # SCENARIO
  local ok=1 p=/home/$H_ADMIN/.ssh/authorized_keys d
  have_run "$1" 1 || return 1
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)" "$(grep '^Abbruch' "$(art "$1")/err1")"
  [[ -n $(snap_path "$1" 0 "$p") ]] || no "fixture: $p not there before the run"
  d=$(diff <(snap_path "$1" 0 "$p") <(snap_path "$1" 1 "$p")) || no "$p changed:" "$d"
  return $((1 - ok))
}

# sudo for H_ADMIN in SCENARIO only with its password: no NOPASSWD in /etc/sudoers or
# /etc/sudoers.d (upper layer), and "sudo -l -U H_ADMIN" lists (ALL : ALL) ALL without
# NOPASSWD.
t_h_no_nopasswd() { # SCENARIO
  local ok=1 a hits
  a=$(art "$1")
  hits=$(grep -rlsE 'NOPASSWD' "$(upper "$1" etc)/sudoers" "$(upper "$1" etc)/sudoers.d")
  [[ -z $hits ]] || no "NOPASSWD in:" "$hits"
  if grep -q 'may run the following commands' "$a/h_sudo" 2>/dev/null; then
    grep -qE '^[[:space:]]+\(ALL( : ALL)?\) ALL$' "$a/h_sudo" || no "sudo -l: $H_ADMIN may not run everything (with its password):" "$(cat "$a/h_sudo")"
    ! grep -q 'NOPASSWD' "$a/h_sudo" || no "sudo -l shows NOPASSWD:" "$(cat "$a/h_sudo")"
  else
    no "sudo -l -U $H_ADMIN does not list any rights:" "$(cat "$a/h_sudo" 2>/dev/null)"
  fi
  return $((1 - ok))
}

# sshd after run 1 of SCENARIO, with the files of Hostinger's image in place (before the
# run root could log in from the internet with a password; 50-cloud-init.conf and
# 60-cloudimg-settings.conf stay unchanged):
#   global (sshd -T): PasswordAuthentication, KbdInteractiveAuthentication and
#     PermitRootLogin no;
#   from the internet (H_PUBLIC): admin user and deploy only with the key, root neither
#     with a key nor with a password;
#   from the web console (H_CONSOLE): root with password, admin user and deploy still
#     only with the key;
#   AllowUsers exactly H_ADMIN, deploy and root@H_CONSOLE in every view;
# sshd -t passes, ssh reloaded once.
t_h_sshd() { # SCENARIO
  local ok=1 a v f s got want d
  have_run "$1" 1 || return 1
  a=$(art "$1")
  { grep -qx 'permitrootlogin yes' "$a/sshdT0_root_pub" && grep -qx 'passwordauthentication yes' "$a/sshdT0_root_pub"; } ||
    no "fixture: before the run root from the internet could not log in with a password:" "$(grep -E '^(permitrootlogin|passwordauthentication) ' "$a/sshdT0_root_pub")"
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)" "$(grep '^Abbruch' "$a/err1")"
  for v in \
    "_T:passwordauthentication no" "_T:kbdinteractiveauthentication no" "_T:permitrootlogin no" \
    "T_admin_pub:passwordauthentication no" "T_admin_pub:kbdinteractiveauthentication no" \
    "T_admin_pub:pubkeyauthentication yes" "T_admin_pub:authenticationmethods any" \
    "T_root_pub:permitrootlogin no" "T_root_pub:passwordauthentication no" "T_root_pub:kbdinteractiveauthentication no" \
    "T_deploy_pub:passwordauthentication no" "T_deploy_pub:kbdinteractiveauthentication no" \
    "T_deploy_pub:pubkeyauthentication yes" \
    "T_root_con:permitrootlogin yes" "T_root_con:passwordauthentication yes" \
    "T_admin_con:passwordauthentication no" "T_admin_con:kbdinteractiveauthentication no" \
    "T_admin_con:pubkeyauthentication yes" \
    "T_deploy_con:passwordauthentication no" "T_deploy_con:kbdinteractiveauthentication no" \
    "T_deploy_con:pubkeyauthentication yes"; do
    f="$a/sshd${v%%:*}" s=${v#*:}
    grep -qx "$s" "$f" || no "${f##*/}: lacks '$s', has '$(grep -E "^${s%% *} " "$f" | tr '\n' ' ')'"
  done
  want=$(printf '%s\n' "$H_ADMIN" deploy "root@$H_CONSOLE" | LC_ALL=C sort | tr '\n' ' ')
  for f in "$a/sshd_T" "$a"/sshdT_*_pub "$a"/sshdT_*_con; do
    got=$(awk '$1 == "allowusers" { print $2 }' "$f" | LC_ALL=C sort | tr '\n' ' ')
    [[ $got == "$want" ]] || no "${f##*/}: AllowUsers '$got', expected '$want'"
  done
  grep -qx 'rc=0' "$a/sshd_t" || no "sshd -t fails after the run:" "$(cat "$a/sshd_t")"
  [[ $(grep -cxE 'systemctl reload ssh(\.service)?' "$a/log1") == 1 ]] || no "ssh was not reloaded exactly once in run 1"
  for f in /etc/ssh/sshd_config.d/50-cloud-init.conf /etc/ssh/sshd_config.d/60-cloudimg-settings.conf; do
    [[ -n $(snap_path "$1" 0 "$f") ]] || no "fixture: $f missing before the run"
    d=$(diff <(snap_path "$1" 0 "$f") <(snap_path "$1" 1 "$f")) || no "$f changed:" "$d"
  done
  return $((1 - ok))
}

# A setting from before the run conflicts with the profile hostinger. The run aborts and
# the abort message names REGEX (case-insensitive); /etc/ssh/sshd_config.d is as before
# the run (names, modes, owners, contents: the drop-in removed again), ssh not reloaded,
# sshd -t passes afterwards, the run stops there (no jail.local, no user deploy). The
# fixture is in effect: FILE (sshd_T or sshdT_WHO_pub|con, after the run) has LINE.
t_h_sshd_rollback() { # SCENARIO REGEX FILE LINE
  local ok=1 a rc d
  have_run "$1" 1 || return 1
  a=$(art "$1")
  rc=$(rc_of "$1" 1)
  [[ $rc =~ ^[0-9]+$ && $rc -ne 0 ]] || no "expected exit code != 0, got: $rc"
  grep -qiE -- "$2" <<<"$(grep '^Abbruch' "$a/err1")" || no "the abort message does not name /$2/:" "$(cat "$a/err1")"
  d=$(diff "$a/sshd_state0" "$a/sshd_state_end") || no "/etc/ssh/sshd_config.d is not as before the run (name mode owner sha256):" "$d"
  ! grep -qE '^systemctl [a-z-]*(reload|restart)[a-z-]* ssh' "$a/log1" || no "ssh was reloaded:" "$(grep -E '^systemctl .* ssh' "$a/log1")"
  grep -qx 'rc=0' "$a/sshd_t" || no "sshd -t fails after the abort:" "$(cat "$a/sshd_t")"
  [[ ! -e $(upper "$1" etc)/fail2ban/jail.local ]] || no "the script went on after the failed check (jail.local written)"
  ! grep -qE '^useradd( .*)? deploy$' "$a/log1" || no "the script went on after the failed check (user deploy created)"
  grep -qxF -- "$4" "$a/$3" || no "fixture not in effect: $3 lacks '$4'"
  return $((1 - ok))
}

# fail2ban-client -d after the runs of SCENARIO: the jail sshd ignores exactly the
# addresses of H_IGNOREIP, no more and no fewer.
t_h_f2b_ignoreip() { # SCENARIO
  local ok=1 out
  have_run "$1" 1 || return 1
  [[ -s $(art "$1")/f2b_dump ]] || no "fail2ban-client -d after the run printed nothing"
  out=$(
    python3 -I - "$(art "$1")/f2b_dump" "$H_IGNOREIP" <<'PY'
import ast
import sys

got = []
with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.strip()
        if line.startswith("['set', 'sshd', 'addignoreip'"):
            got += [str(x) for x in ast.literal_eval(line)[3:]]
want = sys.argv[2].split()
if sorted(got) != sorted(want):
    print("ignoreip of the jail sshd: %r, expected exactly %r" % (got, want))
    sys.exit(1)
PY
  ) || no "$out"
  return $((1 - ok))
}

# ufw installed and inactive: run 1 of SCENARIO asks "ufw status", goes on to the end with
# exit 0 and says that ufw goes away and where the firewall is then: a line that names
# ufw and the rules file /etc/iptables/rules.v4.
t_h_ufw_note() { # SCENARIO
  local ok=1 a
  have_run "$1" 1 || return 1
  a=$(art "$1")
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)" "$(grep '^Abbruch' "$a/err1")"
  grep -qx 'ufw status' "$a/log1" || no "the script did not ask 'ufw status'"
  grep -qF 'rules.v4' <<<"$(grep -ihF 'ufw' "$a/out1" "$a/err1")" ||
    no "no note naming ufw and the rules that replace it (rules.v4):" "$(cat "$a/out1" "$a/err1" | grep -iF ufw)"
  grep -qE 'Änderungen in diesem Lauf: [0-9]' "$a/out1" || no "the run did not reach the end"
  return $((1 - ok))
}

# None of STRING... (parts of the key passed as ADMIN_PUBKEY) appears in the output
# (stdout, stderr) of any run of SCENARIO.
t_h_key_hidden() { # SCENARIO STRING...
  local ok=1 s=$1 a f str n=0
  shift
  have_run "$s" 1 || return 1
  a=$(art "$s")
  for str in "$@"; do
    [[ ${#str} -ge 16 ]] || {
      no "test: string '$str' too short to look for"
      continue
    }
    n=$((n + 1))
    for f in "$a"/out[0-9]* "$a"/err[0-9]*; do
      ! grep -qF -- "$str" "$f" || no "${f##*/} shows key material: $(grep -F -- "$str" "$f" | head -2 | cut -c1-120)"
    done
  done
  ((n > 0)) || no "test: nothing to look for"
  return $((1 - ok))
}

# h_key_parts KEYFILE: what t_h_key_hidden looks for: of a public key the base64 part and
# 20 characters from its middle; of a private key every line between the armor lines.
h_key_parts() { # KEYFILE
  local b
  if grep -q -- '-----BEGIN' "$1"; then
    grep -v -- '-----' "$1"
  else
    b=$(awk '{ print $2 }' "$1")
    printf '%s\n' "$b" "${b:40:20}"
  fi
}

# The fingerprint of KEYFILE (ssh-keygen -l, SHA256) is in the output of run 1 of SCENARIO.
t_h_key_fpr_shown() { # SCENARIO KEYFILE
  local ok=1 fpr
  have_run "$1" 1 || return 1
  fpr=$(ssh-keygen -l -f "$2" | awk '{ print $2 }')
  [[ $fpr == SHA256:* ]] || no "test: no fingerprint for $2"
  grep -qF -- "$fpr" "$(art "$1")/out1" "$(art "$1")/err1" || no "run 1 does not show the fingerprint $fpr"
  return $((1 - ok))
}

# Run 2 of SCENARIO: runs 1 and 2 exit 0, run 1 reports changes, run 2 reports 0 changes,
# changes no file and no firewall rule and runs no modifying command (package updates
# excepted).
t_h_rerun() { # SCENARIO
  local ok=1 a d calls r
  have_run "$1" 2 || return 1
  a=$(art "$1")
  for r in 1 2; do
    [[ $(rc_of "$1" "$r") == 0 ]] || no "run $r: expected exit code 0, got: $(rc_of "$1" "$r")" "$(grep '^Abbruch' "$a/err$r")"
  done
  grep -qE 'Änderungen in diesem Lauf: [1-9]' "$a/out1" || no "run 1 does not report changes"
  grep -qE 'Änderungen in diesem Lauf: 0([^0-9]|$)' "$a/out2" || no "run 2 does not report 0 changes:" "$(grep 'Änderungen' "$a/out2")"
  d=$(diff "$a/snap1" "$a/snap2") || no "run 2 changed files:" "$d"
  d=$(diff "$a/fw1" "$a/fw2") || no "run 2 changed firewall rules:" "$d"
  calls=$(modifying_calls "$a/log2" rerun)
  [[ -z $calls ]] || no "run 2 ran modifying commands:" "$calls"
  return $((1 - ok))
}

# Dry run of the profile hostinger: exit 0, nothing changed (files, firewall, no modifying
# command), no "a real run would abort", and the output shows every REGEX.
t_h_dry() { # SCENARIO REGEX...
  local ok=1 s=$1 a all re
  shift
  have_run "$s" 1 || return 1
  a=$(art "$s")
  [[ $(rc_of "$s" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$s" 1)"
  assert_unchanged "$s" 1
  ! grep -qE '\[Testlauf\].*abbrechen' "$a/err1" || no "the dry run says a real run would abort:" "$(grep -E 'abbrechen' "$a/err1")"
  all=$(cat "$a/out1" "$a/err1")
  for re in "$@"; do
    grep -qE -- "$re" <<<"$all" || no "dry-run output lacks: $re"
  done
  return $((1 - ok))
}

# Listening services (ss) in run 1 of SCENARIO. none: only sshd (22), Hostinger's
# Traefik (80, 443), docker-proxy (32768), loopback and the DHCP client listen, so no
# warning names traefik, docker-proxy or 32768. 8080: a service on 0.0.0.0:8080 as well,
# a warning names 8080 (it is not reachable from outside afterwards), none names
# traefik, docker-proxy or 32768.
t_h_ss() { # SCENARIO none|8080
  local ok=1 a w
  have_run "$1" 1 || return 1
  a=$(art "$1")
  grep -qE '^ss -H?[a-zA-Z]*t' "$a/log1" || no "the script did not ask ss for listening TCP sockets"
  w=$(grep 'WARNUNG:' "$a/err1")
  ! grep -qE 'traefik|docker-proxy|32768' <<<"$w" || no "warning about Traefik or a port Docker publishes:" "$(grep -E 'traefik|docker-proxy|32768' <<<"$w")"
  if [[ $2 == 8080 ]]; then
    grep -q '8080' <<<"$w" || no "no warning about the service on port 8080:" "$w"
  else
    ! grep -q '8080' <<<"$w" || no "fixture: a service on 8080 although none should listen there"
  fi
  return $((1 - ok))
}

# Profile oracle (SCENARIO with the default or PROFIL=oracle) has nothing of the profile
# hostinger: exit 0; no Match block and no 169.254 in the drop-in; no ignoreip in
# jail.local, fail2ban ignores no 169.254 address; daemon.json written as before (log
# limits, no live-restore); Docker installed from the repository as before.
t_oracle_profile() { # SCENARIO
  local ok=1 a f
  have_run "$1" 1 || return 1
  a=$(art "$1")
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)" "$(grep '^Abbruch' "$a/err1")"
  f="$(upper "$1" etc)${SSHD_DROPIN#/etc}"
  [[ -f $f ]] || no "$SSHD_DROPIN missing"
  ! grep -qiE 'match|169\.254' "$f" 2>/dev/null || no "the drop-in has a Match block or 169.254:" "$(cat "$f")"
  ! grep -qi 'ignoreip' "$(upper "$1" etc)/fail2ban/jail.local" 2>/dev/null || no "jail.local sets ignoreip"
  ! grep -q '169\.254' "$a/f2b_dump" || no "fail2ban ignores a 169.254 address:" "$(grep '169\.254' "$a/f2b_dump")"
  t_h_daemon_json "$1" '{"log-driver": "local", "log-opts": {"max-size": "10m", "max-file": "3"}}' || ok=0
  grep -qE '^apt-get .* install .*docker-ce( |$)' "$a/log1" || no "docker-ce not installed"
  return $((1 - ok))
}

# Profile oracle with ADMIN_PUBKEY (KEYFILE) set: exit 0, a warning that names
# ADMIN_PUBKEY, ubuntu's authorized_keys as before (inode, mode, times, content), the key
# not in it.
t_oracle_pubkey_ignored() { # SCENARIO KEYFILE
  local ok=1 a p=/home/ubuntu/.ssh/authorized_keys d
  have_run "$1" 1 || return 1
  a=$(art "$1")
  [[ $(rc_of "$1" 1) == 0 ]] || no "expected exit code 0, got: $(rc_of "$1" 1)" "$(grep '^Abbruch' "$a/err1")"
  grep -qF 'ADMIN_PUBKEY' <<<"$(grep 'WARNUNG:' "$a/err1")" || no "no warning that names ADMIN_PUBKEY:" "$(grep 'WARNUNG' "$a/err1")"
  [[ -n $(snap_path "$1" 0 "$p") ]] || no "fixture: $p not there before the run"
  d=$(diff <(snap_path "$1" 0 "$p") <(snap_path "$1" 1 "$p")) || no "$p changed:" "$d"
  [[ $(h_key_count "$(upper "$1" home)/ubuntu/.ssh/authorized_keys" "$(<"$2")") == 0 ]] || no "the key was added for ubuntu"
  return $((1 - ok))
}

# prepare_ssh_keys DIR: throwaway SSH keys for ADMIN_PUBKEY, made for this run with
# ssh-keygen (no passphrase) and removed with the work directory: ed25519, other (a
# second ed25519), ecdsa256, ecdsa384, ecdsa521, rsa2048, rsa1024 (DIR/NAME and NAME.pub).
prepare_ssh_keys() {
  local dir=$1 spec name type bits
  local -a size
  install -d -m 700 "$dir" || return 1
  for spec in ed25519:ed25519: other:ed25519: ecdsa256:ecdsa:256 ecdsa384:ecdsa:384 ecdsa521:ecdsa:521 \
    rsa2048:rsa:2048 rsa1024:rsa:1024; do
    IFS=: read -r name type bits <<<"$spec"
    size=()
    if [[ -n $bits ]]; then size=(-b "$bits"); fi
    ssh-keygen -q -t "$type" "${size[@]}" -N '' -C "$name@example.invalid" -f "$dir/$name" </dev/null >/dev/null 2>&1 || return 1
    [[ $(ssh-keygen -l -f "$dir/$name.pub" | awk '{ print $1 }') == "${bits:-256}" ]] || return 1
  done
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

# Scenarios of the profile hostinger (PROFIL=hostinger), and the profile oracle next to
# it. H: a Hostinger VPS (hostinger_fixture, hostinger_v4/v6: Docker installed and
# running with docker-ce from Docker's repository, ufw installed and inactive, INPUT open,
# Docker's chains and a DNAT for 32768, root with password), run as root from the web
# console or an SSH login as root (audit login UID 0, no SUDO_USER); nobody else has a
# key. HA: the same with ADMIN_USER=H_ADMIN and ADMIN_PUBKEY=the ed25519 key.
hostinger_scenarios() {
  local k=$WORK/sshkeys ed other dpkg b64
  local -a H HA
  ed=$(<"$k/ed25519.pub")
  other=$(<"$k/other.pub")
  dpkg=$(printf '%s\n' 'docker-ce=install ok installed' 'docker-ce-cli=install ok installed' \
    'containerd.io=install ok installed' 'docker-compose-plugin=install ok installed' 'ufw=install ok installed')
  H=(SC_PROFIL=hostinger SC_HOSTINGER=1 SC_LOGINUID=0 SC_KEY=none SC_HIDE_DOCKER=0
    SC_FW=hostinger SC_V6=hostinger "SC_DPKG=$dpkg" SC_SS=hostinger)
  HA=("${H[@]}" "SC_ADMIN_USER=$H_ADMIN" "SC_ADMIN_PUBKEY=$ed")
  # PROFIL
  scenario profil_unknown SC_PROFIL=hetzner
  scenario profil_case "${HA[@]}" SC_PROFIL=Hostinger
  scenario oracle_explicit SC_PROFIL=oracle
  scenario oracle_pubkey "SC_ADMIN_PUBKEY=$ed"
  # Fresh Hostinger VPS, run twice; dry runs
  scenario h_fresh "${HA[@]}" SC_RUNS=2
  scenario h_dry "${HA[@]}" SC_DRY_RUN=1
  scenario h_dry_nobody "${HA[@]}" SC_DRY_RUN=1 SC_AS=nobody
  scenario h_dry_badkey "${HA[@]}" SC_DRY_RUN=1 "SC_ADMIN_PUBKEY=restrict $ed"
  scenario h_ss_other "${HA[@]}" SC_DRY_RUN=1 SC_SS=other
  # Between the runs fail2ban's chain and the CI key arrive
  scenario h_rerun_real "${HA[@]}" SC_RUNS=2 SC_H_BETWEEN=1
  # Admin user exists already
  scenario h_existing "${HA[@]}" SC_RUNS=2 SC_H_EXISTING=1 \
    "SC_H_OLDKEYS=# keys from before (test fixture)\nfrom=\"192.0.2.0/24\" $other\n"
  scenario h_existing_samekey "${HA[@]}" SC_H_EXISTING=1 SC_H_SSH_MODE=700 SC_H_KEYS_MODE=600 \
    "SC_H_OLDKEYS=$(awk '{ print $1, $2 }' <<<"$ed") same key, other comment\n"
  # Rules saved before (netfilter-persistent save: all tables)
  scenario h_rules_old "${HA[@]}" SC_RUNS=2 SC_RULES_SAVED=1
  # daemon.json from before
  scenario h_dj_merge "${HA[@]}" SC_RUNS=2 \
    'SC_DAEMON_JSON={\n  "dns": ["192.0.2.53"],\n  "log-driver": "json-file",\n  "log-opts": {"max-size": "50m"},\n  "features": {"buildkit": true}\n}'
  scenario h_dj_keep "${HA[@]}" 'SC_DAEMON_JSON={"live-restore": false, "log-driver": "syslog"}'
  scenario h_dj_invalid "${HA[@]}" 'SC_DAEMON_JSON={"log-driver": "local",'
  scenario h_dj_array "${HA[@]}" 'SC_DAEMON_JSON=["live-restore"]'
  # ufw active
  scenario h_ufw_active "${HA[@]}" SC_UFW=active
  # Other allowed key types (real run each)
  scenario h_key_ecdsa256 "${H[@]}" "SC_ADMIN_USER=$H_ADMIN" "SC_ADMIN_PUBKEY=$(<"$k/ecdsa256.pub")"
  scenario h_key_ecdsa384 "${H[@]}" "SC_ADMIN_USER=$H_ADMIN" "SC_ADMIN_PUBKEY=$(<"$k/ecdsa384.pub")"
  scenario h_key_ecdsa521 "${H[@]}" "SC_ADMIN_USER=$H_ADMIN" "SC_ADMIN_PUBKEY=$(<"$k/ecdsa521.pub")"
  scenario h_key_rsa2048 "${H[@]}" "SC_ADMIN_USER=$H_ADMIN" "SC_ADMIN_PUBKEY=$(<"$k/rsa2048.pub")"
  # ADMIN_USER
  scenario h_pre_noadmin "${H[@]}" "SC_ADMIN_PUBKEY=$ed"
  scenario h_pre_admin_bad "${H[@]}" "SC_ADMIN_PUBKEY=$ed" "SC_ADMIN_USER=Bad.User"
  scenario h_pre_admin_long "${H[@]}" "SC_ADMIN_PUBKEY=$ed" "SC_ADMIN_USER=$(printf 'a%.0s' {1..33})"
  scenario h_pre_admin_root "${H[@]}" "SC_ADMIN_PUBKEY=$ed" SC_ADMIN_USER=root
  scenario h_pre_admin_deploy "${H[@]}" "SC_ADMIN_PUBKEY=$ed" SC_ADMIN_USER=deploy
  scenario h_pre_admin_sys "${H[@]}" "SC_ADMIN_PUBKEY=$ed" "SC_ADMIN_USER=$H_SYSUSER"
  scenario h_pre_admin_nologin "${H[@]}" "SC_ADMIN_PUBKEY=$ed" "SC_ADMIN_USER=$H_NOLOGIN"
  scenario h_pre_admin_group "${H[@]}" "SC_ADMIN_PUBKEY=$ed" "SC_ADMIN_USER=$H_GROUP"
  # ADMIN_PUBKEY
  scenario h_pre_nokey "${H[@]}" "SC_ADMIN_USER=$H_ADMIN"
  scenario h_pre_key_blank "${H[@]}" "SC_ADMIN_USER=$H_ADMIN" "SC_ADMIN_PUBKEY=   "
  scenario h_pre_key_private "${H[@]}" "SC_ADMIN_USER=$H_ADMIN" "SC_ADMIN_PUBKEY=$(<"$k/ed25519")"
  scenario h_pre_key_twolines "${H[@]}" "SC_ADMIN_USER=$H_ADMIN" "SC_ADMIN_PUBKEY=$ed"$'\n'"$other"
  scenario h_pre_key_restrict "${H[@]}" "SC_ADMIN_USER=$H_ADMIN" "SC_ADMIN_PUBKEY=restrict $ed"
  scenario h_pre_key_command "${H[@]}" "SC_ADMIN_USER=$H_ADMIN" "SC_ADMIN_PUBKEY=command=\"/usr/bin/id\" $ed"
  scenario h_pre_key_from "${H[@]}" "SC_ADMIN_USER=$H_ADMIN" "SC_ADMIN_PUBKEY=from=\"192.0.2.0/24\" $ed"
  scenario h_pre_key_b64 "${H[@]}" "SC_ADMIN_USER=$H_ADMIN" "SC_ADMIN_PUBKEY=ssh-ed25519 AAAA!!!!not*base64 x@example.invalid"
  b64=$(printf 'not a key at all, only base64 text' | base64 -w0)
  scenario h_pre_key_notkey "${H[@]}" "SC_ADMIN_USER=$H_ADMIN" "SC_ADMIN_PUBKEY=ssh-ed25519 $b64 x@example.invalid"
  scenario h_pre_key_typemix "${H[@]}" "SC_ADMIN_USER=$H_ADMIN" "SC_ADMIN_PUBKEY=ssh-rsa $(awk '{ print $2 }' <<<"$ed") x@example.invalid"
  scenario h_pre_key_curve "${H[@]}" "SC_ADMIN_USER=$H_ADMIN" \
    "SC_ADMIN_PUBKEY=ecdsa-sha2-nistp256 $(awk '{ print $2 }' "$k/ecdsa384.pub") x@example.invalid"
  scenario h_pre_key_rsa1024 "${H[@]}" "SC_ADMIN_USER=$H_ADMIN" "SC_ADMIN_PUBKEY=$(<"$k/rsa1024.pub")"
  b64=$(printf '\x00\x00\x00\x07ssh-dss' | base64 -w0)
  scenario h_pre_key_dss "${H[@]}" "SC_ADMIN_USER=$H_ADMIN" "SC_ADMIN_PUBKEY=ssh-dss $b64 x@example.invalid"
  b64=$(printf '\x00\x00\x00\x1ask-ssh-ed25519@openssh.com' | base64 -w0)
  scenario h_pre_key_sk "${H[@]}" "SC_ADMIN_USER=$H_ADMIN" "SC_ADMIN_PUBKEY=sk-ssh-ed25519@openssh.com $b64 x@example.invalid"
  # Who runs it
  scenario h_pre_nonroot "${HA[@]}" SC_AS=nobody
  scenario h_pre_sudo_other "${HA[@]}" SC_SUDO_USER=ubuntu
  # sshd settings from before that conflict with the profile
  scenario h_ssh_early_root "${HA[@]}" "SC_SSHD_EARLY=PermitRootLogin yes"
  scenario h_ssh_match_addr "${HA[@]}" "SC_SSHD_EARLY=Match Address $H_CONSOLE\n    PasswordAuthentication yes"
  scenario h_ssh_match_root "${HA[@]}" "SC_SSHD_EARLY=Match User root Address $H_CONSOLE\n    PasswordAuthentication no"
  scenario h_ssh_usepam "${HA[@]}" "SC_SSHD_EARLY=UsePAM no"
  scenario h_ssh_late_allowroot "${HA[@]}" "SC_SSHD_LATE=AllowUsers root"
  # fail2ban: a foreign file exempts more addresses
  scenario h_f2b_ignoreip "${HA[@]}" "SC_F2B_JAIL_D=[sshd]\nignoreip = $H_IGNOREIP 0.0.0.0/0"
}

hostinger_checks() {
  local k=$WORK/sshkeys s ed fresh_want merge_want
  local -a parts ed_parts other_parts rsa1024_parts
  ed=$(<"$k/ed25519.pub")
  mapfile -t ed_parts < <(h_key_parts "$k/ed25519.pub")
  mapfile -t other_parts < <(h_key_parts "$k/other.pub")
  mapfile -t rsa1024_parts < <(h_key_parts "$k/rsa1024.pub")
  fresh_want='{"log-driver": "local", "log-opts": {"max-size": "10m", "max-file": "3"}, "live-restore": true}'
  merge_want='{"dns": ["192.0.2.53"], "log-driver": "json-file", "log-opts": {"max-size": "50m", "max-file": "3"}, "features": {"buildkit": true}, "live-restore": true}'

  check "PROFIL=hetzner (unknown): abort before any change, naming PROFIL" t_aborts_because profil_unknown 'PROFIL'
  check "PROFIL=Hostinger (wrong case, unknown): abort before any change" t_aborts_because profil_case 'PROFIL'
  check "PROFIL=oracle explicit: as the default (AllowUsers ubuntu deploy, sshd -T)" t_sshd_effective oracle_explicit ubuntu
  check "profile oracle (PROFIL=oracle): no console exception, no ignoreip, daemon.json as before, Docker from the repository" \
    t_oracle_profile oracle_explicit
  check "profile oracle (default): no console exception, no ignoreip, daemon.json as before, Docker from the repository" \
    t_oracle_profile fresh
  check "profile oracle with ADMIN_PUBKEY set: warning, key not installed, ubuntu's authorized_keys unchanged" \
    t_oracle_pubkey_ignored oracle_pubkey "$k/ed25519.pub"

  check "hostinger: run 2 exits 0, 0 changes, no file or firewall rule changed, no modifying command" t_h_rerun h_fresh
  check "hostinger: admin user created (home /home/$H_ADMIN, bash, group sudo), ~/.ssh 700 and authorized_keys 600 owned by it, key once, no NOPASSWD, created before ssh reload" \
    t_h_admin_created h_fresh "$ed"
  check "hostinger: SSH from the internet: admin and deploy only with key, root denied; from $H_CONSOLE: root with password, admin and deploy still only key; AllowUsers $H_ADMIN deploy root@$H_CONSOLE; overrides 50-cloud-init and 60-cloudimg-settings" \
    t_h_sshd h_fresh
  check "hostinger: fail2ban values as in profile oracle (fail2ban-client -d)" t_f2b_effective h_fresh 2
  check "hostinger: fail2ban ignoreip exactly $H_IGNOREIP" t_h_f2b_ignoreip h_fresh
  check "hostinger firewall IPv4 on empty INPUT: lo, RELATED/ESTABLISHED, ICMP, DHCP client, tcp 22/80/443 in this order, REJECT last, policy ACCEPT" \
    t_h_fw_input h_fresh v4 1
  check "hostinger firewall IPv6 on empty INPUT: lo, RELATED/ESTABLISHED, ICMPv6, DHCPv6 client (link-local), tcp 22/80/443 in this order, REJECT last, policy ACCEPT" \
    t_h_fw_input h_fresh v6 1
  check "hostinger firewall IPv4 after run 2: no duplicates, same order" t_h_fw_input h_fresh v4 2
  check "hostinger firewall IPv6 after run 2: no duplicates, same order" t_h_fw_input h_fresh v6 2
  check "hostinger firewall: nat (DNAT 32768) byte for byte, FORWARD and DOCKER* chains untouched after two runs (IPv4 and IPv6)" \
    t_h_fw_others_untouched h_fresh 2
  check "hostinger firewall: rules.v4/v6 only table filter with the INPUT rules in effect, 640, restore --test passes; restore only with --test" \
    t_h_rules_files h_fresh 1
  check "hostinger firewall: no rules file before: no backup" t_h_no_backup h_fresh /etc/iptables/rules.v4
  check "hostinger: daemon.json created with live-restore true and log-driver local 10m x 3, dockerd --validate passes" \
    t_h_daemon_json h_fresh "$fresh_want"
  check "hostinger: no daemon.json before: no backup" t_h_no_backup h_fresh /etc/docker/daemon.json
  check "hostinger: Docker reloaded once before apt-get full-upgrade, never restarted, not reinstalled; not reloaded in run 2" \
    t_h_docker_calls h_fresh 1
  check "hostinger: ufw inactive: clear note that it goes and the iptables rules take over, run goes on" t_h_ufw_note h_fresh
  check "hostinger: listening Traefik (80/443) and docker-proxy (32768): no warning about them" t_h_ss h_fresh none
  check "hostinger: service on 0.0.0.0:8080: warning that names it" t_h_ss h_ss_other 8080
  check "hostinger: ADMIN_PUBKEY not printed in runs 1 and 2" t_h_key_hidden h_fresh "${ed_parts[@]}"
  check "hostinger: fingerprint of ADMIN_PUBKEY shown" t_h_key_fpr_shown h_fresh "$k/ed25519.pub"

  check "hostinger dry run: exit 0, nothing changed, shows admin user, sudo, REJECT for IPv4 and IPv6, console exception, ignoreip, live-restore, reload of docker" \
    t_h_dry h_dry "useradd .*$H_ADMIN" "usermod .*sudo.* $H_ADMIN" 'iptables -A INPUT .*-j REJECT' 'ip6tables -A INPUT .*-j REJECT' \
    "Match User root Address 169\.254\.0\.1" "AllowUsers $H_ADMIN deploy root@169\.254\.0\.1" \
    'ignoreip = 127\.0\.0\.1/8 ::1 169\.254\.0\.1' '"live-restore": true' 'systemctl reload docker'
  check "hostinger dry run: ADMIN_PUBKEY not printed" t_h_key_hidden h_dry "${ed_parts[@]}"
  check "hostinger dry run as non-root: nothing changed, says a real run would abort" t_dry_would_abort h_dry_nobody 'root'
  check "hostinger dry run with option in front of the key: nothing changed, says a real run would abort naming ADMIN_PUBKEY" \
    t_dry_would_abort h_dry_badkey 'ADMIN_PUBKEY'

  check "hostinger, second run on a used server (fail2ban chain at the top of INPUT, CI key): 0 changes, nothing changed" \
    t_h_rerun h_rerun_real
  check "hostinger, second run on a used server: IPv4 INPUT keeps fail2ban's jump on top, no duplicates" t_h_fw_input h_rerun_real v4 2 f2b
  check "hostinger, second run on a used server: IPv6 INPUT keeps fail2ban's jump on top, no duplicates" t_h_fw_input h_rerun_real v6 2 f2b
  check "hostinger, second run on a used server: rules files without fail2ban's jump" t_h_rules_files h_rerun_real 2

  check "hostinger: existing admin user with other keys: not recreated, put in sudo, 700/600 fixed, old keys kept, key added once, no NOPASSWD" \
    t_h_admin_existing h_existing "$ed"
  check "hostinger: existing admin user: run 2 changes nothing" t_h_rerun h_existing
  check "hostinger: key already there with another comment: authorized_keys untouched" t_h_key_kept h_existing_samekey

  check "hostinger: earlier rules.v4 (all tables) replaced, timestamped backup with the old content" \
    t_h_backup h_rules_old /etc/iptables/rules.v4 "$WORK/h_rules_old/rules.v4.orig"
  check "hostinger: earlier rules.v6 (all tables) replaced, timestamped backup with the old content" \
    t_h_backup h_rules_old /etc/iptables/rules.v6 "$WORK/h_rules_old/rules.v6.orig"
  check "hostinger: earlier rules files: new ones only table filter with the INPUT rules" t_h_rules_files h_rules_old 1
  check "hostinger: earlier rules files: run 2 changes nothing (no second backup)" t_h_rerun h_rules_old

  check "hostinger: daemon.json with other keys merged (dns, json-file, max-size 50m, features kept; max-file 3, live-restore true added), dockerd --validate passes" \
    t_h_daemon_json h_dj_merge "$merge_want"
  check "hostinger: daemon.json merged: timestamped backup with the old content" \
    t_h_backup h_dj_merge /etc/docker/daemon.json "$WORK/h_dj_merge/daemon.json.orig"
  check "hostinger: daemon.json merged: reloaded once in run 1, never restarted; run 2 changes nothing" t_h_docker_calls h_dj_merge 1
  check "hostinger: daemon.json merged: run 2 changes nothing" t_h_rerun h_dj_merge
  check "hostinger: live-restore false and log-driver syslog kept with warnings, file untouched, no reload, no backup" t_h_dj_keep h_dj_keep
  check "hostinger: invalid daemon.json: abort before any change, naming daemon.json" t_aborts_because h_dj_invalid 'daemon\.json'
  check "hostinger: daemon.json not an object: abort before any change, naming daemon.json" t_aborts_because h_dj_array 'daemon\.json'
  check "hostinger: Docker never restarted, stopped or started in any scenario of the profile" t_h_docker_never_restarted

  check "hostinger: UFW active: abort before any change" t_aborts_because h_ufw_active '^Abbruch.*(UFW|ufw)'

  for s in ecdsa256 ecdsa384 ecdsa521 rsa2048; do
    check "hostinger: ADMIN_PUBKEY of type $s accepted and installed" t_h_admin_created "h_key_$s" "$(<"$k/$s.pub")"
  done

  check "hostinger: ADMIN_USER missing (no default): abort before any change, naming ADMIN_USER" t_aborts_because h_pre_noadmin 'ADMIN_USER'
  check "hostinger: ADMIN_USER Bad.User (invalid name): abort before any change" t_aborts_because h_pre_admin_bad 'ADMIN_USER'
  check "hostinger: ADMIN_USER with 33 characters: abort before any change" t_aborts_because h_pre_admin_long 'ADMIN_USER'
  check "hostinger: ADMIN_USER=root: abort before any change" t_aborts_because h_pre_admin_root 'root'
  check "hostinger: ADMIN_USER=deploy: abort before any change" t_aborts_because h_pre_admin_deploy 'deploy'
  check "hostinger: ADMIN_USER is a system user: abort before any change, naming it" t_aborts_because h_pre_admin_sys "$H_SYSUSER"
  check "hostinger: ADMIN_USER exists with shell nologin: abort before any change, naming it" t_aborts_because h_pre_admin_nologin "$H_NOLOGIN"
  check "hostinger: only a group of that name exists: abort before any change, naming it" t_aborts_because h_pre_admin_group "$H_GROUP"

  check "hostinger: ADMIN_PUBKEY missing: abort before any change, naming ADMIN_PUBKEY" t_aborts_because h_pre_nokey 'ADMIN_PUBKEY'
  check "hostinger: ADMIN_PUBKEY only blanks: abort before any change" t_aborts_because h_pre_key_blank 'ADMIN_PUBKEY'
  for s in private twolines restrict command from b64 notkey typemix curve rsa1024 dss sk; do
    check "hostinger: ADMIN_PUBKEY rejected ($s): abort before any change, naming ADMIN_PUBKEY" t_aborts_because "h_pre_key_$s" 'ADMIN_PUBKEY'
  done
  mapfile -t parts < <(h_key_parts "$k/ed25519")
  check "hostinger: private key passed: not printed" t_h_key_hidden h_pre_key_private "${parts[@]}"
  for s in twolines restrict command from typemix; do
    check "hostinger: rejected ADMIN_PUBKEY ($s) not printed" t_h_key_hidden "h_pre_key_$s" "${ed_parts[@]}"
  done
  check "hostinger: rejected ADMIN_PUBKEY (second line of twolines) not printed" t_h_key_hidden h_pre_key_twolines "${other_parts[@]}"
  check "hostinger: rejected RSA-1024 key not printed" t_h_key_hidden h_pre_key_rsa1024 "${rsa1024_parts[@]}"

  check "hostinger: not root: abort before any change" t_aborts_because h_pre_nonroot 'root'
  check "hostinger: run with sudo by ubuntu (not ADMIN_USER): abort before any change, naming ubuntu" t_aborts_because h_pre_sudo_other "'ubuntu'"

  check "hostinger SSH: earlier PermitRootLogin yes: abort, drop-in rolled back, no reload, sshd valid" \
    t_h_sshd_rollback h_ssh_early_root 'permitrootlogin' sshd_T 'permitrootlogin yes'
  check "hostinger SSH: earlier Match Address $H_CONSOLE with PasswordAuthentication yes: abort, drop-in rolled back" \
    t_h_sshd_rollback h_ssh_match_addr 'passwordauthentication' sshdT_admin_con 'passwordauthentication yes'
  check "hostinger SSH: earlier Match User root Address $H_CONSOLE with PasswordAuthentication no: abort, drop-in rolled back" \
    t_h_sshd_rollback h_ssh_match_root 'passwordauthentication' sshdT_root_con 'passwordauthentication no'
  check "hostinger SSH: UsePAM no: abort, drop-in rolled back" t_h_sshd_rollback h_ssh_usepam 'usepam' sshd_T 'usepam no'
  check "hostinger SSH: AllowUsers root in a later drop-in: abort, drop-in rolled back" \
    t_h_sshd_rollback h_ssh_late_allowroot 'allowusers' sshd_T 'allowusers root'

  check "hostinger fail2ban: foreign jail.d/zz.local adds 0.0.0.0/0 to ignoreip: abort naming the file, fail2ban not restarted" \
    t_f2b_foreign_abort h_f2b_ignoreip 1 /etc/fail2ban/jail.d/zz.local \
    "['set', 'sshd', 'addignoreip', '127.0.0.1/8', '::1', '169.254.0.1', '0.0.0.0/0']"
}

main() {
  local missing=() c
  if [[ $EUID -ne 0 ]]; then
    echo "CANNOT RUN: needs root (sandbox with unshare, overlayfs and network namespace)."
    exit 2
  fi
  for c in unshare setpriv iptables ip6tables iptables-save ip6tables-save iptables-restore \
    ip6tables-restore /usr/sbin/sshd fail2ban-client apt-config shellcheck python3 diff \
    gpg gpgconf /usr/sbin/useradd /usr/sbin/groupadd /usr/sbin/groupdel mount readlink cmp ssh-keygen; do
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
  for c in "$H_ADMIN" "$H_SYSUSER" "$H_NOLOGIN" "$H_GROUP"; do
    if getent passwd "$c" >/dev/null || getent group "$c" >/dev/null; then
      echo "CANNOT RUN: user or group $c exists on this host (the fixtures of the profile hostinger create it)"
      exit 2
    fi
  done
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
  # The runs get a defined audit login UID (run_setup); the result must not depend on
  # the session the tests are started from. Every value the scenarios use must be
  # settable from here.
  if ! CALLER_LOGINUID=$(loginuid_now); then
    echo "CANNOT RUN: /proc/self/loginuid not readable (kernel without audit login UID); the runs cannot get a defined login UID"
    exit 2
  fi
  if getent passwd "$LOGINUID_NOUSER" >/dev/null; then
    echo "CANNOT RUN: UID $LOGINUID_NOUSER has a user on this host (the fixtures use it as a UID without a user)"
    exit 2
  fi
  for c in "$LOGINUID_UNSET" 0 "$(id -u ubuntu)" "$(id -u claude)" "$LOGINUID_NOUSER"; do
    if ! (set_loginuid "$c") 2>/dev/null; then
      echo "CANNOT RUN: the audit login UID of this session ($CALLER_LOGINUID, /proc/self/loginuid) cannot be changed to $c for the runs (the kernel refuses: loginuid immutable, or no CAP_AUDIT_CONTROL). The script compares it with ADMIN_USER, so the results would depend on the session. Start the tests from a session without a login UID or with permission to change it."
      exit 2
    fi
  done

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
  if ! prepare_ssh_keys "$WORK/sshkeys"; then
    echo "CANNOT RUN: SSH test keys could not be made (ssh-keygen)"
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
  # 00-auth-log needs logrotate (package and program) as well, so the rsyslog
  # scenarios have it.
  scenario rsyslog "SC_DPKG=$(printf '%s\n' 'rsyslog=install ok installed' 'logrotate=install ok installed')" \
    SC_LOGROTATE_BIN=1 SC_LOGROTATE_RSYSLOG=1 SC_RUNS=2
  scenario rsyslog_removed "SC_DPKG=$(printf '%s\n' 'rsyslog=deinstall ok config-files' 'logrotate=install ok installed')" \
    SC_LOGROTATE_BIN=1 SC_LOGROTATE_RSYSLOG=1
  scenario rsyslog_hold "SC_DPKG=$(printf '%s\n' 'rsyslog=hold ok installed' 'logrotate=install ok installed')" \
    SC_LOGROTATE_BIN=1 SC_LOGROTATE_RSYSLOG=1 SC_RUNS=2
  scenario dry_rsyslog SC_DRY_RUN=1 "SC_DPKG=$(printf '%s\n' 'rsyslog=install ok installed' 'logrotate=install ok installed')" \
    SC_LOGROTATE_BIN=1 SC_LOGROTATE_RSYSLOG=1
  scenario journald_old SC_JOURNALD_OLD=1
  scenario lr "SC_DPKG=logrotate=install ok installed" SC_LOGROTATE_BIN=1 SC_LOGROTATE_PKG=1 SC_RUNS=2
  scenario lr_rsyslog "SC_DPKG=$(printf '%s\n' 'rsyslog=install ok installed' 'logrotate=hold ok installed')" \
    SC_LOGROTATE_BIN=1 SC_LOGROTATE_PKG=1 SC_LOGROTATE_RSYSLOG=1
  scenario lr_removed "SC_DPKG=logrotate=deinstall ok config-files" SC_LOGROTATE_PKG=1
  scenario dry_lr SC_DRY_RUN=1 "SC_DPKG=logrotate=install ok installed" SC_LOGROTATE_BIN=1 SC_LOGROTATE_PKG=1
  # Only half of logrotate: package without program, program without package.
  scenario lr_nobin "SC_DPKG=$(printf '%s\n' 'rsyslog=install ok installed' 'logrotate=install ok installed')" \
    SC_LOGROTATE_PKG=1 SC_LOGROTATE_RSYSLOG=1
  scenario lr_binonly "SC_DPKG=rsyslog=install ok installed" SC_LOGROTATE_BIN=1 SC_LOGROTATE_RSYSLOG=1
  # fail2ban values of the privacy policy
  scenario f2b_defaults SC_F2B_DEFAULTS=1
  scenario f2b_edit_local SC_RUNS=2 SC_F2B_EDIT=local
  scenario f2b_edit_jail SC_RUNS=2 SC_F2B_EDIT=jail
  # Foreign jail.d/*.local and fail2ban.d/*.local that override them, or not.
  scenario f2b_jail_bantime 'SC_F2B_JAIL_D=[sshd]\nbantime = 1h'
  scenario f2b_jail_increment 'SC_F2B_JAIL_D=[DEFAULT]\nbantime.increment = true'
  scenario f2b_main_dbpurgeage 'SC_F2B_MAIN_D=[Definition]\ndbpurgeage = 30d'
  scenario f2b_jail_findtime 'SC_F2B_JAIL_D=[sshd]\nfindtime = 1h'
  scenario f2b_main_logtarget 'SC_F2B_MAIN_D=[Definition]\nlogtarget = /var/log/fail2ban.log'
  scenario f2b_rerun_maxretry SC_RUNS=2 SC_F2B_FOREIGN_AT=between 'SC_F2B_JAIL_D=[sshd]\nmaxretry = 3'
  scenario f2b_equiv SC_RUNS=2 \
    'SC_F2B_JAIL_D=[DEFAULT]\nbantime.increment = false\n\n[sshd]\nbantime = 600\nfindtime = 10 minutes\nmaxretry = 5' \
    'SC_F2B_MAIN_D=[Definition]\ndbpurgeage = 24h'
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
  # Rules that keep out deploy (on a fresh server it will be in the groups deploy and
  # docker), but not ubuntu.
  scenario ssh_deploy_denyusers "SC_SSHD_LATE=DenyUsers deploy"
  scenario ssh_deploy_allowgroups SC_GROUPS=sshlogin:ubuntu "SC_SSHD_LATE=AllowGroups sshlogin"
  scenario ssh_deploy_denygroups "SC_SSHD_LATE=DenyGroups docker"
  scenario ssh_deploy_docker_ok SC_GROUPS=sshlogin:ubuntu "SC_SSHD_LATE=AllowGroups sshlogin docker"
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
  # Login with a key alone (checks before any change; check after the drop-in)
  scenario auth_pubkey_no "SC_SSHD_EARLY=PubkeyAuthentication no"
  scenario auth_pubkey_match "SC_SSHD_MATCH=PubkeyAuthentication no"
  scenario auth_methods_pw "SC_SSHD_EARLY=AuthenticationMethods publickey,password"
  scenario auth_methods_match_kbd "SC_SSHD_MATCH=AuthenticationMethods publickey,keyboard-interactive"
  scenario auth_methods_alt "SC_SSHD_EARLY=AuthenticationMethods publickey,password publickey"
  scenario dry_auth_pubkey_no SC_DRY_RUN=1 "SC_SSHD_EARLY=PubkeyAuthentication no"
  scenario auth_after_apt "SC_APT_SSHD_MATCH=PubkeyAuthentication no"
  # sshd checks on every run: the configuration changes elsewhere between run 1 and run 2
  scenario rerun_denyusers SC_RUNS=2 "SC_BETWEEN_SSHD_LATE=DenyUsers ubuntu"
  scenario rerun_match_pw SC_RUNS=2 "SC_BETWEEN_SSHD_MATCH=PasswordAuthentication yes"
  # Audit login UID of the session
  scenario loginuid_other SC_LOGINUID=claude
  scenario loginuid_other_sudo_root SC_LOGINUID=claude SC_SUDO_USER=root
  scenario loginuid_other_sudo_admin SC_LOGINUID=claude SC_SUDO_USER=ubuntu
  scenario loginuid_nouser "SC_LOGINUID=$LOGINUID_NOUSER"
  scenario loginuid_admin SC_LOGINUID=ubuntu
  scenario loginuid_root SC_LOGINUID=0
  scenario loginuid_unset "SC_LOGINUID=$LOGINUID_UNSET"
  scenario loginuid_alt_admin SC_LOGINUID=claude SC_ADMIN_USER=claude SC_KEY_USER=claude
  scenario loginuid_alt_other SC_LOGINUID=ubuntu SC_ADMIN_USER=claude SC_KEY_USER=claude
  scenario dry_loginuid_other SC_DRY_RUN=1 SC_LOGINUID=claude
  # Firewall changed by the package installation; final DROP; nothing that filters
  scenario fw_apt_flush_v4 SC_APT_FW=flush_v4 SC_RULES_SAVED=1 SC_NAT=1
  scenario fw_apt_flush_v6 SC_APT_FW=flush_v6 SC_RULES_SAVED=1 SC_NAT=1
  scenario fw_apt_policy_v4 SC_FW=drop_policy SC_V6=drop_policy SC_APT_FW=policy_v4 SC_NAT=1
  scenario fw_apt_policy_v6 SC_FW=drop_policy SC_V6=drop_policy SC_APT_FW=policy_v6 SC_NAT=1
  scenario fw_apt_del_drop SC_FW=drop_rule SC_V6=drop_rule SC_APT_FW=del_final_v4 SC_NAT=1
  scenario fw_apt_flush_comment SC_FW=oracle_comment SC_APT_FW=flush_v4 SC_NAT=1
  # ... and putting back the copy does not help, or there is none
  scenario fw_apt_restore_fail SC_APT_FW=flush_v4 SC_RULES_SAVED=1 SC_RESTORE=fail
  scenario fw_apt_restore_noop SC_APT_FW=flush_v6 SC_RULES_SAVED=1 SC_RESTORE=noop
  scenario fw_apt_nosave SC_APT_FW=flush_v4 SC_RULES_SAVED=1 SC_IPT_SAVE=fail
  scenario fw_apt_save_empty SC_FW=drop_policy SC_V6=drop_policy SC_APT_FW=policy_v4 SC_IPT_SAVE=empty
  scenario fw_nosave_ok SC_IPT_SAVE=fail
  scenario fw_apt_unreadable SC_APT_FW=unreadable_v4 SC_RULES_SAVED=1
  # ... and a nat rule added in the same apt run
  scenario fw_apt_nat SC_APT_FW=flush_v4_nat SC_NAT=1
  scenario fw_comment SC_FW=oracle_comment
  scenario fw_open SC_FW=open SC_V6=open
  scenario fw_drop_rule SC_FW=drop_rule SC_V6=drop_rule SC_RUNS=2
  scenario fw_cond_drop SC_FW=cond_drop SC_V6=none
  # Other fail2ban jails
  scenario f2b_recidive 'SC_F2B_JAIL_D=[recidive]\nenabled = true'
  scenario f2b_recidive_off 'SC_F2B_JAIL_D=[recidive]\nenabled = false'
  scenario dry_f2b_recidive SC_DRY_RUN=1 'SC_F2B_JAIL_D=[recidive]\nenabled = true'
  # GSSAPIAuthentication and HostbasedAuthentication that do not take effect
  scenario ssh_early_gssapi "SC_SSHD_EARLY=GSSAPIAuthentication yes"
  scenario ssh_early_hostbased "SC_SSHD_EARLY=HostbasedAuthentication yes"
  scenario ssh_match_gssapi "SC_SSHD_MATCH=GSSAPIAuthentication yes"
  scenario ssh_match_hostbased "SC_SSHD_MATCH=HostbasedAuthentication yes"
  # deploy cannot log in with a key alone (Match User deploy)
  scenario ssh_deploy_match_pubkey "SC_SSHD_MATCH_DEPLOY=PubkeyAuthentication no"
  scenario ssh_deploy_match_methods "SC_SSHD_MATCH_DEPLOY=AuthenticationMethods publickey,password"
  # Run 2 with the drop-in unchanged: /run/sshd cannot be created, sshd -t fails
  scenario rerun_rundir SC_RUNS=2 SC_APT_RUNDIR_RUN=2
  scenario rerun_sshd_t_fail SC_RUNS=2 SC_SSHD_T_FAIL_RUN=2
  # deploy with a home directory other than /home/deploy
  scenario deploy_home SC_DEPLOY_HOME=/srv/deployhome SC_RUNS=2
  scenario dry_deploy_home SC_DRY_RUN=1 SC_DEPLOY_HOME=/srv/deployhome
  # The sandbox itself
  hostinger_scenarios
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
  check "firewall: no rule deleted, replaced or flushed in any scenario; ip(6)tables-restore only after the package installation changed INPUT of that family, once, from the copy saved with -t filter in the same run (call logs and dry-run output)" t_fw_never_deletes

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
  check "log retention: rsyslog removed, conffiles left (deinstall ok config-files), logrotate installed: no 00-auth-log, logrotate.d/rsyslog unchanged" \
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
  check "log retention: logrotate installed, rsyslog not installed: no 00-auth-log" t_no_auth_logrotate lr
  check "log retention: package logrotate installed, program missing (rsyslog installed): no 00-auth-log, 00-login-logs, 00-fail2ban-log; warning that the program is missing" \
    t_lr_half lr_nobin none 'Programm' 'nicht installiert'
  check "log retention: program logrotate there, package not installed (rsyslog installed): no 00-auth-log, 00-login-logs, 00-fail2ban-log; warning that the package is missing" \
    t_lr_half lr_binonly present 'nicht installiert' 'Programm[^.]*fehlt'

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
  check "fail2ban: foreign jail.d/zz.local with [sshd] bantime = 1h: abort naming the file, fail2ban neither restarted nor started, foreign file unchanged" \
    t_f2b_foreign_abort f2b_jail_bantime 1 /etc/fail2ban/jail.d/zz.local "['set', 'sshd', 'bantime', '1h']"
  check "fail2ban: foreign jail.d/zz.local with [DEFAULT] bantime.increment = true: abort naming the file, fail2ban neither restarted nor started, foreign file unchanged" \
    t_f2b_foreign_abort f2b_jail_increment 1 /etc/fail2ban/jail.d/zz.local "['set', 'sshd', 'bantime.increment', True]"
  check "fail2ban: foreign fail2ban.d/zz.local with dbpurgeage = 30d: abort naming the file, fail2ban neither restarted nor started, foreign file unchanged" \
    t_f2b_foreign_abort f2b_main_dbpurgeage 1 /etc/fail2ban/fail2ban.d/zz.local "['set', 'dbpurgeage', '30d']"
  check "fail2ban: foreign jail.d/zz.local with [sshd] findtime = 1h: abort naming the file, fail2ban neither restarted nor started, foreign file unchanged" \
    t_f2b_foreign_abort f2b_jail_findtime 1 /etc/fail2ban/jail.d/zz.local "['set', 'sshd', 'findtime', '1h']"
  check "fail2ban: foreign fail2ban.d/zz.local with logtarget = /var/log/fail2ban.log: abort naming the file, fail2ban neither restarted nor started, foreign file unchanged" \
    t_f2b_foreign_abort f2b_main_logtarget 1 /etc/fail2ban/fail2ban.d/zz.local "['set', 'logtarget', '/var/log/fail2ban.log']"
  check "fail2ban: foreign jail.d/zz.local with [sshd] maxretry = 3 added before run 2 (own files unchanged): run 2 aborts naming the file, no restart or start, foreign file unchanged" \
    t_f2b_foreign_abort f2b_rerun_maxretry 2 /etc/fail2ban/jail.d/zz.local "['set', 'sshd', 'maxretry', 3]"
  check "fail2ban: foreign files with equivalent values (bantime 600, findtime 10 minutes, maxretry 5, dbpurgeage 24h, bantime.increment false): no abort, restarted once in run 1, files unchanged" \
    t_f2b_equiv f2b_equiv "['set', 'sshd', 'bantime', '600']" "['set', 'sshd', 'findtime', '10 minutes']" \
    "['set', 'dbpurgeage', '24h']" "['set', 'sshd', 'bantime.increment', False]"

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
  check "SSH: DenyUsers deploy (ubuntu not affected): warning naming deploy and DenyUsers, no abort, ssh reloaded, the run goes on" \
    t_sshd_deploy_warns ssh_deploy_denyusers 'DenyUsers' "denyusers deploy"
  check "SSH: AllowGroups sshlogin, ubuntu a member, deploy (groups deploy, docker) not: warning naming deploy and AllowGroups, no abort, ssh reloaded, the run goes on" \
    t_sshd_deploy_warns ssh_deploy_allowgroups 'AllowGroups' "allowgroups sshlogin"
  check "SSH: DenyGroups docker (deploy will be in docker, ubuntu is not): warning naming deploy and DenyGroups, no abort, ssh reloaded, the run goes on" \
    t_sshd_deploy_warns ssh_deploy_denygroups 'DenyGroups' "denygroups docker"
  check "SSH: AllowGroups sshlogin docker (ubuntu in sshlogin, deploy will be in docker): ssh reloaded" \
    t_sshd_accepts ssh_deploy_docker_ok "allowgroups sshlogin" "allowgroups docker"
  check "SSH: AllowGroups sshlogin docker: no warning about deploy" t_no_warning ssh_deploy_docker_ok '(^|[^[:alnum:]_])deploy([^[:alnum:]_]|$)'
  check "SSH: fresh server without user or group rules: no warning about deploy" t_no_warning fresh '(^|[^[:alnum:]_])deploy([^[:alnum:]_]|$)'

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

  check "key login: PubkeyAuthentication no (earlier drop-in): checks abort before any change, naming PubkeyAuthentication" \
    t_auth_precheck_abort auth_pubkey_no 'PubkeyAuthentication' global 'pubkeyauthentication no'
  check "key login: Match User ubuntu with PubkeyAuthentication no (only sshd -T -C sees it): checks abort before any change" \
    t_auth_precheck_abort auth_pubkey_match 'PubkeyAuthentication' admin 'pubkeyauthentication no'
  check "key login: AuthenticationMethods publickey,password: checks abort before any change, naming AuthenticationMethods" \
    t_auth_precheck_abort auth_methods_pw 'AuthenticationMethods' global 'authenticationmethods publickey,password'
  check "key login: Match User ubuntu with AuthenticationMethods publickey,keyboard-interactive: checks abort before any change" \
    t_auth_precheck_abort auth_methods_match_kbd 'AuthenticationMethods' admin 'authenticationmethods publickey,keyboard-interactive'
  check "key login: AuthenticationMethods publickey,password publickey (second list: key alone): runs, ssh reloaded" \
    t_sshd_accepts auth_methods_alt 'authenticationmethods publickey,password publickey'
  check "key login: dry run with PubkeyAuthentication no: nothing changed, says a real run would abort" \
    t_dry_would_abort dry_auth_pubkey_no 'PubkeyAuthentication'
  check "key login: package update in step 1 adds PubkeyAuthentication no for ubuntu: check after the drop-in aborts, drop-in removed, no reload" \
    t_auth_after_packages auth_after_apt

  check "sshd checks on every run: run 2 (drop-in unchanged) runs sshd -t and sshd -T for ubuntu and deploy" \
    t_sshd_checks_every_run fresh
  check "sshd checks on every run: DenyUsers ubuntu in a foreign drop-in before run 2: run 2 aborts, own drop-in unchanged (no rollback), no reload" \
    t_sshd_rerun_abort rerun_denyusers 'DenyUsers' sshd_T 'denyusers ubuntu'
  check "sshd checks on every run: Match User ubuntu with PasswordAuthentication yes before run 2: run 2 aborts, own drop-in unchanged, no reload" \
    t_sshd_rerun_abort rerun_match_pw 'passwordauthentication' sshd_T_admin 'passwordauthentication yes'

  check "login UID: logged in as claude (sudo su -), ADMIN_USER=ubuntu: abort before any change, naming claude" \
    t_loginuid_aborts loginuid_other claude "'claude'"
  check "login UID: logged in as claude, SUDO_USER=root: abort before any change" \
    t_loginuid_aborts loginuid_other_sudo_root claude "'claude'"
  check "login UID: logged in as claude, SUDO_USER=ubuntu (= ADMIN_USER): abort before any change" \
    t_loginuid_aborts loginuid_other_sudo_admin claude "'claude'"
  check "login UID: UID $LOGINUID_NOUSER without user: abort before any change, naming the UID" \
    t_loginuid_aborts loginuid_nouser - "$LOGINUID_NOUSER"
  check "login UID: logged in as claude, ADMIN_USER=claude: runs" t_loginuid_runs loginuid_alt_admin claude
  check "login UID: logged in as ubuntu, ADMIN_USER=claude: abort before any change, naming ubuntu" \
    t_loginuid_aborts loginuid_alt_other ubuntu "'ubuntu'"
  check "login UID: logged in as ubuntu (= ADMIN_USER): runs" t_loginuid_runs loginuid_admin ubuntu
  check "login UID 0 (root): runs" t_loginuid_runs loginuid_root root
  check "login UID $LOGINUID_UNSET (not set): runs" t_loginuid_runs loginuid_unset -
  check "login UID: dry run logged in as claude: nothing changed, says a real run would abort" \
    t_dry_would_abort dry_loginuid_other "'claude'"

  check "firewall: debconf autosave_v4/v6 false before installing iptables-persistent; INPUT read before the first apt-get" \
    t_fw_before_packages fresh
  check "firewall: package installation flushes IPv4 INPUT (final REJECT gone): saved filter table restored, warning, exit 0, INPUT closed with 22/80/443 before REJECT, saved, nat unchanged" \
    t_fw_apt_restored fw_apt_flush_v4 flush_v4 iptables 'REJECT'
  check "firewall: package installation flushes IPv6 INPUT: saved filter table restored with ip6tables-restore, warning naming ip6tables, exit 0, closed again, saved, nat unchanged" \
    t_fw_apt_restored fw_apt_flush_v6 flush_v6 ip6tables 'REJECT'
  check "firewall: package installation sets IPv4 policy DROP to ACCEPT: restored (policy DROP again), warning, exit 0, 22/80/443 open, saved, nat unchanged" \
    t_fw_apt_restored fw_apt_policy_v4 policy_v4 iptables 'Policy'
  check "firewall: package installation sets IPv6 policy DROP to ACCEPT: restored with ip6tables-restore, warning naming ip6tables, exit 0, saved, nat unchanged" \
    t_fw_apt_restored fw_apt_policy_v6 policy_v6 ip6tables 'Policy'
  check "firewall: package installation deletes the final -A INPUT -j DROP: restored, warning, exit 0, 22/80/443 before the DROP, saved, nat unchanged" \
    t_fw_apt_restored fw_apt_del_drop del_final_v4 iptables 'DROP'
  check "firewall (edge case): package installation flushes INPUT whose final REJECT has a comment: restored, warning, exit 0, closed again, saved, nat unchanged" \
    t_fw_apt_restored fw_apt_flush_comment flush_v4 iptables 'REJECT'
  check "firewall: temporary copy of the filter table removed after a restore" t_tmp_cleaned fw_apt_flush_v4
  check "firewall: package installation flushes IPv4 INPUT, iptables-restore fails: abort after step 1 naming the failed restore, nothing saved" \
    t_fw_apt_abort fw_apt_restore_fail flush_v4 iptables 'REJECT' 1 'gescheitert|fehlgeschlagen' saved
  check "firewall: temporary copy of the filter table removed after the abort" t_tmp_cleaned fw_apt_restore_fail
  check "firewall: package installation flushes IPv6 INPUT, ip6tables-restore changes nothing (INPUT still open): abort after the re-check, nothing saved" \
    t_fw_apt_abort fw_apt_restore_noop flush_v6 ip6tables 'REJECT' 1 'weiter|immer noch|noch immer' saved
  check "firewall: no copy of the filter table (iptables-save fails), package installation flushes IPv4 INPUT: abort without restore, nothing saved" \
    t_fw_apt_abort fw_apt_nosave flush_v4 iptables 'REJECT' 0 'Sicherung' saved
  check "firewall (edge case): copy of the filter table empty (iptables-save prints nothing), package installation sets policy ACCEPT: abort without restore, nothing saved" \
    t_fw_apt_abort fw_apt_save_empty policy_v4 iptables 'Policy' 0 'Sicherung|gesichert'
  check "firewall (edge case): no copy of the filter table, INPUT unchanged by the package installation: no restore, exit 0, 22/80/443 opened and saved" \
    t_fw_nosave_ok fw_nosave_ok
  check "firewall: IPv4 INPUT unreadable after the package installation: restore tried, still unreadable: abort, nothing saved" \
    t_fw_apt_abort fw_apt_unreadable unreadable_v4 iptables 'lesen|lesbar' 1 'weiter|immer noch|noch immer' saved
  check "firewall: package installation flushes IPv4 INPUT and adds a nat rule: filter table restored, warning, exit 0, closed again, saved" \
    t_fw_apt_restored fw_apt_nat flush_v4_nat iptables 'REJECT'
  check "firewall: restoring the filter table keeps the nat rule and chain added during the package installation and the nat rule from before" \
    t_fw_apt_nat_kept fw_apt_nat
  check "firewall (edge case): final REJECT with a comment: no warning that INPUT does not filter" t_fw_open_warns fw_comment ''
  check "firewall: neither final REJECT/DROP nor policy DROP (IPv4 and IPv6): a warning for each, the run goes on" \
    t_fw_open_warns fw_open 'iptables ip6tables'
  check "firewall: Oracle rules (final REJECT): no warning that INPUT does not filter" t_fw_open_warns fresh ''
  check "firewall: IPv4 policy DROP, IPv6 open: warning only for ip6tables" t_fw_open_warns fw_drop_policy 'ip6tables'
  check "firewall IPv4: final -A INPUT -j DROP counts like REJECT: missing ACCEPT rules right before it, conditional DROP does not count, run 2 unchanged" \
    t_fw_final_drop fw_drop_rule v4
  check "firewall IPv6: final -A INPUT -j DROP counts like REJECT: missing ACCEPT rules right before it, conditional DROP does not count, run 2 unchanged" \
    t_fw_final_drop fw_drop_rule v6
  check "firewall: only conditional DROP rules, policy ACCEPT: no rule added" t_fw_family_unchanged fw_cond_drop v4
  check "firewall: only conditional DROP rules, policy ACCEPT: warning that INPUT does not filter" \
    t_fw_open_warns fw_cond_drop 'iptables ip6tables'

  check "fail2ban: jail recidive enabled as well: abort naming recidive and the files with [recidive], fail2ban neither restarted nor started" \
    t_f2b_other_jail_aborts f2b_recidive recidive
  check "fail2ban: jail recidive disabled: no warning about other jails" t_f2b_only_sshd f2b_recidive_off recidive
  check "fail2ban: dry run with jail recidive enabled: nothing changed, says a real run would abort, naming recidive and jail.d/zz.local" \
    t_dry_f2b_other_jail dry_f2b_recidive recidive /etc/fail2ban/jail.d/zz.local

  check "SSH: drop-in also has GSSAPIAuthentication no and HostbasedAuthentication no, both effective (sshd -T)" \
    t_sshd_dropin_lines fresh 'GSSAPIAuthentication no' 'HostbasedAuthentication no'
  check "SSH: earlier drop-in with GSSAPIAuthentication yes: drop-in reset, no reload, abort" \
    t_sshd_rollback_fixture ssh_early_gssapi '[Gg][Ss][Ss][Aa][Pp][Ii][Aa]uthentication' global 'gssapiauthentication yes'
  check "SSH: earlier drop-in with HostbasedAuthentication yes: drop-in reset, no reload, abort" \
    t_sshd_rollback_fixture ssh_early_hostbased '[Hh]ostbased[Aa]uthentication' global 'hostbasedauthentication yes'
  check "SSH: Match User ubuntu with GSSAPIAuthentication yes (only sshd -T -C sees it): drop-in reset, no reload, abort" \
    t_sshd_rollback_fixture ssh_match_gssapi '[Gg][Ss][Ss][Aa][Pp][Ii][Aa]uthentication' admin 'gssapiauthentication yes'
  check "SSH: Match User ubuntu with HostbasedAuthentication yes (only sshd -T -C sees it): drop-in reset, no reload, abort" \
    t_sshd_rollback_fixture ssh_match_hostbased '[Hh]ostbased[Aa]uthentication' admin 'hostbasedauthentication yes'
  check "SSH: Match User deploy with PubkeyAuthentication no (ubuntu not affected): warning naming deploy and PubkeyAuthentication, no abort, ssh reloaded" \
    t_sshd_deploy_auth_warns ssh_deploy_match_pubkey 'PubkeyAuthentication' 'pubkeyauthentication no'
  check "SSH: Match User deploy with AuthenticationMethods publickey,password: warning naming deploy and AuthenticationMethods, no abort, ssh reloaded" \
    t_sshd_deploy_auth_warns ssh_deploy_match_methods 'AuthenticationMethods' 'authenticationmethods publickey,password'
  check "SSH, drop-in unchanged in run 2, /run/sshd cannot be created: abort says sshd was not checked (cause rundir), drop-in kept, no reload" \
    t_sshd_unchanged_cause rerun_rundir rundir
  check "SSH, drop-in unchanged in run 2, sshd -t fails: abort says sshd reports an error (cause error), not that another file changed" \
    t_sshd_unchanged_cause rerun_sshd_t_fail error
  check "SSH, drop-in unchanged in run 2, DenyUsers ubuntu in a later drop-in: abort says another file changed (cause config)" \
    t_sshd_unchanged_cause rerun_denyusers config
  check "fail2ban: fresh server, only jail sshd: no warning about other jails" t_f2b_only_sshd fresh

  check "user deploy with home /srv/deployhome (getent passwd): authorized_keys there, nothing under /home/deploy, run 2 unchanged" \
    t_deploy_home deploy_home /srv/deployhome
  check "dry run, deploy with home /srv/deployhome: shows authorized_keys there, not /home/deploy" \
    t_dry_deploy_home dry_deploy_home /srv/deployhome

  hostinger_checks

  check "sandbox: inner entry point without caller markers refuses, mounts nothing" t_guard_refuses guard_no_markers
  check "sandbox: inner entry point in its caller's namespaces refuses, mounts nothing" t_guard_refuses guard_caller_ns
  check "sandbox: inner entry point in the namespaces of PID 1 refuses, mounts nothing" t_guard_refuses guard_pid1

  check "sandbox: every run had a defined audit login UID (default not set), whatever the caller's session has" t_loginuid_defined

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
