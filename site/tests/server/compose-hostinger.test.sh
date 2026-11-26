#!/usr/bin/env bash
# Tests for deploy/compose.hostinger.yml: the website behind the Traefik that Hostinger
# manages on the VPS (docs/server.md, "Variante Hostinger-VPS").
#
# Part 1, static (docker CLI with the compose plugin, jq, awk; no daemon needed):
#   `docker compose config` in temporary copies of deploy/, laid out like /opt/website on
#   the server (.env next to the compose files). The environment of the caller does not
#   leak in (env -i), a deploy/.env in the repository is never read. Values are synthetic
#   (reserved .example names).
# Part 2, live (running Docker daemon, curl, local images; nothing is pulled):
#   - a Traefik configured like Hostinger's: host network, docker provider with
#     exposedbydefault=false, entrypoints web (:80, redirects to https) and websecure
#     (:443), certresolver letsencrypt (HTTP challenge, CA address unreachable, so nothing
#     leaves the machine and Traefik serves its default certificate),
#   - a stand-in for the app Hermes with router and service hermes-agent-fjbe,
#   - the website deployed with an unchanged copy of deploy/deploy.sh, selected by
#     COMPOSE_FILE=compose.hostinger.yml in .env. A docker wrapper turns
#     `docker compose pull` and `docker image prune` into no-ops (no registry, the host's
#     images stay); every other call goes to the real docker.
#   Requests go to 127.0.0.1 (curl --resolve, no proxy). Needs ports 80, 443 and
#   LIVE_API_PORT free, no network funkenundstahl-web and no compose project "website".
#   Everything started is removed at the end.
#
# Usage: bash site/tests/server/compose-hostinger.test.sh
#   DEPLOY_DIR=path            test another copy of deploy/ (default: deploy/ of this repo)
#   LIVE=auto|0|1              auto (default): live part if its prerequisites are met,
#                              otherwise SKIP; 0: skip it; 1: required (exit 2 if it cannot run)
#   LIVE_WEBSITE_IMAGE=image   local image built from site/Dockerfile (required for the live
#                              part), e.g. after: docker build -t website:test ./site
#   LIVE_TRAEFIK_IMAGE=image   default traefik:latest (what Hostinger runs)
#   LIVE_STANDIN_IMAGE=image   stand-in for Hermes, any image serving HTTP on port 80
#                              (default nginx:1.30-alpine-slim, the base of the site image)
#   LIVE_API_PORT=port         Traefik API on 127.0.0.1 for the checks (default 8099)
#   KEEP_WORK=1                keep the temporary directory for debugging
# Exit code: 0 no FAIL (SKIPs are listed and never count as passed), 1 at least one FAIL,
#            2 the tests cannot run here.
# jq programs and literal ${1} are single-quoted on purpose.
# shellcheck disable=SC2016
set -uo pipefail

SELF=$(readlink -f "${BASH_SOURCE[0]}")
HERE=$(dirname "$SELF")
DEPLOY=$(readlink -f "${DEPLOY_DIR:-$HERE/../../../deploy}")

LIVE=${LIVE:-auto}
LIVE_WEBSITE_IMAGE=${LIVE_WEBSITE_IMAGE:-}
LIVE_TRAEFIK_IMAGE=${LIVE_TRAEFIK_IMAGE:-traefik:latest}
LIVE_STANDIN_IMAGE=${LIVE_STANDIN_IMAGE:-nginx:1.30-alpine-slim}
LIVE_API_PORT=${LIVE_API_PORT:-8099}

# Synthetic values only.
T_DOMAIN=site.example
T_REDIRECT=www.site.example
T_IMAGE=ghcr.io/test-owner/test-repo/website@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
T_EMAIL=acme@site.example
# Names at the Traefik of Hostinger (docs/server.md): ours all start with PREFIX, the
# existing app Hermes uses HERMES.
PREFIX=funkenundstahl-
HERMES=hermes-agent-fjbe
# HSTS as fixed for both variants (deploy/traefik/dynamic.yml).
HSTS_SECONDS=31536000
# Network with a fixed name in compose.hostinger.yml (docs/server.md).
WEB_NET=funkenundstahl-web
# Local tag for the live deploy: deploy.sh only accepts ghcr.io references.
LIVE_TAG=ghcr.io/compose-hostinger-test/website:live
LIVE_PREFIX=cht-

# .env of variant B as documented in docs/server.md (Einrichten, step 5), synthetic values.
B_ENV=("COMPOSE_FILE=compose.hostinger.yml" "DOMAIN=$T_DOMAIN" "REDIRECT_DOMAIN=$T_REDIRECT" "WEBSITE_IMAGE=$T_IMAGE")
# .env of variant A (own Traefik, compose.yml by default).
A_ENV=("DOMAIN=$T_DOMAIN" "REDIRECT_DOMAIN=$T_REDIRECT" "ACME_EMAIL=$T_EMAIL" "WEBSITE_IMAGE=$T_IMAGE")

# ===========================================================================
# Helpers
# ===========================================================================

PASS=0
FAILS=0
SKIPS=0
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

skip() { # NAME REASON
  echo "SKIP: $1 ($2)"
  SKIPS=$((SKIPS + 1))
}

# Inside test functions: "ok=1" at the start, "no MESSAGE" for every problem,
# "return $((1 - ok))" at the end.
no() {
  echo "$*"
  ok=0
}

# Copy of deploy/ laid out like /opt/website on the server; prints the directory.
mkdeploy() { # NAME
  local d="$WORK/$1"
  mkdir -p "$d/traefik"
  cp "$DEPLOY/compose.hostinger.yml" "$DEPLOY/compose.yml" "$DEPLOY/deploy.sh" "$DEPLOY/.env.example" "$d/" &&
    cp "$DEPLOY/traefik/dynamic.yml" "$d/traefik/" || return 1
  echo "$d"
}

envfile() { # DIR LINE...
  local d=$1
  shift
  printf '%s\n' "$@" >"$d/.env"
}

# docker compose in DIR with a clean environment (only what compose itself needs).
dc() { # DIR ARGS...
  local d=$1
  shift
  (
    cd "$d" || exit 1
    env -i PATH="$PATH" HOME="$HOME" \
      ${DOCKER_HOST:+DOCKER_HOST="$DOCKER_HOST"} \
      ${DOCKER_CONFIG:+DOCKER_CONFIG="$DOCKER_CONFIG"} \
      ${DOCKER_CONTEXT:+DOCKER_CONTEXT="$DOCKER_CONTEXT"} \
      docker compose "$@"
  )
}

# Resolved config of a scenario: $WORK/NAME.json, stderr in NAME.err, exit code in NAME.rc.
resolve() { # NAME DIR [ARGS...]
  local name=$1 d=$2 rc=0
  shift 2
  dc "$d" "$@" config --format json >"$WORK/$name.json" 2>"$WORK/$name.err" || rc=$?
  echo "$rc" >"$WORK/$name.rc"
}

need_cfg() { # NAME: the scenario resolved, otherwise every check on it fails
  local rc
  rc=$(cat "$WORK/$1.rc" 2>/dev/null || echo missing)
  if [[ $rc != 0 ]]; then
    echo "docker compose config failed for scenario $1 (exit $rc):"
    sed 's/^/  /' "$WORK/$1.err" 2>/dev/null
    return 1
  fi
}

# jq on the resolved config of a scenario, with the helpers below.
# Label keys: Traefik reads option names case-insensitively, so "opt" is lowercased;
# router, middleware and service names are kept as they are.
JQ_LIB='
def labels: (.services.website.labels // {})
  | if type == "array" then (map(capture("^(?<k>[^=]+)=(?<v>.*)$") | {(.k): .v}) | add // {}) else . end;
def tentries: labels | to_entries
  | map(select(.key | test("^traefik\\.http\\.(routers|middlewares|services)\\.[^.]+\\.."))
      | (.key | capture("^traefik\\.http\\.(?<kind>routers|middlewares|services)\\.(?<name>[^.]+)\\.(?<opt>.+)$"))
        + {value: .value}
      | .opt |= ascii_downcase);
def names(kind): [tentries[] | select(.kind == kind) | .name] | unique;
def opt(kind; name; o): [tentries[] | select(.kind == kind and .name == name and .opt == o) | .value] | first;
def routers_for(host): [tentries[] | select(.kind == "routers" and .opt == "rule"
  and .value == ("Host(`" + host + "`)")) | .name];
def mwlist(r): (opt("routers"; r; "middlewares") // "") | split(",")
  | map(gsub("^\\s+|\\s+$"; "")) | map(select(. != ""));
def bare: sub("@docker$"; "");
def hasopts(kind; name; p): [tentries[] | select(.kind == kind and .name == name and (.opt | startswith(p)))] | length > 0;
def unesc: gsub("\\$\\$"; "$");
# Go regexp.Expand: $$ is a literal $, ${name} and $name (longest run of letters, digits,
# underscores) refer to a group; numbers to numbered groups, other names count as empty.
def go_expand($m): gsub("\\$\\$|\\$\\{(?<b>[A-Za-z0-9_]+)\\}|\\$(?<d>[A-Za-z0-9_]+)";
  if .b == null and .d == null then "$"
  else (.b // .d) as $name
    | if ($name | test("^[0-9]+$")) then ($name | tonumber) as $i
        | (if $i == 0 then $m.string else ($m.captures[$i - 1].string // "") end)
      else "" end
  end);
def go_replace($re; $repl): . as $u | [match($re)] as $ms
  | if ($ms | length) == 0 then $u
    else $ms[0] as $m | ($repl | go_expand($m)) as $e
      | $u[0:$m.offset] + $e + $u[($m.offset + $m.length):] end;
'

jqc() { # SCENARIO [JQ-ARGS...] FILTER
  local sc=$1
  shift
  local filter=${*: -1}
  local args=("${@:1:$#-1}")
  jq -r "${args[@]}" "$JQ_LIB $filter" "$WORK/$sc.json"
}

# Name of the only router for Host(HOST) in a scenario, empty otherwise.
router_for() { # SCENARIO HOST
  jqc "$1" --arg h "$2" 'routers_for($h) | if length == 1 then .[0] else "" end'
}

# Middleware with headers.* among the middlewares of the main router.
hsts_mw() { # SCENARIO
  local r
  r=$(router_for "$1" "$T_DOMAIN")
  [[ -n $r ]] || return 0
  jqc "$1" --arg r "$r" '. as $c | [mwlist($r)[] | bare | select(. as $n | $c | hasopts("middlewares"; $n; "headers."))] | if length == 1 then .[0] else "" end'
}

# Headers of the middleware "hsts" in a traefik/dynamic.yml, as lowercased key=value lines.
# A small indentation parser: Go template lines ({{ ... }} at the start) and comments
# are ignored; quotes around values are removed.
dynamic_hsts() { # FILE
  awk -v q="'" '
    function ind(s) { match(s, /^ */); return RLENGTH }
    /^[ \t]*$/ || /^[ \t]*#/ || /^[ \t]*\{\{/ { next }
    {
      i = ind($0); s = substr($0, i + 1)
      if (s ~ /^- /) next
      if (!match(s, /^[A-Za-z0-9_.-]+:/)) next
      k = substr(s, 1, RLENGTH - 1); v = substr(s, RLENGTH + 1)
      sub(/^[ \t]+/, "", v); sub(/[ \t]+#.*$/, "", v); sub(/[ \t]+$/, "", v)
      while (n > 0 && lvl[n] >= i) n--
      n++; lvl[n] = i; key[n] = k
      path = key[1]; for (j = 2; j <= n; j++) path = path "." key[j]
      p = "http.middlewares.hsts.headers."
      if (v != "" && index(path, p) == 1) {
        c = substr(v, 1, 1)
        if ((c == q || c == "\"") && substr(v, length(v), 1) == c) v = substr(v, 2, length(v) - 2)
        print tolower(substr(path, length(p) + 1)) "=" tolower(v)
      }
    }' "$1" | sort
}

# Headers of the HSTS middleware from the labels, same format as dynamic_hsts.
label_hsts() { # SCENARIO
  local mw
  mw=$(hsts_mw "$1")
  [[ -n $mw ]] || return 0
  jqc "$1" --arg m "$mw" '[tentries[] | select(.kind == "middlewares" and .name == $m and (.opt | startswith("headers.")))
    | (.opt | ltrimstr("headers.")) + "=" + (.value | ascii_downcase)] | .[]' | sort
}

# ===========================================================================
# Part 1: static tests
# ===========================================================================

# --- AC 1: only the website, no published ports, same hardening as compose.yml ---

t_only_website() {
  local ok=1 s
  need_cfg B || return 1
  s=$(jqc B '.services | keys | join(" ")')
  [[ $s == website ]] || no "services with COMPOSE_FILE=compose.hostinger.yml in .env: '$s', expected exactly 'website'"
  s=$(dc "$WORK/B" config --services 2>&1)
  [[ $s == website ]] || no "docker compose config --services: '$s', expected exactly 'website'"
  return $((1 - ok))
}

t_no_ports() {
  local ok=1 s
  need_cfg B || return 1
  s=$(jqc B '.services.website.ports // [] | tojson')
  [[ $s == '[]' ]] || no "website publishes ports: $s"
  s=$(jqc B '.services.website.network_mode // ""')
  [[ $s != host ]] || no "website uses the host network (would expose port 8080 on the host)"
  return $((1 - ok))
}

t_hardening_values() {
  local ok=1 s
  need_cfg B || return 1
  s=$(jqc B '.services.website.read_only // false')
  [[ $s == true ]] || no "read_only is '$s', expected true"
  s=$(jqc B '[.services.website.tmpfs // [] | if type == "string" then [.] else . end | .[] | select(. == "/tmp" or startswith("/tmp:"))] | length')
  [[ $s == 1 ]] || no "tmpfs: no single entry for /tmp ($(jqc B '.services.website.tmpfs | tojson'))"
  s=$(jqc B '[.services.website.security_opt // [] | .[] | select(test("^no-new-privileges([:=]true)?$"))] | length')
  [[ $s -ge 1 ]] || no "security_opt without no-new-privileges ($(jqc B '.services.website.security_opt | tojson'))"
  s=$(jqc B '.services.website.cap_drop // [] | tojson')
  [[ $s == '["ALL"]' ]] || no "cap_drop is $s, expected [\"ALL\"]"
  s=$(jqc B '.services.website.cap_add // [] | tojson')
  [[ $s == '[]' ]] || no "cap_add is $s, expected none"
  s=$(jqc B '.services.website.privileged // false')
  [[ $s == false ]] || no "privileged is $s"
  s=$(jqc B '.services.website.restart // ""')
  [[ $s == unless-stopped ]] || no "restart is '$s', expected unless-stopped"
  return $((1 - ok))
}

HARDENING_FIELDS='.services.website | {read_only, tmpfs, security_opt, cap_drop, cap_add, privileged,
  restart, user, volumes, devices, pid, ipc, userns_mode, sysctls, ports, network_mode}'

t_hardening_equal() {
  local ok=1 a b
  need_cfg A || return 1
  need_cfg B || return 1
  a=$(jq -S "$HARDENING_FIELDS" "$WORK/A.json")
  b=$(jq -S "$HARDENING_FIELDS" "$WORK/B.json")
  [[ $a == "$b" ]] || no "website in compose.hostinger.yml differs from website in compose.yml:" \
    "$(diff <(echo "$a") <(echo "$b") | sed 's/^/  /')"
  return $((1 - ok))
}

# --- AC 2: image from WEBSITE_IMAGE, required variables, ACME_EMAIL not required ---

t_image_from_env() {
  local ok=1 s
  need_cfg B || return 1
  s=$(jqc B '.services.website.image // ""')
  [[ $s == "$T_IMAGE" ]] || no "image is '$s', expected WEBSITE_IMAGE from .env ('$T_IMAGE')"
  return $((1 - ok))
}

# Scenario: the variant B .env without VAR (MODE=missing) or with "VAR=" (MODE=empty).
t_var_required() { # VAR MODE
  local ok=1 var=$1 mode=$2 sc d line lines=() rc=0 err
  # A broken file would make every negative case "fail" for the wrong reason.
  need_cfg B || return 1
  sc="neg_${var}_$mode"
  d=$(mkdeploy "$sc") || return 1
  for line in "${B_ENV[@]}"; do
    if [[ $line == "$var="* ]]; then
      [[ $mode == empty ]] && lines+=("$var=")
    else
      lines+=("$line")
    fi
  done
  envfile "$d" "${lines[@]}"
  err=$(dc "$d" config 2>&1 >/dev/null) || rc=$?
  ((rc != 0)) || no "docker compose config succeeded with $var $mode in .env"
  [[ $err == *"$var"* && $err == *fehlt* ]] ||
    no "message does not name $var with 'fehlt' (as in docs/server.md: '… fehlt in .env'):" "$err"
  return $((1 - ok))
}

t_acme_not_required() {
  local ok=1 s
  need_cfg B || return 1
  grep -q '^ACME' "$WORK/B/.env" && no "test setup: .env of scenario B contains ACME_*"
  grep -qi 'acme' "$WORK/B.err" && no "docker compose config mentions ACME:" "$(cat "$WORK/B.err")"
  s=$(dc "$WORK/B" config --services 2>&1) || no "config --services failed without ACME_EMAIL: $s"
  return $((1 - ok))
}

# --- AC 3: main router ---

t_main_router() {
  local ok=1 r s
  need_cfg B || return 1
  s=$(jqc B --arg h "$T_DOMAIN" 'routers_for($h) | join(" ")')
  r=$(router_for B "$T_DOMAIN")
  [[ -n $r ]] || { no "expected exactly one router with rule Host(\`$T_DOMAIN\`), found: '$s'"; return 1; }
  s=$(jqc B --arg r "$r" 'opt("routers"; $r; "entrypoints") // ""')
  [[ $s == websecure ]] || no "router $r: entrypoints '$s', expected exactly 'websecure'"
  s=$(jqc B --arg r "$r" 'opt("routers"; $r; "tls.certresolver") // ""')
  [[ $s == letsencrypt ]] || no "router $r: tls.certresolver '$s', expected 'letsencrypt'"
  return $((1 - ok))
}

t_main_service_port() {
  local ok=1 r svc s
  need_cfg B || return 1
  r=$(router_for B "$T_DOMAIN")
  [[ -n $r ]] || { no "no single router for Host(\`$T_DOMAIN\`)"; return 1; }
  # Without a service label Traefik uses the container's only service.
  svc=$(jqc B --arg r "$r" '(opt("routers"; $r; "service") // "") | bare')
  if [[ -z $svc ]]; then
    svc=$(jqc B 'names("services") | if length == 1 then .[0] else "" end')
  fi
  [[ -n $svc ]] || { no "router $r: no service and not exactly one service defined"; return 1; }
  s=$(jqc B --arg s "$svc" 'opt("services"; $s; "loadbalancer.server.port") // ""')
  [[ $s == 8080 ]] || no "service $svc of router $r: loadbalancer.server.port '$s', expected 8080"
  s=$(jqc B --arg s "$svc" '[tentries[] | select(.kind == "services" and .name == $s and (.opt | test("^loadbalancer\\.server\\.(url|scheme)$")))] | map(.opt + "=" + .value) | join(" ")')
  [[ -z $s ]] || no "service $svc overrides the backend: $s"
  return $((1 - ok))
}

t_main_hsts_attached() {
  local ok=1 r mw
  need_cfg B || return 1
  r=$(router_for B "$T_DOMAIN")
  [[ -n $r ]] || { no "no single router for Host(\`$T_DOMAIN\`)"; return 1; }
  mw=$(hsts_mw B)
  [[ -n $mw ]] || { no "router $r: middlewares '$(jqc B --arg r "$r" 'mwlist($r) | join(",")')' contain no single headers middleware"; return 1; }
  [[ -n $(jqc B --arg m "$mw" 'opt("middlewares"; $m; "headers.stsseconds") // ""') ]] ||
    no "middleware $mw on router $r sets no stsSeconds"
  return $((1 - ok))
}

# --- AC 4: www router, permanent redirect to https://DOMAIN with path ---

redirect_mw() { # SCENARIO: the only redirectregex middleware of the www router
  local r
  r=$(router_for "$1" "$T_REDIRECT")
  [[ -n $r ]] || return 0
  jqc "$1" --arg r "$r" '. as $c | [mwlist($r)[] | bare | select(. as $n | $c | hasopts("middlewares"; $n; "redirectregex."))] | if length == 1 then .[0] else "" end'
}

t_www_router() {
  local ok=1 r mw s
  need_cfg B || return 1
  s=$(jqc B --arg h "$T_REDIRECT" 'routers_for($h) | join(" ")')
  r=$(router_for B "$T_REDIRECT")
  [[ -n $r ]] || { no "expected exactly one router with rule Host(\`$T_REDIRECT\`), found: '$s'"; return 1; }
  s=$(jqc B --arg r "$r" '(opt("routers"; $r; "entrypoints") // "") | split(",") | index("websecure") != null')
  [[ $s == true ]] || no "router $r: not on entrypoint websecure ('$(jqc B --arg r "$r" 'opt("routers"; $r; "entrypoints") // ""')')"
  s=$(jqc B --arg r "$r" 'opt("routers"; $r; "tls.certresolver") // ""')
  [[ $s == letsencrypt ]] || no "router $r: tls.certresolver '$s', expected 'letsencrypt' (https://$T_REDIRECT needs a certificate)"
  mw=$(redirect_mw B)
  [[ -n $mw ]] || { no "router $r: middlewares '$(jqc B --arg r "$r" 'mwlist($r) | join(",")')' contain no single redirectregex middleware"; return 1; }
  s=$(jqc B --arg m "$mw" '(opt("middlewares"; $m; "redirectregex.permanent") // "") | ascii_downcase')
  [[ $s == true ]] || no "middleware $mw: redirectregex.permanent '$s', expected true"
  return $((1 - ok))
}

# What Traefik does with the labels as the container gets them ($$ -> $): Go's
# Regexp.ReplaceAllString on scheme://host/request-uri (first match; the regex is
# expected to cover the whole URL).
t_redirect_keeps_path() {
  local ok=1 mw re repl u want got
  need_cfg B || return 1
  mw=$(redirect_mw B)
  [[ -n $mw ]] || { no "no single redirectregex middleware on the router for Host(\`$T_REDIRECT\`)"; return 1; }
  re=$(jqc B --arg m "$mw" '(opt("middlewares"; $m; "redirectregex.regex") // "") | unesc')
  repl=$(jqc B --arg m "$mw" '(opt("middlewares"; $m; "redirectregex.replacement") // "") | unesc')
  while IFS='|' read -r u want; do
    got=$(jq -rn --arg u "$u" --arg re "$re" --arg repl "$repl" "$JQ_LIB \$u | go_replace(\$re; \$repl)") ||
      { no "regex '$re' cannot be evaluated"; break; }
    [[ $got == "$want" ]] || no "$u -> '$got', expected '$want' (regex '$re', replacement '$repl')"
  done <<EOF
https://$T_REDIRECT/|https://$T_DOMAIN/
https://$T_REDIRECT/vergleichstest/?a=1&b=2|https://$T_DOMAIN/vergleichstest/?a=1&b=2
https://$T_REDIRECT/blog/feuerstahl-mit-kindern/|https://$T_DOMAIN/blog/feuerstahl-mit-kindern/
https://$T_REDIRECT:443/impressum/|https://$T_DOMAIN/impressum/
https://$T_REDIRECT//evil.example/x|https://$T_DOMAIN//evil.example/x
http://$T_REDIRECT/x?y=1|https://$T_DOMAIN/x?y=1
EOF
  return $((1 - ok))
}

t_replacement_label() {
  local ok=1 mw s want
  need_cfg B || return 1
  mw=$(redirect_mw B)
  [[ -n $mw ]] || { no "no single redirectregex middleware on the router for Host(\`$T_REDIRECT\`)"; return 1; }
  want="https://$T_DOMAIN"'${1}'
  s=$(jqc B --arg m "$mw" '(opt("middlewares"; $m; "redirectregex.replacement") // "") | unesc')
  [[ $s == "$want" ]] || no "replacement as the container gets it: '$s', expected '$want'"
  return $((1 - ok))
}

# --- AC 5: HSTS as in traefik/dynamic.yml ---

t_hsts_values() {
  local ok=1 l d
  need_cfg B || return 1
  l=$(label_hsts B)
  d=$(dynamic_hsts "$WORK/B/traefik/dynamic.yml")
  [[ -n $l ]] || no "no HSTS middleware on the router for Host(\`$T_DOMAIN\`)"
  grep -qx "stsseconds=$HSTS_SECONDS" <<<"$l" || no "labels: stsSeconds is not $HSTS_SECONDS: $(tr "\n" " " <<<"$l")"
  grep -qx "stsseconds=$HSTS_SECONDS" <<<"$d" || no "traefik/dynamic.yml: stsSeconds is not $HSTS_SECONDS: $(tr "\n" " " <<<"$d")"
  grep -qx 'stsincludesubdomains=true' <<<"$l" && no "labels: stsIncludeSubdomains is true"
  grep -qx 'stsincludesubdomains=true' <<<"$d" && no "traefik/dynamic.yml: stsIncludeSubdomains is true"
  grep -qx 'stspreload=true' <<<"$l" && no "labels: stsPreload is true"
  grep -qx 'stspreload=true' <<<"$d" && no "traefik/dynamic.yml: stsPreload is true"
  return $((1 - ok))
}

t_hsts_same_as_dynamic() {
  local ok=1 l d
  need_cfg B || return 1
  l=$(label_hsts B)
  d=$(dynamic_hsts "$WORK/B/traefik/dynamic.yml")
  # Otherwise the comparison would look at nothing.
  grep -q '^stsseconds=' <<<"$d" || no "could not read http.middlewares.hsts.headers from traefik/dynamic.yml (got: '$(tr "\n" " " <<<"$d")')"
  [[ -n $l ]] || no "no HSTS middleware on the router for Host(\`$T_DOMAIN\`)"
  [[ $l == "$d" ]] || no "HSTS headers differ (< traefik/dynamic.yml, > labels in compose.hostinger.yml):" \
    "$(diff <(echo "$d") <(echo "$l") | grep '^[<>]' | sed 's/^/  /')"
  return $((1 - ok))
}

# --- AC 6: unique names, traefik.enable, references, network ---

t_names_prefixed() {
  local ok=1 n count=0 kind
  need_cfg B || return 1
  for kind in routers middlewares services; do
    while read -r n; do
      [[ -n $n ]] || continue
      count=$((count + 1))
      [[ $n == "$PREFIX"?* ]] || no "$kind name '$n' does not start with '$PREFIX'"
      [[ $n == "$HERMES"* ]] && no "$kind name '$n' collides with the existing router '$HERMES'"
    done < <(jqc B "names(\"$kind\")[]")
  done
  # Main and www router plus a service at least, otherwise this checks nothing.
  [[ $(jqc B 'names("routers") | length') -ge 2 && $(jqc B 'names("services") | length') -ge 1 ]] ||
    no "too little to check: $count names ($(jqc B 'names("routers") | length') routers, $(jqc B 'names("services") | length') services)"
  return $((1 - ok))
}

t_enable_label() {
  local ok=1 s
  need_cfg B || return 1
  s=$(jqc B '(labels["traefik.enable"] // "") | ascii_downcase')
  [[ $s == true ]] || no "label traefik.enable is '$s', expected true (Hostinger's Traefik has exposedbydefault=false)"
  return $((1 - ok))
}

# Every middleware a router uses is defined in these labels (@docker or no provider; the
# Traefik of Hostinger has no file provider); a router's service is defined here or is
# noop@internal.
t_references_resolve() {
  local ok=1 r m s defined
  need_cfg B || return 1
  while read -r r; do
    [[ -n $r ]] || continue
    while read -r m; do
      [[ -n $m ]] || continue
      if [[ $m == *@* && $m != *@docker ]]; then
        no "router $r uses middleware '$m' from another provider"
        continue
      fi
      defined=$(jqc B --arg m "${m%@docker}" 'names("middlewares") | index($m) != null')
      [[ $defined == true ]] || no "router $r uses middleware '$m', which is not defined in the labels"
    done < <(jqc B --arg r "$r" 'mwlist($r)[]')
    s=$(jqc B --arg r "$r" 'opt("routers"; $r; "service") // ""')
    [[ -z $s || $s == noop@internal ]] && continue
    if [[ $s == *@* && $s != *@docker ]]; then
      no "router $r uses service '$s' from another provider"
      continue
    fi
    defined=$(jqc B --arg s "${s%@docker}" 'names("services") | index($s) != null')
    [[ $defined == true ]] || no "router $r uses service '$s', which is not defined in the labels"
  done < <(jqc B 'names("routers")[]')
  return $((1 - ok))
}

# Traefik runs in the host network and needs the container's address on the network
# named in traefik.docker.network.
t_docker_network() {
  local ok=1 label nets
  need_cfg B || return 1
  label=$(jqc B 'labels["traefik.docker.network"] // ""')
  nets=$(jqc B '. as $c | (.services.website.networks // {default: null}) | keys
    | map(($c.networks[.].name) // ($c.name + "_" + .)) | join(" ")')
  if [[ -n $label ]]; then
    [[ " $nets " == *" $label "* ]] || no "traefik.docker.network is '$label', but the website is attached to: $nets"
  else
    [[ $nets != *" "* ]] || no "website is attached to several networks ($nets) without traefik.docker.network"
  fi
  return $((1 - ok))
}

# --- AC 7 and the switch COMPOSE_FILE in .env (.env.example as installed on the server) ---

t_variant_a_env_example() {
  local ok=1 d s
  d=$(mkdeploy env_example_a) || return 1
  cp "$d/.env.example" "$d/.env"
  s=$(dc "$d" config --services 2>&1 | sort | tr '\n' ' ')
  [[ $s == "traefik website " ]] || no "compose.yml with .env.example as .env: services '$s', expected 'traefik website'"
  return $((1 - ok))
}

t_variant_b_env_example() {
  local ok=1 d s
  d=$(mkdeploy env_example_b) || return 1
  sed 's/^#[[:space:]]*COMPOSE_FILE=/COMPOSE_FILE=/' "$d/.env.example" >"$d/.env"
  grep -qx 'COMPOSE_FILE=compose.hostinger.yml' "$d/.env" ||
    { no ".env.example has no commented line 'COMPOSE_FILE=compose.hostinger.yml' to switch to variant B"; return 1; }
  s=$(dc "$d" config --services 2>&1 | tr '\n' ' ')
  [[ $s == "website " ]] || no ".env.example with COMPOSE_FILE line enabled: services '$s', expected 'website'"
  return $((1 - ok))
}

# ===========================================================================
# Part 2: live tests
# ===========================================================================

LIVE_STARTED=0
LIVE_REASON=""

port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

live_prereqs() { # sets LIVE_REASON if the live part cannot run
  local p
  command -v curl >/dev/null || { LIVE_REASON="curl missing"; return 1; }
  docker info >/dev/null 2>&1 || { LIVE_REASON="no Docker daemon"; return 1; }
  [[ -n $LIVE_WEBSITE_IMAGE ]] || { LIVE_REASON="LIVE_WEBSITE_IMAGE not set (image built from site/Dockerfile)"; return 1; }
  for p in "$LIVE_WEBSITE_IMAGE" "$LIVE_TRAEFIK_IMAGE" "$LIVE_STANDIN_IMAGE"; do
    docker image inspect "$p" >/dev/null 2>&1 || { LIVE_REASON="image $p not present locally"; return 1; }
  done
  # compose.hostinger.yml takes the health check test from the image (site/Dockerfile).
  [[ $(docker image inspect --format '{{if .Config.Healthcheck}}{{len .Config.Healthcheck.Test}}{{else}}0{{end}}' "$LIVE_WEBSITE_IMAGE") -gt 0 ]] ||
    { LIVE_REASON="$LIVE_WEBSITE_IMAGE has no HEALTHCHECK, not built from site/Dockerfile?"; return 1; }
  [[ -S /var/run/docker.sock ]] || { LIVE_REASON="/var/run/docker.sock missing (Traefik's docker provider needs it)"; return 1; }
  for p in 80 443 "$LIVE_API_PORT"; do
    port_busy "$p" && { LIVE_REASON="port $p on 127.0.0.1 is in use"; return 1; }
  done
  docker network inspect "$WEB_NET" >/dev/null 2>&1 && { LIVE_REASON="network $WEB_NET exists already"; return 1; }
  [[ -z $(docker ps -aq --filter label=com.docker.compose.project=website) ]] ||
    { LIVE_REASON="containers of a compose project 'website' exist already"; return 1; }
  [[ -z $(docker ps -aq --filter "name=^${LIVE_PREFIX}") ]] ||
    { LIVE_REASON="containers named ${LIVE_PREFIX}* exist already"; return 1; }
  return 0
}

# curl to the local Traefik: HOST resolved to 127.0.0.1, its default certificate accepted.
lcurl() { # ARGS...
  curl -sk --noproxy '*' --max-time 10 \
    --resolve "$T_DOMAIN:443:127.0.0.1" --resolve "$T_REDIRECT:443:127.0.0.1" \
    --resolve "hermes.example:443:127.0.0.1" --resolve "other.example:443:127.0.0.1" \
    --resolve "$T_DOMAIN:80:127.0.0.1" --resolve "$T_REDIRECT:80:127.0.0.1" "$@"
}

api() { curl -s --noproxy '*' --max-time 5 "http://127.0.0.1:$LIVE_API_PORT/api/$1"; }

wait_for() { # SECONDS COMMAND...: until the command succeeds
  local end=$((SECONDS + $1))
  shift
  until "$@"; do
    ((SECONDS < end)) || return 1
    sleep 1
  done
}

code_is() { [[ $(lcurl -o /dev/null -w '%{http_code}' "$2") == "$1" ]]; }
api_has_router() { api http/routers | jq -e --arg n "$1" 'map(.name) | index($n) != null' >/dev/null 2>&1; }

live_up() {
  local d
  LIVE_STARTED=1
  docker tag "$LIVE_WEBSITE_IMAGE" "$LIVE_TAG" || return 1
  docker network create "${LIVE_PREFIX}hermes-net" >/dev/null || return 1
  # Stand-in for Hermes, labels like an app at Hostinger's Traefik.
  docker run -d --pull never --name "${LIVE_PREFIX}hermes" --network "${LIVE_PREFIX}hermes-net" \
    --label traefik.enable=true \
    --label "traefik.http.routers.$HERMES.rule=Host(\`hermes.example\`)" \
    --label "traefik.http.routers.$HERMES.entrypoints=websecure" \
    --label "traefik.http.routers.$HERMES.tls=true" \
    --label "traefik.http.routers.$HERMES.tls.certresolver=letsencrypt" \
    --label "traefik.http.services.$HERMES.loadbalancer.server.port=80" \
    "$LIVE_STANDIN_IMAGE" >/dev/null || return 1
  # Like Hostinger's Traefik (docs/server.md); the API only for the checks, on loopback.
  docker run -d --pull never --name "${LIVE_PREFIX}traefik" --network host \
    -v /var/run/docker.sock:/var/run/docker.sock:ro "$LIVE_TRAEFIK_IMAGE" \
    --providers.docker=true --providers.docker.exposedbydefault=false \
    --entrypoints.web.address=:80 \
    --entrypoints.web.http.redirections.entrypoint.to=websecure \
    --entrypoints.web.http.redirections.entrypoint.scheme=https \
    --entrypoints.websecure.address=:443 \
    --certificatesresolvers.letsencrypt.acme.httpchallenge=true \
    --certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web \
    --certificatesresolvers.letsencrypt.acme.email=acme@site.example \
    --certificatesresolvers.letsencrypt.acme.storage=/tmp/acme.json \
    --certificatesresolvers.letsencrypt.acme.caserver=https://127.0.0.1:9/directory \
    --entrypoints.traefik.address="127.0.0.1:$LIVE_API_PORT" --api.insecure=true \
    --global.checknewversion=false --global.sendanonymoususage=false >/dev/null || return 1
  wait_for 30 api_has_router "$HERMES@docker" || { echo "Traefik did not pick up the Hermes stand-in"; return 1; }

  # The server directory: an unchanged copy of deploy/, .env as in docs/server.md step 5.
  d=$(mkdeploy live) || return 1
  envfile "$d" "COMPOSE_FILE=compose.hostinger.yml" "DOMAIN=$T_DOMAIN" "REDIRECT_DOMAIN=$T_REDIRECT" \
    "WEBSITE_IMAGE=ghcr.io/compose-hostinger-test/website:previous"
  mkdir -p "$WORK/bin"
  cat >"$WORK/bin/docker" <<'WRAP'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$WRAP_LOG"
case "${1:-} ${2:-}" in
  "compose pull") exit 0 ;; # no registry in the tests
  "image prune") exit 0 ;;  # never prune the host's images
esac
exec "$REAL_DOCKER" "$@"
WRAP
  chmod +x "$WORK/bin/docker"
  local rc=0
  (
    cd "$d" || exit 1
    env -i PATH="$WORK/bin:$PATH" HOME="$HOME" WRAP_LOG="$WORK/docker-calls.log" REAL_DOCKER="$(command -v docker)" \
      ${DOCKER_HOST:+DOCKER_HOST="$DOCKER_HOST"} ${DOCKER_CONFIG:+DOCKER_CONFIG="$DOCKER_CONFIG"} \
      timeout 180 bash ./deploy.sh "$LIVE_TAG"
  ) >"$WORK/deploy.log" 2>&1 || rc=$?
  echo "$rc" >"$WORK/deploy.rc"
  # Traefik takes the container once it is healthy; give it a moment, the checks decide.
  wait_for 30 code_is 200 "https://$T_DOMAIN/" || true
  return 0
}

live_down() {
  ((LIVE_STARTED)) || return 0
  [[ -d $WORK/live ]] && dc "$WORK/live" down --remove-orphans >/dev/null 2>&1
  docker rm -f "${LIVE_PREFIX}traefik" "${LIVE_PREFIX}hermes" >/dev/null 2>&1
  docker network rm "${LIVE_PREFIX}hermes-net" >/dev/null 2>&1
  docker image rm "$LIVE_TAG" >/dev/null 2>&1 # only the extra tag
  if docker network inspect "$WEB_NET" >/dev/null 2>&1; then
    echo "WARNING: network $WEB_NET still exists after the live tests"
  fi
  if [[ -n $(docker ps -aq --filter label=com.docker.compose.project=website) ||
    -n $(docker ps -aq --filter "name=^${LIVE_PREFIX}") ]]; then
    echo "WARNING: containers of the live tests are left over"
  fi
}

website_id() { dc "$WORK/live" ps -q website 2>/dev/null; }

t_live_deploy() {
  local ok=1 rc id status
  rc=$(cat "$WORK/deploy.rc" 2>/dev/null || echo missing)
  [[ $rc == 0 ]] || no "deploy.sh exited with $rc:" "$(sed 's/^/  /' "$WORK/deploy.log" 2>/dev/null)"
  grep -q "Website läuft mit $LIVE_TAG" "$WORK/deploy.log" 2>/dev/null || no "deploy.sh did not report success"
  # The wrapper saw the calls, so the checks below are about this deploy.
  grep -qx 'compose up -d --remove-orphans' "$WORK/docker-calls.log" 2>/dev/null ||
    no "deploy.sh did not run 'docker compose up -d --remove-orphans' through the wrapper"
  id=$(website_id)
  [[ -n $id ]] || { no "no website container in the compose project"; return 1; }
  status=$(docker inspect --format '{{.State.Health.Status}}' "$id" 2>&1)
  [[ $status == healthy ]] || no "website container health: '$status'"
  # Only the website was started, no Traefik of our own.
  local svcs
  svcs=$(docker ps --filter label=com.docker.compose.project=website --format '{{.Label "com.docker.compose.service"}}' | sort | tr '\n' ' ')
  [[ $svcs == "website " ]] || no "running services of project website: '$svcs', expected 'website'"
  return $((1 - ok))
}

t_live_env_kept() {
  local ok=1 f="$WORK/live/.env"
  if [[ $(grep -c '^COMPOSE_FILE=' "$f") != 1 ]] || ! grep -qx 'COMPOSE_FILE=compose.hostinger.yml' "$f"; then
    no ".env after the deploy no longer selects compose.hostinger.yml:" "$(sed 's/^/  /' "$f")"
  fi
  grep -qx "WEBSITE_IMAGE=$LIVE_TAG" "$f" || no ".env after the deploy: WEBSITE_IMAGE is not $LIVE_TAG"
  return $((1 - ok))
}

t_live_container() {
  local ok=1 id j s
  id=$(website_id)
  [[ -n $id ]] || { no "no website container"; return 1; }
  j=$(docker inspect "$id")
  s=$(jq -c '.[0].HostConfig.PortBindings // {} | with_entries(select(.value != null and .value != [])) ' <<<"$j")
  [[ $s == '{}' ]] || no "port bindings: $s"
  s=$(jq -c '[.[0].NetworkSettings.Ports // {} | to_entries[] | select(.value != null and .value != [])]' <<<"$j")
  [[ $s == '[]' ]] || no "published ports: $s"
  s=$(jq -r '.[0].HostConfig.PublishAllPorts' <<<"$j")
  [[ $s == false ]] || no "PublishAllPorts: $s"
  s=$(jq -r '.[0].HostConfig.NetworkMode' <<<"$j")
  [[ $s != host ]] || no "network mode host"
  s=$(jq -r '.[0].HostConfig.ReadonlyRootfs' <<<"$j")
  [[ $s == true ]] || no "ReadonlyRootfs: $s"
  s=$(jq -c '.[0].HostConfig.CapDrop' <<<"$j")
  [[ $s == '["ALL"]' ]] || no "CapDrop: $s"
  s=$(jq -c '.[0].HostConfig.CapAdd // []' <<<"$j")
  [[ $s == '[]' ]] || no "CapAdd: $s"
  s=$(jq -r '.[0].HostConfig.SecurityOpt // [] | index("no-new-privileges:true") != null' <<<"$j")
  [[ $s == true ]] || no "SecurityOpt: $(jq -c '.[0].HostConfig.SecurityOpt' <<<"$j")"
  s=$(jq -r '.[0].HostConfig.Tmpfs // {} | has("/tmp")' <<<"$j")
  [[ $s == true ]] || no "Tmpfs: $(jq -c '.[0].HostConfig.Tmpfs' <<<"$j")"
  s=$(jq -r '.[0].HostConfig.RestartPolicy.Name' <<<"$j")
  [[ $s == unless-stopped ]] || no "RestartPolicy: $s"
  s=$(jq -r '.[0].HostConfig.Privileged' <<<"$j")
  [[ $s == false ]] || no "Privileged: $s"
  return $((1 - ok))
}

t_live_replacement_label() {
  local ok=1 id s want
  id=$(website_id)
  [[ -n $id ]] || { no "no website container"; return 1; }
  want="https://$T_DOMAIN"'${1}'
  s=$(docker inspect "$id" | jq -r '[.[0].Config.Labels | to_entries[]
    | select(.key | ascii_downcase | test("^traefik\\.http\\.middlewares\\.[^.]+\\.redirectregex\\.replacement$"))
    | .value] | if length == 1 then .[0] else "found \(length) replacement labels" end')
  [[ $s == "$want" ]] || no "container label redirectregex.replacement: '$s', expected '$want'"
  return $((1 - ok))
}

t_live_traefik_routers() {
  local ok=1 routers r ip s svc
  routers=$(api http/routers) || { no "Traefik API not reachable"; return 1; }
  for r in "Host(\`$T_DOMAIN\`)" "Host(\`$T_REDIRECT\`)"; do
    s=$(jq -c --arg r "$r" '[.[] | select(.rule == $r)]' <<<"$routers")
    [[ $(jq length <<<"$s") == 1 ]] || { no "Traefik has $(jq length <<<"$s") routers for $r, expected 1"; continue; }
    jq -e --arg p "$PREFIX" '.[0] | .provider == "docker" and (.name | startswith($p))' <<<"$s" >/dev/null ||
      no "router for $r: $(jq -c '.[0] | {name, provider}' <<<"$s")"
    jq -e '.[0] | .status == "enabled" and (has("error") | not)' <<<"$s" >/dev/null ||
      no "router for $r not enabled or with errors: $(jq -c '.[0] | {status, error}' <<<"$s")"
    jq -e '.[0] | .entryPoints == ["websecure"] and .tls.certResolver == "letsencrypt"' <<<"$s" >/dev/null ||
      no "router for $r: $(jq -c '.[0] | {entryPoints, tls}' <<<"$s")"
  done
  jq -e --arg n "$HERMES@docker" '.[] | select(.name == $n) | .status == "enabled" and (has("error") | not)' <<<"$routers" >/dev/null ||
    no "router $HERMES@docker of the stand-in is missing, disabled or has errors"
  # Main router -> website container on the fixed network, port 8080.
  svc=$(jq -r --arg r "Host(\`$T_DOMAIN\`)" '.[] | select(.rule == $r) | .service' <<<"$routers" | head -n1)
  ip=$(docker inspect --format "{{(index .NetworkSettings.Networks \"$WEB_NET\").IPAddress}}" "$(website_id)" 2>/dev/null)
  s=$(api "http/services/${svc}@docker" | jq -r '[.loadBalancer.servers[]?.url] | join(" ")')
  [[ -n $ip && $s == "http://$ip:8080" ]] || no "service $svc: servers '$s', expected 'http://$ip:8080' (container on $WEB_NET)"
  return $((1 - ok))
}

t_live_main() {
  local ok=1 h code sts
  h=$(lcurl -D - -o "$WORK/body.html" -w '%{http_code}' "https://$T_DOMAIN/")
  code=${h##*$'\n'}
  [[ $code == 200 ]] || no "https://$T_DOMAIN/: status '$code'"
  sts=$(grep -i '^strict-transport-security:' <<<"$h" | tr -d '\r')
  [[ $(grep -ci '^strict-transport-security:' <<<"$h") == 1 ]] || no "expected one Strict-Transport-Security header, got: '$sts'"
  [[ ${sts#*: } == "max-age=$HSTS_SECONDS" ]] || no "Strict-Transport-Security: '${sts#*: }', expected 'max-age=$HSTS_SECONDS'"
  grep -qi '<html' "$WORK/body.html" 2>/dev/null || no "https://$T_DOMAIN/ did not return the website's HTML"
  return $((1 - ok))
}

t_live_redirect() {
  local ok=1 path out code loc
  for path in "/" "/vergleichstest/?a=1&b=2" "/blog/feuerstahl-mit-kindern/"; do
    out=$(lcurl -o /dev/null -w '%{http_code} %{redirect_url}' "https://$T_REDIRECT$path")
    code=${out%% *} loc=${out#* }
    [[ $code == 301 || $code == 308 ]] || no "GET https://$T_REDIRECT$path: status $code, expected a permanent redirect (301/308)"
    [[ $loc == "https://$T_DOMAIN$path" ]] || no "GET https://$T_REDIRECT$path: Location '$loc', expected 'https://$T_DOMAIN$path'"
  done
  # A request target starting with // must not leave the site (open redirect).
  loc=$(lcurl -o /dev/null -w '%{redirect_url}' --path-as-is --request-target '//evil.example/x' "https://$T_REDIRECT/")
  [[ $loc == "https://$T_DOMAIN/"* ]] || no "request target //evil.example/x: Location '$loc' leaves https://$T_DOMAIN/"
  return $((1 - ok))
}

t_live_other_hosts() {
  local ok=1 code
  code=$(lcurl -o /dev/null -w '%{http_code}' "https://other.example/")
  [[ $code == 404 ]] || no "https://other.example/: status $code, expected 404 (website must only answer its own names)"
  code=$(lcurl -o /dev/null -w '%{http_code}' "https://hermes.example/")
  [[ $code == 200 ]] || no "https://hermes.example/ (stand-in for Hermes): status $code, expected 200"
  return $((1 - ok))
}

# ===========================================================================
# Main
# ===========================================================================

cleanup() {
  live_down
  if [[ ${KEEP_WORK:-0} == 1 ]]; then
    echo "Work directory kept: $WORK"
  else
    rm -rf "$WORK"
  fi
}

main() {
  local cmd
  for cmd in docker jq awk sed; do
    command -v "$cmd" >/dev/null || { echo "cannot run: $cmd missing" >&2; exit 2; }
  done
  docker compose version >/dev/null 2>&1 || { echo "cannot run: docker compose plugin missing" >&2; exit 2; }
  [[ -f $DEPLOY/compose.hostinger.yml ]] || { echo "cannot run: $DEPLOY/compose.hostinger.yml missing" >&2; exit 2; }
  case $LIVE in
    auto | 0 | 1) ;;
    *) echo "LIVE must be auto, 0 or 1" >&2; exit 2 ;;
  esac
  WORK=$(mktemp -d)
  trap cleanup EXIT

  echo "Testing $DEPLOY"
  mkdeploy B >/dev/null && envfile "$WORK/B" "${B_ENV[@]}" && resolve B "$WORK/B"
  mkdeploy A >/dev/null && envfile "$WORK/A" "${A_ENV[@]}" && resolve A "$WORK/A"

  check "variant B (COMPOSE_FILE=compose.hostinger.yml in .env): only the service website" t_only_website
  check "variant B: website publishes no ports and does not use the host network" t_no_ports
  check "variant B: read_only, tmpfs /tmp, no-new-privileges, cap_drop ALL, no cap_add, not privileged, restart unless-stopped" \
    t_hardening_values
  check "variant B: hardening of website identical to website in compose.yml" t_hardening_equal

  check "image is WEBSITE_IMAGE from .env (digest reference as written by deploy.sh)" t_image_from_env
  local v
  for v in DOMAIN REDIRECT_DOMAIN WEBSITE_IMAGE; do
    check "$v missing in .env: docker compose config fails, message names $v and 'fehlt'" t_var_required "$v" missing
    check "$v empty in .env ($v=): docker compose config fails, message names $v and 'fehlt'" t_var_required "$v" empty
  done
  check ".env as in docs/server.md without ACME_EMAIL and ACME_CA_SERVER: config succeeds, nothing asks for ACME" \
    t_acme_not_required

  check "main router: exactly one router for Host(DOMAIN), entrypoints exactly websecure, certresolver letsencrypt" t_main_router
  check "main router: service on port 8080, backend not overridden" t_main_service_port
  check "main router: uses the HSTS middleware" t_main_hsts_attached

  check "www router: exactly one router for Host(REDIRECT_DOMAIN) on websecure, certresolver letsencrypt, redirectregex permanent=true" \
    t_www_router
  check "www redirect (labels evaluated like Traefik): https://DOMAIN with path and query, never another host" t_redirect_keeps_path
  check "www redirect: replacement as the container gets it is exactly https://DOMAIN\${1} (\$\$ unescaped)" t_replacement_label

  check "HSTS: stsSeconds $HSTS_SECONDS, includeSubdomains and preload not true, in the labels and in traefik/dynamic.yml" \
    t_hsts_values
  check "HSTS: headers of the labels identical to http.middlewares.hsts.headers in traefik/dynamic.yml (keys and values)" \
    t_hsts_same_as_dynamic

  check "all router, middleware and service names start with '$PREFIX', none collides with $HERMES" t_names_prefixed
  check "label traefik.enable=true" t_enable_label
  check "routers only use middlewares and services defined in the labels (@docker) or noop@internal" t_references_resolve
  check "traefik.docker.network names the network the website is attached to" t_docker_network

  check "variant A: compose.yml with .env.example as .env resolves to traefik and website" t_variant_a_env_example
  check "variant B: .env.example with its COMPOSE_FILE line enabled resolves to website only" t_variant_b_env_example

  local live_names=(
    "live: unchanged deploy.sh deploys variant B selected by COMPOSE_FILE in .env, website healthy, no own Traefik"
    "live: .env after the deploy still has COMPOSE_FILE=compose.hostinger.yml and the new WEBSITE_IMAGE"
    "live: container without published ports, read-only, CapDrop ALL, no-new-privileges, tmpfs /tmp, restart unless-stopped"
    "live: container label redirectregex.replacement is exactly https://DOMAIN\${1}"
    "live: Traefik routers for DOMAIN and REDIRECT_DOMAIN enabled without errors (websecure, letsencrypt, prefixed), $HERMES unaffected, service -> container:8080 on $WEB_NET"
    "live: https://DOMAIN/ answers 200 with the website and Strict-Transport-Security: max-age=$HSTS_SECONDS"
    "live: https://REDIRECT_DOMAIN/<path>?<query> redirects permanently to https://DOMAIN/<path>?<query>, // stays on the site"
    "live: other host names get 404, the Hermes stand-in still answers 200"
  )
  local live_fns=(t_live_deploy t_live_env_kept t_live_container t_live_replacement_label
    t_live_traefik_routers t_live_main t_live_redirect t_live_other_hosts)
  local i run_live=0
  if [[ $LIVE == 0 ]]; then
    LIVE_REASON="LIVE=0"
  elif live_prereqs; then
    run_live=1
  elif [[ $LIVE == 1 ]]; then
    echo "cannot run the live part (LIVE=1): $LIVE_REASON" >&2
    exit 2
  fi
  if ((run_live)); then
    # Not in a subshell: cleanup needs LIVE_STARTED.
    if live_up >"$WORK/live_up.log" 2>&1; then
      for i in "${!live_fns[@]}"; do check "${live_names[$i]}" "${live_fns[$i]}"; done
    else
      echo "FAIL: live setup"
      sed 's/^/      /' "$WORK/live_up.log"
      FAILS=$((FAILS + 1))
    fi
  else
    for i in "${!live_names[@]}"; do skip "${live_names[$i]}" "$LIVE_REASON"; done
  fi

  echo
  echo "Result: $PASS passed, $FAILS failed, $SKIPS skipped"
  ((FAILS == 0))
}

main "$@"
