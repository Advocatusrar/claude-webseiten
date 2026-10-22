#!/usr/bin/env bash
# Deploys a website image on the server and rolls back if it does not become healthy.
#
# Called by the CI via SSH. The deploy key in ~deploy/.ssh/authorized_keys is restricted
# to this script (forced command), so the image reference arrives in SSH_ORIGINAL_COMMAND.
# Manually: ./deploy.sh ghcr.io/<owner>/<repo>/website@sha256:...
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

NEU="${1:-${SSH_ORIGINAL_COMMAND:-}}"
# Only image references from GHCR, nothing else may come through the forced command.
if [[ ! "$NEU" =~ ^ghcr\.io/[a-z0-9._/-]+(:[A-Za-z0-9._-]+)?(@sha256:[a-f0-9]{64})?$ ]]; then
  echo "Ungültige Image-Angabe: '$NEU'" >&2
  exit 2
fi

[[ -f .env ]] || { echo ".env fehlt in $(pwd)" >&2; exit 1; }
ALT="$(sed -n 's/^WEBSITE_IMAGE=//p' .env)"

setze_image() {
  if grep -q '^WEBSITE_IMAGE=' .env; then
    sed -i "s|^WEBSITE_IMAGE=.*|WEBSITE_IMAGE=$1|" .env
  else
    echo "WEBSITE_IMAGE=$1" >> .env
  fi
}

gesund() {
  local id status
  for _ in $(seq 1 30); do
    id="$(docker compose ps -q website)"
    status="$(docker inspect --format '{{.State.Health.Status}}' "$id" 2>/dev/null || true)"
    [[ "$status" == "healthy" ]] && return 0
    sleep 2
  done
  return 1
}

echo "Deploy: $NEU"
setze_image "$NEU"
docker compose pull --quiet website
docker compose up -d --remove-orphans

if gesund; then
  echo "Website läuft mit $NEU"
  # Keep the last images for a quick manual rollback, remove older ones.
  docker image prune --force --filter "until=720h" >/dev/null
  exit 0
fi

echo "Neues Image wird nicht gesund, zurück auf: ${ALT:-<keins>}" >&2
docker compose logs --tail 50 website >&2 || true
if [[ -n "$ALT" ]]; then
  setze_image "$ALT"
  docker compose up -d --remove-orphans
fi
exit 1
