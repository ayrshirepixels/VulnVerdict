#!/usr/bin/env bash
# VulnVerdict update: pull a new image tag, keep the previous one for rollback, restart web and worker. The database
# and TLS proxy move to the images released with the same tag.
# Usage: ./update.sh [tag]   (default: latest published tag from the release channel in .env, or "latest")
# Opt-in by design: nothing updates until someone runs this.
set -euo pipefail
cd "$(dirname "$0")"
[ -f .env ] && set -a && . ./.env && set +a
TAG="${1:-${VV_CHANNEL:-latest}}"
IMAGE_BASE="${VV_IMAGE_BASE:-ghcr.io/ayrshirepixels/vulnverdict}"
NEW="${IMAGE_BASE}:${TAG}"
set_env() { if grep -q "^$1=" .env 2>/dev/null; then sed -i "s|^$1=.*|$1=$2|" .env; else echo "$1=$2" >> .env; fi; }
CURRENT="$(docker compose images web --format json 2>/dev/null | sed -n 's/.*"Repository":"\([^"]*\)".*"Tag":"\([^"]*\)".*/\1:\2/p' | head -1 || true)"

echo "Current image: ${CURRENT:-none}"
echo "New image:     ${NEW}"
docker pull "${NEW}"

# keep the current image under a rollback tag before switching
if [ -n "${CURRENT}" ]; then
  docker tag "${CURRENT}" "${IMAGE_BASE}:rollback" || true
  echo "${CURRENT}" > .rollback-image
fi

# changelog for the release, if the image carries one
docker run --rm --entrypoint sh "${NEW}" -c 'cat /app/CHANGELOG.md 2>/dev/null | head -60' || true

# The database and TLS proxy images released with this version (Postgres 16 without gosu, Caddy built with the current
# Go release), where the Compose file takes them. Same Postgres major version and the same volumes, so nothing migrates.
if grep -q VV_DB_IMAGE docker-compose.yml; then
  case "${TAG}" in latest) DB="${IMAGE_BASE}:db"; PROXY="${IMAGE_BASE}:proxy" ;; *) DB="${NEW}-db"; PROXY="${NEW}-proxy" ;; esac
  if docker pull "${DB}" && docker pull "${PROXY}"; then
    # exported: .env was loaded into this shell above, and its old values would otherwise win for the rest of the script
    export VV_DB_IMAGE="${DB}" VV_PROXY_IMAGE="${PROXY}"
    docker compose up -d --no-build --no-deps --wait db
    docker compose up -d --no-build --no-deps proxy
    set_env VV_DB_IMAGE "${DB}"; set_env VV_PROXY_IMAGE "${PROXY}"
  else
    echo "No database and proxy images for ${TAG}; keeping the current ones."
  fi
fi

VV_IMAGE="${NEW}" docker compose up -d --no-build --no-deps web worker
echo "Waiting for the console to answer..."
for i in $(seq 1 30); do
  if docker compose exec -T web curl -fsS http://localhost:8080/healthz >/dev/null 2>&1; then
    echo "Updated to ${NEW}. Migrations run automatically on start. Roll back with ./rollback.sh if anything is wrong."
    set_env VV_IMAGE "${NEW}"
    exit 0
  fi
  sleep 2
done
echo "The console did not come up within 60 seconds. Rolling back." >&2
./rollback.sh
exit 1
