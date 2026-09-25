#!/usr/bin/env bash
# VulnVerdict update: pull a new image tag, keep the previous one for rollback, restart web and worker.
# Usage: ./update.sh [tag]   (default: latest published tag from the release channel in .env, or "latest")
# Opt-in by design: nothing updates until someone runs this.
set -euo pipefail
cd "$(dirname "$0")"
[ -f .env ] && set -a && . ./.env && set +a
TAG="${1:-${VV_CHANNEL:-latest}}"
IMAGE_BASE="${VV_IMAGE_BASE:-ghcr.io/ayrshirepixels/vulnverdict}"
NEW="${IMAGE_BASE}:${TAG}"
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

VV_IMAGE="${NEW}" docker compose up -d --no-build web worker
echo "Waiting for the console to answer..."
for i in $(seq 1 30); do
  if docker compose exec -T web curl -fsS http://localhost:8080/healthz >/dev/null 2>&1; then
    echo "Updated to ${NEW}. Migrations run automatically on start. Roll back with ./rollback.sh if anything is wrong."
    sed -i "s|^VV_IMAGE=.*|VV_IMAGE=${NEW}|" .env 2>/dev/null || echo "VV_IMAGE=${NEW}" >> .env
    exit 0
  fi
  sleep 2
done
echo "The console did not come up within 60 seconds. Rolling back." >&2
./rollback.sh
exit 1
