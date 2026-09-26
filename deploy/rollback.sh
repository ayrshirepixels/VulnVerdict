#!/usr/bin/env bash
# VulnVerdict rollback: switch web and worker back to the image that ran before the last update.sh.
# Database migrations are additive, so an older image runs against the newer schema.
set -euo pipefail
cd "$(dirname "$0")"
[ -f .env ] && set -a && . ./.env && set +a
IMAGE_BASE="${VV_IMAGE_BASE:-ghcr.io/ayrshirepixels/vulnverdict}"
PREV="$(cat .rollback-image 2>/dev/null || echo "${IMAGE_BASE}:rollback")"
echo "Rolling back to ${PREV}"
VV_IMAGE="${PREV}" docker compose up -d --no-build --no-deps web worker
sed -i "s|^VV_IMAGE=.*|VV_IMAGE=${PREV}|" .env 2>/dev/null || echo "VV_IMAGE=${PREV}" >> .env
echo "Done. The console is back on ${PREV}."
