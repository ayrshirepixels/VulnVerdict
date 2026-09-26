#!/usr/bin/env bash
# Packs what a Docker Compose install needs (compose file, Caddyfile, .env.example set to the release's image,
# update and rollback scripts) into vulnverdict-compose.tar.gz, attached to every GitHub release so that
#   curl -fsSL https://github.com/ayrshirepixels/VulnVerdict/releases/latest/download/vulnverdict-compose.tar.gz | tar -xz
# fetches the latest release's files. Usage: deploy/make-compose-bundle.sh <version> <output dir>
set -euo pipefail
VERSION="${1:?usage: make-compose-bundle.sh <version> <output dir>}"
OUT="${2:?usage: make-compose-bundle.sh <version> <output dir>}"
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
d="$work/vulnverdict"; mkdir -p "$d" "$OUT"
# the bundle runs published images only, so the build sections (which point into a checkout) are dropped
sed '/^    build: \.\.$/d' "$here/docker-compose.yml" > "$d/docker-compose.yml"
sed "s|^VV_IMAGE=.*|VV_IMAGE=ghcr.io/ayrshirepixels/vulnverdict:${VERSION}|; s|^# Comment it out to build from a checkout.*|# (This file came from the ${VERSION} release bundle.)|" "$here/.env.example" > "$d/.env.example"
cp "$here/Caddyfile" "$d/"
install -m 0755 "$here/update.sh" "$here/rollback.sh" "$d/"
grep -q "^VV_IMAGE=ghcr.io/ayrshirepixels/vulnverdict:${VERSION}$" "$d/.env.example"
! grep -q "build:" "$d/docker-compose.yml"
tar -czf "$OUT/vulnverdict-compose.tar.gz" -C "$work" vulnverdict
echo "$OUT/vulnverdict-compose.tar.gz"
