#!/usr/bin/env bash
# Builds the VulnVerdict images from this checkout (the console, and the stack's database and TLS proxy) and saves
# them into images/ so the appliance build can load them without a registry.
# Usage: ./save-image.sh <version>   (tags vulnverdict:<version>, vulnverdict:<version>-db and vulnverdict:<version>-proxy)
set -euo pipefail
VERSION="${1:?usage: save-image.sh <version>}"
cd "$(dirname "$0")"
root="$(cd ../.. && pwd)"
docker build --build-arg VV_VERSION="${VERSION}" -t "vulnverdict:${VERSION}" "$root"
rm -f images/*.tar.gz
docker build -t "vulnverdict:${VERSION}-db" -f "$root/deploy/images/db.Dockerfile" "$root/deploy/images"
docker build -t "vulnverdict:${VERSION}-proxy" -f "$root/deploy/images/proxy.Dockerfile" "$root/deploy/images"
docker save "vulnverdict:${VERSION}" "vulnverdict:${VERSION}-db" "vulnverdict:${VERSION}-proxy" | gzip -1 > "images/vulnverdict-${VERSION}.tar.gz"
ls -l "images/vulnverdict-${VERSION}.tar.gz"
