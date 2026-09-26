#!/usr/bin/env bash
# Builds the VulnVerdict image from this checkout and saves it into images/ so the appliance build can
# load it without a registry. Usage: ./save-image.sh <version>   (tags vulnverdict:<version>)
set -euo pipefail
VERSION="${1:?usage: save-image.sh <version>}"
cd "$(dirname "$0")"
root="$(cd ../.. && pwd)"
docker build --build-arg VV_VERSION="${VERSION}" -t "vulnverdict:${VERSION}" "$root"
rm -f images/*.tar.gz
docker save "vulnverdict:${VERSION}" | gzip -1 > "images/vulnverdict-${VERSION}.tar.gz"
ls -l "images/vulnverdict-${VERSION}.tar.gz"
