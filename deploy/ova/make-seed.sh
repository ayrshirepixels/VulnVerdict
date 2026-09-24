#!/usr/bin/env bash
# Builds seed/seed.iso (volume label CIDATA) from seed/user-data and seed/meta-data. The Hyper-V build
# attaches it as a second DVD; Ubuntu's installer finds the autoinstall answers on it by its label.
# Needs Docker only.
set -euo pipefail
cd "$(dirname "$0")/seed"
here="$(pwd -W 2>/dev/null || pwd)"
MSYS_NO_PATHCONV=1 docker run --rm -v "$here:/seed" -w /seed alpine:3.20 sh -c \
  'apk add --no-cache xorriso >/dev/null && xorriso -as mkisofs -quiet -output seed.iso -volid CIDATA -joliet -rock user-data meta-data'
ls -l seed.iso
