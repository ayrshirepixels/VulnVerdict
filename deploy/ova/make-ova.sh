#!/usr/bin/env bash
# Packages the Hyper-V build's disk as a standard OVA:  ./make-ova.sh <version>
#   output/hyperv-<version>/Virtual Hard Disks/*.vhdx
#     -> output/vulnverdict-<version>.ova          (OVF 1.0 + SHA-256 manifest + streamOptimized VMDK, USTAR)
#     -> output/vulnverdict-<version>-hyperv.vhdx  (for Hyper-V: generation 1 VM)
#     -> output/vulnverdict-<version>.sha256
# The VirtualBox build exports its own OVA and doesn't need this. Needs Docker (for qemu-img) and tar.
set -euo pipefail
VERSION="${1:?usage: make-ova.sh <version>}"
cd "$(dirname "$0")"
NAME="vulnverdict-${VERSION}"
VHDX="$(ls output/hyperv-"${VERSION}"/Virtual\ Hard\ Disks/*.vhdx 2>/dev/null | head -1 || true)"
[ -n "$VHDX" ] || { echo "no VHDX under output/hyperv-${VERSION}/ - run the Hyper-V build first" >&2; exit 1; }

STAGE="output/ova-${VERSION}"
rm -rf "$STAGE" && mkdir -p "$STAGE"
cp "$VHDX" "$STAGE/source.vhdx"
DISK="${NAME}-disk1.vmdk"
here="$(pwd -W 2>/dev/null || pwd)"

# streamOptimized VMDK: compressed, the format OVAs carry.
MSYS_NO_PATHCONV=1 docker run --rm -v "$here/$STAGE:/w" -w /w alpine:3.20 sh -c "
  apk add --no-cache qemu-img >/dev/null &&
  qemu-img convert -p -O vmdk -o subformat=streamOptimized,adapter_type=lsilogic source.vhdx '$DISK' &&
  qemu-img info --output=json source.vhdx > info.json"
rm -f "$STAGE/source.vhdx"

CAPACITY="$(node -e "console.log(JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'))['virtual-size'])" "$STAGE/info.json")"
FILE_SIZE="$(stat -c %s "$STAGE/$DISK")"
rm -f "$STAGE/info.json"

sed -e "s|@NAME@|${NAME}|g" -e "s|@VERSION@|${VERSION}|g" -e "s|@DISK_FILE@|${DISK}|g" \
    -e "s|@DISK_FILE_SIZE@|${FILE_SIZE}|g" -e "s|@DISK_CAPACITY@|${CAPACITY}|g" \
    vulnverdict.ovf.template > "$STAGE/${NAME}.ovf"

( cd "$STAGE"
  for f in "${NAME}.ovf" "$DISK"; do echo "SHA256($f)= $(sha256sum "$f" | cut -d' ' -f1)"; done > "${NAME}.mf"
  # The OVF must be the first entry in an OVA, then the manifest, then the disk.
  tar --format=ustar -cf "../${NAME}.ova" "${NAME}.ovf" "${NAME}.mf" "$DISK" )
# A Hyper-V disk made from the OVA's own VMDK: the same conversion docs/install.md gives Hyper-V users,
# so shipping it (and testing with it) proves that path. Dynamic, so the zeroed free space costs nothing.
MSYS_NO_PATHCONV=1 docker run --rm -v "$here/$STAGE:/w" -w /w alpine:3.20 sh -c "
  apk add --no-cache qemu-img >/dev/null &&
  qemu-img convert -O vhdx -o subformat=dynamic '$DISK' '${NAME}-hyperv.vhdx'"
mv "$STAGE/${NAME}-hyperv.vhdx" output/
( cd output && sha256sum "${NAME}.ova" "${NAME}-hyperv.vhdx" > "${NAME}.sha256" )
rm -rf "$STAGE"
ls -l "output/${NAME}.ova" "output/${NAME}-hyperv.vhdx"
cat "output/${NAME}.sha256"
