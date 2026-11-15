#!/usr/bin/env bash
# VulnVerdict automatic patch updates (opt-in). Run nightly by a systemd timer on the appliance, or by cron on a
# Compose host (docs/install.md, "Automatic patch updates"). Does nothing unless .env says VV_AUTO_UPDATE=patch.
#
# If the latest release is a patch of the running one (1.2.3 to 1.2.4, never 1.2 to 1.3), it runs ./update.sh, which
# backs up the database and keys, moves all four images and rolls everything back by itself if the new version does
# not come up. The outcome is written into the console's database, so the console shows a failure as a banner and the
# digest mentions a success; the full output goes to auto-update.log in this folder.
#
# Usage: ./auto-update.sh [--dry-run]
set -euo pipefail
cd "$(dirname "$0")"

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1
if [ -f .env ]; then
  set -a
  # shellcheck source=/dev/null
  . ./.env
  set +a
fi
LOG=auto-update.log
log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" | tee -a "$LOG"; }

case "${VV_AUTO_UPDATE:-off}" in
  patch) ;;
  *) [ "$DRY_RUN" = 1 ] && echo "VV_AUTO_UPDATE is not 'patch' in .env: nothing to do."; exit 0 ;;
esac

RELEASES="${VV_RELEASES_URL:-https://api.github.com/repos/ayrshirepixels/VulnVerdict/releases/latest}"

# the version the running console reports, and the latest release's
current="$(docker compose exec -T web printenv VV_VERSION 2>/dev/null | tr -d '[:space:]' || true)"
latest="$(curl -fsSL -m 30 -H 'Accept: application/vnd.github+json' "$RELEASES" 2>/dev/null \
  | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\{0,1\}\([0-9][0-9.]*\)".*/\1/p' | head -n 1 || true)"

is_version() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; }
if ! is_version "$current"; then log "skipped: the console does not report a release version ('${current:-nothing}'), so it is left alone"; exit 0; fi
if ! is_version "$latest"; then log "skipped: could not read the latest release from $RELEASES"; exit 0; fi

IFS=. read -r cmaj cmin cpat <<<"$current"
IFS=. read -r lmaj lmin lpat <<<"$latest"
if [ "$lmaj" != "$cmaj" ] || [ "$lmin" != "$cmin" ]; then
  # a minor or major release can change behaviour (everyone signing in again, new settings): a person chooses when
  [ "$(( lmaj * 1000 + lmin ))" -gt "$(( cmaj * 1000 + cmin ))" ] && log "not applied: $latest is a new minor or major release, not a patch of $current. Read its notes and run ./update.sh $latest by hand."
  exit 0
fi
if [ "$lpat" -le "$cpat" ]; then exit 0; fi   # up to date

# the outcome, into the console's settings table, where the console and the digest read it
record() {
  local msg="${4//[|\'\\]/ }" at value
  at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  value="$1|$2|$3|$at|${msg:0:300}"
  docker compose exec -T db psql -q -U vulnverdict -d vulnverdict -v ON_ERROR_STOP=1 -c \
    "INSERT INTO \"Settings\" (\"Key\", \"Value\", \"Encrypted\", \"UpdatedAt\") VALUES ('state:update:auto', '$value', false, now())
     ON CONFLICT (\"Key\") DO UPDATE SET \"Value\" = EXCLUDED.\"Value\", \"Encrypted\" = false, \"UpdatedAt\" = now();" >/dev/null 2>&1 \
    || log "could not record the result in the console's database"
}

if [ "$DRY_RUN" = 1 ]; then echo "would run ./update.sh $latest (running $current)"; exit 0; fi

log "updating $current to $latest"
status=0
./update.sh "$latest" >>"$LOG" 2>&1 || status=$?
state="$(sed -n "s/^STATUS='\(.*\)'$/\1/p" .rollback-state 2>/dev/null || true)"
if [ "$status" = 0 ] && [ "$(docker compose exec -T web printenv VV_VERSION 2>/dev/null | tr -d '[:space:]')" = "$latest" ]; then
  log "updated to $latest"; record ok "$current" "$latest" ""
elif [ "$state" = "rolled-back" ]; then
  log "update to $latest did not come up and was rolled back (see above)"; record rolled-back "$current" "$latest" ""
else
  # update.sh's own last words say why (could not pull, could not back up), before this script adds its line
  reason="$(grep -v '^[[:space:]]*$' "$LOG" | tail -n 1 | sed 's/^update: //')"
  log "update to $latest failed before anything changed (status $status, see above)"; record failed "$current" "$latest" "$reason"
fi
