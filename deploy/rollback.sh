#!/usr/bin/env bash
# VulnVerdict rollback: put the stack back on the images that ran before the last update.sh: console, worker, database
# and TLS proxy. A newer console may have changed the database schema, which the older console cannot be assumed to
# run against, so when the schema has moved the database is restored from the dump update.sh took just before.
#
# Usage: ./rollback.sh [--restore-db | --keep-db] [--yes] [--dry-run]
#   --restore-db  restore the pre-update database dump (everything written since the update is lost)
#   --keep-db     keep the database as it is, whatever the schema
#   --yes         do not ask for confirmation
#   --dry-run     show what would be done; nothing is stopped, started, restored or written
# The encryption keys copied before the update are always put back, so the older console can read what it saved.
# With neither --restore-db nor --keep-db: if the schema has not moved, the database is kept; if it has, the script
# asks (and, with nobody to ask, stops without changing anything). update.sh calls this with --auto after a failed
# update, which restores without asking: the new version never served anyone.
# Safe to run again: it always returns to the same images and the same dump.
set -euo pipefail
cd "$(dirname "$0")"

usage() { sed -n '2,15p' "$(basename "$0")" | sed 's/^# \{0,1\}//'; }
die() { echo "rollback: $*" >&2; exit 1; }

MODE=ask
YES=0
DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --restore-db) MODE=restore ;;
    --keep-db) MODE=keep ;;
    --auto) MODE=auto; YES=1 ;;
    --yes|-y) YES=1 ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option $arg (see --help)" ;;
  esac
done

if [ -f .env ]; then
  set -a
  # shellcheck source=/dev/null
  . ./.env
  set +a
fi
IMAGE_BASE="${VV_IMAGE_BASE:-ghcr.io/ayrshirepixels/vulnverdict}"
TIMEOUT="${VV_UPDATE_TIMEOUT:-180}"
STATE=.rollback-state

run() {
  if [ "$DRY_RUN" = 1 ]; then echo "  would run: $*"; else "$@"; fi
}

set_env() {
  if [ "$DRY_RUN" = 1 ]; then echo "  would set $1=$2 in .env"; return 0; fi
  local tmp
  tmp="$(mktemp .env.XXXXXX)"
  if [ -f .env ]; then grep -v "^$1=" .env > "$tmp" || true; fi
  echo "$1=$2" >> "$tmp"
  chmod 600 "$tmp"
  mv "$tmp" .env
}

local_image_id() { docker image inspect --format '{{.Id}}' "$1" 2>/dev/null || true; }
container_of() { docker compose ps -a -q "$1" 2>/dev/null | head -n 1; }

image_id_of() {
  local c
  c="$(container_of "$1")"
  if [ -n "$c" ]; then docker inspect --format '{{.Image}}' "$c" 2>/dev/null || true; fi
}

console_answers() { docker compose exec -T web curl -fsS http://localhost:8080/healthz >/dev/null 2>&1; }

wait_for_console() {
  local waited=0
  while [ "$waited" -lt "$TIMEOUT" ]; do
    if console_answers; then return 0; fi
    sleep 2
    waited=$((waited + 2))
  done
  return 1
}

last_migration() {
  docker compose exec -T db psql -U vulnverdict -d vulnverdict -tAc 'SELECT "MigrationId" FROM "__EFMigrationsHistory" ORDER BY "MigrationId" DESC LIMIT 1' 2>/dev/null | tr -d '[:space:]' || true
}

# The name to start a previous image by: the name it had, if that still points at the same image; otherwise the
# rollback tag update.sh put on it (with TAG=latest the old name now points at the new image).
target_for() {
  local ref="$1" id="$2" tag="$3"
  if [ -z "$id" ]; then return 0; fi
  if [ -n "$ref" ] && [ "$(local_image_id "$ref")" = "$id" ]; then echo "$ref"; return 0; fi
  if [ "$(local_image_id "$tag")" = "$id" ]; then echo "$tag"; return 0; fi
  die "the previous image ${ref:-$tag} (${id#sha256:}) is no longer on this machine, so it cannot be put back."
}

# ---------------------------------------------------------------- what to go back to
STATUS=""
PREV_WEB_REF=""
PREV_WEB_ID=""
PREV_DB_REF=""
PREV_DB_ID=""
PREV_PROXY_REF=""
PREV_PROXY_ID=""
MIGRATION_BEFORE=""
BACKUP=""
KEYS=""
NEW_IMAGE=""
if [ -f "$STATE" ]; then
  # shellcheck source=/dev/null
  . "./$STATE"
  WEB_TARGET="$(target_for "$PREV_WEB_REF" "$PREV_WEB_ID" "${IMAGE_BASE}:rollback")"
  DB_TARGET="$(target_for "$PREV_DB_REF" "$PREV_DB_ID" "${IMAGE_BASE}:rollback-db")"
  PROXY_TARGET="$(target_for "$PREV_PROXY_REF" "$PREV_PROXY_ID" "${IMAGE_BASE}:rollback-proxy")"
else
  # an update made by an earlier update.sh, which kept the console image only
  WEB_TARGET="$(cat .rollback-image 2>/dev/null || echo "${IMAGE_BASE}:rollback")"
  DB_TARGET=""
  PROXY_TARGET=""
  [ -n "$(local_image_id "$WEB_TARGET")" ] || die "no update has been recorded here (no $STATE), so there is nothing to roll back to."
fi
[ -n "$WEB_TARGET" ] || die "$STATE does not say which console image ran before the update."

echo "Rolling back${NEW_IMAGE:+ from $NEW_IMAGE} to ${WEB_TARGET}${STATUS:+ (last update: $STATUS)}"
export VV_IMAGE="$WEB_TARGET"
if [ -n "$DB_TARGET" ]; then export VV_DB_IMAGE="$DB_TARGET"; fi
if [ -n "$PROXY_TARGET" ]; then export VV_PROXY_IMAGE="$PROXY_TARGET"; fi

db_answers() { docker compose exec -T db pg_isready -U vulnverdict -d vulnverdict >/dev/null 2>&1; }

database_back() {
  if [ -n "$DB_TARGET" ] && [ "$(image_id_of db)" != "$PREV_DB_ID" ]; then
    echo "Putting the database back on ${DB_TARGET}..."
    run docker compose up -d --no-build --no-deps --wait db
  elif ! db_answers; then
    run docker compose up -d --no-build --no-deps --wait db
  fi
}

# ---------------------------------------------------------------- has the schema moved?
# The check needs a database that answers. While the running one does, nothing is touched until the decision below is
# made; if it does not (the new database image is the trouble), the previous image goes back first.
if ! db_answers; then database_back; fi
MIGRATION_NOW="$(last_migration)"
RESTORE=0
case "$MODE" in
  restore) RESTORE=1 ;;
  keep) RESTORE=0 ;;
  *)
    if [ -f "$STATE" ] && [ "$MIGRATION_NOW" != "$MIGRATION_BEFORE" ]; then
      echo "The database schema has moved since the update (was ${MIGRATION_BEFORE:-unknown}, now ${MIGRATION_NOW:-unknown})."
      if [ -z "$BACKUP" ] || [ ! -f "$BACKUP" ]; then
        echo "There is no pre-update dump to restore (${BACKUP:-none recorded}). The older console may not run against this schema." >&2
        if [ "$MODE" != auto ]; then
          die "nothing has been changed. Run again with --keep-db to go back without restoring, or restore a backup with ./restore.sh first."
        fi
      elif [ "$MODE" = auto ] || [ "$YES" = 1 ]; then
        RESTORE=1
      elif [ -t 0 ]; then
        echo "Restoring ${BACKUP} puts the database back as it was just before the update."
        echo "Everything recorded since then (verdict changes, settings, new connectors) is lost."
        read -r -p "Restore the database from that dump? [y/N] " answer
        case "$answer" in
          y|Y|yes|YES) RESTORE=1 ;;
          *) die "nothing has been changed. Run again with --restore-db, or with --keep-db to keep the database as it is." ;;
        esac
      else
        die "the schema has moved and there is nobody to ask. Run again with --restore-db (restores ${BACKUP}) or --keep-db. Nothing has been changed."
      fi
    fi
    ;;
esac
if [ "$RESTORE" = 1 ]; then
  if [ -z "$BACKUP" ] || [ ! -f "$BACKUP" ]; then die "there is no pre-update dump to restore (${BACKUP:-none recorded})."; fi
  if [ ! -x ./restore.sh ]; then die "restore.sh is not in this folder; it does the restoring."; fi
fi

# ---------------------------------------------------------------- console and worker off, database back, console and worker on
echo "Stopping the console and worker..."
run docker compose stop web worker
database_back
if [ "$RESTORE" = 1 ]; then
  echo "Restoring the database from ${BACKUP}..."
  run ./restore.sh --yes --no-restart "$BACKUP"
fi

# The encryption keys as they were before the update: the newer console may have rewritten them (VV_KEY_SECRET wraps
# every key file) in a form the older one cannot read. Keys made since are left in place.
if [ -n "$KEYS" ] && [ -f "$KEYS" ]; then
  echo "Putting back the encryption keys from before the update..."
  if [ "$DRY_RUN" = 1 ]; then echo "  would unpack $KEYS into /data"
  else docker compose run --rm --no-deps -T --entrypoint tar web -C /data -xf - < "$KEYS" || die "the keys in $KEYS could not be put back; the console and worker are stopped. Run again, or see docs/install.md."
  fi
fi

echo "Starting the console and worker on ${WEB_TARGET}..."
run docker compose up -d --no-build --no-deps web worker
if [ -n "$PROXY_TARGET" ] && [ "$(image_id_of proxy)" != "$PREV_PROXY_ID" ]; then
  echo "Putting the TLS proxy back on ${PROXY_TARGET}..."
  run docker compose up -d --no-build --no-deps proxy
fi

set_env VV_IMAGE "$WEB_TARGET"
if [ -n "$DB_TARGET" ]; then set_env VV_DB_IMAGE "$DB_TARGET"; fi
if [ -n "$PROXY_TARGET" ]; then set_env VV_PROXY_IMAGE "$PROXY_TARGET"; fi

if [ "$DRY_RUN" = 1 ]; then echo "Dry run complete. Nothing was changed."; exit 0; fi

if [ -f "$STATE" ]; then
  tmp="$(mktemp "$STATE.XXXXXX")"
  grep -v '^STATUS=' "$STATE" > "$tmp" || true
  echo "STATUS='rolled-back'" >> "$tmp"
  chmod 600 "$tmp"
  mv "$tmp" "$STATE"
fi

echo "Waiting for the console to answer..."
if wait_for_console; then
  if [ "$RESTORE" = 1 ]; then
    echo "Done. The console is back on ${WEB_TARGET}, with the database as it was before the update."
  else
    echo "Done. The console is back on ${WEB_TARGET}."
  fi
else
  echo "The console is on ${WEB_TARGET} again but is not answering yet. Look at: docker compose logs web" >&2
  exit 1
fi
