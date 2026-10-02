#!/usr/bin/env bash
# VulnVerdict update: move the stack (console, worker, database, TLS proxy) to a new release, and put all four back if
# the new one does not come up. Opt-in by design: nothing updates until someone runs this.
#
# Usage: ./update.sh [--dry-run] [--no-pull] [tag]
#   tag        release to move to (default: VV_CHANNEL from .env, or "latest")
#   --no-pull  the images are already on this machine (an air-gapped site that used docker load)
#   --dry-run  show what would be done; nothing is pulled, stopped, started or written
#
# What it does, in order:
#   1. notes the image each running container was started from, by image ID (a tag such as :latest moves; an ID does not)
#   2. pulls the new images; if they are what is already running, stops here
#   3. tags the noted images as :rollback, :rollback-db and :rollback-proxy and writes .rollback-state
#   4. stops the console and worker and dumps the database to backups/pre-update-<time>.dump, checked with
#      pg_restore --list, with a copy of the encryption keys beside it. No backup, no update: the old containers are
#      started again and the script stops
#   4b. takes the new release's update.sh, rollback.sh and restore.sh from its image, and its docker-compose.yml and
#      Caddyfile where the copies here are unedited (an edited one is left alone, the new one written as <name>.new)
#   5. starts the database, then the console and worker, then the proxy on the new images, checking each
#   6. if anything in step 5 fails, runs ./rollback.sh, which puts back all four images and, because the new console
#      may already have migrated the schema, the database from step 4
# Safe to run again: a second run with the same tag finds nothing to do.
set -euo pipefail
cd "$(dirname "$0")"

usage() { sed -n '2,22p' "$(basename "$0")" | sed 's/^# \{0,1\}//'; }
die() { echo "update: $*" >&2; exit 1; }

DRY_RUN=0
PULL=1
TAG_ARG=""
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --no-pull) PULL=0 ;;
    -h|--help) usage; exit 0 ;;
    -*) die "unknown option $arg (see --help)" ;;
    *) TAG_ARG="$arg" ;;
  esac
done

if [ -f .env ]; then
  set -a
  # shellcheck source=/dev/null
  . ./.env
  set +a
fi
TAG="${TAG_ARG:-${VV_CHANNEL:-latest}}"
IMAGE_BASE="${VV_IMAGE_BASE:-ghcr.io/ayrshirepixels/vulnverdict}"
NEW="${IMAGE_BASE}:${TAG}"
TIMEOUT="${VV_UPDATE_TIMEOUT:-180}"
STATE=.rollback-state
BACKUP_DIR=backups
KEEP_BACKUPS=3

# run a command that changes something; with --dry-run, print it instead
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

# -a: a container that has stopped or crashed still says which image it ran
container_of() { docker compose ps -a -q "$1" 2>/dev/null | head -n 1; }

# the ID of the image a service's container was created from, or nothing if there is no container
image_id_of() {
  local c
  c="$(container_of "$1")"
  if [ -n "$c" ]; then docker inspect --format '{{.Image}}' "$c" 2>/dev/null || true; fi
}

# the image name the container was created with (what .env said at the time)
image_ref_of() {
  local c
  c="$(container_of "$1")"
  if [ -n "$c" ]; then docker inspect --format '{{.Config.Image}}' "$c" 2>/dev/null || true; fi
}

local_image_id() { docker image inspect --format '{{.Id}}' "$1" 2>/dev/null || true; }

is_running() {
  local c
  c="$(container_of "$1")"
  [ -n "$c" ] && [ "$(docker inspect --format '{{.State.Running}} {{.State.Restarting}}' "$c" 2>/dev/null)" = "true false" ]
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

write_state() {
  if [ "$DRY_RUN" = 1 ]; then echo "  would write $STATE (status $1)"; return 0; fi
  local tmp
  tmp="$(mktemp "$STATE.XXXXXX")"
  {
    echo "# written by update.sh; read by rollback.sh"
    echo "STATUS='$1'"
    echo "STARTED='$STARTED'"
    echo "NEW_IMAGE='$NEW'"
    echo "PREV_WEB_REF='$PREV_WEB_REF'"
    echo "PREV_WEB_ID='$PREV_WEB_ID'"
    echo "PREV_DB_REF='$PREV_DB_REF'"
    echo "PREV_DB_ID='$PREV_DB_ID'"
    echo "PREV_PROXY_REF='$PREV_PROXY_REF'"
    echo "PREV_PROXY_ID='$PREV_PROXY_ID'"
    echo "MIGRATION_BEFORE='$MIGRATION_BEFORE'"
    echo "BACKUP='$BACKUP'"
    echo "KEYS='$KEYS'"
  } > "$tmp"
  chmod 600 "$tmp"
  mv "$tmp" "$STATE"
}

# ---------------------------------------------------------------- one update at a time
if [ "$DRY_RUN" = 0 ]; then
  if ! mkdir .update.lock 2>/dev/null; then die "another update is running (remove .update.lock if it is not)"; fi
  trap 'rmdir .update.lock 2>/dev/null || true' EXIT
fi

# ---------------------------------------------------------------- 1. what is running now
PREV_WEB_ID="$(image_id_of web)"
PREV_WEB_REF="$(image_ref_of web)"
PREV_WORKER_ID="$(image_id_of worker)"
PREV_DB_ID="$(image_id_of db)"
PREV_DB_REF="$(image_ref_of db)"
PREV_PROXY_ID="$(image_id_of proxy)"
PREV_PROXY_REF="$(image_ref_of proxy)"
STARTED="$(date -u +%Y%m%d-%H%M%S)"
MIGRATION_BEFORE=""
BACKUP=""
KEYS=""
DEPLOY_CHANGED=""

[ -n "$PREV_WEB_ID" ] || die "the console is not running in this folder. Start it with 'docker compose up -d' first; there is nothing to update from."
if ! docker compose exec -T db pg_isready -U vulnverdict -d vulnverdict >/dev/null 2>&1; then
  die "the database is not answering, so it cannot be backed up before the update. Fix that first (docker compose logs db)."
fi

echo "Running now:  ${PREV_WEB_REF} (${PREV_WEB_ID#sha256:})"
echo "Updating to:  ${NEW}"

# ---------------------------------------------------------------- 2. the new images
if [ "$PULL" = 1 ]; then
  run docker pull "$NEW" || die "could not pull ${NEW}. Nothing has been changed."
fi
NEW_ID="$(local_image_id "$NEW")"
if [ -z "$NEW_ID" ] && [ "$DRY_RUN" = 0 ]; then die "${NEW} is not on this machine. Nothing has been changed."; fi

# The database and TLS proxy images released with this version (Postgres 16 without gosu, Caddy built with the current
# Go release), where the Compose file takes them. Same Postgres major version and the same volumes, so nothing migrates.
NEW_DB=""
NEW_PROXY=""
if grep -q VV_DB_IMAGE docker-compose.yml; then
  case "$TAG" in
    latest) NEW_DB="${IMAGE_BASE}:db"; NEW_PROXY="${IMAGE_BASE}:proxy" ;;
    *) NEW_DB="${NEW}-db"; NEW_PROXY="${NEW}-proxy" ;;
  esac
  if [ "$PULL" = 1 ] && [ "$DRY_RUN" = 0 ]; then
    if ! { docker pull "$NEW_DB" && docker pull "$NEW_PROXY"; }; then NEW_DB=""; NEW_PROXY=""; fi
  elif [ "$PULL" = 1 ]; then
    echo "  would run: docker pull $NEW_DB; docker pull $NEW_PROXY"
  elif [ -z "$(local_image_id "$NEW_DB")" ] || [ -z "$(local_image_id "$NEW_PROXY")" ]; then
    NEW_DB=""; NEW_PROXY=""
  fi
  if [ -z "$NEW_DB" ]; then echo "No database and proxy images for ${TAG}; keeping the current ones."; fi
fi
NEW_DB_ID=""
NEW_PROXY_ID=""
if [ -n "$NEW_DB" ]; then NEW_DB_ID="$(local_image_id "$NEW_DB")"; NEW_PROXY_ID="$(local_image_id "$NEW_PROXY")"; fi

# Run twice, change once: if every container already runs the image the tag points at, there is nothing to do, and the
# rollback tags from the update that got here are left alone.
if [ -n "$NEW_ID" ] && [ "$NEW_ID" = "$PREV_WEB_ID" ] && [ "$NEW_ID" = "$PREV_WORKER_ID" ] \
   && { [ -z "$NEW_DB_ID" ] || [ "$NEW_DB_ID" = "$PREV_DB_ID" ]; } \
   && { [ -z "$NEW_PROXY_ID" ] || [ "$NEW_PROXY_ID" = "$PREV_PROXY_ID" ]; }; then
  echo "Already running ${NEW}. Nothing to do."
  exit 0
fi

# ---------------------------------------------------------------- 3. keep what runs now
# Tagged by image ID, noted before the pull: with TAG=latest the name the containers were started from now points at
# the new image, so tagging by name would keep the wrong one.
run docker tag "$PREV_WEB_ID" "${IMAGE_BASE}:rollback"
if [ -n "$PREV_DB_ID" ]; then run docker tag "$PREV_DB_ID" "${IMAGE_BASE}:rollback-db"; fi
if [ -n "$PREV_PROXY_ID" ]; then run docker tag "$PREV_PROXY_ID" "${IMAGE_BASE}:rollback-proxy"; fi
if [ "$DRY_RUN" = 0 ]; then MIGRATION_BEFORE="$(last_migration)"; fi
write_state started

# changelog for the release, if the image carries one
if [ "$DRY_RUN" = 0 ]; then
  docker run --rm --entrypoint sh "$NEW" -c 'cat /app/CHANGELOG.md 2>/dev/null | head -60' || true
fi

# ---------------------------------------------------------------- 4. backup before the new console migrates the schema
# The console and worker are stopped first, so the dump is exactly what the old version left and nothing is written
# between the dump and the new version starting.
pre_update_backup() {
  local file="$BACKUP_DIR/pre-update-$STARTED.dump"
  ( umask 077; mkdir -p "$BACKUP_DIR" )
  chmod 700 "$BACKUP_DIR"
  rm -f "$file.tmp"
  if ! ( umask 077; docker compose exec -T db pg_dump -U vulnverdict -d vulnverdict --format=custom > "$file.tmp" ); then
    rm -f "$file.tmp"; echo "pg_dump failed." >&2; return 1
  fi
  if [ ! -s "$file.tmp" ]; then rm -f "$file.tmp"; echo "pg_dump wrote nothing." >&2; return 1; fi
  # read the dump back: a dump that does not list, or lists no table data, is not a backup
  # (grep -c reads to the end; grep -q would hang up on pg_restore and fail the pipeline)
  if ! docker compose exec -T db pg_restore --list < "$file.tmp" | grep -c "TABLE DATA" >/dev/null; then
    rm -f "$file.tmp"; echo "The dump did not verify (pg_restore --list)." >&2; return 1
  fi
  mv "$file.tmp" "$file"
  BACKUP="$file"
  # The encryption keys as they are now. The new console may rewrite them in place (VV_KEY_SECRET wraps every key file),
  # and an older console cannot read a wrapped key: rollback.sh puts these back, or every saved credential is lost.
  local keys="$BACKUP_DIR/pre-update-$STARTED.keys.tar"
  if ( umask 077; docker compose run --rm --no-deps -T --entrypoint tar web -C /data -cf - keys > "$keys.tmp" ) \
     && tar -tf "$keys.tmp" 2>/dev/null | grep -q '\.xml$'; then
    mv "$keys.tmp" "$keys"; KEYS="$keys"
  else
    rm -f "$keys.tmp"
    echo "The encryption keys could not be copied; a rollback after this update will keep the keys as the new version leaves them." >&2
  fi
  # keep the last few; older pre-update dumps and key copies go
  # shellcheck disable=SC2012
  ls -1t "$BACKUP_DIR"/pre-update-*.dump 2>/dev/null | tail -n +$((KEEP_BACKUPS + 1)) | while IFS= read -r old; do rm -f "$old" "${old%.dump}.keys.tar"; done
}

echo "Stopping the console and worker..."
run docker compose stop web worker
echo "Backing up the database..."
if [ "$DRY_RUN" = 1 ]; then
  echo "  would dump the database to $BACKUP_DIR/pre-update-$STARTED.dump and check it with pg_restore --list"
elif pre_update_backup; then
  echo "Backup: $BACKUP ($(wc -c < "$BACKUP" | tr -d ' ') bytes)"
  write_state started
else
  echo "The database could not be backed up, so the update is not going ahead. Starting the current version again." >&2
  docker compose start web worker || true
  write_state aborted
  exit 1
fi

# ---------------------------------------------------------------- 4b. this release's Compose file, Caddyfile and scripts
# Every console image carries the deploy files of its release in /app/deploy (images before 1.2 do not; then nothing
# here changes). The scripts are ours and are replaced. docker-compose.yml and the Caddyfile are replaced only when this
# folder's copy is exactly the one the running release shipped, so nobody's edits are overwritten; an edited copy is
# kept and the new one is written beside it as <name>.new. A replaced file is kept as <name>.before-<time>.
release_files() {
  mkdir -p "$2"
  docker run --rm --entrypoint tar "$1" -C /app/deploy -cf - . 2>/dev/null | tar -xf - -C "$2" 2>/dev/null
}

refresh_deploy_files() {
  local new old f
  new="$(mktemp -d)"; old="$(mktemp -d)"
  if ! release_files "$NEW" "$new" || [ ! -s "$new/docker-compose.yml" ]; then rm -rf "$new" "$old"; return 0; fi
  release_files "$PREV_WEB_ID" "$old" || true
  for f in docker-compose.yml Caddyfile; do
    if [ ! -f "$new/$f" ] || [ ! -f "$f" ] || cmp -s "$f" "$new/$f"; then continue; fi
    if [ -f "$old/$f" ] && cmp -s "$f" "$old/$f"; then
      cp -p "$f" "$f.before-$STARTED" && cp "$new/$f" "$f.tmp" && mv "$f.tmp" "$f"
      DEPLOY_CHANGED="$DEPLOY_CHANGED $f"
      echo "Updated $f to the ${TAG} one (the previous one is kept as $f.before-$STARTED)."
    else
      cp "$new/$f" "$f.new"
      echo "NOTE: $f here is not the one the running version shipped (edited, or from before 1.2), so it is left as it is." >&2
      echo "      The ${TAG} one is in $f.new: compare the two, merge, and run 'docker compose up -d'." >&2
    fi
  done
  # replaced by rename: this script keeps running from the copy it started with
  for f in update.sh rollback.sh restore.sh; do
    if [ -f "$new/$f" ]; then cp "$new/$f" "$f.tmp" && chmod 755 "$f.tmp" && mv "$f.tmp" "$f"; fi
  done
  if [ -f "$new/.env.example" ]; then cp "$new/.env.example" .env.example; fi
  rm -rf "$new" "$old"
}

if [ "$DRY_RUN" = 1 ]; then
  echo "  would take this release's update.sh, rollback.sh and restore.sh from $NEW, and its docker-compose.yml and Caddyfile where the copies here are unedited"
else
  refresh_deploy_files
fi

# ---------------------------------------------------------------- 5. the new images, one tier at a time
roll_back() {
  echo "$1 Rolling back." >&2
  # the Compose file and Caddyfile this run replaced go back first: the older images are started under the older file
  for f in $DEPLOY_CHANGED; do if [ -f "$f.before-$STARTED" ]; then cp -p "$f.before-$STARTED" "$f"; fi; done
  ./rollback.sh --auto || echo "The rollback did not finish; see the messages above and docs/install.md." >&2
  exit 1
}

# exported: .env was loaded into this shell above, and its old values would otherwise win for the rest of the script
export VV_IMAGE="$NEW"
if [ -n "$NEW_DB" ]; then export VV_DB_IMAGE="$NEW_DB" VV_PROXY_IMAGE="$NEW_PROXY"; fi

if [ "$DRY_RUN" = 1 ]; then
  if [ -n "$NEW_DB" ]; then echo "  would start db on $NEW_DB and wait for it to be healthy"; fi
  echo "  would start web and worker on $NEW and wait up to ${TIMEOUT}s for /healthz"
  if [ -n "$NEW_PROXY" ]; then echo "  would start proxy on $NEW_PROXY"; fi
  echo "  on any failure: ./rollback.sh --auto (all four images back, database restored from the backup)"
  set_env VV_IMAGE "$NEW"
  echo "Dry run complete. Nothing was changed."
  exit 0
fi

if [ -n "$NEW_DB" ] && [ "$NEW_DB_ID" != "$PREV_DB_ID" ]; then
  echo "Starting the database on ${NEW_DB}..."
  docker compose up -d --no-build --no-deps --wait db || roll_back "The database did not come up on the new image."
fi

echo "Starting the console and worker on ${NEW}..."
docker compose up -d --no-build --no-deps web worker || roll_back "The new console could not be started."
echo "Waiting for the console to answer (up to ${TIMEOUT}s; migrations run on start)..."
wait_for_console || roll_back "The console did not come up within ${TIMEOUT} seconds."
is_running worker || roll_back "The worker is not running on the new image."

if [ -n "$NEW_PROXY" ] && [ "$NEW_PROXY_ID" != "$PREV_PROXY_ID" ]; then
  echo "Starting the TLS proxy on ${NEW_PROXY}..."
  docker compose up -d --no-build --no-deps proxy || roll_back "The proxy could not be started on the new image."
  sleep 3
  is_running proxy || roll_back "The proxy does not stay up on the new image."
fi

# ---------------------------------------------------------------- done: only now does .env change
set_env VV_IMAGE "$NEW"
if [ -n "$NEW_DB" ]; then set_env VV_DB_IMAGE "$NEW_DB"; set_env VV_PROXY_IMAGE "$NEW_PROXY"; fi
write_state updated
echo "Updated to ${NEW}."
echo "The previous version is kept: ./rollback.sh puts back all four images and offers to restore ${BACKUP}."
