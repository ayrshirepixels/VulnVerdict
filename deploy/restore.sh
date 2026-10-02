#!/usr/bin/env bash
# VulnVerdict restore: put a backup back. Replaces the database (and, from a console backup, the data-protection keys
# that decrypt the credentials stored in it). See docs/backup.md.
#
# Usage: ./restore.sh [options] <backup>
#        ./restore.sh --list
#   <backup>  a console backup (vulnverdict-<time>-<kind>.vvbak, or .vvbak.enc if encrypted): a path on this machine,
#             or just the file name to take it from the stack's backups folder;
#             or a pre-update dump written by update.sh (backups/pre-update-<time>.dump)
#   --list              list the console backups in the stack's backups folder
#   --yes               do not ask for confirmation
#   --db-only           restore the database but leave the data-protection keys as they are
#   --no-restart        leave the console and worker stopped afterwards (rollback.sh starts them itself)
#   --container NAME    restore into the all-in-one container NAME instead of the Compose stack in this folder
#   --dry-run           check the backup and show what would be done; nothing is changed
# An encrypted backup needs its passphrase: set VV_BACKUP_PASSPHRASE, or type it when asked.
#
# The Postgres restore goes into a new database beside the live one and the two are swapped only when it has loaded
# completely, so a restore that fails part-way leaves the console as it was. The database that was live is kept as
# vulnverdict_before_restore until the next restore.
set -euo pipefail
cd "$(dirname "$0")"

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "restore: $*" >&2; exit 1; }

YES=0
DB_ONLY=0
RESTART=1
DRY_RUN=0
LIST=0
CONTAINER=""
BACKUP=""
while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y) YES=1 ;;
    --db-only) DB_ONLY=1 ;;
    --no-restart) RESTART=0 ;;
    --dry-run) DRY_RUN=1 ;;
    --list) LIST=1 ;;
    --container) shift; CONTAINER="${1:-}"; [ -n "$CONTAINER" ] || die "--container needs the container's name" ;;
    -h|--help) usage; exit 0 ;;
    -*) die "unknown option $1 (see --help)" ;;
    *) [ -z "$BACKUP" ] || die "one backup at a time"; BACKUP="$1" ;;
  esac
  shift
done

# .env is not loaded here: Compose reads it itself, and an image name already in the environment (rollback.sh sets
# VV_IMAGE to the image it is going back to) must win over the one in the file.
TIMEOUT="${VV_UPDATE_TIMEOUT:-180}"
DB=vulnverdict

# ---------------------------------------------------------------- the two layouts
# Compose: the database is the db service, the data volume is reached through a one-off web container.
# All-in-one: Postgres (or SQLite) and the data folder are inside the one container.
if [ -n "$CONTAINER" ]; then
  docker inspect "$CONTAINER" >/dev/null 2>&1 || die "there is no container called $CONTAINER"
  IMAGE="$(docker inspect --format '{{.Config.Image}}' "$CONTAINER")"
  in_db() { docker exec -i -u postgres "$CONTAINER" "$@"; }
  in_data() { docker run --rm -i --volumes-from "$CONTAINER" --user 0:0 --entrypoint "$1" "$IMAGE" "${@:2}"; }
  console_tool() { docker run --rm -i -e VV_BACKUP_PASSPHRASE -v "$WORK:/restore" --user "$(id -u):$(id -g)" -e HOME=/tmp --entrypoint dotnet "$IMAGE" /app/VulnVerdict.Web.dll "$@"; }
  DB_SUPERUSER=postgres
else
  [ -f docker-compose.yml ] || die "run this from the folder that holds docker-compose.yml, or name the all-in-one container with --container"
  in_db() { docker compose exec -T db "$@"; }
  in_data() { docker compose run --rm --no-deps -T --user 0:0 --entrypoint "$1" web "${@:2}"; }
  console_tool() { docker compose run --rm --no-deps -T -e VV_BACKUP_PASSPHRASE -v "$WORK:/restore" --user "$(id -u):$(id -g)" -e HOME=/tmp --entrypoint dotnet web /app/VulnVerdict.Web.dll "$@"; }
  DB_SUPERUSER=vulnverdict
fi

if [ "$LIST" = 1 ]; then
  in_data sh -c 'ls -l /data/backups 2>/dev/null | grep -E "\.vvbak(\.enc)?$" || echo "No backups in /data/backups."'
  exit 0
fi
[ -n "$BACKUP" ] || { usage; exit 1; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/vv-restore.XXXXXX")"
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------- find and unpack the backup
# a bare file name that is not here is taken from the stack's backups folder
if [ ! -f "$BACKUP" ]; then
  case "$BACKUP" in
    */*) die "$BACKUP does not exist" ;;
    *)
      echo "Fetching $BACKUP from the backups folder..."
      ( umask 077; in_data cat "/data/backups/$BACKUP" > "$WORK/$BACKUP" ) || die "$BACKUP is not in this folder or in the stack's backups folder (./restore.sh --list shows what is)"
      BACKUP="$WORK/$BACKUP"
      ;;
  esac
fi

PROVIDER=postgres
DUMP=""
KEYS=""
case "$BACKUP" in
  *.dump)
    DUMP="$BACKUP"
    DB_ONLY=1
    ;;
  *.vvbak|*.vvbak.enc)
    ARCHIVE="$BACKUP"
    case "$BACKUP" in
      *.enc)
        if [ -z "${VV_BACKUP_PASSPHRASE:-}" ]; then
          [ -t 0 ] || die "this backup is encrypted: set VV_BACKUP_PASSPHRASE to its passphrase"
          read -r -s -p "Backup passphrase: " VV_BACKUP_PASSPHRASE
          echo
        fi
        export VV_BACKUP_PASSPHRASE
        echo "Decrypting..."
        # the console image does the decrypting (backup-decrypt), as the user running this script, in the work folder
        ( umask 077; cp "$BACKUP" "$WORK/encrypted.vvbak.enc" )
        console_tool backup-decrypt /restore/encrypted.vvbak.enc /restore/plain.vvbak || die "the backup could not be decrypted (wrong passphrase, or the file is damaged)"
        rm -f "$WORK/encrypted.vvbak.enc"
        ARCHIVE="$WORK/plain.vvbak"
        ;;
    esac
    # only the names a backup holds, and nothing that could land outside the work folder
    if ! tar -tzf "$ARCHIVE" > "$WORK/names" 2>/dev/null; then die "$BACKUP is not a readable backup archive (damaged or incomplete)"; fi
    if grep -Ev '^(manifest\.json|database\.dump|database\.sqlite|keys/|keys/[A-Za-z0-9._-]+)$' "$WORK/names" >/dev/null; then die "$BACKUP holds files a backup does not; refusing to unpack it"; fi
    mkdir "$WORK/x"
    tar -xzf "$ARCHIVE" -C "$WORK/x"
    [ -f "$WORK/x/manifest.json" ] || die "$BACKUP has no manifest.json; it is not a VulnVerdict backup"
    PROVIDER="$(tr -d '\n' < "$WORK/x/manifest.json" | sed -n 's/.*"provider" *: *"\([a-z]*\)".*/\1/p')"
    echo "Backup: $(tr -d '\n' < "$WORK/x/manifest.json" | sed -n 's/.*"createdUtc" *: *"\([^"]*\)".*/\1/p') UTC, ${PROVIDER}, console version $(tr -d '\n' < "$WORK/x/manifest.json" | sed -n 's/.*"appVersion" *: *"\([^"]*\)".*/\1/p')"
    case "$PROVIDER" in
      postgres) DUMP="$WORK/x/database.dump" ;;
      sqlite) DUMP="$WORK/x/database.sqlite" ;;
      *) die "the manifest names a database this script does not know ($PROVIDER)" ;;
    esac
    [ -s "$DUMP" ] || die "$BACKUP has no database in it"
    if [ -d "$WORK/x/keys" ] && [ "$DB_ONLY" = 0 ]; then KEYS="$WORK/x/keys"; fi
    ;;
  *) die "$BACKUP is not a .vvbak, .vvbak.enc or .dump file" ;;
esac

if [ "$PROVIDER" = sqlite ] && [ -z "$CONTAINER" ]; then
  die "this backup is of a SQLite console; the Compose stack runs Postgres. Restore it into the all-in-one container with --container NAME."
fi

# the dump must read before anything is touched
if [ "$PROVIDER" = postgres ]; then
  if ! in_db pg_isready -U "$DB_SUPERUSER" -d postgres >/dev/null 2>&1; then die "the database is not running; start it first (docker compose up -d db)"; fi
  # (grep -c reads to the end; grep -q would hang up on pg_restore and fail the pipeline)
  if ! in_db pg_restore --list < "$DUMP" | grep -c "TABLE DATA" >/dev/null; then die "the database dump in $BACKUP does not read (pg_restore --list)"; fi
fi

echo "This replaces the console's database$( [ -n "$KEYS" ] && echo " and data-protection keys" ) with the backup."
echo "Everything recorded since the backup was taken is lost."
if [ "$DRY_RUN" = 1 ]; then echo "Dry run: the backup reads correctly. Nothing was changed."; exit 0; fi
if [ "$YES" = 0 ]; then
  [ -t 0 ] || die "nobody to ask: run again with --yes to go ahead"
  read -r -p "Go ahead? [y/N] " answer
  case "$answer" in y|Y|yes|YES) ;; *) die "nothing has been changed" ;; esac
fi

psql_admin() { in_db psql -v ON_ERROR_STOP=1 -q -U "$DB_SUPERUSER" -d postgres "$@"; }

restore_postgres() {
  echo "Loading the dump into a new database..."
  psql_admin -c "DROP DATABASE IF EXISTS ${DB}_restore"
  psql_admin -c "CREATE DATABASE ${DB}_restore OWNER vulnverdict"
  if ! in_db pg_restore -U "$DB_SUPERUSER" -d "${DB}_restore" --no-owner --role=vulnverdict --exit-on-error < "$DUMP"; then
    psql_admin -c "DROP DATABASE IF EXISTS ${DB}_restore" || true
    die "the dump did not load. The live database has not been touched."
  fi
  if [ -z "$CONTAINER" ]; then
    echo "Stopping the console and worker..."
    docker compose stop web worker
  fi
  echo "Swapping the databases..."
  # the all-in-one console is still running and reconnects at once, so the swap is retried a few times
  local attempt=0
  until psql_admin \
      -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname IN ('${DB}', '${DB}_restore', '${DB}_before_restore') AND pid <> pg_backend_pid()" \
      -c "DROP DATABASE IF EXISTS ${DB}_before_restore" \
      -c "ALTER DATABASE ${DB} RENAME TO ${DB}_before_restore" >/dev/null; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 5 ]; then die "the live database could not be moved aside (it is in use). The loaded backup is in ${DB}_restore; nothing else has changed."; fi
    sleep 1
  done
  psql_admin -c "ALTER DATABASE ${DB}_restore RENAME TO ${DB}"
}

restore_sqlite() {
  echo "Stopping the container and replacing the SQLite database..."
  docker stop "$CONTAINER" >/dev/null
  in_data sh -c 'cat > /data/vulnverdict.db.restore && rm -f /data/vulnverdict.db-wal /data/vulnverdict.db-shm && mv /data/vulnverdict.db.restore /data/vulnverdict.db && chown vulnverdict:vulnverdict /data/vulnverdict.db' < "$DUMP"
}

restore_keys() {
  echo "Restoring the data-protection keys..."
  tar -C "$WORK/x" -cf - keys | in_data sh -c 'mkdir -p /data/keys && tar -xf - -C /data --no-same-owner && chown -R vulnverdict:vulnverdict /data/keys'
}

if [ "$PROVIDER" = postgres ]; then restore_postgres; else restore_sqlite; fi
if [ -n "$KEYS" ]; then restore_keys; fi

# ---------------------------------------------------------------- start again
if [ -n "$CONTAINER" ]; then
  if [ "$RESTART" = 1 ]; then
    echo "Restarting $CONTAINER..."
    if [ "$PROVIDER" = sqlite ]; then docker start "$CONTAINER" >/dev/null; else docker restart "$CONTAINER" >/dev/null; fi
  fi
  echo "Restored. The database that was live is kept as ${DB}_before_restore (Postgres only) until the next restore."
  exit 0
fi

if [ "$RESTART" = 0 ]; then
  echo "Restored. The console and worker are stopped."
  exit 0
fi
echo "Starting the console and worker..."
docker compose up -d --no-build --no-deps web worker
waited=0
until docker compose exec -T web curl -fsS http://localhost:8080/healthz >/dev/null 2>&1; do
  waited=$((waited + 2))
  if [ "$waited" -ge "$TIMEOUT" ]; then
    echo "Restored, but the console is not answering yet. Look at: docker compose logs web" >&2
    exit 1
  fi
  sleep 2
done
echo "Restored. The console is answering."
echo "The database that was live is kept as ${DB}_before_restore until the next restore. To remove it now:"
echo "  docker compose exec db psql -U vulnverdict -d postgres -c 'DROP DATABASE ${DB}_before_restore'"
