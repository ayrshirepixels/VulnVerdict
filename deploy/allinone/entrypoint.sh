#!/usr/bin/env bash
# All-in-one entrypoint: embedded PostgreSQL (or SQLite / external), the console+worker, and Caddy for TLS.
# Everything persistent lives under /data. Runs as root only long enough to fix ownership, then drops privileges.
set -euo pipefail

DATA=/data
PGDATA="$DATA/pg"
PG_BIN="/usr/lib/postgresql/${PG_MAJOR}/bin"
export PGDATA

log() { echo "[vulnverdict] $*"; }

mkdir -p "$DATA/keys" "$DATA/caddy" "$DATA/cvelist"
chown -R vulnverdict:vulnverdict "$DATA/keys" "$DATA/caddy" "$DATA/cvelist"

# ---------------------------------------------------------------- database
case "${VV_DB:-embedded}" in
  embedded)
    mkdir -p "$PGDATA" && chown -R postgres:postgres "$PGDATA" && chmod 700 "$PGDATA"
    if [ ! -s "$PGDATA/PG_VERSION" ]; then
      log "Initialising embedded PostgreSQL ${PG_MAJOR} in $PGDATA"
      gosu postgres "$PG_BIN/initdb" -D "$PGDATA" --auth=trust --encoding=UTF8 --locale=C.UTF-8 >/dev/null
      # local socket only; nothing listens on a network port
      printf "listen_addresses = ''\nunix_socket_directories = '/var/run/postgresql'\nshared_buffers = 256MB\nwork_mem = 16MB\nmaintenance_work_mem = 128MB\nwal_level = minimal\nmax_wal_senders = 0\n" >> "$PGDATA/postgresql.conf"
    fi
    mkdir -p /var/run/postgresql && chown postgres:postgres /var/run/postgresql
    gosu postgres "$PG_BIN/pg_ctl" -D "$PGDATA" -w -t 60 -l "$DATA/postgres.log" start
    if ! gosu postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='vulnverdict'" | grep -q 1; then
      gosu postgres createuser vulnverdict
      gosu postgres createdb -O vulnverdict vulnverdict
    fi
    export Database__Provider=postgres
    export Database__ConnectionString="Host=/var/run/postgresql;Database=vulnverdict;Username=vulnverdict"
    ;;
  sqlite)
    export Database__Provider=sqlite
    export Database__ConnectionString="Data Source=$DATA/vulnverdict.db"
    ;;
  external)
    : "${Database__ConnectionString:?VV_DB=external needs Database__ConnectionString}"
    export Database__Provider="${Database__Provider:-postgres}"
    ;;
  *) log "Unknown VV_DB=${VV_DB}"; exit 1 ;;
esac

# ---------------------------------------------------------------- TLS proxy
CADDY_PID=""
if [ "${VV_TLS:-internal}" != "off" ]; then
  HOST="${VV_HOSTNAME:-localhost}"
  TLS_LINE="tls internal"
  [ "${VV_TLS}" = "public" ] && TLS_LINE=""
  sed -e "s|__HOST__|$HOST|" -e "s|__TLS__|$TLS_LINE|" /etc/caddy/Caddyfile.template > "$DATA/caddy/Caddyfile"
  chown vulnverdict:vulnverdict "$DATA/caddy/Caddyfile"
  # caddy needs to bind 443/80: grant the capability to the binary instead of running as root
  setcap 'cap_net_bind_service=+ep' /usr/bin/caddy 2>/dev/null || true
  XDG_DATA_HOME="$DATA/caddy" XDG_CONFIG_HOME="$DATA/caddy" gosu vulnverdict caddy run --config "$DATA/caddy/Caddyfile" --adapter caddyfile >"$DATA/caddy.log" 2>&1 &
  CADDY_PID=$!
  log "Caddy started for https://$HOST/ (${VV_TLS} certificate)"
  # export the internal root certificate so it can be imported on clients
  ( sleep 15; cp "$DATA/caddy/caddy/pki/authorities/local/root.crt" "$DATA/caddy-root.crt" 2>/dev/null || true ) &
fi

# ---------------------------------------------------------------- shutdown
shutdown() {
  log "Stopping"
  [ -n "${APP_PID:-}" ] && kill -TERM "$APP_PID" 2>/dev/null || true
  [ -n "$CADDY_PID" ] && kill -TERM "$CADDY_PID" 2>/dev/null || true
  wait "${APP_PID:-}" 2>/dev/null || true
  if [ "${VV_DB:-embedded}" = "embedded" ]; then gosu postgres "$PG_BIN/pg_ctl" -D "$PGDATA" -m fast -w stop || true; fi
  exit 0
}
trap shutdown TERM INT

# ---------------------------------------------------------------- application (console + worker)
export Worker__CveMinYear="${CVE_MIN_YEAR:-0}"
cd /app
gosu vulnverdict dotnet VulnVerdict.Web.dll &
APP_PID=$!
log "VulnVerdict started (role ${Role:-all}, database ${VV_DB:-embedded})"
wait "$APP_PID"
shutdown
