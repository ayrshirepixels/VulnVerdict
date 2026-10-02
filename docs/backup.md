# Backup and restore

The console backs itself up every night. This page says what is in a backup, where it goes, how to get it off the machine, and how to put one back.

## What a backup is

One file per backup in the `backups` folder of the data volume, named for when it was taken:

```
vulnverdict-20261002-013000Z-scheduled.vvbak        nightly
vulnverdict-20261002-141210Z-manual.vvbak           "Back up now"
vulnverdict-20261002-013000Z-scheduled.vvbak.enc    with a passphrase set
```

It is a gzip-compressed tar archive holding:

| Entry | What |
|---|---|
| `manifest.json` | when, which database, which console version, the last schema migration, the size and SHA-256 of the database entry |
| `keys/` | the data-protection key ring |
| `database.dump` | Postgres: a `pg_dump` custom-format dump (restores with `pg_restore`) |
| `database.sqlite` | SQLite (the all-in-one image with `VV_DB=sqlite`): a copy taken with `VACUUM INTO` |

Feed downloads and the TLS proxy's certificates are not in it: the feeds load again by themselves, and Caddy issues new certificates.

> **A backup and its keys together open every stored credential.** Connector passwords, the mail password, API keys and the webhook secret are encrypted in the database with the data-protection keys. The archive holds both, because a database without its keys cannot be used again. Treat the backups folder like a password store: readable by administrators only, and encrypted (below) if it leaves the machine or sits on a share other people can read.
>
> With a key-ring secret set (`VV_KEY_SECRET`, see [security](security.md#secrets)) the keys in the archive are themselves encrypted, so the archive alone opens nothing. The secret is not in the backup: a restore needs the same `VV_KEY_SECRET` in `.env`, so keep a copy of it somewhere other than this machine.

## How it is taken

The worker runs the backup at 02:30 in the console's time zone (Settings, Backups, to change the time or turn it off). Each run:

1. dumps the database: `pg_dump` for Postgres, `VACUUM INTO` for SQLite. Both take a consistent copy while the console keeps working;
2. checks the dump: `pg_restore --list` must read it and find table data; SQLite must pass `PRAGMA integrity_check`;
3. writes the archive under a temporary name, reads it back from start to finish and compares the database inside with the manifest;
4. renames it into place. A file with a backup's name is therefore always a complete, verified backup; a run that fails leaves nothing behind;
5. removes backups beyond the retention, and only after a good run, so a week of failures never costs the last good backup.

**Retention** (Settings, Backups): the newest backup of each of the last 14 days that have one, plus the newest of each of the last 8 weeks. A manual backup counts as that day's if it is the newest.

**Health.** The result of every run (time, size, how long it took, or why it failed) is on Settings under Backups, and the last one is on the Sources page beside the worker's heartbeat. If a backup fails, or there has been no good backup for 48 hours, the administrator alert address is emailed, and from 48 hours the daily digest says so in its footer. `/metrics` reports `vulnverdict_backup_age_seconds` and `vulnverdict_backup_last_run_ok` (see [metrics](metrics.md)).

**Back up now** on the same page takes one immediately, for instance before a change you are unsure of. `update.sh` takes its own dump before every update (see below).

### Why the console image carries pg_dump

The worker runs `pg_dump` itself rather than leaving it to a sidecar container or a `docker compose exec` on a timer. The image carries the PostgreSQL 16 client, the same major version as the database image. That keeps one path for every layout (Compose, the appliance, the all-in-one container, your own Postgres), lets the worker verify the result and report on it, and needs no access to the Docker socket. The client and the database must stay on the same major version: an older `pg_dump` refuses a newer server, and a newer one writes dumps the database container's `pg_restore` cannot read. The two are raised together in a release.

If you point the console at your own Postgres of a newer major version, the nightly backup will fail and say so; back that database up with your own tooling and turn the console's backup off.

## Getting backups off the machine

By default the backups are in a Docker volume on the same disk as the database, which protects against a bad update or a mistake, not against losing the machine. Put them somewhere else:

**Compose and the appliance:** set `VV_BACKUP_DIR` in `.env` to an absolute path on the host, such as a mounted NAS share or a second disk, and recreate the containers:

```bash
sudo mkdir -p /mnt/backups/vulnverdict
sudo chown 10001 /mnt/backups/vulnverdict && sudo chmod 700 /mnt/backups/vulnverdict
echo "VV_BACKUP_DIR=/mnt/backups/vulnverdict" >> .env
docker compose up -d
```

The console runs as uid 10001 and must be able to write there. Your existing backup software can then collect the folder like any other.

**All-in-one container:** mount a host path over `/data/backups`:

```bash
docker run -d --name vulnverdict ... -v vulnverdict:/data -v /mnt/backups/vulnverdict:/data/backups ...
```

## Encrypting the archives

Settings, Backups, **Archive passphrase**. With a passphrase set, each archive is encrypted before it touches the backups folder: AES-256-GCM in 1 MiB chunks, with the key derived from the passphrase by PBKDF2-HMAC-SHA256 (600,000 iterations, a random salt per archive). Each chunk is authenticated together with its position and the file header, so a damaged, shortened or rearranged file is detected, and a wrong passphrase fails at once.

Keep the passphrase somewhere other than the console (a password manager). It is stored encrypted for the nightly run, but it cannot be read back from the console, and a restore onto a new machine needs it typed in. **A lost passphrase means the encrypted backups cannot be read by anyone.** Changing or removing it affects new backups only; older archives keep the passphrase they were written with.

## Restoring

`restore.sh` is in the Compose folder (`/opt/vulnverdict` on the appliance) beside `update.sh`.

```bash
./restore.sh --list                                           # what is in the backups folder
./restore.sh vulnverdict-20261002-013000Z-scheduled.vvbak     # by name from that folder, or a path to a file
./restore.sh --dry-run /mnt/usb/vulnverdict-...vvbak          # check a backup without changing anything
```

What it does:

1. unpacks the archive (asking for the passphrase if it is encrypted, or reading `VV_BACKUP_PASSPHRASE`) and refuses it if it holds anything a backup does not, or if the dump does not read;
2. asks for confirmation: everything recorded since the backup is lost;
3. loads the dump into a new database beside the live one. If that fails, the live database has not been touched;
4. stops the console and worker, swaps the two databases, and restores the keys into the data volume;
5. starts the console and worker and waits for the console to answer.

The database that was live is kept as `vulnverdict_before_restore` until the next restore; the script prints the command to remove it.

Options: `--yes` (no question), `--db-only` (leave the keys alone), `--no-restart`, `--container NAME` (the all-in-one container), `--dry-run`.

### Onto a new machine

1. Install VulnVerdict the usual way (see [install](install.md)) with the same or a newer version than the backup's (`manifest.json` says which), and start it once so the database exists. You do not need to create the administrator account.
2. Copy the backup file into the Compose folder.
3. `./restore.sh vulnverdict-....vvbak`
4. Sign in with the accounts from the backup. Connectors and mail work at once, because the keys came back with the database.

Restoring a backup from a newer console into an older one is not supported: the older console does not know the newer schema.

### The all-in-one container

```bash
./restore.sh --container vulnverdict vulnverdict-20261002-013000Z-scheduled.vvbak
```

The script needs only `docker`; run it from anywhere. With the embedded Postgres the container keeps running while the dump loads and is restarted after the swap. With `VV_DB=sqlite` the container is stopped, the database file replaced and the container started again.

### By hand

If the script is not to hand, a plain archive opens with standard tools:

```bash
tar -xzf vulnverdict-20261002-013000Z-scheduled.vvbak        # manifest.json, keys/, database.dump
docker compose stop web worker
docker compose exec -T db psql -U vulnverdict -d postgres -c 'DROP DATABASE vulnverdict' -c 'CREATE DATABASE vulnverdict OWNER vulnverdict'
docker compose exec -T db pg_restore -U vulnverdict -d vulnverdict --no-owner < database.dump
tar -cf - keys | docker compose run --rm --no-deps -T --user 0:0 --entrypoint sh web -c 'tar -xf - -C /data && chown -R vulnverdict /data/keys'
docker compose up -d
```

An encrypted archive is decrypted first with the console image:

```bash
docker compose run --rm --no-deps -e VV_BACKUP_PASSPHRASE -v "$PWD:/restore" --user "$(id -u):$(id -g)" -e HOME=/tmp \
  --entrypoint dotnet web /app/VulnVerdict.Web.dll backup-decrypt /restore/NAME.vvbak.enc /restore/NAME.vvbak
```

`backup-verify <archive>` in place of `backup-decrypt` checks an archive and prints what it is.

## Updates take their own dump

`update.sh` stops the console and worker and dumps the database to `backups/pre-update-<time>.dump` in the Compose folder (on the host, not in the data volume) before it starts a new version, and does not update if that dump fails or does not read back. `rollback.sh` restores it when the new version changed the database schema. The last three are kept. They are plain `pg_dump` files without the keys, readable by root only; `./restore.sh backups/pre-update-<time>.dump` restores one by hand. See [install](install.md#updating-and-rolling-back).

## Testing your backups

A backup that has never been restored is a hope. Twice a year, restore the latest archive onto a spare VM (the "onto a new machine" steps above take ten minutes) and check that you can sign in and that a connector's **Test** button works: that proves the database, the keys and, if you use one, the passphrase.

## When it goes wrong

| The page says | Do this |
|---|---|
| `pg_dump is not installed` | The console image is older than the backup feature, or it is your own build without the PostgreSQL client. Update the image. |
| `pg_dump failed ... server version mismatch` | The database is a newer major version than the client in the image. See "Why the console image carries pg_dump". |
| `Access to the path '/data/backups/...' is denied` | The backups folder is not writable by uid 10001. `docker compose run --rm --no-deps --user 0:0 --entrypoint chown web 10001 /data/backups`, or fix the ownership of the host path. |
| `The saved backup passphrase cannot be read` | The data-protection keys were replaced. Set the passphrase again under Settings. |
| `A backup is already running` | Another one is in progress (the worker's, or someone pressed the button). A lock left by a killed process clears itself after six hours. |
