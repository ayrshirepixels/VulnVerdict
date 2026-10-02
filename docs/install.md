# Installing VulnVerdict

Fifteen minutes: run one command or import one OVA, sign in, paste read-only credentials for the connectors you have, receive your first digest.

## Option A: Docker Compose (you already run Docker)

Requirements: a Linux VM with Docker Engine and the Compose plugin. 2 vCPU, 4 GB RAM, 40 GB disk is plenty for 250 assets.

```bash
curl -fsSL https://github.com/ayrshirepixels/VulnVerdict/releases/latest/download/vulnverdict-compose.tar.gz | tar -xz
cd vulnverdict
cp .env.example .env        # set DB_PASSWORD and VV_HOSTNAME
docker compose up -d
```

That downloads the latest release's Compose files (the compose file, Caddyfile, `.env.example` set to that release's images, and the update and rollback scripts) and runs the published, scanned images. Open `https://<VV_HOSTNAME>/`. The first page creates the local administrator account and asks for the setup token, a one-time code the console prints in its log on first start so that only someone with access to the server can claim the console:

```bash
docker compose logs web | grep -i "setup token"
```

The token is also in the file `setup-token` in the data volume until the account exists (`docker compose exec web cat /data/setup-token`), and stops working once it does.

To build from source instead: clone the repository, `cd deploy`, comment out `VV_IMAGE` in `.env`, and run `docker compose up -d --build`.

What runs: `web` (the console), `worker` (feeds, connectors, verdicts, digests), `db` (PostgreSQL 16), `proxy` (Caddy, TLS). Only ports 443 and 80 are published. The worker needs outbound HTTPS to the public feeds (or to your central bundle URL); nothing else needs the internet.

## Option A2: one container (everything inside)

For a customer who wants a single `docker run` and nothing to compose, the all-in-one image carries PostgreSQL, the console and worker, and Caddy for TLS, with one volume for everything:

```bash
docker run -d --name vulnverdict --restart unless-stopped \
  -p 443:443 -p 80:80 -v vulnverdict:/data -e VV_HOSTNAME=vulnverdict.internal \
  ghcr.io/ayrshirepixels/vulnverdict:allinone
```

The setup token for the first page is in the container log: `docker logs vulnverdict 2>&1 | grep -i "setup token"`.

Build it with `docker build -f Dockerfile.allinone -t vulnverdict:allinone .`. Options: `VV_TLS=public` for Let's Encrypt on a public name, `VV_TLS=off` to expose plain HTTP on 8080 behind your own proxy, `VV_DB=sqlite` to skip Postgres for small estates, `VV_DB=external` with `Database__ConnectionString` to use your own Postgres. Back up the `vulnverdict` volume; it holds the database, the keys and the CA. The trade-off against Option A is that the database lifecycle (major-version upgrades, separate backups) is tied to the application container; the Compose stack is the better fit when someone already runs Postgres.

## Option B: the appliance (a VM)

A ready-built Ubuntu 24.04 LTS VM with Docker and the stack inside. 2 vCPU, 4 GB RAM, 40 GB disk, BIOS boot, DHCP on its first network card.

Download `vulnverdict-<version>.ova` and its `.sha256` from the [latest release](https://github.com/ayrshirepixels/VulnVerdict/releases/latest).

- **VMware (ESXi, Workstation) or VirtualBox:** import the OVA.
- **Proxmox:** `qm importovf <vmid> vulnverdict-<version>.ovf <storage>` after unpacking the OVA with `tar -xf`.
- **Hyper-V:** convert the OVA's disk (the Hyper-V disk is too large to attach to a release): `tar -xf vulnverdict-<version>.ova`, then `qemu-img convert -O vhdx -o subformat=dynamic vulnverdict-<version>-disk1.vmdk vulnverdict.vhdx`. Attach it to a **generation 1** VM with 2 vCPU, 4096 MB static memory and one network adapter.

Start it and answer the questions on its console: the hostname the console will answer on, and a password for the local `vulnverdict` account. The wizard then gives this appliance its own database password, SSH host keys and machine ID, turns SSH on, starts the stack and prints the URL and the setup token the console's first page asks for (later, `cd /opt/vulnverdict && sudo docker compose logs web | grep -i "setup token"` shows it again). SSH is off until the wizard has run, so the build's default password is never reachable over the network.

The appliance installs Ubuntu's security updates automatically. The first run starts a few minutes after first boot, so a reboot in that window can take several minutes to complete while it finishes; later reboots are quick.

To build the appliance yourself, see the header of `deploy/ova/build.pkr.hcl`: Packer on a Hyper-V host (then `make-ova.sh`) or on a VirtualBox host.

## First ten minutes in the console

1. **Settings**: mail (SMTP, Microsoft 365, SendGrid or Brevo; see [mail](mail.md)), digest recipients, the console address used in email links, helpdesk intake address if you want tickets by email.
2. **Watchlist**: add what you run that no connector will see (or import `watchlist.example.json`). Verdicts appear immediately.
3. **Connectors**: add the sources you have, in the order they pay off: endpoint management, Windows servers (WinRM), your firewall, hypervisor, Linux (SSH), SBOMs from CI, SNMP for the management network, a discovery sweep, the external cross-check. Each needs a hostname and a read-only account; the form tells you the minimum permission.
4. Check **Needs mapping** once the first collections land: anything a connector reported that could not be tied to a vendor's CVE naming is listed there for a one-click mapping.
5. **Sources** shows feed health and what each feed is doing.

Until all of that is done, **Today** shows administrators a short setup checklist: mail, digest recipients, something to match (a watchlist entry or a connector), the CVE baseline, the first evaluation and the first digest. Each line links to the page that settles it, and the card can be hidden per browser.

The console works on a phone (the menu is behind the button in the top bar) and follows the device's light or dark setting; the Auto / Light / Dark switch at the foot of the menu pins one for that browser. It can also be installed from the browser's menu ("Install app" or "Add to Home Screen"). An installed console is the same site in its own window: it needs its connection to the server and has no offline mode.

### What the first hour looks like

The first start downloads what later runs only update, so give it about half an hour on a normal office line before judging the verdicts:

- **CVE List**: the full baseline, about 600 MB, 10 to 20 minutes. Verdicts start appearing as soon as it lands.
- **Debian, Ubuntu and Red Hat trackers**: about 100 MB between them, only used for Linux packages.
- **Microsoft security updates**: the last three months first, then the history back to 2016, about a year of it per run and roughly 1 GB in all, over 15 to 30 minutes. Old Windows CVEs whose records say "publication" instead of a version settle as this history arrives, so expect some Windows verdicts to close on their own during that time.
- **Microsoft 365 Apps update history**: one page, a few seconds.

Nothing is wrong if verdicts move during the first hour; the Sources page shows which feed is still loading. After that each feed runs on its own schedule (hourly for the CVE List, daily for most others) and takes seconds to minutes. A site that cannot reach the internet can load a signed feed bundle instead (Licence and updates page).

## TLS

Caddy issues a certificate from its internal CA for an internal hostname (import `caddy-root.crt` on the clients or replace it with your own certificate in the Caddyfile). For a public hostname, delete `tls internal` in `deploy/Caddyfile` to get Let's Encrypt.

## Updating and rolling back

Updates are opt-in. In the Compose folder, or `/opt/vulnverdict` on the appliance (with `sudo`):

```bash
./update.sh            # to the latest release; ./update.sh 1.4.0 for a particular one
./update.sh --dry-run  # show what it would do
```

`update.sh` notes which images are running (console, worker, database, proxy), pulls the new ones, and keeps the old ones under `:rollback` tags. It then stops the console and worker, dumps the database to `backups/pre-update-<time>.dump` in the same folder and checks that the dump reads back; if it cannot take that backup it starts the old version again and stops. Only then does it start the new images, the database first, then the console and worker (migrations run on start), then the proxy. If any of them does not come up, it rolls everything back by itself. Expect the console to be away for a minute or two. Running it again with the same release does nothing.

With the dump it keeps a copy of the encryption keys (`backups/pre-update-<time>.keys.tar`), which a rollback puts back: a newer console may rewrite the key files (`VV_KEY_SECRET` does) in a form an older one cannot read. It also brings this folder up to date: it takes the new release's `update.sh`, `rollback.sh` and `restore.sh` from the new image, and its `docker-compose.yml` and `Caddyfile` too where the copies here are the ones the running version shipped. A file you have edited is left alone, the new one is written beside it as `docker-compose.yml.new` or `Caddyfile.new` to merge by hand, and a replaced file is kept as `<name>.before-<time>`.

### Updating from 1.1.x

The `update.sh` that 1.1.x shipped changes images only, never `docker-compose.yml`, so the settings added in 1.2 (the backup folder `VV_BACKUP_DIR`, `VV_KEY_SECRET`) would be ignored and `restore.sh` would be missing; the console says so in a banner. Take this release's files first, then update with the new script. In the Compose folder, or `/opt/vulnverdict` on the appliance (with `sudo`):

```bash
curl -fsSL https://github.com/ayrshirepixels/VulnVerdict/releases/latest/download/vulnverdict-compose.tar.gz | tar -xz --strip-components=1 vulnverdict/docker-compose.yml vulnverdict/update.sh vulnverdict/rollback.sh vulnverdict/restore.sh vulnverdict/.env.example
./update.sh
```

That leaves `.env` and the `Caddyfile` as they are; if you had edited `docker-compose.yml` (ports, extra volumes), make the same edits to the new one before running `./update.sh`. Set `VV_KEY_SECRET` only once the update has come up and you are staying on it.

`./rollback.sh` puts all four images back by hand, for the release that came up but turned out wrong. A newer console may have changed the database schema, which the older one cannot be assumed to run against, so when the schema has moved it asks whether to restore the pre-update dump (everything recorded since the update is lost); `--restore-db` or `--keep-db` answers in advance, and with nobody to ask and neither given it changes nothing. The last three pre-update dumps are kept; they hold your data, so the `backups` folder is readable by root only.

On an air-gapped site, load the release's images with `docker load` and run `./update.sh --no-pull <tag>`.

The all-in-one container updates by pulling the new `:allinone` image and recreating the container on the same volume. Press **Back up now** (Settings, Backups) first, or copy the latest file from the backups folder: rolling back means recreating the container from the previous image and, if the schema moved, restoring that backup with `restore.sh --container` (see [backup](backup.md)).

## Air-gapped sites

Set no bundle URL and upload a signed feed bundle under **Licence and updates** (see `docs/security.md` for how bundles are signed and verified). The console refuses unsigned or older bundles. While it is fed by bundles no feed calls out, including the vendor VEX and end-of-life feeds; that data arrives in the bundle when the central service includes it.

## Backups

The worker backs up the database and the data-protection keys every night at 02:30 into the `backups` folder of the data volume, checks each backup, keeps 14 daily and 8 weekly, and tells you (Sources page, digest footer, administrator alert) when one fails or the last good one is older than 48 hours. By default that folder is a Docker volume on the same machine: set `VV_BACKUP_DIR` in `.env` to a mounted share or another disk so the backups survive the machine, and consider the archive passphrase, because a backup and its keys together open every stored credential. `./restore.sh` puts one back. All of it, including restoring onto a new machine, is in [backup](backup.md).

## Monitoring

`GET /metrics` serves Prometheus metrics (backlog by tier, overdue, feed and connector freshness, mail, backup age) once an administrator turns it on under Settings; it needs the metrics token or a listed scraper address. See [metrics](metrics.md) for the list, a scrape configuration and a starter Grafana dashboard.
