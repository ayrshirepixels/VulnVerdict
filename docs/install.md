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

That downloads the latest release's Compose files (the compose file, Caddyfile, `.env.example` set to that release's images, and the update and rollback scripts) and runs the published, scanned images. Open `https://<VV_HOSTNAME>/`. The first page creates the local administrator account.

To build from source instead: clone the repository, `cd deploy`, comment out `VV_IMAGE` in `.env`, and run `docker compose up -d --build`.

What runs: `web` (the console), `worker` (feeds, connectors, verdicts, digests), `db` (PostgreSQL 16), `proxy` (Caddy, TLS). Only ports 443 and 80 are published. The worker needs outbound HTTPS to the public feeds (or to your central bundle URL); nothing else needs the internet.

## Option A2: one container (everything inside)

For a customer who wants a single `docker run` and nothing to compose, the all-in-one image carries PostgreSQL, the console and worker, and Caddy for TLS, with one volume for everything:

```bash
docker run -d --name vulnverdict --restart unless-stopped \
  -p 443:443 -p 80:80 -v vulnverdict:/data -e VV_HOSTNAME=vulnverdict.internal \
  ghcr.io/ayrshirepixels/vulnverdict:allinone
```

Build it with `docker build -f Dockerfile.allinone -t vulnverdict:allinone .`. Options: `VV_TLS=public` for Let's Encrypt on a public name, `VV_TLS=off` to expose plain HTTP on 8080 behind your own proxy, `VV_DB=sqlite` to skip Postgres for small estates, `VV_DB=external` with `Database__ConnectionString` to use your own Postgres. Back up the `vulnverdict` volume; it holds the database, the keys and the CA. The trade-off against Option A is that the database lifecycle (major-version upgrades, separate backups) is tied to the application container; the Compose stack is the better fit when someone already runs Postgres.

## Option B: the appliance (a VM)

A ready-built Ubuntu 24.04 LTS VM with Docker and the stack inside. 2 vCPU, 4 GB RAM, 40 GB disk, BIOS boot, DHCP on its first network card.

Download `vulnverdict-<version>.ova` and its `.sha256` from the [latest release](https://github.com/ayrshirepixels/VulnVerdict/releases/latest).

- **VMware (ESXi, Workstation) or VirtualBox:** import the OVA.
- **Proxmox:** `qm importovf <vmid> vulnverdict-<version>.ovf <storage>` after unpacking the OVA with `tar -xf`.
- **Hyper-V:** convert the OVA's disk (the Hyper-V disk is too large to attach to a release): `tar -xf vulnverdict-<version>.ova`, then `qemu-img convert -O vhdx -o subformat=dynamic vulnverdict-<version>-disk1.vmdk vulnverdict.vhdx`. Attach it to a **generation 1** VM with 2 vCPU, 4096 MB static memory and one network adapter.

Start it and answer the questions on its console: the hostname the console will answer on, and a password for the local `vulnverdict` account. The wizard then gives this appliance its own database password, SSH host keys and machine ID, turns SSH on, starts the stack and prints the URL. SSH is off until the wizard has run, so the build's default password is never reachable over the network.

The appliance installs Ubuntu's security updates automatically. The first run starts a few minutes after first boot, so a reboot in that window can take several minutes to complete while it finishes; later reboots are quick.

To build the appliance yourself, see the header of `deploy/ova/build.pkr.hcl`: Packer on a Hyper-V host (then `make-ova.sh`) or on a VirtualBox host.

## First ten minutes in the console

1. **Settings**: mail (SMTP, Microsoft 365, SendGrid or Brevo; see [mail](mail.md)), digest recipients, the console address used in email links, helpdesk intake address if you want tickets by email.
2. **Watchlist**: add what you run that no connector will see (or import `watchlist.example.json`). Verdicts appear immediately.
3. **Connectors**: add the sources you have, in the order they pay off: endpoint management, Windows servers (WinRM), your firewall, hypervisor, Linux (SSH), SBOMs from CI, SNMP for the management network, a discovery sweep, the external cross-check. Each needs a hostname and a read-only account; the form tells you the minimum permission.
4. Check **Needs mapping** once the first collections land: anything a connector reported that could not be tied to a vendor's CVE naming is listed there for a one-click mapping.
5. **Sources** shows feed health and what each feed is doing.

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

Updates are opt-in. `./update.sh [tag]` (in the Compose folder, or `/opt/vulnverdict` on the appliance) pulls the new image, keeps the previous one, moves the database and proxy to the images released with it, restarts web and worker, and rolls back automatically if the console does not answer within a minute. `./rollback.sh` returns the console to the previous image. Database migrations are additive, so an older image runs against a newer schema. The all-in-one container updates by pulling the new `:allinone` image and recreating the container on the same volume.

## Air-gapped sites

Set no bundle URL and upload a signed feed bundle under **Licence and updates** (see `docs/security.md` for how bundles are signed and verified). The console refuses unsigned or older bundles.

## Backups

Back up the `db` volume (Postgres) and the `data` volume (data-protection keys, which encrypt stored credentials and secrets). Without the keys a restored database cannot decrypt connector credentials; everything else survives.
