# Installing VulnVerdict

Fifteen minutes: run one command or import one OVA, sign in, paste read-only credentials for the connectors you have, receive your first digest.

## Option A: Docker Compose (you already run Docker)

Requirements: a Linux VM with Docker Engine and the Compose plugin. 2 vCPU, 4 GB RAM, 40 GB disk is plenty for 250 assets.

```bash
git clone https://github.com/ayrshirepixels/VulnVerdict.git
cd VulnVerdict/deploy
cp .env.example .env        # set DB_PASSWORD and VV_HOSTNAME
docker compose up -d --build
```

Open `https://<VV_HOSTNAME>/`. The first page creates the local administrator account.

What runs: `web` (the console), `worker` (feeds, connectors, verdicts, digests), `db` (PostgreSQL 16), `proxy` (Caddy, TLS). Only ports 443 and 80 are published. The worker needs outbound HTTPS to the public feeds (or to your central bundle URL); nothing else needs the internet.

## Option B: the appliance (OVA)

Import `vulnverdict-<version>.ova` into VMware, Hyper-V (convert with `qemu-img`) or VirtualBox, start it, and answer three questions on the console: hostname, password, done. The stack starts and prints the URL. Build the OVA yourself with Packer from `deploy/ova/`.

## First ten minutes in the console

1. **Settings**: mail (SMTP, SendGrid or Brevo), digest recipients, the console address used in email links, helpdesk intake address if you want tickets by email.
2. **Watchlist**: add what you run that no connector will see (or import `watchlist.example.json`). Verdicts appear immediately.
3. **Connectors**: add the sources you have, in the order they pay off: endpoint management, Windows servers (WinRM), your firewall, hypervisor, Linux (SSH), SBOMs from CI, SNMP for the management network, a discovery sweep, the external cross-check. Each needs a hostname and a read-only account; the form tells you the minimum permission.
4. Check **Needs mapping** once the first collections land: anything a connector reported that could not be tied to a vendor's CVE naming is listed there for a one-click mapping.
5. **Sources** shows feed health. The first CVE baseline is about 600 MB and takes 10 to 20 minutes.

## TLS

Caddy issues a certificate from its internal CA for an internal hostname (import `caddy-root.crt` on the clients or replace it with your own certificate in the Caddyfile). For a public hostname, delete `tls internal` in `deploy/Caddyfile` to get Let's Encrypt.

## Updating and rolling back

Updates are opt-in. `deploy/update.sh [tag]` pulls the new image, keeps the previous one, restarts web and worker, and rolls back automatically if the console does not answer within a minute. `deploy/rollback.sh` returns to the previous image. Database migrations are additive, so an older image runs against a newer schema.

## Air-gapped sites

Set no bundle URL and upload a signed feed bundle under **Licence and updates** (see `docs/security.md` for how bundles are signed and verified). The console refuses unsigned or older bundles.

## Backups

Back up the `db` volume (Postgres) and the `data` volume (data-protection keys, which encrypt stored credentials and secrets). Without the keys a restored database cannot decrypt connector credentials; everything else survives.
