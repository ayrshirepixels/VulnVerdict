# VulnVerdict

Cut the noise. Know your risk.

Verdicts are advisory: read the [advisory notice](docs/disclaimer.md). Free and open source under the [AGPL-3.0](LICENSE). Run the whole product on your own VM with no asset cap and no registration. Support plans add a curated signed feed, a tested update channel and email support; see the website or `docs/`. The VulnVerdict name and logo are trademarks (`TRADEMARK.md`).

An on-premises vulnerability triage console for organisations with one IT person and no security team. It pulls the public vulnerability feeds, matches them against what you actually run, works out how an attacker would have to reach each one in your estate, and emails a short verdict in plain words: **Fix today**, **Fix this week**, **Next patch cycle**, or ignore. It is a prioritisation layer, not a scanner and not a patch tool.

This repository holds the whole console: the feeds, watchlist, decision table and evidence chains; the console, digest and workflow; the inventory connectors, needs-mapping queue and coverage reconciliation; vendor advisories, native ticket adapters, compensating controls, auto-close, the weekly report, API and webhooks; and the console side of signed feed bundles, licence tiers, air-gap mode, MSP reporting, opt-in telemetry and the appliance build. See `docs/` for install, connectors, the digest, the API and security.

## What it does

- **Feeds** (all public, all self-updating): CVE List V5 with the CISA Vulnrichment ADP container (full baseline once, hourly deltas after), CISA KEV, EPSS, Exploit-DB, Metasploit module index, Nuclei CVE templates.
- **Watchlist**: the products you run, with version, exposure (internet-facing, internal, isolated) and criticality. Product names autocomplete from how vendors name things in their own CVE records, so matches are exact rather than fuzzy.
- **Verdicts**: every CVE matched to a watchlist entry gets a verdict from the deterministic decision table (`DecisionTable.cs`), an SLA, a one-sentence explanation, a match confidence (exact, likely, possible) and an evidence chain listing every claim, its source and when it was retrieved. Not-affected verdicts keep their evidence too, because a false negative is the dangerous direction.
- **Digest email**: daily at 07:30 local on weekdays by default, plus an immediate email for any new Fix today. Headline, fix today, fix this week, changed since last time, overdue, next-cycle count, coverage line, EPSS attribution. Nothing else.
- **Tickets**: one email per Fix today or Fix this week verdict to the helpdesk intake address, with a stable correlation key in the subject.
- **Workflow**: done, snooze, accept risk (owner, reason, expiry), suppression rules (CVE, product or asset scope, with expiry). Promotions re-open snoozed and accepted items and appear under "Changed".
- **Self-monitoring**: feed health on the Sources page and in the digest footer; stale feeds, a stopped worker or an unsendable digest email the administrator.
- **Inventory connectors** (each one credential form, read-only, never writes to the source): FortiClient EMS, endpoint management, MDM and RMM tools (Microsoft Intune, Defender for Endpoint, Configuration Manager, Jamf Pro, Kandji, NinjaOne, Datto RMM, N-able N-central, Lansweeper and PDQ Connect), Windows servers over WinRM or OpenSSH (roles, features, listeners, IIS, SQL Server, .NET, Hyper-V VM list), FortiGate (firmware, switches, APs, and exposure from VIPs, policies and WAN services), the other common small-business firewalls with the same exposure model (Palo Alto Networks PAN-OS, SonicWall SonicOS 7, Sophos Firewall, Cisco Meraki MX, UniFi gateways, pfSense, OPNsense and Zyxel USG FLEX / ATP; WatchGuard Firebox and Check Point Quantum Spark for firmware), VMware vCenter, Linux over SSH (packages matched through OSV), SBOM upload or URL (CycloneDX, SPDX), SNMP for the management network, a pure .NET discovery sweep, and an external cross-check with optional Shodan. Assets are merged across sources; unmapped software goes to the Needs mapping queue; stale assets fall out of digests after 30 days and are archived after 90.
- **Vendor advisories**: Fortinet PSIRT, Microsoft MSRC (with its history back to 2016), Cisco openVuln (with credentials), Broadcom/VMware, Ubuntu, Debian and Red Hat feed the evidence chain and the "exploited in the wild" signal. Microsoft's fixed builds, the cumulative Windows build history and the Microsoft 365 Apps update history settle Windows and Office CVEs whose records give "publication" or a link instead of a version.
- **Ticketing**: email, or native adapters for Jira, ServiceNow, Freshservice, Zendesk, Azure DevOps, HaloPSA and Autotask, with a stable correlation key and search-first idempotency.
- **Central service** (separate, not open source): builds the signed feed bundles for support plans, issues licence keys, hosts the MSP portal and receives opt-in telemetry. The console side of that (bundle verification, licence parsing, air-gap upload) is all here: consoles verify the ECDSA signature and every file hash and refuse unsigned or downgraded bundles. Without a bundle URL the console pulls the public feeds itself.
- **Mail**: SMTP, Microsoft 365 through Microsoft Graph (an app registration allowed to send as one mailbox, since Exchange Online is retiring password sign-in for SMTP), or the SendGrid or Brevo HTTP API, chosen in Settings. See [docs/mail.md](docs/mail.md).
- **AI explanations (optional, BYOM: bring your own model)**: "Explain in plain English" per CVE and "How an attacker would have to do it here" per verdict, from Anthropic, OpenAI or any OpenAI-compatible endpoint (Ollama for fully offline sites). The model never decides a verdict; it explains one. Only the product, version, exposure level and public CVE text are sent, never asset names or addresses. Results are cached with provider, model and prompt version recorded.
- **Security**: local admin created at install, optional OpenID Connect (Entra, Google, generic) with group-to-role mapping, three roles, audit log, encrypted secrets, CSP and security headers, login rate limiting, only port 443 exposed through Caddy.
- **API**: token-authenticated read endpoints for verdicts, watchlist and digest, plus watchlist import.

## Run it with Docker Compose

Requirements: a Linux VM with Docker (2 vCPU, 4 GB RAM, 40 GB disk is plenty).

```bash
cd deploy
cp .env.example .env      # set DB_PASSWORD and VV_HOSTNAME
docker compose up -d --build
```

Open `https://<VV_HOSTNAME>/`, create the administrator account, set the mail server and digest recipients under Settings, then add what you run under Watchlist (or import `watchlist.example.json`). The first CVE baseline is about 600 MB and takes 10 to 20 minutes to load; the Sources page shows progress. Verdicts appear as soon as it is in, and the first digest goes at the next scheduled time.

The same stack ships three ways, all supported: this Compose file for people who already run Docker, a single all-in-one container (`Dockerfile.allinone`) for people who want one `docker run`, and an OVA appliance (Ubuntu LTS with Docker and this Compose pre-installed, first-boot wizard for hostname and admin account) for people who do not run Docker at all. All three point at the same signed feed bundle from the central service when one is configured. See `docs/install.md`.

The image runs as `web` and `worker` from the same build; Postgres holds the data; Caddy terminates TLS with an internal CA by default (delete `tls internal` in the Caddyfile for Let's Encrypt on a public name).

## Run it locally for development

Requires the .NET 10 SDK. SQLite is used when no Postgres connection string is configured.

```bash
dotnet run --project src/VulnVerdict.Web --launch-profile http
```

Then open http://localhost:5080. Data (SQLite file, data-protection keys, feed downloads) lands in `src/VulnVerdict.Web/data`.

```bash
dotnet test
```

## Configuration

Settings that a customer changes live in the console (Settings page) and in the database. Host-level configuration is in `appsettings.json` or environment variables:

| Key | Environment variable | Default | Meaning |
|---|---|---|---|
| Role | `Role` | `all` | `all`, `web` or `worker` |
| Database:Provider | `Database__Provider` | `sqlite` | `sqlite` or `postgres` |
| Database:ConnectionString | `Database__ConnectionString` | SQLite file under the data dir | |
| Worker:DataDir | `Worker__DataDir` | `data` | keys, feed downloads, SQLite file |
| Worker:CveMinYear | `Worker__CveMinYear` | `0` | load only CVEs from this year on for the first baseline (deltas always load fully) |

## Layout

```
src/VulnVerdict.Core    domain model, EF Core context, feeds, decision engine, evaluator, digest, workflow, worker
src/VulnVerdict.Web     Blazor Server console, auth, API, Program.cs
tests/VulnVerdict.Tests decision table (all 16 rules), version comparison and matching, CVE record parsing, sentence
deploy/                 docker-compose.yml, Caddyfile, .env.example
Dockerfile              single image for web and worker
watchlist.example.json  a starter watchlist to import
```

## How a verdict is decided

Four inputs, all computed, none tuned:

1. **Exploitation**: Active if in CISA KEV or Vulnrichment says active; PoC if Exploit-DB, Metasploit, Nuclei or EPSS at or above 0.10 says so; otherwise None.
2. **Automatable**: CVSS attack vector Network, complexity Low, no privileges, no user interaction (v4.0 preferred over v3.1), or Vulnrichment says yes.
3. **Exposure**: from the watchlist entry, capped to Internal when the attack vector is Local or Physical, and Not installed when the version is outside the affected range.
4. **Criticality**: from the watchlist entry.

The decision table in `DecisionTable.cs` is evaluated top to bottom, first match wins, and every rule is covered by a unit test. "Possible" matches (product matched but version unknown or unparsed) are listed under "Check these" and are never emailed as Fix today.

## Data licensing

CVE List V5 is CC0 (CVE is a registered trademark of The MITRE Corporation, used as a data reference only). CISA KEV is public. EPSS is free with attribution to FIRST, which every digest carries. Exploit-DB, Metasploit and Nuclei data are referenced and linked, never redistributed.
