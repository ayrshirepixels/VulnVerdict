# Security policy

VulnVerdict holds a map of its users' weakest points. We treat reports about it seriously and quickly.

## Reporting a vulnerability

Email **security@ayrshirepixels.co.uk** with the version (Licence and updates page or image tag), steps to reproduce, and the impact as you understand it. Please do not open a public issue for anything exploitable. We acknowledge within two working days, keep you informed, and credit you in the release notes if you wish.

## Scope

- The console, worker and all-in-one image in this repository.
- The adapters and feeds: anything that would let a source system, a feed, an SBOM, a webhook receiver or a vendor advisory page influence a verdict, run code, or read data it should not.
- The API and webhooks.

Out of scope: the third-party feeds themselves, and denial of service by feeding the console a very large SBOM or subnet list (limits exist, but they are not a security boundary).

## What we do

- On every push and release, the NuGet packages (direct and transitive) are checked for known vulnerabilities and every image is scanned with Trivy. A known-vulnerable package, a fixable critical or high vulnerability in an image, or a secret baked into an image fails the build, and a release is not pushed until it passes. The published images are scanned again every week.
- The images do not run as root. Postgres and the console run as their own users; Caddy runs as the console user with only the capability to bind 443. The Compose stack's database and proxy images are built here rather than taken as published: Postgres without gosu, and Caddy compiled with the current Go release and dependencies.
- Fixes ship as an image on the update channel with a changelog; `deploy/update.sh` applies them and `deploy/rollback.sh` reverts.
- Credentials are encrypted at rest, adapters are read-only, and nothing customer-identifying is sent to an AI provider or the central service. See `docs/security.md`.
