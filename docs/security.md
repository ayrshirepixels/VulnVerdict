# Security of the console

The console holds a map of your weakest points. It is a target, and it is built as one.

## Access

- A local administrator is created at install, on a first page that needs a one-time setup token printed in the console's log and kept in the data volume, so whoever reaches the console first over the network cannot claim it. Only one administrator can be created that way, even from two requests at once. OpenID Connect (Microsoft Entra, Google Workspace, generic OIDC) with group-to-role mapping for everyone else.
- Roles: Administrator (everything, including adding, editing, testing and deleting connectors), Operator (verdict workflow, watchlist, mapping, suppressions, running connectors and AI explanations), Viewer (read only), Reporter (digest recipient without a login). Every action checks the role on the server, not only by hiding the button.
- Every state change is written to the audit log with actor, time and before/after. The last administrator cannot be deleted or demoted.
- Login is rate limited; sessions are cookie-based, HttpOnly, SameSite=Lax, 12 hours sliding. Each account has a security stamp that changes when it is deleted, its role changes or its password is reset: its cookies stop working on the next request and open console tabs lose access within five minutes. Signing out is a POST with an antiforgery token.
- The API has a read-only token and a read-write token (imports). Only their SHA-256 hashes are stored, compared in constant time; a token is shown once when generated. Every API write is in the audit log.
- Besides the per-address login rate limit, each local account locks for 15 minutes after 10 wrong passwords in a row, wherever they come from. The right password does not unlock it early; an administrator resetting the password does.

## Two-factor sign-in for local accounts

Single sign-on users get two-factor from their identity provider. Local accounts, the first administrator included, have their own: a time-based code from an authenticator app (TOTP, RFC 6238: SHA-1, six digits, 30 seconds, which every authenticator app supports).

- **Setting it up.** Under **My account**, or straight after creating the first administrator (it can be skipped there). The console shows a QR code and the key to type by hand, and turns two-factor on only once a code from the app confirms it. The QR code is drawn by the console itself; nothing is sent to an image service. Ten recovery codes are shown once: each signs in once when the phone is not to hand.
- **Signing in.** After the right password the console asks for the code (or a recovery code). Until the code is accepted nothing is signed in: the browser holds only a five-minute token for that one step, tied to the account and its security stamp, which is not a session cookie. The current code and the one either side of it are accepted, so a phone clock up to 30 seconds out works; a code that has been used is refused. Five wrong codes in a row lock the second step for 15 minutes.
- **Storage.** The secret is encrypted with Data Protection under its own purpose and is never sent to the browser again after enrolment. Recovery codes are stored as salted SHA-256 hashes.
- **Policy.** **Users > Require two-factor for local accounts** is off unless you turn it on. When on, a local user without two-factor must set it up at the next sign-in before reaching anything else, local users without it are signed out when the policy is switched on, and it cannot be turned off under My account.
- **Changes.** Turning your own two-factor off takes the password and a current code. An administrator can reset another user's two-factor (a lost phone) on the Users page. Turning it on or off, a reset, new recovery codes, each recovery code used and each lockout are in the audit log; turning it on, off or resetting it changes the security stamp, which ends that account's other sessions.

### If the last administrator is locked out

When nobody can sign in to reset it (the only administrator lost the phone and the recovery codes), reset it from the host. Whoever can do this already has the data volume and the database, so it asks for nothing more:

```
docker compose exec web dotnet VulnVerdict.Web.dll reset-2fa <username>
```

The all-in-one image (and the appliance, which runs it) sets its database settings in its start script, so pass them with the command. With the default embedded database:

```
docker exec -u vulnverdict -w /app \
  -e Database__Provider=postgres \
  -e "Database__ConnectionString=Host=/var/run/postgresql;Database=vulnverdict;Username=vulnverdict" \
  <container> dotnet VulnVerdict.Web.dll reset-2fa <username>
```

The console keeps running while the command runs. It removes that local account's two-factor and recovery codes, clears its lockouts, ends its sessions and writes `user.2fa.reset` by `console` to the audit log. The account then signs in with its password, and sets two-factor up again at once if the policy requires it. It does not change the password.

## Secrets

- Connector credentials, mail passwords, API keys, the webhook secret, the MSP token and the licence key are encrypted with ASP.NET Data Protection before they reach the database. The key ring lives in the `data` volume; keep it on an encrypted disk and back it up with the database.
- Saved secrets are never sent back to the browser: the forms show that one is saved, and a blank field keeps it. A blank connector password is only reused while the connector's address, account and TLS setting are unchanged, so a changed address cannot be tested with the saved password. Pinning an SSH host key does not count as a change; a different host or port does.
- SSH connectors only sign in to hosts whose key is pinned. An administrator pins a key from the connector test (one click, audited with the fingerprint); a key that differs from the pinned one is never accepted in bulk and has to be replaced host by host. See [connectors](connectors.md#ssh-host-keys).
- Credentials never appear in configuration files or logs. Every adapter uses read-only accounts and never writes to the source.

## Network

- Only 443 (and 80 for redirects) is published, through Caddy. Postgres and the application containers are on the internal Compose network only.
- Outbound: the worker needs HTTPS to the public feeds, or only to your central bundle URL, plus whatever your connectors and mail transport need. The AI provider, if enabled, receives the product, version, exposure level and public CVE text: never hostnames, addresses or asset names.

## Headers and browser

Content Security Policy (scripts only from the console itself, no inline scripts, connections only to the console, forms only to the console and the configured identity provider), X-Content-Type-Options, X-Frame-Options same-origin, Referrer-Policy, Permissions-Policy. Antiforgery tokens on every form. No external CDNs: fonts and styles are served locally so an air-gapped console renders the same.

## Feed bundles and licences

The central service signs each bundle manifest (ECDSA P-256) and every file in it is hashed. The console verifies the signature against the public key it ships with, verifies every hash, and refuses unsigned bundles and any bundle whose version is not newer than the one applied. Vendor VEX statements and end-of-life dates travel as two optional files with their own signature over their hashes, checked the same way; a console that predates them ignores them. Licence keys are signed the same way; an absent licence means the internal build, which never blocks anything.

## Supply chain

Every push and release checks the NuGet packages, direct and transitive, for known vulnerabilities, and scans all four images (console, all-in-one, database, proxy) with Trivy. A known-vulnerable package, a fixable critical or high vulnerability, or a secret baked into an image fails the build, and a release is not pushed until it passes. The published images are scanned again every week, so a vulnerability disclosed after a release is caught and fixed with a patch release.

Nothing runs as root inside the containers. Postgres and the console run as their own users; Caddy runs as the console user with only the capability to bind 443. The Compose database image is Postgres 16 without gosu, running as postgres from the start, and the proxy image is Caddy compiled with the current Go release and dependencies, because the published Postgres and Caddy images can lag behind Go security fixes.

Image updates are opt-in with a changelog and a one-command rollback; `deploy/update.sh` moves the database and proxy images along with the console.

## Reporting a vulnerability in VulnVerdict

Email security@ayrshirepixels.co.uk. We will acknowledge within two working days.
