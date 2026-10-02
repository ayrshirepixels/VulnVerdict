# API and webhooks

Token-authenticated REST for MSPs and customers who want verdicts in their own tooling. Generate a token under Settings and send it as `Authorization: Bearer <token>`. Requests are rate limited (120 per minute per address).

There are two tokens. The **read-only** token can call every `GET`. The **read-write** token can also call the `POST` imports; give it only to the job that imports. The console keeps a SHA-256 hash of each, not the token, so it is shown once when generated: copy it then. A lost token is replaced, which stops the old one. Every write through the API is in the audit log.

Upgrading from a release with a single token: the existing token keeps working with read-write scope, and Settings suggests replacing it, since earlier releases displayed it on the page.

| Method and path | Purpose |
|---|---|
| `GET /api/verdicts?tier=FixToday&state=Open` | verdicts with subject, verdict, rule, confidence, state, SLA, sentence, fix version, inputs |
| `GET /api/verdicts/{id}` | one verdict with its evidence chain and history |
| `GET /api/watchlist` | the watchlist |
| `POST /api/watchlist` | import a JSON array (vendor, product, version, assetName, exposure, criticality); read-write token |
| `GET /api/assets` | assets with kind, exposure, criticality, sources, last seen |
| `GET /api/digest` | the current digest as JSON (headline, sections, coverage) |
| `POST /api/sbom?asset=<name>` | upload a CycloneDX or SPDX JSON SBOM for a named application or site; read-write token |
| `GET /reports/weekly.csv` | the weekly report as CSV (cookie session) |
| `GET /healthz` | liveness (no auth) |

Tier values: `FixToday`, `FixThisWeek`, `NextPatchCycle`, `IgnoreTracked`, `NotAffected`. State values: `Open`, `Suppressed`, `Snoozed`, `AcceptedRisk`, `Closed`.

Unauthenticated calls get `401` with a JSON body; a `POST` with the read-only token gets `403`.

## Webhooks

Set a URL and a secret under Settings. Events: `verdict.created`, `verdict.promoted`, `verdict.closed`. The body is JSON:

```json
{ "event": "verdict.promoted", "sentAt": "2026-09-24T07:31:02Z",
  "verdict": { "id": "...", "cveId": "CVE-2024-21762", "subject": "Fortinet FortiOS 7.2.5 on FW-EDGE-01",
               "verdict": "Fix today", "rule": 2, "confidence": "Exact", "state": "Open", "slaDue": "...",
               "sentence": "...", "fixedIn": "7.2.8", "url": "https://vulnverdict.internal/verdicts/..." } }
```

Headers: `X-VulnVerdict-Event` and `X-VulnVerdict-Signature: sha256=<hex HMAC-SHA256 of the raw body with the secret>`. Verify the signature before trusting a delivery. Deliveries are retried once and logged.

## Example

```bash
curl -s -H "Authorization: Bearer $TOKEN" "https://vulnverdict.internal/api/verdicts?tier=FixToday&state=Open" | jq '.[] | {cveId, subject, sentence}'
```
