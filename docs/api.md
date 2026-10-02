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

`sentAt` is when the event happened. The verdict is as it was at that moment, and the body is byte-for-byte the same on every retry.

### Headers

| Header | Value |
|---|---|
| `X-VulnVerdict-Event` | the event name |
| `X-VulnVerdict-Delivery` | an id for this event, the same on every retry: use it to drop duplicates |
| `X-VulnVerdict-Timestamp` | when this attempt was sent, in Unix seconds |
| `X-VulnVerdict-Signature-V2` | `sha256=<hex HMAC-SHA256 of timestamp + "." + raw body>`, keyed with the secret |
| `X-VulnVerdict-Signature` | `sha256=<hex HMAC-SHA256 of the raw body>`, keyed with the secret |

The signature headers are sent only when a secret is set.

### Verifying a delivery

Verify before trusting anything in the body:

1. Take `X-VulnVerdict-Timestamp` exactly as received and refuse the delivery if it is more than five minutes from your clock.
2. Compute HMAC-SHA256 over the timestamp, a full stop and the raw request body (the bytes as received, before any JSON parsing), with the secret as the key.
3. Compare `sha256=` plus the lower-case hex of that with `X-VulnVerdict-Signature-V2`, using a constant-time comparison.

```python
import hmac, hashlib, time

def verify(secret: bytes, headers, raw_body: bytes) -> bool:
    ts = headers["X-VulnVerdict-Timestamp"]
    if abs(time.time() - int(ts)) > 300:
        return False
    expected = "sha256=" + hmac.new(secret, ts.encode() + b"." + raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, headers["X-VulnVerdict-Signature-V2"])
```

`X-VulnVerdict-Signature` is the signature from earlier releases, over the body alone. It is still sent and unchanged, so an existing receiver keeps working. It does not cover the timestamp, so a delivery captured in transit could be replayed to a receiver that checks only this header; move receivers to `X-VulnVerdict-Signature-V2` when you can.

### Delivery and retries

An event is written to an outbox table in the same database transaction as the change it reports, and the worker sends it, normally within a minute. Nothing is held in memory: an event survives a restart, and it does not matter whether the web container or the worker made the change. Marking a verdict done in the console also tries its `verdict.closed` delivery straight away.

Any 2xx answer within 20 seconds is a success. Anything else is retried after 30 seconds, then 1, 2, 4, 8, 16 and 32 minutes (longer if the answer is 429 with a `Retry-After`). After eight attempts the delivery is given up: the console shows a banner and emails the administrator alert address. Delivery is at-least-once, so a receiver should treat a repeated `X-VulnVerdict-Delivery` as already handled. Every attempt is logged.

Teams and Slack messages use the same outbox: see [chat.md](chat.md).

## Example

```bash
curl -s -H "Authorization: Bearer $TOKEN" "https://vulnverdict.internal/api/verdicts?tier=FixToday&state=Open" | jq '.[] | {cveId, subject, sentence}'
```
