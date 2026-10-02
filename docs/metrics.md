# Metrics for Prometheus

`GET /metrics` reports the console's own health and the shape of the backlog in the Prometheus text format, for the monitoring you already run. It is off until an administrator turns it on.

## Turning it on

Settings, **Metrics (Prometheus)**, **Turn on**. The console generates a metrics token and shows it once; only its SHA-256 hash is stored. The scraper sends it as a bearer token:

```bash
curl -H "Authorization: Bearer vv_metrics_..." https://vulnverdict.internal/metrics
```

The endpoint is never open:

- while it is off it answers 404;
- on, it answers 401 unless the request carries the metrics token, or comes from an address in the allow-list on the same Settings card (addresses or CIDR ranges, for a scraper that cannot send a token);
- the metrics token reads `/metrics` and nothing else, and the API tokens do not read `/metrics`.

The allow-list compares the address the TLS proxy reports for the client. Prefer the token; use the allow-list only on a network where that address can be trusted.

## What is in it, and what is not

Everything is read from the database when the scraper asks, so one scrape of the console is complete even though the worker (a separate container in the Compose layout) does the feed loading, the evaluation, the mail and the backups.

Labels are tiers, workflow states, feed names, adapter kinds, a connector's eight-character id and, for one metric, product names. There are no asset names, hostnames, addresses, user names or CVE identifiers, so the numbers can sit in a shared Prometheus without describing your estate.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `vulnverdict_build_info` | gauge | `version` | always 1 |
| `vulnverdict_worker_up` | gauge | | 1 when the worker reported in the last 10 minutes |
| `vulnverdict_worker_heartbeat_timestamp_seconds` | gauge | | when it last reported |
| `vulnverdict_verdicts` | gauge | `tier`, `state` | verdicts by tier and workflow state |
| `vulnverdict_verdicts_overdue` | gauge | `tier` | open verdicts past their fix window |
| `vulnverdict_verdicts_opened_total` | counter | | verdicts that needed action, counting re-openings |
| `vulnverdict_verdicts_closed_total` | counter | | closures in the verdict history |
| `vulnverdict_time_to_fix_mean_seconds` | gauge | `tier` | mean time from opening to closing, last 90 days |
| `vulnverdict_time_to_fix_closures` | gauge | `tier` | how many closures that mean is over |
| `vulnverdict_product_open_verdicts` | gauge | `product` | open verdicts for the ten products with the most |
| `vulnverdict_assets` | gauge | | assets in the inventory |
| `vulnverdict_feed_last_success_timestamp_seconds` | gauge | `feed` | when each feed last loaded |
| `vulnverdict_feed_age_seconds` | gauge | `feed` | seconds since then |
| `vulnverdict_feed_last_run_failed` | gauge | `feed` | 1 when the last attempt failed |
| `vulnverdict_feed_overdue` | gauge | `feed` | 1 when past its schedule plus the grace period |
| `vulnverdict_feed_records` | gauge | `feed` | records in the last run |
| `vulnverdict_feed_failures_total` | counter | `feed` | failed runs |
| `vulnverdict_connector_last_success_timestamp_seconds` | gauge | `connector`, `adapter` | when each connector last completed |
| `vulnverdict_connector_last_run_duration_seconds` | gauge | `connector`, `adapter` | how long that run took |
| `vulnverdict_connector_assets` | gauge | `connector`, `adapter` | assets in that run |
| `vulnverdict_connector_consecutive_failures` | gauge | `connector`, `adapter` | failed runs in a row |
| `vulnverdict_connector_last_run_partial` | gauge | `connector`, `adapter` | 1 when the run completed but part of the source could not be read |
| `vulnverdict_evaluation_last_timestamp_seconds` | gauge | | when verdicts were last evaluated in full |
| `vulnverdict_evaluation_duration_seconds` | gauge | | how long that took |
| `vulnverdict_evaluation_failed_subjects` | gauge | | subjects it could not evaluate (retried on their own) |
| `vulnverdict_mail_sent_total`, `vulnverdict_mail_failed_total` | counter | | outbound mail |
| `vulnverdict_tickets_raised_total`, `vulnverdict_tickets_failed_total` | counter | | tickets by email or helpdesk adapter |
| `vulnverdict_webhook_deliveries_total` | counter | `result` | webhook attempts, `success` or `failure` |
| `vulnverdict_backup_last_run_ok` | gauge | | 1 when the last backup attempt succeeded |
| `vulnverdict_backup_last_success_timestamp_seconds` | gauge | | when the last good backup was taken |
| `vulnverdict_backup_age_seconds` | gauge | | seconds since then |
| `vulnverdict_backup_size_bytes`, `vulnverdict_backup_duration_seconds` | gauge | | of the last good backup |
| `vulnverdict_licence_valid`, `vulnverdict_licence_expiry_timestamp_seconds` | gauge | | only with a licence key |
| `vulnverdict_bundle_built_timestamp_seconds`, `vulnverdict_bundle_age_seconds` | gauge | | only when a feed bundle is applied |
| `vulnverdict_metrics_sections_failed` | gauge | | parts of the page that could not be read on this scrape |

`tier` is `fix_today`, `fix_this_week`, `next_patch_cycle`, `ignore_tracked` or `not_affected`; `state` is `open`, `suppressed`, `snoozed`, `accepted_risk` or `closed`. The `connector` label is the first eight characters of the connector's id: the connector's name is your own text and often a hostname, so it is not used.

The two verdict counters are counted from the stored verdicts and their history. They fall if verdicts are deleted (removing a watchlist entry deletes its verdicts), which Prometheus treats as a counter reset.

## Scrape configuration

`deploy/monitoring/prometheus-scrape.yml`:

```yaml
scrape_configs:
  - job_name: vulnverdict
    scheme: https
    metrics_path: /metrics
    scrape_interval: 60s
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/secrets/vulnverdict-metrics-token
    tls_config:
      ca_file: /etc/prometheus/secrets/vulnverdict-caddy-root.crt   # the console's internal CA; omit with a public certificate
    static_configs:
      - targets: ["vulnverdict.internal"]
```

Sixty seconds is plenty: the numbers change when the worker finishes something, and the endpoint shares the API's rate limit of 120 requests a minute per address.

## Alerts worth having

```yaml
groups:
  - name: vulnverdict
    rules:
      - alert: VulnVerdictWorkerDown
        expr: vulnverdict_worker_up == 0
        for: 15m
      - alert: VulnVerdictFeedOverdue
        expr: vulnverdict_feed_overdue == 1
        for: 1h
      - alert: VulnVerdictBackupStale
        expr: vulnverdict_backup_age_seconds > 48 * 3600 or vulnverdict_backup_last_run_ok == 0
        for: 1h
      - alert: VulnVerdictFixTodayOverdue
        expr: vulnverdict_verdicts_overdue{tier="fix_today"} > 0
        for: 30m
      - alert: VulnVerdictMailFailing
        expr: increase(vulnverdict_mail_failed_total[1h]) > 0
```

The console sends its own administrator alerts for the first three; these catch the case where its mail is the thing that is broken.

## Dashboard

`deploy/monitoring/grafana-dashboard.json` is a starter Grafana dashboard: the backlog by tier, overdue, opened against closed, time to fix, feed and connector freshness, mail, and backup age. Import it (Dashboards, New, Import) and pick your Prometheus data source.
