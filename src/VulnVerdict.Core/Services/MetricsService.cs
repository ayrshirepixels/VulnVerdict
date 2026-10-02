using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Digest;
using VulnVerdict.Core.Feeds;

namespace VulnVerdict.Core.Services;

/// <summary>
/// Running totals kept in the database rather than in memory: in the Compose layout the worker sends the mail and runs
/// the feeds while the web container answers /metrics, so an in-process counter would never be scraped. Services call
/// the static <see cref="Add"/> (they keep their constructors); it writes in the background and never throws.
/// </summary>
public static class MetricCounters
{
    public const string MailSent = "mail_sent_total";
    public const string MailFailed = "mail_failed_total";
    public const string TicketsFailed = "tickets_failed_total";
    public const string FeedFailures = "feed_failures_total";

    private static IDbContextFactory<VvDbContext>? _factory;

    /// <summary>Called once at start-up. Until then (unit tests of other services) <see cref="Add"/> does nothing.</summary>
    public static void Use(IDbContextFactory<VvDbContext>? factory) => _factory = factory;

    public static void Add(string name, string label = "", long by = 1)
    {
        var factory = _factory;
        if (factory is null) return;
        _ = Task.Run(async () => { try { await AddAsync(factory, name, label, by); } catch { } });
    }

    public static async Task AddAsync(IDbContextFactory<VvDbContext> factory, string name, string label = "", long by = 1, CancellationToken ct = default)
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        var now = DateTime.UtcNow;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            // one statement, so the web and the worker can both add without losing a count
            var updated = await db.MetricCounters.Where(c => c.Name == name && c.Label == label)
                .ExecuteUpdateAsync(u => u.SetProperty(c => c.Value, c => c.Value + by).SetProperty(c => c.UpdatedAt, now), ct);
            if (updated > 0) return;
            try
            {
                db.MetricCounters.Add(new MetricCounter { Name = name, Label = label, Value = by, UpdatedAt = now });
                await db.SaveChangesAsync(ct);
                return;
            }
            catch (DbUpdateException) { db.ChangeTracker.Clear(); }   // the other process created the row first: add to it
        }
    }
}

public enum MetricsAccess { Disabled, Denied, Allowed }

/// <summary>
/// Who may read /metrics. Off until an administrator turns it on, and never anonymous: a scraper presents the metrics
/// bearer token (only its SHA-256 hash is stored, shown once, like the API tokens but good for nothing else) or comes
/// from an address in the allow-list.
/// </summary>
public sealed class MetricsAuth
{
    public const string EnabledKey = "metrics:enabled";
    public const string TokenHashKey = "metrics:token";
    public const string AllowKey = "metrics:allow";
    public const string TokenPrefix = "vv_metrics_";

    private readonly IDbContextFactory<VvDbContext> _factory;

    public MetricsAuth(IDbContextFactory<VvDbContext> factory) => _factory = factory;

    public sealed record Status(bool Enabled, bool HasToken, string AllowList);

    public async Task<Status> StatusAsync(CancellationToken ct = default)
    {
        var rows = await RowsAsync(ct);
        return new Status(rows.GetValueOrDefault(EnabledKey) == "1", !string.IsNullOrEmpty(rows.GetValueOrDefault(TokenHashKey)), rows.GetValueOrDefault(AllowKey) ?? "");
    }

    private async Task<Dictionary<string, string?>> RowsAsync(CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        return await db.Settings.AsNoTracking().Where(s => s.Key == EnabledKey || s.Key == TokenHashKey || s.Key == AllowKey).ToDictionaryAsync(s => s.Key, s => s.Value, ct);
    }

    /// <summary>Turn the endpoint on. With no token and no allow-list yet, a token is generated and returned (the only time it is shown).</summary>
    public async Task<string?> EnableAsync(string actor, CancellationToken ct = default)
    {
        var status = await StatusAsync(ct);
        string? token = null;
        await using var db = await _factory.CreateDbContextAsync(ct);
        var now = DateTime.UtcNow;
        Upsert(db, EnabledKey, "1", now);
        if (!status.HasToken && Parse(status.AllowList).Count == 0) Upsert(db, TokenHashKey, ApiTokenService.Hash(token = NewToken()), now);
        db.Audit.Add(new AuditEntry { At = now, Actor = actor, Action = "metrics.enable", Target = "metrics", After = token is null ? "enabled" : "enabled, token generated" });
        await db.SaveChangesAsync(ct);
        return token;
    }

    public async Task DisableAsync(string actor, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var now = DateTime.UtcNow;
        Upsert(db, EnabledKey, null, now);
        db.Audit.Add(new AuditEntry { At = now, Actor = actor, Action = "metrics.disable", Target = "metrics" });
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Create (or replace) the metrics token. The plain value is returned once and never stored.</summary>
    public async Task<string> GenerateTokenAsync(string actor, CancellationToken ct = default)
    {
        var token = NewToken();
        await SetTokenAsync(ApiTokenService.Hash(token), actor, "metrics.token.generate", ct);
        return token;
    }

    public Task RevokeTokenAsync(string actor, CancellationToken ct = default) => SetTokenAsync(null, actor, "metrics.token.revoke", ct);

    private async Task SetTokenAsync(string? hash, string actor, string action, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var now = DateTime.UtcNow;
        Upsert(db, TokenHashKey, hash, now);
        db.Audit.Add(new AuditEntry { At = now, Actor = actor, Action = action, Target = "metrics" });
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Addresses or CIDR ranges, separated by commas, spaces or new lines. Throws with the entry that does not parse.</summary>
    public async Task SetAllowListAsync(string? list, string actor, CancellationToken ct = default)
    {
        var entries = Split(list);
        foreach (var e in entries)
            if (!TryParseNetwork(e, out _)) throw new ArgumentException("'" + e + "' is not an address or a CIDR range such as 10.0.5.0/24.");
        var value = string.Join(", ", entries);
        await using var db = await _factory.CreateDbContextAsync(ct);
        var now = DateTime.UtcNow;
        Upsert(db, AllowKey, value, now);
        db.Audit.Add(new AuditEntry { At = now, Actor = actor, Action = "metrics.allowlist", Target = "metrics", After = value == "" ? "cleared" : value });
        await db.SaveChangesAsync(ct);
    }

    public async Task<MetricsAccess> AuthoriseAsync(string? authorizationHeader, IPAddress? remote, CancellationToken ct = default)
    {
        var rows = await RowsAsync(ct);
        if (rows.GetValueOrDefault(EnabledKey) != "1") return MetricsAccess.Disabled;
        var token = authorizationHeader is not null && authorizationHeader.StartsWith("Bearer ", StringComparison.Ordinal) ? authorizationHeader["Bearer ".Length..].Trim() : null;
        if (ApiTokenService.Matches(token, rows.GetValueOrDefault(TokenHashKey))) return MetricsAccess.Allowed;
        return IsAllowed(remote, rows.GetValueOrDefault(AllowKey)) ? MetricsAccess.Allowed : MetricsAccess.Denied;
    }

    private static string NewToken() => TokenPrefix + Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();

    private static string[] Split(string? list) => (list ?? "").Split(new[] { ',', ';', ' ', '\n', '\r', '\t' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    public static List<IPNetwork> Parse(string? list)
    {
        var result = new List<IPNetwork>();
        foreach (var e in Split(list)) if (TryParseNetwork(e, out var n)) result.Add(n);
        return result;
    }

    public static bool TryParseNetwork(string entry, out IPNetwork network)
    {
        if (entry.Contains('/')) return IPNetwork.TryParse(entry, out network);
        if (IPAddress.TryParse(entry, out var ip)) { network = new IPNetwork(ip, ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128); return true; }
        network = default;
        return false;
    }

    /// <summary>True when the address is inside one of the listed ranges. An empty list allows nobody.</summary>
    public static bool IsAllowed(IPAddress? remote, string? list)
    {
        if (remote is null) return false;
        if (remote.IsIPv4MappedToIPv6) remote = remote.MapToIPv4();
        return Parse(list).Any(n => n.Contains(remote));
    }

    private static void Upsert(VvDbContext db, string key, string? value, DateTime now)
    {
        var row = db.Settings.FirstOrDefault(s => s.Key == key);
        if (row is null) db.Settings.Add(new AppSetting { Key = key, Value = value, UpdatedAt = now });
        else { row.Value = value; row.UpdatedAt = now; }
    }
}

/// <summary>
/// Writes the Prometheus text exposition format (version 0.0.4): one HELP and TYPE line per family, then all of that
/// family's samples together, whatever order they were added in.
/// </summary>
public sealed class PrometheusWriter
{
    private readonly List<string> _order = new();
    private readonly Dictionary<string, StringBuilder> _families = new(StringComparer.Ordinal);
    private readonly StringBuilder _comments = new();

    public void Family(string name, string type, string help)
    {
        if (_families.ContainsKey(name)) return;
        var sb = new StringBuilder();
        sb.Append("# HELP ").Append(name).Append(' ').Append(help.Replace("\\", "\\\\").Replace("\n", "\\n")).Append('\n');
        sb.Append("# TYPE ").Append(name).Append(' ').Append(type).Append('\n');
        _families[name] = sb; _order.Add(name);
    }

    public void Sample(string name, double value, params (string Name, string Value)[] labels)
    {
        if (!_families.ContainsKey(name)) Family(name, "untyped", name);
        var sb = _families[name];
        sb.Append(name);
        if (labels.Length > 0)
        {
            sb.Append('{');
            for (var i = 0; i < labels.Length; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append(labels[i].Name).Append("=\"").Append(Escape(labels[i].Value)).Append('"');
            }
            sb.Append('}');
        }
        sb.Append(' ').Append(Number(value)).Append('\n');
    }

    public void Comment(string text) => _comments.Append("# ").Append(text.Replace("\n", " ")).Append('\n');

    public static string Escape(string v) => v.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n");

    public static string Number(double v) => double.IsNaN(v) ? "NaN" : double.IsPositiveInfinity(v) ? "+Inf" : double.IsNegativeInfinity(v) ? "-Inf" : v.ToString("R", CultureInfo.InvariantCulture);

    public override string ToString() => string.Concat(_order.Select(n => _families[n].ToString())) + _comments;
}

/// <summary>
/// Everything /metrics reports, read from the database and the recorded state in one pass, so a scrape of the web
/// container is complete whichever process did the work. Labels are tiers, states, feed names, adapter kinds, a
/// connector's short id and, at most, product names: never an asset name, a hostname, an address or a CVE on an asset.
/// </summary>
public sealed class MetricsService
{
    public const string ContentType = "text/plain; version=0.0.4; charset=utf-8";
    /// <summary>Seconds the last full evaluation took, written by the evaluator.</summary>
    public const string EvaluationSecondsKey = "state:evaluate:lastSeconds";
    public const int TimeToFixWindowDays = 90;
    public const int TopProducts = 10;

    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly SettingsService _settings;

    public MetricsService(IDbContextFactory<VvDbContext> factory, SettingsService settings) { _factory = factory; _settings = settings; }

    public static string Label(VerdictTier t) => t switch
    {
        VerdictTier.FixToday => "fix_today",
        VerdictTier.FixThisWeek => "fix_this_week",
        VerdictTier.NextPatchCycle => "next_patch_cycle",
        VerdictTier.IgnoreTracked => "ignore_tracked",
        _ => "not_affected"
    };

    public static string Label(VerdictState s) => s switch { VerdictState.AcceptedRisk => "accepted_risk", _ => s.ToString().ToLowerInvariant() };

    private static double Unix(DateTime utc) => new DateTimeOffset(DateTime.SpecifyKind(utc, DateTimeKind.Utc)).ToUnixTimeMilliseconds() / 1000.0;
    private static DateTime? Stamp(string? s) => DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var d) ? d.ToUniversalTime() : null;

    public async Task<string> RenderAsync(DateTime? nowUtc = null, CancellationToken ct = default)
    {
        var now = nowUtc ?? DateTime.UtcNow;
        var w = new PrometheusWriter();
        var failed = 0;
        // a section that cannot be read (a table from a migration not yet applied) must not cost the rest of the scrape
        async Task Section(string name, Func<Task> body)
        {
            try { await body(); }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { failed++; w.Comment(name + " unavailable: " + ex.GetType().Name); }
        }

        w.Family("vulnverdict_build_info", "gauge", "The running version, as a label.");
        w.Sample("vulnverdict_build_info", 1, ("version", Environment.GetEnvironmentVariable("VV_VERSION") ?? "dev"));

        await using var db = await _factory.CreateDbContextAsync(ct);
        await Section("worker", async () =>
        {
            var beat = Stamp(await _settings.GetStateAsync(SettingsService.Keys.WorkerHeartbeat, ct));
            w.Family("vulnverdict_worker_up", "gauge", "1 when the worker reported in the last 10 minutes.");
            w.Sample("vulnverdict_worker_up", beat is not null && now - beat < TimeSpan.FromMinutes(10) ? 1 : 0);
            if (beat is not null)
            {
                w.Family("vulnverdict_worker_heartbeat_timestamp_seconds", "gauge", "When the worker last reported.");
                w.Sample("vulnverdict_worker_heartbeat_timestamp_seconds", Unix(beat.Value));
            }
        });

        await Section("verdicts", async () =>
        {
            var counts = await db.Verdicts.AsNoTracking().GroupBy(v => new { v.Tier, v.State }).Select(g => new { g.Key.Tier, g.Key.State, N = g.Count() }).ToListAsync(ct);
            w.Family("vulnverdict_verdicts", "gauge", "Verdicts by tier and workflow state.");
            foreach (var tier in Enum.GetValues<VerdictTier>())
                foreach (var state in Enum.GetValues<VerdictState>())
                    w.Sample("vulnverdict_verdicts", counts.FirstOrDefault(c => c.Tier == tier && c.State == state)?.N ?? 0, ("tier", Label(tier)), ("state", Label(state)));

            var overdue = await db.Verdicts.AsNoTracking().Where(v => v.State == VerdictState.Open && v.Tier >= VerdictTier.NextPatchCycle && v.SlaDue != null && v.SlaDue < now)
                .GroupBy(v => v.Tier).Select(g => new { Tier = g.Key, N = g.Count() }).ToListAsync(ct);
            w.Family("vulnverdict_verdicts_overdue", "gauge", "Open verdicts past their fix window, by tier.");
            foreach (var tier in SlaMath.Tiers) w.Sample("vulnverdict_verdicts_overdue", overdue.FirstOrDefault(c => c.Tier == tier)?.N ?? 0, ("tier", Label(tier)));

            // counted from the stored verdicts and their history, so they fall if verdicts are deleted (a watchlist entry removed)
            var actionable = await db.Verdicts.CountAsync(v => v.Tier >= VerdictTier.NextPatchCycle, ct);
            var reopened = await db.VerdictHistory.CountAsync(h => h.Kind == "state" && h.From == "Closed" && h.To == "Open", ct);
            var closed = await db.VerdictHistory.CountAsync(h => h.Kind == "state" && h.To == "Closed", ct);
            w.Family("vulnverdict_verdicts_opened_total", "counter", "Verdicts that needed action, counting each re-opening.");
            w.Sample("vulnverdict_verdicts_opened_total", actionable + reopened);
            w.Family("vulnverdict_verdicts_closed_total", "counter", "Verdict closures recorded in the history.");
            w.Sample("vulnverdict_verdicts_closed_total", closed);
        });

        await Section("time to fix", async () =>
        {
            var closures = await new SlaReportService(_factory, _settings).ClosuresAsync(now.AddDays(-TimeToFixWindowDays), now, ct);
            w.Family("vulnverdict_time_to_fix_mean_seconds", "gauge", "Mean time from a verdict opening to its closing, over the last " + TimeToFixWindowDays + " days, by tier at closing.");
            w.Family("vulnverdict_time_to_fix_closures", "gauge", "Closures behind the mean time to fix, over the last " + TimeToFixWindowDays + " days, by tier.");
            foreach (var tier in SlaMath.Tiers)
            {
                var mine = closures.Where(c => c.Tier == tier).ToList();
                if (mine.Count > 0) w.Sample("vulnverdict_time_to_fix_mean_seconds", mine.Average(c => (c.ClosedUtc - c.OpenedUtc).TotalSeconds), ("tier", Label(tier)));
                w.Sample("vulnverdict_time_to_fix_closures", mine.Count, ("tier", Label(tier)));
            }
        });

        await Section("products", async () =>
        {
            var open = await db.Verdicts.AsNoTracking().Include(v => v.WatchlistEntry).Include(v => v.SoftwareInstance)
                .Where(v => v.State == VerdictState.Open && v.Tier >= VerdictTier.NextPatchCycle).ToListAsync(ct);
            w.Family("vulnverdict_product_open_verdicts", "gauge", "Open verdicts needing action for the " + TopProducts + " products with the most (vendor and product only).");
            foreach (var p in SlaReportService.TopProducts(open, now, TopProducts))
                w.Sample("vulnverdict_product_open_verdicts", p.Open, ("product", p.Product.Length > 100 ? p.Product[..100] : p.Product));
            w.Family("vulnverdict_assets", "gauge", "Assets in the inventory (not archived).");
            w.Sample("vulnverdict_assets", await db.Assets.CountAsync(a => !a.Archived, ct));
        });

        await Section("feeds", async () =>
        {
            var feeds = await db.FeedStatuses.AsNoTracking().OrderBy(f => f.Name).ToListAsync(ct);
            w.Family("vulnverdict_feed_last_success_timestamp_seconds", "gauge", "When each feed last loaded.");
            w.Family("vulnverdict_feed_age_seconds", "gauge", "Seconds since each feed last loaded.");
            w.Family("vulnverdict_feed_last_run_failed", "gauge", "1 when the feed's last attempt failed.");
            w.Family("vulnverdict_feed_overdue", "gauge", "1 when the feed is past its schedule plus the grace period.");
            w.Family("vulnverdict_feed_records", "gauge", "Records in the feed's last run.");
            foreach (var f in feeds)
            {
                var l = ("feed", f.Name);
                if (f.LastSuccess is { } ok)
                {
                    w.Sample("vulnverdict_feed_last_success_timestamp_seconds", Unix(ok), l);
                    w.Sample("vulnverdict_feed_age_seconds", Math.Max((now - ok).TotalSeconds, 0), l);
                }
                w.Sample("vulnverdict_feed_last_run_failed", f.LastError is null ? 0 : 1, l);
                w.Sample("vulnverdict_feed_overdue", FeedHealth.IsOverdue(f, now) ? 1 : 0, l);
                w.Sample("vulnverdict_feed_records", f.RecordsLastRun, l);
            }
        });

        await Section("connectors", async () =>
        {
            var connectors = await db.Connectors.AsNoTracking().OrderBy(c => c.CreatedAt).ToListAsync(ct);
            w.Family("vulnverdict_connector_last_success_timestamp_seconds", "gauge", "When each connector last completed a run.");
            w.Family("vulnverdict_connector_last_run_duration_seconds", "gauge", "How long each connector's last successful run took.");
            w.Family("vulnverdict_connector_assets", "gauge", "Assets in each connector's last run.");
            w.Family("vulnverdict_connector_consecutive_failures", "gauge", "Failed runs in a row.");
            w.Family("vulnverdict_connector_last_run_partial", "gauge", "1 when the last run completed with warnings (part of the source could not be read).");
            foreach (var c in connectors)
            {
                // the display name is the customer's own text and often a hostname, so the label is the short id
                var l = new[] { ("connector", c.Id.ToString("N")[..8]), ("adapter", c.AdapterId) };
                if (c.LastSuccess is { } ok)
                {
                    w.Sample("vulnverdict_connector_last_success_timestamp_seconds", Unix(ok), l);
                    if (c.LastAttempt is { } started && ok >= started) w.Sample("vulnverdict_connector_last_run_duration_seconds", (ok - started).TotalSeconds, l);
                }
                w.Sample("vulnverdict_connector_assets", c.AssetsLastRun, l);
                w.Sample("vulnverdict_connector_consecutive_failures", c.ConsecutiveFailures, l);
                w.Sample("vulnverdict_connector_last_run_partial", c.ConsecutiveFailures == 0 && c.LastError is { } e && e.StartsWith("Warnings:", StringComparison.Ordinal) ? 1 : 0, l);
            }
        });

        await Section("evaluation", async () =>
        {
            if (Stamp(await _settings.GetStateAsync(SettingsService.Keys.LastEvaluation, ct)) is { } last)
            {
                w.Family("vulnverdict_evaluation_last_timestamp_seconds", "gauge", "When verdicts were last evaluated in full.");
                w.Sample("vulnverdict_evaluation_last_timestamp_seconds", Unix(last));
            }
            if (double.TryParse(await _settings.GetStateAsync(EvaluationSecondsKey, ct), NumberStyles.Float, CultureInfo.InvariantCulture, out var seconds))
            {
                w.Family("vulnverdict_evaluation_duration_seconds", "gauge", "How long the last full evaluation took.");
                w.Sample("vulnverdict_evaluation_duration_seconds", seconds);
            }
            var failedSubjects = 0;
            try
            {
                if (await _settings.GetStateAsync(VerdictEvaluator.FailedSubjectsKey, ct) is { } json && JsonSerializer.Deserialize<VerdictEvaluator.FailedSubjects>(json) is { } f)
                    failedSubjects = f.Entries.Count + f.Software.Count;
            }
            catch (JsonException) { }
            w.Family("vulnverdict_evaluation_failed_subjects", "gauge", "Watchlist entries and software the last evaluation could not evaluate (retried on their own).");
            w.Sample("vulnverdict_evaluation_failed_subjects", failedSubjects);
        });

        await Section("outbound", async () =>
        {
            var tickets = await db.Tickets.CountAsync(ct);
            var hooksOk = await db.WebhookDeliveries.CountAsync(d => d.StatusCode >= 200 && d.StatusCode < 300, ct);
            var hooksAll = await db.WebhookDeliveries.CountAsync(ct);
            w.Family("vulnverdict_tickets_raised_total", "counter", "Tickets raised (email or helpdesk adapter).");
            w.Sample("vulnverdict_tickets_raised_total", tickets);
            w.Family("vulnverdict_webhook_deliveries_total", "counter", "Webhook delivery attempts by result.");
            w.Sample("vulnverdict_webhook_deliveries_total", hooksOk, ("result", "success"));
            w.Sample("vulnverdict_webhook_deliveries_total", hooksAll - hooksOk, ("result", "failure"));
        });

        await Section("counters", async () =>
        {
            var counters = await db.MetricCounters.AsNoTracking().ToListAsync(ct);
            long One(string name) => counters.Where(c => c.Name == name).Sum(c => c.Value);
            w.Family("vulnverdict_mail_sent_total", "counter", "Messages handed to the mail transport.");
            w.Sample("vulnverdict_mail_sent_total", One(MetricCounters.MailSent));
            w.Family("vulnverdict_mail_failed_total", "counter", "Messages the mail transport refused or could not send.");
            w.Sample("vulnverdict_mail_failed_total", One(MetricCounters.MailFailed));
            w.Family("vulnverdict_tickets_failed_total", "counter", "Tickets that could not be raised.");
            w.Sample("vulnverdict_tickets_failed_total", One(MetricCounters.TicketsFailed));
            w.Family("vulnverdict_feed_failures_total", "counter", "Failed feed runs, by feed.");
            foreach (var c in counters.Where(c => c.Name == MetricCounters.FeedFailures).OrderBy(c => c.Label, StringComparer.Ordinal))
                w.Sample("vulnverdict_feed_failures_total", c.Value, ("feed", c.Label));
        });

        await Section("backup", async () =>
        {
            var health = await BackupService.HealthAsync(_settings, null, now, ct);
            w.Family("vulnverdict_backup_last_run_ok", "gauge", "1 when the last backup attempt succeeded.");
            w.Sample("vulnverdict_backup_last_run_ok", health.Last is { Ok: true } ? 1 : 0);
            if (health.LastOk is { } ok)
            {
                w.Family("vulnverdict_backup_last_success_timestamp_seconds", "gauge", "When the last good backup was taken.");
                w.Sample("vulnverdict_backup_last_success_timestamp_seconds", Unix(ok.At));
                w.Family("vulnverdict_backup_age_seconds", "gauge", "Seconds since the last good backup.");
                w.Sample("vulnverdict_backup_age_seconds", Math.Max((now - ok.At).TotalSeconds, 0));
                w.Family("vulnverdict_backup_size_bytes", "gauge", "Size of the last good backup archive.");
                w.Sample("vulnverdict_backup_size_bytes", ok.Bytes);
                w.Family("vulnverdict_backup_duration_seconds", "gauge", "How long the last good backup took.");
                w.Sample("vulnverdict_backup_duration_seconds", ok.Seconds);
            }
        });

        await Section("licence and bundle", async () =>
        {
            var licence = LicenseService.Parse((await _settings.LoadAsync(ct)).LicenceKey);
            w.Family("vulnverdict_licence_valid", "gauge", "1 with a valid licence, 0 with an invalid or expired one; absent without a licence key.");
            if (licence.Present) w.Sample("vulnverdict_licence_valid", licence.Valid ? 1 : 0);
            if (licence.Expires is { } expires)
            {
                w.Family("vulnverdict_licence_expiry_timestamp_seconds", "gauge", "When the licence expires.");
                w.Sample("vulnverdict_licence_expiry_timestamp_seconds", Unix(expires));
            }
            if (await BundleApplier.CurrentAsync(db, ct) is { } bundle)
            {
                w.Family("vulnverdict_bundle_built_timestamp_seconds", "gauge", "When the applied feed bundle was built.");
                w.Sample("vulnverdict_bundle_built_timestamp_seconds", Unix(bundle.BuiltAt));
                w.Family("vulnverdict_bundle_age_seconds", "gauge", "Seconds since the applied feed bundle was built.");
                w.Sample("vulnverdict_bundle_age_seconds", Math.Max((now - DateTime.SpecifyKind(bundle.BuiltAt, DateTimeKind.Utc)).TotalSeconds, 0));
            }
        });

        w.Family("vulnverdict_metrics_sections_failed", "gauge", "Sections of this page that could not be read on this scrape.");
        w.Sample("vulnverdict_metrics_sections_failed", failed);
        return w.ToString();
    }
}
