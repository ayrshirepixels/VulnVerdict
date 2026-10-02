using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

/// <summary>/metrics: the output parses as the Prometheus text format, says nothing that identifies an asset, and is never open.</summary>
public class MetricsTests : IDisposable
{
    private readonly OpsTestHost _host = new();
    private static readonly DateTime Now = new(2026, 10, 2, 9, 0, 0, DateTimeKind.Utc);

    public void Dispose() => _host.Dispose();

    // ---- a strict reader of the text format

    private sealed record Sample(string Name, Dictionary<string, string> Labels, double Value);

    private static readonly Regex NameRx = new(@"^[a-zA-Z_:][a-zA-Z0-9_:]*$");
    private static readonly Regex SampleRx = new(@"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})? (\S+)$");
    private static readonly Regex LabelRx = new(@"\G([a-zA-Z_][a-zA-Z0-9_]*)=""((?:[^""\\]|\\.)*)""(?:,|$)");

    /// <summary>Parses the exposition format back, failing on anything a Prometheus server would reject.</summary>
    private static (List<Sample> Samples, Dictionary<string, string> Types) Parse(string text)
    {
        Assert.EndsWith("\n", text);
        var samples = new List<Sample>();
        var types = new Dictionary<string, string>();
        var help = new HashSet<string>();
        var closed = new HashSet<string>();   // families whose samples have ended: they must not appear again
        string? current = null;
        foreach (var line in text.TrimEnd('\n').Split('\n'))
        {
            if (line.StartsWith("# HELP "))
            {
                var name = line.Split(' ')[2];
                Assert.Matches(NameRx, name);
                Assert.True(help.Add(name), "HELP twice for " + name);
                continue;
            }
            if (line.StartsWith("# TYPE "))
            {
                var parts = line.Split(' ');
                Assert.Equal(4, parts.Length);
                Assert.Contains(parts[3], new[] { "counter", "gauge", "untyped" });
                Assert.False(types.ContainsKey(parts[2]), "TYPE twice for " + parts[2]);
                types[parts[2]] = parts[3];
                continue;
            }
            if (line.StartsWith('#')) continue;
            var m = SampleRx.Match(line);
            Assert.True(m.Success, "not a sample line: " + line);
            var sampleName = m.Groups[1].Value;
            Assert.True(types.ContainsKey(sampleName), "sample before its TYPE: " + sampleName);
            if (current != sampleName)
            {
                if (current is not null) closed.Add(current);
                Assert.DoesNotContain(sampleName, closed);
                current = sampleName;
            }
            var labels = new Dictionary<string, string>();
            if (m.Groups[2].Success && m.Groups[2].Value.Length > 0)
            {
                var body = m.Groups[2].Value;
                var pos = 0;
                while (pos < body.Length)
                {
                    var l = LabelRx.Match(body, pos);
                    Assert.True(l.Success, "bad labels: " + line);
                    labels.Add(l.Groups[1].Value, l.Groups[2].Value.Replace("\\\"", "\"").Replace("\\n", "\n").Replace("\\\\", "\\"));
                    pos += l.Length;
                }
            }
            Assert.True(double.TryParse(m.Groups[3].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var value) || m.Groups[3].Value is "NaN" or "+Inf" or "-Inf", "bad value: " + line);
            samples.Add(new Sample(sampleName, labels, value));
            if (types[sampleName] == "counter") { Assert.EndsWith("_total", sampleName); Assert.True(value >= 0); }
        }
        // one series per name and label set
        Assert.Equal(samples.Count, samples.Select(s => s.Name + "|" + string.Join(",", s.Labels.OrderBy(l => l.Key).Select(l => l.Key + "=" + l.Value))).Distinct().Count());
        return (samples, types);
    }

    // ---- data

    private const string Hostname = "fw-edge-01.corp.example.co.uk";
    private const string AssetName = "FINANCE-LAPTOP-07";
    private const string ConnectorName = "FortiGate at 10.20.30.40 (head office)";

    private async Task SeedAsync()
    {
        await using var db = _host.Db.CreateDbContext();
        var entry = new WatchlistEntry { Id = Guid.NewGuid(), Vendor = "Fortinet", Product = "FortiOS", VendorNorm = "fortinet", ProductNorm = "fortios", Version = "7.2.5", AssetName = Hostname, CreatedAt = Now.AddDays(-40), UpdatedAt = Now };
        var asset = new Asset { Id = Guid.NewGuid(), DisplayName = AssetName, HostnamesJson = "[\"" + Hostname + "\"]", IpAddressesJson = "[\"10.20.30.41\"]", FirstSeen = Now.AddDays(-40), LastSeen = Now };
        var software = new SoftwareInstance { Id = Guid.NewGuid(), AssetId = asset.Id, Vendor = "Veeam", Product = "Backup \"Enterprise\" & Replication", Version = "12.1", VendorNorm = "veeam", ProductNorm = "backup replication", FirstSeen = Now.AddDays(-40), LastSeen = Now };
        db.Watchlist.Add(entry); db.Assets.Add(asset); db.Software.Add(software);
        for (var i = 1; i <= 5; i++) db.Cves.Add(new Cve { Id = "CVE-2026-100" + i, State = "PUBLISHED", RetrievedAt = Now });

        Verdict V(int n, VerdictTier tier, VerdictState state, DateTime created, DateTime? due, bool inventory = false) => new()
        {
            Id = Guid.NewGuid(), CveId = "CVE-2026-100" + n, WatchlistEntryId = inventory ? null : entry.Id, SoftwareInstanceId = inventory ? software.Id : null, AssetId = inventory ? asset.Id : null,
            Subject = (inventory ? "Veeam Backup 12.1 on " + AssetName : "Fortinet FortiOS 7.2.5 on " + Hostname), Tier = tier, State = state, CreatedAt = created, UpdatedAt = Now, LastEvaluatedAt = Now, SlaDue = due,
            Sentence = "FortiOS 7.2.5 on " + Hostname + ": exploited in the wild."
        };
        var overdue = V(1, VerdictTier.FixToday, VerdictState.Open, Now.AddDays(-5), Now.AddDays(-3));
        var open = V(2, VerdictTier.FixThisWeek, VerdictState.Open, Now.AddDays(-2), Now.AddDays(5));
        var inventory = V(3, VerdictTier.FixThisWeek, VerdictState.Open, Now.AddDays(-2), Now.AddDays(5), inventory: true);
        var closed = V(4, VerdictTier.FixThisWeek, VerdictState.Closed, Now.AddDays(-10), null);
        var ignored = V(5, VerdictTier.IgnoreTracked, VerdictState.Open, Now.AddDays(-10), null);
        db.Verdicts.AddRange(overdue, open, inventory, closed, ignored);
        db.VerdictHistory.Add(new VerdictHistory { VerdictId = closed.Id, At = Now.AddDays(-6), Kind = "state", From = "Open", To = "Closed", Reason = "marked done" });

        db.FeedStatuses.Add(new FeedStatus { Name = "kev", DisplayName = "CISA KEV", IntervalMinutes = 60, LastAttempt = Now.AddMinutes(-30), LastSuccess = Now.AddMinutes(-30), RecordsLastRun = 1200 });
        db.FeedStatuses.Add(new FeedStatus { Name = "epss", DisplayName = "EPSS", IntervalMinutes = 1440, LastAttempt = Now.AddHours(-1), LastSuccess = Now.AddDays(-3), LastError = "HTTP 503 from " + Hostname });
        db.Connectors.Add(new Connector { Id = Guid.Parse("aaaaaaaa-1111-2222-3333-444444444444"), AdapterId = "fortigate", DisplayName = ConnectorName, CreatedAt = Now.AddDays(-40), LastAttempt = Now.AddMinutes(-10), LastSuccess = Now.AddMinutes(-9), AssetsLastRun = 42, LastError = "Warnings: " + Hostname + " refused the software list" });
        db.Tickets.Add(new Ticket { Id = Guid.NewGuid(), VerdictId = overdue.Id, CorrelationKey = "VV:1", SentAt = Now });
        db.WebhookDeliveries.Add(new WebhookDelivery { At = Now, Event = "verdict.created", VerdictId = overdue.Id, Url = "https://hooks.example.com/" + Hostname, StatusCode = 200 });
        db.WebhookDeliveries.Add(new WebhookDelivery { At = Now, Event = "verdict.created", VerdictId = open.Id, Url = "https://hooks.example.com/x", Error = "timeout" });
        db.Bundles.Add(new BundleState { Version = "202610010800", BuiltAt = Now.AddDays(-1), AppliedAt = Now.AddHours(-20), Source = "upload by admin" });
        await db.SaveChangesAsync();

        await _host.Settings.SetStateAsync(SettingsService.Keys.WorkerHeartbeat, Now.AddMinutes(-1).ToString("O"));
        await _host.Settings.SetStateAsync(SettingsService.Keys.LastEvaluation, Now.AddMinutes(-20).ToString("O"));
        await _host.Settings.SetStateAsync(MetricsService.EvaluationSecondsKey, "12.5");
        await _host.Settings.SetStateAsync(VerdictEvaluator.FailedSubjectsKey, System.Text.Json.JsonSerializer.Serialize(new VerdictEvaluator.FailedSubjects(Now, new List<Guid> { entry.Id }, new List<Guid> { software.Id, Guid.NewGuid() })));
        var backup = new BackupResult(Now.AddHours(-7), true, "scheduled", "vulnverdict-20261002-013000Z-scheduled.vvbak", 123456, 4.5, null, false);
        await _host.Settings.SetStateAsync(BackupService.LastOkKey, System.Text.Json.JsonSerializer.Serialize(backup));
        await _host.Settings.SetStateAsync(BackupService.HistoryKey, System.Text.Json.JsonSerializer.Serialize(new[] { backup }));
        await MetricCounters.AddAsync(_host.Db, MetricCounters.MailSent);
        await MetricCounters.AddAsync(_host.Db, MetricCounters.MailSent, "", 2);
        await MetricCounters.AddAsync(_host.Db, MetricCounters.MailFailed);
        await MetricCounters.AddAsync(_host.Db, MetricCounters.FeedFailures, "epss", 4);
    }

    private static double Value(List<Sample> samples, string name, params (string, string)[] labels) =>
        samples.Single(s => s.Name == name && labels.All(l => s.Labels.GetValueOrDefault(l.Item1) == l.Item2)).Value;

    [Fact]
    public async Task The_output_parses_and_reports_what_the_database_holds()
    {
        await SeedAsync();
        var text = await new MetricsService(_host.Db, _host.Settings).RenderAsync(Now);
        var (samples, types) = Parse(text);

        Assert.Equal(0, Value(samples, "vulnverdict_metrics_sections_failed"));
        Assert.Equal(1, Value(samples, "vulnverdict_worker_up"));
        Assert.Equal(1, Value(samples, "vulnverdict_verdicts", ("tier", "fix_today"), ("state", "open")));
        Assert.Equal(2, Value(samples, "vulnverdict_verdicts", ("tier", "fix_this_week"), ("state", "open")));
        Assert.Equal(1, Value(samples, "vulnverdict_verdicts", ("tier", "fix_this_week"), ("state", "closed")));
        Assert.Equal(0, Value(samples, "vulnverdict_verdicts", ("tier", "next_patch_cycle"), ("state", "accepted_risk")));
        Assert.Equal(25, samples.Count(s => s.Name == "vulnverdict_verdicts"));
        Assert.Equal(1, Value(samples, "vulnverdict_verdicts_overdue", ("tier", "fix_today")));
        Assert.Equal(0, Value(samples, "vulnverdict_verdicts_overdue", ("tier", "fix_this_week")));
        Assert.Equal(4, Value(samples, "vulnverdict_verdicts_opened_total"));
        Assert.Equal(1, Value(samples, "vulnverdict_verdicts_closed_total"));
        Assert.Equal("counter", types["vulnverdict_verdicts_closed_total"]);
        // closed four days after it opened
        Assert.Equal(4 * 86400, Value(samples, "vulnverdict_time_to_fix_mean_seconds", ("tier", "fix_this_week")), 1);

        Assert.Equal(1800, Value(samples, "vulnverdict_feed_age_seconds", ("feed", "kev")), 1);
        Assert.Equal(new DateTimeOffset(Now.AddMinutes(-30)).ToUnixTimeSeconds(), Value(samples, "vulnverdict_feed_last_success_timestamp_seconds", ("feed", "kev")), 1);
        Assert.Equal(1, Value(samples, "vulnverdict_feed_last_run_failed", ("feed", "epss")));
        Assert.Equal(1, Value(samples, "vulnverdict_feed_overdue", ("feed", "epss")));
        Assert.Equal(4, Value(samples, "vulnverdict_feed_failures_total", ("feed", "epss")));

        var connector = new[] { ("connector", "aaaaaaaa"), ("adapter", "fortigate") };
        Assert.Equal(60, Value(samples, "vulnverdict_connector_last_run_duration_seconds", connector), 1);
        Assert.Equal(42, Value(samples, "vulnverdict_connector_assets", connector));
        Assert.Equal(1, Value(samples, "vulnverdict_connector_last_run_partial", connector));

        Assert.Equal(12.5, Value(samples, "vulnverdict_evaluation_duration_seconds"));
        Assert.Equal(3, Value(samples, "vulnverdict_evaluation_failed_subjects"));
        Assert.Equal(3, Value(samples, "vulnverdict_mail_sent_total"));
        Assert.Equal(1, Value(samples, "vulnverdict_mail_failed_total"));
        Assert.Equal(0, Value(samples, "vulnverdict_tickets_failed_total"));
        Assert.Equal(1, Value(samples, "vulnverdict_tickets_raised_total"));
        Assert.Equal(1, Value(samples, "vulnverdict_webhook_deliveries_total", ("result", "success")));
        Assert.Equal(1, Value(samples, "vulnverdict_webhook_deliveries_total", ("result", "failure")));
        Assert.Equal(7 * 3600, Value(samples, "vulnverdict_backup_age_seconds"), 1);
        Assert.Equal(123456, Value(samples, "vulnverdict_backup_size_bytes"));
        Assert.Equal(1, Value(samples, "vulnverdict_backup_last_run_ok"));
        Assert.Equal(86400, Value(samples, "vulnverdict_bundle_age_seconds"), 1);
        Assert.Equal(1, Value(samples, "vulnverdict_assets"));
        // product names are escaped, and read back as they were
        Assert.Equal(1, Value(samples, "vulnverdict_product_open_verdicts", ("product", "Veeam Backup \"Enterprise\" & Replication")));
        Assert.Equal(2, Value(samples, "vulnverdict_product_open_verdicts", ("product", "Fortinet FortiOS")));
    }

    [Fact]
    public async Task Nothing_in_the_output_identifies_an_asset()
    {
        await SeedAsync();
        var text = await new MetricsService(_host.Db, _host.Settings).RenderAsync(Now);
        var (samples, _) = Parse(text);

        Assert.DoesNotContain(Hostname, text);
        Assert.DoesNotContain("corp.example", text);
        Assert.DoesNotContain(AssetName, text);
        Assert.DoesNotContain("10.20.30", text);
        Assert.DoesNotContain("head office", text);
        Assert.DoesNotContain("CVE-", text);
        // only these label names exist, so a new one is a decision someone has to make here
        var allowed = new HashSet<string> { "version", "tier", "state", "feed", "connector", "adapter", "result", "product" };
        Assert.All(samples.SelectMany(s => s.Labels.Keys), k => Assert.Contains(k, allowed));
        Assert.True(samples.Count(s => s.Name == "vulnverdict_product_open_verdicts") <= MetricsService.TopProducts);
    }

    [Fact]
    public async Task An_empty_console_still_produces_a_valid_page()
    {
        var (samples, _) = Parse(await new MetricsService(_host.Db, _host.Settings).RenderAsync(Now));
        Assert.Equal(0, Value(samples, "vulnverdict_worker_up"));
        Assert.Equal(0, Value(samples, "vulnverdict_metrics_sections_failed"));
        Assert.DoesNotContain(samples, s => s.Name == "vulnverdict_backup_age_seconds");
    }

    [Fact]
    public void Label_values_and_numbers_are_written_as_the_format_requires()
    {
        var w = new PrometheusWriter();
        w.Family("b_total", "counter", "Second family.\nTwo lines \\ here");
        w.Family("a", "gauge", "First family");
        w.Sample("b_total", 1, ("k", "quote \" backslash \\ newline \n end"));
        w.Sample("a", 0.5);
        w.Sample("b_total", 2, ("k", "plain"));
        w.Sample("a", double.PositiveInfinity, ("x", "1"));
        var text = w.ToString();
        Assert.Contains("# HELP b_total Second family.\\nTwo lines \\\\ here\n", text);
        Assert.Contains("b_total{k=\"quote \\\" backslash \\\\ newline \\n end\"} 1\n", text);
        Assert.Contains("a{x=\"1\"} +Inf\n", text);
        var (samples, _) = Parse(text);
        // samples of a family stay together even though they were added interleaved
        Assert.Equal(new[] { "b_total", "b_total", "a", "a" }, samples.Select(s => s.Name));
        Assert.Equal("quote \" backslash \\ newline \n end", samples[0].Labels["k"]);
    }

    // ---- who may read it

    private static readonly IPAddress Scraper = IPAddress.Parse("10.0.5.20");

    [Fact]
    public async Task Metrics_are_off_by_default_and_never_anonymous()
    {
        var auth = new MetricsAuth(_host.Db);
        Assert.Equal(MetricsAccess.Disabled, await auth.AuthoriseAsync(null, Scraper));
        Assert.Equal(MetricsAccess.Disabled, await auth.AuthoriseAsync("Bearer anything", IPAddress.Loopback));

        var token = await auth.EnableAsync("admin");
        Assert.NotNull(token);
        Assert.StartsWith(MetricsAuth.TokenPrefix, token);
        Assert.Equal(MetricsAccess.Denied, await auth.AuthoriseAsync(null, Scraper));
        Assert.Equal(MetricsAccess.Denied, await auth.AuthoriseAsync("", IPAddress.Loopback));
        Assert.Equal(MetricsAccess.Denied, await auth.AuthoriseAsync("Bearer ", Scraper));
        Assert.Equal(MetricsAccess.Denied, await auth.AuthoriseAsync("Bearer " + token + "x", Scraper));
        Assert.Equal(MetricsAccess.Denied, await auth.AuthoriseAsync("Basic " + token, Scraper));
        Assert.Equal(MetricsAccess.Allowed, await auth.AuthoriseAsync("Bearer " + token, Scraper));

        // only the hash is stored
        await using (var db = _host.Db.CreateDbContext())
        {
            Assert.Equal(ApiTokenService.Hash(token!), db.Settings.Single(s => s.Key == MetricsAuth.TokenHashKey).Value);
            Assert.DoesNotContain(db.Settings, s => s.Value != null && s.Value.Contains(token!));
            Assert.DoesNotContain(db.Audit, a => (a.After ?? "").Contains(token!));
        }

        // revoked: enabled, but with no token and no allow-list nobody gets in
        await auth.RevokeTokenAsync("admin");
        Assert.Equal(MetricsAccess.Denied, await auth.AuthoriseAsync("Bearer " + token, Scraper));
        Assert.Equal(MetricsAccess.Denied, await auth.AuthoriseAsync(null, null));

        var replacement = await auth.GenerateTokenAsync("admin");
        Assert.NotEqual(token, replacement);
        Assert.Equal(MetricsAccess.Allowed, await auth.AuthoriseAsync("Bearer " + replacement, Scraper));
        await auth.DisableAsync("admin");
        Assert.Equal(MetricsAccess.Disabled, await auth.AuthoriseAsync("Bearer " + replacement, Scraper));
    }

    [Fact]
    public async Task The_metrics_token_and_the_api_tokens_do_not_open_each_others_doors()
    {
        var auth = new MetricsAuth(_host.Db);
        var api = new ApiTokenService(_host.Db, _host.Protection);
        var metricsToken = await auth.EnableAsync("admin");
        var read = await api.GenerateAsync(ApiScope.Read, "admin");
        var write = await api.GenerateAsync(ApiScope.ReadWrite, "admin");

        Assert.Equal(ApiScope.None, await api.AuthoriseAsync("Bearer " + metricsToken));
        Assert.Equal(MetricsAccess.Denied, await auth.AuthoriseAsync("Bearer " + read, Scraper));
        Assert.Equal(MetricsAccess.Denied, await auth.AuthoriseAsync("Bearer " + write, Scraper));
        Assert.Equal(MetricsAccess.Allowed, await auth.AuthoriseAsync("Bearer " + metricsToken, Scraper));
    }

    [Fact]
    public async Task An_allow_list_lets_listed_scrapers_in_without_a_token()
    {
        var auth = new MetricsAuth(_host.Db);
        await auth.SetAllowListAsync("10.0.5.20, 192.168.8.0/24\n2001:db8::/32", "admin");
        // with an allow-list in place, turning metrics on does not also mint a token
        Assert.Null(await auth.EnableAsync("admin"));

        Assert.Equal(MetricsAccess.Allowed, await auth.AuthoriseAsync(null, Scraper));
        Assert.Equal(MetricsAccess.Allowed, await auth.AuthoriseAsync(null, IPAddress.Parse("::ffff:10.0.5.20")));
        Assert.Equal(MetricsAccess.Allowed, await auth.AuthoriseAsync(null, IPAddress.Parse("192.168.8.77")));
        Assert.Equal(MetricsAccess.Allowed, await auth.AuthoriseAsync(null, IPAddress.Parse("2001:db8:1::5")));
        Assert.Equal(MetricsAccess.Denied, await auth.AuthoriseAsync(null, IPAddress.Parse("10.0.5.21")));
        Assert.Equal(MetricsAccess.Denied, await auth.AuthoriseAsync(null, IPAddress.Parse("192.168.9.1")));
        Assert.Equal(MetricsAccess.Denied, await auth.AuthoriseAsync(null, IPAddress.Loopback));
        Assert.Equal(MetricsAccess.Denied, await auth.AuthoriseAsync(null, null));

        await Assert.ThrowsAsync<ArgumentException>(() => auth.SetAllowListAsync("10.0.5.0/33", "admin"));
        await Assert.ThrowsAsync<ArgumentException>(() => auth.SetAllowListAsync("scraper.internal", "admin"));
        Assert.Equal("10.0.5.20, 192.168.8.0/24, 2001:db8::/32", (await auth.StatusAsync()).AllowList);

        await auth.SetAllowListAsync("", "admin");
        Assert.Equal(MetricsAccess.Denied, await auth.AuthoriseAsync(null, Scraper));
    }

    [Fact]
    public async Task Counters_add_up_across_writers()
    {
        await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => MetricCounters.AddAsync(_host.Db, MetricCounters.MailSent)));
        await MetricCounters.AddAsync(_host.Db, MetricCounters.FeedFailures, "kev");
        await using var db = _host.Db.CreateDbContext();
        Assert.Equal(20, db.MetricCounters.Single(c => c.Name == MetricCounters.MailSent).Value);
        Assert.Equal(1, db.MetricCounters.Single(c => c.Name == MetricCounters.FeedFailures && c.Label == "kev").Value);
    }
}
