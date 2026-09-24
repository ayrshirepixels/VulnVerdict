using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Digest;
using VulnVerdict.Core.Feeds;

namespace VulnVerdict.Core.Services;

public sealed class WorkerOptions
{
    public string DataDir { get; set; } = "data";
    /// <summary>Baseline CVE load: only CVEs from this year on (0 = everything). Deltas always load fully.</summary>
    public int CveMinYear { get; set; } = 0;
    public int LoopSeconds { get; set; } = 60;
}

/// <summary>
/// Section 10.1 "worker": feed ingestion, matching, verdict evaluation, digest generation, ticket emission,
/// self-monitoring. One loop, idempotent steps, nothing to babysit.
/// </summary>
public sealed class WorkerService : BackgroundService
{
    private readonly IServiceProvider _sp;
    private readonly ILogger<WorkerService> _log;
    private readonly WorkerOptions _opt;

    public WorkerService(IServiceProvider sp, ILogger<WorkerService> log, WorkerOptions opt)
    {
        _sp = sp; _log = log; _opt = opt;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        _log.LogInformation("Worker starting; data dir {Dir}", Path.GetFullPath(_opt.DataDir));
        Directory.CreateDirectory(_opt.DataDir);
        await EnsureFeedRowsAsync(ct);
        // the heartbeat runs on its own timer: a long feed load or evaluation must never look like a dead worker
        _ = Task.Run(() => HeartbeatLoopAsync(ct), ct);
        while (!ct.IsCancellationRequested)
        {
            try
            {
                // section 10.2: with a central bundle configured, the bundle replaces the public feeds
                bool feedsRan;
                using (var bundleScope = _sp.CreateScope())
                {
                    var bundles = bundleScope.ServiceProvider.GetRequiredService<BundleService>();
                    var check = await bundles.CheckAndApplyAsync(ct);
                    feedsRan = check.Outcome == BundleOutcome.Applied || (!bundles.BundleModeEnabled && await RunDueFeedsAsync(ct));
                }
                var connectorsRan = await RunDueConnectorsAsync(ct);
                var evaluateRequested = await EvaluateRequestedAsync(ct);
                if (feedsRan || connectorsRan || evaluateRequested || await EvaluationDueAsync(ct))
                {
                    using var scope = _sp.CreateScope();
                    _activity = "evaluating verdicts";
                    await scope.ServiceProvider.GetRequiredService<VerdictEvaluator>().EvaluateAllAsync(ct);
                    await scope.ServiceProvider.GetRequiredService<SettingsService>().SetStateAsync(SettingsService.Keys.EvaluateRequested, null, ct);
                }
                await NotifyAsync(ct);
                await DailyDigestIfDueAsync(ct);
                await WeeklyReportIfDueAsync(ct);
                await FeedHealthAlertAsync(ct);
                using (var scope = _sp.CreateScope())
                {
                    await scope.ServiceProvider.GetRequiredService<TelemetryService>().SendIfDueAsync(ct);
                    await scope.ServiceProvider.GetRequiredService<MspReportService>().SendIfDueAsync(ct);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
            catch (Exception ex)
            {
                _log.LogError(ex, "Worker loop error");
            }
            _activity = "idle";
            try { await Task.Delay(TimeSpan.FromSeconds(_opt.LoopSeconds), ct); } catch (OperationCanceledException) { }
        }
    }

    private volatile string _activity = "idle";
    /// <summary>What the worker is doing right now, shown on the Sources page.</summary>
    public const string ActivityKey = "state:worker:activity";

    private async Task HeartbeatLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                using var scope = _sp.CreateScope();
                var settings = scope.ServiceProvider.GetRequiredService<SettingsService>();
                await settings.SetStateAsync(SettingsService.Keys.WorkerHeartbeat, DateTime.UtcNow.ToString("O"), ct);
                await settings.SetStateAsync(ActivityKey, _activity, ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
            catch (Exception ex) { _log.LogDebug(ex, "Heartbeat write failed"); }
            try { await Task.Delay(TimeSpan.FromSeconds(30), ct); } catch (OperationCanceledException) { }
        }
    }

    private async Task EnsureFeedRowsAsync(CancellationToken ct)
    {
        using var scope = _sp.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<VvDbContext>();
        var feeds = scope.ServiceProvider.GetServices<IFeed>().ToList();
        foreach (var f in feeds)
        {
            var row = await db.FeedStatuses.FirstOrDefaultAsync(x => x.Name == f.Name, ct);
            if (row is null) db.FeedStatuses.Add(new FeedStatus { Name = f.Name, DisplayName = f.DisplayName, IntervalMinutes = f.IntervalMinutes });
            else { row.DisplayName = f.DisplayName; row.IntervalMinutes = f.IntervalMinutes; row.Running = false; }
        }
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Run every feed that is due or explicitly requested. Returns true if any feed succeeded.</summary>
    private async Task<bool> RunDueFeedsAsync(CancellationToken ct)
    {
        var any = false;
        using var scope = _sp.CreateScope();
        var feeds = scope.ServiceProvider.GetServices<IFeed>().ToList();
        var factory = scope.ServiceProvider.GetRequiredService<IDbContextFactory<VvDbContext>>();
        var http = scope.ServiceProvider.GetRequiredService<IHttpClientFactory>().CreateClient("feeds");
        var now = DateTime.UtcNow;

        // KEV and the exploit indexes are small; run them before the CVE list so the first evaluation has exploit data
        foreach (var feed in feeds.OrderBy(f => f.Name == FeedNames.CveList ? 1 : 0))
        {
            ct.ThrowIfCancellationRequested();
            await using var statusDb = await factory.CreateDbContextAsync(ct);
            var status = await statusDb.FeedStatuses.FirstAsync(s => s.Name == feed.Name, ct);
            var due = status.RunRequested || status.LastSuccess is null || now - status.LastSuccess.Value >= TimeSpan.FromMinutes(feed.IntervalMinutes)
                      || (status.LastError is not null && status.LastAttempt is not null && now - status.LastAttempt.Value >= TimeSpan.FromMinutes(15));
            if (!due) continue;
            if (status.LastError is not null && status.LastAttempt is not null && now - status.LastAttempt.Value < TimeSpan.FromMinutes(15) && !status.RunRequested) continue;

            status.Running = true; status.RunRequested = false; status.LastAttempt = now; status.Progress = "Starting";
            await statusDb.SaveChangesAsync(ct);
            _activity = "loading feed " + feed.DisplayName;
            _log.LogInformation("Feed {Feed} starting", feed.Name);

            try
            {
                await using var db = await factory.CreateDbContextAsync(ct);
                db.Database.SetCommandTimeout(TimeSpan.FromMinutes(30));
                var ctx = new FeedContext
                {
                    Db = db, Http = http, Log = _log, DataDir = _opt.DataDir, Cursor = status.Cursor,
                    Progress = msg => { _ = ReportProgressAsync(factory, feed.Name, msg); }
                };
                var result = await feed.RunAsync(ctx, ct);
                status.LastSuccess = DateTime.UtcNow; status.LastError = null; status.RecordsLastRun = result.Records; status.Cursor = result.Cursor;
                status.Progress = result.Note;
                any = true;
                _log.LogInformation("Feed {Feed} done: {Records} records, cursor {Cursor} {Note}", feed.Name, result.Records, result.Cursor, result.Note);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { status.Running = false; await statusDb.SaveChangesAsync(CancellationToken.None); throw; }
            catch (Exception ex)
            {
                status.LastError = ex.Message.Length > 2000 ? ex.Message[..2000] : ex.Message;
                status.Progress = null;
                _log.LogError(ex, "Feed {Feed} failed", feed.Name);
            }
            finally
            {
                status.Running = false;
                await statusDb.SaveChangesAsync(CancellationToken.None);
            }
        }
        return any;
    }

    private static async Task ReportProgressAsync(IDbContextFactory<VvDbContext> factory, string feed, string msg)
    {
        try
        {
            await using var db = await factory.CreateDbContextAsync();
            await db.FeedStatuses.Where(f => f.Name == feed).ExecuteUpdateAsync(u => u.SetProperty(f => f.Progress, msg.Length > 256 ? msg[..256] : msg));
        }
        catch { }
    }

    /// <summary>Section 9.1: run connectors that are due or requested; three failures in a row raise the administrator alert.</summary>
    private async Task<bool> RunDueConnectorsAsync(CancellationToken ct)
    {
        using var scope = _sp.CreateScope();
        var connectors = scope.ServiceProvider.GetRequiredService<ConnectorService>();
        var inventory = scope.ServiceProvider.GetRequiredService<InventoryService>();
        var licence = scope.ServiceProvider.GetRequiredService<LicenseService>();
        var now = DateTime.UtcNow;
        var any = false;
        // phase 5: a licensed console stops collecting new assets beyond its tier's cap (the banner explains; nothing is deleted)
        if (!await licence.WithinAssetCapAsync(ct))
        {
            _log.LogWarning("Asset cap reached for this licence tier; connector runs paused");
            await AdminAlertAsync(scope.ServiceProvider, "Asset cap reached", "The licence tier's asset cap has been reached. Connector collection is paused until assets are archived or the licence is upgraded.", ct);
            return false;
        }
        foreach (var c in await connectors.ListAsync(ct))
        {
            ct.ThrowIfCancellationRequested();
            if (!c.Enabled && !c.RunRequested) continue;
            var due = c.RunRequested || c.LastSuccess is null || now - c.LastSuccess.Value >= TimeSpan.FromMinutes(c.IntervalMinutes);
            if (c.LastError is not null && c.LastSuccess is not null && c.LastAttempt is not null && now - c.LastAttempt.Value < TimeSpan.FromMinutes(15) && !c.RunRequested) due = false;
            if (!due) continue;
            var before = c.ConsecutiveFailures;
            _activity = "collecting from " + c.DisplayName;
            var result = await connectors.RunAsync(c.Id, ct);
            if (result is not null) any = true;
            else if (before + 1 == 3)
                await AdminAlertAsync(scope.ServiceProvider, "Connector " + c.DisplayName + " has failed three times in a row", "Adapter: " + c.AdapterId + "\nLast error: " + c.LastError, ct);
        }
        if (any)
        {
            await inventory.HousekeepAsync(ct);
            await inventory.RemapAsync(ct);
        }
        return any;
    }

    private async Task<bool> EvaluateRequestedAsync(CancellationToken ct)
    {
        using var scope = _sp.CreateScope();
        var s = scope.ServiceProvider.GetRequiredService<SettingsService>();
        return await s.GetStateAsync(SettingsService.Keys.EvaluateRequested, ct) is not null;
    }

    private async Task<bool> EvaluationDueAsync(CancellationToken ct)
    {
        using var scope = _sp.CreateScope();
        var s = scope.ServiceProvider.GetRequiredService<SettingsService>();
        var last = await s.GetStateAsync(SettingsService.Keys.LastEvaluation, ct);
        return last is null || !DateTime.TryParse(last, null, System.Globalization.DateTimeStyles.RoundtripKind, out var d) || DateTime.UtcNow - d > TimeSpan.FromHours(6);
    }

    private async Task NotifyAsync(CancellationToken ct)
    {
        using var scope = _sp.CreateScope();
        var digest = scope.ServiceProvider.GetRequiredService<DigestService>();
        var n = await digest.SendImmediateAsync(ct);
        if (n > 0) _log.LogInformation("Sent immediate Fix-today email for {Count} verdict(s)", n);
        var t = await digest.SendTicketsAsync(ct);
        if (t > 0) _log.LogInformation("Raised {Count} ticket(s)", t);
        await scope.ServiceProvider.GetRequiredService<WebhookService>().FlushPendingAsync(ct);
    }

    private async Task DailyDigestIfDueAsync(CancellationToken ct)
    {
        using var scope = _sp.CreateScope();
        var settingsSvc = scope.ServiceProvider.GetRequiredService<SettingsService>();
        var s = await settingsSvc.LoadAsync(ct);
        var tz = s.ResolveTimeZone();
        var localNow = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, tz);
        if (s.DigestWeekdaysOnly && localNow.DayOfWeek is DayOfWeek.Saturday or DayOfWeek.Sunday) return;
        if (!TimeOnly.TryParse(s.DigestTime, out var at)) at = new TimeOnly(7, 30);
        if (TimeOnly.FromDateTime(localNow) < at) return;
        var last = await settingsSvc.GetStateAsync(SettingsService.Keys.LastDailyDigest, ct);
        if (last is not null && DateTime.TryParse(last, null, System.Globalization.DateTimeStyles.RoundtripKind, out var lastUtc)
            && TimeZoneInfo.ConvertTimeFromUtc(lastUtc, tz).Date == localNow.Date) return;
        if (!s.SmtpConfigured || !s.Recipients.Any())
        {
            // still record that the day's digest was generated so the Today page can show it, without sending
            await settingsSvc.SetStateAsync(SettingsService.Keys.LastDailyDigest, DateTime.UtcNow.ToString("O"), ct);
            return;
        }
        var digest = scope.ServiceProvider.GetRequiredService<DigestService>();
        var run = await digest.SendDigestAsync(DigestKind.Daily, null, ct);
        if (run.SentAt is null)
        {
            // do not retry every minute all day; mark and alert
            await settingsSvc.SetStateAsync(SettingsService.Keys.LastDailyDigest, DateTime.UtcNow.ToString("O"), ct);
            await AdminAlertAsync(scope.ServiceProvider, "Daily digest could not be sent", run.Error ?? "unknown error", ct);
        }
    }

    private async Task WeeklyReportIfDueAsync(CancellationToken ct)
    {
        using var scope = _sp.CreateScope();
        var sent = await scope.ServiceProvider.GetRequiredService<Digest.ReportService>().SendIfDueAsync(ct);
        if (sent) _log.LogInformation("Weekly management report sent");
    }

    /// <summary>Section 7: a feed more than 24 hours stale triggers the administrator alert (at most once a day).</summary>
    private async Task FeedHealthAlertAsync(CancellationToken ct)
    {
        using var scope = _sp.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<VvDbContext>();
        var now = DateTime.UtcNow;
        var stale = await db.FeedStatuses.AsNoTracking()
            .Where(f => f.LastAttempt != null && (f.LastSuccess == null || f.LastSuccess < now.AddHours(-24)) && f.LastAttempt < now.AddHours(-1))
            .ToListAsync(ct);
        if (stale.Count == 0) return;
        var body = string.Join("\n", stale.Select(f => f.DisplayName + ": last success " + (f.LastSuccess?.ToString("u") ?? "never") + ", last error: " + (f.LastError ?? "none")));
        await AdminAlertAsync(scope.ServiceProvider, "Feeds stale for more than 24 hours", body, ct);
    }

    public static async Task AdminAlertAsync(IServiceProvider sp, string subject, string body, CancellationToken ct)
    {
        var settingsSvc = sp.GetRequiredService<SettingsService>();
        var s = await settingsSvc.LoadAsync(ct);
        if (!s.SmtpConfigured || string.IsNullOrWhiteSpace(s.AdminAlertAddress)) return;
        var last = await settingsSvc.GetStateAsync(SettingsService.Keys.LastAdminAlert, ct);
        if (last is not null && DateTime.TryParse(last, null, System.Globalization.DateTimeStyles.RoundtripKind, out var d) && DateTime.UtcNow - d < TimeSpan.FromHours(24)) return;
        var email = sp.GetRequiredService<EmailService>();
        try
        {
            await email.SendAsync(new[] { s.AdminAlertAddress }, "VulnVerdict administrator alert: " + subject,
                "<pre style=\"font-family:Segoe UI,Helvetica,Arial,sans-serif\">" + System.Net.WebUtility.HtmlEncode(body) + "</pre>", body, ct);
            await settingsSvc.SetStateAsync(SettingsService.Keys.LastAdminAlert, DateTime.UtcNow.ToString("O"), ct);
        }
        catch (Exception ex)
        {
            sp.GetRequiredService<ILogger<WorkerService>>().LogWarning(ex, "Administrator alert could not be sent");
        }
    }
}
