using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Services;

/// <summary>What opt-in telemetry sends: counts only. No hostnames, no CVE lists, no organisation name.</summary>
public sealed class TelemetryPayload
{
    /// <summary>Random id generated once per install so the central service can count installs, not identify them.</summary>
    public string InstallId { get; set; } = "";
    public string Version { get; set; } = "";
    public DateTime SentAt { get; set; }
    public int Assets { get; set; }
    public int WatchlistEntries { get; set; }
    public int Connectors { get; set; }
    /// <summary>Open verdicts by tier name (FixToday, FixThisWeek, NextPatchCycle, IgnoreTracked, NotAffected).</summary>
    public Dictionary<string, int> VerdictsByTier { get; set; } = new();
    /// <summary>Hours since each feed last succeeded, by feed name; null when never.</summary>
    public Dictionary<string, double?> FeedAgeHours { get; set; } = new();
    public bool BundleMode { get; set; }
    public string? BundleVersion { get; set; }
    public string? LicenceTier { get; set; }
}

public static class AppVersion
{
    /// <summary>The image version baked in by the release pipeline (VV_VERSION), "dev" otherwise.</summary>
    public static string Current => Environment.GetEnvironmentVariable("VV_VERSION") is { Length: > 0 } v ? v : "dev";
}

/// <summary>Opt-in telemetry: once a day, anonymous counts to the central service.</summary>
public sealed class TelemetryService
{
    public const string LastSentKey = "state:telemetry:last";
    public const string InstallIdKey = "state:telemetry:installId";
    public static readonly TimeSpan Interval = TimeSpan.FromHours(24);

    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly SettingsService _settings;
    private readonly IHttpClientFactory _http;
    private readonly ILogger<TelemetryService> _log;

    public TelemetryService(IDbContextFactory<VvDbContext> factory, SettingsService settings, IHttpClientFactory http, ILogger<TelemetryService> log)
    {
        _factory = factory; _settings = settings; _http = http; _log = log;
    }

    /// <summary>Worker entry point. Sends nothing unless TelemetryOptIn is on and a bundle URL is set.</summary>
    public async Task<bool> SendIfDueAsync(CancellationToken ct)
    {
        var s = await _settings.LoadAsync(ct);
        if (!s.TelemetryOptIn || string.IsNullOrWhiteSpace(s.BundleUrl)) return false;
        var last = await _settings.GetStateAsync(LastSentKey, ct);
        if (last is not null && DateTime.TryParse(last, null, System.Globalization.DateTimeStyles.RoundtripKind, out var d) && DateTime.UtcNow - d < Interval) return false;

        try
        {
            var payload = await BuildAsync(s, ct);
            var http = _http.CreateClient("feeds");
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(30));
            using var resp = await http.PostAsJsonAsync(s.BundleUrl.Trim().TrimEnd('/') + "/telemetry", payload, BundleJson.Options, cts.Token);
            resp.EnsureSuccessStatusCode();
            await _settings.SetStateAsync(LastSentKey, DateTime.UtcNow.ToString("O"), ct);
            return true;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            _log.LogWarning("Telemetry could not be sent: {Error}", ex.Message);
            return false;
        }
    }

    /// <summary>Build the payload (also shown on the Licence page so the administrator can see exactly what leaves the box).</summary>
    public async Task<TelemetryPayload> BuildAsync(AppSettings? s = null, CancellationToken ct = default)
    {
        s ??= await _settings.LoadAsync(ct);
        var installId = await _settings.GetStateAsync(InstallIdKey, ct);
        if (string.IsNullOrEmpty(installId))
        {
            installId = Guid.NewGuid().ToString("N");
            await _settings.SetStateAsync(InstallIdKey, installId, ct);
        }
        await using var db = await _factory.CreateDbContextAsync(ct);
        var now = DateTime.UtcNow;
        var p = new TelemetryPayload
        {
            InstallId = installId, Version = AppVersion.Current, SentAt = now,
            Assets = await db.Assets.CountAsync(a => !a.Archived, ct),
            WatchlistEntries = await db.Watchlist.CountAsync(w => w.Enabled, ct),
            Connectors = await db.Connectors.CountAsync(c => c.Enabled, ct),
            BundleMode = !string.IsNullOrWhiteSpace(s.BundleUrl),
            BundleVersion = (await BundleApplier.CurrentAsync(db, ct))?.Version,
            LicenceTier = LicenseService.Parse(s.LicenceKey).Tier
        };
        foreach (var g in await db.Verdicts.Where(v => v.State == VerdictState.Open).GroupBy(v => v.Tier).Select(g => new { g.Key, N = g.Count() }).ToListAsync(ct))
            p.VerdictsByTier[g.Key.ToString()] = g.N;
        foreach (var f in await db.FeedStatuses.AsNoTracking().ToListAsync(ct))
            p.FeedAgeHours[f.Name] = f.LastSuccess is null ? null : Math.Round((now - f.LastSuccess.Value).TotalHours, 1);
        return p;
    }
}
