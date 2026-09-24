using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Services;

/// <summary>Section 10.2 MSP mode: the verdict summary a client console posts to the MSP portal. Counts and product names only; never a hostname.</summary>
public sealed class MspReportPayload
{
    public string Tenant { get; set; } = "";
    public DateTime GeneratedAt { get; set; }
    public int FixToday { get; set; }
    public int FixThisWeek { get; set; }
    public int NextCycle { get; set; }
    public int Dismissed { get; set; }
    public int Overdue { get; set; }
    public DateTime? FeedsAsOf { get; set; }
    public List<MspTopItem> TopItems { get; set; } = new();
    public string? ConsoleVersion { get; set; }
}

public sealed class MspTopItem
{
    public string Cve { get; set; } = "";
    public string Sentence { get; set; } = "";
    /// <summary>FixToday | FixThisWeek</summary>
    public string Tier { get; set; } = "";
}

/// <summary>
/// Daily, with the customer's consent (MspReportOptIn), posts the verdict summary to the MSP portal. Asset names are
/// stripped before anything leaves: the top items carry the product part of the verdict subject only.
/// </summary>
public sealed class MspReportService
{
    public const string LastSentKey = "state:msp:last";
    public static readonly TimeSpan Interval = TimeSpan.FromHours(24);

    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly SettingsService _settings;
    private readonly IHttpClientFactory _http;
    private readonly ILogger<MspReportService> _log;

    public MspReportService(IDbContextFactory<VvDbContext> factory, SettingsService settings, IHttpClientFactory http, ILogger<MspReportService> log)
    {
        _factory = factory; _settings = settings; _http = http; _log = log;
    }

    public static bool Configured(AppSettings s) => s.MspReportOptIn && !string.IsNullOrWhiteSpace(s.MspPortalUrl) && !string.IsNullOrWhiteSpace(s.MspTenantToken);

    /// <summary>Worker entry point: at most once a day, only when opted in and the portal URL and tenant token are set.</summary>
    public async Task<bool> SendIfDueAsync(CancellationToken ct)
    {
        var s = await _settings.LoadAsync(ct);
        if (!Configured(s)) return false;
        var last = await _settings.GetStateAsync(LastSentKey, ct);
        if (last is not null && DateTime.TryParse(last, null, System.Globalization.DateTimeStyles.RoundtripKind, out var d) && DateTime.UtcNow - d < Interval) return false;
        var sent = await SendNowAsync(s, ct);
        if (sent) await _settings.SetStateAsync(LastSentKey, DateTime.UtcNow.ToString("O"), ct);
        return sent;
    }

    /// <summary>Post immediately (the Licence page's "Send test report" button). Returns false and logs on failure.</summary>
    public async Task<bool> SendNowAsync(AppSettings? s = null, CancellationToken ct = default)
    {
        s ??= await _settings.LoadAsync(ct);
        if (string.IsNullOrWhiteSpace(s.MspPortalUrl) || string.IsNullOrWhiteSpace(s.MspTenantToken)) return false;
        try
        {
            var payload = await BuildAsync(s, ct);
            var http = _http.CreateClient("feeds");
            using var req = new HttpRequestMessage(HttpMethod.Post, s.MspPortalUrl.Trim().TrimEnd('/') + "/msp/report") { Content = JsonContent.Create(payload, options: BundleJson.Options) };
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", s.MspTenantToken.Trim());
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(30));
            using var resp = await http.SendAsync(req, cts.Token);
            if (!resp.IsSuccessStatusCode) throw new HttpRequestException("MSP portal answered " + (int)resp.StatusCode + " " + resp.ReasonPhrase);
            return true;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            _log.LogWarning("MSP report could not be sent: {Error}", ex.Message);
            LastError = ex.Message;
            return false;
        }
    }

    public string? LastError { get; private set; }

    /// <summary>Build the summary: what the MSP portal receives, and nothing else.</summary>
    public async Task<MspReportPayload> BuildAsync(AppSettings? s = null, CancellationToken ct = default)
    {
        s ??= await _settings.LoadAsync(ct);
        await using var db = await _factory.CreateDbContextAsync(ct);
        var now = DateTime.UtcNow;
        var open = db.Verdicts.AsNoTracking().Where(v => v.State == VerdictState.Open);
        var p = new MspReportPayload
        {
            Tenant = string.IsNullOrWhiteSpace(s.OrganisationName) ? "Unnamed client" : s.OrganisationName.Trim(),
            GeneratedAt = now,
            FixToday = await open.CountAsync(v => v.Tier == VerdictTier.FixToday, ct),
            FixThisWeek = await open.CountAsync(v => v.Tier == VerdictTier.FixThisWeek, ct),
            NextCycle = await open.CountAsync(v => v.Tier == VerdictTier.NextPatchCycle, ct),
            Dismissed = await db.Verdicts.CountAsync(v => v.Tier <= VerdictTier.IgnoreTracked || v.State == VerdictState.Suppressed, ct),
            Overdue = await open.CountAsync(v => v.Tier >= VerdictTier.NextPatchCycle && v.SlaDue != null && v.SlaDue < now, ct),
            ConsoleVersion = AppVersion.Current
        };
        var feeds = await db.FeedStatuses.AsNoTracking().Where(f => f.LastSuccess != null).Select(f => f.LastSuccess!.Value).ToListAsync(ct);
        p.FeedsAsOf = feeds.Count == 0 ? null : feeds.Min();
        var top = await open.Where(v => v.Tier >= VerdictTier.FixThisWeek)
            .OrderByDescending(v => v.Tier).ThenBy(v => v.SlaDue).ThenBy(v => v.CveId)
            .Select(v => new { v.CveId, v.Subject, v.Tier }).Take(10).ToListAsync(ct);
        foreach (var v in top)
            p.TopItems.Add(new MspTopItem { Cve = v.CveId, Sentence = StripAssetName(v.Subject) + " is affected by " + v.CveId + ": " + v.Tier.Plain().ToLowerInvariant() + ".", Tier = v.Tier.ToString() });
        return p;
    }

    /// <summary>"Fortinet FortiOS 7.2.5 on FW-EDGE-01" becomes "Fortinet FortiOS 7.2.5".</summary>
    public static string StripAssetName(string subject)
    {
        var i = subject.IndexOf(" on ", StringComparison.Ordinal);
        var s = (i > 0 ? subject[..i] : subject).Trim();
        return s.Length == 0 ? "A product" : s;
    }
}
