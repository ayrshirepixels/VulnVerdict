using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;

namespace VulnVerdict.Core.Feeds.Psirt;

/// <summary>
/// Cisco PSIRT openVuln API (OAuth2 client credentials). Optional: credentials are read from the AppSetting rows
/// "psirt:cisco:clientId" and "psirt:cisco:clientSecret" (plain values); when either is missing the feed reports
/// "not configured" without error. Advisories last updated between the cursor date and today are fetched via
/// /all/lastpublished?startDate=&amp;endDate=. Cursor: yyyy-MM-dd of the newest lastUpdated seen.
/// </summary>
public sealed class CiscoOpenVulnFeed : IFeed
{
    public string Name => PsirtFeedNames.Cisco;
    public string DisplayName => "Cisco PSIRT openVuln advisories";
    public int IntervalMinutes => 1440;
    public string Licence => "Cisco openVuln API terms (free registration). Referenced and linked only.";
    public const string Vendor = "cisco";
    public const string TokenUrl = "https://id.cisco.com/oauth2/default/v1/token";
    public const string ApiBase = "https://apix.cisco.com/security/advisories/v2/";
    public const string ClientIdKey = "psirt:cisco:clientId";
    public const string ClientSecretKey = "psirt:cisco:clientSecret";
    public const string NotConfigured = "not configured (Cisco API credentials missing)";

    public int InitialDays { get; init; } = 30;

    public async Task<FeedResult> RunAsync(FeedContext ctx, CancellationToken ct)
    {
        var settings = await ctx.Db.Settings.AsNoTracking().Where(s => s.Key == ClientIdKey || s.Key == ClientSecretKey).ToListAsync(ct);
        var id = settings.FirstOrDefault(s => s.Key == ClientIdKey);
        var secret = settings.FirstOrDefault(s => s.Key == ClientSecretKey);
        if (string.IsNullOrWhiteSpace(id?.Value) || string.IsNullOrWhiteSpace(secret?.Value))
            return new FeedResult(0, ctx.Cursor, NotConfigured);
        if (id.Encrypted || secret.Encrypted)
            return new FeedResult(0, ctx.Cursor, "not configured (Cisco API credential rows must be stored as plain state values)");

        var now = DateTime.UtcNow;
        var token = await GetTokenAsync(ctx.Http, id.Value.Trim(), secret.Value.Trim(), ct);
        var cursor = PsirtStore.ParseDate(ctx.Cursor, "yyyy-MM-dd");
        var start = (cursor ?? now.AddDays(-InitialDays)).Date;
        var url = ApiBase + $"all/lastpublished?startDate={start:yyyy-MM-dd}&endDate={now:yyyy-MM-dd}";

        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Accept.ParseAdd("application/json");
        req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        using var resp = await ctx.Http.SendAsync(req, ct);
        var body = await resp.Content.ReadAsStringAsync(ct);
        if (resp.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.NotAcceptable)
        {
            // openVuln answers 404/406 with an errorCode body when the window holds no advisories
            ctx.Log.LogInformation("Cisco openVuln: no advisories since {Start} ({Status})", start, (int)resp.StatusCode);
            return new FeedResult(0, start.ToString("yyyy-MM-dd"), "no advisories in window");
        }
        if (!resp.IsSuccessStatusCode) throw new HttpRequestException($"Cisco openVuln {(int)resp.StatusCode}: {PsirtStore.Trunc(body, 300)}");

        using var doc = JsonDocument.Parse(body);
        var rows = Parse(doc.RootElement, now);
        var count = await PsirtStore.UpsertAsync(ctx.Db, Vendor, rows, ct);
        var newest = rows.Select(r => r.Updated).Where(d => d is not null).DefaultIfEmpty(cursor).Max() ?? now;
        return new FeedResult(count, newest.ToString("yyyy-MM-dd"), $"{count} advisories updated {start:yyyy-MM-dd}..{now:yyyy-MM-dd}");
    }

    public static async Task<string> GetTokenAsync(HttpClient http, string clientId, string clientSecret, CancellationToken ct)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret
        });
        using var resp = await http.PostAsync(TokenUrl, form, ct);
        var body = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode) throw new HttpRequestException($"Cisco token endpoint {(int)resp.StatusCode}: {PsirtStore.Trunc(body, 200)}");
        using var doc = JsonDocument.Parse(body);
        return PsirtStore.Str(doc.RootElement, "access_token") ?? throw new InvalidOperationException("Cisco token response had no access_token");
    }

    /// <summary>Parse an openVuln v2 {"advisories":[...]} response.</summary>
    public static List<Advisory> Parse(JsonElement root, DateTime now)
    {
        var list = new List<Advisory>();
        var advisories = root.ValueKind == JsonValueKind.Array ? root.EnumerateArray() : PsirtStore.Arr(root, "advisories");
        foreach (var a in advisories)
        {
            var id = PsirtStore.Str(a, "advisoryId")?.Trim();
            if (string.IsNullOrEmpty(id)) continue;
            var summary = PsirtStore.HtmlText(PsirtStore.Str(a, "summary"));
            var fixedText = FixedSoftwareText(a);
            var rows = PsirtStore.StrArr(a, "productNames").Select(p => p!.Trim()).Where(p => p.Length > 0).Distinct().Take(100)
                .Select(p => new AffectedRow(p, "", fixedText)).ToList();
            var cves = PsirtStore.StrArr(a, "cves").SelectMany(c => Normalizer.ExtractCveIds(c)).ToList();
            list.Add(new Advisory
            {
                Vendor = Vendor,
                AdvisoryId = PsirtStore.Trunc(id, 64),
                Title = PsirtStore.TruncOrNull(PsirtStore.Str(a, "advisoryTitle"), 500),
                Url = PsirtStore.TruncOrNull(PsirtStore.Str(a, "publicationUrl"), 500) ?? "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/" + id,
                Published = PsirtStore.ParseDate(PsirtStore.Str(a, "firstPublished")),
                Updated = PsirtStore.ParseDate(PsirtStore.Str(a, "lastUpdated")),
                CveIdsJson = PsirtStore.CveIdsJson(cves),
                AffectedJson = PsirtStore.AffectedJson(rows),
                Severity = PsirtStore.TruncOrNull(PsirtStore.Str(a, "sir"), 32),
                ExploitedInTheWild = PsirtStore.ExploitationStated(summary),
                RetrievedAt = now
            });
        }
        return list;
    }

    private static string FixedSoftwareText(JsonElement a)
    {
        foreach (var name in new[] { "fixedSoftware", "firstFixed", "first_fixed" })
        {
            if (!a.TryGetProperty(name, out var v)) continue;
            var text = v.ValueKind switch
            {
                JsonValueKind.String => v.GetString(),
                JsonValueKind.Array => string.Join(", ", v.EnumerateArray().Select(PsirtStore.Val).Where(s => !string.IsNullOrWhiteSpace(s))),
                JsonValueKind.Object => PsirtStore.HtmlText(v.GetRawText()),
                _ => null
            };
            if (!string.IsNullOrWhiteSpace(text)) return PsirtStore.Trunc(PsirtStore.HtmlText(text), 500);
        }
        return "";
    }
}
