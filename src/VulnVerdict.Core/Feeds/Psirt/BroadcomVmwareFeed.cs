using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;

namespace VulnVerdict.Core.Feeds.Psirt;

/// <summary>
/// VMware security advisories on the Broadcom support portal. The portal's list endpoint
/// (POST getSecurityAdvisoryList, no authentication) returns the VMSA id, title, CVE list, severity, dates, products and URL
/// per segment (VC = VMware Cloud Foundation, VA = application networking and security, VT = Tanzu). Affected and fixed
/// versions are only on the advisory pages, so rows carry product names only. Cursor: ISO 8601 of the newest "updated" seen.
/// </summary>
public sealed partial class BroadcomVmwareFeed : IFeed
{
    public string Name => PsirtFeedNames.Vmware;
    public string DisplayName => "VMware (Broadcom) security advisories";
    public int IntervalMinutes => 1440;
    public string Licence => "Broadcom support portal, public advisory list. Referenced and linked only.";
    public const string Vendor = "vmware";
    public const string ListUrl = "https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList";

    public string[] Segments { get; init; } = { "VC", "VA", "VT" };
    public int PageSize { get; init; } = 50;
    public int MaxPagesPerSegment { get; init; } = 20;

    public async Task<FeedResult> RunAsync(FeedContext ctx, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var cursor = PsirtStore.ParseDate(ctx.Cursor);
        DateTime? newest = cursor;
        var total = 0;
        var notes = new List<string>();
        foreach (var segment in Segments)
        {
            for (var page = 0; page < MaxPagesPerSegment; page++)
            {
                ct.ThrowIfCancellationRequested();
                ctx.Progress($"VMware {segment} page {page}");
                List<Advisory> rows;
                int lastPage;
                try
                {
                    var body = JsonSerializer.Serialize(new { pageNumber = page, pageSize = PageSize, searchVal = "", segment, sortInfo = new { column = "", order = "" } });
                    using var req = new HttpRequestMessage(HttpMethod.Post, ListUrl) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
                    req.Headers.Accept.ParseAdd("application/json");
                    using var resp = await ctx.Http.SendAsync(req, ct);
                    resp.EnsureSuccessStatusCode();
                    using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
                    rows = Parse(doc.RootElement, now, out lastPage);
                }
                catch (Exception ex) when (ex is not OperationCanceledException && total > 0)
                {
                    ctx.Log.LogWarning(ex, "Broadcom advisory list {Segment} page {Page} failed; will retry next run", segment, page);
                    return new FeedResult(total, cursor?.ToString("o"), $"stopped at {segment} page {page}: {ex.Message}");
                }
                if (rows.Count == 0) break;
                var fresh = cursor is null ? rows : rows.Where(r => r.Updated is null || r.Updated > cursor).ToList();
                total += await PsirtStore.UpsertAsync(ctx.Db, Vendor, fresh, ct);
                foreach (var r in fresh) if (r.Updated is { } u && (newest is null || u > newest)) newest = u;
                if (fresh.Count == 0 || page >= lastPage) break;
            }
        }
        return new FeedResult(total, (newest ?? now).ToString("o"), notes.Count > 0 ? string.Join("; ", notes) : null);
    }

    [GeneratedRegex(@"VMSA-\d{4}-\d{4}", RegexOptions.IgnoreCase)] private static partial Regex Vmsa();

    /// <summary>Parse a getSecurityAdvisoryList response. Non-security rows (alertType other than "S") are skipped.</summary>
    public static List<Advisory> Parse(JsonElement root, DateTime now, out int lastPage)
    {
        lastPage = 0;
        var list = new List<Advisory>();
        if (!root.TryGetProperty("data", out var data)) return list;
        if (data.TryGetProperty("pageInfo", out var pi)) lastPage = PsirtStore.Int(pi, "lastPage") ?? 0;
        foreach (var a in PsirtStore.Arr(data, "list"))
        {
            var alertType = PsirtStore.Str(a, "alertType");
            if (alertType is not null && !alertType.Equals("S", StringComparison.OrdinalIgnoreCase)) continue;
            var title = PsirtStore.Str(a, "title")?.Trim() ?? "";
            var idm = Vmsa().Match(title);
            var id = idm.Success ? idm.Value.ToUpperInvariant() : PsirtStore.Str(a, "documentId")?.Trim();
            if (string.IsNullOrEmpty(id)) continue;
            var cves = Normalizer.ExtractCveIds((PsirtStore.Str(a, "affectedCve") ?? "") + " " + title).ToList();
            var products = (PsirtStore.Str(a, "supportProducts") ?? "")
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(p => !p.Contains("...", StringComparison.Ordinal)) // the list truncates long product strings
                .Distinct().Take(50).Select(p => new AffectedRow(p, "", "")).ToList();
            var notificationId = PsirtStore.Str(a, "notificationId");
            list.Add(new Advisory
            {
                Vendor = Vendor,
                AdvisoryId = PsirtStore.Trunc(id, 64),
                Title = PsirtStore.TruncOrNull(title, 500),
                Url = PsirtStore.TruncOrNull(PsirtStore.Str(a, "notificationUrl"), 500)
                      ?? (notificationId is null ? null : "https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/" + notificationId),
                Published = PsirtStore.ParseDate(PsirtStore.Str(a, "published"), "dd MMMM yyyy", "d MMMM yyyy"),
                Updated = PsirtStore.ParseDate(PsirtStore.Str(a, "updated")),
                CveIdsJson = PsirtStore.CveIdsJson(cves),
                AffectedJson = PsirtStore.AffectedJson(products),
                Severity = PsirtStore.TruncOrNull(PsirtStore.Str(a, "severity"), 32),
                ExploitedInTheWild = PsirtStore.ExploitationStated(title),
                RetrievedAt = now
            });
        }
        return list;
    }
}
