using System.Text.Json;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;

namespace VulnVerdict.Core.Feeds.Psirt;

/// <summary>
/// Ubuntu security tracker CVE API (https://ubuntu.com/security/cves.json). Pages newest-updated first
/// (sort_by=updated, order=descending) for critical, high and medium priority CVEs until a page reaches the cursor.
/// Each package status per release becomes one affected row: "released" carries the fixed version.
/// Cursor: ISO 8601 of the newest updated_at stored. At most MaxRecords per run.
/// </summary>
public sealed class UbuntuSecurityFeed : IFeed
{
    public string Name => PsirtFeedNames.Ubuntu;
    public string DisplayName => "Ubuntu security tracker";
    public int IntervalMinutes => 1440;
    public string Licence => "Ubuntu security data, public API. Referenced and linked only.";
    public const string Vendor = "ubuntu";
    public const string Url = "https://ubuntu.com/security/cves.json";
    private static readonly HashSet<string> SkipStatus = new(StringComparer.OrdinalIgnoreCase) { "not-affected", "DNE" };

    public int PageSize { get; init; } = 20; // the API rejects anything above 20
    public int MaxRecords { get; init; } = 2000;
    public string Priorities { get; init; } = "critical,high,medium";

    public string PageUrl(int offset)
    {
        var pri = string.Join("", Priorities.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(p => "&priority=" + p));
        return $"{Url}?limit={PageSize}&offset={offset}&order=descending&sort_by=updated{pri}";
    }

    public async Task<FeedResult> RunAsync(FeedContext ctx, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var cursor = PsirtStore.ParseDate(ctx.Cursor);
        DateTime? newest = cursor;
        var total = 0;
        var offset = 0;
        string? note = null;
        while (total < MaxRecords)
        {
            ct.ThrowIfCancellationRequested();
            ctx.Progress($"Ubuntu offset {offset}");
            List<Advisory> rows;
            try
            {
                using var doc = await PsirtStore.GetJsonAsync(ctx.Http, PageUrl(offset), ct);
                rows = Parse(doc.RootElement, now);
            }
            catch (Exception ex) when (ex is not OperationCanceledException && total > 0)
            {
                ctx.Log.LogWarning(ex, "Ubuntu page at offset {Offset} failed; will retry next run", offset);
                return new FeedResult(total, cursor?.ToString("o"), $"stopped at offset {offset}: {ex.Message}");
            }
            if (rows.Count == 0) break;
            var fresh = cursor is null ? rows : rows.Where(r => r.Updated is null || r.Updated > cursor).ToList();
            total += await PsirtStore.UpsertAsync(ctx.Db, Vendor, fresh, ct);
            foreach (var r in fresh) if (r.Updated is { } u && (newest is null || u > newest)) newest = u;
            if (fresh.Count < rows.Count || rows.Count < PageSize) break;
            offset += rows.Count;
        }
        if (total >= MaxRecords) note = $"capped at {MaxRecords} records; continuing next run";
        return new FeedResult(total, (newest ?? now).ToString("o"), note);
    }

    /// <summary>Parse one cves.json page.</summary>
    public static List<Advisory> Parse(JsonElement root, DateTime now)
    {
        var list = new List<Advisory>();
        foreach (var c in PsirtStore.Arr(root, "cves"))
        {
            var id = PsirtStore.Str(c, "id")?.Trim().ToUpperInvariant();
            if (string.IsNullOrEmpty(id) || !id.StartsWith("CVE-", StringComparison.Ordinal)) continue;
            var rows = new List<AffectedRow>();
            foreach (var p in PsirtStore.Arr(c, "packages"))
            {
                var pkg = PsirtStore.Str(p, "name")?.Trim();
                if (string.IsNullOrEmpty(pkg)) continue;
                foreach (var s in PsirtStore.Arr(p, "statuses"))
                {
                    var release = PsirtStore.Str(s, "release_codename")?.Trim();
                    var status = PsirtStore.Str(s, "status")?.Trim() ?? "";
                    if (string.IsNullOrEmpty(release) || release.Equals("upstream", StringComparison.OrdinalIgnoreCase) || SkipStatus.Contains(status)) continue;
                    var desc = PsirtStore.Str(s, "description")?.Trim() ?? "";
                    var product = pkg + " (" + release + ")";
                    rows.Add(status.Equals("released", StringComparison.OrdinalIgnoreCase)
                        ? new AffectedRow(product, "", desc)
                        : new AffectedRow(product, status, ""));
                    if (rows.Count >= 400) break;
                }
                if (rows.Count >= 400) break;
            }
            var description = PsirtStore.Str(c, "description")?.Trim();
            var title = description is null ? null : PsirtStore.Trunc(description.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault() ?? "", 500);
            list.Add(new Advisory
            {
                Vendor = Vendor,
                AdvisoryId = PsirtStore.Trunc(id, 64),
                Title = string.IsNullOrEmpty(title) ? null : title,
                Url = "https://ubuntu.com/security/" + id,
                Published = PsirtStore.ParseDate(PsirtStore.Str(c, "published")),
                Updated = PsirtStore.ParseDate(PsirtStore.Str(c, "updated_at")),
                CveIdsJson = PsirtStore.CveIdsJson(Normalizer.ExtractCveIds(id)),
                AffectedJson = PsirtStore.AffectedJson(rows),
                Severity = PsirtStore.TruncOrNull(PsirtStore.Str(c, "priority"), 32),
                ExploitedInTheWild = false,
                RetrievedAt = now
            });
        }
        return list;
    }
}
