using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;

namespace VulnVerdict.Core.Feeds.Psirt;

/// <summary>
/// Red Hat Security Data API (https://access.redhat.com/hydra/rest/securitydata/cve.json?after=YYYY-MM-DD,
/// per_page/page). One Advisory per CVE; affected_packages ("openssl-1:1.1.1k-14.el8_6") become rows of package name and
/// fixed NEVR. Cursor: yyyy-MM-dd of the newest public_date stored (re-queried from one day earlier; upsert is idempotent).
/// First run covers the last InitialDays days.
/// </summary>
public sealed partial class RedHatCsafFeed : IFeed
{
    public string Name => PsirtFeedNames.RedHat;
    public string DisplayName => "Red Hat security data";
    public int IntervalMinutes => 1440;
    public string Licence => "Red Hat Security Data API (CC BY 4.0). Referenced and linked only.";
    public const string Vendor = "redhat";
    public const string Url = "https://access.redhat.com/hydra/rest/securitydata/cve.json";

    public int InitialDays { get; init; } = 90;
    public int PerPage { get; init; } = 1000;
    public int MaxPages { get; init; } = 10;

    public async Task<FeedResult> RunAsync(FeedContext ctx, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var cursor = PsirtStore.ParseDate(ctx.Cursor, "yyyy-MM-dd");
        var after = (cursor ?? now.AddDays(-InitialDays)).Date.AddDays(-1);
        DateTime? newest = cursor;
        var total = 0;
        for (var page = 1; page <= MaxPages; page++)
        {
            ct.ThrowIfCancellationRequested();
            ctx.Progress($"Red Hat page {page}");
            var url = $"{Url}?after={after:yyyy-MM-dd}&per_page={PerPage}&page={page}";
            List<Advisory> rows;
            try
            {
                using var doc = await PsirtStore.GetJsonAsync(ctx.Http, url, ct);
                rows = Parse(doc.RootElement, now);
            }
            catch (Exception ex) when (ex is not OperationCanceledException && total > 0)
            {
                ctx.Log.LogWarning(ex, "Red Hat page {Page} failed; will retry next run", page);
                return new FeedResult(total, cursor?.ToString("yyyy-MM-dd"), $"stopped at page {page}: {ex.Message}");
            }
            if (rows.Count == 0) break;
            total += await PsirtStore.UpsertAsync(ctx.Db, Vendor, rows, ct);
            foreach (var r in rows) if (r.Published is { } p && (newest is null || p > newest)) newest = p;
            if (rows.Count < PerPage) break;
        }
        return new FeedResult(total, (newest ?? now).ToString("yyyy-MM-dd"), cursor is null ? $"first run: CVEs public since {after:yyyy-MM-dd}" : null);
    }

    /// <summary>Parse a cve.json array.</summary>
    public static List<Advisory> Parse(JsonElement root, DateTime now)
    {
        var list = new List<Advisory>();
        if (root.ValueKind != JsonValueKind.Array) return list;
        foreach (var c in root.EnumerateArray())
        {
            var id = PsirtStore.Str(c, "CVE")?.Trim().ToUpperInvariant();
            if (string.IsNullOrEmpty(id) || !id.StartsWith("CVE-", StringComparison.Ordinal)) continue;
            var rows = new List<AffectedRow>();
            foreach (var pkg in PsirtStore.StrArr(c, "affected_packages"))
            {
                var (name, version) = SplitNevr(pkg!);
                rows.Add(new AffectedRow(name, "", version));
                if (rows.Count >= 300) break;
            }
            var published = PsirtStore.ParseDate(PsirtStore.Str(c, "public_date"));
            list.Add(new Advisory
            {
                Vendor = Vendor,
                AdvisoryId = PsirtStore.Trunc(id, 64),
                Title = PsirtStore.TruncOrNull(PsirtStore.Str(c, "bugzilla_description"), 500),
                Url = "https://access.redhat.com/security/cve/" + id,
                Published = published,
                Updated = published,
                CveIdsJson = PsirtStore.CveIdsJson(Normalizer.ExtractCveIds(id)),
                AffectedJson = PsirtStore.AffectedJson(rows),
                Severity = PsirtStore.TruncOrNull(PsirtStore.Str(c, "severity"), 32),
                ExploitedInTheWild = false,
                RetrievedAt = now
            });
        }
        return list;
    }

    [GeneratedRegex(@"^(?<n>.+?)-(?<v>\d+:[^-]+-[^-]+)$")] private static partial Regex WithEpoch();
    [GeneratedRegex(@"^(?<n>.+)-(?<v>[^-]+-[^-]+)$")] private static partial Regex NoEpoch();

    /// <summary>"openssl-1:1.1.1k-14.el8_6" -> ("openssl", "1:1.1.1k-14.el8_6"); "kernel-4.18.0-553.el8_10" -> ("kernel", "4.18.0-553.el8_10").</summary>
    public static (string Name, string Version) SplitNevr(string nevr)
    {
        var s = nevr.Trim();
        var m = WithEpoch().Match(s);
        if (!m.Success) m = NoEpoch().Match(s);
        return m.Success ? (m.Groups["n"].Value, m.Groups["v"].Value) : (s, "");
    }
}
