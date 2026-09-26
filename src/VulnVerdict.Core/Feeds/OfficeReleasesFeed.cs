using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Feeds;

/// <summary>
/// Microsoft 365 Apps release history: every build of every version, per channel and date, from Microsoft's update
/// history page. Microsoft's CVE records and security update data give a link, not a build, for Microsoft 365 Apps;
/// with this history the evaluator can tell whether an installed build predates the fix. Replaced in full each run
/// (a couple of thousand rows).
/// </summary>
public sealed partial class OfficeReleasesFeed : IFeed
{
    public const string FeedName = "office-releases";
    public const string Url = "https://learn.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date";

    public string Name => FeedName;
    public string DisplayName => "Microsoft 365 Apps release history";
    public int IntervalMinutes => 1440;
    public string Licence => "Microsoft Learn, Update history for Microsoft 365 Apps. Build numbers and dates only; referenced and linked.";

    public sealed record Release(string Channel, string Version, int Build, int Revision, DateTime Released);

    [GeneratedRegex(@"<table>(.*?)</table>", RegexOptions.Singleline)] private static partial Regex TableRx();
    [GeneratedRegex(@"<th[^>]*>(.*?)</th>", RegexOptions.Singleline)] private static partial Regex HeaderRx();
    [GeneratedRegex(@"<tr>(.*?)</tr>", RegexOptions.Singleline)] private static partial Regex RowRx();
    [GeneratedRegex(@"<td[^>]*>(.*?)</td>", RegexOptions.Singleline)] private static partial Regex CellRx();
    [GeneratedRegex(@"Version\s+(\d{4})\s*\(Build\s+(\d+)\.(\d+)\)")] private static partial Regex BuildRx();
    [GeneratedRegex(@"<[^>]+>")] private static partial Regex TagRx();

    public async Task<FeedResult> RunAsync(FeedContext ctx, CancellationToken ct)
    {
        ctx.Progress("Reading the Microsoft 365 Apps update history");
        using var req = new HttpRequestMessage(HttpMethod.Get, Url);
        req.Headers.Accept.ParseAdd("text/html");
        using var resp = await ctx.Http.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();
        var releases = Parse(await resp.Content.ReadAsStringAsync(ct));
        // a changed page layout must not wipe a good history: keep the old rows and fail loudly instead
        if (releases.Count < 100) throw new InvalidOperationException("the update history page yielded only " + releases.Count + " releases; its layout may have changed");

        await ctx.Db.OfficeReleases.ExecuteDeleteAsync(ct);
        ctx.Db.OfficeReleases.AddRange(releases.Select(r => new OfficeRelease { Channel = r.Channel, Version = r.Version, Build = r.Build, Revision = r.Revision, Released = r.Released }));
        await ctx.Db.SaveChangesAsync(ct);
        var newest = releases.Max(r => r.Released);
        return new FeedResult(releases.Count, newest.ToString("yyyy-MM-dd"), releases.Count + " releases from " + releases.Min(r => r.Released).ToString("MMM yyyy") + " to " + newest.ToString("d MMM yyyy"));
    }

    /// <summary>The release-history table: rows of year, date, then one cell per channel listing "Version 2406 (Build 17726.20160)".</summary>
    public static List<Release> Parse(string html)
    {
        var list = new List<Release>();
        foreach (Match table in TableRx().Matches(html))
        {
            var headers = HeaderRx().Matches(table.Groups[1].Value).Select(h => WebUtility.HtmlDecode(TagRx().Replace(h.Groups[1].Value, "")).Trim()).ToList();
            if (headers.Count < 3 || !headers[0].Equals("Year", StringComparison.OrdinalIgnoreCase)) continue;
            foreach (Match row in RowRx().Matches(table.Groups[1].Value))
            {
                var cells = CellRx().Matches(row.Groups[1].Value).Select(c => c.Groups[1].Value).ToList();
                if (cells.Count < 3) continue;
                var year = TagRx().Replace(cells[0], "").Trim();
                var day = TagRx().Replace(cells[1], "").Trim();
                if (!DateTime.TryParseExact(day + " " + year, new[] { "MMMM d yyyy", "MMMM dd yyyy" }, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var date)) continue;
                for (var i = 2; i < cells.Count; i++)
                {
                    var channel = i < headers.Count ? headers[i] : "";
                    foreach (Match b in BuildRx().Matches(cells[i]))
                        list.Add(new Release(channel, b.Groups[1].Value, int.Parse(b.Groups[2].Value, CultureInfo.InvariantCulture), int.Parse(b.Groups[3].Value, CultureInfo.InvariantCulture), DateTime.SpecifyKind(date.Date, DateTimeKind.Utc)));
                }
            }
        }
        return list.Distinct().ToList();
    }
}
