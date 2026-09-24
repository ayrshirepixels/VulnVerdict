using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;

namespace VulnVerdict.Core.Feeds.Psirt;

public sealed record FortinetRssItem(string AdvisoryId, string Title, string Link, DateTime? Published, DateTime? Revised)
{
    /// <summary>Date used for "updated since cursor": the revision date when the description carries one, else the publish date.</summary>
    public DateTime? ItemDate => Revised ?? Published;
}

public sealed class FortinetAdvisoryPage
{
    public string? Title { get; set; }
    public List<string> CveIds { get; set; } = new();
    public List<AffectedRow> Affected { get; set; } = new();
    public string? Severity { get; set; }
    public DateTime? Published { get; set; }
    public DateTime? Updated { get; set; }
    /// <summary>The sidebar "Known Exploited" cell says Yes.</summary>
    public bool KnownExploited { get; set; }
    /// <summary>KnownExploited, or the page text states exploitation in the wild.</summary>
    public bool ExploitedInTheWild { get; set; }
}

/// <summary>
/// Section 7: Fortinet PSIRT. RSS index (https://www.fortiguard.com/rss/ir.xml, 50 most recent advisories) then each advisory page
/// for the "Version / Affected / Solution" table, severity, CVE ids and the exploited-in-the-wild statement.
/// Cursor: yyyy-MM-dd of the newest item date seen; items dated on or after it are (re)fetched, at most MaxPagesPerRun per run.
/// </summary>
public sealed partial class FortinetPsirtFeed : IFeed
{
    public string Name => PsirtFeedNames.Fortinet;
    public string DisplayName => "Fortinet PSIRT advisories";
    public int IntervalMinutes => 1440;
    public string Licence => "Public (Fortinet PSIRT). Referenced and linked only.";
    public const string Vendor = "fortinet";
    public const string RssUrl = "https://www.fortiguard.com/rss/ir.xml";
    public const string FallbackRssUrl = "https://filestore.fortinet.com/fortiguard/rss/ir.xml";

    public int MaxPagesPerRun { get; init; } = 50;
    public int DelayMs { get; init; } = 300;

    public async Task<FeedResult> RunAsync(FeedContext ctx, CancellationToken ct)
    {
        string xml;
        try { xml = await ctx.Http.GetStringAsync(RssUrl, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            ctx.Log.LogWarning(ex, "Fortinet RSS {Url} failed, trying {Fallback}", RssUrl, FallbackRssUrl);
            xml = await ctx.Http.GetStringAsync(FallbackRssUrl, ct);
        }
        var items = ParseRss(xml);
        var cursor = PsirtStore.ParseDate(ctx.Cursor, "yyyy-MM-dd");
        var due = items.Where(i => cursor is null || i.ItemDate is null || i.ItemDate.Value.Date >= cursor.Value.Date)
                       .OrderByDescending(i => i.ItemDate ?? DateTime.MinValue).Take(MaxPagesPerRun).ToList();
        var ids = due.Select(i => i.AdvisoryId).ToList();
        var stored = await ctx.Db.Advisories.AsNoTracking().Where(a => a.Vendor == Vendor && ids.Contains(a.AdvisoryId)).Select(a => a.AdvisoryId).ToListAsync(ct);
        var storedSet = stored.ToHashSet(StringComparer.OrdinalIgnoreCase);

        var now = DateTime.UtcNow;
        var rows = new List<Advisory>();
        var failures = 0;
        foreach (var item in due)
        {
            ct.ThrowIfCancellationRequested();
            var adv = new Advisory
            {
                Vendor = Vendor,
                AdvisoryId = item.AdvisoryId,
                Title = PsirtStore.TruncOrNull(item.Title, 500),
                Url = PsirtStore.Trunc(item.Link, 500),
                Published = item.Published,
                Updated = item.ItemDate,
                RetrievedAt = now
            };
            try
            {
                var html = await ctx.Http.GetStringAsync(item.Link, ct);
                Apply(adv, ParsePage(html));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                failures++;
                ctx.Log.LogWarning(ex, "Fortinet advisory page {Url} failed", item.Link);
                // keep the stored detail for an advisory we already have; store the index-level row for a new one
                if (storedSet.Contains(item.AdvisoryId)) continue;
            }
            rows.Add(adv);
            ctx.Progress($"Fortinet {item.AdvisoryId}");
            if (DelayMs > 0) await Task.Delay(DelayMs, ct);
        }
        var count = await PsirtStore.UpsertAsync(ctx.Db, Vendor, rows, ct);
        var newest = items.Select(i => i.ItemDate).Where(d => d is not null).DefaultIfEmpty(cursor).Max();
        var note = $"{items.Count} in feed, {due.Count} due, {count} stored" + (failures > 0 ? $", {failures} page fetches failed" : "");
        return new FeedResult(count, (newest ?? now).ToString("yyyy-MM-dd"), note);
    }

    public static void Apply(Advisory adv, FortinetAdvisoryPage page)
    {
        adv.Title = PsirtStore.TruncOrNull(page.Title, 500) ?? adv.Title;
        adv.CveIdsJson = PsirtStore.CveIdsJson(page.CveIds);
        adv.AffectedJson = PsirtStore.AffectedJson(page.Affected);
        adv.Severity = PsirtStore.TruncOrNull(page.Severity, 32);
        adv.Published = page.Published ?? adv.Published;
        adv.Updated = page.Updated ?? adv.Updated;
        adv.ExploitedInTheWild = page.ExploitedInTheWild;
    }

    // ---- RSS -------------------------------------------------------------------------------------------------------

    [GeneratedRegex(@"FG-IR-\d{2}-\d{3,}", RegexOptions.IgnoreCase)] private static partial Regex FgIr();
    [GeneratedRegex(@"Revised on\s+(\d{4}-\d{2}-\d{2})", RegexOptions.IgnoreCase)] private static partial Regex Revised();

    public static List<FortinetRssItem> ParseRss(string xml)
    {
        var list = new List<FortinetRssItem>();
        var doc = XDocument.Parse(xml);
        foreach (var item in doc.Descendants("item"))
        {
            var link = ((string?)item.Element("link"))?.Trim() ?? ((string?)item.Element("guid"))?.Trim() ?? "";
            var title = ((string?)item.Element("title"))?.Trim() ?? "";
            var id = FgIr().Match(link + " " + title);
            if (!id.Success) continue;
            var desc = (string?)item.Element("description") ?? "";
            var rev = Revised().Match(desc);
            list.Add(new FortinetRssItem(
                id.Value.ToUpperInvariant(),
                title,
                link.Length > 0 ? link : "https://fortiguard.fortinet.com/psirt/" + id.Value.ToUpperInvariant(),
                PsirtStore.ParseDate((string?)item.Element("pubDate"), "ddd, dd MMM yyyy HH:mm:ss zzz"),
                rev.Success ? PsirtStore.ParseDate(rev.Groups[1].Value, "yyyy-MM-dd") : null));
        }
        return list;
    }

    // ---- advisory page ------------------------------------------------------------------------------------------------

    [GeneratedRegex(@"<(script|style)[^>]*>.*?</\1>", RegexOptions.IgnoreCase | RegexOptions.Singleline)] private static partial Regex ScriptStyle();
    [GeneratedRegex(@"<h1[^>]*class=""[^""]*\btitle\b[^""]*""[^>]*>(.*?)</h1>", RegexOptions.IgnoreCase | RegexOptions.Singleline)] private static partial Regex TitleRx();
    [GeneratedRegex(@"<th>\s*Affected\s*</th>.*?<tbody>(.*?)</tbody>", RegexOptions.IgnoreCase | RegexOptions.Singleline)] private static partial Regex AffectedTable();
    [GeneratedRegex(@"<tr[^>]*>(.*?)</tr>", RegexOptions.IgnoreCase | RegexOptions.Singleline)] private static partial Regex Rows();
    [GeneratedRegex(@"<td[^>]*>(.*?)</td>", RegexOptions.IgnoreCase | RegexOptions.Singleline)] private static partial Regex Cells();
    [GeneratedRegex(@"data-cveid=""(CVE-\d{4}-\d{4,})""", RegexOptions.IgnoreCase)] private static partial Regex CveAttr();
    [GeneratedRegex(@"^(?<p>.+?)\s+(?<v>\d+(?:\.\d+)*)$")] private static partial Regex ProductBranch();
    [GeneratedRegex(@"^\s*(?:please\s+)?upgrade\s+to\s+", RegexOptions.IgnoreCase)] private static partial Regex UpgradeTo();

    private static string? MetaCell(string html, string label)
    {
        var m = Regex.Match(html, @"<td[^>]*>\s*" + Regex.Escape(label) + @"\s*</td>\s*<td[^>]*>(.*?)</td>", RegexOptions.IgnoreCase | RegexOptions.Singleline);
        return m.Success ? m.Groups[1].Value : null;
    }

    /// <summary>Best-effort extraction from a FortiGuard PSIRT advisory page. Never throws on layout changes; missing parts stay empty.</summary>
    public static FortinetAdvisoryPage ParsePage(string html)
    {
        var page = new FortinetAdvisoryPage();
        if (string.IsNullOrEmpty(html)) return page;
        var main = ScriptStyle().Replace(html, " ");

        var t = TitleRx().Match(main);
        if (t.Success) page.Title = PsirtStore.HtmlText(t.Groups[1].Value);

        page.Severity = PsirtStore.TruncOrNull(PsirtStore.HtmlText(MetaCell(main, "Severity")), 32);
        page.Published = PsirtStore.ParseDate(PsirtStore.HtmlText(MetaCell(main, "Published Date")), "MMM d, yyyy", "MMMM d, yyyy");
        page.Updated = PsirtStore.ParseDate(PsirtStore.HtmlText(MetaCell(main, "Updated Date")), "MMM d, yyyy", "MMMM d, yyyy");
        page.KnownExploited = string.Equals(PsirtStore.HtmlText(MetaCell(main, "Known Exploited")), "Yes", StringComparison.OrdinalIgnoreCase);

        var cveCell = MetaCell(main, "CVE ID");
        var ids = new List<string>();
        foreach (Match m in CveAttr().Matches(main)) ids.Add(m.Groups[1].Value.ToUpperInvariant());
        if (cveCell is not null) ids.AddRange(Normalizer.ExtractCveIds(PsirtStore.HtmlText(cveCell)));
        var text = PsirtStore.HtmlText(main);
        if (ids.Count == 0) ids.AddRange(Normalizer.ExtractCveIds(text));
        page.CveIds = ids.Distinct().ToList();

        var table = AffectedTable().Match(main);
        if (table.Success)
        {
            foreach (Match row in Rows().Matches(table.Groups[1].Value))
            {
                var cells = Cells().Matches(row.Groups[1].Value).Select(c => PsirtStore.HtmlText(c.Groups[1].Value)).ToList();
                if (cells.Count < 2) continue;
                var affected = cells[1];
                if (affected.Length == 0 || affected.StartsWith("Not affected", StringComparison.OrdinalIgnoreCase) || affected.Equals("N/A", StringComparison.OrdinalIgnoreCase)) continue;
                var (product, branch) = SplitProduct(cells[0]);
                if (product.Length == 0) continue;
                var solution = cells.Count > 2 ? cells[2] : "";
                var fixedIn = UpgradeTo().Replace(solution, "").Trim();
                if (branch is not null && !affected.Contains(branch, StringComparison.Ordinal) && !char.IsDigit(affected[0])) affected = branch + " " + affected;
                page.Affected.Add(new AffectedRow(product, affected, fixedIn));
            }
        }

        page.ExploitedInTheWild = page.KnownExploited || PsirtStore.ExploitationStated(text);
        return page;
    }

    /// <summary>"FortiOS 7.2" -> ("FortiOS", "7.2"); "FortiSandbox" -> ("FortiSandbox", null).</summary>
    public static (string Product, string? Branch) SplitProduct(string cell)
    {
        var s = cell.Trim();
        var m = ProductBranch().Match(s);
        return m.Success ? (m.Groups["p"].Value.Trim(), m.Groups["v"].Value) : (s, null);
    }
}
