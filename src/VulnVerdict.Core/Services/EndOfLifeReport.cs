using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;

namespace VulnVerdict.Core.Services;

/// <summary>One product on the watchlist, or installed on a number of assets, with where it stands on vendor support.</summary>
public sealed record EolItem(string Product, string? Version, string Where, int Assets, Guid? WatchlistEntryId, EolFinding Finding);

/// <summary>
/// End-of-life flags across the estate: watchlist entries, operating systems and installed software (not distribution
/// packages or libraries, which live and die with the release they ship in). Feeds the "End of life" list and one
/// line of the digest; verdicts get their flag from the evaluator. Nothing here is a verdict tier.
/// </summary>
public static class EndOfLifeReport
{
    /// <summary>The digest counts releases whose support ends within this many days, whatever the flag window is set to.</summary>
    public const int DigestSoonDays = 90;

    /// <summary>
    /// Everything past vendor support or within <paramref name="warnDays"/> of it, worst first. With
    /// <paramref name="suggestions"/>, also products the curated map does not know whose name matches an endoflife.date
    /// product: marked as suggestions, for a person to judge.
    /// </summary>
    public static async Task<List<EolItem>> BuildAsync(VvDbContext db, DateTime now, int warnDays, bool suggestions = false, CancellationToken ct = default)
    {
        var items = new List<EolItem>();
        var index = await EolIndex.LoadAsync(db, ct);
        if (index.Empty) return items;

        void Add(string? vendor, string? product, string? version, string where, int assets, Guid? entry)
        {
            if (index.Find(vendor, product, version, now, warnDays, suggestions) is { State: not EolState.Supported } f)
                items.Add(new EolItem(((vendor ?? "") + " " + product).Trim(), string.IsNullOrWhiteSpace(version) ? null : version, where, assets, entry, f));
        }

        foreach (var w in await db.Watchlist.AsNoTracking().Where(w => w.Enabled).ToListAsync(ct))
            Add(w.Vendor, w.Product, w.Version, "watchlist: " + w.DisplayName, 0, w.Id);

        var staleBefore = now.AddDays(-30);
        var systems = await db.Assets.AsNoTracking().Where(a => !a.Archived && a.LastSeen >= staleBefore && a.OsProduct != null)
            .GroupBy(a => new { a.OsVendor, a.OsProduct, a.OsVersion, a.OsBuild })
            .Select(g => new { g.Key.OsVendor, g.Key.OsProduct, g.Key.OsVersion, g.Key.OsBuild, Count = g.Count() }).ToListAsync(ct);
        foreach (var o in systems)
            // Windows is told apart by its build (10.0.19045); everything else by its version
            Add(o.OsVendor, o.OsProduct, o.OsBuild is { } b && b.StartsWith("10.0.", StringComparison.Ordinal) ? b : o.OsVersion ?? o.OsBuild, Assets(o.Count), o.Count, null);

        var software = await db.Software.AsNoTracking()
            .Where(s => s.Purl == null && s.Ecosystem == null && s.Kind != SoftwareKind.Package && s.Kind != SoftwareKind.Library
                        && s.Asset != null && !s.Asset.Archived && s.Asset.LastSeen >= staleBefore)
            .GroupBy(s => new { s.Vendor, s.Product, s.Version })
            .Select(g => new { g.Key.Vendor, g.Key.Product, g.Key.Version, Count = g.Select(x => x.AssetId).Distinct().Count() }).ToListAsync(ct);
        foreach (var s in software)
            Add(s.Vendor, s.Product, s.Version, Assets(s.Count), s.Count, null);

        return items.OrderBy(i => i.Finding.Suggestion).ThenByDescending(i => i.Finding.State).ThenBy(i => i.Finding.EolDate ?? DateTime.MinValue).ThenBy(i => i.Product, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static string Assets(int n) => n + (n == 1 ? " asset" : " assets");

    /// <summary>
    /// "3 products are past vendor support; 2 reach end of support within 90 days." A product here is a release
    /// (FortiOS 7.0, Windows Server 2012 R2) however many assets run it. Null when there is nothing to say.
    /// </summary>
    public static string? DigestLine(IEnumerable<EolItem> items)
    {
        var releases = items.Where(i => i.Finding.Flagged).Select(i => i.Finding).DistinctBy(f => (f.Slug, f.Cycle)).ToList();
        var past = releases.Count(f => f.State == EolState.EndOfLife);
        var soon = releases.Count(f => f.State == EolState.EndingSoon && f.Days <= DigestSoonDays);
        var pastText = past == 0 ? null : past + (past == 1 ? " product is" : " products are") + " past vendor support";
        var soonText = soon == 0 ? null : soon + (soon == 1 ? " product reaches" : " products reach") + " end of support within " + DigestSoonDays + " days";
        if (pastText is null && soonText is null) return null;
        if (pastText is not null && soonText is not null) return pastText + "; " + soon + (soon == 1 ? " reaches" : " reach") + " end of support within " + DigestSoonDays + " days.";
        return (pastText ?? soonText) + ".";
    }

    public static async Task<string?> DigestLineAsync(VvDbContext db, DateTime now, CancellationToken ct = default) =>
        DigestLine(await BuildAsync(db, now, DigestSoonDays, false, ct));
}
