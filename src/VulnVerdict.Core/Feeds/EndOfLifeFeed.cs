using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Feeds.Psirt;

namespace VulnVerdict.Core.Feeds;

/// <summary>
/// Release cycles and support end dates from endoflife.date (API v1, one request for every product). The console maps
/// what is installed to a cycle (see <see cref="Engine.EolProductMap"/>) and flags releases the vendor has stopped, or is
/// about to stop, patching. Replaced in full each run, a few thousand rows; a response that has shrunk by half or lost
/// most of its products is refused and the stored set kept. Data is MIT-licensed and attributed in the README.
/// </summary>
public sealed class EndOfLifeFeed : IFeed
{
    public const string FeedName = "eol";
    public const string Url = "https://endoflife.date/api/v1/products/full";

    public string Name => FeedName;
    public string DisplayName => "End-of-life dates (endoflife.date)";
    public int IntervalMinutes => 1440;
    public string Licence => "endoflife.date (MIT licence). Release cycles and support end dates, with attribution.";

    /// <summary>The source tracks several hundred products; a response with fewer than this is not the real list.</summary>
    public int MinProducts { get; init; } = 100;

    public async Task<FeedResult> RunAsync(FeedContext ctx, CancellationToken ct)
    {
        ctx.Progress("Reading endoflife.date");
        var now = DateTime.UtcNow;
        List<EolCycle> rows;
        using (var doc = await PsirtStore.GetJsonAsync(ctx.Http, Url, ct)) rows = Parse(doc.RootElement, now);
        var products = rows.Select(r => r.Slug).Distinct().Count();
        if (products < MinProducts) throw new InvalidOperationException("endoflife.date returned " + products + " products; its response may have changed shape");
        await ReplaceAsync(ctx.Db, rows, ct);
        return new FeedResult(rows.Count, now.ToString("yyyy-MM-dd"), rows.Count + " release cycles of " + products + " products");
    }

    /// <summary>Replace every stored cycle in one transaction, unless the new set is under half the stored one.</summary>
    public static async Task ReplaceAsync(VvDbContext db, List<EolCycle> rows, CancellationToken ct)
    {
        var unique = rows.DistinctBy(r => (r.Slug, r.Cycle)).ToList();
        SignalStore.GuardShrink("end-of-life data", await db.EolCycles.CountAsync(ct), unique.Count);
        await using var tx = db.Database.CurrentTransaction is null ? await db.Database.BeginTransactionAsync(ct) : null;
        await db.EolCycles.ExecuteDeleteAsync(ct);
        foreach (var chunk in unique.Chunk(2000))
        {
            db.EolCycles.AddRange(chunk);
            await db.SaveChangesAsync(ct);
            db.ChangeTracker.Clear();
        }
        if (tx is not null) await tx.CommitAsync(ct);
    }

    /// <summary>Parse the v1 "products/full" response: {"result":[{name, label, aliases, links, releases:[{name, label, eolFrom, isEol, ...}]}]}.</summary>
    public static List<EolCycle> Parse(JsonElement root, DateTime now)
    {
        var list = new List<EolCycle>();
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("result", out var result) || result.ValueKind != JsonValueKind.Array) return list;
        foreach (var p in result.EnumerateArray())
        {
            var slug = PsirtStore.Str(p, "name");
            if (string.IsNullOrWhiteSpace(slug) || slug.Length > 64) continue;
            var label = PsirtStore.Str(p, "label") ?? slug;
            var aliases = string.Join('|', PsirtStore.StrArr(p, "aliases"));
            var link = p.TryGetProperty("links", out var links) ? PsirtStore.Str(links, "html") : null;
            foreach (var r in PsirtStore.Arr(p, "releases"))
            {
                var cycle = PsirtStore.Str(r, "name");
                if (string.IsNullOrWhiteSpace(cycle) || cycle.Length > 64) continue;
                var eolFrom = Date(r, "eolFrom");
                list.Add(new EolCycle
                {
                    Slug = slug, ProductLabel = PsirtStore.Trunc(label, 200), Aliases = PsirtStore.TruncOrNull(aliases, 500),
                    Cycle = cycle, CycleLabel = PsirtStore.TruncOrNull(PsirtStore.Str(r, "label"), 200),
                    ReleaseDate = Date(r, "releaseDate"), EolFrom = eolFrom,
                    // the flag as the source computed it, kept for cycles that are out of support with no date given
                    IsEol = Bool(r, "isEol") ?? (eolFrom is { } d && d <= now),
                    EoasFrom = Date(r, "eoasFrom"), EoesFrom = Date(r, "eoesFrom"),
                    IsMaintained = Bool(r, "isMaintained") ?? true,
                    Latest = r.TryGetProperty("latest", out var latest) ? PsirtStore.TruncOrNull(PsirtStore.Str(latest, "name"), 64) : null,
                    Link = PsirtStore.TruncOrNull(link, 300), RetrievedAt = now
                });
            }
        }
        return list;
    }

    private static DateTime? Date(JsonElement e, string name) => PsirtStore.ParseDate(e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null, "yyyy-MM-dd");
    private static bool? Bool(JsonElement e, string name) => e.TryGetProperty(name, out var v) ? v.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, _ => null } : null;
}
