using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Feeds;

/// <summary>CISA Known Exploited Vulnerabilities. Exploitation = Active.</summary>
public sealed class KevFeed : IFeed
{
    public string Name => FeedNames.Kev;
    public string DisplayName => "CISA Known Exploited Vulnerabilities";
    public int IntervalMinutes => 240;
    public string Licence => "Public (CISA).";
    public const string Url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    public async Task<FeedResult> RunAsync(FeedContext ctx, CancellationToken ct)
    {
        using var doc = JsonDocument.Parse(await ctx.Http.GetStringAsync(Url, ct));
        var root = doc.RootElement;
        var version = root.TryGetProperty("catalogVersion", out var cv) ? cv.GetString() : null;
        var now = DateTime.UtcNow;
        var rows = new List<KevEntry>();
        foreach (var v in root.GetProperty("vulnerabilities").EnumerateArray())
        {
            var id = v.GetProperty("cveID").GetString();
            if (string.IsNullOrEmpty(id)) continue;
            rows.Add(new KevEntry
            {
                CveId = id.ToUpperInvariant(),
                VendorProject = S(v, "vendorProject", 200),
                Product = S(v, "product", 200),
                VulnerabilityName = S(v, "vulnerabilityName", 500),
                DateAdded = D(v, "dateAdded") ?? now,
                RequiredAction = S(v, "requiredAction", 2000),
                DueDate = D(v, "dueDate"),
                KnownRansomwareUse = S(v, "knownRansomwareCampaignUse", 16),
                Notes = S(v, "notes", 2000),
                RetrievedAt = now
            });
        }
        // replace atomically
        await using var tx = await ctx.Db.Database.BeginTransactionAsync(ct);
        await ctx.Db.Kev.ExecuteDeleteAsync(ct);
        ctx.Db.Kev.AddRange(rows.DistinctBy(r => r.CveId));
        await ctx.Db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        ctx.Db.ChangeTracker.Clear();
        return new FeedResult(rows.Count, version);
    }

    private static string? S(JsonElement e, string n, int max) => e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? (v.GetString() is { } s ? (s.Length <= max ? s : s[..max]) : null) : null;
    private static DateTime? D(JsonElement e, string n) => e.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String && DateTime.TryParse(v.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d) ? d : null;
}
