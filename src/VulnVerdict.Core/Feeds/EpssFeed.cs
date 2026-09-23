using System.Globalization;
using System.IO.Compression;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Feeds;

/// <summary>EPSS daily scores from FIRST. Free with attribution.</summary>
public sealed class EpssFeed : IFeed
{
    public string Name => FeedNames.Epss;
    public string DisplayName => "EPSS exploit probability (FIRST)";
    public int IntervalMinutes => 1440;
    public string Licence => "Free with attribution to FIRST (https://www.first.org/epss).";
    public const string Url = "https://epss.cyentia.com/epss_scores-current.csv.gz";

    public async Task<FeedResult> RunAsync(FeedContext ctx, CancellationToken ct)
    {
        using var resp = await ctx.Http.GetAsync(Url, HttpCompletionOption.ResponseHeadersRead, ct);
        resp.EnsureSuccessStatusCode();
        await using var gz = new GZipStream(await resp.Content.ReadAsStreamAsync(ct), CompressionMode.Decompress);
        using var reader = new StreamReader(gz);

        var now = DateTime.UtcNow;
        DateTime scoreDate = now;
        string? modelVersion = null;
        var rows = new List<EpssScore>(320_000);
        string? line;
        while ((line = await reader.ReadLineAsync(ct)) is not null)
        {
            if (line.StartsWith('#'))
            {
                foreach (var part in line.TrimStart('#').Split(','))
                {
                    var kv = part.Split(':', 2);
                    if (kv.Length != 2) continue;
                    if (kv[0] == "model_version") modelVersion = kv[1];
                    if (kv[0] == "score_date" && DateTime.TryParse(kv[1], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d)) scoreDate = d;
                }
                continue;
            }
            if (line.StartsWith("cve,")) continue;
            var f = line.Split(',');
            if (f.Length < 3) continue;
            if (!double.TryParse(f[1], NumberStyles.Float, CultureInfo.InvariantCulture, out var score)) continue;
            double.TryParse(f[2], NumberStyles.Float, CultureInfo.InvariantCulture, out var pct);
            rows.Add(new EpssScore { CveId = f[0].ToUpperInvariant(), Score = score, Percentile = pct, ScoreDate = scoreDate, RetrievedAt = now });
        }

        ctx.Progress("Storing " + rows.Count.ToString("N0") + " EPSS scores");
        var db = ctx.Db;
        db.ChangeTracker.AutoDetectChangesEnabled = false;
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        await db.Epss.ExecuteDeleteAsync(ct);
        foreach (var chunk in rows.Chunk(5000))
        {
            db.Epss.AddRange(chunk);
            await db.SaveChangesAsync(ct);
            db.ChangeTracker.Clear();
        }
        await tx.CommitAsync(ct);
        return new FeedResult(rows.Count, modelVersion + "@" + scoreDate.ToString("yyyy-MM-dd"));
    }
}
