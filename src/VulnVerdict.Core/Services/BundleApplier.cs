using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Feeds;

namespace VulnVerdict.Core.Services;

/// <summary>Thrown when a bundle must not be applied: unsigned, downgraded, or its files do not match the manifest.</summary>
public sealed class BundleRejectedException : Exception
{
    public BundleRejectedException(string reason) : base(reason) { }
}

public sealed class BundleApplyResult
{
    public string Version { get; init; } = "";
    public int Cves { get; set; }
    public int Kev { get; set; }
    public int Epss { get; set; }
    public int Signals { get; set; }
    public int AliasesAdded { get; set; }
    public int Narratives { get; set; }
    public Dictionary<string, int> SignalsBySource { get; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Applies a verified bundle directory to the console database in one transaction: CVEs and their affected rows are
/// upserted, KEV, EPSS and exploit signals replaced, aliases merged, narratives upserted, the product catalogue rebuilt,
/// then the BundleState and the six public FeedStatus rows are recorded so the digest's "feeds current as of" line and the
/// staleness alert keep working without the feeds running.
/// </summary>
public static class BundleApplier
{
    private const int BatchSize = 2000;

    /// <summary>A bundle must be strictly newer than the applied one. Returns the refusal reason, or null when fine.</summary>
    public static string? CheckDowngrade(string incoming, string? current)
    {
        if (!BundleManifest.IsValidVersion(incoming)) return "Bundle version '" + incoming + "' is not a valid yyyyMMddHHmm version";
        if (current is null) return null;
        var cmp = string.CompareOrdinal(incoming, current);
        if (cmp < 0) return "Bundle " + incoming + " is older than the applied bundle " + current + " (downgrade refused)";
        if (cmp == 0) return "Bundle " + incoming + " is already applied";
        return null;
    }

    /// <summary>Check every manifest entry exists in <paramref name="dir"/> with the stated size and SHA-256. Returns the reason on failure, null when all match.</summary>
    public static async Task<string?> VerifyFilesAsync(BundleManifest manifest, string dir, CancellationToken ct)
    {
        foreach (var required in BundleFiles.Required)
            if (!manifest.Files.Any(f => f.Name == required)) return "Manifest does not list " + required;
        foreach (var f in manifest.Files)
        {
            if (f.Name.Contains('/') || f.Name.Contains('\\') || f.Name.Contains("..")) return "Manifest entry '" + f.Name + "' has an invalid name";
            var path = Path.Combine(dir, f.Name);
            if (!File.Exists(path)) return "Bundle is missing " + f.Name;
            var info = new FileInfo(path);
            if (info.Length != f.Bytes) return f.Name + " is " + info.Length + " bytes, manifest says " + f.Bytes;
            var sha = await BundleHash.FileSha256Async(path, ct);
            if (!sha.Equals(f.Sha256, StringComparison.OrdinalIgnoreCase)) return f.Name + " does not match its manifest hash (tampered or corrupt)";
        }
        return null;
    }

    public static Task<BundleState?> CurrentAsync(VvDbContext db, CancellationToken ct) =>
        db.Bundles.AsNoTracking().OrderByDescending(b => b.Id).FirstOrDefaultAsync(ct);

    /// <summary>
    /// Apply an extracted bundle. The caller has already verified the manifest signature; this method refuses a downgrade
    /// and any file that does not match the manifest, then applies everything in a single transaction.
    /// </summary>
    public static async Task<BundleApplyResult> ApplyAsync(VvDbContext db, BundleManifest manifest, string dir, string source, CancellationToken ct, Action<string>? progress = null)
    {
        progress ??= _ => { };
        var current = await CurrentAsync(db, ct);
        if (CheckDowngrade(manifest.Version, current?.Version) is { } why) throw new BundleRejectedException(why);
        progress("Verifying bundle files");
        if (await VerifyFilesAsync(manifest, dir, ct) is { } bad) throw new BundleRejectedException(bad);

        var result = new BundleApplyResult { Version = manifest.Version };
        db.ChangeTracker.AutoDetectChangesEnabled = false;
        db.Database.SetCommandTimeout(TimeSpan.FromMinutes(30));
        await using var tx = await db.Database.BeginTransactionAsync(ct);

        result.Cves = await ApplyCvesAsync(db, Path.Combine(dir, BundleFiles.Cves), progress, ct);
        progress("Applying KEV");
        result.Kev = await ApplyKevAsync(db, Path.Combine(dir, BundleFiles.Kev), ct);
        progress("Applying EPSS");
        result.Epss = await ApplyEpssAsync(db, Path.Combine(dir, BundleFiles.Epss), ct);
        progress("Applying exploit signals");
        result.Signals = await ApplySignalsAsync(db, Path.Combine(dir, BundleFiles.Signals), result.SignalsBySource, ct);
        progress("Merging aliases");
        result.AliasesAdded = await MergeAliasesAsync(db, Path.Combine(dir, BundleFiles.Aliases), ct);
        progress("Applying narratives");
        result.Narratives = await UpsertNarrativesAsync(db, Path.Combine(dir, BundleFiles.Narratives), ct);
        progress("Rebuilding product catalogue");
        await CveListFeed.RebuildCatalogueAsync(db, ct);

        var now = DateTime.UtcNow;
        db.Bundles.Add(new BundleState
        {
            Version = manifest.Version, BuiltAt = DateTime.SpecifyKind(manifest.BuiltAt, DateTimeKind.Utc), AppliedAt = now,
            Source = source.Length > 64 ? source[..64] : source, Signer = manifest.Signer is { Length: > 128 } s ? s[..128] : manifest.Signer
        });
        await db.SaveChangesAsync(ct);
        db.ChangeTracker.Clear();
        await RecordFeedStatusAsync(db, manifest, result, now, ct);

        await tx.CommitAsync(ct);
        db.ChangeTracker.Clear();
        return result;
    }

    // ------------------------------------------------------------------ CVEs

    private static async Task<int> ApplyCvesAsync(VvDbContext db, string path, Action<string> progress, CancellationToken ct)
    {
        // a database that has never held CVE data takes the fast insert-only path; otherwise upsert so the verdicts that
        // reference these CVEs (cascade delete) survive the refresh
        var insertOnly = !await db.Cves.AnyAsync(ct);
        var count = 0;
        var batch = new List<Cve>(BatchSize);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using var reader = new StreamReader(path);
        while (await reader.ReadLineAsync(ct) is { } line)
        {
            if (line.Length == 0) continue;
            var dto = JsonSerializer.Deserialize<BundleCve>(line, BundleJson.Options);
            if (dto is null || string.IsNullOrEmpty(dto.Id)) continue;
            if (!seen.Add(dto.Id)) continue;
            batch.Add(dto.ToEntity());
            if (batch.Count >= BatchSize)
            {
                count += await FlushCvesAsync(db, batch, insertOnly, ct);
                batch.Clear(); seen.Clear();
                progress("Applied " + count.ToString("N0") + " CVE records");
            }
        }
        if (batch.Count > 0) count += await FlushCvesAsync(db, batch, insertOnly, ct);
        return count;
    }

    private static async Task<int> FlushCvesAsync(VvDbContext db, List<Cve> batch, bool insertOnly, CancellationToken ct)
    {
        if (insertOnly)
        {
            db.Cves.AddRange(batch);
            await db.SaveChangesAsync(ct);
            db.ChangeTracker.Clear();
            return batch.Count;
        }
        foreach (var chunk in batch.Chunk(500))
        {
            var ids = chunk.Select(c => c.Id).ToList();
            var existing = await db.Cves.Where(c => ids.Contains(c.Id)).ToDictionaryAsync(c => c.Id, ct);
            await db.CveAffected.Where(a => ids.Contains(a.CveId)).ExecuteDeleteAsync(ct);
            foreach (var c in chunk)
            {
                if (existing.TryGetValue(c.Id, out var e))
                {
                    var affected = c.Affected.ToList();
                    c.Affected.Clear();
                    db.Entry(e).CurrentValues.SetValues(c);
                    foreach (var a in affected) { a.CveId = c.Id; db.CveAffected.Add(a); }
                }
                else db.Cves.Add(c);
            }
            await db.SaveChangesAsync(ct);
            db.ChangeTracker.Clear();
        }
        return batch.Count;
    }

    // ------------------------------------------------------------------ KEV, EPSS, signals

    private static async Task<int> ApplyKevAsync(VvDbContext db, string path, CancellationToken ct)
    {
        await using var s = File.OpenRead(path);
        var rows = await JsonSerializer.DeserializeAsync<List<BundleKev>>(s, BundleJson.Options, ct) ?? new List<BundleKev>();
        await db.Kev.ExecuteDeleteAsync(ct);
        var entities = rows.Where(r => !string.IsNullOrEmpty(r.CveId)).DistinctBy(r => r.CveId, StringComparer.OrdinalIgnoreCase).Select(r => r.ToEntity()).ToList();
        foreach (var chunk in entities.Chunk(BatchSize))
        {
            db.Kev.AddRange(chunk);
            await db.SaveChangesAsync(ct);
            db.ChangeTracker.Clear();
        }
        return entities.Count;
    }

    private static async Task<int> ApplyEpssAsync(VvDbContext db, string path, CancellationToken ct)
    {
        await db.Epss.ExecuteDeleteAsync(ct);
        var count = 0;
        var chunk = new List<EpssScore>(5000);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using var reader = new StreamReader(path);
        var header = true;
        while (await reader.ReadLineAsync(ct) is { } line)
        {
            if (header) { header = false; continue; }
            if (line.Length == 0) continue;
            var parts = line.Split(',');
            if (parts.Length < 4 || !seen.Add(parts[0])) continue;
            if (!double.TryParse(parts[1], NumberStyles.Float, CultureInfo.InvariantCulture, out var score)) continue;
            double.TryParse(parts[2], NumberStyles.Float, CultureInfo.InvariantCulture, out var pct);
            DateTime.TryParse(parts[3], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var date);
            var retrieved = parts.Length > 4 && DateTime.TryParse(parts[4], CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var r) ? r : DateTime.UtcNow;
            chunk.Add(new EpssScore { CveId = parts[0].ToUpperInvariant(), Score = score, Percentile = pct, ScoreDate = date, RetrievedAt = retrieved });
            if (chunk.Count >= 5000) { count += await FlushAsync(db, db.Epss, chunk, ct); }
        }
        if (chunk.Count > 0) count += await FlushAsync(db, db.Epss, chunk, ct);
        return count;
    }

    private static async Task<int> ApplySignalsAsync(VvDbContext db, string path, Dictionary<string, int> bySource, CancellationToken ct)
    {
        var rows = new List<ExploitSignal>();
        using (var reader = new StreamReader(path))
        {
            while (await reader.ReadLineAsync(ct) is { } line)
            {
                if (line.Length == 0) continue;
                var dto = JsonSerializer.Deserialize<BundleSignal>(line, BundleJson.Options);
                if (dto is null || string.IsNullOrEmpty(dto.CveId) || string.IsNullOrEmpty(dto.Source) || string.IsNullOrEmpty(dto.Url)) continue;
                rows.Add(dto.ToEntity());
            }
        }
        // only the sources the bundle carries are replaced; a source the console collects itself (e.g. a future GitHub PoC search) is left alone
        var count = 0;
        foreach (var group in rows.GroupBy(r => r.Source, StringComparer.OrdinalIgnoreCase))
        {
            var source = group.Key;
            await db.ExploitSignals.Where(s => s.Source == source).ExecuteDeleteAsync(ct);
            var unique = group.DistinctBy(r => (r.CveId.ToUpperInvariant(), r.Url)).ToList();
            var chunk = new List<ExploitSignal>(5000);
            foreach (var r in unique)
            {
                chunk.Add(r);
                if (chunk.Count >= 5000) await FlushAsync(db, db.ExploitSignals, chunk, ct);
            }
            if (chunk.Count > 0) await FlushAsync(db, db.ExploitSignals, chunk, ct);
            bySource[source] = unique.Count;
            count += unique.Count;
        }
        return count;
    }

    private static async Task<int> FlushAsync<T>(VvDbContext db, DbSet<T> set, List<T> chunk, CancellationToken ct) where T : class
    {
        set.AddRange(chunk);
        await db.SaveChangesAsync(ct);
        db.ChangeTracker.Clear();
        var n = chunk.Count;
        chunk.Clear();
        return n;
    }

    // ------------------------------------------------------------------ aliases, narratives

    private static async Task<int> MergeAliasesAsync(VvDbContext db, string path, CancellationToken ct)
    {
        await using var s = File.OpenRead(path);
        var rows = await JsonSerializer.DeserializeAsync<List<BundleAlias>>(s, BundleJson.Options, ct) ?? new List<BundleAlias>();
        var existing = (await db.Aliases.AsNoTracking().Select(a => new { a.AliasNorm, a.VendorNorm, a.ProductNorm }).ToListAsync(ct))
            .Select(a => (a.AliasNorm, a.VendorNorm, a.ProductNorm)).ToHashSet();
        var added = 0;
        foreach (var r in rows)
        {
            if (string.IsNullOrEmpty(r.AliasNorm) || string.IsNullOrEmpty(r.ProductNorm)) continue;
            if (!existing.Add((r.AliasNorm, r.VendorNorm, r.ProductNorm))) continue;
            db.Aliases.Add(r.ToEntity());
            added++;
        }
        if (added > 0) { await db.SaveChangesAsync(ct); db.ChangeTracker.Clear(); }
        return added;
    }

    private static async Task<int> UpsertNarrativesAsync(VvDbContext db, string path, CancellationToken ct)
    {
        var rows = new List<Narrative>();
        using (var reader = new StreamReader(path))
        {
            while (await reader.ReadLineAsync(ct) is { } line)
            {
                if (line.Length == 0) continue;
                var dto = JsonSerializer.Deserialize<BundleNarrative>(line, BundleJson.Options);
                if (dto is null || string.IsNullOrEmpty(dto.Key) || string.IsNullOrEmpty(dto.Text)) continue;
                rows.Add(dto.ToEntity());
            }
        }
        var count = 0;
        foreach (var chunk in rows.DistinctBy(r => r.Key).Chunk(500))
        {
            var keys = chunk.Select(r => r.Key).ToList();
            var existing = await db.Narratives.Where(n => keys.Contains(n.Key)).ToDictionaryAsync(n => n.Key, ct);
            foreach (var n in chunk)
            {
                if (existing.TryGetValue(n.Key, out var e))
                {
                    if (e.CreatedAt >= n.CreatedAt) continue;
                    e.Text = n.Text; e.Provider = n.Provider; e.Model = n.Model; e.PromptVersion = n.PromptVersion; e.CreatedAt = n.CreatedAt;
                    db.Entry(e).State = EntityState.Modified;
                }
                else db.Narratives.Add(n);
                count++;
            }
            await db.SaveChangesAsync(ct);
            db.ChangeTracker.Clear();
        }
        return count;
    }

    // ------------------------------------------------------------------ feed status

    private static async Task RecordFeedStatusAsync(VvDbContext db, BundleManifest manifest, BundleApplyResult r, DateTime now, CancellationToken ct)
    {
        var builtAt = DateTime.SpecifyKind(manifest.BuiltAt, DateTimeKind.Utc);
        var records = new Dictionary<string, int>
        {
            [FeedNames.CveList] = r.Cves, [FeedNames.Kev] = r.Kev, [FeedNames.Epss] = r.Epss,
            [FeedNames.ExploitDb] = r.SignalsBySource.GetValueOrDefault("exploitdb"),
            [FeedNames.Metasploit] = r.SignalsBySource.GetValueOrDefault("metasploit"),
            [FeedNames.Nuclei] = r.SignalsBySource.GetValueOrDefault("nuclei")
        };
        var names = records.Keys.ToList();
        var rows = await db.FeedStatuses.Where(f => names.Contains(f.Name)).ToDictionaryAsync(f => f.Name, ct);
        foreach (var (name, n) in records)
        {
            if (!rows.TryGetValue(name, out var row))
            {
                row = new FeedStatus { Name = name, DisplayName = name, IntervalMinutes = 60 };
                db.FeedStatuses.Add(row);
            }
            else db.Entry(row).State = EntityState.Modified;
            row.LastAttempt = now; row.LastSuccess = builtAt; row.LastError = null; row.RecordsLastRun = n;
            row.Cursor = "bundle " + manifest.Version; row.Running = false; row.RunRequested = false; row.Progress = "from bundle " + manifest.Version;
        }
        await db.SaveChangesAsync(ct);
        db.ChangeTracker.Clear();
    }
}
