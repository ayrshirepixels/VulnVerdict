using System.Globalization;
using System.IO.Compression;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;

namespace VulnVerdict.Core.Feeds;

/// <summary>
/// CVE List V5 from the CVEProject/cvelistV5 GitHub releases: a full "all CVEs at midnight" baseline once,
/// then every hourly delta release after it. The CISA ADP (Vulnrichment) container is read from the same records.
/// Cursor format: "tag=cve_YYYY-MM-DD_HHMMZ".
/// </summary>
public sealed class CveListFeed : IFeed
{
    public string Name => FeedNames.CveList;
    public string DisplayName => "CVE List V5 (CVE Program, with CISA Vulnrichment)";
    public int IntervalMinutes => 60;
    public string Licence => "CC0. CVE is a registered trademark of The MITRE Corporation; used as a data reference only.";

    private const string ReleasesApi = "https://api.github.com/repos/CVEProject/cvelistV5/releases";
    private const int BatchSize = 2000;

    /// <summary>Optional: only load CVEs published in or after this year on the baseline load (0 = all). Deltas always load fully.</summary>
    public int MinYear { get; init; } = 0;

    public async Task<FeedResult> RunAsync(FeedContext ctx, CancellationToken ct)
    {
        var dir = Path.Combine(ctx.DataDir, "cvelist");
        Directory.CreateDirectory(dir);

        // A cursor from an older parser forces one full reload: deltas only re-read records that changed upstream,
        // so a parser improvement ("n/a" placeholders now fall back to the CISA data, for example) would otherwise
        // never reach the records already in the database.
        var cursorTag = CursorIsCurrent(ctx.Cursor) ? ParseCursor(ctx.Cursor) : null;
        var releases = await ListReleasesAsync(ctx, cursorTag, ct);
        if (releases.Count == 0) throw new InvalidOperationException("No releases returned by GitHub");

        var latest = releases[0];
        var stats = new LoadStats();
        int total = 0;

        if (cursorTag is null || !releases.Any(r => r.Tag == cursorTag))
        {
            if (ctx.Cursor is not null && !CursorIsCurrent(ctx.Cursor)) ctx.Progress("Reloading the CVE list: the record parser changed since this data was loaded");
            // baseline: the latest release always carries the midnight snapshot of its own day
            var asset = latest.Assets.FirstOrDefault(a => a.Name.EndsWith("_all_CVEs_at_midnight.zip.zip", StringComparison.OrdinalIgnoreCase));
            if (asset.Name is null) throw new InvalidOperationException("Latest release has no all_CVEs_at_midnight asset");
            var baselineDate = asset.Name[..10]; // YYYY-MM-DD
            ctx.Progress("Downloading baseline " + asset.Name);
            var zipPath = Path.Combine(dir, asset.Name);
            await DownloadAsync(ctx, asset.Url, zipPath, asset.Size, ct);

            // A reload upserts over the existing rows and never deletes them: verdicts cascade from their CVE, so a
            // delete-and-reload took every verdict, its history and accepted-risk decisions with it. One transaction,
            // so a load that fails part-way leaves the previous data as it was.
            var reload = await ctx.Db.Cves.AnyAsync(ct);
            await using var tx = ctx.Db.Database.CurrentTransaction is null ? await ctx.Db.Database.BeginTransactionAsync(ct) : null;
            try { total += await LoadNestedZipAsync(ctx, zipPath, latest.Tag, insertOnly: !reload, stats, ct); }
            finally { try { File.Delete(zipPath); } catch { } }
            if (reload) await MarkAbsentAsync(ctx, stats, ct);

            // then any delta after that midnight up to and including latest; the cursor stops at the last one applied
            var midnightTag = "cve_" + baselineDate + "_0000Z";
            var applied = releases.Select(r => r.Tag).FirstOrDefault(t => string.CompareOrdinal(t, midnightTag) <= 0) ?? midnightTag;
            var after = releases.Where(r => string.CompareOrdinal(r.Tag, midnightTag) > 0).OrderBy(r => r.Tag).ToList();
            for (var i = 0; i < after.Count; i++)
            {
                var n = await ApplyDeltaAsync(ctx, after[i], dir, ct, stats, newerReleases: after.Count - 1 - i);
                if (n is null) break;
                total += n.Value; applied = after[i].Tag;
            }

            ctx.Progress("Rebuilding product catalogue");
            await RebuildCatalogueAsync(ctx.Db, ct);
            if (tx is not null) await tx.CommitAsync(ct);
            return new FeedResult(total, Cursor(applied), Note("baseline " + baselineDate, stats));
        }

        var pending = releases.Where(r => string.CompareOrdinal(r.Tag, cursorTag) > 0).OrderBy(r => r.Tag).ToList();
        var touched = new HashSet<(string, string)>();
        var last = cursorTag;
        var done = 0;
        for (var i = 0; i < pending.Count; i++)
        {
            var n = await ApplyDeltaAsync(ctx, pending[i], dir, ct, stats, newerReleases: pending.Count - 1 - i, touched);
            if (n is null) break;
            total += n.Value; last = pending[i].Tag; done++;
        }
        if (touched.Count > 0) await UpdateCatalogueAsync(ctx.Db, touched, ct);
        return new FeedResult(total, Cursor(last), Note(done + " delta releases" + (done < pending.Count ? ", waiting for " + pending[done].Tag : ""), stats));
    }

    /// <summary>
    /// A release with no delta asset yet is waited for (GitHub assets are uploaded after the release is made) unless
    /// this many newer releases already exist, by which point it is never coming.
    /// </summary>
    private const int MissingDeltaPatience = 3;

    /// <summary>Records seen and records unreadable across one run.</summary>
    private sealed class LoadStats
    {
        public HashSet<string> Seen { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Unreadable { get; } = new();
    }

    private static string Note(string what, LoadStats stats) =>
        stats.Unreadable.Count == 0 ? what : what + "; " + stats.Unreadable.Count.ToString("N0") + " unreadable records skipped (see log)";

    /// <summary>Bump when a change to <see cref="Parse"/> should be applied to records already loaded.</summary>
    public const int ParserVersion = 2;

    private static string Cursor(string tag) => "tag=" + tag + ";parser=" + ParserVersion;

    /// <summary>True when the cursor was written by this parser version; anything older means a full reload.</summary>
    public static bool CursorIsCurrent(string? cursor) => CursorPart(cursor, "parser=") == ParserVersion.ToString();

    private static string? ParseCursor(string? cursor) => CursorPart(cursor, "tag=");

    private static string? CursorPart(string? cursor, string prefix)
    {
        if (string.IsNullOrWhiteSpace(cursor)) return null;
        foreach (var part in cursor.Split(';'))
            if (part.StartsWith(prefix, StringComparison.Ordinal)) return part[prefix.Length..];
        return null;
    }

    private sealed record Release(string Tag, List<(string Name, string Url, long Size)> Assets);

    private static async Task<List<Release>> ListReleasesAsync(FeedContext ctx, string? cursorTag, CancellationToken ct)
    {
        var all = new List<Release>();
        for (var page = 1; page <= 10; page++)
        {
            using var resp = await ctx.Http.GetAsync(ReleasesApi + "?per_page=100&page=" + page, ct);
            resp.EnsureSuccessStatusCode();
            var arr = JsonNode.Parse(await resp.Content.ReadAsStringAsync(ct)) as JsonArray;
            if (arr is null || arr.Count == 0) break;
            foreach (var r in arr)
            {
                var tag = r?["tag_name"]?.GetValue<string>() ?? "";
                if (!tag.StartsWith("cve_")) continue;
                var assets = new List<(string, string, long)>();
                foreach (var a in r?["assets"] as JsonArray ?? new JsonArray())
                    assets.Add((a?["name"]?.GetValue<string>() ?? "", a?["browser_download_url"]?.GetValue<string>() ?? "", a?["size"]?.GetValue<long>() ?? 0));
                all.Add(new Release(tag, assets));
            }
            if (cursorTag is null || all.Any(r => r.Tag == cursorTag)) break;
        }
        return all.OrderByDescending(r => r.Tag).ToList();
    }

    private static async Task DownloadAsync(FeedContext ctx, string url, string path, long size, CancellationToken ct)
    {
        using var resp = await ctx.Http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
        resp.EnsureSuccessStatusCode();
        await using var src = await resp.Content.ReadAsStreamAsync(ct);
        await using var dst = File.Create(path);
        var buf = new byte[1 << 20];
        long done = 0; int n; var lastReport = 0L;
        while ((n = await src.ReadAsync(buf, ct)) > 0)
        {
            await dst.WriteAsync(buf.AsMemory(0, n), ct);
            done += n;
            if (done - lastReport > 20L << 20) { lastReport = done; ctx.Progress("Downloading " + (done >> 20) + "/" + (size >> 20) + " MB"); }
        }
    }

    private async Task<int> LoadNestedZipAsync(FeedContext ctx, string outerZipPath, string sourceRef, bool insertOnly, LoadStats stats, CancellationToken ct)
    {
        using var outer = ZipFile.OpenRead(outerZipPath);
        var innerEntry = outer.Entries.FirstOrDefault(e => e.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                         ?? throw new InvalidOperationException("Baseline zip does not contain an inner zip");
        var innerPath = outerZipPath + ".inner";
        ctx.Progress("Extracting baseline archive");
        innerEntry.ExtractToFile(innerPath, true);
        try
        {
            using var inner = ZipFile.OpenRead(innerPath);
            return await LoadEntriesAsync(ctx, inner, sourceRef, baseline: true, insertOnly, stats, touched: null, ct);
        }
        finally { try { File.Delete(innerPath); } catch { } }
    }

    /// <summary>Apply one hourly delta. Null when the release has no delta asset yet: stop there and retry next run.</summary>
    private async Task<int?> ApplyDeltaAsync(FeedContext ctx, Release rel, string dir, CancellationToken ct, LoadStats stats, int newerReleases, HashSet<(string, string)>? touched = null)
    {
        var asset = rel.Assets.FirstOrDefault(a => a.Name.Contains("_delta_CVEs_", StringComparison.OrdinalIgnoreCase) && a.Name.EndsWith(".zip"));
        if (asset.Name is null)
        {
            if (newerReleases < MissingDeltaPatience) { ctx.Log.LogInformation("Release {Tag} has no delta asset yet; waiting for it", rel.Tag); return null; }
            ctx.Log.LogWarning("Release {Tag} never got a delta asset; skipping it", rel.Tag);
            return 0;
        }
        var path = Path.Combine(dir, asset.Name);
        ctx.Progress("Applying delta " + rel.Tag);
        await DownloadAsync(ctx, asset.Url, path, asset.Size, ct);
        try
        {
            using var zip = ZipFile.OpenRead(path);
            return await LoadEntriesAsync(ctx, zip, rel.Tag, baseline: false, insertOnly: false, stats, touched, ct);
        }
        finally { try { File.Delete(path); } catch { } }
    }

    private async Task<int> LoadEntriesAsync(FeedContext ctx, ZipArchive zip, string sourceRef, bool baseline, bool insertOnly, LoadStats stats, HashSet<(string, string)>? touched, CancellationToken ct)
    {
        var db = ctx.Db;
        db.ChangeTracker.AutoDetectChangesEnabled = false;
        var now = DateTime.UtcNow;
        var batch = new List<Cve>(BatchSize);
        int count = 0;
        var entries = zip.Entries.Where(e => e.Name.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase) && e.Name.EndsWith(".json", StringComparison.OrdinalIgnoreCase)).ToList();
        var total = entries.Count;
        // deltas can contain the same CVE twice (published then updated); keep the last
        var latest = new Dictionary<string, Cve>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in entries)
        {
            ct.ThrowIfCancellationRequested();
            if (baseline && MinYear > 0 && YearOf(entry.Name) < MinYear) continue;
            Cve? cve;
            try
            {
                await using var s = entry.Open();
                using var doc = await JsonDocument.ParseAsync(s, cancellationToken: ct);
                cve = Parse(doc.RootElement, now, sourceRef);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                var id = Path.GetFileNameWithoutExtension(entry.Name).ToUpperInvariant();
                stats.Unreadable.Add(id);
                ctx.Log.LogWarning("Skipping unreadable CVE record {CveId} ({Entry}) in {Release}: {Error}", id, entry.FullName, sourceRef, ex.Message);
                continue;
            }
            if (cve is null) continue;
            if (!baseline) { latest[cve.Id] = cve; continue; }
            // the baseline holds each CVE once; the set spans the whole load, not one batch
            if (!stats.Seen.Add(cve.Id)) continue;
            batch.Add(cve);
            if (batch.Count >= BatchSize)
            {
                if (insertOnly) await InsertBatchAsync(db, batch, ct); else await UpsertAsync(db, batch, null, ct);
                count += batch.Count; batch.Clear();
                ctx.Progress("Loaded " + count.ToString("N0") + " of " + total.ToString("N0") + " CVE records");
            }
        }

        if (baseline)
        {
            if (batch.Count > 0) { if (insertOnly) await InsertBatchAsync(db, batch, ct); else await UpsertAsync(db, batch, null, ct); count += batch.Count; }
            return count;
        }
        await UpsertAsync(db, latest.Values, touched, ct);
        return latest.Count;
    }

    private static int YearOf(string name) => name.Length > 8 && int.TryParse(name.AsSpan(4, 4), out var y) ? y : 0;

    /// <summary>Insert new CVEs and update existing ones in place, replacing their affected rows. Existing rows (and the verdicts on them) stay.</summary>
    private static async Task UpsertAsync(VvDbContext db, IEnumerable<Cve> cves, HashSet<(string, string)>? touched, CancellationToken ct)
    {
        foreach (var chunk in cves.Chunk(500))
        {
            var ids = chunk.Select(c => c.Id).ToList();
            var existing = await db.Cves.Where(c => ids.Contains(c.Id)).ToDictionaryAsync(c => c.Id, ct);
            await db.CveAffected.Where(a => ids.Contains(a.CveId)).ExecuteDeleteAsync(ct);
            foreach (var c in chunk)
            {
                if (existing.TryGetValue(c.Id, out var e))
                {
                    db.Entry(e).CurrentValues.SetValues(c);
                    foreach (var a in c.Affected) { a.CveId = c.Id; db.CveAffected.Add(a); }
                }
                else db.Cves.Add(c);
                foreach (var a in c.Affected) touched?.Add((a.VendorNorm, a.ProductNorm));
            }
            await db.SaveChangesAsync(ct);
            db.ChangeTracker.Clear();
        }
    }

    /// <summary>
    /// After a completed reload, a CVE List record the baseline no longer carries is marked rejected rather than deleted,
    /// so its verdicts close through the evaluator instead of vanishing by cascade. Records this run could not read, years
    /// excluded by <see cref="MinYear"/>, and rows from other sources (OSV package stubs) are left alone.
    /// </summary>
    private async Task MarkAbsentAsync(FeedContext ctx, LoadStats stats, CancellationToken ct)
    {
        var unreadable = stats.Unreadable.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var ids = await ctx.Db.Cves.Where(c => c.SourceRef != null && c.SourceRef.StartsWith("cve_") && c.State != "REJECTED")
            .Select(c => c.Id).ToListAsync(ct);
        var absent = ids.Where(id => !stats.Seen.Contains(id) && !unreadable.Contains(id) && (MinYear <= 0 || YearOf(id) >= MinYear)).ToList();
        if (absent.Count == 0) return;
        ctx.Log.LogWarning("{Count} CVE records are no longer in the CVE List baseline; marking them rejected", absent.Count);
        foreach (var chunk in absent.Chunk(500))
        {
            var c = chunk.ToList();
            await ctx.Db.Cves.Where(x => c.Contains(x.Id)).ExecuteUpdateAsync(u => u.SetProperty(x => x.State, "REJECTED"), ct);
        }
    }

    private static async Task InsertBatchAsync(VvDbContext db, List<Cve> batch, CancellationToken ct)
    {
        db.Cves.AddRange(batch);
        await db.SaveChangesAsync(ct);
        db.ChangeTracker.Clear();
    }

    // ------------------------------------------------------------------ parsing

    public static Cve? Parse(JsonElement root, DateTime now, string sourceRef)
    {
        if (!root.TryGetProperty("cveMetadata", out var meta)) return null;
        var id = meta.GetProperty("cveId").GetString();
        if (string.IsNullOrEmpty(id)) return null;
        var cve = new Cve
        {
            Id = id.ToUpperInvariant(),
            State = meta.TryGetProperty("state", out var st) ? (st.GetString() ?? "") : "",
            Published = Date(meta, "datePublished"),
            LastModified = Date(meta, "dateUpdated") ?? Date(meta, "datePublished"),
            Assigner = Str(meta, "assignerShortName", 64),
            RetrievedAt = now,
            SourceRef = sourceRef
        };
        if (!root.TryGetProperty("containers", out var containers)) return cve;

        JsonElement cna = default;
        var hasCna = containers.TryGetProperty("cna", out cna);
        if (hasCna)
        {
            cve.Title = Str(cna, "title", 512);
            if (cna.TryGetProperty("descriptions", out var descs) && descs.ValueKind == JsonValueKind.Array)
            {
                string? en = null, any = null;
                foreach (var d in descs.EnumerateArray())
                {
                    var v = d.TryGetProperty("value", out var vv) ? vv.GetString() : null;
                    if (v is null) continue;
                    any ??= v;
                    var lang = d.TryGetProperty("lang", out var l) ? l.GetString() : null;
                    if (lang is not null && lang.StartsWith("en", StringComparison.OrdinalIgnoreCase)) { en = v; break; }
                }
                cve.Description = Trunc(en ?? any, 4000);
            }
            if (cna.TryGetProperty("references", out var refs) && refs.ValueKind == JsonValueKind.Array)
            {
                var urls = refs.EnumerateArray().Select(r => r.TryGetProperty("url", out var u) ? u.GetString() : null).Where(u => !string.IsNullOrEmpty(u)).Take(20).ToList();
                if (urls.Count > 0) cve.ReferencesJson = JsonSerializer.Serialize(urls);
            }
            ReadMetrics(cna, cve);
            ReadAffected(cna, cve);
        }

        if (containers.TryGetProperty("adp", out var adps) && adps.ValueKind == JsonValueKind.Array)
        {
            foreach (var adp in adps.EnumerateArray())
            {
                if (adp.TryGetProperty("metrics", out var metrics) && metrics.ValueKind == JsonValueKind.Array)
                {
                    foreach (var m in metrics.EnumerateArray())
                    {
                        if (m.TryGetProperty("other", out var other) && other.TryGetProperty("type", out var t) && t.GetString() == "ssvc"
                            && other.TryGetProperty("content", out var content) && content.TryGetProperty("options", out var opts) && opts.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var o in opts.EnumerateArray())
                            {
                                if (o.TryGetProperty("Exploitation", out var ex)) cve.SsvcExploitation = Trunc(ex.GetString()?.ToLowerInvariant(), 16);
                                if (o.TryGetProperty("Automatable", out var au)) cve.SsvcAutomatable = Trunc(au.GetString()?.ToLowerInvariant(), 8);
                            }
                        }
                    }
                    if (cve.CvssV31Vector is null && cve.CvssV40Vector is null) ReadMetrics(adp, cve);
                }
                if (cve.Affected.Count == 0) ReadAffected(adp, cve);
            }
        }
        return cve;
    }

    private static void ReadMetrics(JsonElement container, Cve cve)
    {
        if (!container.TryGetProperty("metrics", out var metrics) || metrics.ValueKind != JsonValueKind.Array) return;
        foreach (var m in metrics.EnumerateArray())
        {
            if (m.TryGetProperty("cvssV4_0", out var v4) && cve.CvssV40Vector is null)
            {
                cve.CvssV40Vector = Str(v4, "vectorString", 300);
                cve.CvssV40Score = v4.TryGetProperty("baseScore", out var s) && s.ValueKind == JsonValueKind.Number ? s.GetDouble() : null;
            }
            if (m.TryGetProperty("cvssV3_1", out var v31) && cve.CvssV31Vector is null)
            {
                cve.CvssV31Vector = Str(v31, "vectorString", 200);
                cve.CvssV31Score = v31.TryGetProperty("baseScore", out var s) && s.ValueKind == JsonValueKind.Number ? s.GetDouble() : null;
            }
            else if (m.TryGetProperty("cvssV3_0", out var v30) && cve.CvssV31Vector is null)
            {
                cve.CvssV31Vector = Str(v30, "vectorString", 200);
                cve.CvssV31Score = v30.TryGetProperty("baseScore", out var s) && s.ValueKind == JsonValueKind.Number ? s.GetDouble() : null;
            }
        }
    }

    /// <summary>
    /// Values CNAs write when they are not naming anything: "n/a" above all (a third of the whole CVE list has
    /// vendor and product "n/a"), plus the other ways of saying so. Compared in normalised form, so "N/A", "n/a"
    /// and "-" are all placeholders.
    /// </summary>
    private static readonly HashSet<string> Placeholders = new(StringComparer.Ordinal) { "", "na", "notapplicable", "unknown", "unspecified", "none", "null", "tbd", "various" };

    public static bool IsPlaceholder(string? name) => Placeholders.Contains(Normalizer.Norm(name));

    private static void ReadAffected(JsonElement container, Cve cve)
    {
        if (!container.TryGetProperty("affected", out var affected) || affected.ValueKind != JsonValueKind.Array) return;
        foreach (var a in affected.EnumerateArray())
        {
            var vendor = Str(a, "vendor", 200) ?? "";
            var product = Str(a, "product", 200) ?? "";
            if (product == "" && a.TryGetProperty("packageName", out var pn)) product = Trunc(pn.GetString(), 200) ?? "";
            // A placeholder product names nothing: skip the row, so the CISA ADP container's affected list (which
            // often carries the real vendor and product for exactly these records) is read instead.
            if (IsPlaceholder(product)) continue;
            // A placeholder vendor with a real product ("n/a" / "BIG-IP") is stored with no vendor at all, which the
            // evaluator reads as "vendor not stated" rather than as a vendor called "n/a".
            if (IsPlaceholder(vendor)) vendor = "";
            var row = new CveAffected
            {
                Vendor = vendor,
                Product = product,
                VendorNorm = Normalizer.Norm(vendor),
                ProductNorm = Normalizer.Norm(product),
                DefaultStatus = Str(a, "defaultStatus", 16),
                VersionsJson = a.TryGetProperty("versions", out var vs) && vs.ValueKind == JsonValueKind.Array ? vs.GetRawText() : null,
                CpesJson = a.TryGetProperty("cpes", out var cp) && cp.ValueKind == JsonValueKind.Array ? cp.GetRawText() : null
            };
            cve.Affected.Add(row);
        }
    }

    private static string? Str(JsonElement e, string name, int max) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? Trunc(v.GetString(), max) : null;

    private static string? Trunc(string? s, int max) => s is null ? null : (s.Length <= max ? s : s[..max]);

    private static DateTime? Date(JsonElement e, string name)
    {
        if (!e.TryGetProperty(name, out var v) || v.ValueKind != JsonValueKind.String) return null;
        return DateTime.TryParse(v.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var d) ? d : null;
    }

    // ------------------------------------------------------------------ product catalogue

    public static async Task RebuildCatalogueAsync(VvDbContext db, CancellationToken ct)
    {
        await db.CnaProducts.ExecuteDeleteAsync(ct);
        var groups = await db.CveAffected
            .GroupBy(a => new { a.VendorNorm, a.ProductNorm })
            .Select(g => new { g.Key.VendorNorm, g.Key.ProductNorm, Vendor = g.Min(x => x.Vendor), Product = g.Min(x => x.Product), Count = g.Count() })
            .ToListAsync(ct);
        var now = DateTime.UtcNow;
        db.ChangeTracker.AutoDetectChangesEnabled = false;
        foreach (var chunk in groups.Chunk(5000))
        {
            db.CnaProducts.AddRange(chunk.Select(g => new CnaProduct { VendorNorm = g.VendorNorm, ProductNorm = g.ProductNorm, Vendor = g.Vendor ?? "", Product = g.Product ?? "", CveCount = g.Count, LastSeen = now }));
            await db.SaveChangesAsync(ct);
            db.ChangeTracker.Clear();
        }
    }

    private static async Task UpdateCatalogueAsync(VvDbContext db, HashSet<(string VendorNorm, string ProductNorm)> touched, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        foreach (var (vn, pn) in touched)
        {
            var stats = await db.CveAffected.Where(a => a.VendorNorm == vn && a.ProductNorm == pn)
                .GroupBy(a => 1).Select(g => new { Vendor = g.Min(x => x.Vendor), Product = g.Min(x => x.Product), Count = g.Count() }).FirstOrDefaultAsync(ct);
            if (stats is null) continue;
            var row = await db.CnaProducts.FindAsync(new object[] { vn, pn }, ct);
            if (row is null) db.CnaProducts.Add(new CnaProduct { VendorNorm = vn, ProductNorm = pn, Vendor = stats.Vendor ?? "", Product = stats.Product ?? "", CveCount = stats.Count, LastSeen = now });
            else { row.CveCount = stats.Count; row.LastSeen = now; }
        }
        await db.SaveChangesAsync(ct);
        db.ChangeTracker.Clear();
    }
}
