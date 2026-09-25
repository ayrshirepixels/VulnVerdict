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
        // so a parser improvement (section 9.2: "n/a" placeholders now fall back to the CISA data) would otherwise
        // never reach the records already in the database.
        var cursorTag = CursorIsCurrent(ctx.Cursor) ? ParseCursor(ctx.Cursor) : null;
        var releases = await ListReleasesAsync(ctx, cursorTag, ct);
        if (releases.Count == 0) throw new InvalidOperationException("No releases returned by GitHub");

        var latest = releases[0];
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

            ctx.Progress("Clearing previous CVE data");
            await ctx.Db.CveAffected.ExecuteDeleteAsync(ct);
            await ctx.Db.Cves.ExecuteDeleteAsync(ct);

            total += await LoadNestedZipAsync(ctx, zipPath, latest.Tag, ct);
            try { File.Delete(zipPath); } catch { }

            // then any delta after that midnight up to and including latest
            var midnightTag = "cve_" + baselineDate + "_0000Z";
            foreach (var rel in releases.Where(r => string.CompareOrdinal(r.Tag, midnightTag) > 0).OrderBy(r => r.Tag))
                total += await ApplyDeltaAsync(ctx, rel, dir, ct);

            ctx.Progress("Rebuilding product catalogue");
            await RebuildCatalogueAsync(ctx.Db, ct);
            return new FeedResult(total, Cursor(latest.Tag), "baseline " + baselineDate);
        }

        var pending = releases.Where(r => string.CompareOrdinal(r.Tag, cursorTag) > 0).OrderBy(r => r.Tag).ToList();
        var touched = new HashSet<(string, string)>();
        foreach (var rel in pending)
            total += await ApplyDeltaAsync(ctx, rel, dir, ct, touched);
        if (touched.Count > 0) await UpdateCatalogueAsync(ctx.Db, touched, ct);
        return new FeedResult(total, Cursor(pending.LastOrDefault()?.Tag ?? cursorTag), pending.Count + " delta releases");
    }

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

    private async Task<int> LoadNestedZipAsync(FeedContext ctx, string outerZipPath, string sourceRef, CancellationToken ct)
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
            return await LoadEntriesAsync(ctx, inner, sourceRef, insertOnly: true, touched: null, ct);
        }
        finally { try { File.Delete(innerPath); } catch { } }
    }

    private async Task<int> ApplyDeltaAsync(FeedContext ctx, Release rel, string dir, CancellationToken ct, HashSet<(string, string)>? touched = null)
    {
        var asset = rel.Assets.FirstOrDefault(a => a.Name.Contains("_delta_CVEs_", StringComparison.OrdinalIgnoreCase) && a.Name.EndsWith(".zip"));
        if (asset.Name is null) return 0;
        var path = Path.Combine(dir, asset.Name);
        ctx.Progress("Applying delta " + rel.Tag);
        await DownloadAsync(ctx, asset.Url, path, asset.Size, ct);
        try
        {
            using var zip = ZipFile.OpenRead(path);
            return await LoadEntriesAsync(ctx, zip, rel.Tag, insertOnly: false, touched, ct);
        }
        finally { try { File.Delete(path); } catch { } }
    }

    private async Task<int> LoadEntriesAsync(FeedContext ctx, ZipArchive zip, string sourceRef, bool insertOnly, HashSet<(string, string)>? touched, CancellationToken ct)
    {
        var db = ctx.Db;
        db.ChangeTracker.AutoDetectChangesEnabled = false;
        var now = DateTime.UtcNow;
        var batch = new List<Cve>(BatchSize);
        int count = 0;
        var entries = zip.Entries.Where(e => e.Name.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase) && e.Name.EndsWith(".json", StringComparison.OrdinalIgnoreCase)).ToList();
        var total = entries.Count;
        // deltas can contain the same CVE twice (published then updated); keep the last
        var seen = new Dictionary<string, Cve>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in entries)
        {
            ct.ThrowIfCancellationRequested();
            if (insertOnly && MinYear > 0)
            {
                var yr = entry.Name.Length > 8 && int.TryParse(entry.Name.AsSpan(4, 4), out var y) ? y : 0;
                if (yr < MinYear) continue;
            }
            Cve? cve;
            try
            {
                await using var s = entry.Open();
                using var doc = await JsonDocument.ParseAsync(s, cancellationToken: ct);
                cve = Parse(doc.RootElement, now, sourceRef);
            }
            catch (Exception ex)
            {
                ctx.Log.LogWarning("Skipping {Entry}: {Error}", entry.FullName, ex.Message);
                continue;
            }
            if (cve is null) continue;
            if (insertOnly)
            {
                if (seen.ContainsKey(cve.Id)) continue;
                seen[cve.Id] = cve;
                batch.Add(cve);
                if (batch.Count >= BatchSize)
                {
                    await InsertBatchAsync(db, batch, ct);
                    count += batch.Count; batch.Clear(); seen.Clear();
                    ctx.Progress("Loaded " + count.ToString("N0") + " of " + total.ToString("N0") + " CVE records");
                }
            }
            else
            {
                seen[cve.Id] = cve;
            }
        }

        if (insertOnly)
        {
            if (batch.Count > 0) { await InsertBatchAsync(db, batch, ct); count += batch.Count; }
            return count;
        }

        // upsert path for deltas
        foreach (var chunk in seen.Values.Chunk(500))
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
            count += chunk.Length;
        }
        return count;
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
