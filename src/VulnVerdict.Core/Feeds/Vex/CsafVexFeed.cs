using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;
using VulnVerdict.Core.Feeds.Psirt;

namespace VulnVerdict.Core.Feeds.Vex;

/// <summary>
/// Vendor VEX statements from CSAF providers (see <see cref="VexProviders"/>): which products a vendor says are affected,
/// fixed, not affected or still under investigation for a CVE.
///
/// Volume. Red Hat alone publishes one VEX file per CVE, several megabytes each for a busy one, and hundreds of
/// thousands of them; the whole-set archive is a zstd tarball of the lot. Neither belongs on a small console, so the
/// feed is driven by what is installed: a provider is called only when the watchlist or inventory holds one of its
/// vendors' products, a per-CVE document is fetched only when that CVE already has a verdict against one of those
/// products, and only the statements about those products are stored. A VEX statement can only adjust a verdict that
/// exists, so nothing is lost; a CVE that is new today gets its verdict first and its vendor statement on the next run.
/// Providers whose files are not named by CVE (advisories covering several) are small and are read in full.
///
/// Resuming. The provider's index (changes.csv, or a ROLIE feed) says when each document last changed. A document is
/// due while the stored copy is older than that, while it was filtered for fewer products than are now wanted, or
/// after a failed fetch; <see cref="VexDocument"/> records this per document and is only updated in the same
/// transaction that stores the statements. A run takes at most <see cref="MaxDocumentsPerRun"/> documents per provider
/// and asks to be run again on the next pass when more are due, so there is no date cursor that could step over
/// unfinished or failed work. The cursor shown on the Sources page is a summary: the newest change every wanted
/// document is stored up to, held at the oldest unfinished one.
/// </summary>
public sealed class CsafVexFeed : IFeed
{
    public const string FeedName = "vex";

    public string Name => FeedName;
    public string DisplayName => "Vendor VEX statements (CSAF)";
    public int IntervalMinutes => 360;
    public string Licence => "Each vendor's CSAF terms (Red Hat: CC BY 4.0). Statements for installed products are stored with a link to the vendor's document; documents are not redistributed.";

    /// <summary>Documents fetched per provider per run; the rest wait for the next pass.</summary>
    public int MaxDocumentsPerRun { get; init; } = 150;
    /// <summary>This many failures in a row with nothing fetched means the provider is down: stop asking until the next run.</summary>
    public int GiveUpAfterFailures { get; init; } = 5;

    /// <summary>One line of a provider's index: the document, where it is, and when it last changed.</summary>
    public sealed record IndexEntry(string Path, string Url, DateTime Changed);

    /// <summary>What the watchlist and inventory hold of one provider's vendors.</summary>
    private sealed class Estate
    {
        public bool Any;
        /// <summary>CVE to the normalised names of the products it has verdicts against.</summary>
        public readonly Dictionary<string, HashSet<string>> ProductsByCve = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed record ProviderRun(int Statements, bool Unfinished, bool More, DateTime? Through, string Note);

    public async Task<FeedResult> RunAsync(FeedContext ctx, CancellationToken ct)
    {
        var setting = await ctx.Db.Settings.AsNoTracking().Where(s => s.Key == VexProviders.SettingKey).Select(s => s.Value).FirstOrDefaultAsync(ct);
        var providers = VexProviders.Parse(setting).Where(p => p.Enabled).ToList();
        if (providers.Count == 0) return new FeedResult(0, ctx.Cursor, "no VEX providers are switched on");

        var total = 0; var more = false;
        var cursor = new List<string>(); var notes = new List<string>(); var errors = new List<string>();
        var called = 0;
        foreach (var p in providers)
        {
            ct.ThrowIfCancellationRequested();
            var estate = await EstateAsync(ctx.Db, p, ct);
            if (!estate.Any) { notes.Add(p.Name + ": none of its products are in the watchlist or inventory, not called"); continue; }
            called++;
            try
            {
                ctx.Progress(p.Name + ": reading the index");
                var run = await RunProviderAsync(ctx, p, estate, ct);
                total += run.Statements;
                more |= run.More;
                notes.Add(p.Name + ": " + run.Note);
                if (run.Through is { } through)
                    cursor.Add(p.Id + ":" + (run.Unfinished ? "held " : "") + through.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture));
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                ctx.Db.ChangeTracker.Clear();
                ctx.Log.LogWarning(ex, "VEX provider {Provider} failed; its stored statements are kept", p.Id);
                errors.Add(p.Name + ": " + ex.Message);
            }
        }
        // every provider that was asked failed: the feed failed. Some failed: say so, and keep what the others gave.
        if (errors.Count > 0 && errors.Count == called) throw new InvalidOperationException(string.Join("; ", errors));
        notes.AddRange(errors.Select(e => "failed, will retry: " + e));
        var note = string.Join("; ", notes);
        var cursorText = cursor.Count == 0 ? ctx.Cursor : string.Join(" ", cursor);
        return new FeedResult(total, PsirtStore.TruncOrNull(cursorText, 256), note.Length > 250 ? note[..250] : note, more);
    }

    // ------------------------------------------------------------------ what is installed

    /// <summary>
    /// The provider's share of the estate: whether any watchlist entry or inventory item is one of its vendors' products,
    /// and for each CVE with a verdict against such a product, the product names. Closed verdicts count too: a statement
    /// can still be evidence, and a re-opened verdict should not wait a run for it.
    /// </summary>
    private static async Task<Estate> EstateAsync(VvDbContext db, VexProvider p, CancellationToken ct)
    {
        var estate = new Estate();
        void Want(string cve, params string?[] names)
        {
            var set = estate.ProductsByCve.TryGetValue(cve, out var s) ? s : estate.ProductsByCve[cve] = new(StringComparer.Ordinal);
            foreach (var n in names) if (Normalizer.Norm(n) is { Length: > 0 } norm) set.Add(norm);
        }

        var entries = (await db.Watchlist.AsNoTracking().Where(w => w.Enabled).Select(w => new { w.Id, w.Vendor, w.Product, w.VendorNorm }).ToListAsync(ct))
            .Where(w => p.SpeaksFor(w.Vendor) || p.SpeaksFor(w.VendorNorm)).ToDictionary(w => w.Id);
        if (entries.Count > 0)
        {
            estate.Any = true;
            var verdicts = await db.Verdicts.AsNoTracking().Where(v => v.WatchlistEntryId != null).Select(v => new { v.WatchlistEntryId, v.CveId }).ToListAsync(ct);
            foreach (var v in verdicts)
                if (entries.TryGetValue(v.WatchlistEntryId!.Value, out var w)) Want(v.CveId, w.Product);
        }

        // inventory: the distinct vendor and ecosystem spellings first, so only the provider's own software is joined to verdicts
        var kinds = (await db.Software.AsNoTracking().Select(s => new { s.Vendor, s.MappedVendorNorm, s.Ecosystem }).Distinct().ToListAsync(ct))
            .Where(k => p.SpeaksFor(k.Vendor, k.Ecosystem) || p.SpeaksFor(k.MappedVendorNorm)).ToList();
        if (kinds.Count == 0) return estate;
        estate.Any = true;
        var vendors = kinds.Select(k => k.Vendor).Distinct().ToList();
        var mapped = kinds.Where(k => k.MappedVendorNorm is not null).Select(k => k.MappedVendorNorm!).Distinct().ToList();
        foreach (var chunk in vendors.Chunk(200))
        {
            var rows = await (from v in db.Verdicts.AsNoTracking()
                              join s in db.Software.AsNoTracking() on v.SoftwareInstanceId equals (Guid?)s.Id
                              where chunk.Contains(s.Vendor) || (s.MappedVendorNorm != null && mapped.Contains(s.MappedVendorNorm))
                              select new { v.CveId, s.Vendor, s.Product, s.MappedVendorNorm, s.MappedProductNorm, s.Ecosystem }).Distinct().ToListAsync(ct);
            foreach (var r in rows)
                if (p.SpeaksFor(r.Vendor, r.Ecosystem) || p.SpeaksFor(r.MappedVendorNorm)) Want(r.CveId, r.Product, r.MappedProductNorm);
        }
        return estate;
    }

    /// <summary>
    /// True when a statement about <paramref name="productNorm"/> is worth keeping for these wanted products: the same name,
    /// or one containing the other ("openssl" keeps "openssl-libs"), which the evaluator shows as evidence only.
    /// </summary>
    public static bool Relevant(IEnumerable<string> wanted, string productNorm)
    {
        foreach (var w in wanted)
        {
            if (w == productNorm) return true;
            if (w.Length >= 4 && productNorm.Length >= 4 && (productNorm.Contains(w, StringComparison.Ordinal) || w.Contains(productNorm, StringComparison.Ordinal))) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------ one provider

    private async Task<ProviderRun> RunProviderAsync(FeedContext ctx, VexProvider p, Estate estate, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var index = await ReadIndexAsync(ctx.Http, p, ct);
        if (index.Count == 0) throw new InvalidOperationException("the provider's index lists no documents");

        var stored = await ctx.Db.VexDocuments.AsNoTracking().Where(d => d.Provider == p.Id).ToDictionaryAsync(d => d.Path, ct);

        // documents the provider no longer lists: their statements go, so a withdrawn not-affected stops applying. An index
        // that has lost more than half of what is stored is a bad download, not a clean-up: refused.
        var gone = stored.Values.Where(d => !index.ContainsKey(d.Path)).ToList();
        if (stored.Count >= SignalStore.ShrinkGuardMin && gone.Count > stored.Count / 2.0)
            throw new InvalidOperationException($"the index no longer lists {gone.Count} of {stored.Count} stored documents; not removing them");
        foreach (var d in gone) await RemoveAsync(ctx.Db, p.Id, d, ct);

        var due = new List<(IndexEntry Entry, string Scope, HashSet<string>? Wanted, VexDocument? Doc)>();
        DateTime? newest = null;
        foreach (var e in index.Values)
        {
            HashSet<string>? wanted = null;
            if (CveInPath(e.Path) is { } cve && !estate.ProductsByCve.TryGetValue(cve, out wanted)) continue;
            if (newest is null || e.Changed > newest) newest = e.Changed;
            var scope = wanted is null ? "*" : string.Join('|', wanted.OrderBy(w => w, StringComparer.Ordinal));
            var doc = stored.GetValueOrDefault(e.Path);
            if (doc?.ChangedAt is { } at && at >= e.Changed && Covers(doc.Scope, wanted)) continue;
            due.Add((e, scope, wanted, doc));
        }

        // untried documents first, newest change first; ones that failed before go last so they cannot starve the rest
        var batch = due.OrderBy(d => d.Doc?.Attempts ?? 0).ThenByDescending(d => d.Entry.Changed).Take(MaxDocumentsPerRun).ToList();
        int statements = 0, fetched = 0, failed = 0, failedInARow = 0;
        var unfinished = due.Select(d => d.Entry.Path).ToHashSet(StringComparer.Ordinal);
        var gaveUp = false;
        string? lastError = null;
        foreach (var (entry, scope, wanted, _) in batch)
        {
            ct.ThrowIfCancellationRequested();
            ctx.Progress($"{p.Name}: document {fetched + failed + 1} of {batch.Count}" + (due.Count > batch.Count ? $" ({due.Count} due)" : ""));
            try
            {
                CsafDocument parsed;
                using (var json = await PsirtStore.GetJsonAsync(ctx.Http, entry.Url, ct))
                    parsed = CsafVexParser.Parse(json.RootElement, p.Id, p.Name, entry.Url, now, wanted is null ? null : n => Relevant(wanted, n));
                statements += await StoreAsync(ctx.Db, p.Id, entry, scope, parsed, now, ct);
                unfinished.Remove(entry.Path);
                fetched++; failedInARow = 0;
            }
            catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
            {
                ctx.Db.ChangeTracker.Clear();
                failed++; failedInARow++;
                lastError = ex.Message;
                ctx.Log.LogWarning("VEX document {Url} failed and will be retried: {Error}", entry.Url, ex.Message);
                await RecordFailureAsync(ctx.Db, p.Id, entry, ex.Message, ct);
                if (fetched == 0 && failedInARow >= GiveUpAfterFailures) { gaveUp = true; break; }
            }
        }

        // held at the oldest change not yet stored; with nothing outstanding, the newest change in the index that matters here
        var through = unfinished.Count == 0 ? newest : due.Where(d => unfinished.Contains(d.Entry.Path)).Min(d => d.Entry.Changed);
        var pending = due.Count - fetched - failed;
        var note = fetched + " document" + (fetched == 1 ? "" : "s") + " read, " + statements + " statement" + (statements == 1 ? "" : "s") + " kept"
            + (pending > 0 ? ", " + pending + " more due" : "")
            + (failed > 0 ? ", " + failed + " failed and will be retried (" + PsirtStore.Trunc(lastError, 80) + ")" : "")
            + (gone.Count > 0 ? ", " + gone.Count + " withdrawn" : "");
        // more is due and the provider answers: next pass. A provider that is down waits for the next scheduled run.
        return new ProviderRun(statements, unfinished.Count > 0, pending > 0 && !gaveUp, through, note);
    }

    private static bool Covers(string storedScope, HashSet<string>? wanted)
    {
        if (storedScope == "*") return true;
        if (wanted is null) return false;
        var have = storedScope.Split('|', StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.Ordinal);
        return wanted.IsSubsetOf(have);
    }

    /// <summary>The CVE a per-CVE file is named after ("2024/cve-2024-6387.json", "msrc_cve-2026-1234.json"), or null.</summary>
    public static string? CveInPath(string path)
    {
        var slash = path.LastIndexOf('/');
        return Normalizer.ExtractCveIds(slash >= 0 ? path[(slash + 1)..] : path).FirstOrDefault();
    }

    /// <summary>Replace the document's statements and record the revision, in one transaction: either both happen or neither.</summary>
    private static async Task<int> StoreAsync(VvDbContext db, string provider, IndexEntry entry, string scope, CsafDocument parsed, DateTime now, CancellationToken ct)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        var doc = await db.VexDocuments.FirstOrDefaultAsync(d => d.Provider == provider && d.Path == entry.Path, ct);
        if (doc is null) { doc = new VexDocument { Provider = provider, Path = entry.Path }; db.VexDocuments.Add(doc); }
        var ids = new[] { parsed.DocumentId, doc.DocumentId ?? parsed.DocumentId };
        await db.VexStatements.Where(s => s.Provider == provider && ids.Contains(s.DocumentId)).ExecuteDeleteAsync(ct);
        db.VexStatements.AddRange(parsed.Statements);
        doc.CveId = CveInPath(entry.Path); doc.DocumentId = parsed.DocumentId; doc.ChangedAt = entry.Changed; doc.FetchedAt = now;
        doc.Scope = scope; doc.Statements = parsed.Statements.Count; doc.Attempts = 0; doc.LastError = null;
        await db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        db.ChangeTracker.Clear();
        return parsed.Statements.Count;
    }

    /// <summary>A failed fetch leaves ChangedAt and the stored statements alone, so the document stays due.</summary>
    private static async Task RecordFailureAsync(VvDbContext db, string provider, IndexEntry entry, string error, CancellationToken ct)
    {
        var doc = await db.VexDocuments.FirstOrDefaultAsync(d => d.Provider == provider && d.Path == entry.Path, ct);
        if (doc is null) { doc = new VexDocument { Provider = provider, Path = entry.Path, CveId = CveInPath(entry.Path) }; db.VexDocuments.Add(doc); }
        doc.Attempts++; doc.LastError = PsirtStore.Trunc(error, 500);
        await db.SaveChangesAsync(ct);
        db.ChangeTracker.Clear();
    }

    private static async Task RemoveAsync(VvDbContext db, string provider, VexDocument d, CancellationToken ct)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        if (d.DocumentId is { } id) await db.VexStatements.Where(s => s.Provider == provider && s.DocumentId == id).ExecuteDeleteAsync(ct);
        await db.VexDocuments.Where(x => x.Id == d.Id).ExecuteDeleteAsync(ct);
        await tx.CommitAsync(ct);
    }

    // ------------------------------------------------------------------ the provider's index

    /// <summary>
    /// The provider's list of documents and when each last changed. A directory URL is read through its changes.csv
    /// (less anything deletions.csv says was removed since); a provider-metadata.json is followed to its VEX directory
    /// or its ROLIE feeds; any other .json URL is read as a ROLIE feed.
    /// </summary>
    public static async Task<Dictionary<string, IndexEntry>> ReadIndexAsync(HttpClient http, VexProvider p, CancellationToken ct)
    {
        var url = p.Url.Trim();
        if (url.EndsWith("provider-metadata.json", StringComparison.OrdinalIgnoreCase))
        {
            using var meta = await PsirtStore.GetJsonAsync(http, url, ct);
            var (directories, feeds) = Distributions(meta.RootElement);
            var want = string.IsNullOrWhiteSpace(p.Distribution) ? "vex" : p.Distribution;
            var directory = directories.FirstOrDefault(d => d.Contains(want, StringComparison.OrdinalIgnoreCase)) ?? (feeds.Count == 0 ? directories.FirstOrDefault() : null);
            if (directory is not null) return await ReadDirectoryAsync(http, directory, ct);
            if (feeds.Count == 0) throw new InvalidOperationException("provider-metadata.json lists no distribution");
            var all = new Dictionary<string, IndexEntry>(StringComparer.Ordinal);
            foreach (var feed in feeds)
                foreach (var e in await ReadRolieAsync(http, feed, ct)) all[e.Path] = e;
            return all;
        }
        if (url.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            return (await ReadRolieAsync(http, url, ct)).ToDictionary(e => e.Path, StringComparer.Ordinal);
        return await ReadDirectoryAsync(http, url, ct);
    }

    /// <summary>directory_url values and ROLIE feed URLs from a provider-metadata.json.</summary>
    public static (List<string> Directories, List<string> Feeds) Distributions(JsonElement meta)
    {
        var directories = new List<string>(); var feeds = new List<string>();
        foreach (var d in PsirtStore.Arr(meta, "distributions"))
        {
            if (PsirtStore.Str(d, "directory_url") is { Length: > 0 } dir) directories.Add(dir);
            if (d.ValueKind == JsonValueKind.Object && d.TryGetProperty("rolie", out var rolie))
                foreach (var f in PsirtStore.Arr(rolie, "feeds"))
                    if (PsirtStore.Str(f, "url") is { Length: > 0 } u) feeds.Add(u);
        }
        return (directories, feeds);
    }

    private static async Task<Dictionary<string, IndexEntry>> ReadDirectoryAsync(HttpClient http, string directory, CancellationToken ct)
    {
        var baseUrl = directory.TrimEnd('/') + "/";
        var index = new Dictionary<string, IndexEntry>(StringComparer.Ordinal);
        foreach (var (path, changed) in ParseChanges(await http.GetStringAsync(baseUrl + "changes.csv", ct)))
            if (!index.TryGetValue(path, out var have) || changed > have.Changed) index[path] = new IndexEntry(path, baseUrl + path, changed);

        // deletions.csv is a Red Hat extension; most providers have none
        using var resp = await http.GetAsync(baseUrl + "deletions.csv", ct);
        if (resp.IsSuccessStatusCode)
            foreach (var (path, deleted) in ParseChanges(await resp.Content.ReadAsStringAsync(ct)))
                if (index.TryGetValue(path, out var e) && deleted >= e.Changed) index.Remove(path);
        return index;
    }

    /// <summary>Rows of changes.csv: "2024/cve-2024-6387.json","2026-09-01T11:07:00+00:00". Rows that do not read as that are skipped.</summary>
    public static IEnumerable<(string Path, DateTime Changed)> ParseChanges(string csv)
    {
        using var reader = new StringReader(csv);
        foreach (var row in Csv.Read(reader))
        {
            if (row.Length < 2 || !row[0].EndsWith(".json", StringComparison.OrdinalIgnoreCase) || row[0].Contains("..")) continue;
            if (PsirtStore.ParseDate(row[1]) is { } changed) yield return (row[0].Trim().TrimStart('/'), changed);
        }
    }

    /// <summary>Entries of a ROLIE feed: the document URL (content.src) and its updated time.</summary>
    public static async Task<List<IndexEntry>> ReadRolieAsync(HttpClient http, string feedUrl, CancellationToken ct)
    {
        using var doc = await PsirtStore.GetJsonAsync(http, feedUrl, ct);
        return ParseRolie(doc.RootElement);
    }

    public static List<IndexEntry> ParseRolie(JsonElement root)
    {
        var list = new List<IndexEntry>();
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("feed", out var feed)) return list;
        foreach (var e in PsirtStore.Arr(feed, "entry"))
        {
            var src = e.TryGetProperty("content", out var c) ? PsirtStore.Str(c, "src") : null;
            var updated = PsirtStore.ParseDate(PsirtStore.Str(e, "updated")) ?? PsirtStore.ParseDate(PsirtStore.Str(e, "published"));
            if (src is null || updated is null || !Uri.TryCreate(src, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps) continue;
            list.Add(new IndexEntry(PsirtStore.Trunc(src, 400), src, updated.Value));
        }
        return list;
    }
}
