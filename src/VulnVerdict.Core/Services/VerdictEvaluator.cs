using System.Diagnostics;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;

namespace VulnVerdict.Core.Services;

public sealed record EvaluationSummary(int Entries, int Candidates, int Created, int Changed, int Removed, TimeSpan Elapsed);

/// <summary>
/// For every subject (watchlist entries and mapped software instances on live assets): finds candidate CVEs by
/// normalised vendor/product (or OSV for packages), evaluates the version range, computes the four SSVC-derived
/// inputs, applies compensating-control modifiers, runs the decision table and stores a verdict with its evidence
/// chain. Tier changes are recorded with a reason; a fixed version observed in inventory closes the verdict
/// automatically.
/// </summary>
public sealed partial class VerdictEvaluator
{
    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly SettingsService _settings;
    private readonly IServiceProvider _sp;
    private readonly WebhookService _webhooks;
    private readonly ILogger<VerdictEvaluator> _log;

    public VerdictEvaluator(IDbContextFactory<VvDbContext> factory, SettingsService settings, IServiceProvider sp, WebhookService webhooks, ILogger<VerdictEvaluator> log)
    {
        _factory = factory; _settings = settings; _sp = sp; _webhooks = webhooks; _log = log;
    }

    /// <summary>
    /// State key holding the subjects the last run could not evaluate (OSV down, a write that collided) and when to
    /// try them again: JSON <see cref="FailedSubjects"/>, null when every subject evaluated.
    /// </summary>
    public const string FailedSubjectsKey = "state:evaluate:failed";
    /// <summary>How long failed subjects wait before <see cref="RetryFailedAsync"/> tries them again.</summary>
    public static readonly TimeSpan RetryAfter = TimeSpan.FromMinutes(15);

    public sealed record FailedSubjects(DateTime RetryAt, List<Guid> Entries, List<Guid> Software);

    public async Task<EvaluationSummary> EvaluateAllAsync(CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        await using var db = await _factory.CreateDbContextAsync(ct);
        var settings = await _settings.LoadAsync(ct);
        var subjects = await LoadSubjectsAsync(db, null, ct);
        var run = new RunCache();
        await PrefetchPackagesAsync(db, subjects, run, ct);
        var (total, failed) = await EvaluateEachAsync(db, subjects, settings, run, ct);
        var removed = total.Removed + await CloseGoneAsync(db, ct);
        await MaintainStatesAsync(db, ct);
        // a run with failures still counts as a run: the failed subjects are retried on their own, not the whole run
        // every minute
        await _settings.SetStateAsync(SettingsService.Keys.LastEvaluation, DateTime.UtcNow.ToString("O"), ct);
        await RecordFailedAsync(failed, ct);
        var summary = total with { Removed = removed, Elapsed = sw.Elapsed };
        _log.LogInformation("Evaluated {Entries} subjects: {Candidates} candidates, {Created} new, {Changed} changed, {Removed} removed, {Failed} failed in {Elapsed}", summary.Entries, summary.Candidates, summary.Created, summary.Changed, summary.Removed, failed.Count, summary.Elapsed);
        return summary;
    }

    public async Task<EvaluationSummary> EvaluateEntryAsync(Guid entryId, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        await using var db = await _factory.CreateDbContextAsync(ct);
        var settings = await _settings.LoadAsync(ct);
        var subjects = await LoadSubjectsAsync(db, entryId, ct);
        var (total, _) = await EvaluateEachAsync(db, subjects, settings, new RunCache(), ct);
        if (subjects.Count == 0) await db.Verdicts.Where(v => v.WatchlistEntryId == entryId).ExecuteDeleteAsync(ct);
        await MaintainStatesAsync(db, ct);
        return total with { Elapsed = sw.Elapsed };
    }

    /// <summary>
    /// Evaluates the subjects the last run could not, once their retry time has come. Returns null when there was
    /// nothing due. Anything that fails again waits another <see cref="RetryAfter"/>.
    /// </summary>
    public async Task<EvaluationSummary?> RetryFailedAsync(CancellationToken ct = default)
    {
        var json = await _settings.GetStateAsync(FailedSubjectsKey, ct);
        FailedSubjects? due = null;
        try { if (json is not null) due = JsonSerializer.Deserialize<FailedSubjects>(json); } catch (JsonException) { }
        if (due is null) { if (json is not null) await _settings.SetStateAsync(FailedSubjectsKey, null, ct); return null; }
        if (DateTime.UtcNow < due.RetryAt) return null;

        var sw = Stopwatch.StartNew();
        await using var db = await _factory.CreateDbContextAsync(ct);
        var settings = await _settings.LoadAsync(ct);
        var entries = due.Entries.ToHashSet(); var software = due.Software.ToHashSet();
        var subjects = (await LoadSubjectsAsync(db, null, ct))
            .Where(s => (s.WatchlistEntryId is { } e && entries.Contains(e)) || (s.SoftwareInstanceId is { } i && software.Contains(i))).ToList();
        var run = new RunCache();
        await PrefetchPackagesAsync(db, subjects, run, ct);
        var (total, failed) = await EvaluateEachAsync(db, subjects, settings, run, ct);
        await RecordFailedAsync(failed, ct);
        _log.LogInformation("Retried {Entries} subjects that failed last run: {Failed} failed again", subjects.Count, failed.Count);
        return total with { Elapsed = sw.Elapsed };
    }

    private Task RecordFailedAsync(List<Subject> failed, CancellationToken ct) =>
        _settings.SetStateAsync(FailedSubjectsKey, failed.Count == 0 ? null : JsonSerializer.Serialize(new FailedSubjects(DateTime.UtcNow + RetryAfter,
            failed.Where(s => s.WatchlistEntryId is not null).Select(s => s.WatchlistEntryId!.Value).ToList(),
            failed.Where(s => s.SoftwareInstanceId is not null).Select(s => s.SoftwareInstanceId!.Value).ToList())), ct);

    /// <summary>
    /// Evaluates each subject on its own: one that fails (OSV unreachable with nothing cached, a database error) is
    /// logged and returned in the failed list, and the run carries on with the next. A unique-index collision (the
    /// web saving a watchlist entry while the worker evaluates it) is retried once, when the other writer's verdict
    /// is there to update.
    /// </summary>
    private async Task<(EvaluationSummary Total, List<Subject> Failed)> EvaluateEachAsync(VvDbContext db, List<Subject> subjects, AppSettings settings, RunCache run, CancellationToken ct)
    {
        var total = new EvaluationSummary(subjects.Count, 0, 0, 0, 0, TimeSpan.Zero);
        var failed = new List<Subject>();
        foreach (var s in subjects)
        {
            ct.ThrowIfCancellationRequested();
            EvaluationSummary? r = null;
            for (var attempt = 1; r is null; attempt++)
            {
                try { r = await EvaluateSubjectAsync(db, s, settings, run, ct); }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (DbUpdateException ex) when (attempt == 1)
                {
                    db.ChangeTracker.Clear();
                    _log.LogInformation(ex, "Verdicts for {Subject} were written by another process meanwhile; evaluating it again", s.Display);
                }
                catch (Exception ex)
                {
                    db.ChangeTracker.Clear();
                    if (ex is PackageDataUnavailableException) _log.LogWarning("Skipped {Subject}: {Reason}", s.Display, ex.Message);
                    else _log.LogError(ex, "Evaluating {Subject} failed; carrying on with the rest", s.Display);
                    failed.Add(s);
                    break;
                }
            }
            if (r is null) continue;
            total = total with { Candidates = total.Candidates + r.Candidates, Created = total.Created + r.Created, Changed = total.Changed + r.Changed, Removed = total.Removed + r.Removed };
        }
        return (total, failed);
    }

    // ------------------------------------------------------------------ subjects

    private static async Task<List<Subject>> LoadSubjectsAsync(VvDbContext db, Guid? onlyEntry, CancellationToken ct)
    {
        var list = new List<Subject>();
        var entries = await db.Watchlist.AsNoTracking().Where(w => w.Enabled && (onlyEntry == null || w.Id == onlyEntry)).ToListAsync(ct);
        foreach (var e in entries)
            list.Add(new Subject(e.Vendor, e.Product, e.Version, e.AssetName, e.Exposure, e.Criticality, WatchlistEntryId: e.Id, DeclaredAt: e.UpdatedAt));
        if (onlyEntry is not null) return list;

        var staleBefore = DateTime.UtcNow.AddDays(-30);
        var software = await db.Software.AsNoTracking().Include(s => s.Asset)
            .Where(s => s.Asset != null && !s.Asset.Archived && s.Asset.LastSeen >= staleBefore
                        && (s.MappingStatus == MappingStatus.Exact || s.MappingStatus == MappingStatus.Alias || s.MappingStatus == MappingStatus.Fuzzy || s.MappingStatus == MappingStatus.Package))
            .ToListAsync(ct);
        foreach (var s in software)
        {
            var a = s.Asset!;
            list.Add(new Subject(s.Vendor, s.Product, s.Version == "" ? null : s.Version, a.DisplayName, a.Exposure, a.Criticality,
                SoftwareInstanceId: s.Id, AssetId: a.Id, MappedVendorNorm: s.MappedVendorNorm, MappedProductNorm: s.MappedProductNorm,
                ProductConfidence: s.MappingStatus == MappingStatus.Fuzzy ? MatchConfidence.Likely : MatchConfidence.Exact,
                FeatureDisabled: !s.Enabled, Purl: s.Purl, Ecosystem: s.Ecosystem, DeclaredAt: s.LastSeen));
        }
        return list;
    }

    // ------------------------------------------------------------------ candidates

    private sealed record ProductMatch(CveAffected? Row, string CveId, MatchConfidence Confidence, string How, PackageVuln? Package = null);

    private static readonly TimeSpan PackageCacheTtl = TimeSpan.FromHours(24);

    private static bool IsPackage(Subject s) => s.SoftwareInstanceId is not null && (s.Purl is not null || s.Ecosystem is not null);
    private static PackageQuery PackageQueryFor(Subject s) =>
        new((s.Purl ?? s.Ecosystem + "/" + s.Product) + "@" + s.Version, s.Ecosystem ?? "", s.Product, s.Version ?? "", s.Purl);

    /// <summary>A package subject OSV could not answer for, with nothing cached to fall back on: skipped, not emptied.</summary>
    private sealed class PackageDataUnavailableException(string message, Exception? inner = null) : Exception(message, inner);

    /// <summary>Fed by signed bundles (air-gapped, or the central service): OSV is never called, cached results only.</summary>
    private async Task<bool> OfflineAsync(RunCache run, CancellationToken ct)
    {
        if (run.Offline is { } known) return known;
        var bundles = _sp.GetService<BundleService>();
        run.Offline = bundles is not null && await bundles.IsBundleModeAsync(ct);
        return run.Offline.Value;
    }

    /// <summary>
    /// One OSV batch for every package whose cached result is missing or older than a day, written to the cache before
    /// the subjects are evaluated. If OSV fails the run carries on from the cache and marks OSV unavailable.
    /// </summary>
    private async Task PrefetchPackagesAsync(VvDbContext db, List<Subject> subjects, RunCache run, CancellationToken ct)
    {
        var queries = subjects.Where(IsPackage).Select(PackageQueryFor).DistinctBy(q => q.Key).ToList();
        if (queries.Count == 0 || _sp.GetService<IPackageVulnSource>() is not { } source || await OfflineAsync(run, ct)) return;
        var cutoff = DateTime.UtcNow - PackageCacheTtl;
        var fresh = new HashSet<string>();
        foreach (var chunk in queries.Select(q => q.Key).Chunk(400))
            fresh.UnionWith(await db.PackageVulns.AsNoTracking().Where(p => chunk.Contains(p.Key) && p.FetchedAt >= cutoff).Select(p => p.Key).ToListAsync(ct));
        var due = queries.Where(q => !fresh.Contains(q.Key)).ToList();
        if (due.Count == 0) return;

        IReadOnlyList<PackageVuln> found;
        try { found = await source.LookupAsync(due, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            run.OsvUnavailable = true;
            _log.LogWarning(ex, "OSV lookup for {Count} package(s) failed; using cached results where there are any", due.Count);
            return;
        }
        var byKey = found.GroupBy(v => v.Key).ToDictionary(g => g.Key, g => g.ToList());
        var now = DateTime.UtcNow;
        foreach (var chunk in due.Chunk(400))
        {
            var keys = chunk.Select(q => q.Key).ToList();
            var rows = await db.PackageVulns.Where(p => keys.Contains(p.Key)).ToDictionaryAsync(p => p.Key, ct);
            foreach (var q in chunk)
            {
                if (!rows.TryGetValue(q.Key, out var row)) { row = new PackageVulnCache { Key = q.Key }; db.PackageVulns.Add(row); }
                row.ResultJson = JsonSerializer.Serialize(byKey.GetValueOrDefault(q.Key) ?? new()); row.FetchedAt = now;
            }
            await db.SaveChangesAsync(ct);
            db.ChangeTracker.Clear();
        }
    }

    private async Task<List<ProductMatch>> FindCandidatesAsync(VvDbContext db, Subject s, RunCache run, CancellationToken ct)
    {
        var result = new List<ProductMatch>();

        // packages: OSV by purl or ecosystem + name
        if (IsPackage(s))
        {
            var source = _sp.GetService<IPackageVulnSource>();
            if (source is null) return result;
            var query = PackageQueryFor(s);
            var key = query.Key;
            var cached = await db.PackageVulns.AsNoTracking().FirstOrDefaultAsync(p => p.Key == key, ct);
            List<PackageVuln> Cached() => JsonSerializer.Deserialize<List<PackageVuln>>(cached!.ResultJson) ?? new();
            var offline = await OfflineAsync(run, ct);
            List<PackageVuln> vulns;
            if (cached is not null && (DateTime.UtcNow - cached.FetchedAt < PackageCacheTtl || offline || run.OsvUnavailable))
                vulns = Cached();
            else if (offline) vulns = new();   // bundle-fed: OSV is never asked, and there is nothing cached for it
            else if (run.OsvUnavailable) throw new PackageDataUnavailableException("OSV is unavailable and nothing is cached for " + key);
            else
            {
                try
                {
                    vulns = (await source.LookupAsync(new[] { query }, ct)).ToList();
                    var row = await db.PackageVulns.FirstOrDefaultAsync(p => p.Key == key, ct);
                    if (row is null) { row = new PackageVulnCache { Key = key }; db.PackageVulns.Add(row); }
                    row.ResultJson = JsonSerializer.Serialize(vulns); row.FetchedAt = DateTime.UtcNow;
                    await db.SaveChangesAsync(ct);
                }
                catch (Exception ex) when (ex is not DbUpdateException && (ex is not OperationCanceledException || !ct.IsCancellationRequested))
                {
                    run.OsvUnavailable = true;   // one failure is enough: the rest of the run does not wait on retries again
                    if (cached is null) throw new PackageDataUnavailableException("OSV lookup failed and nothing is cached for " + key + ": " + ex.Message, ex);
                    _log.LogWarning(ex, "OSV lookup for {Key} failed; using the result cached {At:u}", key, cached.FetchedAt);
                    vulns = Cached();
                }
            }
            foreach (var v in vulns) result.Add(new ProductMatch(null, v.CveId, MatchConfidence.Exact, "package " + (s.Purl ?? s.Ecosystem + " " + s.Product) + " " + s.Version + " is affected according to " + v.Source, v));
            return result;
        }

        var vn = s.VendorNorm; var pn = s.ProductNorm;
        if (string.IsNullOrEmpty(pn)) return result;

        if (!string.IsNullOrEmpty(vn))
        {
            var exact = await db.CveAffected.AsNoTracking().Where(a => a.VendorNorm == vn && a.ProductNorm == pn).ToListAsync(ct);
            result.AddRange(exact.Select(a => new ProductMatch(a, a.CveId, s.ProductConfidence, s.MappedProductNorm is null ? "vendor and product match exactly" : "mapped to " + a.Vendor + " / " + a.Product)));
            // Records whose CNA wrote "n/a" for the vendor but named the product ("n/a" / "BIG-IP"): the product
            // name is the whole match, so a step below exact.
            var unvendored = await db.CveAffected.AsNoTracking().Where(a => a.VendorNorm == "" && a.ProductNorm == pn).ToListAsync(ct);
            result.AddRange(unvendored.Select(a => new ProductMatch(a, a.CveId, MatchConfidence.Likely, "product name matches; the CVE record does not state a vendor")));
        }
        if (s.WatchlistEntryId is not null)
        {
            var aliases = await db.Aliases.AsNoTracking().Where(a => a.AliasNorm == pn || a.AliasNorm == vn + pn).ToListAsync(ct);
            foreach (var al in aliases)
            {
                var rows = await db.CveAffected.AsNoTracking().Where(a => a.VendorNorm == al.VendorNorm && a.ProductNorm == al.ProductNorm).ToListAsync(ct);
                result.AddRange(rows.Select(a => new ProductMatch(a, a.CveId, MatchConfidence.Exact, "alias '" + s.Product + "' maps to " + a.Vendor + " / " + a.Product)));
            }
            // Longer CNA product names that contain the entry's name are one of three things:
            //  - the same product written differently: "Fortinet FortiOS", or a list such as
            //    "Fortinet FortiOS, FortiProxy" — always a match;
            //  - another product from the same vendor: "Jenkins Azure CLI Plugin", "GitLab Runner",
            //    "FortiOS-6K7K" — never a match once the product has been found under its own name;
            //  - the only way the CNA names it: "Microsoft Exchange Server 2019 Cumulative Update 14" for
            //    an entry called "Exchange Server 2019" — the fallback when nothing matched exactly.
            if (!string.IsNullOrEmpty(vn) && pn.Length >= 5)
            {
                var foundByName = result.Count > 0;
                var contains = await db.CveAffected.AsNoTracking().Where(a => a.VendorNorm == vn && a.ProductNorm != pn && a.ProductNorm.Contains(pn)).ToListAsync(ct);
                foreach (var a in contains)
                {
                    if (NamesProduct(a.Product, vn, pn))
                        result.Add(new ProductMatch(a, a.CveId, MatchConfidence.Likely, "CNA product '" + a.Product + "' names '" + s.Product + "'"));
                    else if (!foundByName)
                        result.Add(new ProductMatch(a, a.CveId, MatchConfidence.Likely, "CNA product '" + a.Product + "' contains '" + s.Product + "'"));
                }
            }
            if (string.IsNullOrEmpty(vn))
            {
                var any = await db.CveAffected.AsNoTracking().Where(a => a.ProductNorm == pn).ToListAsync(ct);
                result.AddRange(any.Select(a => new ProductMatch(a, a.CveId, MatchConfidence.Possible, "product name matches, vendor not declared")));
            }
        }
        return result.DistinctBy(m => m.Row?.Id ?? (object)m.CveId).ToList();
    }

    /// <summary>
    /// True when a CNA product string names this product outright: on its own after a leading vendor
    /// name ("Fortinet FortiOS"), or as one item of a list ("Fortinet FortiOS, FortiProxy",
    /// "FortiOS and FortiProxy"). Normalised names in, so punctuation and case don't matter.
    /// </summary>
    internal static bool NamesProduct(string cnaProduct, string vendorNorm, string productNorm)
    {
        foreach (var part in ListSeparators().Split(cnaProduct))
        {
            var n = Normalizer.Norm(part);
            if (n.Length == 0) continue;
            if (n == productNorm) return true;
            if (vendorNorm.Length > 0 && n.StartsWith(vendorNorm, StringComparison.Ordinal) && n[vendorNorm.Length..] == productNorm) return true;
        }
        return false;
    }

    [System.Text.RegularExpressions.GeneratedRegex(@"\s*(?:,|;|/|&|\band\b)\s*", System.Text.RegularExpressions.RegexOptions.IgnoreCase)]
    private static partial System.Text.RegularExpressions.Regex ListSeparators();

    // ------------------------------------------------------------------ evaluation

    private async Task<EvaluationSummary> EvaluateSubjectAsync(VvDbContext db, Subject s, AppSettings settings, RunCache run, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        int created = 0, changed = 0, removed = 0;

        var existing = s.WatchlistEntryId is not null
            ? await db.Verdicts.Where(v => v.WatchlistEntryId == s.WatchlistEntryId).ToDictionaryAsync(v => v.CveId, ct)
            : await db.Verdicts.Where(v => v.SoftwareInstanceId == s.SoftwareInstanceId).ToDictionaryAsync(v => v.CveId, ct);

        var matches = await FindCandidatesAsync(db, s, run, ct);
        var byCve = matches.GroupBy(m => m.CveId).ToDictionary(g => g.Key, g => g.ToList());
        var ids = byCve.Keys.ToList();

        var cves = new Dictionary<string, Cve>();
        var kev = new Dictionary<string, KevEntry>();
        var epss = new Dictionary<string, EpssScore>();
        var signals = new Dictionary<string, List<ExploitSignal>>();
        foreach (var chunk in ids.Chunk(400))
        {
            foreach (var c in await db.Cves.AsNoTracking().Where(c => chunk.Contains(c.Id)).ToListAsync(ct)) cves[c.Id] = c;
            foreach (var k in await db.Kev.AsNoTracking().Where(k => chunk.Contains(k.CveId)).ToListAsync(ct)) kev[k.CveId] = k;
            foreach (var e in await db.Epss.AsNoTracking().Where(e => chunk.Contains(e.CveId)).ToListAsync(ct)) epss[e.CveId] = e;
            foreach (var sig in await db.ExploitSignals.AsNoTracking().Where(x => chunk.Contains(x.CveId)).ToListAsync(ct))
                (signals.TryGetValue(sig.CveId, out var l) ? l : signals[sig.CveId] = new()).Add(sig);
        }

        // vendor PSIRT advisories that mention any candidate CVE: evidence, and "exploited in the wild" = Active
        var advisories = new Dictionary<string, List<Advisory>>(StringComparer.OrdinalIgnoreCase);
        var vendorKey = AdvisoryVendor(s);
        if (ids.Count > 0 && vendorKey is not null)
        {
            if (vendorKey is "microsoft" or "ubuntu" or "redhat" or "debian")
            {
                // keyed by CVE or by package: a targeted query per subject
                var rows = new List<Advisory>();
                if (vendorKey == "debian")
                {
                    var suffix = ":" + s.Product;
                    rows.AddRange(await db.Advisories.AsNoTracking().Where(a => a.Vendor == "debian" && a.AdvisoryId.EndsWith(suffix)).ToListAsync(ct));
                }
                else
                    foreach (var chunk in ids.Chunk(400))
                        rows.AddRange(await db.Advisories.AsNoTracking().Where(a => a.Vendor == vendorKey && chunk.Contains(a.AdvisoryId)).ToListAsync(ct));
                var idSet = new HashSet<string>(ids, StringComparer.OrdinalIgnoreCase);
                foreach (var a in rows)
                    foreach (var id in Normalizer.ExtractCveIds(a.CveIdsJson).Distinct())
                        if (idSet.Contains(id)) (advisories.TryGetValue(id, out var l) ? l : advisories[id] = new()).Add(a);
            }
            else
            {
                // Fortinet, Cisco, VMware: the vendor's whole table, read and indexed by CVE once per run
                if (!run.AdvisoriesByVendor.TryGetValue(vendorKey, out var index))
                {
                    index = new(StringComparer.OrdinalIgnoreCase);
                    foreach (var a in await db.Advisories.AsNoTracking().Where(a => a.Vendor == vendorKey).ToListAsync(ct))
                        foreach (var id in Normalizer.ExtractCveIds(a.CveIdsJson).Distinct(StringComparer.OrdinalIgnoreCase))
                            (index.TryGetValue(id, out var l) ? l : index[id] = new()).Add(a);
                    run.AdvisoriesByVendor[vendorKey] = index;
                }
                foreach (var id in ids)
                    if (index.TryGetValue(id, out var l)) advisories[id] = l;
            }
        }

        var windowsTimeline = await TimelineAsync(db, run, s, ct);
        var officeTimeline = await OfficeTimelineAsync(db, run, s, ct);
        var rules = run.Rules ??= await db.Suppressions.AsNoTracking().ToListAsync(ct);
        var controls = await db.Controls.AsNoTracking()
            .Where(c => (c.Expiry == null || c.Expiry > now) && ((s.AssetId != null && c.AssetId == s.AssetId) || (s.WatchlistEntryId != null && c.WatchlistEntryId == s.WatchlistEntryId)))
            .ToListAsync(ct);
        controls = controls.Where(c => c.ProductNorm == null || c.ProductNorm == s.ProductNorm).ToList();
        var seen = new HashSet<string>();
        var events = new List<(string Event, Guid VerdictId)>();

        foreach (var (cveId, productMatches) in byCve)
        {
            var cve = cves.GetValueOrDefault(cveId);
            if (cve is not null && cve.State.Equals("REJECTED", StringComparison.OrdinalIgnoreCase)) continue;
            if (cve is null && productMatches.All(m => m.Package is null)) continue;
            seen.Add(cveId);

            var computed = Compute(s, cveId, cve, productMatches, kev.GetValueOrDefault(cveId), epss.GetValueOrDefault(cveId), signals.GetValueOrDefault(cveId) ?? new(), controls, advisories.GetValueOrDefault(cveId) ?? new(), now, windowsTimeline, officeTimeline);

            if (existing.TryGetValue(cveId, out var v))
            {
                if (Apply(v, computed, s, now, rules, settings, events)) changed++;
            }
            else
            {
                v = new Verdict { Id = Guid.NewGuid(), CveId = cveId, WatchlistEntryId = s.WatchlistEntryId, SoftwareInstanceId = s.SoftwareInstanceId, AssetId = s.AssetId, CreatedAt = now, State = VerdictState.Open };
                Apply(v, computed, s, now, rules, settings, events, isNew: true);
                if (cve is null) { db.Cves.Add(new Cve { Id = cveId, State = "PACKAGE", RetrievedAt = now, SourceRef = "osv", Title = cveId + " (from package advisory data)" }); cves[cveId] = new Cve { Id = cveId }; }
                db.Verdicts.Add(v);
                existing[cveId] = v;
                created++;
            }
        }

        // a CVE that no longer matches (the record was corrected, or the product was re-mapped) closes rather than
        // vanishing, so what was reported and what was done about it stays on record
        foreach (var v in existing.Values.Where(v => !seen.Contains(v.CveId) && IsOpenish(v.State)))
        {
            CloseAsGone(db, v, NoLongerMatches, now, events);
            removed++;
        }

        await db.SaveChangesAsync(ct);
        db.ChangeTracker.Clear();
        foreach (var (evt, id) in events) _webhooks.Enqueue(evt, id);
        return new EvaluationSummary(1, byCve.Count, created, changed, removed, TimeSpan.Zero);
    }

    private sealed record Computed(DecisionInputs Inputs, Decision Decision, MatchConfidence Confidence, bool VersionUnknown, string Sentence, string? FixedIn, List<EvidenceClaim> Evidence, double? Epss, bool InKev, CvssVector? Cvss, List<string> Modifiers);

    /// <summary>Which PSIRT feed speaks for this subject's vendor, if any.</summary>
    private static string? AdvisoryVendor(Subject s)
    {
        var v = s.VendorNorm; var eco = s.Ecosystem ?? "";
        if (eco.StartsWith("Ubuntu", StringComparison.OrdinalIgnoreCase)) return "ubuntu";
        if (eco.StartsWith("Debian", StringComparison.OrdinalIgnoreCase)) return "debian";
        if (eco.StartsWith("Red Hat", StringComparison.OrdinalIgnoreCase) || eco.StartsWith("RedHat", StringComparison.OrdinalIgnoreCase) || eco.StartsWith("AlmaLinux", StringComparison.OrdinalIgnoreCase) || eco.StartsWith("Rocky", StringComparison.OrdinalIgnoreCase)) return "redhat";
        if (v.StartsWith("microsoft")) return "microsoft";
        if (v.Contains("fortinet")) return "fortinet";
        if (v.Contains("cisco")) return "cisco";
        if (v.Contains("vmware") || v.Contains("broadcom")) return "vmware";
        return null;
    }

    /// <summary>
    /// The fixed build Microsoft's security update data gives for this subject's product ("10.0.14393.7070 (KB5041773)"
    /// for "Windows Server 2016"), or null. Only a build on the same release line counts: a Windows build is compared
    /// only with builds of the same release (10.0.14393.x), anything else only when the major version agrees.
    /// </summary>
    public static (string Product, string Build)? VendorFixedBuild(List<Advisory> advisories, Subject s)
    {
        if (s.Version is null || !VersionCompare.IsParseable(s.Version) || s.ProductNorm.Length < 4) return null;
        foreach (var adv in advisories.Where(a => a.Vendor == "microsoft" && a.AffectedJson is not null).OrderByDescending(a => a.Updated ?? a.Published))
        {
            JsonDocument doc;
            try { doc = JsonDocument.Parse(adv.AffectedJson!); } catch (JsonException) { continue; }
            using (doc)
            {
                if (doc.RootElement.ValueKind != JsonValueKind.Array) continue;
                foreach (var item in doc.RootElement.EnumerateArray())
                {
                    var product = item.TryGetProperty("product", out var p) ? p.GetString() ?? "" : "";
                    var pn = Normalizer.Norm(product);
                    if (pn.Length == 0 || !pn.StartsWith(s.ProductNorm, StringComparison.Ordinal)) continue;
                    var fix = item.TryGetProperty("fixedIn", out var f) ? f.GetString() : null;
                    var m = fix is null ? null : System.Text.RegularExpressions.Regex.Match(fix, @"^\s*\d+(?:\.\d+){2,}");
                    if (m is null || !m.Success || !SameReleaseLine(s.Version, m.Value.Trim())) continue;
                    return (product, m.Value.Trim());
                }
            }
        }
        return null;
    }

    private static bool SameReleaseLine(string installed, string build)
    {
        var a = installed.Split('.'); var b = build.Split('.');
        if (a[0] != b[0]) return false;
        if (a.Length >= 3 && b.Length >= 3 && a[0] == "10" && a[1] == "0") return b[1] == "0" && a[2] == b[2];
        return true;
    }

    /// <summary>
    /// What every subject in a run shares, read once per run: Microsoft's Windows and Office build history (only when a
    /// subject needs it), suppression rules, the whole-table vendor advisories indexed by CVE, and whether OSV may be asked.
    /// </summary>
    private sealed class RunCache
    {
        public bool Loaded; public WindowsBuildTimeline? Value; public bool OfficeLoaded; public OfficeBuildTimeline? Office;
        public List<SuppressionRule>? Rules;
        public readonly Dictionary<string, Dictionary<string, List<Advisory>>> AdvisoriesByVendor = new();
        public bool? Offline;
        public bool OsvUnavailable;
    }

    private static async Task<OfficeBuildTimeline?> OfficeTimelineAsync(VvDbContext db, RunCache holder, Subject s, CancellationToken ct)
    {
        if (!s.ProductNorm.StartsWith("microsoft365apps", StringComparison.Ordinal)) return null;
        if (!holder.OfficeLoaded)
        {
            holder.OfficeLoaded = true;
            var rows = await db.OfficeReleases.AsNoTracking().Select(r => new { r.Build, r.Revision, r.Version, r.Released }).ToListAsync(ct);
            holder.Office = rows.Count == 0 ? null : OfficeBuildTimeline.From(rows.Select(r => (r.Build, r.Revision, r.Version, r.Released)));
        }
        return holder.Office;
    }

    private static async Task<WindowsBuildTimeline?> TimelineAsync(VvDbContext db, RunCache holder, Subject s, CancellationToken ct)
    {
        if (!s.ProductNorm.StartsWith("windows", StringComparison.Ordinal) || AdvisoryVendor(s) != "microsoft") return null;
        if (!holder.Loaded)
        {
            holder.Loaded = true;
            var rows = await db.Advisories.AsNoTracking()
                .Where(a => a.Vendor == "microsoft" && a.AffectedJson != null && a.AffectedJson.Contains("\"fixedIn\":\"10.0."))
                .Select(a => new { a.Published, a.AffectedJson }).ToListAsync(ct);
            holder.Value = WindowsBuildTimeline.From(rows.Select(r => (r.Published, r.AffectedJson)));
        }
        return holder.Value;
    }

    /// <summary>
    /// The date Microsoft's advisory for this CVE says the subject's Windows edition was fixed by an update (a KB or a
    /// build is named for it), or null when Microsoft does not list the edition as fixed by an update. Opt-in fixes and
    /// records Microsoft never published an update for stay unresolved rather than being called patched.
    /// </summary>
    private static DateTime? WindowsFixDate(List<Advisory> advisories, Subject s, bool anyFix = false)
    {
        foreach (var adv in advisories.Where(a => a.Vendor == "microsoft" && a.Published is not null && a.AffectedJson is not null))
        {
            try
            {
                using var doc = JsonDocument.Parse(adv.AffectedJson!);
                if (doc.RootElement.ValueKind != JsonValueKind.Array) continue;
                foreach (var item in doc.RootElement.EnumerateArray())
                {
                    var pn = Normalizer.Norm(item.TryGetProperty("product", out var p) ? p.GetString() : null);
                    var fix = item.TryGetProperty("fixedIn", out var f) ? f.GetString() : null;
                    if (pn.StartsWith(s.ProductNorm, StringComparison.Ordinal) && !string.IsNullOrWhiteSpace(fix)
                        && (anyFix || fix.TrimStart().StartsWith("KB", StringComparison.OrdinalIgnoreCase) || char.IsDigit(fix.TrimStart()[0])))
                        return adv.Published;
                }
            }
            catch (JsonException) { }
        }
        return null;
    }

    private static Computed Compute(Subject s, string cveId, Cve? cve, List<ProductMatch> productMatches, KevEntry? kev, EpssScore? epss, List<ExploitSignal> signals, List<CompensatingControl> controls, List<Advisory> advisories, DateTime now, WindowsBuildTimeline? windowsTimeline = null, OfficeBuildTimeline? officeTimeline = null)
    {
        var ev = new List<EvidenceClaim>();
        var retrieved = cve?.RetrievedAt ?? now;
        var cnaSource = "CVE List V5, " + (cve?.Assigner ?? "CNA") + " container" + (cve?.SourceRef is null ? "" : " (" + cve.SourceRef + ")");
        var subjectSource = s.WatchlistEntryId is not null ? "Watchlist entry (declared by user)" : "Inventory (" + (s.AssetName ?? "asset") + ", last seen " + s.DeclaredAt.ToString("yyyy-MM-dd HH:mm") + "Z)";

        // ---- product and version match
        var best = productMatches.OrderByDescending(m => m.Confidence).First();
        var productConfidence = best.Confidence;
        VersionMatch overall = VersionMatch.NotAffected;
        var versionConfidence = MatchConfidence.Exact;
        string? fixedIn = null;
        var explanations = new List<string>();

        if (best.Package is not null)
        {
            ev.Add(new EvidenceClaim("Affected package: " + best.How, "OSV.dev", retrieved));
            overall = VersionMatch.Affected; fixedIn = best.Package.FixedIn;
            explanations.Add("package version " + s.Version + " is inside the advisory's affected range" + (fixedIn is null ? "" : ", fixed in " + fixedIn));
        }
        else
        {
            ev.Add(new EvidenceClaim("Affected product " + best.Row!.Vendor + " / " + best.Row.Product + ": " + best.How, cnaSource, retrieved));
            foreach (var m in productMatches.Where(m => m.Row is not null).OrderByDescending(m => m.Confidence))
            {
                var r = VersionMatcher.Evaluate(s.Version, VersionMatcher.ParseVersions(m.Row!.VersionsJson), m.Row.DefaultStatus);
                fixedIn ??= r.FixedIn;
                explanations.Add(r.Explanation);
                if (r.Match == VersionMatch.Affected) { overall = VersionMatch.Affected; versionConfidence = r.Confidence; fixedIn = r.FixedIn ?? fixedIn; break; }
                if (r.Match == VersionMatch.Unknown) { overall = VersionMatch.Unknown; versionConfidence = MatchConfidence.Possible; }
            }
        }
        // Microsoft often writes "10.0.0 < publication", or a web link, where the fixed build belongs. Its own security
        // update data names the fixed build for each product; when the CVE record cannot answer, that decides.
        var versionSource = best.Package is null ? cnaSource : "OSV.dev";
        if (overall == VersionMatch.Unknown && best.Package is null && VendorFixedBuild(advisories, s) is { } vendorFix)
        {
            var cmp = VersionCompare.Compare(s.Version, vendorFix.Build);
            if (cmp is not null)
            {
                overall = cmp < 0 ? VersionMatch.Affected : VersionMatch.NotAffected;
                versionConfidence = MatchConfidence.Likely;
                fixedIn = vendorFix.Build;
                explanations.Insert(0, "the CVE record gives no usable version range; Microsoft's security update data gives fixed build " + vendorFix.Build
                    + " for " + vendorFix.Product + ", and " + s.Version + (cmp < 0 ? " is older" : " is that build or later"));
                versionSource = "Microsoft Security Response Center (CVRF)";
            }
        }
        // Older advisories name only a KB. Windows updates are cumulative, so a build at least as new as one Microsoft
        // shipped on or after the fix date contains the fix. This only ever clears a verdict; it never calls one affected.
        if (overall == VersionMatch.Unknown && best.Package is null && windowsTimeline is not null && s.Version is { } installed
            && WindowsFixDate(advisories, s) is { } fixDate && windowsTimeline.FirstBuildOnOrAfter(installed, fixDate) is { } later
            && VersionCompare.Compare(installed, later.Build) is >= 0)
        {
            overall = VersionMatch.NotAffected;
            versionConfidence = MatchConfidence.Likely;
            explanations.Insert(0, "Windows updates are cumulative: Microsoft fixed this in the " + fixDate.ToString("MMMM yyyy") + " updates, build "
                + later.Build + " (" + later.Date.ToString("MMMM yyyy") + ") already includes that fix, and " + installed + " is that build or later");
            versionSource = "Microsoft Security Response Center (CVRF)";
        }
        // Microsoft 365 Apps: the record and Microsoft's own data give a link, not a build. The fix date from Microsoft's
        // advisory and the version's release history decide it, both ways.
        if (overall == VersionMatch.Unknown && best.Package is null && officeTimeline is not null && s.Version is { } officeInstalled
            && WindowsFixDate(advisories, s, anyFix: true) is { } officeFix && officeTimeline.Assess(officeInstalled, officeFix) is { } office)
        {
            overall = office.Affected ? VersionMatch.Affected : VersionMatch.NotAffected;
            versionConfidence = MatchConfidence.Likely;
            fixedIn = office.FixedBuild ?? fixedIn;
            explanations.Insert(0, office.Explanation);
            versionSource = "Microsoft Security Response Center and the Microsoft 365 Apps update history";
        }
        ev.Add(new EvidenceClaim("Version check: " + explanations.First(), versionSource, retrieved, best.Row?.VersionsJson is { Length: < 400 } vj ? vj : null));
        ev.Add(new EvidenceClaim((s.AssetName ?? s.Product) + " runs " + s.ProductText + " " + (s.Version ?? "(version not recorded)") + (s.FeatureDisabled ? " (disabled)" : ""), subjectSource, s.DeclaredAt == default ? now : s.DeclaredAt));

        var confidence = (MatchConfidence)Math.Min((int)productConfidence, (int)versionConfidence);
        var versionUnknown = overall == VersionMatch.Unknown;

        // ---- exploitation
        var exploitation = Exploitation.None;
        if (kev is not null)
        {
            exploitation = Exploitation.Active;
            ev.Add(new EvidenceClaim("Listed in CISA Known Exploited Vulnerabilities since " + kev.DateAdded.ToString("yyyy-MM-dd") + (kev.KnownRansomwareUse == "Known" ? ", known ransomware use" : ""), "CISA KEV", kev.RetrievedAt, kev.RequiredAction));
        }
        else if (string.Equals(cve?.SsvcExploitation, "active", StringComparison.OrdinalIgnoreCase))
        {
            exploitation = Exploitation.Active;
            ev.Add(new EvidenceClaim("CISA Vulnrichment SSVC Exploitation: active", "CISA ADP container in CVE List V5", retrieved));
        }
        // vendor advisories: the vendor's own affected/fixed statement and "exploited in the wild". Evidence from the two
        // latest; the exploitation signal from any of them, with its own line when it is in an older one.
        var latest = advisories.OrderByDescending(a => a.Updated ?? a.Published).Take(2).ToList();
        foreach (var adv in latest)
        {
            string? fixText = null;
            try
            {
                if (adv.AffectedJson is not null)
                {
                    using var doc = JsonDocument.Parse(adv.AffectedJson);
                    foreach (var item in doc.RootElement.EnumerateArray())
                    {
                        var product = item.TryGetProperty("product", out var p) ? p.GetString() ?? "" : "";
                        var pn = Normalizer.Norm(product);
                        if (pn.Length > 0 && (pn.Contains(s.ProductNorm) || s.ProductNorm.Contains(pn)))
                        {
                            var aff = item.TryGetProperty("affected", out var af) ? af.GetString() : null;
                            var fix = item.TryGetProperty("fixedIn", out var fi) ? fi.GetString() : null;
                            fixText = (string.IsNullOrWhiteSpace(aff) ? "" : "affected " + aff + "; ") + (string.IsNullOrWhiteSpace(fix) ? "" : "fixed in " + fix);
                            if (fixedIn is null && !string.IsNullOrWhiteSpace(fix)) fixedIn = fix;
                            break;
                        }
                    }
                }
            }
            catch (JsonException) { }
            ev.Add(new EvidenceClaim("Vendor advisory " + adv.AdvisoryId + (adv.Title is null ? "" : ": " + adv.Title) + (fixText is null ? "" : " (" + fixText.TrimEnd(';', ' ') + ")") + (adv.ExploitedInTheWild ? "; the vendor states it is exploited in the wild" : ""), adv.Url ?? adv.Vendor + " PSIRT", adv.RetrievedAt));
        }
        if (advisories.FirstOrDefault(a => a.ExploitedInTheWild) is { } exploited)
        {
            if (!latest.Any(a => a.ExploitedInTheWild))
                ev.Add(new EvidenceClaim("Vendor advisory " + exploited.AdvisoryId + (exploited.Title is null ? "" : ": " + exploited.Title) + "; the vendor states it is exploited in the wild", exploited.Url ?? exploited.Vendor + " PSIRT", exploited.RetrievedAt));
            if (exploitation == Exploitation.None) exploitation = Exploitation.Active;
        }

        if (exploitation == Exploitation.None)
        {
            foreach (var sig in signals.Take(4))
            {
                exploitation = Exploitation.PoC;
                ev.Add(new EvidenceClaim("Public exploit: " + SourceName(sig.Source) + (sig.Title is null ? "" : " - " + sig.Title), sig.Url, sig.RetrievedAt));
            }
            if (epss is not null && epss.Score >= 0.10)
            {
                exploitation = Exploitation.PoC;
                ev.Add(new EvidenceClaim("EPSS " + epss.Score.ToString("0.00") + " (probability of exploitation in the next 30 days), at or above the 0.10 threshold", "EPSS by FIRST, scores dated " + epss.ScoreDate.ToString("yyyy-MM-dd"), epss.RetrievedAt));
            }
            else if (string.Equals(cve?.SsvcExploitation, "poc", StringComparison.OrdinalIgnoreCase))
            {
                exploitation = Exploitation.PoC;
                ev.Add(new EvidenceClaim("CISA Vulnrichment SSVC Exploitation: poc", "CISA ADP container in CVE List V5", retrieved));
            }
        }
        if (exploitation == Exploitation.None)
        {
            var epssNote = epss is not null ? "EPSS " + epss.Score.ToString("0.000") + (epss.Score >= 0.02 ? " (signal: between 0.02 and 0.10)" : "") : "no EPSS score";
            ev.Add(new EvidenceClaim("No known exploitation: not in KEV, no public exploit indexed, " + epssNote, "CISA KEV, Exploit-DB, Metasploit, Nuclei, EPSS", now));
        }

        // ---- automatable and attack path
        var cvss = CvssVector.Parse(cve?.CvssV40Vector) ?? CvssVector.Parse(cve?.CvssV31Vector);
        var automatable = cvss?.Automatable == true;
        var attackVector = cvss?.AttackVector ?? AttackVector.Unknown;
        if (cvss is not null)
            ev.Add(new EvidenceClaim("CVSS " + cvss.Version + " vector: attack vector " + cvss.AttackVector + ", complexity " + cvss.AttackComplexity + ", privileges " + cvss.PrivilegesRequired + ", user interaction " + cvss.UserInteraction + (automatable ? " (automatable)" : " (not automatable)"), cnaSource, retrieved, cvss.Raw));
        else
            ev.Add(new EvidenceClaim("No CVSS vector supplied by the CNA or CISA; treated as network-reachable and not automatable", cnaSource, retrieved));
        if (string.Equals(cve?.SsvcAutomatable, "yes", StringComparison.OrdinalIgnoreCase))
        {
            automatable = true;
            ev.Add(new EvidenceClaim("CISA Vulnrichment SSVC Automatable: yes", "CISA ADP container in CVE List V5", retrieved));
        }
        if (attackVector == AttackVector.Unknown) attackVector = AttackVector.Network;

        // ---- exposure and criticality
        var declared = overall == VersionMatch.NotAffected || s.FeatureDisabled ? Exposure.NotInstalled : s.Exposure;
        if (s.FeatureDisabled && overall != VersionMatch.NotAffected)
            ev.Add(new EvidenceClaim("The role, feature or service is present but disabled, so it is treated as not installed", subjectSource, s.DeclaredAt == default ? now : s.DeclaredAt));
        var inputs = new DecisionInputs(exploitation, automatable, attackVector, declared, s.Criticality);
        ev.Add(new EvidenceClaim("Exposure " + inputs.DeclaredExposure.Plain() + (inputs.ExposureCapped ? ", treated as internal because the attack vector is " + attackVector.ToString().ToLowerInvariant() : "") + "; criticality " + s.Criticality, subjectSource, s.DeclaredAt == default ? now : s.DeclaredAt));

        var decision = DecisionTable.Evaluate(inputs);
        ev.Add(new EvidenceClaim("Decision table rule " + decision.Rule + ": " + DecisionTable.RuleText(decision.Rule) + " => " + decision.Tier.Plain(), "VulnVerdict decision table", now));

        // ---- compensating-control modifiers: one tier down, never for Active + Internet
        var modifiers = new List<string>();
        if (controls.Count > 0 && decision.Tier >= VerdictTier.NextPatchCycle && !(exploitation == Exploitation.Active && inputs.EffectiveExposure == Exposure.Internet))
        {
            var c = controls[0];
            modifiers.Add(c.KindText + (string.IsNullOrWhiteSpace(c.Description) ? "" : " (" + c.Description + ")"));
            var lowered = (VerdictTier)Math.Max((int)VerdictTier.IgnoreTracked, (int)decision.Tier - 1);
            ev.Add(new EvidenceClaim("Compensating control: " + modifiers[0] + " lowers the verdict from " + decision.Tier.Plain() + " to " + lowered.Plain(), "Recorded by " + c.CreatedBy, c.CreatedAt));
            decision = decision with { Tier = lowered };
        }
        else if (controls.Count > 0 && exploitation == Exploitation.Active && inputs.EffectiveExposure == Exposure.Internet)
            ev.Add(new EvidenceClaim("Compensating control recorded (" + controls[0].KindText + ") but not applied: exploited in the wild and internet-facing is never lowered", "VulnVerdict decision table", now));

        var sentence = SentenceBuilder.Build(s, inputs, cvss, decision.Tier, fixedIn, confidence, versionUnknown, modifiers);
        return new Computed(inputs, decision, confidence, versionUnknown, sentence, fixedIn, ev, epss?.Score, kev is not null, cvss, modifiers);
    }

    private static string SourceName(string s) => s switch
    {
        "exploitdb" => "Exploit-DB",
        "metasploit" => "Metasploit module",
        "nuclei" => "Nuclei template",
        _ => s
    };

    /// <summary>Copy a computed result onto a verdict row. Returns true if the tier changed.</summary>
    private static bool Apply(Verdict v, Computed c, Subject s, DateTime now, List<SuppressionRule> rules, AppSettings settings, List<(string Event, Guid VerdictId)> events, bool isNew = false)
    {
        var tierChanged = !isNew && v.Tier != c.Decision.Tier;
        if (isNew && c.Decision.Tier >= VerdictTier.NextPatchCycle) events.Add((WebhookService.EventCreated, v.Id));

        // a closed verdict that is affected again re-opens, with a fresh SLA and fresh alerts, instead of a second verdict
        // appearing next to the closed one (see ReopenReason for which closures re-open when)
        var reopenWhy = isNew ? null : ReopenReason(v, c, s);
        if (reopenWhy is not null)
        {
            v.History.Add(new VerdictHistory { At = now, Actor = "system", Kind = "state", From = "Closed", To = "Open", Reason = "re-opened: " + reopenWhy });
            v.State = VerdictState.Open; v.StateReason = null; v.StateOwner = null; v.StateChangedAt = now;
            v.ImmediateEmailSentAt = null; v.TicketSentAt = null;
            if (!tierChanged) v.TierChangeReason = "re-opened: " + reopenWhy;
            if (c.Decision.Tier >= VerdictTier.NextPatchCycle && !(tierChanged && c.Decision.Tier > v.Tier)) events.Add((WebhookService.EventPromoted, v.Id));
        }
        var reopened = reopenWhy is not null;
        if (tierChanged)
        {
            var reason = c.InKev && !v.InKev ? "now in CISA KEV"
                : c.Inputs.Exploitation > v.Exploitation ? "public exploit published"
                : c.Inputs.Exploitation < v.Exploitation ? "exploit evidence withdrawn"
                : c.Decision.Tier == VerdictTier.NotAffected && c.Inputs.DeclaredExposure == Exposure.NotInstalled
                    ? (s.SoftwareInstanceId is not null ? "fixed version observed: " : "watchlist now records: ") + (s.Version ?? "?")
                : c.Inputs.DeclaredExposure != v.DeclaredExposure ? "exposure changed to " + c.Inputs.DeclaredExposure.Plain().ToLowerInvariant()
                : c.Inputs.Criticality != v.Criticality ? "criticality changed to " + c.Inputs.Criticality
                : c.Inputs.Automatable != v.Automatable ? "attack path re-assessed"
                : c.Modifiers.Count > 0 && string.IsNullOrEmpty(v.AppliedModifiersJson) ? "compensating control recorded"
                : c.Modifiers.Count == 0 && !string.IsNullOrEmpty(v.AppliedModifiersJson) ? "compensating control removed or expired"
                : "inputs changed";
            // carried on the tier line too, which is what the digest's "Changed" section reads
            if (reopenWhy is not null) reason = (v.Tier == VerdictTier.NotAffected ? reopenWhy : reason) + " (re-opened)";
            v.History.Add(new VerdictHistory { At = now, Actor = "system", Kind = "tier", From = v.Tier.ToString(), To = c.Decision.Tier.ToString(), Reason = reason });
            v.PreviousTier = v.Tier;
            v.TierChangedAt = now;
            v.TierChangeReason = reason;
            var promoted = c.Decision.Tier > v.Tier;
            if (promoted)
            {
                if (c.Decision.Tier >= VerdictTier.NextPatchCycle) events.Add((WebhookService.EventPromoted, v.Id));
                if (c.Decision.Tier == VerdictTier.FixToday) v.ImmediateEmailSentAt = null;
                if (c.Decision.Tier >= VerdictTier.FixThisWeek) v.TicketSentAt = null;
                if (v.State is VerdictState.Snoozed or VerdictState.AcceptedRisk)
                {
                    v.History.Add(new VerdictHistory { At = now, Actor = "system", Kind = "state", From = v.State.ToString(), To = VerdictState.Open.ToString(), Reason = "re-opened: promoted to " + c.Decision.Tier.Plain() + " (" + reason + ")" });
                    v.State = VerdictState.Open; v.StateReason = null; v.SnoozedUntil = null; v.AcceptedRiskExpiry = null; v.StateChangedAt = now;
                }
            }
            // auto-close: the version now recorded is outside the affected range. For an asset that is the version a
            // connector saw; for a watchlist entry it is the version someone recorded after upgrading, which is how
            // one upgrade (7.5 to 7.8, say) settles every CVE the new version fixes, not only the one marked done.
            // Snoozed and accepted-risk items close too: the risk they were parked for no longer exists.
            else if (c.Decision.Tier == VerdictTier.NotAffected && v.Tier > VerdictTier.NotAffected
                     && v.State is VerdictState.Open or VerdictState.Snoozed or VerdictState.AcceptedRisk)
            {
                var source = s.SoftwareInstanceId is not null ? "fixed version observed" : "watchlist now records";
                var fromState = v.State;
                v.History.Add(new VerdictHistory { At = now, Actor = "system", Kind = "state", From = fromState.ToString(), To = "Closed", Reason = "patched, closed: " + source + " " + (s.Version ?? "?") });
                v.State = VerdictState.Closed; v.StateReason = source + ": " + (s.Version ?? "?"); v.StateOwner = "system"; v.StateChangedAt = now;
                v.SnoozedUntil = null; v.AcceptedRiskExpiry = null;
                events.Add((WebhookService.EventClosed, v.Id));
            }
        }

        v.Exploitation = c.Inputs.Exploitation;
        v.Automatable = c.Inputs.Automatable;
        v.AttackVector = c.Inputs.AttackVector;
        v.DeclaredExposure = c.Inputs.DeclaredExposure;
        v.EffectiveExposure = c.Inputs.EffectiveExposure;
        v.Criticality = c.Inputs.Criticality;
        v.Epss = c.Epss;
        v.InKev = c.InKev;
        v.Confidence = c.Confidence;
        v.Subject = s.Display.Length > 400 ? s.Display[..400] : s.Display;
        v.Sentence = c.Sentence.Length > 1000 ? c.Sentence[..1000] : c.Sentence;
        v.FixedIn = c.FixedIn is { Length: > 200 } ? c.FixedIn[..200] : c.FixedIn;
        v.EvidenceJson = JsonSerializer.Serialize(c.Evidence);
        v.AppliedModifiersJson = c.Modifiers.Count == 0 ? null : JsonSerializer.Serialize(c.Modifiers);
        v.LastEvaluatedAt = now;
        v.UpdatedAt = now;

        if (isNew || tierChanged || reopened)
        {
            v.Tier = c.Decision.Tier;
            v.RuleNumber = c.Decision.Rule;
            var days = c.Decision.Tier switch
            {
                VerdictTier.FixToday => settings.SlaFixTodayDays,
                VerdictTier.FixThisWeek => settings.SlaFixThisWeekDays,
                VerdictTier.NextPatchCycle => settings.SlaNextPatchCycleDays,
                _ => (int?)null
            };
            v.SlaDue = days.HasValue ? now.AddDays(days.Value) : null;
        }
        else v.RuleNumber = c.Decision.Rule;

        if (v.State is VerdictState.Open or VerdictState.Suppressed)
        {
            var rule = rules.FirstOrDefault(r => !r.IsExpired(now) && SuppressionMatcher.Matches(r, v, s));
            if (rule is not null && v.State == VerdictState.Open)
            {
                v.History.Add(new VerdictHistory { At = now, Actor = "system", Kind = "state", From = "Open", To = "Suppressed", Reason = "suppression rule: " + rule.Reason });
                v.State = VerdictState.Suppressed; v.SuppressedByRuleId = rule.Id; v.StateReason = rule.Reason; v.StateOwner = rule.Owner; v.StateChangedAt = now;
            }
            else if (rule is null && v.State == VerdictState.Suppressed && v.SuppressedByRuleId is not null)
            {
                v.History.Add(new VerdictHistory { At = now, Actor = "system", Kind = "state", From = "Suppressed", To = "Open", Reason = "suppression rule expired or removed" });
                v.State = VerdictState.Open; v.SuppressedByRuleId = null; v.StateReason = null; v.StateChangedAt = now;
            }
        }
        return tierChanged || reopened;
    }

    // ------------------------------------------------------------------ gone: close, never delete

    /// <summary>Reason prefix for verdicts closed because their software or asset stopped being reported.</summary>
    public const string NoLongerReported = "no longer reported";
    /// <summary>Reason for verdicts closed because the CVE stopped matching the subject.</summary>
    public const string NoLongerMatches = "no longer matches: the CVE record or the product mapping changed";

    private static readonly VerdictState[] OpenishStates = { VerdictState.Open, VerdictState.Snoozed, VerdictState.AcceptedRisk, VerdictState.Suppressed };
    private static bool IsOpenish(VerdictState s) => OpenishStates.Contains(s);

    /// <summary>Closed by the system because its subject went away, as opposed to fixed or closed by a person.</summary>
    public static bool IsClosedAsGone(Verdict v) => v.State == VerdictState.Closed && v.StateOwner == "system"
        && v.StateReason is { } r && (r.StartsWith(NoLongerReported, StringComparison.Ordinal) || r.StartsWith("no longer matches", StringComparison.Ordinal));

    /// <summary>
    /// Why a closed verdict re-opens on this evaluation, or null if it stays closed. Closed by the system (gone, or
    /// patched because a fixed version was seen): whenever it is affected again, as when a CNA widens the range or the
    /// version rolls back. Closed by a person: only when it gets worse in a way they cannot have weighed, promoted to
    /// Fix today or newly exploited in the wild.
    /// </summary>
    private static string? ReopenReason(Verdict v, Computed c, Subject s)
    {
        if (v.State != VerdictState.Closed || c.Decision.Tier <= VerdictTier.NotAffected) return null;
        if (IsClosedAsGone(v))
            return v.StateReason!.StartsWith("no longer matches", StringComparison.Ordinal) ? "matches again"
                : "reported again" + (s.Version is null ? "" : " at " + s.Version);
        if (v.StateOwner == "system")
            return "affected again" + (s.Version is null ? "" : " at " + s.Version);
        if (c.InKev && !v.InKev) return "now in CISA KEV";
        if (c.Inputs.Exploitation == Exploitation.Active && v.Exploitation != Exploitation.Active) return "now exploited in the wild";
        if (c.Decision.Tier == VerdictTier.FixToday && v.Tier < VerdictTier.FixToday) return "promoted to " + c.Decision.Tier.Plain();
        return null;
    }

    private static void CloseAsGone(VvDbContext db, Verdict v, string reason, DateTime now, List<(string Event, Guid VerdictId)> events)
    {
        v.History.Add(new VerdictHistory { At = now, Actor = "system", Kind = "state", From = v.State.ToString(), To = "Closed", Reason = "closed: " + reason });
        v.State = VerdictState.Closed; v.StateReason = reason; v.StateOwner = "system"; v.StateChangedAt = now;
        v.SnoozedUntil = null; v.AcceptedRiskExpiry = null; v.SuppressedByRuleId = null; v.UpdatedAt = now;
        events.Add((WebhookService.EventClosed, v.Id));
    }

    /// <summary>
    /// Closes (never deletes) the open verdicts of software a connector stopped reporting, and of assets that were
    /// archived or not seen for 30 days. The verdict and its history stay; if the software or asset comes back the
    /// same verdict re-opens (see <see cref="Apply"/>).
    /// </summary>
    private async Task<int> CloseGoneAsync(VvDbContext db, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var staleBefore = now.AddDays(-30);
        var events = new List<(string Event, Guid VerdictId)>();
        var names = (await db.Connectors.AsNoTracking().Select(c => new { c.Id, c.DisplayName }).ToListAsync(ct))
            .ToDictionary(c => c.Id.ToString("N"), c => c.DisplayName);

        var removedSoftware = await (from v in db.Verdicts
                                     join s in db.Software.IgnoreQueryFilters() on v.SoftwareInstanceId equals (Guid?)s.Id
                                     where s.RemovedAt != null && OpenishStates.Contains(v.State)
                                     select new { Verdict = v, s.ConnectorId, s.RemovedAt }).ToListAsync(ct);
        foreach (var x in removedSoftware)
            CloseAsGone(db, x.Verdict, NoLongerReported + " by " + (names.TryGetValue(x.ConnectorId, out var n) ? n : "a connector that has since been deleted")
                + " (since " + x.RemovedAt!.Value.ToString("yyyy-MM-dd") + ")", now, events);

        var goneAssets = await (from v in db.Verdicts
                                join a in db.Assets on v.AssetId equals (Guid?)a.Id
                                where (a.Archived || a.LastSeen < staleBefore) && OpenishStates.Contains(v.State)
                                select new { Verdict = v, a.Archived, a.LastSeen }).ToListAsync(ct);
        foreach (var x in goneAssets.Where(x => IsOpenish(x.Verdict.State)))
            CloseAsGone(db, x.Verdict, NoLongerReported + ": " + (x.Archived ? "asset archived" : "asset not seen since " + x.LastSeen.ToString("yyyy-MM-dd")), now, events);

        await db.SaveChangesAsync(ct);
        db.ChangeTracker.Clear();
        foreach (var (evt, id) in events) _webhooks.Enqueue(evt, id);
        return events.Count;
    }

    private static async Task MaintainStatesAsync(VvDbContext db, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var due = await db.Verdicts.Where(v => (v.State == VerdictState.Snoozed && v.SnoozedUntil != null && v.SnoozedUntil < now)
                                             || (v.State == VerdictState.AcceptedRisk && v.AcceptedRiskExpiry != null && v.AcceptedRiskExpiry < now)).ToListAsync(ct);
        foreach (var v in due)
        {
            db.VerdictHistory.Add(new VerdictHistory { VerdictId = v.Id, At = now, Actor = "system", Kind = "state", From = v.State.ToString(), To = "Open", Reason = v.State == VerdictState.Snoozed ? "snooze expired" : "accepted risk expired" });
            v.State = VerdictState.Open; v.SnoozedUntil = null; v.AcceptedRiskExpiry = null; v.StateChangedAt = now; v.StateReason = null;
        }
        if (due.Count > 0) await db.SaveChangesAsync(ct);
    }
}

public static class SuppressionMatcher
{
    public static bool Matches(SuppressionRule r, Verdict v, Subject s) => r.Scope switch
    {
        SuppressionScope.Cve => string.Equals(r.CveId, v.CveId, StringComparison.OrdinalIgnoreCase),
        SuppressionScope.Product => r.VendorNorm == s.VendorNorm && r.ProductNorm == s.ProductNorm,
        SuppressionScope.WatchlistEntry => r.WatchlistEntryId != null && (r.WatchlistEntryId == s.WatchlistEntryId || r.WatchlistEntryId == s.AssetId),
        _ => false
    };

    public static bool Matches(SuppressionRule r, Verdict v, WatchlistEntry e) =>
        Matches(r, v, new Subject(e.Vendor, e.Product, e.Version, e.AssetName, e.Exposure, e.Criticality, WatchlistEntryId: e.Id));
}
