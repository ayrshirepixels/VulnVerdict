using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;

namespace VulnVerdict.Core.Services;

public sealed record ApplySummary(int Assets, int Software, int Findings, int Exposures, int Unmapped);

/// <summary>
/// Sections 8 and 9: takes adapter output into the canonical model, merges assets seen by several sources,
/// resolves software to CNA identities (exact, alias, fuzzy, or the needs-mapping queue), applies exposure
/// evidence, stamps last-seen, and keeps coverage reconciliation honest.
/// </summary>
public sealed class InventoryService
{
    public const string DiscoveryConnectorPrefix = "discovery";
    /// <summary>State key prefix (plus the connector id) for <see cref="RunState"/>: one settings row per connector.</summary>
    public const string RunStatePrefix = "state:inventory:";
    /// <summary>Per-asset floor: a list that had at least this many rows and loses more than half of them in one run is held.</summary>
    public const int FloorMinRows = 10;
    /// <summary>Per-asset floor: a list that had more than this many rows and comes back as the operating system alone is held.</summary>
    public const int FloorHandful = 5;
    /// <summary>The same reduced list on this many runs in a row is accepted as a real mass uninstall.</summary>
    public const int FloorAcceptRuns = 3;
    private const int StaleDays = 30;

    /// <summary>
    /// What the next run needs to know about this connector's earlier runs: when a complete (non-partial) run last
    /// finished, since when its runs have been partial, and the reduced software lists being held by the per-asset floor.
    /// </summary>
    public sealed class RunState
    {
        public DateTime? LastComplete { get; set; }
        public DateTime? PartialSince { get; set; }
        /// <summary>Asset id to the reduced list seen (a hash of its product names) and on how many runs in a row.</summary>
        public Dictionary<string, HeldDrop> Held { get; set; } = new();
    }

    public sealed record HeldDrop(string Signature, int Runs);

    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly ILogger<InventoryService> _log;

    public InventoryService(IDbContextFactory<VvDbContext> factory, ILogger<InventoryService> log)
    {
        _factory = factory; _log = log;
    }

    // ------------------------------------------------------------------ apply adapter output

    public async Task<ApplySummary> ApplyAsync(Connector connector, CollectResult result, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        // whole milliseconds: the run state compares this stamp with LastSeen columns, and PostgreSQL keeps fewer digits than a tick
        var now = new DateTime(DateTime.UtcNow.Ticks / TimeSpan.TicksPerMillisecond * TimeSpan.TicksPerMillisecond, DateTimeKind.Utc);
        var connectorId = connector.Id.ToString("N");
        var isDiscovery = connector.AdapterId.StartsWith(DiscoveryConnectorPrefix, StringComparison.OrdinalIgnoreCase);

        var links = await db.AssetSources.Where(s => s.ConnectorId == connectorId).ToListAsync(ct);
        var linkByExt = links.ToDictionary(l => l.ExternalId, StringComparer.OrdinalIgnoreCase);
        var assetIds = links.Select(l => l.AssetId).ToHashSet();
        var assetCache = await db.Assets.Include(a => a.Sources).Where(a => assetIds.Contains(a.Id)).ToDictionaryAsync(a => a.Id, ct);

        // identity index of every non-archived asset for cross-source merging (MAC, then hostname, then IP)
        var all = await db.Assets.Include(a => a.Sources).Where(a => !a.Archived).ToListAsync(ct);
        var byMac = new Dictionary<string, Asset>(StringComparer.OrdinalIgnoreCase);
        var byHost = new HostIndex();
        var byIp = new Dictionary<string, List<Asset>>();
        foreach (var a in all)
        {
            foreach (var m in Json(a.MacAddressesJson)) byMac.TryAdd(NormMac(m), a);
            foreach (var h in Json(a.HostnamesJson)) byHost.Add(h, a);
            foreach (var ip in Json(a.IpAddressesJson)) (byIp.TryGetValue(ip, out var l) ? l : byIp[ip] = new()).Add(a);
        }

        var extToAsset = new Dictionary<string, Asset>(StringComparer.OrdinalIgnoreCase);
        foreach (var rec in result.Assets)
        {
            ct.ThrowIfCancellationRequested();
            Asset? asset = null;
            if (linkByExt.TryGetValue(rec.ExternalId, out var link) && assetCache.TryGetValue(link.AssetId, out var known)) asset = known;
            asset ??= rec.MacAddresses.Select(m => byMac.GetValueOrDefault(NormMac(m))).FirstOrDefault(a => a is not null);
            asset ??= rec.Hostnames.Concat(new[] { rec.DisplayName }).Select(byHost.Find).FirstOrDefault(a => a is not null);
            if (asset is null)
            {
                foreach (var ip in rec.IpAddresses)
                    if (byIp.TryGetValue(ip, out var cands) && cands.Count == 1 && !IsPrivateShared(ip)) { asset = cands[0]; break; }
            }

            if (asset is null)
            {
                asset = new Asset { Id = Guid.NewGuid(), FirstSeen = now, Criticality = DefaultCriticality(rec), Exposure = Exposure.Internal, Unknown = isDiscovery };
                db.Assets.Add(asset);
                all.Add(asset);
            }
            else if (!isDiscovery && asset.Unknown) asset.Unknown = false; // now claimed by a real adapter

            // merge fields; a real adapter's data beats discovery's
            if (!isDiscovery || string.IsNullOrEmpty(asset.DisplayName)) asset.DisplayName = rec.DisplayName is { Length: > 0 } ? rec.DisplayName : (rec.Hostnames.FirstOrDefault() ?? rec.IpAddresses.FirstOrDefault() ?? rec.ExternalId);
            if (!isDiscovery || asset.Kind == AssetKind.Other) asset.Kind = rec.Kind;
            asset.HostnamesJson = MergeJson(asset.HostnamesJson, rec.Hostnames);
            asset.IpAddressesJson = MergeJson(asset.IpAddressesJson, rec.IpAddresses);
            asset.MacAddressesJson = MergeJson(asset.MacAddressesJson, rec.MacAddresses.Select(NormMac));
            // a hypervisor's guest label ("Ubuntu Linux (64-bit)") never overwrites what a server collector saw on the box
            var weakOsSource = connector.AdapterId is "vcenter" or "hyperv" || isDiscovery;
            if (rec.OsProduct is not null && (!weakOsSource || string.IsNullOrEmpty(asset.OsProduct)))
            { asset.OsVendor = rec.OsVendor; asset.OsProduct = rec.OsProduct; asset.OsVersion = rec.OsVersion; asset.OsBuild = rec.OsBuild; }
            if (rec.Owner is not null) asset.Owner = rec.Owner;
            if (!asset.CriticalityPinned && (rec.Criticality ?? DefaultCriticality(rec)) == Criticality.Critical) asset.Criticality = Criticality.Critical;
            asset.LastSeen = now;
            asset.Archived = false;

            var src = asset.Sources.FirstOrDefault(s => s.ConnectorId == connectorId && s.ExternalId.Equals(rec.ExternalId, StringComparison.OrdinalIgnoreCase));
            if (src is null) asset.Sources.Add(new AssetSource { AssetId = asset.Id, ConnectorId = connectorId, AdapterId = connector.AdapterId, ExternalId = rec.ExternalId, FirstSeen = now, LastSeen = now });
            else src.LastSeen = now;

            extToAsset[rec.ExternalId] = asset;
            foreach (var m in rec.MacAddresses) byMac.TryAdd(NormMac(m), asset);
            foreach (var h in rec.Hostnames.Concat(new[] { rec.DisplayName })) byHost.Add(h, asset);
        }
        await db.SaveChangesAsync(ct);

        // ---- software
        var aliases = await db.Aliases.AsNoTracking().ToListAsync(ct);
        var stateRow = await db.Settings.FirstOrDefaultAsync(s => s.Key == RunStatePrefix + connectorId, ct);
        var state = ParseRunState(stateRow?.Value) ?? new RunState();
        // a partial run proves nothing about what is gone: no removal, no purge, no ageing (see HeldByPartialRunsAsync)
        var removals = result.FullSnapshot && !result.Partial;
        var unmapped = 0; var softwareCount = 0; var heldDrops = new List<string>();
        foreach (var group in result.Software.GroupBy(s => s.AssetExternalId, StringComparer.OrdinalIgnoreCase))
        {
            if (!extToAsset.TryGetValue(group.Key, out var asset)) continue;
            // removed rows too: software that comes back revives its old row, so its closed verdicts can reopen
            var existing = await db.Software.IgnoreQueryFilters().Where(s => s.AssetId == asset.Id && s.ConnectorId == connectorId).ToListAsync(ct);
            var before = existing.Count(s => s.RemovedAt == null);
            var seen = new HashSet<Guid>();
            foreach (var rec in group)
            {
                var vn = Normalizer.Norm(rec.Vendor); var pn = Normalizer.Norm(rec.Product);
                if (pn == "") continue;
                var match = existing.FirstOrDefault(s => rec.ExternalId is not null ? s.ExternalId == rec.ExternalId
                    : s.VendorNorm == vn && s.ProductNorm == pn && s.Version == (rec.Version ?? "") && s.Kind == rec.Kind);
                if (match is null)
                {
                    match = new SoftwareInstance { Id = Guid.NewGuid(), AssetId = asset.Id, ConnectorId = connectorId, FirstSeen = now };
                    db.Software.Add(match); existing.Add(match);
                }
                match.Vendor = Trunc(rec.Vendor, 200); match.Product = Trunc(rec.Product, 300); match.Version = Trunc(rec.Version ?? "", 100);
                match.VendorNorm = vn; match.ProductNorm = pn; match.Edition = rec.Edition; match.Architecture = rec.Architecture;
                match.Cpe = rec.Cpe; match.Purl = rec.Purl; match.Ecosystem = rec.Ecosystem; match.Kind = rec.Kind; match.Enabled = rec.Enabled;
                match.ExternalId = rec.ExternalId; match.LastSeen = now; match.RemovedAt = null;
                match.ListenersJson = rec.Listeners is { Length: > 0 } ? JsonSerializer.Serialize(rec.Listeners) : null;
                if (match.MappingStatus != MappingStatus.Ignored)
                {
                    await ResolveMappingAsync(db, match, aliases, ct);
                    if (match.MappingStatus == MappingStatus.Unmapped) unmapped++;
                }
                seen.Add(match.Id); softwareCount++;
            }
            if (!removals || result.IncompleteSoftware.Contains(group.Key)) continue;
            var keep = result.IncompleteRows.GetValueOrDefault(group.Key);
            var gone = existing.Where(s => !seen.Contains(s.Id) && s.RemovedAt == null
                && !(keep is not null && s.ExternalId is not null && keep.Any(p => s.ExternalId.StartsWith(p, StringComparison.Ordinal)))).ToList();
            var assetKey = asset.Id.ToString("N");
            // per-asset floor: a list that collapses in one run is more often a failed read than a mass uninstall, so it
            // is held until the same reduced list has come back FloorAcceptRuns times in a row
            var current = existing.Where(s => seen.Contains(s.Id)).ToList();
            var collapsed = gone.Count > 0 && ((before >= FloorMinRows && current.Count * 2 < before)
                || (before > FloorHandful && current.All(s => s.Kind == SoftwareKind.OperatingSystem)));
            if (collapsed)
            {
                var signature = Signature(current);
                var runs = state.Held.TryGetValue(assetKey, out var held) && held.Signature == signature ? held.Runs + 1 : 1;
                if (runs < FloorAcceptRuns)
                {
                    state.Held[assetKey] = new HeldDrop(signature, runs);
                    heldDrops.Add(asset.DisplayName + " (" + before + " to " + current.Count + " rows, run " + runs + " of " + FloorAcceptRuns + ")");
                    continue;
                }
            }
            state.Held.Remove(assetKey);
            // not deleted: marked removed, so the evaluator closes its verdicts with a reason and keeps their history
            foreach (var s in gone) s.RemovedAt = now;
        }
        // first, so it is not cut off the connector's status line (which shows the first few warnings)
        if (heldDrops.Count > 0)
            result.Warnings.Insert(0, "Software list shrank sharply on " + string.Join(", ", heldDrops.Take(10)) + (heldDrops.Count > 10 ? " and " + (heldDrops.Count - 10) + " more" : "")
                + ": nothing was marked removed there; it is accepted once the same list is seen on " + FloorAcceptRuns + " runs in a row");
        // holds for assets this connector no longer reports are dropped with them
        var linked = assetIds.Concat(extToAsset.Values.Select(a => a.Id)).Select(id => id.ToString("N")).ToHashSet();
        foreach (var key in state.Held.Keys.Where(k => !linked.Contains(k)).ToList()) state.Held.Remove(key);
        await db.SaveChangesAsync(ct);

        // ---- exposure evidence (highest wins unless pinned by a person)
        var exposures = 0;
        foreach (var ex in result.Exposures)
        {
            Asset? target = null;
            if (ex.AssetExternalId is not null) extToAsset.TryGetValue(ex.AssetExternalId, out target);
            target ??= ex.Hostname is not null ? byHost.Find(ex.Hostname) : null;
            if (target is null && ex.IpAddress is not null && byIp.TryGetValue(ex.IpAddress, out var c) && c.Count == 1) target = c[0];
            if (target is null || target.ExposurePinned) continue;
            if (ex.Exposure > target.Exposure || (target.ExposureEvidence ?? "").StartsWith(connector.DisplayName + ":"))
            {
                target.Exposure = ex.Exposure;
                target.ExposureEvidence = Trunc(connector.DisplayName + ": " + ex.Evidence, 1000);
            }
            exposures++;
        }

        // ---- findings
        var findings = 0;
        foreach (var f in result.Findings)
        {
            if (!extToAsset.TryGetValue(f.AssetExternalId, out var asset)) continue;
            var ids = f.CveIds.Select(Normalizer.CveIdUpper).Distinct().ToArray();
            if (ids.Length == 0) continue;
            var key = f.RawRef ?? string.Join(",", ids);
            var row = await db.Findings.FirstOrDefaultAsync(x => x.AssetId == asset.Id && x.ConnectorId == connectorId && x.RawRef == key, ct);
            if (row is null) { row = new ExternalFinding { Id = Guid.NewGuid(), AssetId = asset.Id, ConnectorId = connectorId, Source = connector.AdapterId, RawRef = Trunc(key, 500), FirstSeen = now }; db.Findings.Add(row); }
            row.CveIdsJson = JsonSerializer.Serialize(ids); row.SourceSeverity = f.Severity; row.Title = Trunc(f.Title, 500); row.LastSeen = now;
            findings++;
        }
        if (removals && !result.FindingsIncomplete)
        {
            // only where this run is a full picture: assets it listed completely, and assets the source dropped long ago.
            // An asset missing from one run (offline, filtered, a short page) keeps its findings.
            var complete = extToAsset.Where(kv => !result.IncompleteSoftware.Contains(kv.Key)).Select(kv => kv.Value.Id).ToHashSet();
            var dropped = links.Where(l => l.LastSeen < now.AddDays(-StaleDays)).Select(l => l.AssetId).ToHashSet();
            var stale = await db.Findings.Where(x => x.ConnectorId == connectorId && x.LastSeen < now).ToListAsync(ct);
            db.Findings.RemoveRange(stale.Where(f => complete.Contains(f.AssetId) || dropped.Contains(f.AssetId)));
        }

        // ---- run state: only a complete run counts as having missed the assets it did not list
        if (result.Partial) state.PartialSince ??= now;
        else { state.LastComplete = now; state.PartialSince = null; }
        if (stateRow is null) db.Settings.Add(stateRow = new AppSetting { Key = RunStatePrefix + connectorId });
        stateRow.Value = JsonSerializer.Serialize(state); stateRow.UpdatedAt = now;
        await db.SaveChangesAsync(ct);

        _log.LogInformation("Connector {Name}: {Assets} assets, {Software} software, {Findings} findings, {Unmapped} need mapping", connector.DisplayName, extToAsset.Count, softwareCount, findings, unmapped);
        return new ApplySummary(extToAsset.Count, softwareCount, findings, exposures, unmapped);
    }

    // ------------------------------------------------------------------ run state

    private static RunState? ParseRunState(string? json)
    {
        try { return string.IsNullOrEmpty(json) ? null : JsonSerializer.Deserialize<RunState>(json); } catch (JsonException) { return null; }
    }

    /// <summary>The reduced list's identity: product names only, so an update to what is left does not restart the count.</summary>
    private static string Signature(IEnumerable<SoftwareInstance> rows)
    {
        var names = string.Join("\n", rows.Select(s => s.VendorNorm + "|" + s.ProductNorm + "|" + (int)s.Kind).Distinct().OrderBy(n => n, StringComparer.Ordinal));
        return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(names)))[..16];
    }

    /// <summary>
    /// Assets that must not age out (the 30-day stale close, the 90-day archive) because the connector that reports them
    /// has only had partial runs since it last saw them: a truncated listing is not evidence the asset is gone. An asset
    /// a complete run has missed since is not held, and neither are the assets of a disabled or deleted connector.
    /// </summary>
    public static async Task<HashSet<Guid>> HeldByPartialRunsAsync(VvDbContext db, CancellationToken ct = default)
    {
        var held = new HashSet<Guid>();
        var rows = await db.Settings.AsNoTracking().Where(s => s.Key.StartsWith(RunStatePrefix)).ToListAsync(ct);
        if (rows.Count == 0) return held;
        var enabled = (await db.Connectors.AsNoTracking().Where(c => c.Enabled).Select(c => c.Id).ToListAsync(ct)).Select(id => id.ToString("N")).ToHashSet();
        foreach (var row in rows)
        {
            var connectorId = row.Key[RunStatePrefix.Length..];
            if (ParseRunState(row.Value) is not { PartialSince: not null } state || !enabled.Contains(connectorId)) continue;
            var sources = db.AssetSources.AsNoTracking().Where(s => s.ConnectorId == connectorId);
            // seen by the last complete run (same stamp) or by a partial one since: no complete run has missed it yet
            if (state.LastComplete is { } complete) sources = sources.Where(s => s.LastSeen >= complete);
            held.UnionWith(await sources.Select(s => s.AssetId).ToListAsync(ct));
        }
        return held;
    }

    // ------------------------------------------------------------------ mapping

    private static async Task ResolveMappingAsync(VvDbContext db, SoftwareInstance s, List<ProductAlias> aliases, CancellationToken ct)
    {
        // packages are matched through OSV by purl/ecosystem, not through CNA names
        if (s.Kind is SoftwareKind.Package or SoftwareKind.Library && (s.Purl is not null || s.Ecosystem is not null))
        { s.MappingStatus = MappingStatus.Package; s.MappedVendorNorm = null; s.MappedProductNorm = null; return; }

        // 1. adapter-supplied CPE
        if (s.Cpe is not null && s.Cpe.StartsWith("cpe:2.3:"))
        {
            var parts = s.Cpe.Split(':');
            if (parts.Length > 4)
            {
                var vn = Normalizer.Norm(parts[3]); var pn = Normalizer.Norm(parts[4].Replace('_', ' '));
                if (await db.CnaProducts.AnyAsync(p => p.VendorNorm == vn && p.ProductNorm == pn, ct)) { Set(s, MappingStatus.Exact, vn, pn); return; }
            }
        }
        // 2. an alias that names this vendor and product, or redirects within the same vendor, wins over an exact
        //    catalogue name: "Microsoft Edge" is also the retired EdgeHTML product's CNA name, and every Edge still
        //    installed is Chromium-based, so the curated alias must decide, not the coincidence of names
        var alias = aliases.FirstOrDefault(a => a.AliasNorm == s.VendorNorm + s.ProductNorm)
                    ?? aliases.FirstOrDefault(a => a.AliasNorm == s.ProductNorm && s.VendorNorm != "" && a.VendorNorm == s.VendorNorm);
        // only when the alias points at a name the catalogue actually has, so a stale alias never displaces a real match
        if (alias is not null && await db.CnaProducts.AnyAsync(p => p.VendorNorm == alias.VendorNorm && p.ProductNorm == alias.ProductNorm, ct))
        { Set(s, MappingStatus.Alias, alias.VendorNorm, alias.ProductNorm); return; }
        // 3. exact
        if (s.VendorNorm != "" && await db.CnaProducts.AnyAsync(p => p.VendorNorm == s.VendorNorm && p.ProductNorm == s.ProductNorm, ct)) { Set(s, MappingStatus.Exact, s.VendorNorm, s.ProductNorm); return; }
        // 3b. alias by product name alone (the publisher is spelt differently, or missing)
        alias = aliases.FirstOrDefault(a => a.AliasNorm == s.ProductNorm);
        if (alias is not null) { Set(s, MappingStatus.Alias, alias.VendorNorm, alias.ProductNorm); return; }
        // 4. one unambiguous fuzzy candidate from the same vendor
        if (s.VendorNorm != "" && s.ProductNorm.Length >= 5)
        {
            var cands = await db.CnaProducts.AsNoTracking().Where(p => p.VendorNorm == s.VendorNorm && (p.ProductNorm.Contains(s.ProductNorm) || s.ProductNorm.Contains(p.ProductNorm))).Take(3).ToListAsync(ct);
            if (cands.Count == 1 && cands[0].ProductNorm.Length >= 5) { Set(s, MappingStatus.Fuzzy, cands[0].VendorNorm, cands[0].ProductNorm); return; }
        }
        // 5. version-stripped product name ("Google Chrome 128" -> "chrome")
        var stripped = System.Text.RegularExpressions.Regex.Replace(s.Product, @"\s+\d+(\.\d+)*.*$", "");
        var strippedNorm = Normalizer.Norm(stripped);
        if (strippedNorm != s.ProductNorm && strippedNorm.Length >= 3)
        {
            if (await db.CnaProducts.AnyAsync(p => p.VendorNorm == s.VendorNorm && p.ProductNorm == strippedNorm, ct)) { Set(s, MappingStatus.Fuzzy, s.VendorNorm, strippedNorm); return; }
            var al = aliases.FirstOrDefault(a => a.AliasNorm == strippedNorm);
            if (al is not null) { Set(s, MappingStatus.Alias, al.VendorNorm, al.ProductNorm); return; }
        }
        s.MappingStatus = MappingStatus.Unmapped; s.MappedVendorNorm = null; s.MappedProductNorm = null;
    }

    private static void Set(SoftwareInstance s, MappingStatus st, string vn, string pn) { s.MappingStatus = st; s.MappedVendorNorm = vn; s.MappedProductNorm = pn; }

    /// <summary>Needs-mapping queue: accept a mapping for every instance with this vendor/product name, and remember it as an alias.</summary>
    public async Task AcceptMappingAsync(string vendorNorm, string productNorm, string targetVendorNorm, string targetProductNorm, string actor, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var aliasNorm = vendorNorm + productNorm;
        if (!await db.Aliases.AnyAsync(a => a.AliasNorm == aliasNorm, ct))
            db.Aliases.Add(new ProductAlias { AliasNorm = aliasNorm, VendorNorm = targetVendorNorm, ProductNorm = targetProductNorm });
        var rows = await db.Software.Where(s => s.VendorNorm == vendorNorm && s.ProductNorm == productNorm).ToListAsync(ct);
        foreach (var s in rows) Set(s, MappingStatus.Alias, targetVendorNorm, targetProductNorm);
        db.Audit.Add(new AuditEntry { At = DateTime.UtcNow, Actor = actor, Action = "mapping.accept", Target = vendorNorm + "/" + productNorm, After = targetVendorNorm + "/" + targetProductNorm + " (" + rows.Count + " instances)" });
        await db.SaveChangesAsync(ct);
    }

    public async Task IgnoreMappingAsync(string vendorNorm, string productNorm, string actor, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var rows = await db.Software.Where(s => s.VendorNorm == vendorNorm && s.ProductNorm == productNorm).ToListAsync(ct);
        foreach (var s in rows) { s.MappingStatus = MappingStatus.Ignored; s.MappedVendorNorm = null; s.MappedProductNorm = null; }
        db.Audit.Add(new AuditEntry { At = DateTime.UtcNow, Actor = actor, Action = "mapping.ignore", Target = vendorNorm + "/" + productNorm, After = rows.Count + " instances" });
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Re-run mapping for everything unmapped (after the alias table or the CVE catalogue changed).</summary>
    public async Task<int> RemapAsync(CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var aliases = await db.Aliases.AsNoTracking().ToListAsync(ct);
        var rows = await db.Software.Where(s => s.MappingStatus == MappingStatus.Unmapped || s.MappingStatus == MappingStatus.Fuzzy).ToListAsync(ct);
        var resolved = 0;
        foreach (var s in rows) { await ResolveMappingAsync(db, s, aliases, ct); if (s.MappingStatus != MappingStatus.Unmapped) resolved++; }
        await db.SaveChangesAsync(ct);
        return resolved;
    }

    // ------------------------------------------------------------------ housekeeping and coverage

    /// <summary>Not seen for 30 days is stale (excluded from digests), 90 days is archived.</summary>
    public async Task<(int Stale, int Archived)> HousekeepAsync(CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var now = DateTime.UtcNow;
        var held = (await HeldByPartialRunsAsync(db, ct)).ToList();
        var old = db.Assets.Where(a => !a.Archived && a.LastSeen < now.AddDays(-90));
        if (held.Count > 0) old = old.Where(a => !held.Contains(a.Id));
        var archived = await old.ExecuteUpdateAsync(u => u.SetProperty(a => a.Archived, true), ct);
        var stale = await db.Assets.CountAsync(a => !a.Archived && a.LastSeen < now.AddDays(-30), ct);
        return (stale, archived);
    }

    public sealed record Coverage(int Assets, int Sources, int Unknown, int Stale, List<Asset> UnknownHosts, List<Asset> UncoveredVms);

    /// <summary>Coverage: VMs the hypervisor lists that no server collector has seen, plus discovery-only hosts.</summary>
    public async Task<Coverage> CoverageAsync(CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var now = DateTime.UtcNow;
        var assets = await db.Assets.AsNoTracking().Include(a => a.Sources).Where(a => !a.Archived).ToListAsync(ct);
        var sources = assets.SelectMany(a => a.Sources.Select(s => s.ConnectorId)).Distinct().Count();
        var unknown = assets.Where(a => a.Unknown).OrderBy(a => a.DisplayName).ToList();
        var stale = assets.Count(a => a.LastSeen < now.AddDays(-30));
        var collectorAdapters = new[] { "winrm", "ssh", "forticlient-ems", "intune", "defender", "configmgr", "jamf", "kandji", "ninjaone", "datto-rmm", "n-central", "lansweeper", "pdq", "sbom" };
        var uncovered = assets.Where(a => a.Kind == AssetKind.VirtualMachine && !a.Sources.Any(s => collectorAdapters.Any(c => s.AdapterId.StartsWith(c, StringComparison.OrdinalIgnoreCase)))).OrderBy(a => a.DisplayName).ToList();
        return new Coverage(assets.Count, sources, unknown.Count, stale, unknown, uncovered);
    }

    // ------------------------------------------------------------------ helpers

    private static Criticality DefaultCriticality(AssetRecord r) => r.Kind is AssetKind.Firewall or AssetKind.Hypervisor ? Criticality.Critical : r.Criticality ?? Criticality.Standard;
    private static string NormMac(string m) => m.Replace("-", ":").Replace(".", "").ToLowerInvariant();

    /// <summary>
    /// Hostname identity for merging. FQDNs match exactly; a bare name ("SRV01" from AD or an RMM) matches an FQDN's
    /// first label only when exactly one asset carries it. IP literals, blanks and generic names ("localhost") are never
    /// keys: discovery uses the IP as the display name when there is no reverse DNS, and those must not merge.
    /// </summary>
    internal sealed class HostIndex
    {
        private readonly Dictionary<string, Asset> _full = new(StringComparer.Ordinal);
        private readonly Dictionary<string, HashSet<Asset>> _byLabel = new(StringComparer.Ordinal);

        public void Add(string? name, Asset a)
        {
            var n = NormHost(name);
            if (n is null) return;
            _full.TryAdd(n, a);
            var label = n.Split('.')[0];
            (_byLabel.TryGetValue(label, out var set) ? set : _byLabel[label] = new()).Add(a);
        }

        public Asset? Find(string? name)
        {
            var n = NormHost(name);
            if (n is null) return null;
            if (_full.TryGetValue(n, out var exact)) return exact;
            var dot = n.IndexOf('.');
            if (dot < 0)
            {
                // a bare name against FQDNs that share its first label: only when unambiguous
                return _byLabel.TryGetValue(n, out var set) && set.Count == 1 ? set.First() : null;
            }
            // an FQDN against a bare name; a different domain is a different host (www.a.com is not www.b.com)
            return _full.GetValueOrDefault(n[..dot]);
        }
    }

    private static readonly HashSet<string> GenericHosts = new(StringComparer.Ordinal)
    {
        "localhost", "localhost.localdomain", "localhost4", "localhost6", "localhost6.localdomain6", "ip6-localhost", "ip6-loopback",
        "localdomain", "unknown", "none", "(none)", "n/a", "null", "default", "-", "?",
    };

    /// <summary>Lower-cased hostname without a trailing dot, or null when it says nothing about identity.</summary>
    internal static string? NormHost(string? h)
    {
        if (string.IsNullOrWhiteSpace(h)) return null;
        var n = h.Trim().TrimEnd('.').ToLowerInvariant();
        if (n.Length == 0 || GenericHosts.Contains(n) || n.StartsWith("localhost.")) return null;
        if (IsIpLiteral(n)) return null;
        if (n.StartsWith('.') || n.Contains("..")) return null;
        return n;
    }

    private static bool IsIpLiteral(string n)
    {
        var t = n.Trim('[', ']');
        var pct = t.IndexOf('%'); if (pct > 0) t = t[..pct];
        if (t.Contains(':')) return System.Net.IPAddress.TryParse(t, out _);
        // dotted digits ("10.0.0.5") and bare numbers ("10", which IPAddress would also accept) are never hostnames
        return t.All(c => char.IsAsciiDigit(c) || c == '.');
    }
    private static bool IsPrivateShared(string ip) => ip.StartsWith("127.") || ip.StartsWith("169.254.") || ip == "0.0.0.0" || ip.StartsWith("::");
    private static string Trunc(string? s, int max) => s is null ? "" : (s.Length <= max ? s : s[..max]);
    public static List<string> Json(string? json)
    {
        try { return string.IsNullOrEmpty(json) ? new() : JsonSerializer.Deserialize<List<string>>(json) ?? new(); } catch { return new(); }
    }
    private static string MergeJson(string existing, IEnumerable<string> add)
    {
        var set = new List<string>(Json(existing));
        foreach (var v in add) if (!string.IsNullOrWhiteSpace(v) && !set.Contains(v, StringComparer.OrdinalIgnoreCase)) set.Add(v.Trim());
        return JsonSerializer.Serialize(set.Take(50));
    }
}
