using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;

namespace VulnVerdict.Core.Services;

/// <summary>Verdict state workflow: done, snooze, suppress, accept risk, reopen. Every change is audited.</summary>
public sealed class VerdictWorkflow
{
    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly SettingsService _settings;
    private readonly WebhookService _webhooks;
    private readonly WatchlistService _watchlist;

    public VerdictWorkflow(IDbContextFactory<VvDbContext> factory, SettingsService settings, WebhookService webhooks, WatchlistService watchlist)
    {
        _factory = factory; _settings = settings; _webhooks = webhooks; _watchlist = watchlist;
    }

    public Task CloseAsync(Guid id, string actor, string reason, CancellationToken ct = default) =>
        ChangeStateAsync(id, actor, VerdictState.Closed, reason, v => { v.StateOwner = actor; }, ct);

    /// <summary>What marking a verdict done at a version did.</summary>
    /// <param name="WatchlistUpdated">The watchlist entry's version was changed.</param>
    /// <param name="OthersClosed">Other verdicts on the same entry that the new version fixes, closed by the re-evaluation.</param>
    /// <param name="StillAffected">Verdicts on the entry that still affect the new version and remain open.</param>
    /// <param name="ThisStillListed">The CVE just marked done still lists the new version as affected.</param>
    public sealed record DoneResult(bool WatchlistUpdated, string? FromVersion, string? ToVersion, int OthersClosed, int StillAffected, bool ThisStillListed);

    /// <summary>
    /// Mark a verdict done, optionally recording the version now running. With <paramref name="updateWatchlist"/> the
    /// watchlist entry moves to that version and is re-evaluated, so every other verdict the upgrade fixes closes too
    /// (each with its own history line); anything the new version is still affected by stays open.
    /// </summary>
    public async Task<DoneResult> DoneAsync(Guid id, string actor, string? runningVersion, bool updateWatchlist, string? note, CancellationToken ct = default)
    {
        runningVersion = string.IsNullOrWhiteSpace(runningVersion) ? null : runningVersion.Trim();
        note = string.IsNullOrWhiteSpace(note) ? null : note.Trim();
        WatchlistEntry? entry;
        await using (var db = await _factory.CreateDbContextAsync(ct))
        {
            var v = await db.Verdicts.AsNoTracking().Include(x => x.WatchlistEntry).FirstOrDefaultAsync(x => x.Id == id, ct)
                    ?? throw new KeyNotFoundException("Verdict not found");
            entry = v.WatchlistEntry;
        }

        var reason = (note, runningVersion) switch
        {
            (null, null) => "marked done",
            (null, _) => "marked done: now running " + runningVersion,
            (_, null) => note!,
            _ => note + " (now running " + runningVersion + ")",
        };
        await CloseAsync(id, actor, reason, ct);

        if (!updateWatchlist || runningVersion is null || entry is null || entry.Version == runningVersion)
            return new DoneResult(false, entry?.Version, entry?.Version, 0, 0, false);

        var fromVersion = entry.Version;
        List<Guid> openBefore;
        await using (var db = await _factory.CreateDbContextAsync(ct))
            openBefore = await db.Verdicts.Where(x => x.WatchlistEntryId == entry.Id && x.Id != id
                                                      && (x.State == VerdictState.Open || x.State == VerdictState.Snoozed || x.State == VerdictState.AcceptedRisk))
                                          .Select(x => x.Id).ToListAsync(ct);

        entry.Version = runningVersion;
        await _watchlist.UpsertAsync(entry, actor, ct);   // re-evaluates the entry; fixed verdicts close themselves

        await using (var db = await _factory.CreateDbContextAsync(ct))
        {
            var after = await db.Verdicts.AsNoTracking().Where(x => x.WatchlistEntryId == entry.Id)
                                .Select(x => new { x.Id, x.State, x.Tier }).ToListAsync(ct);
            var othersClosed = after.Count(x => openBefore.Contains(x.Id) && x.State == VerdictState.Closed);
            var stillAffected = after.Count(x => x.Id != id && x.Tier > VerdictTier.NotAffected
                                                 && x.State is VerdictState.Open or VerdictState.Snoozed or VerdictState.AcceptedRisk);
            var thisStill = after.FirstOrDefault(x => x.Id == id)?.Tier > VerdictTier.NotAffected;
            return new DoneResult(true, fromVersion, runningVersion, othersClosed, stillAffected, thisStill);
        }
    }

    public Task ReopenAsync(Guid id, string actor, CancellationToken ct = default) =>
        ChangeStateAsync(id, actor, VerdictState.Open, "re-opened manually", v => { v.SnoozedUntil = null; v.AcceptedRiskExpiry = null; v.SuppressedByRuleId = null; v.StateOwner = null; }, ct);

    public Task SnoozeAsync(Guid id, string actor, DateTime untilUtc, string reason, CancellationToken ct = default) =>
        ChangeStateAsync(id, actor, VerdictState.Snoozed, reason + " (until " + untilUtc.ToString("d MMM yyyy") + ")", v => { v.SnoozedUntil = untilUtc; v.StateOwner = actor; }, ct);

    public Task AcceptRiskAsync(Guid id, string actor, string owner, string reason, DateTime? expiryUtc, CancellationToken ct = default) =>
        ChangeStateAsync(id, actor, VerdictState.AcceptedRisk, reason, v => { v.AcceptedRiskExpiry = expiryUtc; v.StateOwner = owner; }, ct);

    private async Task ChangeStateAsync(Guid id, string actor, VerdictState to, string reason, Action<Verdict> mutate, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var v = await db.Verdicts.FirstOrDefaultAsync(x => x.Id == id, ct) ?? throw new KeyNotFoundException("Verdict not found");
        var now = DateTime.UtcNow;
        var from = v.State;
        v.State = to; v.StateReason = reason; v.StateChangedAt = now; v.UpdatedAt = now;
        mutate(v);
        db.VerdictHistory.Add(new VerdictHistory { VerdictId = v.Id, At = now, Actor = actor, Kind = "state", From = from.ToString(), To = to.ToString(), Reason = reason });
        db.Audit.Add(new AuditEntry { At = now, Actor = actor, Action = "verdict." + to.ToString().ToLowerInvariant(), Target = v.CveId + " / " + (v.WatchlistEntryId ?? v.SoftwareInstanceId), Before = from.ToString(), After = to.ToString() + ": " + reason });
        await db.SaveChangesAsync(ct);
        // the web process closes tickets directly; deliver the webhook now rather than through the worker queue
        if (to == VerdictState.Closed) await _webhooks.NotifyAsync(WebhookService.EventClosed, v, ct);
    }

    // ------------------------------------------------------------------ suppression rules

    public async Task<SuppressionRule> AddSuppressionAsync(SuppressionRule rule, string actor, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var now = DateTime.UtcNow;
        rule.Id = rule.Id == Guid.Empty ? Guid.NewGuid() : rule.Id;
        rule.CreatedAt = now; rule.CreatedBy = actor;
        if (rule.Scope == SuppressionScope.Cve) rule.CveId = rule.CveId?.Trim().ToUpperInvariant();
        db.Suppressions.Add(rule);
        db.Audit.Add(new AuditEntry { At = now, Actor = actor, Action = "suppression.add", Target = rule.Describe(), After = rule.Reason });

        // apply immediately to open verdicts
        var open = await db.Verdicts.Include(v => v.WatchlistEntry).Where(v => v.State == VerdictState.Open).ToListAsync(ct);
        foreach (var v in open.Where(v => v.WatchlistEntry is not null && SuppressionMatcher.Matches(rule, v, v.WatchlistEntry!)))
        {
            v.State = VerdictState.Suppressed; v.SuppressedByRuleId = rule.Id; v.StateReason = rule.Reason; v.StateOwner = rule.Owner; v.StateChangedAt = now; v.UpdatedAt = now;
            db.VerdictHistory.Add(new VerdictHistory { VerdictId = v.Id, At = now, Actor = actor, Kind = "state", From = "Open", To = "Suppressed", Reason = "suppression rule: " + rule.Reason });
        }
        await db.SaveChangesAsync(ct);
        return rule;
    }

    public async Task RemoveSuppressionAsync(Guid ruleId, string actor, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var rule = await db.Suppressions.FirstOrDefaultAsync(r => r.Id == ruleId, ct);
        if (rule is null) return;
        var now = DateTime.UtcNow;
        db.Suppressions.Remove(rule);
        db.Audit.Add(new AuditEntry { At = now, Actor = actor, Action = "suppression.remove", Target = rule.Describe(), Before = rule.Reason });
        var affected = await db.Verdicts.Where(v => v.SuppressedByRuleId == ruleId).ToListAsync(ct);
        foreach (var v in affected)
        {
            v.State = VerdictState.Open; v.SuppressedByRuleId = null; v.StateReason = null; v.StateOwner = null; v.StateChangedAt = now; v.UpdatedAt = now;
            db.VerdictHistory.Add(new VerdictHistory { VerdictId = v.Id, At = now, Actor = actor, Kind = "state", From = "Suppressed", To = "Open", Reason = "suppression rule removed" });
        }
        await db.SaveChangesAsync(ct);
    }
}

/// <summary>Watchlist maintenance. Any change requests a re-evaluation of that entry.</summary>
public sealed class WatchlistService
{
    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly VerdictEvaluator _evaluator;

    public WatchlistService(IDbContextFactory<VvDbContext> factory, VerdictEvaluator evaluator)
    {
        _factory = factory; _evaluator = evaluator;
    }

    public async Task<WatchlistEntry> UpsertAsync(WatchlistEntry input, string actor, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var now = DateTime.UtcNow;
        input.Vendor = input.Vendor.Trim(); input.Product = input.Product.Trim();
        input.Version = string.IsNullOrWhiteSpace(input.Version) ? null : input.Version.Trim();
        input.AssetName = string.IsNullOrWhiteSpace(input.AssetName) ? null : input.AssetName.Trim();
        input.VendorNorm = Normalizer.Norm(input.Vendor);
        input.ProductNorm = Normalizer.Norm(input.Product);
        if (input.ProductNorm == "") throw new ArgumentException("Product is required");

        WatchlistEntry entry;
        var existing = input.Id == Guid.Empty ? null : await db.Watchlist.FirstOrDefaultAsync(w => w.Id == input.Id, ct);
        var matchingChanged = false;
        if (existing is null)
        {
            entry = input; entry.Id = Guid.NewGuid(); entry.CreatedAt = now; entry.UpdatedAt = now;
            db.Watchlist.Add(entry);
            db.Audit.Add(new AuditEntry { At = now, Actor = actor, Action = "watchlist.add", Target = entry.DisplayName, After = Describe(entry) });
        }
        else
        {
            var before = Describe(existing);
            matchingChanged = existing.VendorNorm != input.VendorNorm || existing.ProductNorm != input.ProductNorm;
            existing.Vendor = input.Vendor; existing.Product = input.Product; existing.VendorNorm = input.VendorNorm; existing.ProductNorm = input.ProductNorm;
            existing.Version = input.Version; existing.Cpe = input.Cpe; existing.AssetName = input.AssetName; existing.Exposure = input.Exposure;
            existing.Criticality = input.Criticality; existing.Note = input.Note; existing.Enabled = input.Enabled; existing.UpdatedAt = now;
            entry = existing;
            db.Audit.Add(new AuditEntry { At = now, Actor = actor, Action = "watchlist.update", Target = entry.DisplayName, Before = before, After = Describe(entry) });
            if (matchingChanged) await db.Verdicts.Where(v => v.WatchlistEntryId == entry.Id).ExecuteDeleteAsync(ct);
        }
        await db.SaveChangesAsync(ct);
        await _evaluator.EvaluateEntryAsync(entry.Id, ct);
        return entry;
    }

    public async Task DeleteAsync(Guid id, string actor, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var entry = await db.Watchlist.FirstOrDefaultAsync(w => w.Id == id, ct);
        if (entry is null) return;
        db.Watchlist.Remove(entry);
        db.Audit.Add(new AuditEntry { At = DateTime.UtcNow, Actor = actor, Action = "watchlist.delete", Target = entry.DisplayName, Before = Describe(entry) });
        await db.SaveChangesAsync(ct);
    }

    /// <summary>Autocomplete from the CNA product catalogue.</summary>
    public async Task<List<CnaProduct>> SearchProductsAsync(string term, int limit = 15, CancellationToken ct = default)
    {
        var n = Normalizer.Norm(term);
        if (n.Length < 2) return new();
        await using var db = await _factory.CreateDbContextAsync(ct);
        return await db.CnaProducts.AsNoTracking()
            .Where(p => p.ProductNorm.Contains(n) || p.VendorNorm.Contains(n) || (p.VendorNorm + p.ProductNorm).Contains(n))
            .OrderByDescending(p => p.ProductNorm == n || p.VendorNorm + p.ProductNorm == n)
            .ThenByDescending(p => p.CveCount)
            .Take(limit).ToListAsync(ct);
    }

    public sealed class ImportRow
    {
        public string Vendor { get; set; } = "";
        public string Product { get; set; } = "";
        public string? Version { get; set; }
        public string? AssetName { get; set; }
        public string? Exposure { get; set; }
        public string? Criticality { get; set; }
        public string? Note { get; set; }
    }

    /// <summary>Import a JSON array of ImportRow: the "watchlist as a file" route.</summary>
    public async Task<int> ImportJsonAsync(string json, string actor, CancellationToken ct = default)
    {
        var rows = JsonSerializer.Deserialize<List<ImportRow>>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new();
        var n = 0;
        foreach (var r in rows)
        {
            if (string.IsNullOrWhiteSpace(r.Product)) continue;
            await UpsertAsync(new WatchlistEntry
            {
                Vendor = r.Vendor ?? "", Product = r.Product, Version = r.Version, AssetName = r.AssetName, Note = r.Note,
                Exposure = Enum.TryParse<Exposure>(r.Exposure, true, out var ex) ? ex : Exposure.Internal,
                Criticality = Enum.TryParse<Criticality>(r.Criticality, true, out var cr) ? cr : Criticality.Standard
            }, actor, ct);
            n++;
        }
        return n;
    }

    public async Task<string> ExportJsonAsync(CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var rows = await db.Watchlist.AsNoTracking().OrderBy(w => w.Vendor).ThenBy(w => w.Product).Select(w => new ImportRow
        {
            Vendor = w.Vendor, Product = w.Product, Version = w.Version, AssetName = w.AssetName, Exposure = w.Exposure.ToString(), Criticality = w.Criticality.ToString(), Note = w.Note
        }).ToListAsync(ct);
        return JsonSerializer.Serialize(rows, new JsonSerializerOptions { WriteIndented = true, DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });
    }

    private static string Describe(WatchlistEntry e) => e.Vendor + " " + e.Product + " " + (e.Version ?? "-") + " on " + (e.AssetName ?? "-") + ", " + e.Exposure + ", " + e.Criticality + (e.Enabled ? "" : ", disabled");
}
