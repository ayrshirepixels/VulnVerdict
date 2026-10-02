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
        SetState(db, v, actor, to, reason, mutate, DateTime.UtcNow);
        // queued in the same save, so the worker sends it even if this process stops here; tried now as well, so a
        // helpdesk that closes its ticket on this event hears straight away
        var queued = to == VerdictState.Closed ? await _webhooks.EnqueueAsync(db, new[] { (WebhookService.EventClosed, v.Id) }, ct) : null;
        await db.SaveChangesAsync(ct);
        if (queued is { Count: > 0 }) await _webhooks.DeliverNowAsync(queued, ct);
    }

    /// <summary>One state change on a tracked verdict, with its history line and audit entry. The caller saves.</summary>
    private static void SetState(VvDbContext db, Verdict v, string actor, VerdictState to, string reason, Action<Verdict> mutate, DateTime now)
    {
        var from = v.State;
        v.State = to; v.StateReason = reason; v.StateChangedAt = now; v.UpdatedAt = now;
        mutate(v);
        db.VerdictHistory.Add(new VerdictHistory { VerdictId = v.Id, At = now, Actor = actor, Kind = "state", From = from.ToString(), To = to.ToString(), Reason = reason });
        db.Audit.Add(new AuditEntry { At = now, Actor = actor, Action = "verdict." + to.ToString().ToLowerInvariant(), Target = v.CveId + " / " + (v.WatchlistEntryId ?? v.SoftwareInstanceId), Before = from.ToString(), After = to.ToString() + ": " + reason });
    }

    // ------------------------------------------------------------------ bulk

    public enum BulkAction { Done, Snooze, AcceptRisk, Reopen }

    /// <summary>A selected verdict as the page last showed it. If it has moved on since, the bulk action leaves it alone.</summary>
    public sealed record BulkItem(Guid Id, VerdictState State, DateTime? StateChangedAt, VerdictTier Tier);

    /// <param name="Reason">Note for Done, reason for Snooze and Accept risk. Blank takes the same default as the single action.</param>
    /// <param name="UntilUtc">Snooze: until when (required). Accept risk: optional expiry.</param>
    /// <param name="Owner">Accept risk: who is accountable. Blank means the person doing it.</param>
    public sealed record BulkRequest(BulkAction Action, IReadOnlyCollection<BulkItem> Items, string? Reason = null, DateTime? UntilUtc = null, string? Owner = null);

    /// <param name="Changed">Verdicts the action was applied to.</param>
    /// <param name="Skipped">Why the rest were left alone, with how many for each reason.</param>
    public sealed record BulkResult(BulkAction Action, int Changed, IReadOnlyList<(string Why, int Count)> Skipped)
    {
        /// <summary>"12 marked done. 2 skipped: already closed."</summary>
        public string Summary =>
            Changed + " " + Action switch { BulkAction.Done => "marked done", BulkAction.Snooze => "snoozed", BulkAction.AcceptRisk => "accepted as risk", _ => "re-opened" } + "."
            + (Skipped.Count == 0 ? "" : " " + Skipped.Sum(s => s.Count) + " skipped: " + string.Join(", ", Skipped.Select(s => Skipped.Count == 1 ? s.Why : s.Count + " " + s.Why)) + ".");
    }

    /// <summary>The most one bulk action takes. Everything is one save, so the batch has to stay a sensible size.</summary>
    public const int MaxBulk = 2000;

    /// <summary>Same rule the pages apply: Operator or Administrator. Checked here as well, so no caller can skip it.</summary>
    public static bool CanOperate(System.Security.Claims.ClaimsPrincipal? user) =>
        user?.Identity?.IsAuthenticated == true && (user.IsInRole(nameof(UserRole.Administrator)) || user.IsInRole(nameof(UserRole.Operator)));

    /// <summary>Whether the action makes sense in this state: the same rule that shows or hides the single buttons.</summary>
    public static bool Applies(BulkAction action, VerdictState state) => action switch
    {
        BulkAction.Done => state != VerdictState.Closed,
        BulkAction.Reopen => state != VerdictState.Open,
        _ => state == VerdictState.Open
    };

    /// <summary>"12 verdicts: 3 Fix today, 9 Fix this week", most urgent first. For the confirmation.</summary>
    public static string TierSummary(IEnumerable<VerdictTier> tiers)
    {
        var groups = tiers.GroupBy(t => t).OrderByDescending(g => g.Key).Select(g => g.Count() + " " + g.Key.Plain()).ToList();
        var n = tiers.Count();
        return n + " verdict" + (n == 1 ? "" : "s") + (n == 0 ? "" : ": " + string.Join(", ", groups));
    }

    /// <summary>
    /// Apply one action to many verdicts. Each gets its own history line and audit entry, exactly as if done singly,
    /// and they are saved together: all of them or none. A verdict whose state or tier is no longer what the page
    /// showed (<see cref="BulkItem"/>) is skipped and counted, never overwritten. Closed verdicts send their webhook
    /// after the save, as the single action does. Bulk Done does not move a watchlist version; that stays a single action.
    /// </summary>
    public async Task<BulkResult> BulkAsync(System.Security.Claims.ClaimsPrincipal? user, BulkRequest req, CancellationToken ct = default)
    {
        if (!CanOperate(user)) throw new UnauthorizedAccessException("Changing verdicts needs the Operator role or above.");
        if (req.Items.Count > MaxBulk) throw new ArgumentException("At most " + MaxBulk + " verdicts can be changed at once. Narrow the filter and do it in parts.");
        if (req.Action == BulkAction.Snooze && req.UntilUtc is null) throw new ArgumentException("Snooze needs a date.");
        var actor = user!.Identity?.Name ?? "unknown";
        var note = string.IsNullOrWhiteSpace(req.Reason) ? null : req.Reason.Trim();
        var owner = string.IsNullOrWhiteSpace(req.Owner) ? actor : req.Owner.Trim();

        var seen = req.Items.GroupBy(i => i.Id).ToDictionary(g => g.Key, g => g.First());
        var skipped = new Dictionary<string, int>();
        void Skip(string why) => skipped[why] = skipped.GetValueOrDefault(why) + 1;
        var closed = new List<Verdict>();
        List<OutboxMessage>? queued = null;
        var changed = 0;

        await using (var db = await _factory.CreateDbContextAsync(ct))
        {
            var rows = new List<Verdict>();
            foreach (var chunk in seen.Keys.Chunk(400))
                rows.AddRange(await db.Verdicts.Where(v => chunk.Contains(v.Id)).ToListAsync(ct));
            for (var i = rows.Count; i < seen.Count; i++) Skip("removed since the page loaded");

            var now = DateTime.UtcNow;
            foreach (var v in rows)
            {
                var was = seen[v.Id];
                if (v.State != was.State)
                {
                    Skip(v.State switch
                    {
                        VerdictState.Closed => "already closed",
                        VerdictState.Open => "open again",
                        VerdictState.Snoozed => "already snoozed",
                        VerdictState.AcceptedRisk => "risk already accepted",
                        _ => "already suppressed"
                    });
                    continue;
                }
                if (v.StateChangedAt != was.StateChangedAt) { Skip("changed since the page loaded"); continue; }
                // the confirmation named the tiers; a verdict that has since been promoted or demoted is not what was confirmed
                if (v.Tier != was.Tier) { Skip("now " + v.Tier.Plain()); continue; }
                if (!Applies(req.Action, v.State))
                {
                    Skip(req.Action switch { BulkAction.Done => "already closed", BulkAction.Reopen => "already open", _ => "not open" });
                    continue;
                }

                switch (req.Action)
                {
                    case BulkAction.Done:
                        SetState(db, v, actor, VerdictState.Closed, note ?? "marked done", x => { x.StateOwner = actor; }, now);
                        closed.Add(v);
                        break;
                    case BulkAction.Snooze:
                        var until = req.UntilUtc!.Value;
                        SetState(db, v, actor, VerdictState.Snoozed, (note ?? "snoozed") + " (until " + until.ToString("d MMM yyyy") + ")", x => { x.SnoozedUntil = until; x.StateOwner = actor; }, now);
                        break;
                    case BulkAction.AcceptRisk:
                        SetState(db, v, actor, VerdictState.AcceptedRisk, note ?? "risk accepted", x => { x.AcceptedRiskExpiry = req.UntilUtc; x.StateOwner = owner; }, now);
                        break;
                    case BulkAction.Reopen:
                        SetState(db, v, actor, VerdictState.Open, "re-opened manually", x => { x.SnoozedUntil = null; x.AcceptedRiskExpiry = null; x.SuppressedByRuleId = null; x.StateOwner = null; }, now);
                        break;
                }
                changed++;
            }
            // the same webhook the single Done sends, queued in the same save so the worker sends whatever is not
            // delivered straight away
            if (closed.Count > 0) queued = await _webhooks.EnqueueAsync(db, closed.Select(v => (WebhookService.EventClosed, v.Id)).ToList(), ct);
            if (changed > 0) await db.SaveChangesAsync(ct);   // one save: every history line and audit entry, or none
        }

        // tried now, a few at a time so a slow receiver does not hold the page for long; the worker retries the rest
        foreach (var batch in (queued ?? new()).Chunk(8))
            await _webhooks.DeliverNowAsync(batch, ct);

        return new BulkResult(req.Action, changed, skipped.OrderByDescending(s => s.Value).ThenBy(s => s.Key, StringComparer.Ordinal).Select(s => (s.Key, s.Value)).ToList());
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
