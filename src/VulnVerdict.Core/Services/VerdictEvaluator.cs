using System.Diagnostics;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;

namespace VulnVerdict.Core.Services;

public sealed record EvaluationSummary(int Entries, int Candidates, int Created, int Changed, int Removed, TimeSpan Elapsed);

/// <summary>
/// Section 9.3 steps 2 to 5 for watchlist entries: find candidate CVEs by normalised vendor/product,
/// evaluate the version range, compute the four SSVC-derived inputs, run the decision table and store
/// a verdict with its evidence chain. Re-evaluated on every run; tier changes are recorded with a reason.
/// </summary>
public sealed class VerdictEvaluator
{
    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly SettingsService _settings;
    private readonly ILogger<VerdictEvaluator> _log;

    public VerdictEvaluator(IDbContextFactory<VvDbContext> factory, SettingsService settings, ILogger<VerdictEvaluator> log)
    {
        _factory = factory; _settings = settings; _log = log;
    }

    public async Task<EvaluationSummary> EvaluateAllAsync(CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        await using var db = await _factory.CreateDbContextAsync(ct);
        var entries = await db.Watchlist.AsNoTracking().ToListAsync(ct);
        var settings = await _settings.LoadAsync(ct);
        int cand = 0, created = 0, changed = 0, removed = 0;
        foreach (var e in entries)
        {
            ct.ThrowIfCancellationRequested();
            var r = await EvaluateEntryCoreAsync(db, e, settings, ct);
            cand += r.Candidates; created += r.Created; changed += r.Changed; removed += r.Removed;
        }
        await MaintainStatesAsync(db, ct);
        await _settings.SetStateAsync(SettingsService.Keys.LastEvaluation, DateTime.UtcNow.ToString("O"), ct);
        var summary = new EvaluationSummary(entries.Count, cand, created, changed, removed, sw.Elapsed);
        _log.LogInformation("Evaluated {Entries} watchlist entries: {Candidates} candidates, {Created} new, {Changed} changed, {Removed} removed in {Elapsed}", summary.Entries, summary.Candidates, summary.Created, summary.Changed, summary.Removed, summary.Elapsed);
        return summary;
    }

    public async Task<EvaluationSummary> EvaluateEntryAsync(Guid entryId, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        await using var db = await _factory.CreateDbContextAsync(ct);
        var e = await db.Watchlist.AsNoTracking().FirstOrDefaultAsync(w => w.Id == entryId, ct);
        if (e is null) return new EvaluationSummary(0, 0, 0, 0, 0, sw.Elapsed);
        var settings = await _settings.LoadAsync(ct);
        var r = await EvaluateEntryCoreAsync(db, e, settings, ct);
        await MaintainStatesAsync(db, ct);
        return r with { Entries = 1, Elapsed = sw.Elapsed };
    }

    // ------------------------------------------------------------------ candidates

    private sealed record ProductMatch(CveAffected Row, MatchConfidence Confidence, string How);

    private async Task<List<ProductMatch>> FindCandidatesAsync(VvDbContext db, WatchlistEntry e, CancellationToken ct)
    {
        var result = new List<ProductMatch>();
        var vn = e.VendorNorm; var pn = e.ProductNorm;
        if (string.IsNullOrEmpty(pn)) return result;

        // 1. exact vendor + product
        if (!string.IsNullOrEmpty(vn))
        {
            var exact = await db.CveAffected.AsNoTracking().Where(a => a.VendorNorm == vn && a.ProductNorm == pn).ToListAsync(ct);
            result.AddRange(exact.Select(a => new ProductMatch(a, MatchConfidence.Exact, "vendor and product match exactly")));
        }

        // 2. alias table
        var aliases = await db.Aliases.AsNoTracking().Where(a => a.AliasNorm == pn || a.AliasNorm == vn + pn).ToListAsync(ct);
        foreach (var al in aliases)
        {
            var rows = await db.CveAffected.AsNoTracking().Where(a => a.VendorNorm == al.VendorNorm && a.ProductNorm == al.ProductNorm).ToListAsync(ct);
            result.AddRange(rows.Select(a => new ProductMatch(a, MatchConfidence.Exact, "alias '" + e.Product + "' maps to " + a.Vendor + " / " + a.Product)));
        }

        // 3. product name contained in a longer CNA product name from the same vendor (editions, SKUs)
        if (!string.IsNullOrEmpty(vn) && pn.Length >= 5)
        {
            var contains = await db.CveAffected.AsNoTracking()
                .Where(a => a.VendorNorm == vn && a.ProductNorm != pn && a.ProductNorm.Contains(pn)).ToListAsync(ct);
            result.AddRange(contains.Select(a => new ProductMatch(a, MatchConfidence.Likely, "CNA product '" + a.Product + "' contains '" + e.Product + "'")));
        }

        // 4. no vendor given: product name across all vendors, low confidence
        if (string.IsNullOrEmpty(vn))
        {
            var any = await db.CveAffected.AsNoTracking().Where(a => a.ProductNorm == pn).ToListAsync(ct);
            result.AddRange(any.Select(a => new ProductMatch(a, MatchConfidence.Possible, "product name matches, vendor not declared")));
        }

        return result.DistinctBy(m => m.Row.Id).ToList();
    }

    // ------------------------------------------------------------------ evaluation

    private async Task<EvaluationSummary> EvaluateEntryCoreAsync(VvDbContext db, WatchlistEntry e, AppSettings settings, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        int created = 0, changed = 0, removed = 0;

        var existing = await db.Verdicts.Where(v => v.WatchlistEntryId == e.Id).ToDictionaryAsync(v => v.CveId, ct);
        if (!e.Enabled)
        {
            if (existing.Count > 0) { db.Verdicts.RemoveRange(existing.Values); removed = existing.Count; await db.SaveChangesAsync(ct); }
            return new EvaluationSummary(1, 0, 0, 0, removed, TimeSpan.Zero);
        }

        var matches = await FindCandidatesAsync(db, e, ct);
        var byCve = matches.GroupBy(m => m.Row.CveId).ToDictionary(g => g.Key, g => g.ToList());
        var ids = byCve.Keys.ToList();

        var cves = new Dictionary<string, Cve>();
        var kev = new Dictionary<string, KevEntry>();
        var epss = new Dictionary<string, EpssScore>();
        var signals = new Dictionary<string, List<ExploitSignal>>();
        foreach (var chunk in ids.Chunk(400))
        {
            foreach (var c in await db.Cves.AsNoTracking().Where(c => chunk.Contains(c.Id)).ToListAsync(ct)) cves[c.Id] = c;
            foreach (var k in await db.Kev.AsNoTracking().Where(k => chunk.Contains(k.CveId)).ToListAsync(ct)) kev[k.CveId] = k;
            foreach (var s in await db.Epss.AsNoTracking().Where(s => chunk.Contains(s.CveId)).ToListAsync(ct)) epss[s.CveId] = s;
            foreach (var s in await db.ExploitSignals.AsNoTracking().Where(s => chunk.Contains(s.CveId)).ToListAsync(ct))
                (signals.TryGetValue(s.CveId, out var l) ? l : signals[s.CveId] = new()).Add(s);
        }

        var rules = await db.Suppressions.AsNoTracking().ToListAsync(ct);
        var seen = new HashSet<string>();

        foreach (var (cveId, productMatches) in byCve)
        {
            if (!cves.TryGetValue(cveId, out var cve)) continue;
            if (cve.State.Equals("REJECTED", StringComparison.OrdinalIgnoreCase)) continue;
            seen.Add(cveId);

            var computed = Compute(e, cve, productMatches, kev.GetValueOrDefault(cveId), epss.GetValueOrDefault(cveId), signals.GetValueOrDefault(cveId) ?? new(), settings, now);

            if (existing.TryGetValue(cveId, out var v))
            {
                if (Apply(v, computed, e, now, rules, settings)) changed++;
            }
            else
            {
                v = new Verdict { Id = Guid.NewGuid(), CveId = cveId, WatchlistEntryId = e.Id, CreatedAt = now, State = VerdictState.Open };
                Apply(v, computed, e, now, rules, settings, isNew: true);
                db.Verdicts.Add(v);
                existing[cveId] = v;
                created++;
            }
        }

        var stale = existing.Values.Where(v => !seen.Contains(v.CveId)).ToList();
        if (stale.Count > 0) { db.Verdicts.RemoveRange(stale); removed = stale.Count; }

        await db.SaveChangesAsync(ct);
        db.ChangeTracker.Clear();
        return new EvaluationSummary(1, byCve.Count, created, changed, removed, TimeSpan.Zero);
    }

    private sealed record Computed(DecisionInputs Inputs, Decision Decision, MatchConfidence Confidence, bool VersionUnknown, string Sentence, string? FixedIn, List<EvidenceClaim> Evidence, double? Epss, bool InKev, CvssVector? Cvss);

    private static Computed Compute(WatchlistEntry e, Cve cve, List<ProductMatch> productMatches, KevEntry? kev, EpssScore? epss, List<ExploitSignal> signals, AppSettings settings, DateTime now)
    {
        var ev = new List<EvidenceClaim>();
        var cnaSource = "CVE List V5, " + (cve.Assigner ?? "CNA") + " container" + (cve.SourceRef is null ? "" : " (" + cve.SourceRef + ")");

        // ---- product and version match
        var productConfidence = productMatches.Max(m => m.Confidence);
        var best = productMatches.OrderByDescending(m => m.Confidence).First();
        ev.Add(new EvidenceClaim("Affected product " + best.Row.Vendor + " / " + best.Row.Product + ": " + best.How, cnaSource, cve.RetrievedAt));

        VersionMatch overall = VersionMatch.NotAffected;
        var versionConfidence = MatchConfidence.Exact;
        string? fixedIn = null;
        var explanations = new List<string>();
        foreach (var m in productMatches.OrderByDescending(m => m.Confidence))
        {
            var r = VersionMatcher.Evaluate(e.Version, VersionMatcher.ParseVersions(m.Row.VersionsJson), m.Row.DefaultStatus);
            fixedIn ??= r.FixedIn;
            explanations.Add(r.Explanation);
            if (r.Match == VersionMatch.Affected) { overall = VersionMatch.Affected; versionConfidence = r.Confidence; break; }
            if (r.Match == VersionMatch.Unknown) { overall = VersionMatch.Unknown; versionConfidence = MatchConfidence.Possible; }
        }
        ev.Add(new EvidenceClaim("Version check: " + explanations.First(), cnaSource, cve.RetrievedAt, best.Row.VersionsJson is { Length: < 400 } vj ? vj : null));
        ev.Add(new EvidenceClaim((e.AssetName ?? e.Product) + " runs " + e.Vendor + " " + e.Product + " " + (e.Version ?? "(version not declared)"), "Watchlist entry (declared by user)", e.UpdatedAt));

        var confidence = (MatchConfidence)Math.Min((int)productConfidence, (int)versionConfidence);
        var versionUnknown = overall == VersionMatch.Unknown;

        // ---- exploitation
        var exploitation = Exploitation.None;
        if (kev is not null)
        {
            exploitation = Exploitation.Active;
            ev.Add(new EvidenceClaim("Listed in CISA Known Exploited Vulnerabilities since " + kev.DateAdded.ToString("yyyy-MM-dd") + (kev.KnownRansomwareUse == "Known" ? ", known ransomware use" : ""), "CISA KEV", kev.RetrievedAt, kev.RequiredAction));
        }
        else if (string.Equals(cve.SsvcExploitation, "active", StringComparison.OrdinalIgnoreCase))
        {
            exploitation = Exploitation.Active;
            ev.Add(new EvidenceClaim("CISA Vulnrichment SSVC Exploitation: active", "CISA ADP container in CVE List V5", cve.RetrievedAt));
        }
        if (exploitation == Exploitation.None)
        {
            foreach (var s in signals.Take(4))
            {
                exploitation = Exploitation.PoC;
                ev.Add(new EvidenceClaim("Public exploit: " + SourceName(s.Source) + (s.Title is null ? "" : " - " + s.Title), s.Url, s.RetrievedAt));
            }
            if (epss is not null && epss.Score >= 0.10)
            {
                exploitation = Exploitation.PoC;
                ev.Add(new EvidenceClaim("EPSS " + epss.Score.ToString("0.00") + " (probability of exploitation in the next 30 days), at or above the 0.10 threshold", "EPSS by FIRST, scores dated " + epss.ScoreDate.ToString("yyyy-MM-dd"), epss.RetrievedAt));
            }
            else if (string.Equals(cve.SsvcExploitation, "poc", StringComparison.OrdinalIgnoreCase))
            {
                exploitation = Exploitation.PoC;
                ev.Add(new EvidenceClaim("CISA Vulnrichment SSVC Exploitation: poc", "CISA ADP container in CVE List V5", cve.RetrievedAt));
            }
        }
        if (exploitation == Exploitation.None)
        {
            var epssNote = epss is not null ? "EPSS " + epss.Score.ToString("0.000") + (epss.Score >= 0.02 ? " (signal: between 0.02 and 0.10)" : "") : "no EPSS score";
            ev.Add(new EvidenceClaim("No known exploitation: not in KEV, no public exploit indexed, " + epssNote, "CISA KEV, Exploit-DB, Metasploit, Nuclei, EPSS", now));
        }

        // ---- automatable and attack path
        var cvss = CvssVector.Parse(cve.CvssV40Vector) ?? CvssVector.Parse(cve.CvssV31Vector);
        var automatable = cvss?.Automatable == true;
        var attackVector = cvss?.AttackVector ?? AttackVector.Unknown;
        if (cvss is not null)
            ev.Add(new EvidenceClaim("CVSS " + cvss.Version + " vector: attack vector " + cvss.AttackVector + ", complexity " + cvss.AttackComplexity + ", privileges " + cvss.PrivilegesRequired + ", user interaction " + cvss.UserInteraction + (automatable ? " (automatable)" : " (not automatable)"), cnaSource, cve.RetrievedAt, cvss.Raw));
        else
            ev.Add(new EvidenceClaim("No CVSS vector supplied by the CNA or CISA; treated as network-reachable and not automatable", cnaSource, cve.RetrievedAt));
        if (string.Equals(cve.SsvcAutomatable, "yes", StringComparison.OrdinalIgnoreCase))
        {
            automatable = true;
            ev.Add(new EvidenceClaim("CISA Vulnrichment SSVC Automatable: yes", "CISA ADP container in CVE List V5", cve.RetrievedAt));
        }
        // no vector at all: do not let the exposure cap fire
        if (attackVector == AttackVector.Unknown) attackVector = AttackVector.Network;

        // ---- exposure and criticality
        var declared = overall == VersionMatch.NotAffected ? Exposure.NotInstalled : e.Exposure;
        var inputs = new DecisionInputs(exploitation, automatable, attackVector, declared, e.Criticality);
        ev.Add(new EvidenceClaim("Exposure " + inputs.DeclaredExposure.Plain() + (inputs.ExposureCapped ? ", treated as internal because the attack vector is " + attackVector.ToString().ToLowerInvariant() : "") + "; criticality " + e.Criticality, "Watchlist entry (declared by user)", e.UpdatedAt));

        var decision = DecisionTable.Evaluate(inputs);
        ev.Add(new EvidenceClaim("Decision table rule " + decision.Rule + ": " + DecisionTable.RuleText(decision.Rule) + " => " + decision.Tier.Plain(), "VulnVerdict decision table (section 6.3)", now));

        var sentence = SentenceBuilder.Build(e, inputs, cvss, decision.Tier, fixedIn, confidence, versionUnknown);
        return new Computed(inputs, decision, confidence, versionUnknown, sentence, fixedIn, ev, epss?.Score, kev is not null, cvss);
    }

    private static string SourceName(string s) => s switch
    {
        FeedNamesText.ExploitDb => "Exploit-DB",
        FeedNamesText.Metasploit => "Metasploit module",
        FeedNamesText.Nuclei => "Nuclei template",
        _ => s
    };

    private static class FeedNamesText { public const string ExploitDb = "exploitdb"; public const string Metasploit = "metasploit"; public const string Nuclei = "nuclei"; }

    /// <summary>Copy a computed result onto a verdict row. Returns true if the tier changed.</summary>
    private static bool Apply(Verdict v, Computed c, WatchlistEntry e, DateTime now, List<SuppressionRule> rules, AppSettings settings, bool isNew = false)
    {
        var tierChanged = !isNew && v.Tier != c.Decision.Tier;
        string? reason = null;
        if (tierChanged)
        {
            reason = c.InKev && !v.InKev ? "now in CISA KEV"
                : c.Inputs.Exploitation > v.Exploitation ? "public exploit published"
                : c.Inputs.Exploitation < v.Exploitation ? "exploit evidence withdrawn"
                : c.Inputs.DeclaredExposure != v.DeclaredExposure ? "exposure changed to " + c.Inputs.DeclaredExposure.Plain().ToLowerInvariant()
                : c.Inputs.Criticality != v.Criticality ? "criticality changed to " + c.Inputs.Criticality
                : c.Inputs.Automatable != v.Automatable ? "attack path re-assessed"
                : "inputs changed";
            v.History.Add(new VerdictHistory { At = now, Actor = "system", Kind = "tier", From = v.Tier.ToString(), To = c.Decision.Tier.ToString(), Reason = reason });
            v.PreviousTier = v.Tier;
            v.TierChangedAt = now;
            v.TierChangeReason = reason;
            var promoted = c.Decision.Tier > v.Tier;
            if (promoted)
            {
                if (c.Decision.Tier == VerdictTier.FixToday) v.ImmediateEmailSentAt = null;
                if (c.Decision.Tier >= VerdictTier.FixThisWeek) v.TicketSentAt = null;
                if (v.State is VerdictState.Snoozed or VerdictState.AcceptedRisk)
                {
                    v.History.Add(new VerdictHistory { At = now, Actor = "system", Kind = "state", From = v.State.ToString(), To = VerdictState.Open.ToString(), Reason = "re-opened: promoted to " + c.Decision.Tier.Plain() + " (" + reason + ")" });
                    v.State = VerdictState.Open; v.StateReason = null; v.SnoozedUntil = null; v.AcceptedRiskExpiry = null; v.StateChangedAt = now;
                }
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
        v.Sentence = c.Sentence.Length > 1000 ? c.Sentence[..1000] : c.Sentence;
        v.FixedIn = c.FixedIn is { Length: > 200 } ? c.FixedIn[..200] : c.FixedIn;
        v.EvidenceJson = JsonSerializer.Serialize(c.Evidence);
        v.LastEvaluatedAt = now;
        v.UpdatedAt = now;

        if (isNew || tierChanged)
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

        // suppression rules
        if (v.State is VerdictState.Open or VerdictState.Suppressed)
        {
            var rule = rules.FirstOrDefault(r => !r.IsExpired(now) && SuppressionMatcher.Matches(r, v, e));
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
        return tierChanged;
    }

    /// <summary>Expire snoozes and accepted risks.</summary>
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
    public static bool Matches(SuppressionRule r, Verdict v, WatchlistEntry e) => r.Scope switch
    {
        SuppressionScope.Cve => string.Equals(r.CveId, v.CveId, StringComparison.OrdinalIgnoreCase),
        SuppressionScope.Product => r.VendorNorm == e.VendorNorm && r.ProductNorm == e.ProductNorm,
        SuppressionScope.WatchlistEntry => r.WatchlistEntryId == e.Id,
        _ => false
    };
}
