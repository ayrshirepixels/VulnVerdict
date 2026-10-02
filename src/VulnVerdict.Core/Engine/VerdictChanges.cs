using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Engine;

/// <summary>
/// The decision inputs behind a verdict at one evaluation, with the pieces of evidence that explain them. Short JSON
/// names: a before and an after have to fit one history line together.
/// </summary>
public sealed record VerdictSnapshot
{
    [JsonPropertyName("t")] public VerdictTier Tier { get; init; }
    [JsonPropertyName("r")] public int Rule { get; init; }
    [JsonPropertyName("x")] public Exploitation Exploitation { get; init; }
    [JsonPropertyName("au")] public bool Automatable { get; init; }
    [JsonPropertyName("av")] public AttackVector AttackVector { get; init; }
    [JsonPropertyName("de")] public Exposure DeclaredExposure { get; init; }
    [JsonPropertyName("ee")] public Exposure EffectiveExposure { get; init; }
    [JsonPropertyName("cr")] public Criticality Criticality { get; init; }
    [JsonPropertyName("ep")] public double? Epss { get; init; }
    [JsonPropertyName("k")] public bool InKev { get; init; }
    /// <summary>Date the CVE was added to CISA KEV, yyyy-MM-dd.</summary>
    [JsonPropertyName("kd")] public string? KevSince { get; init; }
    /// <summary>Installed version at this evaluation. Not known for the "before" side of a change.</summary>
    [JsonPropertyName("v")] public string? Version { get; init; }
    /// <summary>The version check from the evidence chain, e.g. "7.2.3 is inside the affected range 7.0.0 &lt; 7.2.7".</summary>
    [JsonPropertyName("vc")] public string? VersionCheck { get; init; }
    /// <summary>The evidence claim behind the exploitation status, other than KEV and EPSS.</summary>
    [JsonPropertyName("xe")] public string? ExploitEvidence { get; init; }
    /// <summary>The compensating control applied, if any.</summary>
    [JsonPropertyName("m")] public string? Control { get; init; }
}

/// <summary>One line of the "what changed and why" timeline on a verdict.</summary>
/// <param name="RuleBefore">Decision-table rule that matched before the change, when the evaluation recorded its inputs.</param>
/// <param name="RuleAfter">Decision-table rule that matched after it.</param>
public sealed record TimelineEntry(DateTime At, string Actor, string Text, string? RuleBefore = null, string? RuleAfter = null);

/// <summary>
/// "What changed and why" for a verdict. When an evaluation changes a verdict's inputs, the evaluator stores the
/// inputs before and after as one extra history line (kind "inputs", JSON in the reason). The timeline is built from
/// those lines and the tier and state lines beside them. Deterministic text only: no model is involved.
/// </summary>
public static partial class VerdictChanges
{
    /// <summary>History kind of the before-and-after line.</summary>
    public const string Kind = "inputs";
    /// <summary>EPSS at or above this counts as a public-exploit signal (see VerdictEvaluator).</summary>
    public const double EpssThreshold = 0.10;
    /// <summary>VerdictHistory.Reason holds 1000 characters.</summary>
    private const int MaxPacked = 1000;

    private static readonly JsonSerializerOptions Json = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,   // "<" and "'" stay one character; the text is only ever rendered encoded
    };

    private sealed record Pair([property: JsonPropertyName("b")] VerdictSnapshot Before, [property: JsonPropertyName("a")] VerdictSnapshot After);

    // ------------------------------------------------------------------ recording (called by the evaluator)

    /// <summary>The snapshot for the evaluation that has just been computed.</summary>
    public static VerdictSnapshot Snapshot(DecisionInputs inputs, Decision decision, double? epss, bool inKev, string? version, IReadOnlyList<EvidenceClaim> evidence, IReadOnlyList<string> modifiers) =>
        Build(decision.Tier, decision.Rule, inputs.Exploitation, inputs.Automatable, inputs.AttackVector, inputs.DeclaredExposure, inputs.EffectiveExposure, inputs.Criticality,
            epss, inKev, version, evidence, modifiers);

    /// <summary>The snapshot a verdict row holds from its last evaluation.</summary>
    public static VerdictSnapshot Snapshot(Verdict v) =>
        Build(v.Tier, v.RuleNumber, v.Exploitation, v.Automatable, v.AttackVector, v.DeclaredExposure, v.EffectiveExposure, v.Criticality,
            v.Epss, v.InKev, null, Parse<List<EvidenceClaim>>(v.EvidenceJson) ?? new(), Parse<List<string>>(v.AppliedModifiersJson) ?? new());

    private static VerdictSnapshot Build(VerdictTier tier, int rule, Exploitation exploitation, bool automatable, AttackVector attackVector, Exposure declared, Exposure effective,
        Criticality criticality, double? epss, bool inKev, string? version, IReadOnlyList<EvidenceClaim> evidence, IReadOnlyList<string> modifiers)
    {
        const string kevPrefix = "Listed in CISA Known Exploited Vulnerabilities since ";
        const string versionPrefix = "Version check: ";
        var kev = evidence.FirstOrDefault(e => e.Claim.StartsWith(kevPrefix, StringComparison.Ordinal))?.Claim;
        var exploit = evidence.FirstOrDefault(e => e.Claim.StartsWith("CISA Vulnrichment SSVC Exploitation:", StringComparison.Ordinal)
                                                   || e.Claim.StartsWith("Public exploit: ", StringComparison.Ordinal)
                                                   || (e.Claim.StartsWith("Vendor advisory ", StringComparison.Ordinal) && e.Claim.Contains("exploited in the wild", StringComparison.Ordinal)))?.Claim;
        return new VerdictSnapshot
        {
            Tier = tier, Rule = rule, Exploitation = exploitation, Automatable = automatable, AttackVector = attackVector,
            DeclaredExposure = declared, EffectiveExposure = effective, Criticality = criticality,
            Epss = epss is null ? null : Math.Round(epss.Value, 4), InKev = inKev,
            KevSince = kev is not null && kev.Length >= kevPrefix.Length + 10 ? kev.Substring(kevPrefix.Length, 10) : null,
            Version = Cut(version?.Trim(), 40),
            VersionCheck = Cut(evidence.FirstOrDefault(e => e.Claim.StartsWith(versionPrefix, StringComparison.Ordinal))?.Claim[versionPrefix.Length..], 150),
            ExploitEvidence = Cut(exploit, 100),
            Control = Cut(modifiers.Count > 0 ? modifiers[0] : null, 80),
        };
    }

    /// <summary>
    /// Add the before-and-after line to a verdict that is about to be re-evaluated, if anything the decision table
    /// reads has changed. Call before the new result is copied onto the row. An EPSS score that moves without
    /// changing the exploitation status is not a change: it would add a line a day to every verdict.
    /// </summary>
    public static void Record(Verdict v, DateTime now, VerdictSnapshot after)
    {
        var before = Snapshot(v);
        if (!Material(before, after)) return;
        // already digested: the digest reports the tier and state lines, and must not spend its quota on these
        v.History.Add(new VerdictHistory { At = now, Actor = "system", Kind = Kind, From = "rule " + before.Rule, To = "rule " + after.Rule, Reason = Pack(before, after), Digested = true });
    }

    private static bool Material(VerdictSnapshot b, VerdictSnapshot a) =>
        b.Tier != a.Tier || b.Rule != a.Rule || b.Exploitation != a.Exploitation || b.Automatable != a.Automatable || b.AttackVector != a.AttackVector
        || b.DeclaredExposure != a.DeclaredExposure || b.EffectiveExposure != a.EffectiveExposure || b.Criticality != a.Criticality || b.InKev != a.InKev
        || (b.Control is null) != (a.Control is null);

    /// <summary>Both snapshots as JSON, never longer than a history reason: the free text goes first if it has to.</summary>
    public static string Pack(VerdictSnapshot before, VerdictSnapshot after)
    {
        var json = JsonSerializer.Serialize(new Pair(before, after), Json);
        if (json.Length <= MaxPacked) return json;
        before = before with { ExploitEvidence = null, Control = Cut(before.Control, 30), VersionCheck = Cut(before.VersionCheck, 100) };
        after = after with { ExploitEvidence = Cut(after.ExploitEvidence, 60), Control = Cut(after.Control, 30), VersionCheck = Cut(after.VersionCheck, 100) };
        json = JsonSerializer.Serialize(new Pair(before, after), Json);
        if (json.Length <= MaxPacked) return json;
        return JsonSerializer.Serialize(new Pair(before with { VersionCheck = null, Control = null }, after with { VersionCheck = null, ExploitEvidence = null, Control = null }), Json);
    }

    public static (VerdictSnapshot Before, VerdictSnapshot After)? Unpack(string? reason)
    {
        var p = Parse<Pair>(reason);
        return p?.Before is null || p.After is null ? null : (p.Before, p.After);
    }

    private static T? Parse<T>(string? json) where T : class
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonSerializer.Deserialize<T>(json, Json); } catch (JsonException) { return null; }
    }

    private static string? Cut(string? s, int max) => s is null || s.Length <= max ? s : s[..(max - 3)] + "...";

    // ------------------------------------------------------------------ explaining

    /// <summary>
    /// Why the verdict changed between two snapshots, one plain phrase per cause with the evidence behind it.
    /// <paramref name="exposureEvidence"/> is what the asset's source said about its exposure (a firewall VIP, say).
    /// </summary>
    public static List<string> Explain(VerdictSnapshot b, VerdictSnapshot a, string? exposureEvidence = null)
    {
        var why = new List<string>();

        // ---- exploitation: KEV, then whatever else moved the status
        if (a.InKev && !b.InKev)
            why.Add("CVE added to CISA KEV" + (a.KevSince is null ? "" : " (evidence: KEV entry dated " + a.KevSince + ")"));
        else if (b.InKev && !a.InKev)
            why.Add("CVE no longer listed in CISA KEV");

        if (a.Exploitation != b.Exploitation)
        {
            var crossedUp = a.Epss >= EpssThreshold && !(b.Epss >= EpssThreshold);
            var crossedDown = b.Epss >= EpssThreshold && !(a.Epss >= EpssThreshold);
            if (a.Exploitation == Exploitation.Active && !a.InKev)
                why.Add("now reported as exploited in the wild" + Evidence(a.ExploitEvidence));
            else if (a.Exploitation == Exploitation.PoC && b.Exploitation == Exploitation.None)
            {
                if (a.ExploitEvidence is not null && a.ExploitEvidence != b.ExploitEvidence) why.Add("public exploit code published" + Evidence(a.ExploitEvidence));
                if (crossedUp)
                    why.Add((b.Epss is null ? "EPSS is now " + Score(a.Epss) : "EPSS rose from " + Score(b.Epss) + " to " + Score(a.Epss)) + ", crossing the " + Score(EpssThreshold) + " threshold");
                if (why.Count == 0) why.Add("public exploit code now exists");
            }
            else if (a.Exploitation < b.Exploitation && !(b.InKev && !a.InKev))
            {
                if (crossedDown && a.Exploitation == Exploitation.None)
                    why.Add((a.Epss is null ? "the EPSS score was withdrawn" : "EPSS fell from " + Score(b.Epss) + " to " + Score(a.Epss)) + ", back under the " + Score(EpssThreshold) + " threshold");
                else
                    why.Add("exploit evidence withdrawn: was " + b.Exploitation.Plain() + ", now " + a.Exploitation.Plain());
            }
        }

        // ---- the version check. "Not installed" as the exposure is how the engine says the version is not affected.
        var wasOut = b.DeclaredExposure == Exposure.NotInstalled;
        var isOut = a.DeclaredExposure == Exposure.NotInstalled;
        if (wasOut && !isOut)
        {
            var range = InsideRange(a.VersionCheck);
            var oldVersion = InstalledIn(b.VersionCheck);
            var oldRange = InsideRange(b.VersionCheck) ?? ListedRange(b.VersionCheck);
            if (a.Version is not null && range is not null && oldVersion == a.Version && oldRange is not null && oldRange != range)
                why.Add("installed version " + a.Version + " is inside the widened affected range " + PlainRange(range) + " (was " + PlainRange(oldRange) + ")");
            else if (a.Version is not null && range is not null && oldVersion is not null && oldVersion != a.Version)
                why.Add("installed version changed from " + oldVersion + " to " + a.Version + ", which is inside the affected range " + PlainRange(range));
            else if (a.Version is not null && range is not null)
                why.Add("installed version " + a.Version + " is inside the affected range " + PlainRange(range));
            else
                why.Add("affected again" + (a.VersionCheck is null ? "" : ": " + a.VersionCheck));
        }
        else if (!wasOut && isOut)
        {
            var oldVersion = InstalledIn(b.VersionCheck);
            if (InsideRange(a.VersionCheck) is not null)
                why.Add("the role, feature or service is now disabled, so it is treated as not installed");
            else if (a.Version is not null && oldVersion is not null && oldVersion != a.Version)
                why.Add("installed version changed from " + oldVersion + " to " + a.Version + (a.VersionCheck is null ? ", which is not affected" : ": " + a.VersionCheck));
            else
                why.Add("no longer affected" + (a.VersionCheck is null ? "" : ": " + a.VersionCheck));
        }
        else if (b.DeclaredExposure != a.DeclaredExposure)
            why.Add("exposure changed from " + b.DeclaredExposure.Plain() + " to " + a.DeclaredExposure.Plain() + (string.IsNullOrWhiteSpace(exposureEvidence) ? "" : " (" + exposureEvidence.Trim() + ")"));

        // ---- the rest of the decision-table inputs
        if (b.Criticality != a.Criticality) why.Add("criticality changed from " + b.Criticality + " to " + a.Criticality);
        if (b.AttackVector != a.AttackVector)
            why.Add("attack path re-assessed: was " + b.AttackVector.Plain() + ", now " + a.AttackVector.Plain()
                    + (!isOut && !wasOut && a.DeclaredExposure == b.DeclaredExposure && a.EffectiveExposure != b.EffectiveExposure ? ", so the exposure counts as " + a.EffectiveExposure.Plain().ToLowerInvariant() : ""));
        if (b.Automatable != a.Automatable) why.Add(a.Automatable ? "now judged automatable at scale" : "no longer judged automatable");
        if (a.Control is not null && b.Control is null) why.Add("compensating control recorded: " + a.Control);
        else if (a.Control is null && b.Control is not null) why.Add("compensating control removed or expired: " + b.Control);
        return why;
    }

    private static string Evidence(string? claim) => claim is null ? "" : " (evidence: " + claim + ")";
    private static string Score(double? s) => (s ?? 0).ToString("0.00", CultureInfo.InvariantCulture);

    /// <summary>The rule as the evidence chain words it: "rule 2: exploited in the wild and reachable from the internet (Fix today)".</summary>
    public static string RuleLine(VerdictSnapshot s) =>
        "rule " + s.Rule + ": " + DecisionTable.RuleText(s.Rule) + " (" + s.Tier.Plain() + (s.Control is null ? "" : ", after a compensating control") + ")";

    [GeneratedRegex(@"^(?<v>\S+) is inside the (?:un)?affected range |covers (?<v>[^\s()]+)")] private static partial Regex InstalledRx();
    [GeneratedRegex(@" is inside the affected range (?<r>.+)$")] private static partial Regex InsideRx();
    [GeneratedRegex(@"\(affected: (?<r>.+)\)$")] private static partial Regex ListedRx();
    [GeneratedRegex(@"^(?<a>\S+) (?<op><=|<) (?<b>\S+)$")] private static partial Regex BoundsRx();

    /// <summary>The installed version a version-check line talks about.</summary>
    private static string? InstalledIn(string? check) => check is not null && InstalledRx().Match(check) is { Success: true } m ? m.Groups["v"].Value : null;
    private static string? InsideRange(string? check) => check is not null && InsideRx().Match(check) is { Success: true } m ? m.Groups["r"].Value : null;
    private static string? ListedRange(string? check) => check is not null && ListedRx().Match(check) is { Success: true } m ? m.Groups["r"].Value : null;

    /// <summary>"7.0.0 &lt;= 7.2.6" as "7.0.0–7.2.6", "7.0.0 &lt; 7.2.7" as "7.0.0 up to, not including, 7.2.7". Other wordings are left as the record has them.</summary>
    public static string PlainRange(string range) => string.Join(", ", range.Split(", ").Select(part =>
    {
        var m = BoundsRx().Match(part);
        if (!m.Success) return part;
        var (from, to, inclusive) = (m.Groups["a"].Value, m.Groups["b"].Value, m.Groups["op"].Value == "<=");
        if (to == "any") return from == "any" ? "every version" : from + " and later";
        if (from == "any") return inclusive ? to + " and earlier" : "anything before " + to;
        return inclusive ? from + "–" + to : from + " up to, not including, " + to;
    }));

    // ------------------------------------------------------------------ the timeline

    /// <summary>
    /// The history of a verdict as plain sentences, newest first. Lines written by one evaluation (tier, state and
    /// inputs share a timestamp) become one entry; anything a person did is an entry of its own.
    /// <paramref name="exposureEvidence"/> is attached to the latest exposure change that ends at <paramref name="currentExposure"/>,
    /// the only one the asset's present evidence can speak for.
    /// </summary>
    public static List<TimelineEntry> Timeline(IEnumerable<VerdictHistory> history, string? exposureEvidence = null, Exposure? currentExposure = null)
    {
        var entries = new List<TimelineEntry>();
        var exposureUsed = false;
        foreach (var g in history.GroupBy(h => (h.At, System: h.Actor == "system")).OrderByDescending(g => g.Key.At))
        {
            if (!g.Key.System)
            {
                entries.AddRange(g.Where(h => h.Kind == "state").OrderByDescending(h => h.Id).Select(h => new TimelineEntry(h.At, h.Actor, StateText(h))));
                continue;
            }
            var tier = g.FirstOrDefault(h => h.Kind == "tier");
            var pair = Unpack(g.FirstOrDefault(h => h.Kind == Kind)?.Reason);
            var states = g.Where(h => h.Kind == "state").OrderBy(h => h.Id).ToList();
            if (tier is null && pair is null)
            {
                entries.AddRange(states.AsEnumerable().Reverse().Select(h => new TimelineEntry(h.At, h.Actor, StateText(h))));
                continue;
            }

            List<string> causes = new();
            if (pair is { } p)
            {
                var speaksForIt = !exposureUsed && currentExposure is not null && p.After.DeclaredExposure == currentExposure && p.Before.DeclaredExposure != p.After.DeclaredExposure
                                  && p.Before.DeclaredExposure != Exposure.NotInstalled && p.After.DeclaredExposure != Exposure.NotInstalled;
                causes = Explain(p.Before, p.After, speaksForIt ? exposureEvidence : null);
                exposureUsed |= speaksForIt;
            }

            var from = pair?.Before.Tier ?? (Enum.TryParse<VerdictTier>(tier!.From, out var f) ? f : VerdictTier.NotAffected);
            var to = pair?.After.Tier ?? (Enum.TryParse<VerdictTier>(tier!.To, out var t) ? t : VerdictTier.NotAffected);
            var reopened = states.FirstOrDefault(h => h.From == "Closed" && h.To == "Open");
            var lifted = states.FirstOrDefault(h => h.To == "Open" && h.From is "Snoozed" or "AcceptedRisk");
            var closed = states.FirstOrDefault(h => h.To == "Closed");

            string text;
            if (from != to)
            {
                text = (reopened is not null ? "re-opened and " : "") + (to > from ? "promoted" : "demoted") + " from " + from.Plain() + " to " + to.Plain()
                       + (closed is not null ? " and closed" : "")
                       + (lifted is not null ? ", which lifted the " + (lifted.From == "Snoozed" ? "snooze" : "accepted risk") : "");
                // a tier line from before inputs were recorded only has the evaluator's short reason
                var legacy = tier?.Reason?.Replace(" (re-opened)", "");
                text += causes.Count > 0 ? " because " + string.Join("; ", causes) : string.IsNullOrEmpty(legacy) ? "" : ": " + legacy;
            }
            else if (reopened is not null)
                text = causes.Count > 0 ? "re-opened because " + string.Join("; ", causes) : StateText(reopened);
            else
                text = "still " + to.Plain() + ", for a different reason" + (causes.Count > 0 ? ": " + string.Join("; ", causes) : "");

            // state lines the sentence has not already covered (a suppression rule applying in the same pass, say)
            foreach (var h in states.AsEnumerable().Reverse().Where(h => h != reopened && h != lifted && h != closed))
                entries.Add(new TimelineEntry(h.At, h.Actor, StateText(h)));
            entries.Add(new TimelineEntry(g.Key.At, "system", text, pair is null ? null : RuleLine(pair.Value.Before), pair is null ? null : RuleLine(pair.Value.After)));
        }
        return entries;
    }

    /// <summary>A state line in plain words: who did what, and the reason they gave.</summary>
    private static string StateText(VerdictHistory h)
    {
        var reason = string.IsNullOrWhiteSpace(h.Reason) ? null : h.Reason.Trim();
        if (h.Actor == "system")
        {
            if (reason is null) return (h.From ?? "?") + " to " + (h.To ?? "?");
            return h.To switch
            {
                "Open" when !reason.StartsWith("re-opened", StringComparison.Ordinal) => "re-opened: " + reason,
                "Closed" when !reason.StartsWith("closed", StringComparison.Ordinal) && !reason.StartsWith("patched", StringComparison.Ordinal) => "closed: " + reason,
                "Suppressed" => "suppressed (" + reason + ")",
                _ => reason
            };
        }
        var tail = reason is null ? "" : ": " + reason;
        return h.To switch
        {
            "Closed" => "marked done by " + h.Actor + (reason is null or "marked done" ? "" : reason.StartsWith("marked done: ", StringComparison.Ordinal) ? ": " + reason["marked done: ".Length..] : tail),
            "Snoozed" => "snoozed by " + h.Actor + tail,
            "AcceptedRisk" => "risk accepted by " + h.Actor + tail,
            "Suppressed" => "suppressed by " + h.Actor + tail,
            "Open" => "re-opened by " + h.Actor + (reason is null or "re-opened manually" ? "" : tail),
            _ => (h.From ?? "?") + " to " + (h.To ?? "?") + " by " + h.Actor + tail
        };
    }
}
