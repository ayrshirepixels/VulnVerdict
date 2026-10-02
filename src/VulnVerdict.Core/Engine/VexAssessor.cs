using System.Text.RegularExpressions;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Feeds.Vex;

namespace VulnVerdict.Core.Engine;

/// <summary>
/// How surely a vendor VEX statement is about the subject. Weak: a related name ("openssl-libs" for "openssl").
/// Product: the same product, but the statement's version, branch or platform could not be confirmed against what is
/// installed. Exact: the same product, and the statement covers the installed version on the installed platform.
/// </summary>
public enum VexMatchLevel { None = 0, Weak = 1, Product = 2, Exact = 3 }

public sealed record VexMatch(VexStatement Statement, VexMatchLevel Level, bool VersionExplicit);

/// <summary>
/// What the vendor statements for one CVE mean for one subject. <see cref="Overall"/> and <see cref="Confidence"/> are
/// null when the statements change nothing; the evidence lines are always given.
/// </summary>
public sealed record VexAssessment(List<EvidenceClaim> Evidence, VersionMatch? Overall, MatchConfidence? Confidence, string? FixedIn, string? NotAffectedText, string? CheckText);

/// <summary>
/// Applies vendor VEX statements to a verdict. A missed vulnerability is the dangerous mistake, so the statements are
/// trusted unevenly:
///  - known_affected strengthens the match (and settles a version the CVE record could not be read against);
///  - fixed adds the fixed version to the evidence;
///  - under_investigation is an evidence line;
///  - known_not_affected makes the verdict Not affected only on an Exact match with nothing in the vendor's data
///    saying otherwise, and never for a CVE that is exploited in the wild: that one is flagged for a person. On any
///    weaker match it is an evidence line ("check") and the tier stays where it was.
/// </summary>
public static partial class VexAssessor
{
    /// <summary>Starts the evidence line of a not-affected statement that decided the verdict. The evaluator reads it back to explain tier changes.</summary>
    public const string AppliedPrefix = "Vendor VEX statement applied: ";
    public const string NotAffectedReason = "vendor VEX statement: not affected";
    public const string WithdrawnReason = "the vendor withdrew its not-affected statement";

    public static bool Applied(IEnumerable<EvidenceClaim> evidence) => evidence.Any(e => e.Claim.StartsWith(AppliedPrefix, StringComparison.Ordinal));
    /// <summary>The same test against a stored verdict's evidence JSON.</summary>
    public static bool Applied(string? evidenceJson) => evidenceJson is not null && evidenceJson.Contains(AppliedPrefix, StringComparison.Ordinal);
    /// <summary>The stored verdict was Not affected on a vendor statement and the new evaluation no longer has one that applies.</summary>
    public static bool Withdrawn(string? storedEvidenceJson, IEnumerable<EvidenceClaim> evidence) => Applied(storedEvidenceJson) && !Applied(evidence);

    /// <summary>In the evidence line of a not-affected statement that was held back because the CVE is exploited in the wild.</summary>
    private const string NotLowered = "so the verdict is not lowered automatically";

    /// <summary>
    /// The reason to record for a tier change a vendor statement caused, or null when it was something else. A statement
    /// that still stands but no longer applies because the CVE became exploited is something else: the exploitation is the reason.
    /// </summary>
    public static string? TierReason(string? storedEvidenceJson, IReadOnlyList<EvidenceClaim> evidence, VerdictTier to)
    {
        if (to == VerdictTier.NotAffected) return Applied(evidence) ? NotAffectedReason : null;
        if (!Withdrawn(storedEvidenceJson, evidence)) return null;
        return evidence.Any(e => e.Claim.Contains(NotLowered, StringComparison.Ordinal)) ? null : WithdrawnReason;
    }

    // ------------------------------------------------------------------ assessment

    public static VexAssessment? Assess(Subject s, IReadOnlyList<VexStatement> statements, VersionMatch overall, bool exploited)
    {
        var matches = statements.Select(st => Match(s, st)).Where(m => m.Level > VexMatchLevel.None)
            .OrderByDescending(m => m.Level).ThenByDescending(m => m.Statement.DocumentDate).ToList();
        if (matches.Count == 0) return null;

        var evidence = new List<EvidenceClaim>();
        VersionMatch? newOverall = null; MatchConfidence? confidence = null;
        string? notAffectedText = null, checkText = null;

        var affected = matches.FirstOrDefault(m => m.Statement.Status == VexStatus.KnownAffected);
        var investigating = matches.FirstOrDefault(m => m.Statement.Status == VexStatus.UnderInvestigation);
        var notAffected = matches.FirstOrDefault(m => m.Statement.Status == VexStatus.KnownNotAffected);
        var (fix, fixedIn, olderThanFix) = PickFix(s, matches);

        // ---- not affected: applied only on an exact match that nothing else in the vendor's data contradicts
        var applied = false;
        if (notAffected is not null)
        {
            var st = notAffected.Statement;
            var reason = Reason(st);
            var contradicted = affected is { Level: >= VexMatchLevel.Product } || investigating is { Level: >= VexMatchLevel.Product } || olderThanFix;
            if (notAffected.Level < VexMatchLevel.Exact)
                evidence.Add(Claim(st, "Vendor VEX: " + st.Vendor + " says not affected for " + Describe(st) + ": check. Not applied, because the statement does not name this product and version exactly"));
            else if (contradicted)
                evidence.Add(Claim(st, "Vendor VEX: " + st.Vendor + " says not affected for " + Describe(st) + ", but its data also lists this product as affected, under investigation or fixed in a later version: not applied, check"));
            else if (overall == VersionMatch.NotAffected)
                // the version check already settled it (a fixed version is installed): the statement agrees, it did not decide
                evidence.Add(Claim(st, "Vendor VEX: " + st.Vendor + " also states " + Describe(st) + " is not affected (" + reason + ")" + Dated(st)));
            else if (exploited)
            {
                evidence.Add(Claim(st, "Vendor VEX: " + st.Vendor + " states " + Describe(st) + " is not affected (" + reason + "), but this CVE is exploited in the wild, " + NotLowered + ". Check that the statement applies here, then close it by hand"));
                checkText = "Check this: the vendor states this product is not affected (" + reason + "); it is exploited in the wild, so confirm before closing.";
            }
            else
            {
                applied = true;
                evidence.Add(Claim(st, AppliedPrefix + st.Vendor + " states " + Describe(st) + " is not affected (" + reason + ")" + Dated(st) + ". It names this product and version exactly, so the verdict is Not affected"));
                newOverall = VersionMatch.NotAffected;
                confidence = MatchConfidence.Exact;
                notAffectedText = "the vendor states this product is not affected (" + reason + ")";
            }
        }

        // ---- affected: strengthens the match; an exact statement settles a version the CVE record could not
        if (affected is not null && !applied)
        {
            var st = affected.Statement;
            var detail = st.Detail is null ? "" : " (" + st.Detail + ")";
            if (affected.Level == VexMatchLevel.Weak)
                evidence.Add(Claim(st, "Vendor VEX: " + st.Vendor + " lists " + Describe(st) + " as affected: check whether that is this product"));
            else if (overall == VersionMatch.NotAffected)
            {
                if (affected is { Level: VexMatchLevel.Exact, VersionExplicit: true })
                {
                    evidence.Add(Claim(st, "Vendor VEX: " + st.Vendor + " states " + Describe(st) + " is affected" + detail + ". The vendor names this exact version, which outweighs the version range in the CVE record"));
                    newOverall = VersionMatch.Affected;
                    confidence = MatchConfidence.Exact;
                }
                else
                    evidence.Add(Claim(st, "Vendor VEX: " + st.Vendor + " states " + Describe(st) + " is affected" + detail + ": check, the version check puts the installed version outside the affected range"));
            }
            else
            {
                evidence.Add(Claim(st, "Vendor VEX: " + st.Vendor + " states " + Describe(st) + " is affected" + detail));
                if (overall == VersionMatch.Unknown) newOverall = VersionMatch.Affected;
                confidence = affected.Level == VexMatchLevel.Exact ? MatchConfidence.Exact : MatchConfidence.Likely;
            }
        }

        if (fix is not null)
        {
            var st = fix.Statement;
            evidence.Add(Claim(st, "Vendor VEX: " + st.Vendor + " lists " + Describe(st) + " as fixed" + (st.Detail is null ? "" : " (" + st.Detail + ")")
                + (fix.Level == VexMatchLevel.Weak ? ": check whether that is this product" : "")));
        }
        if (investigating is not null)
            evidence.Add(Claim(investigating.Statement, "Vendor VEX: " + investigating.Statement.Vendor + " is still investigating whether " + Describe(investigating.Statement) + " is affected"));

        var more = matches.Count - evidence.Count;
        if (more > 0 && evidence.Count > 0)
            evidence[^1] = evidence[^1] with { Claim = evidence[^1].Claim + ". " + more + " more vendor statement" + (more == 1 ? "" : "s") + " about related products or versions are in the vendor's document" };
        return new VexAssessment(evidence, newOverall, confidence, applied ? null : fixedIn, notAffectedText, checkText);
    }

    /// <summary>
    /// The fixed statement to show, the fixed version to recommend, and whether the installed version is older than a fix
    /// the vendor lists for this same product (which contradicts a not-affected statement).
    /// </summary>
    private static (VexMatch? Shown, string? FixedIn, bool OlderThanFix) PickFix(Subject s, List<VexMatch> matches)
    {
        var fixes = matches.Where(m => m.Statement.Status == VexStatus.Fixed).ToList();
        if (fixes.Count == 0) return (null, null, false);
        var sure = fixes.Where(m => m.Level >= VexMatchLevel.Product && m.Statement.Version is not null).ToList();
        if (sure.Count == 0) return (fixes[0], null, false);
        var installed = s.Version is null ? null : StripEpoch(s.Version);
        if (installed is null || !VersionCompare.IsParseable(installed))
        {
            var lowest = sure.Where(m => m.Level == sure[0].Level).Aggregate((a, b) => VersionCompare.Compare(StripEpoch(b.Statement.Version!), StripEpoch(a.Statement.Version!)) < 0 ? b : a);
            return (lowest, lowest.Statement.Version, false);
        }
        // the lowest fixed version above what is installed, from the surest statements first
        var newer = sure.Where(m => VersionCompare.Compare(installed, StripEpoch(m.Statement.Version!)) < 0).ToList();
        if (newer.Count == 0) return (sure[0], null, false);
        var best = newer.Where(m => m.Level == newer[0].Level).Aggregate((a, b) => VersionCompare.Compare(StripEpoch(b.Statement.Version!), StripEpoch(a.Statement.Version!)) < 0 ? b : a);
        return (best, best.Statement.Version, true);
    }

    private static EvidenceClaim Claim(VexStatement st, string text) =>
        new(text, st.Url ?? st.Vendor + " VEX", st.RetrievedAt, "Document " + st.DocumentId + (st.Revision is null ? "" : ", revision " + st.Revision) + (st.DocumentDate is { } d ? ", revised " + d.ToString("yyyy-MM-dd") : ""));

    private static string Dated(VexStatement st) => st.DocumentDate is { } d ? ", in a statement dated " + d.ToString("yyyy-MM-dd") : "";

    /// <summary>"openssh 8.7p1-38.el9_4.1 as a component of Red Hat Enterprise Linux 9".</summary>
    public static string Describe(VexStatement st) =>
        st.Product + (st.Version is null ? "" : " " + st.Version) + (st.VersionRange is null ? "" : " " + st.VersionRange) + (st.Platform is null ? "" : " as a component of " + st.Platform);

    /// <summary>The vendor's justification in plain words, else its impact statement, else that none was given.</summary>
    public static string Reason(VexStatement st) => st.Justification switch
    {
        "component_not_present" => "the component is not present",
        "vulnerable_code_not_present" => "the vulnerable code is not present",
        "vulnerable_code_not_in_execute_path" => "the vulnerable code is never run",
        "vulnerable_code_cannot_be_controlled_by_adversary" => "an attacker cannot reach the vulnerable code",
        "inline_mitigations_already_exist" => "built-in mitigations already prevent it",
        { Length: > 0 } other => other.Replace('_', ' '),
        _ => st.Detail is { Length: > 0 } d ? (d.Length > 160 ? d[..160] : d).TrimEnd('.', ' ') : "no reason given"
    };

    // ------------------------------------------------------------------ matching

    /// <summary>How surely the statement is about this subject at its installed version.</summary>
    public static VexMatch Match(Subject s, VexStatement st)
    {
        var level = Identity(s, st);
        // a fixed statement names the version that has the fix, not the one installed: the product is all that has to match
        if (level <= VexMatchLevel.Weak || st.Status == VexStatus.Fixed) return new VexMatch(st, level, false);
        if (st.Version is null && st.VersionRange is null) return new VexMatch(st, level, false);
        if (string.IsNullOrWhiteSpace(s.Version)) return new VexMatch(st, VexMatchLevel.Product, false);

        var installed = StripEpoch(s.Version);
        if (st.Version is not null)
        {
            var named = StripEpoch(st.Version);
            var cmp = VersionCompare.Compare(installed, named);
            if (cmp == 0 || installed.Equals(named, StringComparison.OrdinalIgnoreCase)) return new VexMatch(st, level, true);
            if (cmp is null) return new VexMatch(st, VexMatchLevel.Weak, false);
            // "7.2" against an installed 7.2.5 may be the branch or may be 7.2.0 exactly: the product, not the version, is confirmed
            if (IsBranchOf(named, installed)) return new VexMatch(st, VexMatchLevel.Product, false);
            return new VexMatch(st, VexMatchLevel.None, false);   // a statement about another version
        }
        return InRange(installed, st.VersionRange!) switch
        {
            true => new VexMatch(st, level, false),
            false => new VexMatch(st, VexMatchLevel.None, false),
            _ => new VexMatch(st, VexMatchLevel.Weak, false)
        };
    }

    private static VexMatchLevel Identity(Subject s, VexStatement st)
    {
        var names = new[] { s.ProductNorm, Normalizer.Norm(s.Product) }.Where(n => n.Length > 0).Distinct().ToList();
        var vendors = new[] { s.VendorNorm, Normalizer.Norm(s.Vendor) }.Where(v => v.Length > 0).Distinct().ToList();
        if (names.Count == 0 || st.ProductNorm.Length == 0) return VexMatchLevel.None;
        var cpe = CsafVexParser.ParseCpe(st.Cpe);
        var cpeProduct = Normalizer.Norm(cpe?.Product);

        // the same product: the same name, with or without the vendor in front on either side, or the CPE product
        var same = names.Any(n => n == st.ProductNorm || (cpeProduct.Length > 0 && n == cpeProduct) || n == st.VendorNorm + st.ProductNorm || vendors.Any(v => v + n == st.ProductNorm));
        if (!same)
            return names.Any(n => n.Length >= 4 && st.ProductNorm.Length >= 4 && (st.ProductNorm.Contains(n, StringComparison.Ordinal) || n.Contains(st.ProductNorm, StringComparison.Ordinal)))
                ? VexMatchLevel.Weak : VexMatchLevel.None;

        if (s.Purl is not null || s.Ecosystem is not null) return PackagePlatform(s, st);

        var cpeVendor = Normalizer.Norm(cpe?.Vendor);
        bool SameVendor(string v) => v.Length >= 3 && ((st.VendorNorm.Length > 0 && (st.VendorNorm.StartsWith(v, StringComparison.Ordinal) || v.StartsWith(st.VendorNorm, StringComparison.Ordinal)))
                                                      || (cpeVendor.Length > 0 && (cpeVendor.StartsWith(v, StringComparison.Ordinal) || v.StartsWith(cpeVendor, StringComparison.Ordinal))));
        if (!vendors.Any(SameVendor)) return VexMatchLevel.Weak;
        // "X as a component of Y" for a subject whose platform is not recorded, or a product mapped by a fuzzy name
        if (st.Platform is not null || s.ProductConfidence != MatchConfidence.Exact) return VexMatchLevel.Product;
        return VexMatchLevel.Exact;
    }

    [GeneratedRegex(@"\d+")] private static partial Regex FirstNumber();

    /// <summary>
    /// A package on a Linux host against "package as a component of product stream". Red Hat names the stream by CPE:
    /// the package on RHEL 9 is matched exactly by a statement for enterprise_linux 9, not at all by one for 8, and only
    /// as the same product by an extended-support stream (9.2 EUS) or when the host is a rebuild (AlmaLinux, Rocky Linux).
    /// </summary>
    private static VexMatchLevel PackagePlatform(Subject s, VexStatement st)
    {
        if (st.Platform is null) return VexMatchLevel.Product;
        var eco = s.Ecosystem ?? "";
        var colon = eco.IndexOf(':');
        var family = Normalizer.Norm(colon > 0 ? eco[..colon] : eco);
        var rest = colon > 0 ? eco[(colon + 1)..] : "";

        var cpe = CsafVexParser.ParseCpe(st.PlatformCpe);
        if (cpe is not null && Normalizer.Norm(cpe.Vendor) == "redhat")
        {
            if (family is not ("redhat" or "almalinux" or "rockylinux")) return VexMatchLevel.Weak;
            var major = FirstNumber().Match(rest).Value;
            if (major.Length == 0 || cpe.Version is null) return VexMatchLevel.Weak;
            if (cpe.Version.Split('.')[0] != major) return VexMatchLevel.None;
            var mainStream = cpe.Product == "enterprise_linux" && !cpe.Version.Contains('.');
            return family == "redhat" && mainStream ? VexMatchLevel.Exact : VexMatchLevel.Product;
        }

        // other vendors: exact when the platform is named as the host's ecosystem is ("SUSE:Linux Enterprise Server 15 SP5")
        var stream = Normalizer.Norm(rest.Replace(':', ' '));
        if (stream.Length == 0 || st.PlatformNorm is not { Length: > 0 } platform || !(platform == stream || platform.EndsWith(stream, StringComparison.Ordinal)))
            return VexMatchLevel.Weak;
        var sameFamily = family.Length >= 3 && st.VendorNorm.Length >= 3 && (st.VendorNorm.StartsWith(family, StringComparison.Ordinal) || family.StartsWith(st.VendorNorm, StringComparison.Ordinal));
        return sameFamily ? VexMatchLevel.Exact : VexMatchLevel.Product;
    }

    [GeneratedRegex(@"^\d+:")] private static partial Regex Epoch();
    /// <summary>"1:1.1.1k-14.el8_6" and "1.1.1k-14.el8_6" are the same package version for this purpose.</summary>
    public static string StripEpoch(string version) => Epoch().Replace(version.Trim(), "");

    /// <summary>True when <paramref name="branch"/> ("7.2") is a leading part of <paramref name="installed"/> ("7.2.5") ending on a separator.</summary>
    public static bool IsBranchOf(string branch, string installed) =>
        installed.Length > branch.Length && installed.StartsWith(branch, StringComparison.OrdinalIgnoreCase) && installed[branch.Length] is '.' or '-' or '_';

    [GeneratedRegex(@"^vers:[a-z0-9.+-]+/", RegexOptions.IgnoreCase)] private static partial Regex VersPrefix();
    [GeneratedRegex(@"(?<op>>=|<=|!=|<|>|=)?\s*(?<v>v?\d[^\s,|]*)")] private static partial Regex Constraint();

    /// <summary>
    /// Whether <paramref name="installed"/> falls inside a product_version_range: a vers string ("vers:generic/>=7.0.0|&lt;7.2.8")
    /// or the plain comparisons vendors write ("&lt;= 7.2.4", ">=7.0, &lt;7.2.8"). Null when the range is prose or cannot be compared.
    /// </summary>
    public static bool? InRange(string installed, string range)
    {
        var text = VersPrefix().Replace(range.Trim(), "");
        if (text == "*") return true;
        var constraints = Constraint().Matches(text);
        // anything left over besides separators is prose ("all versions prior to ..."): not something to decide on
        if (constraints.Count == 0 || Constraint().Replace(text, "").Trim(' ', ',', '|', ';').Length > 0) return null;

        string? lower = null; var lowerInclusive = false; var inside = false;
        foreach (Match c in constraints)
        {
            var v = c.Groups["v"].Value;
            var cmp = VersionCompare.Compare(installed, v);
            if (cmp is null) return null;
            switch (c.Groups["op"].Value)
            {
                case "" or "=": if (cmp == 0) inside = true; break;
                case "!=": if (cmp == 0) return false; break;
                case ">" or ">=": lower = v; lowerInclusive = c.Groups["op"].Value == ">="; break;
                default:   // an upper bound closes the interval opened by the last lower bound, or runs from the beginning
                    var belowUpper = c.Groups["op"].Value == "<=" ? cmp <= 0 : cmp < 0;
                    var aboveLower = lower is null || (VersionCompare.Compare(installed, lower) is { } l && (lowerInclusive ? l >= 0 : l > 0));
                    if (belowUpper && aboveLower) inside = true;
                    lower = null;
                    break;
            }
        }
        // a lower bound left open runs to the end
        if (lower is not null && VersionCompare.Compare(installed, lower) is { } open && (lowerInclusive ? open >= 0 : open > 0)) inside = true;
        return inside;
    }
}
