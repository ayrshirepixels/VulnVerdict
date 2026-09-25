using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Engine;

/// <summary>
/// Generic dotted-version comparator. Numeric segments compare numerically, alphabetic segments lexically,
/// a trailing pre-release tag sorts below the bare version. Covers semver, FortiOS, Windows builds, IOS-style
/// strings and most vendor firmware strings. Returns null when either side has no leading digit.
/// </summary>
public static partial class VersionCompare
{
    [GeneratedRegex(@"^\s*v(?=\d)", RegexOptions.IgnoreCase)] private static partial Regex LeadingV();
    [GeneratedRegex(@"\(.*?\)")] private static partial Regex Parens();
    [GeneratedRegex(@"(\d+|[a-z]+)", RegexOptions.IgnoreCase)] private static partial Regex Segment();

    public static string Clean(string v)
    {
        v = Parens().Replace(v, " ");
        v = LeadingV().Replace(v.Trim(), "");
        return v.Trim();
    }

    public static bool IsParseable(string? v)
    {
        if (string.IsNullOrWhiteSpace(v)) return false;
        var c = Clean(v);
        return c.Length > 0 && char.IsDigit(c[0]);
    }

    private static List<(bool numeric, long num, string text)> Segments(string v)
    {
        var list = new List<(bool, long, string)>();
        foreach (Match m in Segment().Matches(Clean(v)))
        {
            var s = m.Value;
            if (char.IsDigit(s[0]))
            {
                if (!long.TryParse(s, out var n)) n = long.MaxValue;
                list.Add((true, n, s));
            }
            else list.Add((false, 0, s.ToLowerInvariant()));
        }
        return list;
    }

    /// <summary>
    /// Tags that mark a release after the bare version: PAN-OS hotfixes ("11.1.5-h1"), Sophos maintenance releases
    /// ("21.0 MR1"), Zyxel and OpenSSH patches ("5.21 Patch 1", "8.9p1"), service packs and updates.
    /// "11.1.5" is older than "11.1.5-h1", where "2.1.0" is newer than "2.1.0-beta".
    /// </summary>
    private static bool IsPostRelease(string t) => t is "h" or "hf" or "hotfix" or "p" or "patch" or "mr" or "sp" or "u" or "update";

    private static int PreReleaseRank(string t) => t switch
    {
        "alpha" or "a" => 1,
        "beta" or "b" => 2,
        "rc" => 3,
        "pre" or "preview" or "dev" or "snapshot" => 0,
        _ => 4
    };

    public static int? Compare(string? a, string? b)
    {
        if (!IsParseable(a) || !IsParseable(b)) return null;
        var sa = Segments(a!);
        var sb = Segments(b!);
        var n = Math.Max(sa.Count, sb.Count);
        for (var i = 0; i < n; i++)
        {
            var ha = i < sa.Count;
            var hb = i < sb.Count;
            if (!ha && !hb) break;
            if (!ha)
            {
                // a ended; b has more. "1.2" vs "1.2.0" equal, "1.2" vs "1.2-beta" a is greater, "1.2" vs "1.2.1" a is less,
                // "1.2" vs "1.2-h1" (a hotfix or patch of it) a is less
                return sb[i].numeric ? (sb.Skip(i).All(s => s.numeric && s.num == 0) ? 0 : -1) : IsPostRelease(sb[i].text) ? -1 : 1;
            }
            if (!hb)
            {
                return sa[i].numeric ? (sa.Skip(i).All(s => s.numeric && s.num == 0) ? 0 : 1) : IsPostRelease(sa[i].text) ? 1 : -1;
            }
            var x = sa[i];
            var y = sb[i];
            if (x.numeric && y.numeric)
            {
                if (x.num != y.num) return x.num.CompareTo(y.num);
                continue;
            }
            if (x.numeric != y.numeric) return x.numeric ? 1 : -1; // number beats tag at same position
            var rx = PreReleaseRank(x.text);
            var ry = PreReleaseRank(y.text);
            if (rx != ry) return rx.CompareTo(ry);
            var c = string.CompareOrdinal(x.text, y.text);
            if (c != 0) return c;
        }
        return 0;
    }
}

/// <summary>One entry of a CVE 5 "versions" array.</summary>
public sealed class AffectedVersion
{
    [JsonPropertyName("version")] public string? Version { get; set; }
    [JsonPropertyName("status")] public string? Status { get; set; }
    [JsonPropertyName("lessThan")] public string? LessThan { get; set; }
    [JsonPropertyName("lessThanOrEqual")] public string? LessThanOrEqual { get; set; }
    [JsonPropertyName("versionType")] public string? VersionType { get; set; }
    [JsonPropertyName("changes")] public List<VersionChange>? Changes { get; set; }
}

public sealed class VersionChange
{
    [JsonPropertyName("at")] public string? At { get; set; }
    [JsonPropertyName("status")] public string? Status { get; set; }
}

public enum VersionMatch { Affected, NotAffected, Unknown }

public sealed record VersionMatchResult(VersionMatch Match, MatchConfidence Confidence, string Explanation, string? FixedIn);

/// <summary>Decide whether an installed version falls inside the CNA affected ranges.</summary>
public static partial class VersionMatcher
{
    private static readonly string[] Wildcards = { "*", "all", "any", "-", "n/a", "unspecified", "unknown", "", "0" };

    [GeneratedRegex(@"^\s*0+(?:\.0+)*\s*$")] private static partial Regex AllZeros();

    /// <summary>"2.440.*" or "2.440.x" becomes "2.441", the first release after that line; anything else, null.</summary>
    private static string? BranchCeiling(string? top)
    {
        var t = top?.Trim();
        if (t is null || t.Length < 3 || !(t.EndsWith(".*") || t.EndsWith(".x", StringComparison.OrdinalIgnoreCase))) return null;
        var parts = t[..^2].Split('.');
        if (parts.Any(p => p.Length == 0 || !p.All(char.IsAsciiDigit)) || !long.TryParse(parts[^1], out var last)) return null;
        parts[^1] = (last + 1).ToString(System.Globalization.CultureInfo.InvariantCulture);
        return string.Join('.', parts);
    }

    [GeneratedRegex(@"^\s*(?<a>[\w.\-]+)\s*(?:-|to|through|thru|~)\s*(?<b>[\w.\-]+)\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex RangeAtoB();
    [GeneratedRegex(@"^\s*(?:<|<=|prior to|before|earlier than|up to|through|below)\s*(?<b>[\w.\-]+)\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex LessThanText();
    [GeneratedRegex(@"^\s*(?<b>[\w.\-]+)\s*(?:and (?:earlier|prior|below|older)|or (?:earlier|prior|lower|older)|and before)(?:\s+versions?)?\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex AndEarlierText();
    [GeneratedRegex(@"^\s*(?:all\s+)?versions?\s+", RegexOptions.IgnoreCase)]
    private static partial Regex LeadingVersionsWord();
    [GeneratedRegex(@"\s+patch\s*(\d+)", RegexOptions.IgnoreCase)]
    private static partial Regex PatchSuffix();

    /// <summary>
    /// Wording some CNAs wrap around version text: "versions V5.00 through V5.38" (Zyxel), "5.21 Patch 1" (Zyxel),
    /// "7.1.1-7058 and older versions" (SonicWall). The leading "versions" goes, "Patch 1" becomes "-patch1" so the
    /// range forms below can read it, and the comparator treats "patch" as later than the bare version.
    /// </summary>
    public static string NormaliseText(string ver) => PatchSuffix().Replace(LeadingVersionsWord().Replace(ver, ""), "-patch$1").Trim();
    [GeneratedRegex(@"^\s*(?:>=|from)\s*(?<a>[\w.\-]+)\s*(?:,|and|to)?\s*(?:<|<=|to|through|before|up to)?\s*(?<b>[\w.\-]+)?\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex GreaterEqText();

    private static bool IsWild(string? s) => s is null || Wildcards.Contains(s.Trim().ToLowerInvariant());
    private static bool Inclusive(string s) => Regex.IsMatch(s, @"<=|through|thru|up to|and earlier|and prior|or earlier|or prior|or lower|and below|and older|or older", RegexOptions.IgnoreCase);

    private sealed record Range(string? From, string? To, bool ToInclusive, bool Affected, MatchConfidence Confidence, string Text);

    [GeneratedRegex(@"\d+(?:\.\d+)+")] private static partial Regex DottedToken();

    /// <summary>
    /// "macOS Mojave 10.14.3" to "10.14.3", "iOS 12.1.3" to "12.1.3", "iTunes 12.9.3 for Windows" to "12.9.3": the one
    /// dotted version inside a bound that starts with a name. Null when there is none, or more than one to choose from.
    /// </summary>
    internal static string? NamedVersion(string bound)
    {
        var tokens = DottedToken().Matches(bound);
        return tokens.Count == 1 && char.IsLetter(bound.TrimStart()[0]) ? tokens[0].Value : null;
    }

    private static IEnumerable<Range> Expand(AffectedVersion v)
    {
        var status = (v.Status ?? "affected").ToLowerInvariant();
        var affected = status == "affected";
        if (status == "unknown") yield break;

        // structured range
        if (!string.IsNullOrWhiteSpace(v.LessThan) || !string.IsNullOrWhiteSpace(v.LessThanOrEqual))
        {
            var top = !string.IsNullOrWhiteSpace(v.LessThan) ? v.LessThan : v.LessThanOrEqual;
            var incl = string.IsNullOrWhiteSpace(v.LessThan);
            // A branch bound such as "2.440.*" (Jenkins, Maven-style records) means the whole 2.440 line: the range
            // ends just before 2.441. Without this, "2.440.1 to 2.440.*" could not be read and a patched LTS
            // release was reported as affected.
            if (BranchCeiling(top) is { } ceiling) { top = ceiling; incl = false; }
            var from = IsWild(v.Version) ? null : v.Version;
            var to = IsWild(top) ? null : top;
            // Apple writes bounds with the product name in them ("macOS Mojave 10.14.3", "iOS 12.1.3"). Unread, every
            // old Apple CVE came out as an unresolved "check this" at the top tier on current devices.
            var named = false;
            if (from is not null && !VersionCompare.IsParseable(from) && NamedVersion(from) is { } nf) { from = nf; named = true; }
            if (to is not null && !VersionCompare.IsParseable(to) && NamedVersion(to) is { } nt) { to = nt; named = true; }
            var conf = (from is null || VersionCompare.IsParseable(from)) && (to is null || VersionCompare.IsParseable(to))
                ? (named ? MatchConfidence.Likely : MatchConfidence.Exact) : MatchConfidence.Possible;
            var text = (from ?? "any") + " " + (incl ? "<= " : "< ") + (to ?? "any");
            yield return new Range(from, to, incl, affected, conf, text);
            // "changes" mark later sub-ranges with a different status
            if (v.Changes is { Count: > 0 })
            {
                foreach (var ch in v.Changes)
                {
                    if (string.IsNullOrWhiteSpace(ch.At)) continue;
                    var chAffected = (ch.Status ?? "").ToLowerInvariant() == "affected";
                    yield return new Range(ch.At, to, incl, chAffected, MatchConfidence.Likely, ch.At + " onwards: " + ch.Status);
                }
            }
            yield break;
        }

        var ver = v.Version?.Trim() ?? "";
        if (IsWild(ver))
        {
            // "0" alone, "*", "n/a": the CNA says every version or does not say
            yield return new Range(null, null, true, affected, ver is "*" or "all" or "any" ? MatchConfidence.Likely : MatchConfidence.Possible, "version " + (ver == "" ? "(blank)" : ver));
            yield break;
        }
        if (VersionCompare.IsParseable(ver) && !ver.Contains(' ') && !ver.Contains('<') && !ver.Contains('>'))
        {
            yield return new Range(ver, ver, true, affected, MatchConfidence.Exact, "= " + ver);
            yield break;
        }

        // lenient text forms produced by some CNAs
        var original = ver;
        ver = NormaliseText(ver);
        if (ver != original && VersionCompare.IsParseable(ver) && !ver.Contains(' ') && !ver.Contains('<') && !ver.Contains('>'))
        {
            yield return new Range(ver, ver, true, affected, MatchConfidence.Likely, original);
            yield break;
        }
        Match m;
        if ((m = RangeAtoB().Match(ver)).Success && VersionCompare.IsParseable(m.Groups["a"].Value) && VersionCompare.IsParseable(m.Groups["b"].Value))
        { yield return new Range(m.Groups["a"].Value, m.Groups["b"].Value, true, affected, MatchConfidence.Likely, ver); yield break; }
        if ((m = LessThanText().Match(ver)).Success && VersionCompare.IsParseable(m.Groups["b"].Value))
        { yield return new Range(null, m.Groups["b"].Value, Inclusive(ver), affected, MatchConfidence.Likely, ver); yield break; }
        if ((m = AndEarlierText().Match(ver)).Success && VersionCompare.IsParseable(m.Groups["b"].Value))
        { yield return new Range(null, m.Groups["b"].Value, true, affected, MatchConfidence.Likely, ver); yield break; }
        if ((m = GreaterEqText().Match(ver)).Success && VersionCompare.IsParseable(m.Groups["a"].Value))
        {
            var b = m.Groups["b"].Success && VersionCompare.IsParseable(m.Groups["b"].Value) ? m.Groups["b"].Value : null;
            yield return new Range(m.Groups["a"].Value, b, Inclusive(ver), affected, MatchConfidence.Likely, ver);
            yield break;
        }
        yield return new Range(null, null, true, affected, MatchConfidence.Possible, ver + " (unparsed)");
    }

    private static bool? Contains(Range r, string installed)
    {
        if (r.From is not null)
        {
            var c = VersionCompare.Compare(installed, r.From);
            if (c is null) return null;
            if (c < 0) return false;
        }
        if (r.To is not null)
        {
            var c = VersionCompare.Compare(installed, r.To);
            if (c is null) return null;
            if (r.ToInclusive ? c > 0 : c >= 0) return false;
        }
        return true;
    }

    public static List<AffectedVersion> ParseVersions(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return new();
        try { return JsonSerializer.Deserialize<List<AffectedVersion>>(json) ?? new(); }
        catch { return new(); }
    }

    /// <summary>Evaluate an installed version against one CNA affected entry.</summary>
    public static VersionMatchResult Evaluate(string? installed, List<AffectedVersion> versions, string? defaultStatus)
    {
        installed = installed?.Trim();
        var ranges = versions.SelectMany(Expand).ToList();
        // Where the record lists unaffected releases, the fix is the lowest of them above the installed version:
        // Jenkins files "unaffected: 0 to 1.606, 2.426.3 to 2.426.*, 2.440.1 to 2.440.*, 2.442 onwards", and for 2.440
        // the answer is 2.440.1, not the first entry listed. A start of "0" only says old releases were never
        // affected, so it is never a fix.
        var unaffectedStarts = versions.Where(v => (v.Status ?? "").Equals("unaffected", StringComparison.OrdinalIgnoreCase)
                                                   && VersionCompare.IsParseable(v.Version) && !AllZeros().IsMatch(v.Version!))
                                       .Select(v => v.Version!).ToList();
        string? fixedIn = null;
        if (!string.IsNullOrEmpty(installed) && VersionCompare.IsParseable(installed))
        {
            foreach (var u in unaffectedStarts)
                if (VersionCompare.Compare(u, installed) > 0 && (fixedIn is null || VersionCompare.Compare(u, fixedIn) < 0)) fixedIn = u;
        }
        fixedIn ??= unaffectedStarts.FirstOrDefault()
                    ?? ranges.Where(r => r.Affected && r.To is not null && !r.ToInclusive).Select(r => r.To).FirstOrDefault();

        if (string.IsNullOrEmpty(installed) || !VersionCompare.IsParseable(installed))
        {
            var any = ranges.Any(r => r.Affected) || (defaultStatus ?? "").Equals("affected", StringComparison.OrdinalIgnoreCase);
            return new VersionMatchResult(any ? VersionMatch.Unknown : VersionMatch.NotAffected, MatchConfidence.Possible,
                string.IsNullOrEmpty(installed) ? "installed version not declared on the watchlist; affected: " + Describe(ranges, defaultStatus)
                                                : "installed version '" + installed + "' could not be parsed; affected: " + Describe(ranges, defaultStatus),
                fixedIn);
        }

        var unknownSeen = false;
        MatchConfidence worst = MatchConfidence.Exact;
        // unaffected ranges take precedence when they explicitly contain the version
        foreach (var r in ranges.Where(r => !r.Affected))
        {
            var c = Contains(r, installed);
            if (c is null) { unknownSeen = true; continue; }
            if (c == true) return new VersionMatchResult(VersionMatch.NotAffected, r.Confidence, installed + " is inside the unaffected range " + r.Text, fixedIn);
        }
        foreach (var r in ranges.Where(r => r.Affected))
        {
            if (r.Confidence == MatchConfidence.Possible && r.From is null && r.To is null)
            {
                unknownSeen = true; continue; // wildcard or unparsed: cannot say
            }
            var c = Contains(r, installed);
            if (c is null) { unknownSeen = true; continue; }
            if (c == true)
            {
                if (r.Confidence < worst) worst = r.Confidence;
                // the fix is the top of the branch the installed version sits in, not the first branch listed
                var branchFix = r.To is null ? null : r.ToInclusive ? "a release later than " + r.To : r.To;
                return new VersionMatchResult(VersionMatch.Affected, worst, installed + " is inside the affected range " + r.Text, branchFix ?? fixedIn);
            }
        }
        if ((defaultStatus ?? "").Equals("affected", StringComparison.OrdinalIgnoreCase))
            return new VersionMatchResult(VersionMatch.Affected, MatchConfidence.Likely, "default status is affected and no unaffected range covers " + installed, fixedIn);
        if (unknownSeen)
            return new VersionMatchResult(VersionMatch.Unknown, MatchConfidence.Possible, "affected versions could not be fully parsed: " + Describe(ranges, defaultStatus), fixedIn);
        return new VersionMatchResult(VersionMatch.NotAffected, MatchConfidence.Exact, "no affected range covers " + installed + " (affected: " + Describe(ranges, defaultStatus) + ")", fixedIn);
    }

    public static string Describe(string? versionsJson, string? defaultStatus) => Describe(ParseVersions(versionsJson).SelectMany(Expand).ToList(), defaultStatus);

    private static string Describe(List<Range> ranges, string? defaultStatus)
    {
        var parts = ranges.Where(r => r.Affected).Select(r => r.Text).Take(6).ToList();
        if (parts.Count == 0) return (defaultStatus ?? "").Equals("affected", StringComparison.OrdinalIgnoreCase) ? "all versions (default status affected)" : "none stated";
        return string.Join(", ", parts) + (ranges.Count(r => r.Affected) > 6 ? ", ..." : "");
    }
}
