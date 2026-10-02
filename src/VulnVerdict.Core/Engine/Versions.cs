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

    private static List<(bool numeric, long num, string text, bool post)> Segments(string v)
    {
        var list = new List<(bool, long, string, bool)>();
        var c = Clean(v);
        foreach (Match m in Segment().Matches(c))
        {
            var s = m.Value;
            if (char.IsDigit(s[0]))
            {
                if (!long.TryParse(s, out var n)) n = long.MaxValue;
                list.Add((true, n, s, false));
                continue;
            }
            var t = s.ToLowerInvariant();
            // A letter run glued to a number is a later build of that release: OpenSSL "1.1.1s" and "1.0.2zf", IOS XE
            // "17.9.4a". Read as a pre-release, 1.1.1s sorted below 1.1.1 and fell outside "1.1.1 to < 1.1.1t".
            // Spelled-out tags ("1.0.0beta", "2.0rc1") and Python-style "1.0a1" or "2.0b3" stay pre-releases.
            var glued = m.Index > 0 && char.IsDigit(c[m.Index - 1]);
            var digitAfter = m.Index + s.Length < c.Length && char.IsDigit(c[m.Index + s.Length]);
            var post = IsPostRelease(t) || (glued && !IsPreReleaseWord(t) && !(t is "a" or "b" && digitAfter));
            list.Add((false, 0, t, post));
        }
        return list;
    }

    /// <summary>
    /// Tags that mark a release after the bare version: PAN-OS hotfixes ("11.1.5-h1"), Sophos maintenance releases
    /// ("21.0 MR1"), Zyxel and OpenSSH patches ("5.21 Patch 1", "8.9p1"), service packs and updates.
    /// "11.1.5" is older than "11.1.5-h1", where "2.1.0" is newer than "2.1.0-beta".
    /// </summary>
    private static bool IsPostRelease(string t) => t is "h" or "hf" or "hotfix" or "p" or "patch" or "mr" or "sp" or "u" or "update";

    private static bool IsPreReleaseWord(string t) => t is "alpha" or "beta" or "rc" or "pre" or "preview" or "dev" or "snapshot";

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
                // "1.2" vs "1.2-h1" or "1.2a" (a hotfix, patch or later build of it) a is less
                return sb[i].numeric ? (sb.Skip(i).All(s => s.numeric && s.num == 0) ? 0 : -1) : sb[i].post ? -1 : 1;
            }
            if (!hb)
            {
                return sa[i].numeric ? (sa.Skip(i).All(s => s.numeric && s.num == 0) ? 0 : 1) : sa[i].post ? 1 : -1;
            }
            var x = sa[i];
            var y = sb[i];
            if (x.numeric && y.numeric)
            {
                if (x.num != y.num) return x.num.CompareTo(y.num);
                continue;
            }
            if (x.numeric != y.numeric)
            {
                // number beats tag at same position, except zeros against a later build: "1.1.1.0" is older than "1.1.1s"
                var (rest, tag, sign) = x.numeric ? (sa, y, 1) : (sb, x, -1);
                return tag.post && rest.Skip(i).All(s => s.numeric && s.num == 0) ? -sign : sign;
            }
            if (x.post != y.post) return x.post ? 1 : -1; // "1.1.1a" is later than "1.1.1-beta"
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

    // Free-text ranges, every one read by TextRange so a CVE 5 "version" string, a PSIRT advisory line and anything
    // else stored as version text mean the same thing. Each bound must be a dotted version (BoundVersion).
    [GeneratedRegex(@"^\s*(?:from\s+)?(?<a>v?\d+(?:\.\d+)+[a-z]*)-(?<b>v?\d+(?:\.\d+)+[a-z]*)\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex GluedDashRange();
    [GeneratedRegex(@"^\s*(?:from\s+)?(?<a>.+?)(?:\s+[-~]\s*|\s*[-~]\s+|\s*[–—]\s*)(?<b>.+?)\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex DashRange();
    [GeneratedRegex(@"^\s*(?:from\s+)?(?<a>.+?)\s+(?:to|through|thru)\s+(?<b>.+?)\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex WordRange();
    [GeneratedRegex(@"^\s*between\s+(?<a>.+?)\s+and\s+(?<b>.+?)\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex BetweenRange();
    [GeneratedRegex(@"^\s*(?<lo>>=|≥|>)\s*(?<a>[\w.\-]+)\s*(?:,|and|&&)?\s*(?<hi><=|≤|<)\s*(?<b>[\w.\-]+)\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex ComparatorPair();
    [GeneratedRegex(@"^\s*(?<a>[\w.\-]+)\s*(?<lo><=|≤|<)\s*[a-z]\w*\s*(?<hi><=|≤|<)\s*(?<b>[\w.\-]+)\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex ComparatorBetween();
    [GeneratedRegex(@"^\d+(?:\.\d+)+[\w.\-]*$")] private static partial Regex DottedBound();
    // Whole-number bounds ("5 - 7", "2019 to 2022"). Glued ("5-7") only reads as a range when it runs upwards.
    [GeneratedRegex(@"^\d{1,4}$")] private static partial Regex WholeBound();
    [GeneratedRegex(@"^\s*(?:from\s+)?(?<a>v?\d{1,4})-(?<b>v?\d{1,4})\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex GluedWholeRange();

    [GeneratedRegex(@"^\s*(?:<|<=|≤|prior to|before|earlier than|up to|through|below)\s*(?<b>[\w.\-]+)\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex LessThanText();
    [GeneratedRegex(@"^\s*(?<b>[\w.\-]+)\s*(?:and (?:earlier|prior|below|older)|or (?:earlier|prior|lower|older)|and before)(?:\s+versions?)?\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex AndEarlierText();
    [GeneratedRegex(@"^\s*(?:(?<op>>=|≥|>)|from|since|starting (?:with|from|at))\s*(?<a>[\w.\-]+)\s*(?:onwards?|and later)?\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex GreaterEqText();
    [GeneratedRegex(@"^\s*(?<a>[\w.\-]+?)\s*(?:\+|and (?:later|above|newer|higher|after|up)|or (?:later|above|newer|higher)|onwards?)(?:\s+(?:versions?|releases?))?\s*$", RegexOptions.IgnoreCase)]
    private static partial Regex AndLaterText();
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

    private static bool IsWild(string? s) => s is null || Wildcards.Contains(s.Trim().ToLowerInvariant());
    private static bool Inclusive(string s) => Regex.IsMatch(s, @"<=|≤|through|thru|up to|and earlier|and prior|or earlier|or prior|or lower|and below|and older|or older", RegexOptions.IgnoreCase);

    private sealed record Range(string? From, string? To, bool ToInclusive, bool Affected, MatchConfidence Confidence, string Text, bool FromInclusive = true)
    {
        public bool Unbounded => From is null && To is null;
    }

    [GeneratedRegex(@"\d+(?:\.\d+)+")] private static partial Regex DottedToken();
    [GeneratedRegex(@"^(?<p>(?:\d+\.)+)(?<d>\d{1,12})x$", RegexOptions.IgnoreCase)] private static partial Regex DigitRunX();
    [GeneratedRegex(@"\b(before|prior|earlier|later|through|thru|since|up to|below|above|older|newer|and|or|to|from|until|between)\b|[<>=,≤≥]", RegexOptions.IgnoreCase)] private static partial Regex RangeWords();
    [GeneratedRegex(@"^\s*(?<v>\d+(?:\.\d+)+)\s*(?:\(\s*(?:x64|x86|amd64|arm64|64-bit|32-bit)\s*\)|(?:32|64)[ -]?bit|x64|x86)\s*$", RegexOptions.IgnoreCase)] private static partial Regex ArchSuffixed();
    // One release written as one token: "7.2.5", "v2.1.0", "7.1.1-7058", "1.2.3-rc.1", "1.2.3+build.5". Anything else
    // (lists, "1.2.x", trailing "+") is not one version and must not be compared as one.
    [GeneratedRegex(@"^v?\d[\w.\-]*(?:\+[\w.\-]+)?$", RegexOptions.IgnoreCase)] private static partial Regex SingleToken();
    [GeneratedRegex(@"(?:^|[.\-])(?:x|\*)(?:$|[.\-])", RegexOptions.IgnoreCase)] private static partial Regex WildSegment();

    /// <summary>
    /// "macOS Mojave 10.14.3" to "10.14.3", "iOS 12.1.3" to "12.1.3", "iTunes 12.9.3 for Windows" to "12.9.3": the one
    /// dotted version inside a bound that starts with a name. Null when there is none, or more than one to choose from.
    /// </summary>
    internal static string? NamedVersion(string bound)
    {
        var tokens = DottedToken().Matches(bound);
        return tokens.Count == 1 && char.IsLetter(bound.TrimStart()[0]) ? tokens[0].Value : null;
    }

    /// <summary>
    /// One end of a text range: a dotted version, optionally after a product name ("FortiOS 7.0.0", "v1.1.0"). Null
    /// for anything else, so "7.1.1-7058" or "1.2.3-rc.1" never splits into a range of two halves.
    /// </summary>
    private static string? BoundVersion(string bound, bool allowWhole = false)
    {
        var words = bound.Trim().TrimEnd(',').Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (words.Length == 0 || words[..^1].Any(w => !char.IsLetter(w[0]) || RangeWords().IsMatch(w))) return null;
        var last = VersionCompare.Clean(words[^1]);
        return DottedBound().IsMatch(last) || (allowWhole && WholeBound().IsMatch(last)) ? last : null;
    }

    /// <summary>
    /// Two-ended free-text ranges: "1.1.0-5.0.0", "1.1.0 - 5.0.0", "1.1.0 – 5.0.0", "from 1.1.0 through 5.0.0",
    /// "between 1.1.0 and 5.0.0", ">= 1.1.0, < 5.0.0", "1.1.0 <= x < 5.0.0". Spelled ranges include both ends;
    /// comparators keep the bound as written. A range written backwards is returned as unparsed, never as a range
    /// that contains nothing. Null when the text is not a two-ended range.
    /// </summary>
    private static Range? TextRange(string text, bool affected)
    {
        string? a = null, b = null;
        bool fromIncl = true, toIncl = true;
        Match m;
        if ((m = ComparatorPair().Match(text)).Success || (m = ComparatorBetween().Match(text)).Success)
        {
            a = BoundVersion(m.Groups["a"].Value, allowWhole: true);
            b = BoundVersion(m.Groups["b"].Value, allowWhole: true);
            fromIncl = m.Groups["lo"].Value is ">=" or "≥" or "<=" or "≤";
            toIncl = m.Groups["hi"].Value is "<=" or "≤";
        }
        else if ((m = GluedWholeRange().Match(text)).Success)
        {
            // "5-7" is a range; "10-3" is one version with a build number, as before
            a = VersionCompare.Clean(m.Groups["a"].Value);
            b = VersionCompare.Clean(m.Groups["b"].Value);
            if (VersionCompare.Compare(a, b) >= 0) return null;
        }
        else
        {
            foreach (var re in new[] { GluedDashRange(), BetweenRange(), WordRange(), DashRange() })
            {
                if (!(m = re.Match(text)).Success) continue;
                a = BoundVersion(m.Groups["a"].Value, allowWhole: true);
                b = BoundVersion(m.Groups["b"].Value, allowWhole: true);
                if (a is not null && b is not null) break;
            }
        }
        if (a is null || b is null) return null;
        if (VersionCompare.Compare(a, b) > 0)
            return new Range(null, null, true, affected, MatchConfidence.Possible, text + " (range written backwards, unparsed)");
        // One dotted end and one bare number is only a range while the number could be a major release: in
        // "7.1.1 - 7058" it is a build number, and that text is one version as before.
        if (WholeBound().IsMatch(a) != WholeBound().IsMatch(b) && (WholeBound().IsMatch(a) ? a : b).Length > 3) return null;
        // A whole number at the top of an affected range means the whole of that line: "5 - 7" covers 7.2.3, so the
        // range ends just before 8. Read as 7.0.0 exactly, every 7.x release would have been cleared. An unaffected
        // range is not widened: there the wider reading is the one that clears releases nobody cleared.
        if (affected && toIncl && WholeBound().IsMatch(b)) { b = (int.Parse(b) + 1).ToString(); toIncl = false; }
        return new Range(a, b, toIncl, affected, MatchConfidence.Likely, text, fromIncl);
    }

    private static IEnumerable<Range> Expand(AffectedVersion v)
    {
        var status = (v.Status ?? "affected").ToLowerInvariant();
        var affected = status == "affected";
        if (status == "unknown") yield break;

        // A git commit hash is not a version and has no order we can compare against: "affected" here cannot be
        // checked, and "unaffected" says nothing about the installed release.
        if ((v.VersionType ?? "").Equals("git", StringComparison.OrdinalIgnoreCase))
        {
            if (affected) yield return new Range(null, null, true, true, MatchConfidence.Possible, "git commit " + (v.Version ?? "?") + " (not comparable)");
            yield break;
        }

        // structured range
        if (!string.IsNullOrWhiteSpace(v.LessThan) || !string.IsNullOrWhiteSpace(v.LessThanOrEqual))
        {
            var top = !string.IsNullOrWhiteSpace(v.LessThan) ? v.LessThan : v.LessThanOrEqual;
            var incl = string.IsNullOrWhiteSpace(v.LessThan);
            // A branch bound such as "2.440.*" (Jenkins, Maven-style records) means the whole 2.440 line: the range
            // ends just before 2.441. Without this, "2.440.1 to 2.440.*" could not be read and a patched LTS
            // release was reported as affected.
            if (BranchCeiling(top) is { } ceiling) { top = ceiling; incl = false; }
            // Adobe writes a run of builds as "20.005.3031x" (30310 to 30319): the range ends just before 20.005.30320
            if (top is not null && DigitRunX().Match(top.Trim()) is { Success: true } xm)
            {
                top = xm.Groups["p"].Value + (long.Parse(xm.Groups["d"].Value) + 1) + "0"; incl = false;
            }
            var from = IsWild(v.Version) ? null : v.Version;
            if (from is not null && DigitRunX().Match(from.Trim()) is { Success: true } fm) from = fm.Groups["p"].Value + fm.Groups["d"].Value + "0";
            var to = IsWild(top) ? null : top;
            // Apple writes bounds with the product name in them ("macOS Mojave 10.14.3", "iOS 12.1.3"). Unread, every
            // old Apple CVE came out as an unresolved "check this" at the top tier on current devices.
            var named = false;
            if (from is not null && !VersionCompare.IsParseable(from) && NamedVersion(from) is { } nf) { from = nf; named = true; }
            if (to is not null && !VersionCompare.IsParseable(to) && NamedVersion(to) is { } nt) { to = nt; named = true; }
            var conf = (from is null || VersionCompare.IsParseable(from)) && (to is null || VersionCompare.IsParseable(to))
                ? (named ? MatchConfidence.Likely : MatchConfidence.Exact) : MatchConfidence.Possible;
            var text = (from ?? "any") + " " + (incl ? "<= " : "< ") + (to ?? "any");

            // "changes" split the range: each status holds from its "at" up to the next change, the last one up to the
            // top of the range. Letting every change run to the top let an early "unaffected" hide a later "affected".
            var changes = (v.Changes ?? new()).Where(c => !string.IsNullOrWhiteSpace(c.At)).ToList();
            if (changes.Count == 0)
            {
                yield return new Range(from, to, incl, affected, conf, text);
                yield break;
            }
            var ordered = changes.All(c => VersionCompare.IsParseable(c.At));
            if (ordered) changes.Sort((x, y) => VersionCompare.Compare(x.At, y.At)!.Value);
            // unordered "at" values: keep the old whole-range reading, but never at better than Possible
            if (ordered) yield return new Range(from, changes[0].At, false, affected, conf, (from ?? "any") + " < " + changes[0].At);
            else yield return new Range(from, to, incl, affected, MatchConfidence.Possible, text);
            for (var i = 0; i < changes.Count; i++)
            {
                var ch = changes[i];
                var chAffected = (ch.Status ?? "").ToLowerInvariant() == "affected";
                var last = !ordered || i == changes.Count - 1;
                var chTo = last ? to : changes[i + 1].At;
                yield return new Range(ch.At, chTo, last && incl, chAffected, ordered ? MatchConfidence.Likely : MatchConfidence.Possible,
                    ch.At + (last ? " onwards" : " < " + chTo) + ": " + ch.Status);
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

        // lenient text forms produced by some CNAs
        Match m0;
        var original = ver;
        ver = NormaliseText(ver);
        // two-ended ranges first: "5.0.0-5.0.5" is one token and would otherwise be read as a single exact version
        if (TextRange(ver, affected) is { } tr) { yield return tr; yield break; }
        // "7.2.*" or "7.2.x": the whole 7.2 line
        if (BranchCeiling(ver) is { } line)
        {
            yield return new Range(ver[..^2], line, false, affected, MatchConfidence.Likely, original);
            yield break;
        }
        if (SingleToken().IsMatch(ver) && !WildSegment().IsMatch(ver))
        {
            yield return new Range(ver, ver, true, affected, ver == original ? MatchConfidence.Exact : MatchConfidence.Likely, ver == original ? "= " + ver : original);
            yield break;
        }
        // "24.08 (x64)", "7.11 (64-bit)", "5.61 32 Bit": one release, written with its architecture (7-Zip, WinRAR records)
        if ((m0 = ArchSuffixed().Match(original)).Success)
        {
            yield return new Range(m0.Groups["v"].Value, m0.Groups["v"].Value, true, affected, MatchConfidence.Likely, original);
            yield break;
        }
        Match m;
        if ((m = LessThanText().Match(ver)).Success && VersionCompare.IsParseable(m.Groups["b"].Value))
        { yield return new Range(null, m.Groups["b"].Value, Inclusive(ver), affected, MatchConfidence.Likely, ver); yield break; }
        if ((m = AndEarlierText().Match(ver)).Success && VersionCompare.IsParseable(m.Groups["b"].Value))
        { yield return new Range(null, m.Groups["b"].Value, true, affected, MatchConfidence.Likely, ver); yield break; }
        // lower bound only: ">= 7.2.5", "from 7.2.5", "7.2.5 and later", "7.2.5 onwards", "7.2.5+"
        if (((m = GreaterEqText().Match(ver)).Success || (m = AndLaterText().Match(ver)).Success) && VersionCompare.IsParseable(m.Groups["a"].Value))
        { yield return new Range(m.Groups["a"].Value, null, true, affected, MatchConfidence.Likely, ver, m.Groups["op"].Value != ">"); yield break; }
        // "Catalina 10.15.3": one release, written with its name (Apple). Checked after the range wordings above, and
        // never when the text reads like a range ("prior to 2.0"), so only a plain name plus one version gets here.
        if (char.IsLetter(original[0]) && !RangeWords().IsMatch(original) && NamedVersion(original) is { } single)
        {
            yield return new Range(single, single, true, affected, MatchConfidence.Likely, original);
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
            if (r.FromInclusive ? c < 0 : c <= 0) return false;
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
        // affected, so it is never a fix. A git commit is never a fix either, even one that starts with a digit.
        var unaffectedStarts = versions.Where(v => (v.Status ?? "").Equals("unaffected", StringComparison.OrdinalIgnoreCase)
                                                   && !(v.VersionType ?? "").Equals("git", StringComparison.OrdinalIgnoreCase)
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
            // an unaffected entry we could not read ("n/a", "7.2.5 and later" before it was understood) says nothing
            // about this release; read as "every version", it overrode every affected range in the record
            // A stated "unaffected: *" is weighed after the affected ranges: a specific affected range beats a blanket.
            if (r.Unbounded) continue;
            var c = Contains(r, installed);
            if (c is null) { unknownSeen = true; continue; }
            if (c == true) return new VersionMatchResult(VersionMatch.NotAffected, r.Confidence, installed + " is inside the unaffected range " + r.Text, fixedIn);
        }
        foreach (var r in ranges.Where(r => r.Affected))
        {
            if (r.Confidence == MatchConfidence.Possible && r.Unbounded)
            {
                unknownSeen = true; continue; // wildcard or unparsed: cannot say
            }
            var c = Contains(r, installed);
            if (c is null) { unknownSeen = true; continue; }
            if (r.Confidence < worst) worst = r.Confidence;
            if (c == true)
            {
                // the fix is the top of the branch the installed version sits in, not the first branch listed
                var branchFix = r.To is null ? null : r.ToInclusive ? "a release later than " + r.To : r.To;
                return new VersionMatchResult(VersionMatch.Affected, r.Confidence, installed + " is inside the affected range " + r.Text, branchFix ?? fixedIn);
            }
        }
        var blanket = ranges.FirstOrDefault(r => !r.Affected && r.Unbounded && r.Confidence != MatchConfidence.Possible);
        if (blanket is not null && !unknownSeen)
            return new VersionMatchResult(VersionMatch.NotAffected, blanket.Confidence, "the record states every version is unaffected and no affected range covers " + installed, fixedIn);
        if ((defaultStatus ?? "").Equals("affected", StringComparison.OrdinalIgnoreCase))
            return new VersionMatchResult(VersionMatch.Affected, MatchConfidence.Likely, "default status is affected and no unaffected range covers " + installed, fixedIn);
        if (unknownSeen)
            return new VersionMatchResult(VersionMatch.Unknown, MatchConfidence.Possible, "affected versions could not be fully parsed: " + Describe(ranges, defaultStatus), fixedIn);
        // Nothing stated at all (no rows, or JSON that would not parse) and no default: the record cannot clear this
        // release. CVE 5 reads a missing defaultStatus as "unknown".
        if (versions.Count == 0 && !(defaultStatus ?? "").Equals("unaffected", StringComparison.OrdinalIgnoreCase))
            return new VersionMatchResult(VersionMatch.Unknown, MatchConfidence.Possible, "the record states no versions and no default status", fixedIn);
        // "not inside" is only as sure as the weakest range it was checked against: a text range read leniently
        // clears a release at "likely", not "exact"
        return new VersionMatchResult(VersionMatch.NotAffected, worst, "no affected range covers " + installed + " (affected: " + Describe(ranges, defaultStatus) + ")", fixedIn);
    }

    public static string Describe(string? versionsJson, string? defaultStatus) => Describe(ParseVersions(versionsJson).SelectMany(Expand).ToList(), defaultStatus);

    private static string Describe(List<Range> ranges, string? defaultStatus)
    {
        var parts = ranges.Where(r => r.Affected).Select(r => r.Text).Take(6).ToList();
        if (parts.Count == 0) return (defaultStatus ?? "").Equals("affected", StringComparison.OrdinalIgnoreCase) ? "all versions (default status affected)" : "none stated";
        return string.Join(", ", parts) + (ranges.Count(r => r.Affected) > 6 ? ", ..." : "");
    }
}
