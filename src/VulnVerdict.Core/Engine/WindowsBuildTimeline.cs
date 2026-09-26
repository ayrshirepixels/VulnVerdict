using System.Text.Json;
using System.Text.RegularExpressions;

namespace VulnVerdict.Core.Engine;

/// <summary>
/// When Microsoft shipped which Windows build, per release line ("10.0.17763"), taken from the fixed builds in its own
/// security update data. Windows updates are cumulative and build numbers only go up within a release line, so a machine
/// running a build at least as new as one Microsoft shipped on or after a CVE's fix date has that fix. That settles old
/// CVEs whose record says "10.0.0 &lt; publication" and whose advisory names only a KB number.
/// </summary>
public sealed partial class WindowsBuildTimeline
{
    [GeneratedRegex(@"^\s*(10\.0\.(\d+)\.\d+)")] private static partial Regex WindowsBuild();

    private readonly Dictionary<string, List<(DateTime Date, string Build)>> _lines = new(StringComparer.Ordinal);

    public int Count => _lines.Values.Sum(l => l.Count);

    /// <summary>From (published, affectedJson) pairs of Microsoft advisories; rows whose product is a Windows edition only.</summary>
    public static WindowsBuildTimeline From(IEnumerable<(DateTime? Published, string? AffectedJson)> advisories)
    {
        var t = new WindowsBuildTimeline();
        var seen = new HashSet<(string, DateTime)>();
        foreach (var (published, json) in advisories)
        {
            if (published is null || string.IsNullOrEmpty(json)) continue;
            JsonDocument doc;
            try { doc = JsonDocument.Parse(json); } catch (JsonException) { continue; }
            using (doc)
            {
                if (doc.RootElement.ValueKind != JsonValueKind.Array) continue;
                foreach (var item in doc.RootElement.EnumerateArray())
                {
                    var product = item.TryGetProperty("product", out var p) ? p.GetString() ?? "" : "";
                    if (!product.StartsWith("Windows", StringComparison.OrdinalIgnoreCase)) continue;
                    var fixedIn = item.TryGetProperty("fixedIn", out var f) ? f.GetString() : null;
                    if (fixedIn is null || WindowsBuild().Match(fixedIn) is not { Success: true } m) continue;
                    var date = published.Value.Date;
                    if (!seen.Add((m.Groups[1].Value, date))) continue;
                    var line = "10.0." + m.Groups[2].Value;
                    (t._lines.TryGetValue(line, out var l) ? l : t._lines[line] = new()).Add((date, m.Groups[1].Value));
                }
            }
        }
        return t;
    }

    /// <summary>The lowest build on the installed build's release line that Microsoft shipped on or after <paramref name="date"/>.</summary>
    public (DateTime Date, string Build)? FirstBuildOnOrAfter(string installed, DateTime date)
    {
        if (WindowsBuild().Match(installed) is not { Success: true } m) return null;
        if (!_lines.TryGetValue("10.0." + m.Groups[2].Value, out var line)) return null;
        (DateTime Date, string Build)? best = null;
        foreach (var e in line)
        {
            if (e.Date < date.Date) continue;
            if (best is null || (VersionCompare.Compare(e.Build, best.Value.Build) ?? 0) < 0) best = e;
        }
        return best;
    }
}
