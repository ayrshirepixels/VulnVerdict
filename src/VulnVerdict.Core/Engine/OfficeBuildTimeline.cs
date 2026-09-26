using System.Text.RegularExpressions;

namespace VulnVerdict.Core.Engine;

/// <summary>
/// Settles a Microsoft 365 Apps CVE from the date Microsoft fixed it and the release history of the installed version.
/// Every version ("2406", build 17726) gets its own series of updates (17726.20126, 17726.20160 ...), so the question is
/// whether the installed revision is at least the first one Microsoft shipped for that version on or after the fix date.
/// </summary>
public sealed partial class OfficeBuildTimeline
{
    public sealed record Assessment(bool Affected, string? FixedBuild, string Explanation);

    [GeneratedRegex(@"^\s*16\.0\.(\d+)\.(\d+)")] private static partial Regex OfficeBuild();

    private readonly Dictionary<int, List<(DateTime Date, int Revision, string Version)>> _builds = new();

    public int Count => _builds.Values.Sum(l => l.Count);

    public static OfficeBuildTimeline From(IEnumerable<(int Build, int Revision, string Version, DateTime Released)> releases)
    {
        var t = new OfficeBuildTimeline();
        foreach (var r in releases)
            (t._builds.TryGetValue(r.Build, out var l) ? l : t._builds[r.Build] = new()).Add((r.Released.Date, r.Revision, r.Version));
        return t;
    }

    /// <summary>Null when the installed build is not a Microsoft 365 Apps build this history knows.</summary>
    public Assessment? Assess(string installed, DateTime fixDate)
    {
        if (OfficeBuild().Match(installed) is not { Success: true } m) return null;
        var build = int.Parse(m.Groups[1].Value); var revision = int.Parse(m.Groups[2].Value);
        if (!_builds.TryGetValue(build, out var releases) || releases.Count == 0) return null;
        var version = releases[0].Version;
        var fix = fixDate.Date;
        var after = releases.Where(r => r.Date >= fix).ToList();
        if (after.Count > 0)
        {
            var first = after.OrderBy(r => r.Revision).First();
            var firstBuild = "16.0." + build + "." + first.Revision;
            if (revision >= first.Revision)
                return new Assessment(false, firstBuild, "Microsoft 365 Apps Version " + version + " received build " + build + "." + first.Revision + " on " + first.Date.ToString("d MMM yyyy")
                    + ", on or after the " + fix.ToString("MMMM yyyy") + " fix, and " + build + "." + revision + " is that build or later");
            if (releases.Any(r => r.Date < fix))
                return new Assessment(true, firstBuild, "Microsoft fixed this in the " + fix.ToString("MMMM yyyy") + " updates; for Version " + version + " that is build " + build + "." + first.Revision
                    + " (" + first.Date.ToString("d MMM yyyy") + "), and " + build + "." + revision + " is older");
            return null;   // a revision older than the version's first known release: not a build this history lists
        }
        var last = releases.OrderByDescending(r => r.Date).First();
        return new Assessment(true, null, "Microsoft 365 Apps Version " + version + " last received an update on " + last.Date.ToString("d MMM yyyy")
            + ", before this was fixed in " + fix.ToString("MMMM yyyy") + ": move to a supported version");
    }
}
