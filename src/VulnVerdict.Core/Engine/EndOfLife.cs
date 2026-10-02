using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Engine;

public enum EolState { Supported = 0, EndingSoon = 1, EndOfLife = 2 }

/// <summary>
/// Where one product at one version stands with its vendor's support. A <see cref="Suggestion"/> came from the fuzzy
/// name fallback and is only ever shown as "possibly"; it flags nothing.
/// </summary>
public sealed record EolFinding(string Slug, string ProductLabel, string Cycle, string CycleLabel, EolState State, DateTime? EolDate, int? Days, DateTime? ExtendedUntil, string? Link, bool Suggestion = false, bool VersionKeyed = true)
{
    /// <summary>True for an "End of life" or "End of life in N days" flag from the curated map.</summary>
    public bool Flagged => State != EolState.Supported && !Suggestion;

    public string Flag => State switch
    {
        EolState.EndOfLife => "End of life",
        EolState.EndingSoon => "End of life in " + Days + (Days == 1 ? " day" : " days"),
        _ => "Supported"
    };

    /// <summary>"FortiOS 7.2", "Microsoft SQL Server 2019 'Aris/Seattle'", "macOS 14 (Sonoma)".</summary>
    public string Release => CycleLabel.Length > 0 && char.IsLetter(CycleLabel[0]) && CycleLabel.Contains(' ') ? CycleLabel : (ProductLabel + " " + CycleLabel).Trim();

    public string Describe() => State switch
    {
        EolState.EndOfLife => Release + " is past vendor support" + (EolDate is { } d ? " (ended " + Day(d) + ")" : "")
                              + (ExtendedUntil is { } x ? "; paid extended support runs to " + Day(x) : ""),
        EolState.EndingSoon => Release + " reaches the end of vendor support on " + Day(EolDate!.Value) + " (in " + Days + (Days == 1 ? " day" : " days") + ")",
        _ => Release + " is supported" + (EolDate is { } d ? " until " + Day(d) : "")
    };

    private static string Day(DateTime d) => d.ToString("d MMM yyyy", CultureInfo.InvariantCulture);

    public const string Source = "endoflife.date";
    /// <summary>The advice that replaces "Fixed in ..." for a release the vendor no longer patches.</summary>
    public const string NoFixAdvice = "No fix will be released for this version: upgrade or replace.";

    public EvidenceClaim Evidence(DateTime now) => new(Flag + ": " + Describe(), Link ?? Source, now);

    /// <summary>
    /// <see cref="NoFixAdvice"/> for a release past support, unless the fix the evidence names is in this same release
    /// (it shipped before support ended): then the usual "Fixed in" stands and the flag stays in the evidence.
    /// </summary>
    public string? FixAdvice(string? installed, string? fixedIn)
    {
        if (State != EolState.EndOfLife || Suggestion) return null;
        if (EolCycles.Numeric(fixedIn) is { } fix)
        {
            // a release found by its version (7.2.5 in cycle 7.2): the fix is in it when it starts the same way
            if (VersionKeyed && EolCycles.NumericKey(Cycle) is { } key) { if (fix == key || fix.StartsWith(key + ".", StringComparison.Ordinal)) return null; }
            else if (EolCycles.Numeric(installed) is { } have && SameReleaseLine(have, fix)) return null;
        }
        return NoFixAdvice;
    }

    /// <summary>For releases named by year or edition: 10.0.19045.3803 and 10.0.19045.5131 are one Windows release, 15.2.1258 and 15.2.1544 one Exchange.</summary>
    private static bool SameReleaseLine(string installed, string fix)
    {
        var a = installed.Split('.'); var b = fix.Split('.');
        if (a.Length < 2 || b.Length < 2 || a[0] != b[0] || a[1] != b[1]) return false;
        return !(a[0] == "10" && a[1] == "0") || (a.Length >= 3 && b.Length >= 3 && a[2] == b[2]);
    }
}

public static class EolMath
{
    /// <summary>
    /// The support state on <paramref name="today"/>. A release is past support from its end date on; within
    /// <paramref name="warnDays"/> of it, it is ending soon. No date: past support only when the source says so outright.
    /// </summary>
    public static (EolState State, int? Days) Assess(DateTime? eolFrom, bool isEol, DateTime today, int warnDays)
    {
        if (eolFrom is not { } end) return (isEol ? EolState.EndOfLife : EolState.Supported, null);
        var days = (end.Date - today.Date).Days;
        if (days <= 0) return (EolState.EndOfLife, null);
        return days <= warnDays ? (EolState.EndingSoon, days) : (EolState.Supported, days);
    }
}

/// <summary>How an installed product is tied to one release cycle of its endoflife.date product.</summary>
public enum CycleBy
{
    /// <summary>The cycle name leads the version: 7.2.5 is cycle 7.2, 22.04.4 is 22.04.</summary>
    Version,
    /// <summary>The cycle is in the product name: Windows Server 2019, Windows 11 Version 24H2, Office 2016.</summary>
    Name,
    /// <summary>The name when it carries a year (SQL Server 2019), else the version (15.0.2000).</summary>
    NameThenVersion
}

/// <summary>
/// The curated map from the console's vendor and product names to endoflife.date products, for the estate a small
/// business runs. Matched on the lower-cased "vendor product" text, first entry wins. SonicOS, Sophos Firewall and
/// pfSense are not here because endoflife.date does not track them; Microsoft 365 Apps, Chrome, Edge and Firefox are
/// evergreen and have no release to outlive.
/// </summary>
public static class EolProductMap
{
    public sealed record Entry(string Slug, Regex Match, CycleBy By, Regex? Not = null, bool VersionFromName = false, bool Java = false);

    private static Regex Rx(string pattern) => new(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static Entry E(string slug, string match, CycleBy by = CycleBy.Version, string? not = null, bool versionFromName = false, bool java = false) =>
        new(slug, Rx(match), by, not is null ? null : Rx(not), versionFromName, java);

    private const string JavaNot = @"javascript|java\s?script|auto updater|update scheduler|java card|javafx";

    public static readonly IReadOnlyList<Entry> Entries = new[]
    {
        // Microsoft
        E("windows-server", @"\bwindows server\b", CycleBy.Name),
        E("windows", @"\bwindows (10|11|8\.1|8|7)\b", CycleBy.Name, not: @"\b(sdk|kit|driver|runtime|redistributable|for windows|defender|terminal|subsystem)\b"),
        E("office", @"\boffice\b.*\b(20\d\d|ltsc)\b", CycleBy.Name, not: @"365|\b(online|web apps|compatibility|viewer|proof|mui|click-to-run extensibility|deployment)\b"),
        E("mssqlserver", @"\bsql server\b", CycleBy.NameThenVersion, not: @"management studio|native client|odbc|ole ?db|compact|report|browser|vss writer|setup|t-sql|clr types|management objects|data-tier|driver|language service|policies|batch parser|localdb"),
        E("msexchange", @"\bexchange server\b", CycleBy.Name),
        E("sharepoint", @"\bsharepoint (server|foundation)\b", CycleBy.Name, not: @"designer|online"),
        E("dotnetfx", @"\.net framework\b", not: @"targeting pack|sdk|multi-targeting|developer pack"),
        E("dotnet", @"\.net (core )?(runtime|sdk|host)\b|\basp\.net core\b|\bwindows desktop runtime\b|^(microsoft )?\.net( core)?( \d|$)", not: @"framework|toolset|templates|targeting pack|apphost", versionFromName: true),
        E("powershell", @"\bpowershell (\d|core)|^(microsoft )?powershell$", not: @"windows powershell|\bise\b|module"),
        // firewalls and network devices
        E("fortios", @"\bfortios\b|\bfortigate\b"),
        E("panos", @"\bpan-?os\b"),
        E("cisco-ios-xe", @"\bios[ -]xe\b"),
        E("big-ip", @"\bbig-?ip\b"),
        E("opnsense", @"\bopnsense\b"),
        E("routeros", @"\brouteros\b"),
        // virtualisation
        E("esxi", @"\besxi?\b"),
        E("vcenter", @"\bvcenter\b"),
        E("proxmox-ve", @"\bproxmox (ve|virtual environment)\b"),
        // operating systems
        E("ubuntu", @"\bubuntu\b", not: @"\bpro\b client"),
        E("debian", @"\bdebian\b"),
        E("rhel", @"\bred hat enterprise linux\b|\brhel\b"),
        E("almalinux", @"\balma ?linux\b"),
        E("rocky-linux", @"\brocky( linux)?\b"),
        E("centos-stream", @"\bcentos stream\b"),
        E("centos", @"\bcentos\b"),
        E("oracle-linux", @"\boracle linux\b"),
        E("sles", @"\bsuse linux enterprise server\b|\bsles\b"),
        E("amazon-linux", @"\bamazon linux\b"),
        E("macos", @"\bmac ?os( x)?\b|\bos x\b", not: @"\bfor mac"),
        E("ipados", @"\bipados\b"),
        E("ios", @"\b(apple )?(ios|iphone os)\b", not: @"\bcisco\b|\bxe\b|\bxr\b"),
        // runtimes and languages
        E("php", @"\bphp\b", not: @"phpmyadmin|composer|\bpecl\b|\bpear\b"),
        E("nodejs", @"\bnode\.?js\b|^node(\.js)? node$|^node$"),
        E("python", @"\bc?python\b", not: @"launcher|pywin|\bpip\b|setuptools|extension|tools for|documentation|test suite|tcl/tk|utility scripts|development libraries|standard library|executables|core interpreter|add to path|bootstrap"),
        E("eclipse-temurin", @"\btemurin\b|\badoptium\b", java: true),
        E("amazon-corretto", @"\bcorretto\b", java: true),
        E("azul-zulu", @"\bzulu\b", java: true),
        E("microsoft-build-of-openjdk", @"microsoft build of openjdk", java: true),
        E("oracle-jdk", @"\bjava( se|\(tm\)| \d| platform| runtime| development)|\boracle (jdk|jre|java)\b|\bjava$|\b(jdk|jre)\b", not: JavaNot, java: true),
        // servers and databases
        E("apache-http-server", @"\bapache http server\b|\bapache httpd\b|^apache( software foundation)? apache$"),
        E("tomcat", @"\btomcat\b", not: @"connector|native"),
        E("nginx", @"\bnginx\b", not: @"ingress|unit|proxy manager"),
        E("mysql", @"\bmysql\b", not: @"workbench|connector|router|shell|odbc|installer|notifier|utilities|for visual studio|documents|examples"),
        E("mariadb", @"\bmariadb\b", not: @"connector"),
        E("postgresql", @"\bpostgres(ql)?\b", not: @"odbc|pgadmin|jdbc|driver"),
        E("mongodb", @"\bmongodb\b", not: @"compass|shell|tools|driver"),
        E("redis", @"\bredis\b", not: @"insight|desktop"),
        E("openssl", @"\bopenssl\b"),
        // applications a small estate tends to host
        E("veeam-backup-and-replication", @"\bveeam\b.*\bbackup (&|and) replication\b|^veeam veeam$"),
        E("gitlab", @"\bgitlab\b", not: @"runner"),
        E("jenkins", @"\bjenkins\b", not: @"plugin"),
        E("confluence", @"\bconfluence\b"),
        E("jira-software", @"\bjira\b"),
        E("wordpress", @"^wordpress( wordpress)?$"),
        E("nextcloud", @"\bnextcloud\b", not: @"client|desktop|talk"),
        E("zabbix", @"\bzabbix\b", not: @"agent"),
    };

    public static Entry? Lookup(string text)
    {
        foreach (var e in Entries)
            if (e.Match.IsMatch(text) && e.Not?.IsMatch(text) != true) return e;
        return null;
    }
}

/// <summary>Picks the release cycle an installed product belongs to.</summary>
public static partial class EolCycles
{
    [GeneratedRegex(@"^\s*v?(\d+(?:\.\d+)*)", RegexOptions.IgnoreCase)] private static partial Regex LeadingNumeric();
    [GeneratedRegex(@"\d+(?:\.\d+)+|\b\d+\b")] private static partial Regex AnyVersion();
    [GeneratedRegex(@"[a-z0-9]+")] private static partial Regex Token();
    [GeneratedRegex(@"^(\d{4}|\d{2}h\d)$")] private static partial Regex ReleaseToken();
    [GeneratedRegex(@"^sp\d$")] private static partial Regex ServicePack();

    /// <summary>The leading dotted number of a version ("7.2.5" from "7.2.5-build1639", "1.1.1" from "1.1.1w"), or null.</summary>
    public static string? Numeric(string? version)
    {
        if (string.IsNullOrWhiteSpace(version)) return null;
        var m = LeadingNumeric().Match(version);
        return m.Success ? m.Groups[1].Value : null;
    }

    /// <summary>The number a cycle name starts with, when the name is that number or continues with a dash ("13.0-sp3"); null for "23h2-ac".</summary>
    public static string? NumericKey(string cycle)
    {
        var key = Numeric(cycle);
        return key is not null && (cycle.Length == key.Length || cycle[key.Length] is '-' or ' ') ? key : null;
    }

    // edition and channel markers in cycle names: not part of what identifies the release
    private static readonly HashSet<string> Markers = new(StringComparer.Ordinal) { "e", "w", "lts", "ltsc", "ltsb", "iot", "sac", "ac", "acp" };
    private static bool LongTerm(IEnumerable<string> tokens) => tokens.Any(t => t is "lts" or "ltsc" or "ltsb" or "iot");

    // Windows reports a build, not a release name
    private static readonly Dictionary<string, string[]> WindowsBuilds = new()
    {
        ["19044"] = new[] { "10", "21h2" }, ["19045"] = new[] { "10", "22h2" }, ["22000"] = new[] { "11", "21h2" }, ["22621"] = new[] { "11", "22h2" },
        ["22631"] = new[] { "11", "23h2" }, ["26100"] = new[] { "11", "24h2" }, ["26200"] = new[] { "11", "25h2" },
    };
    private static readonly Dictionary<string, string> ServerBuilds = new() { ["14393"] = "2016", ["17763"] = "2019", ["20348"] = "2022", ["26100"] = "2025" };
    private static readonly Dictionary<string, string> ExchangeVersions = new() { ["15.2"] = "2019", ["15.1"] = "2016", ["15.0"] = "2013", ["14"] = "2010" };

    /// <summary>The cycle, and whether it was found from the version (as opposed to a year or release name in the product name).</summary>
    public static (EolCycle Cycle, bool ByVersion)? Resolve(IReadOnlyList<EolCycle> cycles, EolProductMap.Entry entry, string text, string? version)
    {
        if (entry.By != CycleBy.Version && ByName(cycles, entry.Slug, text, version) is { } named) return (named, false);
        return entry.By != CycleBy.Name && ByVersion(cycles, entry, text, version) is { } versioned ? (versioned, true) : null;
    }

    private static EolCycle? ByVersion(IReadOnlyList<EolCycle> cycles, EolProductMap.Entry entry, string text, string? version)
    {
        // ".NET Runtime - 8.0.8" carries its version in the name; its installer's own version number is something else
        var fromName = AnyVersion().Match(text) is { Success: true } m ? m.Value : null;
        var installed = entry.VersionFromName ? Numeric(fromName) ?? Numeric(version) : Numeric(version) ?? Numeric(fromName);
        if (installed is null) return null;
        // Java 8 calls itself 1.8.0
        if (entry.Java && installed.StartsWith("1.", StringComparison.Ordinal) && installed.Length > 2) installed = installed[2..];

        EolCycle? best = null; var bestKey = "";
        foreach (var c in cycles)
        {
            if (NumericKey(c.Cycle) is not { } key) continue;
            if (installed != key && !installed.StartsWith(key + ".", StringComparison.Ordinal)) continue;
            var longer = key.Length > bestKey.Length;
            if (best is null || longer || (key.Length == bestKey.Length && Better(c, best, c.Cycle == key, best.Cycle == bestKey))) { best = c; bestKey = key; }
        }
        return best;
    }

    private static EolCycle? ByName(IReadOnlyList<EolCycle> cycles, string slug, string text, string? version)
    {
        var tokens = Token().Matches(text).Select(t => t.Value).ToHashSet(StringComparer.Ordinal);
        var build = version is not null && version.StartsWith("10.0.", StringComparison.Ordinal) ? version.Split('.').ElementAtOrDefault(2) : null;
        if (slug == "windows" && !tokens.Any(t => t.Length == 4 && t[2] == 'h') && build is not null && WindowsBuilds.TryGetValue(build, out var release)) tokens.UnionWith(release);
        if (slug == "windows-server" && !tokens.Any(t => t.Length == 4 && t.StartsWith("20", StringComparison.Ordinal)) && build is not null && ServerBuilds.TryGetValue(build, out var year)) tokens.Add(year);
        if (slug == "msexchange" && Numeric(version) is { } ex && ExchangeVersions.FirstOrDefault(kv => ex == kv.Key || ex.StartsWith(kv.Key + ".", StringComparison.Ordinal)).Value is { } exYear) tokens.Add(exYear);
        var longTerm = LongTerm(tokens);

        EolCycle? best = null; var bestCount = 0;
        foreach (var c in cycles)
        {
            var name = c.Cycle.ToLowerInvariant().Split('-', StringSplitOptions.RemoveEmptyEntries);
            var count = Math.Max(Signature(name, tokens), Signature(Token().Matches((c.CycleLabel ?? "").ToLowerInvariant()).Select(t => t.Value).Where(t => ReleaseToken().IsMatch(t) || t == "r2"), tokens));
            if (count == 0) continue;
            var fits = LongTerm(name) == longTerm;
            if (best is null || count > bestCount || (count == bestCount && Better(c, best, fits, LongTerm(best.Cycle.ToLowerInvariant().Split('-')) == longTerm))) { best = c; bestCount = count; }
        }
        return best;
    }

    /// <summary>How many release tokens of a cycle the product text carries; 0 unless it carries all of them and one is a year or a release like 24h2.</summary>
    private static int Signature(IEnumerable<string> cycleTokens, HashSet<string> text)
    {
        var sig = cycleTokens.Where(t => !Markers.Contains(t) && !ServicePack().IsMatch(t)).ToList();
        return sig.Count > 0 && sig.All(text.Contains) && sig.Any(t => ReleaseToken().IsMatch(t)) ? sig.Count : 0;
    }

    /// <summary>Between two cycles that fit equally: the one that fits the edition, else the one supported longer, so a release is never called out of support while one of its editions is still in.</summary>
    private static bool Better(EolCycle a, EolCycle b, bool aFits, bool bFits)
    {
        if (aFits != bFits) return aFits;
        return End(a) > End(b);
    }

    private static DateTime End(EolCycle c) => c.EolFrom ?? (c.IsEol ? DateTime.MinValue : DateTime.MaxValue);
}

/// <summary>The stored release cycles, indexed for lookups by installed product. Built once per evaluation run or page load.</summary>
public sealed class EolIndex
{
    private readonly Dictionary<string, List<EolCycle>> _bySlug;
    private readonly Dictionary<string, string> _names = new(StringComparer.Ordinal);
    private readonly Dictionary<string, EolFinding?> _cache = new(StringComparer.Ordinal);

    public EolIndex(IEnumerable<EolCycle> cycles)
    {
        _bySlug = cycles.GroupBy(c => c.Slug, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.ToList(), StringComparer.Ordinal);
        // names for the fuzzy fallback: the product label, its slug and its aliases
        foreach (var (slug, list) in _bySlug)
            foreach (var name in new[] { slug, list[0].ProductLabel }.Concat((list[0].Aliases ?? "").Split('|', StringSplitOptions.RemoveEmptyEntries)))
                if (Normalizer.Norm(name) is { Length: >= 3 } n) _names.TryAdd(n, slug);
    }

    public bool Empty => _bySlug.Count == 0;

    public static async Task<EolIndex> LoadAsync(VvDbContext db, CancellationToken ct = default) => new(await db.EolCycles.AsNoTracking().ToListAsync(ct));

    /// <summary>
    /// The support state of an installed product, or null when it maps to no tracked release. With <paramref name="suggest"/>,
    /// a product the curated map does not know is tried by name against every endoflife.date product, and anything found
    /// that way is marked as a suggestion.
    /// </summary>
    public EolFinding? Find(string? vendor, string? product, string? version, DateTime today, int warnDays, bool suggest = false)
    {
        if (Empty || string.IsNullOrWhiteSpace(product)) return null;
        var key = string.Join('\u001f', vendor, product, version, suggest ? "s" : "");
        if (_cache.TryGetValue(key, out var cached)) return cached;
        return _cache[key] = Compute(vendor, product, version, today, warnDays, suggest);
    }

    private EolFinding? Compute(string? vendor, string product, string? version, DateTime today, int warnDays, bool suggest)
    {
        var text = Regex.Replace(((vendor ?? "") + " " + product).Trim().ToLowerInvariant(), @"\s+", " ");
        var entry = EolProductMap.Lookup(text);
        var suggestion = false;
        if (entry is null)
        {
            if (!suggest) return null;
            var p = Normalizer.Norm(product); var vp = Normalizer.Norm(vendor) + p;
            if (!_names.TryGetValue(p, out var slug) && !_names.TryGetValue(vp, out slug)) return null;
            entry = new EolProductMap.Entry(slug, new Regex("$^"), CycleBy.Version);
            suggestion = true;
        }
        if (!_bySlug.TryGetValue(entry.Slug, out var cycles) || EolCycles.Resolve(cycles, entry, text, version) is not var (cycle, byVersion)) return null;
        var (state, days) = EolMath.Assess(cycle.EolFrom, cycle.IsEol, today, warnDays);
        var extended = state == EolState.EndOfLife && cycle.EoesFrom is { } x && x.Date > today.Date ? x : (DateTime?)null;
        return new EolFinding(cycle.Slug, cycle.ProductLabel, cycle.Cycle, cycle.CycleLabel ?? cycle.Cycle, state, cycle.EolFrom, days, extended, cycle.Link, suggestion, byVersion);
    }
}
