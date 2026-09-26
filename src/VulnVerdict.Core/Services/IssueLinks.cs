using System.Text.RegularExpressions;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Services;

/// <summary>
/// Pre-filled GitHub issue links. The console never posts anything: the link opens GitHub's new-issue form in the
/// person's own browser with the fields filled in, and nothing is sent until they review it and submit.
/// The asset's names, host names, owner and its own recorded addresses (passed in as names, because an IP-shaped
/// pattern would also eat four-part versions such as 12.1.2.172), plus anything shaped like a MAC or email address,
/// are replaced before they reach the link.
/// </summary>
public static partial class IssueLinks
{
    public const string Repository = "https://github.com/ayrshirepixels/VulnVerdict";
    /// <summary>Browsers and GitHub cope with long links, but a form stays readable when the evidence is kept short.</summary>
    public const int MaxEvidenceChars = 3000;

    [GeneratedRegex(@"\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", RegexOptions.IgnoreCase)] private static partial Regex Mac();
    [GeneratedRegex(@"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")] private static partial Regex Email();

    /// <summary>Replaces the given names and addresses, then anything shaped like a MAC or email address, with placeholders.</summary>
    public static string Redact(string text, IEnumerable<string?> names)
    {
        var s = text;
        foreach (var n in names.Where(n => !string.IsNullOrWhiteSpace(n) && n!.Trim().Length >= 3).Select(n => n!.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).OrderByDescending(n => n.Length))
            s = Regex.Replace(s, @"(?<![\w.-])" + Regex.Escape(n) + @"(?![\w-]|\.\w)", "[asset]", RegexOptions.IgnoreCase);
        s = Mac().Replace(s, "[mac]");
        s = Email().Replace(s, "[email]");
        return s;
    }

    public static string WrongVerdict(string cveId, string product, string? version, string verdict, IEnumerable<EvidenceClaim> evidence, IEnumerable<string?> redact, string consoleVersion)
    {
        var names = redact.ToList();
        var lines = evidence.Select((e, i) => (i + 1) + ". " + e.Claim + " (" + e.Source + ", " + e.RetrievedAt.ToString("yyyy-MM-dd") + ")");
        var ev = Redact(string.Join("\n", lines), names);
        if (ev.Length > MaxEvidenceChars) ev = ev[..MaxEvidenceChars] + "\n(shortened)";
        product = Redact(product, names);
        return Link("wrong-verdict.yml", "Wrong verdict: " + cveId + " on " + product + (string.IsNullOrWhiteSpace(version) ? "" : " " + version), new()
        {
            ["cve"] = cveId, ["product"] = product, ["version"] = version ?? "", ["verdict"] = Redact(verdict, names),
            ["evidence"] = ev, ["console-version"] = consoleVersion,
        });
    }

    public static string ConnectorProblem(string adapterId, string consoleVersion) =>
        Link("connector-problem.yml", "Connector: " + adapterId + ": ", new() { ["connector"] = adapterId, ["console-version"] = consoleVersion });

    private static string Link(string template, string title, Dictionary<string, string> fields) =>
        Repository + "/issues/new?template=" + template + "&title=" + Uri.EscapeDataString(title)
        + string.Concat(fields.Where(f => f.Value.Length > 0).Select(f => "&" + f.Key + "=" + Uri.EscapeDataString(f.Value)));
}
