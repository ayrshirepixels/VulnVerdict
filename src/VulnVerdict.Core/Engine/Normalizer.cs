using System.Text;
using System.Text.RegularExpressions;

namespace VulnVerdict.Core.Engine;

/// <summary>Product and vendor name normalisation used for matching CNA data to the watchlist.</summary>
public static partial class Normalizer
{
    [GeneratedRegex(@"[^a-z0-9]+")] private static partial Regex NonAlnum();
    [GeneratedRegex(@"\b(inc|ltd|llc|corp|corporation|co|gmbh|the)\b")] private static partial Regex Suffix();

    /// <summary>Lower-case, strip legal suffixes, collapse everything that is not a letter or digit.</summary>
    public static string Norm(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return "";
        var t = s.Trim().ToLowerInvariant();
        t = Suffix().Replace(t, " ");
        t = NonAlnum().Replace(t, "");
        return t;
    }

    public static string CveIdUpper(string s) => s.Trim().ToUpperInvariant();

    [GeneratedRegex(@"CVE-\d{4}-\d{4,}", RegexOptions.IgnoreCase)] private static partial Regex CveRx();
    public static IEnumerable<string> ExtractCveIds(string? text)
    {
        if (string.IsNullOrEmpty(text)) yield break;
        foreach (Match m in CveRx().Matches(text)) yield return m.Value.ToUpperInvariant();
    }
}
