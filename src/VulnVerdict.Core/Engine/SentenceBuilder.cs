using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Engine;

/// <summary>
/// Section 6.5. Template: {Product} {version} on {asset}: {exploitation phrase}, {attack path phrase}, {exposure phrase}. {Fix phrase}.
/// Example: "FortiOS 7.2.5 on FW-EDGE-01: exploited in the wild, works over the network with no login, reachable from the internet. Fixed in 7.2.8."
/// </summary>
public static class SentenceBuilder
{
    public static string Build(WatchlistEntry entry, DecisionInputs inputs, CvssVector? cvss, VerdictTier tier, string? fixedIn, MatchConfidence confidence, bool versionUnknown)
    {
        var product = (entry.Vendor + " " + entry.Product).Trim();
        var version = string.IsNullOrWhiteSpace(entry.Version) ? "" : " " + entry.Version;
        var asset = string.IsNullOrWhiteSpace(entry.AssetName) ? "" : " on " + entry.AssetName;

        if (tier == VerdictTier.NotAffected)
            return product + version + asset + ": not affected, the installed version is outside the affected range.";

        var exploitation = inputs.Exploitation switch
        {
            Exploitation.Active => "exploited in the wild",
            Exploitation.PoC => "public exploit code exists",
            _ => "no known exploit yet"
        };

        var path = AttackPath(inputs, cvss);

        var exposure = inputs.DeclaredExposure switch
        {
            Exposure.Internet when inputs.ExposureCapped => "internet-facing but that does not help this attacker",
            Exposure.Internet => "reachable from the internet",
            Exposure.Internal => "reachable on the internal network only",
            Exposure.Isolated => "on an isolated network",
            _ => "not installed"
        };

        var fix = !string.IsNullOrWhiteSpace(fixedIn) ? " Fixed in " + fixedIn + "."
                : tier >= VerdictTier.NextPatchCycle ? " Check the vendor advisory for the fix." : "";

        var check = confidence == MatchConfidence.Possible
            ? (string.IsNullOrWhiteSpace(entry.Version) ? " Check this: the installed version is not on the watchlist."
               : versionUnknown ? " Check this: the vendor's affected-version data could not be read against " + entry.Version + "."
               : " Check this: the product match is not certain.")
            : "";

        return product + version + asset + ": " + exploitation + ", " + path + ", " + exposure + "." + fix + check;
    }

    public static string AttackPath(DecisionInputs inputs, CvssVector? cvss)
    {
        var login = cvss?.PrivilegesRequired switch
        {
            "N" => "with no login",
            "L" => "with an ordinary user login",
            "H" => "with an administrator login",
            _ => null
        };
        var ui = cvss?.UserInteraction switch
        {
            "R" or "P" or "A" => "and a user has to be tricked",
            _ => null
        };
        var basePhrase = inputs.AttackVector switch
        {
            AttackVector.Network => "works over the network",
            AttackVector.Adjacent => "works from the same network segment or VPN",
            AttackVector.Local => "needs a shell or a logged-in user on the box",
            AttackVector.Physical => "needs hands on the hardware",
            _ => "attack path not stated by the vendor"
        };
        var parts = new List<string> { basePhrase };
        if (login is not null && inputs.AttackVector is AttackVector.Network or AttackVector.Adjacent) parts.Add(login);
        if (ui is not null) parts.Add(ui);
        return string.Join(" ", parts);
    }
}
