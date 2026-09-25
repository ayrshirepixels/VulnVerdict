using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Engine;

/// <summary>What a verdict is about: a product at a version on an asset, from the watchlist or from inventory.</summary>
public sealed record Subject(
    string Vendor,
    string Product,
    string? Version,
    string? AssetName,
    Exposure Exposure,
    Criticality Criticality,
    Guid? WatchlistEntryId = null,
    Guid? SoftwareInstanceId = null,
    Guid? AssetId = null,
    string? MappedVendorNorm = null,
    string? MappedProductNorm = null,
    MatchConfidence ProductConfidence = MatchConfidence.Exact,
    bool FeatureDisabled = false,
    string? Purl = null,
    string? Ecosystem = null,
    DateTime DeclaredAt = default)
{
    public string ProductText => (Vendor + " " + Product).Trim();
    public string Display => ProductText + (string.IsNullOrWhiteSpace(Version) ? "" : " " + Version) + (string.IsNullOrWhiteSpace(AssetName) ? "" : " on " + AssetName);
    public string VendorNorm => MappedVendorNorm ?? Normalizer.Norm(Vendor);
    public string ProductNorm => MappedProductNorm ?? Normalizer.Norm(Product);
}

/// <summary>
/// The one-sentence explanation. Template: {Product} {version} on {asset}: {exploitation phrase}, {attack path phrase}, {exposure phrase}. {Fix phrase}.
/// Example: "FortiOS 7.2.5 on FW-EDGE-01: exploited in the wild, works over the network with no login, reachable from the internet. Fixed in 7.2.8."
/// </summary>
public static class SentenceBuilder
{
    public static string Build(Subject subject, DecisionInputs inputs, CvssVector? cvss, VerdictTier tier, string? fixedIn, MatchConfidence confidence, bool versionUnknown, IReadOnlyList<string>? modifiers = null)
    {
        var head = subject.ProductText + (string.IsNullOrWhiteSpace(subject.Version) ? "" : " " + subject.Version) + (string.IsNullOrWhiteSpace(subject.AssetName) ? "" : " on " + subject.AssetName);

        if (tier == VerdictTier.NotAffected)
            return head + (subject.FeatureDisabled ? ": not affected, the vulnerable feature is disabled." : ": not affected, the installed version is outside the affected range.");

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

        var modifier = modifiers is { Count: > 0 } ? " Lowered one step because " + string.Join(" and ", modifiers) + "." : "";

        var check = confidence == MatchConfidence.Possible
            ? (string.IsNullOrWhiteSpace(subject.Version) ? " Check this: the installed version is not recorded."
               : versionUnknown ? " Check this: the vendor's affected-version data could not be read against " + subject.Version + "."
               : " Check this: the product match is not certain.")
            : "";

        return head + ": " + exploitation + ", " + path + ", " + exposure + "." + fix + modifier + check;
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
