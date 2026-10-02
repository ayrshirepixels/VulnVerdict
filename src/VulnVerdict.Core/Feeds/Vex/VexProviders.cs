using System.Text.Json;
using VulnVerdict.Core.Engine;

namespace VulnVerdict.Core.Feeds.Vex;

/// <summary>
/// One CSAF provider the VEX feed reads. <see cref="Url"/> is a distribution directory (holding changes.csv), a
/// provider-metadata.json, or a ROLIE feed; <see cref="Vendors"/> are the vendor names whose products the provider
/// speaks for, and the provider is only called when the watchlist or inventory holds one of them.
/// </summary>
public sealed record VexProvider(string Id, string Name, string Url, string[] Vendors, bool Enabled = true, string? Distribution = null)
{
    /// <summary>True when a subject with this vendor name or package ecosystem is one the provider speaks for.</summary>
    public bool SpeaksFor(string? vendor, string? ecosystem = null)
    {
        var v = Normalizer.Norm(vendor);
        var colon = ecosystem?.IndexOf(':') ?? -1;
        var eco = Normalizer.Norm(colon > 0 ? ecosystem![..colon] : ecosystem);
        foreach (var name in Vendors)
        {
            var n = Normalizer.Norm(name);
            if (n.Length == 0) continue;
            if (v.StartsWith(n, StringComparison.Ordinal) || eco.StartsWith(n, StringComparison.Ordinal)) return true;
        }
        return false;
    }
}

/// <summary>The VEX provider list: a setting (JSON), with defaults when the setting is blank.</summary>
public static class VexProviders
{
    /// <summary>The AppSetting row holding the list (AppSettings.VexProviders).</summary>
    public const string SettingKey = "VexProviders";

    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web) { WriteIndented = true, AllowTrailingCommas = true, ReadCommentHandling = JsonCommentHandling.Skip };

    /// <summary>
    /// Red Hat and SUSE publish one VEX file per CVE and are read by default. Microsoft, Siemens and Cisco are listed
    /// switched off: their documents have not been exercised against this parser the way Red Hat's have, and Microsoft
    /// and Cisco are already covered by their PSIRT feeds. Switching one on is the whole of adding it.
    /// </summary>
    public static readonly IReadOnlyList<VexProvider> Defaults = new[]
    {
        new VexProvider("redhat", "Red Hat", "https://security.access.redhat.com/data/csaf/v2/vex/", new[] { "Red Hat", "AlmaLinux", "Rocky Linux" }),
        new VexProvider("suse", "SUSE", "https://ftp.suse.com/pub/projects/security/csaf-vex/", new[] { "SUSE", "openSUSE" }),
        new VexProvider("microsoft", "Microsoft", "https://msrc.microsoft.com/csaf/vex/", new[] { "Microsoft" }, Enabled: false),
        new VexProvider("siemens", "Siemens", "https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json", new[] { "Siemens" }, Enabled: false),
        new VexProvider("cisco", "Cisco", "https://www.cisco.com/.well-known/csaf/provider-metadata.json", new[] { "Cisco" }, Enabled: false),
    };

    public static string DefaultsJson => JsonSerializer.Serialize(Defaults, Options);

    /// <summary>The list a setting value stands for. Blank means the defaults; anything unreadable throws <see cref="FormatException"/>.</summary>
    public static IReadOnlyList<VexProvider> Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return Defaults;
        List<VexProvider>? list;
        try { list = JsonSerializer.Deserialize<List<VexProvider>>(json, Options); }
        catch (JsonException ex) { throw new FormatException("The VEX provider list in Settings is not valid JSON: " + ex.Message); }
        if (list is null) return Defaults;
        foreach (var p in list)
        {
            if (string.IsNullOrWhiteSpace(p.Id) || p.Id.Length > 32) throw new FormatException("Every VEX provider needs an id of at most 32 characters.");
            if (!Uri.TryCreate(p.Url, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps) throw new FormatException("VEX provider '" + p.Id + "' needs an https URL.");
            if (p.Vendors is null || p.Vendors.Length == 0) throw new FormatException("VEX provider '" + p.Id + "' needs at least one vendor name.");
        }
        if (list.Select(p => p.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count() != list.Count) throw new FormatException("VEX provider ids must be unique.");
        return list;
    }
}
