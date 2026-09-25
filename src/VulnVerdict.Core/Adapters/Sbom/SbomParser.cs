using System.Text.Json;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Sbom;

/// <summary>A package URL split into its parts (https://github.com/package-url/purl-spec).</summary>
public sealed record ParsedPurl(string Type, string? Namespace, string Name, string? Version, IReadOnlyDictionary<string, string> Qualifiers);

public sealed record SbomParseResult(string Format, string? ApplicationName, string? ApplicationVersion, IReadOnlyList<SoftwareRecord> Software, IReadOnlyList<string> Warnings);

/// <summary>
/// CycloneDX (1.4 to 1.6) and SPDX (2.2, 2.3) JSON documents to software records. The
/// described application becomes one Application record; every component a Library (or Package for OS purls)
/// with its purl and OSV ecosystem, so package CVEs come through the package source rather than CNA names.
/// </summary>
public static class SbomParser
{
    public static SbomParseResult Parse(string json, string assetExternalId)
    {
        if (string.IsNullOrWhiteSpace(json)) throw new FormatException("The SBOM is empty.");
        using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object) throw new FormatException("The SBOM is not a JSON object.");
        if (Str(root, "bomFormat") is { } bf && bf.Equals("CycloneDX", StringComparison.OrdinalIgnoreCase)) return ParseCycloneDx(root, assetExternalId);
        if (Str(root, "spdxVersion") is not null || Str(root, "SPDXID") is not null) return ParseSpdx(root, assetExternalId);
        if (root.TryGetProperty("components", out _) || root.TryGetProperty("metadata", out _)) return ParseCycloneDx(root, assetExternalId);
        if (root.TryGetProperty("packages", out _)) return ParseSpdx(root, assetExternalId);
        throw new FormatException("Not a CycloneDX or SPDX JSON document (no bomFormat or spdxVersion).");
    }

    // ------------------------------------------------------------------ CycloneDX

    private static SbomParseResult ParseCycloneDx(JsonElement root, string asset)
    {
        var warnings = new List<string>();
        var software = new List<SoftwareRecord>();
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string? appName = null, appVersion = null;
        var format = "CycloneDX " + (Str(root, "specVersion") ?? "");

        if (root.TryGetProperty("metadata", out var meta) && meta.ValueKind == JsonValueKind.Object
            && meta.TryGetProperty("component", out var app) && app.ValueKind == JsonValueKind.Object)
        {
            var rec = CycloneComponent(app, asset, SoftwareKind.Application, warnings);
            if (rec is not null && keys.Add(Key(rec))) { software.Add(rec); appName = rec.Product; appVersion = rec.Version; }
        }
        else warnings.Add("CycloneDX metadata.component is missing; the SBOM does not name the application it describes.");

        if (root.TryGetProperty("components", out var comps)) AddCycloneComponents(comps, asset, software, keys, warnings, 0);
        return new SbomParseResult(format.Trim(), appName, appVersion, software, warnings);
    }

    private static void AddCycloneComponents(JsonElement comps, string asset, List<SoftwareRecord> software, HashSet<string> keys, List<string> warnings, int depth)
    {
        if (comps.ValueKind != JsonValueKind.Array || depth > 8) return;
        foreach (var c in comps.EnumerateArray())
        {
            if (c.ValueKind != JsonValueKind.Object) continue;
            var rec = CycloneComponent(c, asset, SoftwareKind.Library, warnings);
            if (rec is not null && keys.Add(Key(rec))) software.Add(rec);
            if (c.TryGetProperty("components", out var nested)) AddCycloneComponents(nested, asset, software, keys, warnings, depth + 1);
        }
    }

    private static SoftwareRecord? CycloneComponent(JsonElement c, string asset, SoftwareKind defaultKind, List<string> warnings)
    {
        var type = Str(c, "type")?.ToLowerInvariant();
        if (type is "file" or "data") return null;
        var purlText = Str(c, "purl");
        var purl = ParsePurl(purlText);
        var name = Str(c, "name") ?? purl?.Name;
        if (string.IsNullOrWhiteSpace(name)) { warnings.Add("Component without a name skipped" + (purlText is null ? "" : " (" + purlText + ")")); return null; }
        var version = Str(c, "version") ?? purl?.Version ?? "";
        var group = Str(c, "group");
        string? supplier = null;
        if (c.TryGetProperty("supplier", out var s) && s.ValueKind == JsonValueKind.Object) supplier = Str(s, "name");
        else if (c.TryGetProperty("publisher", out var p) && p.ValueKind == JsonValueKind.String) supplier = p.GetString();
        var vendor = FirstNonEmpty(group, purl?.Namespace, supplier) ?? "";
        var kind = defaultKind == SoftwareKind.Application ? SoftwareKind.Application : type switch
        {
            "application" => SoftwareKind.Application,
            "operating-system" => SoftwareKind.OperatingSystem,
            "firmware" => SoftwareKind.Firmware,
            "platform" => SoftwareKind.Runtime,
            _ => SoftwareKind.Library
        };
        if (kind == SoftwareKind.Library && purl is not null && IsOsPackageType(purl.Type)) kind = SoftwareKind.Package;
        return new SoftwareRecord(asset, vendor, name.Trim(), version.Trim(), kind, Cpe: Str(c, "cpe"), Purl: purlText, Ecosystem: purl is null ? null : EcosystemFor(purl));
    }

    // ------------------------------------------------------------------ SPDX

    private static SbomParseResult ParseSpdx(JsonElement root, string asset)
    {
        var warnings = new List<string>();
        var software = new List<SoftwareRecord>();
        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string? appName = null, appVersion = null;
        var format = (Str(root, "spdxVersion") ?? "SPDX").Replace("SPDX-", "SPDX ");

        var described = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (root.TryGetProperty("documentDescribes", out var dd) && dd.ValueKind == JsonValueKind.Array)
            foreach (var e in dd.EnumerateArray()) if (e.ValueKind == JsonValueKind.String) described.Add(e.GetString()!);
        if (root.TryGetProperty("relationships", out var rels) && rels.ValueKind == JsonValueKind.Array)
            foreach (var r in rels.EnumerateArray())
                if (r.ValueKind == JsonValueKind.Object && string.Equals(Str(r, "relationshipType"), "DESCRIBES", StringComparison.OrdinalIgnoreCase)
                    && string.Equals(Str(r, "spdxElementId"), "SPDXRef-DOCUMENT", StringComparison.OrdinalIgnoreCase) && Str(r, "relatedSpdxElement") is { } rel)
                    described.Add(rel);

        if (!root.TryGetProperty("packages", out var packages) || packages.ValueKind != JsonValueKind.Array)
        {
            warnings.Add("SPDX document has no packages.");
            return new SbomParseResult(format, null, null, software, warnings);
        }
        if (described.Count == 0) warnings.Add("SPDX document does not say which package it describes (documentDescribes / DESCRIBES relationship); no application record.");

        foreach (var p in packages.EnumerateArray())
        {
            if (p.ValueKind != JsonValueKind.Object) continue;
            var id = Str(p, "SPDXID") ?? "";
            var name = Str(p, "name");
            if (string.IsNullOrWhiteSpace(name)) { warnings.Add("Package " + id + " has no name; skipped."); continue; }
            string? purlText = null, cpe = null;
            if (p.TryGetProperty("externalRefs", out var refs) && refs.ValueKind == JsonValueKind.Array)
                foreach (var r in refs.EnumerateArray())
                {
                    var t = Str(r, "referenceType");
                    var loc = Str(r, "referenceLocator");
                    if (loc is null) continue;
                    if (t == "purl" && purlText is null) purlText = loc;
                    else if (t is "cpe23Type" && cpe is null) cpe = loc;
                }
            var purl = ParsePurl(purlText);
            var version = Str(p, "versionInfo") ?? purl?.Version ?? "";
            if (version.Equals("NOASSERTION", StringComparison.OrdinalIgnoreCase)) version = "";
            var supplier = SpdxActor(Str(p, "supplier")) ?? SpdxActor(Str(p, "originator"));
            var vendor = FirstNonEmpty(purl?.Namespace, supplier) ?? "";
            var isApp = described.Contains(id);
            var purpose = Str(p, "primaryPackagePurpose")?.ToUpperInvariant();
            var kind = isApp ? SoftwareKind.Application : purpose switch
            {
                "APPLICATION" => SoftwareKind.Application,
                "OPERATING-SYSTEM" => SoftwareKind.OperatingSystem,
                "FIRMWARE" => SoftwareKind.Firmware,
                "CONTAINER" or "FILE" or "ARCHIVE" or "SOURCE" or "INSTALL" => purlText is null ? SoftwareKind.Application : SoftwareKind.Library,
                _ => SoftwareKind.Library
            };
            if (kind == SoftwareKind.Library && purl is not null && IsOsPackageType(purl.Type)) kind = SoftwareKind.Package;
            var rec = new SoftwareRecord(asset, vendor, name.Trim(), version.Trim(), kind, Cpe: cpe, Purl: purlText, Ecosystem: purl is null ? null : EcosystemFor(purl));
            if (!keys.Add(Key(rec))) continue;
            software.Add(rec);
            if (isApp && appName is null) { appName = rec.Product; appVersion = rec.Version; }
        }
        return new SbomParseResult(format, appName, appVersion, software, warnings);
    }

    /// <summary>"Organization: Example Ltd (security@example.com)" to "Example Ltd"; NOASSERTION to null.</summary>
    private static string? SpdxActor(string? actor)
    {
        if (string.IsNullOrWhiteSpace(actor) || actor.Equals("NOASSERTION", StringComparison.OrdinalIgnoreCase)) return null;
        var t = actor.Trim();
        var colon = t.IndexOf(':');
        if (colon > 0 && colon < 14) t = t[(colon + 1)..].Trim();
        var paren = t.IndexOf('(');
        if (paren > 0) t = t[..paren].Trim();
        return t == "" ? null : t;
    }

    // ------------------------------------------------------------------ purl and ecosystems

    /// <summary>pkg:type/namespace/name@version?qualifiers#subpath. Returns null for anything that is not a purl.</summary>
    public static ParsedPurl? ParsePurl(string? purl)
    {
        if (string.IsNullOrWhiteSpace(purl)) return null;
        var s = purl.Trim();
        if (!s.StartsWith("pkg:", StringComparison.OrdinalIgnoreCase)) return null;
        s = s[4..].TrimStart('/');
        var hash = s.IndexOf('#'); if (hash >= 0) s = s[..hash];
        var qualifiers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var q = s.IndexOf('?');
        if (q >= 0)
        {
            foreach (var pair in s[(q + 1)..].Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                var eq = pair.IndexOf('=');
                if (eq > 0) qualifiers[Uri.UnescapeDataString(pair[..eq]).ToLowerInvariant()] = Uri.UnescapeDataString(pair[(eq + 1)..]);
            }
            s = s[..q];
        }
        string? version = null;
        var at = s.LastIndexOf('@');
        if (at >= 0) { version = Uri.UnescapeDataString(s[(at + 1)..]); s = s[..at]; }
        var segs = s.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segs.Length < 2) return null;
        var type = segs[0].ToLowerInvariant();
        var name = Uri.UnescapeDataString(segs[^1]);
        var ns = segs.Length > 2 ? string.Join("/", segs[1..^1].Select(Uri.UnescapeDataString)) : null;
        return new ParsedPurl(type, ns, name, string.IsNullOrEmpty(version) ? null : version, qualifiers);
    }

    public static bool IsOsPackageType(string type) => type is "deb" or "rpm" or "apk" or "alpm";

    /// <summary>OSV ecosystem name for the purl type (and distro qualifiers for OS packages). Null when OSV has no ecosystem for it.</summary>
    public static string? EcosystemFor(ParsedPurl p)
    {
        var ns = p.Namespace?.ToLowerInvariant() ?? "";
        p.Qualifiers.TryGetValue("distro", out var distro);
        distro = distro?.ToLowerInvariant() ?? "";
        return p.Type switch
        {
            "npm" => "npm",
            "nuget" => "NuGet",
            "pypi" => "PyPI",
            "maven" => "Maven",
            "golang" => "Go",
            "cargo" => "crates.io",
            "gem" => "RubyGems",
            "composer" => "Packagist",
            "hex" => "Hex",
            "pub" => "Pub",
            "swift" => "SwiftURL",
            "cocoapods" => "CocoaPods",
            "cran" => "CRAN",
            "hackage" => "Hackage",
            "conan" => "ConanCenter",
            "bitnami" => "Bitnami",
            "github" => "GitHub Actions",
            "deb" => distro.StartsWith("ubuntu") || ns == "ubuntu" ? "Ubuntu" : "Debian",
            "apk" => ns == "wolfi" || distro.StartsWith("wolfi") ? "Wolfi" : ns == "chainguard" ? "Chainguard" : "Alpine",
            "rpm" => RpmEcosystem(ns, distro),
            _ => null
        };
    }

    private static string? RpmEcosystem(string ns, string distro)
    {
        var key = ns != "" ? ns : distro;
        if (key.StartsWith("redhat") || key.StartsWith("rhel") || key.StartsWith("centos")) return "Red Hat";
        if (key.StartsWith("fedora")) return "Fedora";
        if (key.StartsWith("rocky")) return "Rocky Linux";
        if (key.StartsWith("alma")) return "AlmaLinux";
        if (key.StartsWith("opensuse")) return "openSUSE";
        if (key.StartsWith("suse") || key.StartsWith("sles")) return "SUSE";
        if (key.StartsWith("mageia")) return "Mageia";
        if (key.StartsWith("photon")) return "Photon OS";
        if (key.StartsWith("amazon") || key.StartsWith("amzn")) return "Amazon Linux";
        if (key.StartsWith("oracle") || key.StartsWith("ol")) return "Oracle Linux";
        return null;
    }

    // ------------------------------------------------------------------ helpers

    private static string Key(SoftwareRecord r) => r.Purl ?? (r.Vendor + "|" + r.Product + "|" + r.Version + "|" + r.Kind);
    private static string? Str(JsonElement e, string name) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    private static string? FirstNonEmpty(params string?[] values) => values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v))?.Trim();
}
