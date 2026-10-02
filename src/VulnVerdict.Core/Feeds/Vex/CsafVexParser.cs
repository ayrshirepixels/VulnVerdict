using System.Text.Json;
using System.Text.RegularExpressions;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;
using VulnVerdict.Core.Feeds.Psirt;

namespace VulnVerdict.Core.Feeds.Vex;

/// <summary>What a parsed document is: its tracking data and the statements kept from it.</summary>
public sealed record CsafDocument(string DocumentId, string? Revision, DateTime? Date, string? Url, List<VexStatement> Statements, int StatementsInDocument);

/// <summary>A CPE 2.2 or 2.3 name reduced to the three parts matching uses.</summary>
public sealed record CpeName(string Vendor, string Product, string? Version);

/// <summary>
/// Reads a CSAF 2.0 document (the csaf_vex profile, or a security advisory carrying product_status) into VEX statements.
/// The product tree is flattened first: every product_id resolves to a vendor, a product name, a version and its CPE or
/// purl, taken from the branches above it; a relationship ("X as a component of Y") resolves to X as the product and Y as
/// its platform. Each product_status entry then becomes one statement per distinct product, version and platform, so
/// the per-architecture copies Red Hat lists collapse into one row.
/// </summary>
public static partial class CsafVexParser
{
    /// <summary>A product from the tree with what its branches say about it.</summary>
    private sealed record TreeProduct(string Id, string Name, string? Vendor, string? ProductName, string? Version, string? VersionRange, string? Cpe, string? Purl);

    private sealed record Resolved(TreeProduct Product, TreeProduct? Platform, string FullName);

    /// <summary>
    /// Parse one document. <paramref name="keep"/> decides which statements are stored (given the normalised product name);
    /// null keeps everything. Throws <see cref="FormatException"/> when the JSON is not a CSAF document with a
    /// vulnerabilities section, so a truncated or wrong download fails instead of replacing stored statements with nothing.
    /// </summary>
    public static CsafDocument Parse(JsonElement root, string provider, string defaultVendor, string? fetchedUrl, DateTime now, Func<string, bool>? keep = null, int max = 5000)
    {
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("document", out var document) || PsirtStore.Str(document, "csaf_version") is null)
            throw new FormatException("not a CSAF document (no document.csaf_version)");
        if (!root.TryGetProperty("vulnerabilities", out var vulns) || vulns.ValueKind != JsonValueKind.Array)
            throw new FormatException("the CSAF document has no vulnerabilities section");

        var tracking = document.TryGetProperty("tracking", out var t) ? t : default;
        var docId = PsirtStore.Str(tracking, "id") ?? throw new FormatException("the CSAF document has no tracking id");
        var revision = PsirtStore.TruncOrNull(PsirtStore.Str(tracking, "version"), 32);
        var date = PsirtStore.ParseDate(PsirtStore.Str(tracking, "current_release_date"));
        var url = PsirtStore.Arr(document, "references").Where(r => PsirtStore.Str(r, "category") == "self").Select(r => PsirtStore.Str(r, "url")).FirstOrDefault(u => u is not null && u.EndsWith(".json", StringComparison.OrdinalIgnoreCase)) ?? fetchedUrl;

        var products = new Dictionary<string, TreeProduct>(StringComparer.Ordinal);
        var relations = new Dictionary<string, Resolved>(StringComparer.Ordinal);
        var groups = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        if (root.TryGetProperty("product_tree", out var tree) && tree.ValueKind == JsonValueKind.Object)
        {
            foreach (var b in PsirtStore.Arr(tree, "branches")) Walk(b, null, null, null, null, products, 0);
            foreach (var p in PsirtStore.Arr(tree, "full_product_names")) AddProduct(p, null, null, null, null, products);
            foreach (var g in PsirtStore.Arr(tree, "product_groups"))
                if (PsirtStore.Str(g, "group_id") is { } gid) groups[gid] = PsirtStore.StrArr(g, "product_ids").ToList();
            foreach (var r in PsirtStore.Arr(tree, "relationships"))
            {
                if (!r.TryGetProperty("full_product_name", out var full) || PsirtStore.Str(full, "product_id") is not { } id) continue;
                var component = PsirtStore.Str(r, "product_reference"); var platform = PsirtStore.Str(r, "relates_to_product_reference");
                if (component is null || platform is null || !products.TryGetValue(component, out var c)) continue;
                relations[id] = new Resolved(c, products.GetValueOrDefault(platform), PsirtStore.Str(full, "name") ?? id);
            }
        }

        Resolved? Resolve(string productId) =>
            relations.TryGetValue(productId, out var rel) ? rel : products.TryGetValue(productId, out var p) ? new Resolved(p, null, p.Name) : null;

        IEnumerable<string> Ids(JsonElement e)
        {
            foreach (var id in PsirtStore.StrArr(e, "product_ids")) yield return id;
            foreach (var g in PsirtStore.StrArr(e, "group_ids"))
                if (groups.TryGetValue(g, out var members)) foreach (var id in members) yield return id;
        }

        var statements = new List<VexStatement>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var total = 0;
        foreach (var v in vulns.EnumerateArray())
        {
            var cve = Normalizer.ExtractCveIds(PsirtStore.Str(v, "cve")).FirstOrDefault();
            if (cve is null || !v.TryGetProperty("product_status", out var status) || status.ValueKind != JsonValueKind.Object) continue;

            // what the document says about each product besides its status: the justification, the impact statement, the remedy
            var justification = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var f in PsirtStore.Arr(v, "flags"))
                if (PsirtStore.Str(f, "label") is { } label) foreach (var id in Ids(f)) justification.TryAdd(id, label);
            var impact = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var th in PsirtStore.Arr(v, "threats"))
                if (PsirtStore.Str(th, "category") == "impact" && PsirtStore.Str(th, "details") is { } d) foreach (var id in Ids(th)) impact.TryAdd(id, d);
            var remedy = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var r in PsirtStore.Arr(v, "remediations"))
            {
                var text = RemedyText(r);
                if (text is not null) foreach (var id in Ids(r)) remedy.TryAdd(id, text);
            }

            foreach (var list in status.EnumerateObject())
            {
                if (StatusOf(list.Name) is not { } st || list.Value.ValueKind != JsonValueKind.Array) continue;
                foreach (var idEl in list.Value.EnumerateArray())
                {
                    if (idEl.GetString() is not { } id || Resolve(id) is not { } r) continue;
                    total++;
                    var row = ToStatement(r, provider, defaultVendor, docId, cve, st, revision, date, url, now);
                    if (row.ProductNorm.Length == 0) continue;
                    row.Justification = st == VexStatus.KnownNotAffected ? PsirtStore.TruncOrNull(justification.GetValueOrDefault(id), 64) : null;
                    row.Detail = PsirtStore.TruncOrNull(st == VexStatus.KnownNotAffected ? impact.GetValueOrDefault(id) : remedy.GetValueOrDefault(id), 500);
                    var key = string.Join('\u001f', cve, st, row.VendorNorm, row.ProductNorm, row.Version, row.VersionRange, row.PlatformNorm, row.PlatformCpe, row.Justification);
                    if (!seen.Add(key) || (keep is not null && !keep(row.ProductNorm))) continue;
                    if (statements.Count < max) statements.Add(row);
                }
            }
        }
        return new CsafDocument(PsirtStore.Trunc(docId, 128), revision, date, url, statements, total);
    }

    private static VexStatus? StatusOf(string name) => name switch
    {
        "known_not_affected" => VexStatus.KnownNotAffected,
        "known_affected" or "first_affected" or "last_affected" => VexStatus.KnownAffected,
        // "recommended" is a version that has the fix and that the vendor says to move to; SUSE lists its fixed packages only there
        "fixed" or "first_fixed" or "recommended" => VexStatus.Fixed,
        "under_investigation" => VexStatus.UnderInvestigation,
        _ => null
    };

    /// <summary>"vendor_fix: https://access.redhat.com/errata/RHSA-2024:4312", "no_fix_planned: Out of support scope".</summary>
    private static string? RemedyText(JsonElement r)
    {
        var category = PsirtStore.Str(r, "category");
        if (category is null) return null;
        var link = PsirtStore.Str(r, "url");
        var details = PsirtStore.Str(r, "details");
        // a vendor fix is best told by its link; anything else by what the vendor wrote
        var text = category == "vendor_fix" && link is not null ? link : Ws().Replace(details ?? link ?? "", " ").Trim();
        return text.Length == 0 ? category : category + ": " + (text.Length > 300 ? text[..300] : text);
    }

    private static void Walk(JsonElement branch, string? vendor, string? productName, string? version, string? range, Dictionary<string, TreeProduct> products, int depth)
    {
        if (branch.ValueKind != JsonValueKind.Object || depth > 32) return;
        var name = PsirtStore.Str(branch, "name");
        switch (PsirtStore.Str(branch, "category"))
        {
            case "vendor": vendor = name; break;
            case "product_name": productName = name; version = null; range = null; break;
            case "product_version": version = name; break;
            case "product_version_range": range = name; break;
        }
        if (branch.TryGetProperty("product", out var p)) AddProduct(p, vendor, productName, version, range, products);
        foreach (var b in PsirtStore.Arr(branch, "branches")) Walk(b, vendor, productName, version, range, products, depth + 1);
    }

    private static void AddProduct(JsonElement p, string? vendor, string? productName, string? version, string? range, Dictionary<string, TreeProduct> products)
    {
        if (PsirtStore.Str(p, "product_id") is not { } id) return;
        string? cpe = null, purl = null;
        if (p.TryGetProperty("product_identification_helper", out var h))
        {
            cpe = PsirtStore.Str(h, "cpe");
            purl = PsirtStore.Str(h, "purl");
        }
        products.TryAdd(id, new TreeProduct(id, PsirtStore.Str(p, "name") ?? id, vendor, productName, version, range, cpe, purl));
    }

    private static VexStatement ToStatement(Resolved r, string provider, string defaultVendor, string docId, string cve, VexStatus status, string? revision, DateTime? date, string? url, DateTime now)
    {
        var p = r.Product;
        var purl = ParsePurl(p.Purl);
        var cpe = ParseCpe(p.Cpe);
        // the name without its version: the purl says it outright; next best is the product_name branch above the
        // product, then the CPE; the display name comes last because vendors fold the version into it
        var name = purl?.Name ?? p.ProductName ?? p.Name;
        var version = purl?.Version ?? (p.ProductName is not null ? p.Version : null) ?? cpe?.Version;
        var vendor = p.Vendor ?? r.Platform?.Vendor ?? defaultVendor;
        return new VexStatement
        {
            Provider = provider, DocumentId = PsirtStore.Trunc(docId, 128), CveId = cve, Status = status,
            Vendor = PsirtStore.Trunc(vendor, 200), VendorNorm = PsirtStore.Trunc(Normalizer.Norm(vendor), 200),
            Product = PsirtStore.Trunc(name, 300), ProductNorm = PsirtStore.Trunc(Normalizer.Norm(name), 300),
            Version = PsirtStore.TruncOrNull(version, 100), VersionRange = PsirtStore.TruncOrNull(p.VersionRange, 200),
            Platform = PsirtStore.TruncOrNull(r.Platform?.Name, 300), PlatformNorm = r.Platform is null ? null : PsirtStore.Trunc(Normalizer.Norm(r.Platform.Name), 300),
            PlatformCpe = PsirtStore.TruncOrNull(r.Platform?.Cpe, 300),
            Cpe = PsirtStore.TruncOrNull(p.Cpe, 300), Purl = PsirtStore.TruncOrNull(p.Purl, 400),
            Url = PsirtStore.TruncOrNull(url, 500), DocumentDate = date, Revision = revision, RetrievedAt = now
        };
    }

    [GeneratedRegex(@"\s+")] private static partial Regex Ws();
    [GeneratedRegex(@"^pkg:(?<type>[^/]+)/(?:(?<ns>[^@?#]+)/)?(?<name>[^/@?#]+)(?:@(?<ver>[^?#]+))?", RegexOptions.IgnoreCase)] private static partial Regex PurlRx();

    /// <summary>
    /// Name and version from a package URL: "pkg:rpm/redhat/openssh@8.7p1-38.el9_4.1?arch=x86_64" gives ("openssh",
    /// "8.7p1-38.el9_4.1"). A container digest is not a version and is dropped.
    /// </summary>
    public static (string Name, string? Version)? ParsePurl(string? purl)
    {
        if (string.IsNullOrWhiteSpace(purl)) return null;
        var m = PurlRx().Match(purl.Trim());
        if (!m.Success) return null;
        var name = Uri.UnescapeDataString(m.Groups["name"].Value);
        var version = m.Groups["ver"].Success ? Uri.UnescapeDataString(m.Groups["ver"].Value) : null;
        if (version is not null && version.StartsWith("sha256", StringComparison.OrdinalIgnoreCase)) version = null;
        return name.Length == 0 ? null : (name, version);
    }

    /// <summary>Vendor, product and version from "cpe:/o:redhat:enterprise_linux:9::baseos" or "cpe:2.3:a:fortinet:fortios:7.2.5:*:...".</summary>
    public static CpeName? ParseCpe(string? cpe)
    {
        if (string.IsNullOrWhiteSpace(cpe)) return null;
        var parts = cpe.Trim().Split(':');
        int first;
        if (parts.Length >= 5 && parts[0] == "cpe" && parts[1] == "2.3") first = 3;
        else if (parts.Length >= 4 && parts[0] == "cpe" && parts[1].StartsWith('/')) first = 2;
        else return null;
        string? At(int i) => i < parts.Length && parts[i] is { Length: > 0 } s && s != "*" && s != "-" ? s : null;
        var vendor = At(first); var product = At(first + 1);
        return vendor is null || product is null ? null : new CpeName(vendor, product, At(first + 2));
    }
}
