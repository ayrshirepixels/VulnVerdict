using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Services;

/// <summary>
/// The signed, versioned feed bundle published by the central service and pulled (or uploaded) by the
/// console. This file holds the on-the-wire shapes shared by the writer (the central service, or the tests' own
/// throwaway signer) and the applier (the console).
/// </summary>
public static class BundleFiles
{
    public const string Cves = "cves.jsonl";
    public const string Kev = "kev.json";
    public const string Epss = "epss.csv";
    public const string Signals = "signals.jsonl";
    public const string Aliases = "aliases.json";
    public const string Narratives = "narratives.jsonl";
    public const string Manifest = "manifest.json";

    /// <summary>Every data file a bundle must carry, in the order they are written.</summary>
    public static readonly string[] Required = { Cves, Kev, Epss, Signals, Aliases, Narratives };

    public const string Vex = "vex.jsonl";
    public const string Eol = "eol.json";

    /// <summary>
    /// Data files a bundle may carry as well: vendor VEX statements and end-of-life dates. They are listed in the
    /// manifest's extras, not its files, because a console from before they existed checks every entry of files against
    /// the six it unpacks and would refuse the bundle.
    /// </summary>
    public static readonly string[] Optional = { Vex, Eol };
}

public static class BundleJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false
    };
}

public sealed record BundleFile(string Name, string Sha256, long Bytes);

/// <summary>
/// manifest.json. The signature is ECDSA P-256 (SHA-256, IEEE P1363 r||s) over <see cref="Canonical"/> (issued by the central service, verified here): the manifest
/// without the signature field, fixed property order, files sorted by name, no whitespace.
/// </summary>
public sealed class BundleManifest
{
    public string Version { get; set; } = "";
    public DateTime BuiltAt { get; set; }
    public List<BundleFile> Files { get; set; } = new();
    public string? Signature { get; set; }
    public string? Signer { get; set; }
    /// <summary>
    /// Optional data files (see <see cref="BundleFiles.Optional"/>), with their own signature over
    /// <see cref="CanonicalExtras"/>. An older console does not read either property, so the same bundle still verifies
    /// and applies there; this one refuses a bundle whose extras are not signed.
    /// </summary>
    public List<BundleFile> Extras { get; set; } = new();
    public string? ExtrasSignature { get; set; }

    public string Canonical()
    {
        var files = Files.OrderBy(f => f.Name, StringComparer.Ordinal).Select(f => new { name = f.Name, sha256 = f.Sha256, bytes = f.Bytes });
        return JsonSerializer.Serialize(new { version = Version, builtAt = DateTime.SpecifyKind(BuiltAt, DateTimeKind.Utc).ToString("O"), files, signer = Signer });
    }


    /// <summary>What the extras signature covers: the bundle version and build time (so extras cannot be moved to another bundle) and the extra files sorted by name.</summary>
    public string CanonicalExtras()
    {
        var extras = Extras.OrderBy(f => f.Name, StringComparer.Ordinal).Select(f => new { name = f.Name, sha256 = f.Sha256, bytes = f.Bytes });
        return JsonSerializer.Serialize(new { version = Version, builtAt = DateTime.SpecifyKind(BuiltAt, DateTimeKind.Utc).ToString("O"), extras, signer = Signer });
    }

    /// <summary>False for an unsigned manifest, a malformed signature or a signature by any other key; also when extras are listed and their signature is not good.</summary>
    public bool Verify(ECDsa publicKey)
    {
        if (!VerifySignature(publicKey, Signature, Canonical())) return false;
        return Extras.Count == 0 || VerifySignature(publicKey, ExtrasSignature, CanonicalExtras());
    }

    private static bool VerifySignature(ECDsa publicKey, string? signature, string canonical)
    {
        if (string.IsNullOrWhiteSpace(signature)) return false;
        byte[] sig;
        try { sig = Convert.FromBase64String(signature); } catch { return false; }
        try { return publicKey.VerifyData(Encoding.UTF8.GetBytes(canonical), sig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
        catch { return false; }
    }

    public string ToJson() => JsonSerializer.Serialize(this, BundleJson.Options);
    public static BundleManifest? Parse(string json)
    {
        try { return JsonSerializer.Deserialize<BundleManifest>(json, BundleJson.Options); }
        catch { return null; }
    }

    /// <summary>Bundle versions are yyyyMMddHHmm, so ordinal string comparison is chronological.</summary>
    public static bool IsValidVersion(string? v) => v is { Length: 12 } && v.All(char.IsAsciiDigit);
}

public static class BundleHash
{
    public static async Task<string> FileSha256Async(string path, CancellationToken ct)
    {
        await using var s = File.OpenRead(path);
        return Convert.ToHexStringLower(await SHA256.HashDataAsync(s, ct));
    }
}

public static class Base64UrlText
{
    public static string Encode(byte[] bytes) => Base64Url.EncodeToString(bytes);
    public static string Encode(string utf8) => Base64Url.EncodeToString(Encoding.UTF8.GetBytes(utf8));
    public static byte[] Decode(string s) => Base64Url.DecodeFromChars(s.AsSpan());
}

// ---------------------------------------------------------------- record shapes (one per line in the jsonl files)

public sealed class BundleCve
{
    public string Id { get; set; } = "";
    public string State { get; set; } = "";
    public DateTime? Published { get; set; }
    public DateTime? LastModified { get; set; }
    public string? Assigner { get; set; }
    public string? Title { get; set; }
    public string? Description { get; set; }
    public string? CvssV31Vector { get; set; }
    public double? CvssV31Score { get; set; }
    public string? CvssV40Vector { get; set; }
    public double? CvssV40Score { get; set; }
    public string? SsvcExploitation { get; set; }
    public string? SsvcAutomatable { get; set; }
    public string? ReferencesJson { get; set; }
    public DateTime RetrievedAt { get; set; }
    public string? SourceRef { get; set; }
    public List<BundleAffected> Affected { get; set; } = new();

    public static BundleCve From(Cve c) => new()
    {
        Id = c.Id, State = c.State, Published = c.Published, LastModified = c.LastModified, Assigner = c.Assigner, Title = c.Title, Description = c.Description,
        CvssV31Vector = c.CvssV31Vector, CvssV31Score = c.CvssV31Score, CvssV40Vector = c.CvssV40Vector, CvssV40Score = c.CvssV40Score,
        SsvcExploitation = c.SsvcExploitation, SsvcAutomatable = c.SsvcAutomatable, ReferencesJson = c.ReferencesJson, RetrievedAt = c.RetrievedAt, SourceRef = c.SourceRef,
        Affected = c.Affected.Select(BundleAffected.From).ToList()
    };

    public Cve ToEntity()
    {
        var cve = new Cve
        {
            Id = Id, State = State, Published = Published, LastModified = LastModified, Assigner = Assigner, Title = Title, Description = Description,
            CvssV31Vector = CvssV31Vector, CvssV31Score = CvssV31Score, CvssV40Vector = CvssV40Vector, CvssV40Score = CvssV40Score,
            SsvcExploitation = SsvcExploitation, SsvcAutomatable = SsvcAutomatable, ReferencesJson = ReferencesJson, RetrievedAt = RetrievedAt, SourceRef = SourceRef
        };
        foreach (var a in Affected) cve.Affected.Add(a.ToEntity(Id));
        return cve;
    }
}

public sealed class BundleAffected
{
    public string Vendor { get; set; } = "";
    public string Product { get; set; } = "";
    public string VendorNorm { get; set; } = "";
    public string ProductNorm { get; set; } = "";
    public string? DefaultStatus { get; set; }
    public string? VersionsJson { get; set; }
    public string? CpesJson { get; set; }

    public static BundleAffected From(CveAffected a) => new()
    {
        Vendor = a.Vendor, Product = a.Product, VendorNorm = a.VendorNorm, ProductNorm = a.ProductNorm, DefaultStatus = a.DefaultStatus, VersionsJson = a.VersionsJson, CpesJson = a.CpesJson
    };

    public CveAffected ToEntity(string cveId) => new()
    {
        CveId = cveId, Vendor = Vendor, Product = Product, VendorNorm = VendorNorm, ProductNorm = ProductNorm, DefaultStatus = DefaultStatus, VersionsJson = VersionsJson, CpesJson = CpesJson
    };
}

public sealed class BundleKev
{
    public string CveId { get; set; } = "";
    public string? VendorProject { get; set; }
    public string? Product { get; set; }
    public string? VulnerabilityName { get; set; }
    public DateTime DateAdded { get; set; }
    public string? RequiredAction { get; set; }
    public DateTime? DueDate { get; set; }
    public string? KnownRansomwareUse { get; set; }
    public string? Notes { get; set; }
    public DateTime RetrievedAt { get; set; }

    public static BundleKev From(KevEntry k) => new()
    {
        CveId = k.CveId, VendorProject = k.VendorProject, Product = k.Product, VulnerabilityName = k.VulnerabilityName, DateAdded = k.DateAdded, RequiredAction = k.RequiredAction,
        DueDate = k.DueDate, KnownRansomwareUse = k.KnownRansomwareUse, Notes = k.Notes, RetrievedAt = k.RetrievedAt
    };

    public KevEntry ToEntity() => new()
    {
        CveId = CveId, VendorProject = VendorProject, Product = Product, VulnerabilityName = VulnerabilityName, DateAdded = DateAdded, RequiredAction = RequiredAction,
        DueDate = DueDate, KnownRansomwareUse = KnownRansomwareUse, Notes = Notes, RetrievedAt = RetrievedAt
    };
}

public sealed class BundleSignal
{
    public string CveId { get; set; } = "";
    public string Source { get; set; } = "";
    public string? Title { get; set; }
    public string Url { get; set; } = "";
    public DateTime? PublishedAt { get; set; }
    public DateTime RetrievedAt { get; set; }

    public static BundleSignal From(ExploitSignal s) => new() { CveId = s.CveId, Source = s.Source, Title = s.Title, Url = s.Url, PublishedAt = s.PublishedAt, RetrievedAt = s.RetrievedAt };
    public ExploitSignal ToEntity() => new() { CveId = CveId, Source = Source, Title = Title, Url = Url, PublishedAt = PublishedAt, RetrievedAt = RetrievedAt };
}

public sealed class BundleAlias
{
    public string AliasNorm { get; set; } = "";
    public string VendorNorm { get; set; } = "";
    public string ProductNorm { get; set; } = "";

    public static BundleAlias From(ProductAlias a) => new() { AliasNorm = a.AliasNorm, VendorNorm = a.VendorNorm, ProductNorm = a.ProductNorm };
    public ProductAlias ToEntity() => new() { AliasNorm = AliasNorm, VendorNorm = VendorNorm, ProductNorm = ProductNorm };
}

public sealed class BundleNarrative
{
    public string Key { get; set; } = "";
    public string Text { get; set; } = "";
    public string Provider { get; set; } = "";
    public string Model { get; set; } = "";
    public string PromptVersion { get; set; } = "";
    public DateTime CreatedAt { get; set; }

    public static BundleNarrative From(Narrative n) => new() { Key = n.Key, Text = n.Text, Provider = n.Provider, Model = n.Model, PromptVersion = n.PromptVersion, CreatedAt = n.CreatedAt };
    public Narrative ToEntity() => new() { Key = Key, Text = Text, Provider = Provider, Model = Model, PromptVersion = PromptVersion, CreatedAt = CreatedAt };
}

/// <summary>One line of vex.jsonl: a vendor VEX statement as the central service parsed it.</summary>
public sealed class BundleVexStatement
{
    public string Provider { get; set; } = "";
    public string DocumentId { get; set; } = "";
    public string CveId { get; set; } = "";
    public VexStatus Status { get; set; }
    public string Vendor { get; set; } = "";
    public string Product { get; set; } = "";
    public string VendorNorm { get; set; } = "";
    public string ProductNorm { get; set; } = "";
    public string? Version { get; set; }
    public string? VersionRange { get; set; }
    public string? Platform { get; set; }
    public string? PlatformNorm { get; set; }
    public string? PlatformCpe { get; set; }
    public string? Cpe { get; set; }
    public string? Purl { get; set; }
    public string? Justification { get; set; }
    public string? Detail { get; set; }
    public string? Url { get; set; }
    public DateTime? DocumentDate { get; set; }
    public string? Revision { get; set; }
    public DateTime RetrievedAt { get; set; }

    public static BundleVexStatement From(VexStatement s) => new()
    {
        Provider = s.Provider, DocumentId = s.DocumentId, CveId = s.CveId, Status = s.Status, Vendor = s.Vendor, Product = s.Product, VendorNorm = s.VendorNorm, ProductNorm = s.ProductNorm,
        Version = s.Version, VersionRange = s.VersionRange, Platform = s.Platform, PlatformNorm = s.PlatformNorm, PlatformCpe = s.PlatformCpe, Cpe = s.Cpe, Purl = s.Purl,
        Justification = s.Justification, Detail = s.Detail, Url = s.Url, DocumentDate = s.DocumentDate, Revision = s.Revision, RetrievedAt = s.RetrievedAt
    };

    public VexStatement ToEntity() => new()
    {
        Provider = Provider, DocumentId = DocumentId, CveId = CveId.ToUpperInvariant(), Status = Status, Vendor = Vendor, Product = Product, VendorNorm = VendorNorm, ProductNorm = ProductNorm,
        Version = Version, VersionRange = VersionRange, Platform = Platform, PlatformNorm = PlatformNorm, PlatformCpe = PlatformCpe, Cpe = Cpe, Purl = Purl,
        Justification = Justification, Detail = Detail, Url = Url, DocumentDate = DocumentDate, Revision = Revision, RetrievedAt = RetrievedAt
    };
}

/// <summary>One element of eol.json: a release cycle and its support end dates.</summary>
public sealed class BundleEolCycle
{
    public string Slug { get; set; } = "";
    public string ProductLabel { get; set; } = "";
    public string? Aliases { get; set; }
    public string Cycle { get; set; } = "";
    public string? CycleLabel { get; set; }
    public DateTime? ReleaseDate { get; set; }
    public bool IsEol { get; set; }
    public DateTime? EolFrom { get; set; }
    public DateTime? EoasFrom { get; set; }
    public DateTime? EoesFrom { get; set; }
    public bool IsMaintained { get; set; }
    public string? Latest { get; set; }
    public string? Link { get; set; }
    public DateTime RetrievedAt { get; set; }

    public static BundleEolCycle From(EolCycle c) => new()
    {
        Slug = c.Slug, ProductLabel = c.ProductLabel, Aliases = c.Aliases, Cycle = c.Cycle, CycleLabel = c.CycleLabel, ReleaseDate = c.ReleaseDate, IsEol = c.IsEol, EolFrom = c.EolFrom,
        EoasFrom = c.EoasFrom, EoesFrom = c.EoesFrom, IsMaintained = c.IsMaintained, Latest = c.Latest, Link = c.Link, RetrievedAt = c.RetrievedAt
    };

    public EolCycle ToEntity() => new()
    {
        Slug = Slug, ProductLabel = ProductLabel, Aliases = Aliases, Cycle = Cycle, CycleLabel = CycleLabel, ReleaseDate = ReleaseDate, IsEol = IsEol, EolFrom = EolFrom,
        EoasFrom = EoasFrom, EoesFrom = EoesFrom, IsMaintained = IsMaintained, Latest = Latest, Link = Link, RetrievedAt = RetrievedAt
    };
}
