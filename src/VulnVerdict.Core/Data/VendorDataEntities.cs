using System.ComponentModel.DataAnnotations;

namespace VulnVerdict.Core.Data;

/// <summary>What a vendor says about one product and one CVE in a VEX document (CSAF product_status).</summary>
public enum VexStatus { UnderInvestigation = 0, KnownAffected = 1, Fixed = 2, KnownNotAffected = 3 }

/// <summary>
/// One vendor VEX statement: this product (at this version, as part of this platform) has this status for this CVE.
/// Written by the CSAF VEX feed, or by a signed bundle. Only statements for products the watchlist or inventory names
/// are kept; the vendor's document is linked, never redistributed.
/// </summary>
public class VexStatement
{
    public long Id { get; set; }
    /// <summary>Provider id from the VEX provider setting: redhat, suse, ...</summary>
    [MaxLength(32)] public string Provider { get; set; } = "";
    /// <summary>The document's own tracking id ("CVE-2024-6387", "cisco-sa-...").</summary>
    [MaxLength(128)] public string DocumentId { get; set; } = "";
    [MaxLength(32)] public string CveId { get; set; } = "";
    public VexStatus Status { get; set; }
    [MaxLength(200)] public string Vendor { get; set; } = "";
    /// <summary>The product or component the statement is about, without its version: "openssh", "FortiOS".</summary>
    [MaxLength(300)] public string Product { get; set; } = "";
    [MaxLength(200)] public string VendorNorm { get; set; } = "";
    [MaxLength(300)] public string ProductNorm { get; set; } = "";
    /// <summary>The exact version the statement names, or null when it covers the product as a whole.</summary>
    [MaxLength(100)] public string? Version { get; set; }
    /// <summary>A product_version_range ("vers:generic/&lt;7.2.8", "&lt;= 7.2.4") when the vendor gives a range instead of a version.</summary>
    [MaxLength(200)] public string? VersionRange { get; set; }
    /// <summary>For "X as a component of Y": Y, the product stream the component ships in ("Red Hat Enterprise Linux 9").</summary>
    [MaxLength(300)] public string? Platform { get; set; }
    [MaxLength(300)] public string? PlatformNorm { get; set; }
    [MaxLength(300)] public string? PlatformCpe { get; set; }
    [MaxLength(300)] public string? Cpe { get; set; }
    [MaxLength(400)] public string? Purl { get; set; }
    /// <summary>CSAF flag label for not-affected statements: vulnerable_code_not_present, component_not_present, ...</summary>
    [MaxLength(64)] public string? Justification { get; set; }
    /// <summary>The vendor's impact statement or remediation, shortened.</summary>
    [MaxLength(500)] public string? Detail { get; set; }
    [MaxLength(500)] public string? Url { get; set; }
    /// <summary>The document's current_release_date: when the vendor last revised the statement.</summary>
    public DateTime? DocumentDate { get; set; }
    [MaxLength(32)] public string? Revision { get; set; }
    public DateTime RetrievedAt { get; set; }
}

/// <summary>
/// One document of a VEX provider that the feed has fetched or tried to. This table, not a date cursor, says what is
/// still to do: a document is due while <see cref="ChangedAt"/> is older than the provider's index says, while
/// <see cref="Scope"/> does not cover every product now wanted for it, or after a failure.
/// </summary>
public class VexDocument
{
    public long Id { get; set; }
    [MaxLength(32)] public string Provider { get; set; } = "";
    /// <summary>Path as the provider's index lists it ("2024/cve-2024-6387.json"), or the full URL for a ROLIE entry.</summary>
    [MaxLength(400)] public string Path { get; set; } = "";
    /// <summary>The CVE in the file name for one-file-per-CVE providers; null otherwise.</summary>
    [MaxLength(32)] public string? CveId { get; set; }
    [MaxLength(128)] public string? DocumentId { get; set; }
    /// <summary>The index timestamp of the revision whose statements are stored; null until a fetch has succeeded.</summary>
    public DateTime? ChangedAt { get; set; }
    public DateTime? FetchedAt { get; set; }
    /// <summary>Normalised product names the stored statements were filtered for, "|"-separated; "*" when nothing was filtered.</summary>
    public string Scope { get; set; } = "";
    public int Statements { get; set; }
    /// <summary>Failed fetches since the last success.</summary>
    public int Attempts { get; set; }
    [MaxLength(500)] public string? LastError { get; set; }
}

/// <summary>
/// One release cycle of one product from endoflife.date (MIT-licensed data): when the vendor stops supporting it.
/// Written by the end-of-life feed, or by a signed bundle.
/// </summary>
public class EolCycle
{
    public long Id { get; set; }
    /// <summary>endoflife.date product name: fortios, windows-server, ubuntu.</summary>
    [MaxLength(64)] public string Slug { get; set; } = "";
    [MaxLength(200)] public string ProductLabel { get; set; } = "";
    /// <summary>Other names the product goes by, "|"-separated.</summary>
    [MaxLength(500)] public string? Aliases { get; set; }
    /// <summary>Release cycle name: "7.2", "22.04", "2019", "11-24h2-e".</summary>
    [MaxLength(64)] public string Cycle { get; set; } = "";
    [MaxLength(200)] public string? CycleLabel { get; set; }
    public DateTime? ReleaseDate { get; set; }
    public bool IsEol { get; set; }
    /// <summary>End of security support. Null with <see cref="IsEol"/> false means no date has been announced.</summary>
    public DateTime? EolFrom { get; set; }
    /// <summary>End of active (feature) support, where the vendor distinguishes it.</summary>
    public DateTime? EoasFrom { get; set; }
    /// <summary>End of paid extended support, where the vendor sells it.</summary>
    public DateTime? EoesFrom { get; set; }
    public bool IsMaintained { get; set; }
    [MaxLength(64)] public string? Latest { get; set; }
    [MaxLength(300)] public string? Link { get; set; }
    public DateTime RetrievedAt { get; set; }
}
