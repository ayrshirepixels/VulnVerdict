using System.ComponentModel.DataAnnotations;

namespace VulnVerdict.Core.Data;

/// <summary>An asset. Written by adapters through the canonical model; nothing downstream knows which product supplied it.</summary>
public class Asset
{
    public Guid Id { get; set; }
    [MaxLength(200)] public string DisplayName { get; set; } = "";
    /// <summary>JSON arrays.</summary>
    public string HostnamesJson { get; set; } = "[]";
    public string IpAddressesJson { get; set; } = "[]";
    public string MacAddressesJson { get; set; } = "[]";
    public AssetKind Kind { get; set; } = AssetKind.Other;
    [MaxLength(100)] public string? OsVendor { get; set; }
    [MaxLength(200)] public string? OsProduct { get; set; }
    [MaxLength(64)] public string? OsVersion { get; set; }
    [MaxLength(64)] public string? OsBuild { get; set; }
    public Criticality Criticality { get; set; } = Criticality.Standard;
    /// <summary>True once a person has set the criticality by hand; adapters then stop overriding it.</summary>
    public bool CriticalityPinned { get; set; }
    public Exposure Exposure { get; set; } = Exposure.Internal;
    [MaxLength(1000)] public string? ExposureEvidence { get; set; }
    public bool ExposurePinned { get; set; }
    [MaxLength(200)] public string? Owner { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    /// <summary>Seen by the discovery sweep only, claimed by no adapter.</summary>
    public bool Unknown { get; set; }
    public bool Archived { get; set; }
    [MaxLength(1000)] public string? Note { get; set; }

    public List<AssetSource> Sources { get; set; } = new();
    public List<SoftwareInstance> Software { get; set; } = new();
}

public class AssetSource
{
    public long Id { get; set; }
    public Guid AssetId { get; set; }
    [MaxLength(64)] public string ConnectorId { get; set; } = "";
    [MaxLength(64)] public string AdapterId { get; set; } = "";
    [MaxLength(256)] public string ExternalId { get; set; } = "";
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
}

/// <summary>One piece of software observed on an asset.</summary>
public class SoftwareInstance
{
    public Guid Id { get; set; }
    public Guid AssetId { get; set; }
    [MaxLength(200)] public string Vendor { get; set; } = "";
    [MaxLength(300)] public string Product { get; set; } = "";
    [MaxLength(100)] public string Version { get; set; } = "";
    [MaxLength(100)] public string? Edition { get; set; }
    [MaxLength(32)] public string? Architecture { get; set; }
    [MaxLength(200)] public string VendorNorm { get; set; } = "";
    [MaxLength(200)] public string ProductNorm { get; set; } = "";
    [MaxLength(300)] public string? Cpe { get; set; }
    [MaxLength(400)] public string? Purl { get; set; }
    /// <summary>OSV ecosystem for packages: Debian, Ubuntu, Alpine, npm, NuGet, PyPI, Maven, Go, crates.io ...</summary>
    [MaxLength(64)] public string? Ecosystem { get; set; }
    public SoftwareKind Kind { get; set; } = SoftwareKind.Application;
    public bool Enabled { get; set; } = true;
    /// <summary>JSON array of {port, proto, bind, process}.</summary>
    public string? ListenersJson { get; set; }
    [MaxLength(64)] public string ConnectorId { get; set; } = "";
    [MaxLength(256)] public string? ExternalId { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }

    /// <summary>
    /// Set when the connector that reported this stops reporting it (uninstalled, or the connector was deleted).
    /// The row is kept so its verdicts close with a reason and their history survives; it is hidden from every
    /// query by a global filter, and cleared again if the software comes back.
    /// </summary>
    public DateTime? RemovedAt { get; set; }

    // resolved CNA identity (set by the mapping step in InventoryService)
    public MappingStatus MappingStatus { get; set; } = MappingStatus.Unmapped;
    [MaxLength(200)] public string? MappedVendorNorm { get; set; }
    [MaxLength(200)] public string? MappedProductNorm { get; set; }

    public Asset? Asset { get; set; }
    public string Display => (Vendor + " " + Product).Trim() + (Version == "" ? "" : " " + Version);
}

/// <summary>A finding from an external scanner or service. Stored as evidence and used as a second opinion, never as the verdict.</summary>
public class ExternalFinding
{
    public Guid Id { get; set; }
    public Guid AssetId { get; set; }
    /// <summary>JSON array of CVE ids.</summary>
    public string CveIdsJson { get; set; } = "[]";
    [MaxLength(64)] public string ConnectorId { get; set; } = "";
    [MaxLength(64)] public string Source { get; set; } = "";
    [MaxLength(64)] public string? SourceSeverity { get; set; }
    [MaxLength(500)] public string? Title { get; set; }
    [MaxLength(500)] public string? RawRef { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
}

/// <summary>A configured instance of an adapter: hostname plus a read-only credential.</summary>
public class Connector
{
    public Guid Id { get; set; }
    [MaxLength(64)] public string AdapterId { get; set; } = "";
    [MaxLength(200)] public string DisplayName { get; set; } = "";
    /// <summary>Data-protection encrypted JSON object of the credential form values.</summary>
    public string CredentialsJson { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public int IntervalMinutes { get; set; } = 240;
    public DateTime? LastAttempt { get; set; }
    public DateTime? LastSuccess { get; set; }
    [MaxLength(2000)] public string? LastError { get; set; }
    public int ConsecutiveFailures { get; set; }
    public int AssetsLastRun { get; set; }
    public int SoftwareLastRun { get; set; }
    public bool RunRequested { get; set; }
    public bool Running { get; set; }
    [MaxLength(256)] public string? Progress { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>Compensating-control modifier. Lowers a verdict one tier and is named in the explanation. Never lowers Active + Internet.</summary>
public class CompensatingControl
{
    public Guid Id { get; set; }
    public Guid? AssetId { get; set; }
    public Guid? WatchlistEntryId { get; set; }
    /// <summary>Optional: only for software whose normalised product name matches.</summary>
    [MaxLength(200)] public string? ProductNorm { get; set; }
    public ControlKind Kind { get; set; }
    [MaxLength(500)] public string Description { get; set; } = "";
    [MaxLength(128)] public string CreatedBy { get; set; } = "";
    public DateTime CreatedAt { get; set; }
    public DateTime? Expiry { get; set; }

    public string KindText => Kind switch
    {
        ControlKind.WafInFront => "WAF in front",
        ControlKind.MfaEnforced => "MFA enforced on the affected service",
        ControlKind.FeatureDisabled => "feature disabled by configuration",
        ControlKind.NetworkRestricted => "network access restricted",
        _ => "compensating control"
    };
}

/// <summary>Cached OSV lookups for packages: purl@version to CVE ids.</summary>
public class PackageVulnCache
{
    [MaxLength(500)] public string Key { get; set; } = "";
    /// <summary>JSON array of {cve, fixedIn, source}.</summary>
    public string ResultJson { get; set; } = "[]";
    public DateTime FetchedAt { get; set; }
}

/// <summary>Webhook delivery log.</summary>
public class WebhookDelivery
{
    public long Id { get; set; }
    public DateTime At { get; set; }
    [MaxLength(64)] public string Event { get; set; } = "";
    public Guid VerdictId { get; set; }
    [MaxLength(500)] public string Url { get; set; } = "";
    public int? StatusCode { get; set; }
    [MaxLength(500)] public string? Error { get; set; }
}

/// <summary>Vendor PSIRT advisory, the earliest and most accurate affected-version data for the products SMEs run.</summary>
public class Advisory
{
    public long Id { get; set; }
    /// <summary>fortinet | microsoft | cisco | vmware | ubuntu | debian | redhat</summary>
    [MaxLength(32)] public string Vendor { get; set; } = "";
    [MaxLength(64)] public string AdvisoryId { get; set; } = "";
    [MaxLength(500)] public string? Title { get; set; }
    [MaxLength(500)] public string? Url { get; set; }
    public DateTime? Published { get; set; }
    public DateTime? Updated { get; set; }
    /// <summary>JSON array of CVE ids.</summary>
    public string CveIdsJson { get; set; } = "[]";
    /// <summary>JSON array of {product, affected, fixedIn} as the vendor states them.</summary>
    public string? AffectedJson { get; set; }
    [MaxLength(32)] public string? Severity { get; set; }
    public bool ExploitedInTheWild { get; set; }
    public DateTime RetrievedAt { get; set; }
}

/// <summary>The signed feed bundle currently applied (central service or air-gap upload).</summary>
public class BundleState
{
    public int Id { get; set; }
    [MaxLength(64)] public string Version { get; set; } = "";
    public DateTime BuiltAt { get; set; }
    public DateTime AppliedAt { get; set; }
    [MaxLength(64)] public string Source { get; set; } = "";
    [MaxLength(128)] public string? Signer { get; set; }
}
