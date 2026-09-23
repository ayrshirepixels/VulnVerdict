using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters;

/// <summary>One field of an adapter's credential form. Every adapter is one credential form (section 3, rule 5).</summary>
public sealed record CredentialField(string Key, string Label, string Type = "text", string? Help = null, bool Required = true, string? Default = null);

/// <summary>Section 9.1 adapter metadata.</summary>
public sealed record AdapterMetadata(
    string Id,
    string DisplayName,
    string Vendor,
    string Description,
    AssetKind[] Kinds,
    CredentialField[] Form,
    string MinimumPermission,
    string? DocsUrl = null,
    int DefaultIntervalMinutes = 240);

public sealed record AssetRecord(
    string ExternalId,
    string DisplayName,
    AssetKind Kind,
    string[] Hostnames,
    string[] IpAddresses,
    string[] MacAddresses,
    string? OsVendor = null,
    string? OsProduct = null,
    string? OsVersion = null,
    string? OsBuild = null,
    Criticality? Criticality = null,
    string? Owner = null);

public sealed record Listener(int Port, string Protocol, string? Bind = null, string? Process = null);

public sealed record SoftwareRecord(
    string AssetExternalId,
    string Vendor,
    string Product,
    string Version,
    SoftwareKind Kind = SoftwareKind.Application,
    string? Cpe = null,
    string? Purl = null,
    string? Ecosystem = null,
    bool Enabled = true,
    string? Edition = null,
    string? Architecture = null,
    string? ExternalId = null,
    Listener[]? Listeners = null);

/// <summary>Exposure evidence for an asset, addressed by external id, hostname or IP (whichever the source knows).</summary>
public sealed record ExposureRecord(Exposure Exposure, string Evidence, string? AssetExternalId = null, string? Hostname = null, string? IpAddress = null);

public sealed record FindingRecord(string AssetExternalId, string[] CveIds, string? Severity = null, string? Title = null, string? RawRef = null);

public sealed class CollectResult
{
    public List<AssetRecord> Assets { get; } = new();
    public List<SoftwareRecord> Software { get; } = new();
    public List<ExposureRecord> Exposures { get; } = new();
    public List<FindingRecord> Findings { get; } = new();
    public List<string> Warnings { get; } = new();
    /// <summary>False for adapters that only add to what they saw last time (deltas); true means software not in this run was removed from the source.</summary>
    public bool FullSnapshot { get; set; } = true;
}

public sealed record TestResult(bool Ok, string Message);

/// <summary>
/// Section 9.1. Every inventory source implements this. Read-only credentials only; never writes to the source.
/// Credentials arrive decrypted for the duration of the call and are never logged.
/// </summary>
public interface IInventoryAdapter
{
    AdapterMetadata Metadata { get; }
    Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct);
    Task<CollectResult> CollectAsync(IReadOnlyDictionary<string, string> credentials, DateTime? since, IProgress<string>? progress, CancellationToken ct);
}

/// <summary>Section 11.3: native ticket adapters follow the same contract shape as inventory sources.</summary>
public interface ITicketAdapter
{
    AdapterMetadata Metadata { get; }
    Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct);
    /// <summary>Create a ticket. Returns the external reference (key or id) and a URL to open it.</summary>
    Task<(string ExternalRef, string? Url)> CreateAsync(IReadOnlyDictionary<string, string> credentials, TicketRequest request, CancellationToken ct);
    /// <summary>Fetch the current status text of a ticket, or null if unknown.</summary>
    Task<string?> StatusAsync(IReadOnlyDictionary<string, string> credentials, string externalRef, CancellationToken ct);
}

public sealed record TicketRequest(string CorrelationKey, string Title, string Body, string Priority, string? Url, VerdictTier Tier, string CveId);

/// <summary>Package vulnerability lookups (OSV) for software identified by purl or ecosystem+name.</summary>
public interface IPackageVulnSource
{
    /// <summary>Returns CVE ids (with fix versions when known) that affect the given package version.</summary>
    Task<IReadOnlyList<PackageVuln>> LookupAsync(IEnumerable<PackageQuery> queries, CancellationToken ct);
}

public sealed record PackageQuery(string Key, string Ecosystem, string Name, string Version, string? Purl);
public sealed record PackageVuln(string Key, string CveId, string? FixedIn, string Source);

public static class CredentialTypes
{
    public const string Text = "text";
    public const string Password = "password";
    public const string Number = "number";
    public const string Bool = "bool";
    public const string TextArea = "textarea";
}
