using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters;

/// <summary>One field of an adapter's credential form. Every adapter is one credential form.</summary>
public sealed record CredentialField(string Key, string Label, string Type = "text", string? Help = null, bool Required = true, string? Default = null);

/// <summary>Adapter metadata: what it collects, what credential it needs and where it shows in the console.</summary>
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
    /// <summary>
    /// Asset external ids whose software list is incomplete this run (a per-device read failed, or the source
    /// refused the software endpoint part-way through). Nothing is marked removed from these assets.
    /// </summary>
    public HashSet<string> IncompleteSoftware { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>False for adapters that only add to what they saw last time (deltas); true means software not in this run was removed from the source.</summary>
    public bool FullSnapshot { get; set; } = true;
    /// <summary>A findings read failed part-way: findings not seen this run are kept, not purged as resolved.</summary>
    public bool FindingsIncomplete { get; set; }
    /// <summary>
    /// Asset external id to software ExternalId prefixes that could not be read this run ("container:" when docker was
    /// unreadable). Rows with those prefixes are kept on that asset; the rest of its list is still a full snapshot.
    /// </summary>
    public Dictionary<string, List<string>> IncompleteRows { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>
    /// The run is not a complete picture of the source: a listing was truncated, a page cap or rate limit was hit, or a
    /// section could not be read. Distinct from <see cref="Warnings"/>, which are informational. Nothing is marked
    /// removed, no finding is purged, and assets this connector did not see do not age towards the stale close.
    /// </summary>
    public bool Partial { get; set; }
    /// <summary>
    /// Exposure evidence (VIPs, NAT, policies, VPN listeners) could not be read this run. Exposure is only ever raised, so
    /// earlier evidence stays; servers published since the last good read keep the Internal default until it can be read.
    /// </summary>
    public bool ExposureUnknown { get; private set; }

    /// <summary>Marks the run partial with a warning that says why.</summary>
    public void MarkPartial(string warning)
    {
        Partial = true;
        if (!Warnings.Contains(warning)) Warnings.Add(warning);
    }

    /// <summary>Exposure could not be read: the run is partial and the warning goes first, so it is never cut off the connector's status line.</summary>
    public void ExposureNotRead(string what)
    {
        Partial = true;
        if (ExposureUnknown) return;
        ExposureUnknown = true;
        Warnings.Insert(0, "Exposure could not be read (" + what + "): newly published servers will not be marked internet-facing until it can be");
    }

    /// <summary>Software rows on <paramref name="assetExternalId"/> whose ExternalId starts with <paramref name="prefix"/> are kept this run.</summary>
    public void KeepRows(string assetExternalId, string prefix) =>
        (IncompleteRows.TryGetValue(assetExternalId, out var l) ? l : IncompleteRows[assetExternalId] = new()).Add(prefix);
}

public sealed record TestResult(bool Ok, string Message)
{
    /// <summary>SSH host keys the test met, for the console's one-click trust prompt. Empty for sources that do not use SSH.</summary>
    public IReadOnlyList<Linux.PresentedHostKey> HostKeys { get; init; } = Array.Empty<Linux.PresentedHostKey>();
}

/// <summary>
/// Every inventory source implements this. Read-only credentials only; never writes to the source.
/// Credentials arrive decrypted for the duration of the call and are never logged.
/// </summary>
public interface IInventoryAdapter
{
    AdapterMetadata Metadata { get; }
    Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct);
    Task<CollectResult> CollectAsync(IReadOnlyDictionary<string, string> credentials, DateTime? since, IProgress<string>? progress, CancellationToken ct);
}

/// <summary>Native ticket adapters follow the same contract shape as inventory sources.</summary>
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
    /// <summary>A calendar date (yyyy-MM-dd), such as when a client secret expires.</summary>
    public const string Date = "date";
    /// <summary>A multi-line secret such as a private key: a text area, kept like a password (blank when editing, never sent back to the browser).</summary>
    public const string SecretArea = "secretarea";

    /// <summary>A field whose saved value is never shown again: reused when left blank, only while the endpoint is unchanged.</summary>
    public static bool IsSecret(string type) => type is Password or SecretArea;
}
