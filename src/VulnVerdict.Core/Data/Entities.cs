using System.ComponentModel.DataAnnotations;

namespace VulnVerdict.Core.Data;

// ---------------------------------------------------------------- feeds

public class Cve
{
    [MaxLength(32)] public string Id { get; set; } = "";
    [MaxLength(16)] public string State { get; set; } = "";
    public DateTime? Published { get; set; }
    public DateTime? LastModified { get; set; }
    [MaxLength(64)] public string? Assigner { get; set; }
    [MaxLength(512)] public string? Title { get; set; }
    [MaxLength(4000)] public string? Description { get; set; }
    [MaxLength(200)] public string? CvssV31Vector { get; set; }
    public double? CvssV31Score { get; set; }
    [MaxLength(300)] public string? CvssV40Vector { get; set; }
    public double? CvssV40Score { get; set; }
    /// <summary>CISA ADP (Vulnrichment) SSVC "Exploitation" value: none / poc / active.</summary>
    [MaxLength(16)] public string? SsvcExploitation { get; set; }
    /// <summary>CISA ADP SSVC "Automatable": yes / no.</summary>
    [MaxLength(8)] public string? SsvcAutomatable { get; set; }
    /// <summary>JSON array of reference URLs (first 20).</summary>
    public string? ReferencesJson { get; set; }
    public DateTime RetrievedAt { get; set; }
    [MaxLength(128)] public string? SourceRef { get; set; }

    public List<CveAffected> Affected { get; set; } = new();
}

/// <summary>One CNA "affected" entry, denormalised for matching.</summary>
public class CveAffected
{
    public long Id { get; set; }
    [MaxLength(32)] public string CveId { get; set; } = "";
    [MaxLength(200)] public string Vendor { get; set; } = "";
    [MaxLength(200)] public string Product { get; set; } = "";
    [MaxLength(200)] public string VendorNorm { get; set; } = "";
    [MaxLength(200)] public string ProductNorm { get; set; } = "";
    [MaxLength(16)] public string? DefaultStatus { get; set; }
    /// <summary>JSON array of {version,status,lessThan,lessThanOrEqual,versionType}.</summary>
    public string? VersionsJson { get; set; }
    public string? CpesJson { get; set; }
    public Cve? Cve { get; set; }
}

/// <summary>Distinct vendor/product pairs seen in CNA data. Drives the watchlist autocomplete.</summary>
public class CnaProduct
{
    [MaxLength(200)] public string VendorNorm { get; set; } = "";
    [MaxLength(200)] public string ProductNorm { get; set; } = "";
    [MaxLength(200)] public string Vendor { get; set; } = "";
    [MaxLength(200)] public string Product { get; set; } = "";
    public int CveCount { get; set; }
    public DateTime LastSeen { get; set; }
}

public class KevEntry
{
    [MaxLength(32)] public string CveId { get; set; } = "";
    [MaxLength(200)] public string? VendorProject { get; set; }
    [MaxLength(200)] public string? Product { get; set; }
    [MaxLength(500)] public string? VulnerabilityName { get; set; }
    public DateTime DateAdded { get; set; }
    [MaxLength(2000)] public string? RequiredAction { get; set; }
    public DateTime? DueDate { get; set; }
    [MaxLength(16)] public string? KnownRansomwareUse { get; set; }
    [MaxLength(2000)] public string? Notes { get; set; }
    public DateTime RetrievedAt { get; set; }
}

public class EpssScore
{
    [MaxLength(32)] public string CveId { get; set; } = "";
    public double Score { get; set; }
    public double Percentile { get; set; }
    public DateTime ScoreDate { get; set; }
    public DateTime RetrievedAt { get; set; }
}

public class ExploitSignal
{
    public long Id { get; set; }
    [MaxLength(32)] public string CveId { get; set; } = "";
    /// <summary>exploitdb, metasploit, nuclei or github</summary>
    [MaxLength(32)] public string Source { get; set; } = "";
    [MaxLength(500)] public string? Title { get; set; }
    [MaxLength(500)] public string Url { get; set; } = "";
    public DateTime? PublishedAt { get; set; }
    public DateTime RetrievedAt { get; set; }
}

public class FeedStatus
{
    [MaxLength(64)] public string Name { get; set; } = "";
    [MaxLength(128)] public string DisplayName { get; set; } = "";
    public int IntervalMinutes { get; set; }
    public DateTime? LastAttempt { get; set; }
    public DateTime? LastSuccess { get; set; }
    [MaxLength(2000)] public string? LastError { get; set; }
    public int RecordsLastRun { get; set; }
    [MaxLength(256)] public string? Cursor { get; set; }
    public bool RunRequested { get; set; }
    public bool Running { get; set; }
    [MaxLength(256)] public string? Progress { get; set; }
}

// ---------------------------------------------------------------- customer data

public class WatchlistEntry
{
    public Guid Id { get; set; }
    [MaxLength(200)] public string Vendor { get; set; } = "";
    [MaxLength(200)] public string Product { get; set; } = "";
    [MaxLength(200)] public string VendorNorm { get; set; } = "";
    [MaxLength(200)] public string ProductNorm { get; set; } = "";
    /// <summary>Installed version, or null if unknown (produces "possible" matches only).</summary>
    [MaxLength(64)] public string? Version { get; set; }
    /// <summary>Optional CPE 2.3 string.</summary>
    [MaxLength(300)] public string? Cpe { get; set; }
    /// <summary>Name used in the explanation sentence, e.g. FW-EDGE-01. Defaults to vendor + product.</summary>
    [MaxLength(128)] public string? AssetName { get; set; }
    public Exposure Exposure { get; set; } = Exposure.Internal;
    public Criticality Criticality { get; set; } = Criticality.Standard;
    [MaxLength(1000)] public string? Note { get; set; }
    public bool Enabled { get; set; } = true;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }

    public string DisplayName => string.IsNullOrWhiteSpace(AssetName) ? (Vendor + " " + Product).Trim() : AssetName!;
}

public class Verdict
{
    public Guid Id { get; set; }
    [MaxLength(32)] public string CveId { get; set; } = "";
    /// <summary>Set for watchlist-derived verdicts.</summary>
    public Guid? WatchlistEntryId { get; set; }
    /// <summary>Set for inventory-derived verdicts.</summary>
    public Guid? SoftwareInstanceId { get; set; }
    public Guid? AssetId { get; set; }
    /// <summary>JSON array of applied compensating-control descriptions.</summary>
    public string? AppliedModifiersJson { get; set; }
    /// <summary>Snapshot of the subject for display: "Fortinet FortiOS 7.2.5 on FW-EDGE-01".</summary>
    [MaxLength(400)] public string Subject { get; set; } = "";

    // inputs snapshot
    public Exploitation Exploitation { get; set; }
    public bool Automatable { get; set; }
    public AttackVector AttackVector { get; set; }
    public Exposure DeclaredExposure { get; set; }
    public Exposure EffectiveExposure { get; set; }
    public Criticality Criticality { get; set; }
    public double? Epss { get; set; }
    public bool InKev { get; set; }

    public VerdictTier Tier { get; set; }
    public int RuleNumber { get; set; }
    public MatchConfidence Confidence { get; set; }
    public DateTime? SlaDue { get; set; }
    [MaxLength(1000)] public string Sentence { get; set; } = "";
    [MaxLength(200)] public string? FixedIn { get; set; }
    /// <summary>JSON array of EvidenceClaim.</summary>
    public string EvidenceJson { get; set; } = "[]";

    public VerdictState State { get; set; } = VerdictState.Open;
    [MaxLength(1000)] public string? StateReason { get; set; }
    [MaxLength(128)] public string? StateOwner { get; set; }
    public DateTime? StateChangedAt { get; set; }
    public DateTime? SnoozedUntil { get; set; }
    public DateTime? AcceptedRiskExpiry { get; set; }
    public Guid? SuppressedByRuleId { get; set; }

    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public DateTime LastEvaluatedAt { get; set; }
    public VerdictTier? PreviousTier { get; set; }
    public DateTime? TierChangedAt { get; set; }
    [MaxLength(300)] public string? TierChangeReason { get; set; }

    public DateTime? ImmediateEmailSentAt { get; set; }
    public DateTime? TicketSentAt { get; set; }
    public DateTime? FirstDigestAt { get; set; }

    public Cve? Cve { get; set; }
    public WatchlistEntry? WatchlistEntry { get; set; }
    public SoftwareInstance? SoftwareInstance { get; set; }
    public Asset? Asset { get; set; }
    public List<VerdictHistory> History { get; set; } = new();

    public bool IsActionable => State == VerdictState.Open && Tier >= VerdictTier.NextPatchCycle;
    public bool IsOverdue(DateTime now) => IsActionable && SlaDue.HasValue && SlaDue.Value < now;
}

public class VerdictHistory
{
    public long Id { get; set; }
    public Guid VerdictId { get; set; }
    public DateTime At { get; set; }
    [MaxLength(128)] public string Actor { get; set; } = "system";
    /// <summary>tier or state</summary>
    [MaxLength(16)] public string Kind { get; set; } = "";
    [MaxLength(64)] public string? From { get; set; }
    [MaxLength(64)] public string? To { get; set; }
    [MaxLength(1000)] public string? Reason { get; set; }
    /// <summary>True once this change has been reported in a digest.</summary>
    public bool Digested { get; set; }
}

public class SuppressionRule
{
    public Guid Id { get; set; }
    public SuppressionScope Scope { get; set; }
    [MaxLength(32)] public string? CveId { get; set; }
    [MaxLength(200)] public string? VendorNorm { get; set; }
    [MaxLength(200)] public string? ProductNorm { get; set; }
    public Guid? WatchlistEntryId { get; set; }
    [MaxLength(1000)] public string Reason { get; set; } = "";
    [MaxLength(128)] public string Owner { get; set; } = "";
    public DateTime? Expiry { get; set; }
    public DateTime CreatedAt { get; set; }
    [MaxLength(128)] public string CreatedBy { get; set; } = "";

    public bool IsExpired(DateTime now) => Expiry.HasValue && Expiry.Value < now;
    public string Describe() => Scope switch
    {
        SuppressionScope.Cve => "CVE " + CveId,
        SuppressionScope.Product => "Product " + VendorNorm + "/" + ProductNorm,
        _ => "Watchlist entry " + WatchlistEntryId
    };
}

public class Ticket
{
    public Guid Id { get; set; }
    public Guid VerdictId { get; set; }
    [MaxLength(32)] public string Channel { get; set; } = "email";
    [MaxLength(128)] public string CorrelationKey { get; set; } = "";
    [MaxLength(256)] public string? ExternalRef { get; set; }
    public DateTime SentAt { get; set; }
    [MaxLength(64)] public string? LastStatus { get; set; }
}

public class DigestRun
{
    public Guid Id { get; set; }
    public DigestKind Kind { get; set; }
    public DateTime GeneratedAt { get; set; }
    public DateTime? SentAt { get; set; }
    [MaxLength(1000)] public string? Recipients { get; set; }
    [MaxLength(300)] public string Subject { get; set; } = "";
    public int FixToday { get; set; }
    public int FixThisWeek { get; set; }
    public int NextPatchCycle { get; set; }
    public int Dismissed { get; set; }
    public string Html { get; set; } = "";
    public string Text { get; set; } = "";
    [MaxLength(2000)] public string? Error { get; set; }
}

public class AppSetting
{
    [MaxLength(128)] public string Key { get; set; } = "";
    public string? Value { get; set; }
    public bool Encrypted { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public class AppUser
{
    public Guid Id { get; set; }
    [MaxLength(128)] public string Username { get; set; } = "";
    [MaxLength(256)] public string? Email { get; set; }
    [MaxLength(512)] public string? PasswordHash { get; set; }
    public UserRole Role { get; set; } = UserRole.Viewer;
    [MaxLength(64)] public string Provider { get; set; } = "local";
    public DateTime CreatedAt { get; set; }
    public DateTime? LastLoginAt { get; set; }
}

public class AuditEntry
{
    public long Id { get; set; }
    public DateTime At { get; set; }
    [MaxLength(128)] public string Actor { get; set; } = "";
    [MaxLength(64)] public string Action { get; set; } = "";
    [MaxLength(256)] public string Target { get; set; } = "";
    public string? Before { get; set; }
    public string? After { get; set; }
}

/// <summary>Product display name to canonical CNA vendor/product. Grown by the needs-mapping queue; seeded here.</summary>
public class ProductAlias
{
    public int Id { get; set; }
    [MaxLength(200)] public string AliasNorm { get; set; } = "";
    [MaxLength(200)] public string VendorNorm { get; set; } = "";
    [MaxLength(200)] public string ProductNorm { get; set; } = "";
}

/// <summary>Cached AI narrative ("cve:CVE-..." ) or attack story ("verdict:guid"), with provenance.</summary>
public class Narrative
{
    [MaxLength(64)] public string Key { get; set; } = "";
    public string Text { get; set; } = "";
    [MaxLength(32)] public string Provider { get; set; } = "";
    [MaxLength(128)] public string Model { get; set; } = "";
    [MaxLength(32)] public string PromptVersion { get; set; } = "";
    public DateTime CreatedAt { get; set; }
}

/// <summary>One link in the evidence chain behind a verdict.</summary>
public record EvidenceClaim(string Claim, string Source, DateTime RetrievedAt, string? Excerpt = null);
