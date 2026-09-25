namespace VulnVerdict.Core.Data;

/// <summary>Exploitation status, the first decision-table input. Highest applicable wins.</summary>
public enum Exploitation { None = 0, PoC = 1, Active = 2 }

/// <summary>Attack path, the second decision-table input, derived from the CVSS Attack Vector.</summary>
public enum AttackVector { Unknown = 0, Physical = 1, Local = 2, Adjacent = 3, Network = 4 }

/// <summary>Exposure, the third decision-table input. Declared per watchlist entry or derived from inventory.</summary>
public enum Exposure { Isolated = 0, Internal = 1, Internet = 2, NotInstalled = 3 }

/// <summary>Criticality, the fourth decision-table input.</summary>
public enum Criticality { Low = 0, Standard = 1, Critical = 2 }

/// <summary>Verdict tier from the decision table (DecisionTable.cs). Higher value is more urgent.</summary>
public enum VerdictTier
{
    NotAffected = 0,
    IgnoreTracked = 1,
    NextPatchCycle = 2,
    FixThisWeek = 3,
    FixToday = 4
}

/// <summary>Match confidence between a CVE and the product it was matched to.</summary>
public enum MatchConfidence { Possible = 0, Likely = 1, Exact = 2 }

/// <summary>Verdict workflow state.</summary>
public enum VerdictState { Open = 0, Suppressed = 1, Snoozed = 2, AcceptedRisk = 3, Closed = 4 }

public enum SuppressionScope { Cve = 0, Product = 1, WatchlistEntry = 2 }

public enum UserRole { Viewer = 0, Operator = 1, Administrator = 2 }

public enum DigestKind { Daily = 0, Immediate = 1, Manual = 2 }

/// <summary>Asset kinds.</summary>
public enum AssetKind
{
    Endpoint = 0, Server = 1, Hypervisor = 2, Firewall = 3, Switch = 4, AccessPoint = 5, NetworkDevice = 6, Printer = 7,
    Storage = 8, OutOfBandManagement = 9, VirtualMachine = 10, ContainerHost = 11, Other = 12
}

/// <summary>Software kinds.</summary>
public enum SoftwareKind { Application = 0, Package = 1, Firmware = 2, Runtime = 3, RoleOrFeature = 4, Service = 5, OperatingSystem = 6, Library = 7 }

/// <summary>How a software instance was tied to a CNA vendor/product (the mapping step in InventoryService).</summary>
public enum MappingStatus { Unmapped = 0, Exact = 1, Alias = 2, Fuzzy = 3, Package = 4, Ignored = 5 }

/// <summary>Compensating-control modifiers applied after the decision table.</summary>
public enum ControlKind { WafInFront = 0, MfaEnforced = 1, FeatureDisabled = 2, NetworkRestricted = 3, Other = 4 }

public static class EnumText
{
    public static string Plain(this VerdictTier t) => t switch
    {
        VerdictTier.FixToday => "Fix today",
        VerdictTier.FixThisWeek => "Fix this week",
        VerdictTier.NextPatchCycle => "Next patch cycle",
        VerdictTier.IgnoreTracked => "Ignore (tracked)",
        VerdictTier.NotAffected => "Not affected",
        _ => t.ToString()
    };

    public static string Plain(this Exposure e) => e switch
    {
        Exposure.Internet => "Internet-facing",
        Exposure.Internal => "Internal network only",
        Exposure.Isolated => "Isolated or management network",
        Exposure.NotInstalled => "Not installed",
        _ => e.ToString()
    };

    public static string Plain(this Exploitation e) => e switch
    {
        Exploitation.Active => "exploited in the wild",
        Exploitation.PoC => "public exploit code exists",
        _ => "no known exploit"
    };

    public static string Plain(this AttackVector av) => av switch
    {
        AttackVector.Network => "reachable over any network",
        AttackVector.Adjacent => "same broadcast domain or VPN segment",
        AttackVector.Local => "needs a shell or a logged-in user on the box",
        AttackVector.Physical => "needs hands on the hardware",
        _ => "attack path not stated"
    };

    public static string Plain(this VerdictState s) => s switch
    {
        VerdictState.AcceptedRisk => "Accepted risk",
        _ => s.ToString()
    };

    public static string Plain(this MatchConfidence c) => c switch
    {
        MatchConfidence.Exact => "exact",
        MatchConfidence.Likely => "likely",
        _ => "possible (check this)"
    };
}
