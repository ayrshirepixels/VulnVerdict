using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Engine;

/// <summary>The four base metrics the decision tree needs, decoded from a CVSS v3.x or v4.0 vector string.</summary>
public sealed record CvssVector(
    string Version,
    AttackVector AttackVector,
    string AttackComplexity,   // L / H
    string PrivilegesRequired, // N / L / H
    string UserInteraction,    // N / R (v3) or N / P / A (v4)
    string? AttackRequirements, // v4 only: N / P
    string Raw)
{
    /// <summary>Automatable: Network AND Low complexity AND no privileges AND no user interaction.</summary>
    public bool Automatable =>
        AttackVector == AttackVector.Network && AttackComplexity == "L" && PrivilegesRequired == "N" && UserInteraction == "N";

    public static CvssVector? Parse(string? vector)
    {
        if (string.IsNullOrWhiteSpace(vector)) return null;
        var v = vector.Trim();
        var parts = v.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || !parts[0].StartsWith("CVSS:", StringComparison.OrdinalIgnoreCase)) return null;
        var version = parts[0][5..];
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in parts.Skip(1))
        {
            var kv = p.Split(':', 2);
            if (kv.Length == 2) map[kv[0]] = kv[1].ToUpperInvariant();
        }
        if (!map.TryGetValue("AV", out var av)) return null;
        var attackVector = av switch
        {
            "N" => AttackVector.Network,
            "A" => AttackVector.Adjacent,
            "L" => AttackVector.Local,
            "P" => AttackVector.Physical,
            _ => AttackVector.Unknown
        };
        return new CvssVector(
            version,
            attackVector,
            map.GetValueOrDefault("AC", "?"),
            map.GetValueOrDefault("PR", "?"),
            map.GetValueOrDefault("UI", "?"),
            map.TryGetValue("AT", out var at) ? at : null,
            v);
    }

    /// <summary>Plain-English decoding for the Explain page.</summary>
    public IEnumerable<(string Metric, string Value, string Meaning)> Decode()
    {
        yield return ("Attack Vector", AttackVector.ToString(), AttackVector.Plain());
        yield return ("Attack Complexity", AttackComplexity, AttackComplexity switch
        {
            "L" => "no special conditions; works reliably",
            "H" => "needs conditions outside the attacker's control (timing, configuration, a race)",
            _ => "not stated"
        });
        if (AttackRequirements is not null)
            yield return ("Attack Requirements", AttackRequirements, AttackRequirements switch
            {
                "N" => "no prerequisites in the target deployment",
                "P" => "needs a specific deployment condition to be present",
                _ => "not stated"
            });
        yield return ("Privileges Required", PrivilegesRequired, PrivilegesRequired switch
        {
            "N" => "no login needed",
            "L" => "needs an ordinary user account",
            "H" => "needs an administrator account",
            _ => "not stated"
        });
        yield return ("User Interaction", UserInteraction, UserInteraction switch
        {
            "N" => "no user has to do anything",
            "R" or "P" => "a user has to do something (open a file, click a link)",
            "A" => "a user has to take several specific actions",
            _ => "not stated"
        });
    }
}
