using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Engine;

public sealed record DecisionInputs(Exploitation Exploitation, bool Automatable, AttackVector AttackVector, Exposure DeclaredExposure, Criticality Criticality)
{
    /// <summary>
    /// Exposure is capped by attack vector. A Local or Physical attack vector on an
    /// Internet-exposed asset is treated as Internal, because network exposure does not help that attacker.
    /// </summary>
    public Exposure EffectiveExposure =>
        DeclaredExposure == Exposure.Internet && AttackVector is AttackVector.Local or AttackVector.Physical
            ? Exposure.Internal
            : DeclaredExposure;

    public bool ExposureCapped => EffectiveExposure != DeclaredExposure;
}

public sealed record Decision(VerdictTier Tier, int Rule);

/// <summary>The decision table. Evaluated top to bottom, first match wins. Deterministic; no tuning.</summary>
public static class DecisionTable
{
    public static Decision Evaluate(DecisionInputs i)
    {
        var ex = i.Exploitation;
        var auto = i.Automatable;
        var exp = i.EffectiveExposure;
        var crit = i.Criticality;

        if (exp == Exposure.NotInstalled) return new(VerdictTier.NotAffected, 1);

        if (ex == Exploitation.Active)
        {
            if (exp == Exposure.Internet) return new(VerdictTier.FixToday, 2);
            if (exp == Exposure.Internal && auto && crit != Criticality.Low) return new(VerdictTier.FixToday, 3);
            if (exp == Exposure.Internal) return new(VerdictTier.FixThisWeek, 4);
            return new(VerdictTier.NextPatchCycle, 5); // Isolated
        }

        if (ex == Exploitation.PoC)
        {
            if (exp == Exposure.Internet && auto) return new(VerdictTier.FixToday, 6);
            if (exp == Exposure.Internet && crit == Criticality.Critical) return new(VerdictTier.FixThisWeek, 7);
            if (exp == Exposure.Internet) return new(VerdictTier.NextPatchCycle, 8);
            if (exp == Exposure.Internal && auto && crit == Criticality.Critical) return new(VerdictTier.FixThisWeek, 9);
            if (exp == Exposure.Internal) return new(VerdictTier.NextPatchCycle, 10);
            return new(VerdictTier.IgnoreTracked, 11); // Isolated
        }

        // Exploitation.None
        if (exp == Exposure.Internet && auto) return new(VerdictTier.FixThisWeek, 12);
        if (exp == Exposure.Internet) return new(VerdictTier.NextPatchCycle, 13);
        if (exp == Exposure.Internal && auto && crit == Criticality.Critical) return new(VerdictTier.NextPatchCycle, 14);
        if (exp == Exposure.Internal) return new(VerdictTier.IgnoreTracked, 15);
        return new(VerdictTier.IgnoreTracked, 16); // Isolated
    }

    /// <summary>Default SLA in days per tier. Null means no SLA.</summary>
    public static int? DefaultSlaDays(VerdictTier tier) => tier switch
    {
        VerdictTier.FixToday => 2,
        VerdictTier.FixThisWeek => 7,
        VerdictTier.NextPatchCycle => 30,
        _ => null
    };

    public static string RuleText(int rule) => rule switch
    {
        1 => "no asset runs the affected product and version",
        2 => "exploited in the wild and reachable from the internet",
        3 => "exploited in the wild, automatable, on an internal asset that is not low-value",
        4 => "exploited in the wild on an internal asset",
        5 => "exploited in the wild but the asset is isolated",
        6 => "public exploit, automatable, and reachable from the internet",
        7 => "public exploit, internet-facing, on a critical asset",
        8 => "public exploit, internet-facing, standard or low-value asset",
        9 => "public exploit, automatable, internal, on a critical asset",
        10 => "public exploit on an internal asset",
        11 => "public exploit but the asset is isolated",
        12 => "no known exploit but automatable and reachable from the internet",
        13 => "no known exploit, internet-facing, not automatable",
        14 => "no known exploit, automatable, internal, on a critical asset",
        15 => "no known exploit, internal asset",
        16 => "no known exploit, isolated asset",
        _ => "rule " + rule
    };
}
