using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;

namespace VulnVerdict.Tests;

public class DecisionTableTests
{
    private static Decision Eval(Exploitation ex, bool auto, Exposure exp, Criticality crit, AttackVector av = AttackVector.Network) =>
        DecisionTable.Evaluate(new DecisionInputs(ex, auto, av, exp, crit));

    [Theory]
    // rule, exploitation, automatable, exposure, criticality, expected tier
    [InlineData(1, Exploitation.Active, true, Exposure.NotInstalled, Criticality.Critical, VerdictTier.NotAffected)]
    [InlineData(2, Exploitation.Active, false, Exposure.Internet, Criticality.Low, VerdictTier.FixToday)]
    [InlineData(3, Exploitation.Active, true, Exposure.Internal, Criticality.Standard, VerdictTier.FixToday)]
    [InlineData(3, Exploitation.Active, true, Exposure.Internal, Criticality.Critical, VerdictTier.FixToday)]
    [InlineData(4, Exploitation.Active, true, Exposure.Internal, Criticality.Low, VerdictTier.FixThisWeek)]
    [InlineData(4, Exploitation.Active, false, Exposure.Internal, Criticality.Critical, VerdictTier.FixThisWeek)]
    [InlineData(5, Exploitation.Active, true, Exposure.Isolated, Criticality.Critical, VerdictTier.NextPatchCycle)]
    [InlineData(6, Exploitation.PoC, true, Exposure.Internet, Criticality.Low, VerdictTier.FixToday)]
    [InlineData(7, Exploitation.PoC, false, Exposure.Internet, Criticality.Critical, VerdictTier.FixThisWeek)]
    [InlineData(8, Exploitation.PoC, false, Exposure.Internet, Criticality.Standard, VerdictTier.NextPatchCycle)]
    [InlineData(8, Exploitation.PoC, false, Exposure.Internet, Criticality.Low, VerdictTier.NextPatchCycle)]
    [InlineData(9, Exploitation.PoC, true, Exposure.Internal, Criticality.Critical, VerdictTier.FixThisWeek)]
    [InlineData(10, Exploitation.PoC, true, Exposure.Internal, Criticality.Standard, VerdictTier.NextPatchCycle)]
    [InlineData(10, Exploitation.PoC, false, Exposure.Internal, Criticality.Critical, VerdictTier.NextPatchCycle)]
    [InlineData(11, Exploitation.PoC, true, Exposure.Isolated, Criticality.Critical, VerdictTier.IgnoreTracked)]
    [InlineData(12, Exploitation.None, true, Exposure.Internet, Criticality.Low, VerdictTier.FixThisWeek)]
    [InlineData(13, Exploitation.None, false, Exposure.Internet, Criticality.Critical, VerdictTier.NextPatchCycle)]
    [InlineData(14, Exploitation.None, true, Exposure.Internal, Criticality.Critical, VerdictTier.NextPatchCycle)]
    [InlineData(15, Exploitation.None, true, Exposure.Internal, Criticality.Standard, VerdictTier.IgnoreTracked)]
    [InlineData(15, Exploitation.None, false, Exposure.Internal, Criticality.Critical, VerdictTier.IgnoreTracked)]
    [InlineData(16, Exploitation.None, true, Exposure.Isolated, Criticality.Critical, VerdictTier.IgnoreTracked)]
    public void Every_rule_matches_the_documented_contract(int rule, Exploitation ex, bool auto, Exposure exp, Criticality crit, VerdictTier expected)
    {
        var d = Eval(ex, auto, exp, crit);
        Assert.Equal(expected, d.Tier);
        Assert.Equal(rule, d.Rule);
    }

    [Fact]
    public void Local_attack_vector_caps_internet_exposure_to_internal()
    {
        // CVSS 9.9 that needs physical access on an internet-facing box: not a Fix today
        var d = Eval(Exploitation.PoC, false, Exposure.Internet, Criticality.Standard, AttackVector.Physical);
        Assert.Equal(VerdictTier.NextPatchCycle, d.Tier);
        Assert.Equal(10, d.Rule);

        var inputs = new DecisionInputs(Exploitation.Active, false, AttackVector.Local, Exposure.Internet, Criticality.Standard);
        Assert.True(inputs.ExposureCapped);
        Assert.Equal(Exposure.Internal, inputs.EffectiveExposure);
        Assert.Equal(VerdictTier.FixThisWeek, DecisionTable.Evaluate(inputs).Tier);
    }

    [Fact]
    public void Active_internet_is_always_fix_today_even_for_low_value_assets()
    {
        Assert.Equal(VerdictTier.FixToday, Eval(Exploitation.Active, false, Exposure.Internet, Criticality.Low).Tier);
    }

    [Fact]
    public void Automatable_requires_all_four_metrics()
    {
        Assert.True(CvssVector.Parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")!.Automatable);
        Assert.False(CvssVector.Parse("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")!.Automatable);
        Assert.False(CvssVector.Parse("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")!.Automatable);
        Assert.False(CvssVector.Parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")!.Automatable);
        Assert.False(CvssVector.Parse("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")!.Automatable);
        var v4 = CvssVector.Parse("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")!;
        Assert.True(v4.Automatable);
        Assert.Equal("4.0", v4.Version);
        Assert.Equal(AttackVector.Physical, CvssVector.Parse("CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H")!.AttackVector);
        Assert.Null(CvssVector.Parse("not a vector"));
    }
}
