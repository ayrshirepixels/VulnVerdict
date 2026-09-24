using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Adapters.Firewalls;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Tests.Firewalls;

/// <summary>WatchGuard Firebox over SNMP (faked). Values are shaped like the WatchGuard enterprise MIB and MIB-II.</summary>
public class WatchGuardFireboxAdapterTests
{
    private static readonly Dictionary<string, string> Creds = new() { ["host"] = "192.0.2.60", ["community"] = "ro-community" };

    private static readonly Dictionary<string, string> Answer = new()
    {
        [WatchGuardFireboxAdapter.SysDescr] = "Firebox T45",
        [WatchGuardFireboxAdapter.SysObjectId] = "1.3.6.1.4.1.3097.1.5.45",
        [WatchGuardFireboxAdapter.SysName] = "FB-BRANCH-01",
        [WatchGuardFireboxAdapter.WgSoftwareVersion] = "12.10.4.B698735",
    };

    private static WatchGuardFireboxAdapter Build(Dictionary<string, string>? values, List<(string[] Gets, string[] Nexts)>? calls = null) => new()
    {
        Snmp = (host, c, gets, nexts, _) =>
        {
            calls?.Add((gets, nexts));
            Assert.Equal("192.0.2.60", host);
            Assert.Equal("ro-community", FwCreds.SnmpFields(c)["community"]);
            return Task.FromResult(values);
        }
    };

    [Fact]
    public async Task Maps_the_firebox_with_fireware_from_the_enterprise_mib()
    {
        var calls = new List<(string[] Gets, string[] Nexts)>();
        var r = await Build(Answer, calls).CollectAsync(Creds, null, null, CancellationToken.None);

        var fw = Assert.Single(r.Assets);
        Assert.Equal(("192.0.2.60", "FB-BRANCH-01", AssetKind.Firewall, Criticality.Critical), (fw.ExternalId, fw.DisplayName, fw.Kind, fw.Criticality));
        Assert.Equal(("WatchGuard", "Fireware OS", "12.10.4"), (fw.OsVendor, fw.OsProduct, fw.OsVersion));
        Assert.Equal(new[] { "192.0.2.60" }, fw.IpAddresses);
        var sw = Assert.Single(r.Software);
        Assert.Equal(("WatchGuard", "Fireware OS", "12.10.4", "Firebox T45"), (sw.Vendor, sw.Product, sw.Version, sw.Edition));
        Assert.Empty(r.Exposures); // SNMP says nothing about exposure, and the adapter does not pretend otherwise
        Assert.Empty(r.Warnings);
        Assert.Equal(new[] { WatchGuardFireboxAdapter.WgSoftwareVersion }, Assert.Single(calls).Nexts);
    }

    [Fact]
    public async Task Falls_back_to_a_version_in_sysdescr()
    {
        var values = new Dictionary<string, string>(Answer);
        values.Remove(WatchGuardFireboxAdapter.WgSoftwareVersion);
        values[WatchGuardFireboxAdapter.SysDescr] = "WatchGuard Firebox M390 Fireware v2025.1.2";
        var r = await Build(values).CollectAsync(Creds, null, null, CancellationToken.None);
        Assert.Equal("2025.1.2", r.Software.Single().Version);
        Assert.Equal("WatchGuard Firebox M390", r.Software.Single().Edition);

        values[WatchGuardFireboxAdapter.SysDescr] = "Firebox M390";
        var r2 = await Build(values).CollectAsync(Creds, null, null, CancellationToken.None);
        Assert.Equal("", r2.Software.Single().Version);
        Assert.Single(r2.Warnings);
    }

    [Fact]
    public async Task No_answer_and_missing_credentials_fail_clearly()
    {
        var t = await Build(null).TestAsync(Creds, CancellationToken.None);
        Assert.False(t.Ok);
        Assert.Contains("did not answer SNMP", t.Message);
        await Assert.ThrowsAsync<FirewallApiException>(() => Build(null).CollectAsync(Creds, null, null, CancellationToken.None));

        var t2 = await Build(Answer).TestAsync(new Dictionary<string, string> { ["host"] = "192.0.2.60" }, CancellationToken.None);
        Assert.False(t2.Ok);
        Assert.Contains("SNMP community", t2.Message);

        var t3 = await Build(Answer).TestAsync(Creds, CancellationToken.None);
        Assert.True(t3.Ok);
        Assert.Equal("192.0.2.60: FB-BRANCH-01, Firebox T45, Fireware 12.10.4.", t3.Message);
    }

    [Theory]
    [InlineData("12.10.4.B698735", "12.10.4")]
    [InlineData("12.11.3 Build 718410", "12.11.3")]
    [InlineData("2025.1.3", "2025.1.3")]
    public void Fireware_version_strings(string raw, string expected) =>
        Assert.Equal(expected, WatchGuardFireboxAdapter.Interpret(new Dictionary<string, string> { [WatchGuardFireboxAdapter.WgSoftwareVersion] = raw }).Version);

    [Fact]
    public void Metadata_says_exposure_is_not_seen()
    {
        var m = new WatchGuardFireboxAdapter().Metadata;
        Assert.Equal("watchguard-firebox", m.Id);
        Assert.Contains("does not see NAT", m.Description);
        Assert.Contains("read-only", m.MinimumPermission);
    }
}
