using VulnVerdict.Core.Adapters.Firewalls;
using VulnVerdict.Core.Adapters.Linux;
using VulnVerdict.Core.Data;
using static VulnVerdict.Tests.Firewalls.FirewallFixtures;

namespace VulnVerdict.Tests.Firewalls;

/// <summary>Zyxel (ZLD CLI) and Check Point Quantum Spark (Gaia Clish) over a fake SSH CLI session.</summary>
public class CliFirewallAdapterTests
{
    private static readonly Dictionary<string, string> Creds = new() { ["host"] = "192.0.2.100", ["username"] = "vv-limited", ["password"] = "pw" };

    // ------------------------------------------------------------------ Zyxel

    private static FakeCli ZyxelCli() => new FakeCli()
        .On(ZyxelFirewallAdapter.ShowVersion, Read("zyxel", "show-version.txt"))
        .On(ZyxelFirewallAdapter.ShowSerial, "serial number: S222Z00000001\n")
        .On(ZyxelFirewallAdapter.ShowWanZone, Read("zyxel", "show-zone-wan.txt"))
        .On(ZyxelFirewallAdapter.ShowVirtualServers, Read("zyxel", "show-virtual-server.txt"));

    private static ZyxelFirewallAdapter Zyxel(FakeCli cli) => new() { SessionFactory = (_, _, _) => Task.FromResult<ISshSession>(cli) };

    [Fact]
    public async Task Zyxel_reports_series_and_model_names_with_the_patch_level()
    {
        var cli = ZyxelCli();
        var r = await Zyxel(cli).CollectAsync(Creds, null, null, CancellationToken.None);

        var fw = Assert.Single(r.Assets);
        Assert.Equal(("S222Z00000001", AssetKind.Firewall, "5.38 Patch 1", "ABWV.1"), (fw.ExternalId, fw.Kind, fw.OsVersion, fw.OsBuild));
        Assert.Equal(new[] { "USG FLEX series firmware", "USG FLEX 100(W) firmware" }, r.Software.Select(s => s.Product).ToArray());
        Assert.All(r.Software, s => Assert.Equal(("Zyxel", "5.38 Patch 1", "USG FLEX 100W"), (s.Vendor, s.Version, s.Edition)));
        Assert.All(cli.Commands, c => Assert.StartsWith("show ", c)); // never configure
    }

    [Fact]
    public async Task Zyxel_active_virtual_servers_on_wan_zone_interfaces_are_exposure()
    {
        var r = await Zyxel(ZyxelCli()).CollectAsync(Creds, null, null, CancellationToken.None);

        Assert.Equal("virtual server Web_HTTPS on wan1 (203.0.113.100) tcp 443 -> 443 to 192.168.10.20", r.Exposures.Single(e => e.IpAddress == "192.168.10.20").Evidence);
        Assert.Equal("1:1 NAT Mail_1to1 on wan1_ppp (203.0.113.101) to 192.168.10.25", r.Exposures.Single(e => e.IpAddress == "192.168.10.25").Evidence);
        Assert.DoesNotContain(r.Exposures, e => e.IpAddress == "192.168.10.21"); // inactive
        Assert.DoesNotContain(r.Exposures, e => e.IpAddress == "192.168.10.30"); // LAN interface
        Assert.Equal(2, r.Exposures.Count);
    }

    [Theory]
    [InlineData("USG FLEX 100W", "USG FLEX series firmware", "USG FLEX 100(W) firmware")]
    [InlineData("USG FLEX 200", "USG FLEX series firmware", "USG FLEX 200 firmware")]
    [InlineData("USG FLEX 50W", "USG FLEX 50(W) series firmware", "USG FLEX 50(W) firmware")]
    [InlineData("USG FLEX 200HP", "USG FLEX H series uOS firmware", null)]
    [InlineData("ATP200", "ATP series firmware", null)]
    [InlineData("USG20W-VPN", "USG20(W)-VPN series firmware", "USG 20(W)-VPN firmware")]
    [InlineData("VPN100", "VPN series firmware", null)]
    public void Zyxel_models_map_to_the_cna_series_names(string model, string series, string? perModel)
    {
        var (primary, alts) = ZyxelFirewallAdapter.ProductNames(model);
        Assert.Equal(series, primary);
        Assert.Equal(perModel is null ? Array.Empty<string>() : new[] { perModel }, alts);
    }

    [Theory]
    [InlineData("V5.38(ABUH.0)", "5.38", "ABUH.0")]
    [InlineData("5.21(ABUH.1)", "5.21 Patch 1", "ABUH.1")]
    [InlineData("V1.31(ABXF.2)", "1.31 Patch 2", "ABXF.2")]
    [InlineData("2.20(AQQ.0)b3", "2.20", "AQQ.0")]
    public void Zyxel_firmware_strings(string raw, string version, string build) => Assert.Equal((version, build), ZyxelFirewallAdapter.FirmwareVersion(raw));

    [Fact]
    public void Zyxel_show_version_table_form_is_understood()
    {
        const string table = "Zyxel Communications Corp.\nimage number model               firmware version\nbuild date          boot status\n" +
                             "===============================================================================\n1  USG110                        V4.11(AAPH.0)b3s1\n2015-01-11 21:53:44 Standby\n";
        Assert.Equal(("USG110", "V4.11(AAPH.0)b3s1"), ZyxelFirewallAdapter.ParseVersion(table));
    }

    [Fact]
    public async Task Zyxel_test_explains_a_non_zyxel_answer_and_a_refused_login()
    {
        var t = await Zyxel(new FakeCli().On("show version", "% Unknown command\n")).TestAsync(Creds, CancellationToken.None);
        Assert.False(t.Ok);
        Assert.Contains("is this a Zyxel", t.Message);

        var refused = new ZyxelFirewallAdapter { SessionFactory = (_, _, _) => throw new InvalidOperationException("Permission denied (keyboard-interactive).") };
        Assert.Contains("Permission denied", (await refused.TestAsync(Creds, CancellationToken.None)).Message);

        var ok = await Zyxel(ZyxelCli()).TestAsync(Creds, CancellationToken.None);
        Assert.True(ok.Ok);
        Assert.StartsWith("Connected: USG FLEX 100W, firmware V5.38(ABWV.1) (USG FLEX series firmware).", ok.Message);
        Assert.Contains("not pinned", ok.Message);
    }

    // ------------------------------------------------------------------ Check Point Quantum Spark

    private static CheckPointSparkAdapter Spark(FakeCli cli) => new() { SessionFactory = (_, _, _) => Task.FromResult<ISshSession>(cli) };

    [Fact]
    public async Task Spark_reads_release_build_serial_and_macs_from_show_diag()
    {
        var cli = new FakeCli().On(CheckPointSparkAdapter.ShowDiag, Read("checkpoint", "show-diag.txt"));
        var r = await Spark(cli).CollectAsync(Creds, null, null, CancellationToken.None);

        var fw = Assert.Single(r.Assets);
        Assert.Equal(("0000EXAMPLE01", "Check Point", "Spark Firewalls", "R81.10.17", "996002945"), (fw.ExternalId, fw.OsVendor, fw.OsProduct, fw.OsVersion, fw.OsBuild));
        Assert.Equal(new[] { "00:1c:7f:00:00:01", "00:1c:7f:00:00:02" }, fw.MacAddresses);
        Assert.Equal(new[] { "192.0.2.100" }, fw.IpAddresses);
        Assert.Equal(new[] { "Spark Firewalls", "Check Point Quantum Gateway, Spark Gateway and CloudGuard Network" }, r.Software.Select(s => s.Product).ToArray());
        Assert.Empty(r.Exposures);
        Assert.Equal(new[] { "show diag" }, cli.Commands);
    }

    [Fact]
    public async Task Spark_test_fails_when_the_shell_is_not_clish()
    {
        var t = await Spark(new FakeCli().On("show diag", "-bash: show: command not found\n")).TestAsync(Creds, CancellationToken.None);
        Assert.False(t.Ok);
        Assert.Contains("Gaia Clish", t.Message);

        var pinned = new Dictionary<string, string>(Creds) { ["hostKey"] = "SHA256:abc" };
        var ok = await Spark(new FakeCli().On("show diag", Read("checkpoint", "show-diag.txt"))).TestAsync(pinned, CancellationToken.None);
        Assert.Equal("Connected: Quantum Spark R81.10.17 (build 996002945), serial 0000EXAMPLE01.", ok.Message);
    }

    [Fact]
    public void Shell_output_loses_the_echoed_command_and_the_prompt()
    {
        var raw = "show diag\r\n\u001b[0mCurrent system info\r\nSerial number : X1\r\nSPARK-01> ";
        Assert.Equal("Current system info\nSerial number : X1", ApplianceSsh.StripEchoAndPrompt(raw, "show diag"));
        Assert.Equal("a\nb", ApplianceSsh.StripEchoAndPrompt("show x\n a\n --More-- \nb\nRouter# ", "show x").Replace(" ", ""));
    }
}
