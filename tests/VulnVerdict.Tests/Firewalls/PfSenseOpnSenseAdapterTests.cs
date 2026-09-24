using System.Net;
using System.Text;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Adapters.Firewalls;
using VulnVerdict.Core.Adapters.Linux;
using VulnVerdict.Core.Data;
using static VulnVerdict.Tests.Firewalls.FirewallFixtures;

namespace VulnVerdict.Tests.Firewalls;

/// <summary>pfSense over SSH (fake session) and OPNsense over its REST API (fake HTTP).</summary>
public class PfSenseOpnSenseAdapterTests
{
    // ------------------------------------------------------------------ pfSense

    private static readonly Dictionary<string, string> PfCreds = new() { ["host"] = "192.0.2.80", ["username"] = "vv-reader", ["password"] = "pw" };

    private static FakeCli PfSession(bool configReadable = true) => new FakeCli()
        .On(PfSenseAdapter.PatchCommand, "0\n") // before the version rule: rules match by substring
        .On(PfSenseAdapter.VersionCommand, "2.7.2-RELEASE\n")
        .On(PfSenseAdapter.HostnameCommand, "pf-edge-01.example.test\n")
        .On(PfSenseAdapter.IfconfigCommand, Read("pfsense", "ifconfig.txt"))
        .On(PfSenseAdapter.ConfigCommand, configReadable ? Read("pfsense", "config.xml") : "", configReadable ? 0 : 1, configReadable ? "" : "cat: /conf/config.xml: Permission denied");

    private static PfSenseAdapter Pf(FakeCli cli, List<SshConnectionOptions>? opts = null) => new()
    {
        SessionFactory = (t, o, _) => { opts?.Add(o); Assert.Equal(("192.0.2.80", 22), (t.Host, t.Port)); return Task.FromResult<ISshSession>(cli); }
    };

    [Fact]
    public async Task PfSense_maps_version_addresses_and_only_runs_read_commands()
    {
        var cli = PfSession();
        var opts = new List<SshConnectionOptions>();
        var r = await Pf(cli, opts).CollectAsync(PfCreds, null, null, CancellationToken.None);

        var fw = Assert.Single(r.Assets);
        Assert.Equal(("pf-edge-01.example.test", "pf-edge-01", AssetKind.Firewall), (fw.ExternalId, fw.DisplayName, fw.Kind));
        Assert.Equal(("Netgate", "pfSense CE", "2.7.2"), (fw.OsVendor, fw.OsProduct, fw.OsVersion));
        Assert.Equal(new[] { "203.0.113.80", "10.120.0.1", "10.130.0.1", "10.140.0.1" }, fw.IpAddresses);
        Assert.Contains("00:08:a2:00:00:01", fw.MacAddresses);
        var sw = Assert.Single(r.Software);
        Assert.Equal(("Netgate", "pfSense CE", "2.7.2", SoftwareKind.OperatingSystem), (sw.Vendor, sw.Product, sw.Version, sw.Kind));

        Assert.All(cli.Commands, c => Assert.Matches(@"^(cat /etc/version(\.patch)?|hostname|ifconfig -a|cat /conf/config\.xml)$", c));
        Assert.True(cli.Disposed);
        Assert.Null(opts.Single().ExpectedFingerprint);
        Assert.Contains(r.Warnings, w => w.Contains("is not pinned")); // unpinned host key is reported
    }

    [Fact]
    public async Task PfSense_wan_rules_to_the_firewall_and_port_forwards_with_a_rule_are_exposure()
    {
        var r = await Pf(PfSession()).CollectAsync(PfCreds, null, null, CancellationToken.None);

        var self = Assert.Single(r.Exposures, e => e.AssetExternalId is not null);
        Assert.Equal("OpenVPN allowed from the internet on wan by rule 'OpenVPN wizard' (udp 1194)", self.Evidence); // the GUI rule admits one source only
        var listeners = r.Software.Single().Listeners!;
        Assert.Contains(listeners, l => l.Port == 8443 && l.Process == "web GUI");     // restricted: a listener, not exposure
        Assert.DoesNotContain(listeners, l => l.Port == 2222);                         // disabled rule

        Assert.Equal("port forward 'web server' on wan tcp wanip:443 -> 10.130.0.20:443", r.Exposures.Single(e => e.IpAddress == "10.130.0.20").Evidence);
        Assert.DoesNotContain(r.Exposures, e => e.IpAddress == "10.130.0.21"); // no filter rule lets it through
        Assert.DoesNotContain(r.Exposures, e => e.IpAddress == "10.130.0.25"); // disabled
        Assert.DoesNotContain(r.Exposures, e => e.IpAddress == "10.130.0.40"); // 1:1 without a pass rule
        Assert.Equal(2, r.Exposures.Count);
    }

    [Fact]
    public async Task PfSense_without_a_readable_config_still_records_the_version()
    {
        var pinned = new Dictionary<string, string>(PfCreds) { ["hostKey"] = "SHA256:q2b1w4Zb2sM6pGkQy0Xf3VJt8nHc9LrE5uA7dKoTiYw" };
        var r = await Pf(PfSession(configReadable: false)).CollectAsync(pinned, null, null, CancellationToken.None);
        Assert.Equal("2.7.2", r.Software.Single().Version);
        Assert.Empty(r.Exposures);
        Assert.Equal(new[] { "config.xml is not readable by this account (cat: /conf/config.xml: Permission denied); exposure not collected." }, r.Warnings);

        var t = await Pf(PfSession(configReadable: false)).TestAsync(pinned, CancellationToken.None);
        Assert.True(t.Ok);
        Assert.Equal("Connected: pfSense CE 2.7.2. The configuration file is not readable by this account: exposure will not be collected.", t.Message);
    }

    [Fact]
    public async Task PfSense_connection_failure_and_non_pfsense_hosts_fail_the_test()
    {
        var refused = new PfSenseAdapter { SessionFactory = (_, _, _) => throw new InvalidOperationException("Permission denied (password).") };
        var t = await refused.TestAsync(PfCreds, CancellationToken.None);
        Assert.False(t.Ok);
        Assert.Contains("Permission denied", t.Message);

        var linux = new FakeCli().On("cat /etc/version", "", 1, "No such file or directory");
        var t2 = await Pf(linux).TestAsync(PfCreds, CancellationToken.None);
        Assert.False(t2.Ok);
        Assert.Contains("is this pfSense", t2.Message);

        var noPassword = await Pf(PfSession()).TestAsync(new Dictionary<string, string> { ["host"] = "192.0.2.80", ["username"] = "x" }, CancellationToken.None);
        Assert.False(noPassword.Ok);
        Assert.Contains("password or a private key", noPassword.Message);
    }

    [Theory]
    [InlineData("2.7.2-RELEASE", "0", "pfSense CE", "2.7.2")]
    [InlineData("2.7.2-RELEASE", "1", "pfSense CE", "2.7.2-p1")]
    [InlineData("24.11-RELEASE", "", "pfSense Plus", "24.11")]
    [InlineData("25.07.1-RELEASE", "0", "pfSense Plus", "25.07.1")]
    public void PfSense_version_files(string version, string patch, string product, string expected) =>
        Assert.Equal((product, expected), PfSenseAdapter.ParseVersion(version, patch));

    // ------------------------------------------------------------------ OPNsense

    private static readonly Dictionary<string, string> OpnCreds = new() { ["host"] = "opn.example.test", ["apiKey"] = "k3yK3yK3y", ["apiSecret"] = "s3cr3t", ["verifyTls"] = "false" };

    private static (OpnSenseAdapter Adapter, FakeHandler Handler) Opn(Func<string, HttpResponseMessage?>? overrides = null)
    {
        var responses = Responses("opnsense");
        var h = new FakeHandler();
        h.On(r => true, (r, _) =>
        {
            var path = r.RequestUri!.AbsolutePath.TrimStart('/');
            if (overrides?.Invoke(path) is { } o) return o;
            return responses.TryGetValue(path, out var json) ? FakeHandler.Json(json) : FakeHandler.Json("{\"errorMessage\":\"Endpoint not found\"}", HttpStatusCode.NotFound);
        });
        return (new OpnSenseAdapter(new FakeHttpClientFactory(h)), h);
    }

    [Fact]
    public async Task OpnSense_maps_the_firewall_and_uses_basic_auth_with_key_and_secret()
    {
        var (a, h) = Opn();
        var r = await a.CollectAsync(OpnCreds, null, null, CancellationToken.None);

        var fw = Assert.Single(r.Assets);
        Assert.Equal(("opn-edge-01.example.test", "Deciso", "OPNsense", "25.7.3_1"), (fw.ExternalId, fw.OsVendor, fw.OsProduct, fw.OsVersion));
        Assert.Equal(new[] { "203.0.113.70", "10.100.0.1", "10.110.0.1" }, fw.IpAddresses);
        Assert.Equal(("Deciso", "OPNsense", "25.7.3_1"), (r.Software.Single().Vendor, r.Software.Single().Product, r.Software.Single().Version));
        var basic = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("k3yK3yK3y:s3cr3t"));
        Assert.All(h.Calls, c => Assert.Equal(basic, c.Auth?.ToString()));
        Assert.All(h.Calls, c => Assert.Equal(HttpMethod.Get, c.Method));
        Assert.Empty(r.Warnings);
    }

    [Fact]
    public async Task OpnSense_port_forwards_one_to_one_and_wan_rules_to_the_firewall_are_exposure()
    {
        var (a, _) = Opn();
        var r = await a.CollectAsync(OpnCreds, null, null, CancellationToken.None);

        Assert.Equal("firewall rule 'WireGuard' passes udp 51820 to the firewall on wan", r.Exposures.Single(e => e.AssetExternalId is not null).Evidence);
        Assert.Equal("port forward 'web server' on wan tcp wanip:443 -> 10.110.0.20:443", r.Exposures.Single(e => e.IpAddress == "10.110.0.20").Evidence);
        Assert.Equal("1:1 NAT 'mail' on wan 203.0.113.71 <-> 10.110.0.25", r.Exposures.Single(e => e.IpAddress == "10.110.0.25").Evidence);
        Assert.DoesNotContain(r.Exposures, e => e.IpAddress is "10.110.0.21" or "10.110.0.53"); // disabled; LAN-side redirect
        Assert.Equal(3, r.Exposures.Count);
    }

    [Fact]
    public async Task OpnSense_before_25_7_skips_port_forwards_with_a_warning_and_falls_back_to_firmware_status()
    {
        var (a, _) = Opn(p => p switch
        {
            OpnSenseAdapter.Paths.DNat or OpnSenseAdapter.Paths.SystemInformation => FakeHandler.Json("{\"errorMessage\":\"Endpoint not found\"}", HttpStatusCode.NotFound),
            OpnSenseAdapter.Paths.FirmwareStatus => FakeHandler.Json("{\"status\":\"none\",\"product\":{\"product_name\":\"OPNsense\",\"product_version\":\"24.7.12_4\",\"product_arch\":\"amd64\"}}"),
            _ => null
        });
        var r = await a.CollectAsync(OpnCreds, null, null, CancellationToken.None);
        Assert.Equal("24.7.12_4", r.Software.Single().Version);
        Assert.Equal("opn.example.test", r.Assets.Single().ExternalId);
        Assert.Equal(new[] { "Skipped api/firewall/d_nat/search_rule: port forwards need OPNsense 25.7 or later" }, r.Warnings);
    }

    [Fact]
    public async Task OpnSense_rejected_key_and_missing_privilege_are_explained()
    {
        var (a, _) = Opn(_ => FakeHandler.Json("{\"status\":401,\"message\":\"Authentication Failed\"}", HttpStatusCode.Unauthorized));
        var t = await a.TestAsync(OpnCreds, CancellationToken.None);
        Assert.False(t.Ok);
        Assert.Contains("rejected the API key and secret", t.Message);
        Assert.DoesNotContain("s3cr3t", t.Message);

        var (b, _) = Opn(p => p == OpnSenseAdapter.Paths.Filter ? FakeHandler.Json("{\"status\":403,\"message\":\"Forbidden\"}", HttpStatusCode.Forbidden) : null);
        var r = await b.CollectAsync(OpnCreds, null, null, CancellationToken.None);
        Assert.Contains(r.Warnings, w => w.Contains("Effective privileges"));

        var (ok, _) = Opn();
        var t2 = await ok.TestAsync(OpnCreds, CancellationToken.None);
        Assert.Equal("Connected to opn-edge-01.example.test, OPNsense 25.7.3_1.", t2.Message);
    }

    [Fact]
    public void Metadata_is_honest_about_na_cve_records()
    {
        Assert.Contains("'n/a'", new PfSenseAdapter().Metadata.Description);
        var m = new OpnSenseAdapter(new FakeHttpClientFactory(new FakeHandler())).Metadata;
        Assert.Contains("'n/a'", m.Description);
        Assert.Equal(("opnsense", "Deciso"), (m.Id, m.Vendor));
        Assert.Equal(CredentialTypes.Password, m.Form.Single(f => f.Key == "apiSecret").Type);
    }
}
