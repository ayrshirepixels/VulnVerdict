using System.Net;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Adapters.Firewalls;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;
using static VulnVerdict.Tests.Firewalls.FirewallFixtures;

namespace VulnVerdict.Tests.Firewalls;

/// <summary>Sophos Firewall: XML API for exposure, SNMP (faked) for the SFOS version.</summary>
public class SophosFirewallAdapterTests
{
    private static readonly Dictionary<string, string> Creds = new() { ["host"] = "xgs.example.test", ["username"] = "vv-api", ["password"] = "<&secret>", ["community"] = "ro-community" };

    private static (SophosFirewallAdapter Adapter, FakeHandler Handler, List<string[]> SnmpCalls) Build(string? xml = null, Dictionary<string, string>? snmp = null)
    {
        var h = new FakeHandler();
        h.On(r => true, (_, _) => Xml(xml ?? Read("sophos", "get-response.xml")));
        var calls = new List<string[]>();
        var a = new SophosFirewallAdapter(new FakeHttpClientFactory(h))
        {
            Snmp = (host, _, oids, _) =>
            {
                calls.Add(oids);
                Assert.Equal("xgs.example.test", host);
                return Task.FromResult<Dictionary<string, string>?>(snmp ?? new Dictionary<string, string>
                {
                    [SophosFirewallAdapter.SfosDeviceName] = "XGS-EDGE-01",
                    [SophosFirewallAdapter.SfosDeviceType] = "XGS2100",
                    [SophosFirewallAdapter.SfosDeviceFwVersion] = "SFOS 21.0.1 MR-1-Build272",
                    [SophosFirewallAdapter.SfosDeviceAppKey] = "X21001ABCDEF01",
                });
            }
        };
        return (a, h, calls);
    }

    [Fact]
    public async Task Maps_the_firewall_with_the_sfos_version_in_the_cna_form()
    {
        var (a, h, snmp) = Build();
        var r = await a.CollectAsync(Creds, null, null, CancellationToken.None);

        var fw = Assert.Single(r.Assets);
        Assert.Equal(("X21001ABCDEF01", "XGS-EDGE-01", AssetKind.Firewall), (fw.ExternalId, fw.DisplayName, fw.Kind));
        Assert.Equal(("Sophos", "Sophos Firewall", "21.0 MR1", "272"), (fw.OsVendor, fw.OsProduct, fw.OsVersion, fw.OsBuild));
        Assert.Equal(new[] { "10.80.0.1", "203.0.113.50", "10.90.0.1" }, fw.IpAddresses);
        var sw = Assert.Single(r.Software);
        Assert.Equal(("Sophos", "Sophos Firewall", "21.0 MR1", "XGS2100"), (sw.Vendor, sw.Product, sw.Version, sw.Edition));
        Assert.Empty(r.Warnings);
        Assert.Single(snmp);

        // one POST to the admin port, credentials only in the (XML-escaped) body
        var call = Assert.Single(h.Calls);
        Assert.Equal(HttpMethod.Post, call.Method);
        Assert.Equal("https://xgs.example.test:4444/webconsole/APIController", call.Url.ToString());
        var reqxml = Uri.UnescapeDataString(call.Body!.Replace('+', ' '));
        Assert.Contains("<Password>&lt;&amp;secret&gt;</Password>", reqxml);
        Assert.Contains("<Get><Zone /><Interface /><NATRule /><IPHost /><AdminSettings /></Get>", reqxml);
        Assert.DoesNotContain("<Set", reqxml);
    }

    [Fact]
    public async Task Wan_zone_device_access_makes_the_firewall_internet_facing()
    {
        var (a, _, _) = Build();
        var r = await a.CollectAsync(Creds, null, null, CancellationToken.None);

        var ex = Assert.Single(r.Exposures, e => e.AssetExternalId == "X21001ABCDEF01");
        Assert.Equal("web admin console on zone WAN:4444; VPN portal on zone WAN:443; SSL VPN on zone WAN:8443; IPsec VPN on zone WAN:500", ex.Evidence);
        Assert.DoesNotContain("SSH", ex.Evidence);        // disabled on WAN
        Assert.DoesNotContain("user portal", ex.Evidence); // enabled on LAN only
        Assert.Contains(r.Software.Single().Listeners!, l => l.Bind == "LAN" && l.Process == "admin SSH");
    }

    [Fact]
    public async Task Dnat_to_the_wan_address_or_on_a_wan_interface_exposes_the_translated_host()
    {
        var (a, _, _) = Build();
        var r = await a.CollectAsync(Creds, null, null, CancellationToken.None);

        Assert.Equal("NAT rule DNAT web to webserver #Port2 HTTPS -> web01 10.90.0.20", r.Exposures.Single(e => e.IpAddress == "10.90.0.20").Evidence);
        Assert.Equal("NAT rule DNAT mail mail-public SMTP -> 10.90.0.25 10.90.0.25", r.Exposures.Single(e => e.IpAddress == "10.90.0.25").Evidence);
        Assert.DoesNotContain(r.Exposures, e => e.IpAddress == "10.90.0.21"); // disabled
        Assert.DoesNotContain(r.Exposures, e => e.IpAddress == "10.90.0.30"); // LAN-side rule
        Assert.Equal(3, r.Exposures.Count);
    }

    [Fact]
    public async Task Without_snmp_the_firewall_is_recorded_with_a_blank_version_and_a_warning()
    {
        var (a, _, snmp) = Build();
        var creds = new Dictionary<string, string>(Creds);
        creds.Remove("community");
        var r = await a.CollectAsync(creds, null, null, CancellationToken.None);

        Assert.Empty(snmp);
        var fw = Assert.Single(r.Assets);
        Assert.Equal(("xgs.example.test", "xgs-edge-01.example.test"), (fw.ExternalId, fw.DisplayName));
        Assert.Equal("", r.Software.Single().Version);
        Assert.Contains(r.Warnings, w => w.Contains("firmware version is blank"));
    }

    [Fact]
    public async Task Ip_not_allowed_and_failed_login_are_explained()
    {
        var (a, _, _) = Build("<Response APIVersion=\"2100.1\" IPS_CAT_VER=\"1\"><Status code=\"534\">API operations are not allowed from the requester IP address</Status></Response>");
        var t = await a.TestAsync(Creds, CancellationToken.None);
        Assert.False(t.Ok);
        Assert.Contains("534", t.Message);
        Assert.Contains("allowed list", t.Message);

        var (b, _, _) = Build("<Response APIVersion=\"2100.1\" IPS_CAT_VER=\"1\"><Login><status>Authentication Failure</status></Login></Response>");
        var t2 = await b.TestAsync(Creds, CancellationToken.None);
        Assert.False(t2.Ok);
        Assert.Contains("Authentication Failure", t2.Message);
        Assert.DoesNotContain("secret", t2.Message);

        var (c, _, _) = Build("<html><body>Sophos Firewall</body></html>");
        var t3 = await c.TestAsync(Creds, CancellationToken.None);
        Assert.False(t3.Ok);
        Assert.Contains("is the API enabled", t3.Message);

        var (ok, _, _) = Build();
        var t4 = await ok.TestAsync(Creds, CancellationToken.None);
        Assert.True(t4.Ok, t4.Message);
        Assert.Equal("Connected to xgs-edge-01.example.test (XML API 2100.1). SNMP: XGS2100 SFOS 21.0.1 MR-1-Build272.", t4.Message);
    }

    [Theory]
    [InlineData("SFOS 21.0.1 MR-1-Build272", "21.0 MR1", "272")]
    [InlineData("SFOS 21.5.0 GA-Build171", "21.5 GA", "171")]
    [InlineData("SFOS 19.5.3 MR-3-Build652", "19.5 MR3", "652")]
    [InlineData("", null, null)]
    public void Sfos_versions_take_the_cna_form(string text, string? version, string? build) => Assert.Equal((version, build), SophosFirewallAdapter.FirmwareVersion(text));

    [Theory]
    [InlineData("21.0 GA", "21.0 MR1 (21.0.1)", -1)]  // CVE-2024-12727: fixed in 21.0 MR1, so GA is older
    [InlineData("21.0 MR1", "21.0 MR1 (21.0.1)", 0)]
    [InlineData("21.0 MR2", "21.0 MR1 (21.0.1)", 1)]
    [InlineData("20.0 MR3", "21.0 MR2 (21.0.2)", -1)]
    [InlineData("21.5 GA", "21.0 MR2 (21.0.2)", 1)]
    public void The_cna_form_compares_the_right_way_round(string installed, string cna, int expected) => Assert.Equal(expected, Math.Sign(VersionCompare.Compare(installed, cna)!.Value));

    [Fact]
    public void Metadata_explains_the_snmp_split()
    {
        var m = new SophosFirewallAdapter(new FakeHttpClientFactory(new FakeHandler())).Metadata;
        Assert.Equal("sophos-firewall", m.Id);
        Assert.Contains("XML API does not report it", m.Description);
        Assert.Contains(m.Form, f => f.Key == "community" && f.Type == CredentialTypes.Password && !f.Required);
        Assert.Contains("read-only", m.MinimumPermission);
        Assert.StartsWith("https://docs.sophos.com/", m.DocsUrl);
    }
}
