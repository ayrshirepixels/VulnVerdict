using System.Net;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Adapters.Firewalls;
using VulnVerdict.Core.Data;
using static VulnVerdict.Tests.Firewalls.FirewallFixtures;

namespace VulnVerdict.Tests.Firewalls;

/// <summary>PAN-OS XML API adapter against hand-written responses shaped like the documented XML API output.</summary>
public class PanOsAdapterTests
{
    private static readonly Dictionary<string, string> KeyCreds = new() { ["host"] = "pa.example.test", ["apiKey"] = "LUFRPT1-test-key", ["verifyTls"] = "false" };

    private static (PanOsAdapter Adapter, FakeHandler Handler, FakeHttpClientFactory Factory) Build(Func<string, string?>? overrides = null)
    {
        var h = new FakeHandler();
        h.On(r => true, (r, _) =>
        {
            var q = Query(r);
            var o = overrides?.Invoke(q);
            if (o is not null) return Xml(o);
            if (q.Contains("type=keygen")) return Xml("<response status=\"success\"><result><key>LUFRPT1-generated</key></result></response>");
            if (q.Contains("type=op") && q.Contains("<show><system><info>")) return Xml(Read("panos", "system-info.xml"));
            string? file = null;
            if (q.Contains("/network/interface")) file = "interfaces.xml";
            else if (q.Contains("interface-management-profile")) file = "mgmt-profiles.xml";
            else if (q.EndsWith("/zone")) file = "zones.xml";
            else if (q.Contains("global-protect-portal")) file = "gp-portal.xml";
            else if (q.Contains("/config/shared/address")) return Xml("<response status=\"success\"><result/></response>");
            else if (q.EndsWith("/address")) file = "addresses.xml";
            else if (q.Contains("/rulebase/nat/rules")) file = "nat.xml";
            else if (q.Contains("/rulebase/security/rules")) file = "security.xml";
            if (file is null) return Xml("<response status=\"error\" code=\"7\"><msg>No such node</msg></response>");
            return Xml(Read("panos", file));
        });
        var f = new FakeHttpClientFactory(h);
        return (new PanOsAdapter(f), h, f);
    }

    [Fact]
    public async Task Maps_the_firewall_with_pan_os_version_model_and_serial()
    {
        var (a, h, f) = Build();
        var r = await a.CollectAsync(KeyCreds, null, null, CancellationToken.None);

        var fw = Assert.Single(r.Assets);
        Assert.Equal(("012801000001", "PA-EDGE-01", AssetKind.Firewall, Criticality.Critical), (fw.ExternalId, fw.DisplayName, fw.Kind, fw.Criticality));
        Assert.Equal(("Palo Alto Networks", "PAN-OS", "11.1.5"), (fw.OsVendor, fw.OsProduct, fw.OsVersion));
        Assert.Contains("192.0.2.10", fw.IpAddresses);
        Assert.Contains("203.0.113.2", fw.IpAddresses);
        Assert.Contains("00:1b:17:00:aa:01", fw.MacAddresses);

        var sw = Assert.Single(r.Software);
        Assert.Equal(("Palo Alto Networks", "PAN-OS", "11.1.5", SoftwareKind.Firmware, "PA-440"), (sw.Vendor, sw.Product, sw.Version, sw.Kind, sw.Edition));
        Assert.Equal(new[] { "adapter-insecure" }, f.Names.Distinct().ToArray());
        Assert.All(h.Calls, c => Assert.Equal("LUFRPT1-test-key", c.Header("X-PAN-KEY")));
        Assert.All(h.Calls, c => Assert.DoesNotContain("key=", c.Url.Query)); // the key never travels in a URL
        Assert.All(h.Calls, c => Assert.Equal(HttpMethod.Get, c.Method));
    }

    [Fact]
    public async Task Management_https_ssh_and_globalprotect_in_the_untrust_zone_make_the_firewall_internet_facing()
    {
        var (a, _, _) = Build();
        var r = await a.CollectAsync(KeyCreds, null, null, CancellationToken.None);

        var ex = Assert.Single(r.Exposures, e => e.AssetExternalId == "012801000001");
        Assert.Equal(Exposure.Internet, ex.Exposure);
        Assert.Contains("management HTTPS on ethernet1/1 (zone untrust)", ex.Evidence);
        Assert.Contains("management SSH on ethernet1/1 (zone untrust)", ex.Evidence);
        Assert.Contains("GlobalProtect portal GP-Portal on loopback.1 (zone untrust)", ex.Evidence);
        Assert.DoesNotContain("ethernet1/2", ex.Evidence); // the same profile on the trust side is not exposure

        var listeners = r.Software.Single().Listeners!;
        Assert.Contains(listeners, l => l.Port == 443 && l.Bind == "ethernet1/2" && l.Process == "management https");
        Assert.Contains(listeners, l => l.Port == 443 && l.Bind == "loopback.1" && l.Process == "GlobalProtect portal");
    }

    [Fact]
    public async Task Destination_nat_with_an_allow_rule_from_untrust_exposes_the_translated_host_only()
    {
        var (a, _, _) = Build();
        var r = await a.CollectAsync(KeyCreds, null, null, CancellationToken.None);

        var web = Assert.Single(r.Exposures, e => e.IpAddress == "10.30.0.20");
        Assert.Equal(Exposure.Internet, web.Exposure);
        Assert.Equal("NAT rule web-dnat 203.0.113.20 service-https -> 10.30.0.20:443 allowed by security rule allow-web-in", web.Evidence);
        Assert.DoesNotContain(r.Exposures, e => e.IpAddress == "10.30.0.21"); // rdp: only a deny rule matches
        Assert.DoesNotContain(r.Exposures, e => e.IpAddress == "10.30.0.25"); // disabled NAT rule
        Assert.Equal(2, r.Exposures.Count);
    }

    [Fact]
    public async Task Missing_globalprotect_gateway_is_not_a_warning_and_zones_guessed_by_name_are()
    {
        var (a, _, _) = Build();
        var r = await a.CollectAsync(KeyCreds, null, null, CancellationToken.None);
        Assert.Single(r.Warnings);
        Assert.Contains("guessed by name: untrust", r.Warnings[0]);

        var named = new Dictionary<string, string>(KeyCreds) { ["internetZones"] = "untrust, dmz" };
        var r2 = await a.CollectAsync(named, null, null, CancellationToken.None);
        Assert.Empty(r2.Warnings);
    }

    [Fact]
    public async Task Username_and_password_generate_a_key_with_a_post_body_not_a_url()
    {
        var (a, h, _) = Build();
        var creds = new Dictionary<string, string> { ["host"] = "https://pa.example.test:8443/", ["username"] = "vv-reader", ["password"] = "s3cret pass" };
        var t = await a.TestAsync(creds, CancellationToken.None);
        Assert.True(t.Ok, t.Message);
        Assert.Contains("PA-EDGE-01", t.Message);
        Assert.Contains("11.1.5", t.Message);

        var keygen = Assert.Single(h.Calls, c => c.Url.Query.Contains("type=keygen"));
        Assert.Equal(HttpMethod.Post, keygen.Method);
        Assert.Equal("pa.example.test", keygen.Url.Host);
        Assert.Equal(8443, keygen.Url.Port);
        Assert.DoesNotContain("s3cret", keygen.Url.ToString());
        Assert.Contains("password=s3cret+pass", keygen.Body);
        Assert.Equal("LUFRPT1-generated", h.Calls.Last().Header("X-PAN-KEY"));
    }

    [Fact]
    public async Task Rejected_key_and_xml_api_errors_fail_the_test_with_the_firewalls_message()
    {
        var h = new FakeHandler();
        h.On(r => true, (_, _) => Xml("<response status=\"error\" code=\"403\"><result><msg>Invalid Credential</msg></result></response>", HttpStatusCode.Forbidden));
        var t = await new PanOsAdapter(new FakeHttpClientFactory(h)).TestAsync(KeyCreds, CancellationToken.None);
        Assert.False(t.Ok);
        Assert.Contains("403", t.Message);
        Assert.Contains("rejected the API key", t.Message);
        Assert.DoesNotContain("LUFRPT1", t.Message);

        var (a, _, _) = Build(q => q.Contains("type=op") ? "<response status=\"error\" code=\"13\"><msg><line>Command not allowed for this role</line></msg></response>" : null);
        var t2 = await a.TestAsync(KeyCreds, CancellationToken.None);
        Assert.False(t2.Ok);
        Assert.Contains("Command not allowed for this role", t2.Message);
    }

    [Fact]
    public void Metadata_names_a_read_only_role_and_the_vendor_docs()
    {
        var m = new PanOsAdapter(new FakeHttpClientFactory(new FakeHandler())).Metadata;
        Assert.Equal("panos", m.Id);
        Assert.Equal("Palo Alto Networks", m.Vendor);
        Assert.Contains(m.Form, f => f.Key == "apiKey" && f.Type == CredentialTypes.Password && !f.Required);
        Assert.Contains(m.Form, f => f.Key == "verifyTls" && f.Default == "true");
        Assert.Contains("read-only", m.MinimumPermission);
        Assert.StartsWith("https://docs.paloaltonetworks.com/", m.DocsUrl);
    }
}
