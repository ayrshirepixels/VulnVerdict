using System.Net;
using System.Text;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Adapters.Firewalls;
using VulnVerdict.Core.Data;
using static VulnVerdict.Tests.Firewalls.FirewallFixtures;

namespace VulnVerdict.Tests.Firewalls;

/// <summary>SonicOS 7 API adapter against responses shaped like the SonicOS OpenAPI schema.</summary>
public class SonicWallAdapterTests
{
    private static readonly Dictionary<string, string> Creds = new() { ["host"] = "sw.example.test", ["username"] = "vv-api", ["password"] = "pa55:word" };
    private const string Ok = "{\"status\":{\"success\":true,\"info\":[{\"level\":\"info\",\"code\":\"E_OK\",\"message\":\"Success.\"}]}}";

    private static (SonicWallAdapter Adapter, FakeHandler Handler) Build(Func<string, string?>? overrides = null)
    {
        var responses = Responses("sonicwall");
        var h = new FakeHandler();
        h.On(r => true, (r, _) =>
        {
            var path = r.RequestUri!.AbsolutePath.Replace("/api/sonicos/", "");
            if (path == "auth") return FakeHandler.Json(Ok);
            var o = overrides?.Invoke(path);
            if (o is not null) return FakeHandler.Json(o);
            return responses.TryGetValue(path, out var json) ? FakeHandler.Json(json)
                : FakeHandler.Json("{\"status\":{\"success\":false,\"info\":[{\"level\":\"error\",\"code\":\"E_NOT_FOUND\",\"message\":\"Not found.\"}]}}", HttpStatusCode.NotFound);
        });
        return (new SonicWallAdapter(new FakeHttpClientFactory(h)), h);
    }

    [Fact]
    public async Task Maps_the_firewall_with_sonicos_version_as_the_cna_writes_it()
    {
        var (a, h) = Build();
        var r = await a.CollectAsync(Creds, null, null, CancellationToken.None);

        var fw = Assert.Single(r.Assets);
        Assert.Equal(("2CB8ED0A0001", "SW-EDGE-01", AssetKind.Firewall), (fw.ExternalId, fw.DisplayName, fw.Kind));
        Assert.Equal(("SonicWall", "SonicOS", "7.1.1-7058"), (fw.OsVendor, fw.OsProduct, fw.OsVersion));
        Assert.Equal(new[] { "10.40.0.1", "198.51.100.2", "10.50.0.1" }, fw.IpAddresses);
        var sw = Assert.Single(r.Software);
        Assert.Equal(("SonicWall", "SonicOS", "7.1.1-7058", "TZ 370"), (sw.Vendor, sw.Product, sw.Version, sw.Edition));

        var basic = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("vv-api:pa55:word"));
        Assert.All(h.Calls, c => Assert.Equal(basic, c.Auth?.ToString()));
        Assert.Equal(HttpMethod.Post, h.Calls.First().Method);                      // open the API session
        Assert.Equal(HttpMethod.Delete, h.Calls.Last().Method);                     // and close it again
        Assert.All(h.Calls.Skip(1).SkipLast(1), c => Assert.Equal(HttpMethod.Get, c.Method));
        Assert.DoesNotContain(h.Calls, c => (c.Body ?? "").Contains("override"));   // never pushes out a logged-in admin
    }

    [Fact]
    public async Task Https_management_user_login_and_ssl_vpn_on_wan_make_the_firewall_internet_facing()
    {
        var (a, _) = Build();
        var r = await a.CollectAsync(Creds, null, null, CancellationToken.None);

        var ex = Assert.Single(r.Exposures, e => e.AssetExternalId == "2CB8ED0A0001");
        Assert.Equal("management HTTPS on X1 (zone WAN):8443; user login HTTPS on X1 (zone WAN); SSL VPN on zone WAN:4433", ex.Evidence);
        var listeners = r.Software.Single().Listeners!;
        Assert.Contains(listeners, l => l.Bind == "X0" && l.Port == 22);  // LAN SSH is a listener, not exposure
        Assert.DoesNotContain("X0", ex.Evidence);
    }

    [Fact]
    public async Task Enabled_inbound_nat_on_a_wan_interface_exposes_the_translated_host()
    {
        var (a, _) = Build();
        var r = await a.CollectAsync(Creds, null, null, CancellationToken.None);

        var web = Assert.Single(r.Exposures, e => e.IpAddress == "10.50.0.20");
        Assert.Equal("NAT policy web inbound on X1 X1 IP HTTPS -> web-server 10.50.0.20", web.Evidence);
        Assert.DoesNotContain(r.Exposures, e => e.IpAddress == "10.50.0.25"); // disabled policy
        Assert.Equal(2, r.Exposures.Count);                                   // the reflexive LAN policy adds nothing
        Assert.Empty(r.Warnings);
    }

    [Fact]
    public async Task Missing_ssl_vpn_endpoints_become_warnings()
    {
        var (a, _) = Build(p => p.StartsWith("ssl-vpn") ? "{\"status\":{\"success\":false,\"info\":[{\"level\":\"error\",\"code\":\"E_NOT_SUPPORTED\",\"message\":\"Not supported.\"}]}}" : null);
        var r = await a.CollectAsync(Creds, null, null, CancellationToken.None);
        Assert.Equal(2, r.Warnings.Count);
        Assert.All(r.Warnings, w => Assert.Contains("Not supported.", w));
        Assert.DoesNotContain("SSL VPN", r.Exposures.Single(e => e.AssetExternalId is not null).Evidence);
    }

    [Fact]
    public async Task Api_disabled_and_rejected_credentials_give_clear_messages()
    {
        var h = new FakeHandler();
        h.On(HttpMethod.Post, "/api/sonicos/auth", "<html>Not Found</html>", HttpStatusCode.NotFound);
        var t = await new SonicWallAdapter(new FakeHttpClientFactory(h)).TestAsync(Creds, CancellationToken.None);
        Assert.False(t.Ok);
        Assert.Contains("SonicOS API is not enabled", t.Message);

        var h2 = new FakeHandler();
        h2.On(HttpMethod.Post, "/api/sonicos/auth", "{\"status\":{\"success\":false,\"info\":[{\"level\":\"error\",\"code\":\"E_UNAUTHORIZED\",\"message\":\"Unauthorized.\"}]}}", HttpStatusCode.Unauthorized);
        var t2 = await new SonicWallAdapter(new FakeHttpClientFactory(h2)).TestAsync(Creds, CancellationToken.None);
        Assert.False(t2.Ok);
        Assert.Contains("401", t2.Message);
        Assert.Contains("rejected the username or password", t2.Message);
        Assert.DoesNotContain("pa55", t2.Message);

        var (ok, _) = Build();
        var t3 = await ok.TestAsync(Creds, CancellationToken.None);
        Assert.True(t3.Ok, t3.Message);
        Assert.Equal("Connected to TZ 370 SonicOS 7.1.1-7058, serial 2CB8ED0A0001.", t3.Message);
    }

    [Fact]
    public void Metadata_states_what_the_api_needs()
    {
        var m = new SonicWallAdapter(new FakeHttpClientFactory(new FakeHandler())).Metadata;
        Assert.Equal("sonicwall", m.Id);
        Assert.Equal(new[] { "host", "username", "password", "verifyTls" }, m.Form.Select(f => f.Key).ToArray());
        Assert.Equal(CredentialTypes.Password, m.Form.Single(f => f.Key == "password").Type);
        Assert.StartsWith("https://www.sonicwall.com/", m.DocsUrl);
    }
}
