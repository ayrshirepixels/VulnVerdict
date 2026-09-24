using System.Net;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Adapters.Firewalls;
using VulnVerdict.Core.Data;
using static VulnVerdict.Tests.Firewalls.FirewallFixtures;

namespace VulnVerdict.Tests.Firewalls;

/// <summary>UniFi: local account (the application's own API, with port forwards) and API key (official API, no port forwards).</summary>
public class UniFiGatewayAdapterTests
{
    private static readonly Dictionary<string, string> LocalCreds = new() { ["host"] = "192.0.2.90", ["username"] = "vv-view", ["password"] = "view-only-pw", ["verifyTls"] = "false" };
    private static readonly Dictionary<string, string> KeyCreds = new() { ["host"] = "192.0.2.90", ["apiKey"] = "unifi-api-key-test" };

    private static (UniFiGatewayAdapter Adapter, FakeHandler Handler) Classic(bool selfHosted = false)
    {
        var responses = Responses("unifi", "classic.json");
        var h = new FakeHandler();
        h.On(r => true, (r, _) =>
        {
            var path = r.RequestUri!.AbsolutePath.TrimStart('/');
            if (path == "api/auth/login")
            {
                if (selfHosted) return FakeHandler.Json("", HttpStatusCode.NotFound);
                var ok = FakeHandler.Json("{\"unique_id\":\"x\",\"username\":\"vv-view\"}");
                ok.Headers.TryAddWithoutValidation("Set-Cookie", "TOKEN=eyJhbGciOi.test.token; path=/; samesite=strict; secure; httponly");
                ok.Headers.TryAddWithoutValidation("X-CSRF-Token", "csrf-123");
                return ok;
            }
            if (path == "api/login" && selfHosted)
            {
                var ok = FakeHandler.Json("{\"meta\":{\"rc\":\"ok\"},\"data\":[]}");
                ok.Headers.TryAddWithoutValidation("Set-Cookie", "unifises=sess-456; Path=/; Secure; HttpOnly");
                ok.Headers.TryAddWithoutValidation("Set-Cookie", "csrf_token=csrf-456; Path=/; Secure");
                return ok;
            }
            if (path is "api/auth/logout" or "api/logout") return FakeHandler.Json("{}");
            var key = selfHosted ? path : path.StartsWith("proxy/network/") ? path["proxy/network/".Length..] : "(not under proxy/network)";
            return responses.TryGetValue(key, out var json) ? FakeHandler.Json(json) : FakeHandler.Json("{\"meta\":{\"rc\":\"error\",\"msg\":\"api.err.NotFound\"},\"data\":[]}", HttpStatusCode.NotFound);
        });
        return (new UniFiGatewayAdapter(new FakeHttpClientFactory(h)), h);
    }

    private static (UniFiGatewayAdapter Adapter, FakeHandler Handler) Integration()
    {
        var responses = Responses("unifi", "integration.json");
        var h = new FakeHandler();
        h.On(r => true, (r, _) =>
        {
            var path = r.RequestUri!.AbsolutePath.TrimStart('/').Replace(UniFiGatewayAdapter.IntegrationBase + "/", "");
            var q = Query(r);
            var parts = path.Split('/');
            string? key = path switch
            {
                "info" => "info",
                "sites" => "sites",
                _ when parts.Length == 3 && parts[2] == "devices" => q.Contains("offset=0") ? "devices-page1" : "devices-page2",
                _ when parts.Length == 4 && parts[2] == "devices" => "detail-" + parts[3],
                _ => null
            };
            return key is not null && responses.TryGetValue(key, out var json) ? FakeHandler.Json(json) : FakeHandler.Json("{\"statusCode\":404}", HttpStatusCode.NotFound);
        });
        return (new UniFiGatewayAdapter(new FakeHttpClientFactory(h)), h);
    }

    [Fact]
    public async Task Local_account_maps_the_gateway_devices_and_network_application()
    {
        var (a, h) = Classic();
        var r = await a.CollectAsync(LocalCreds, null, null, CancellationToken.None);

        var gw = Assert.Single(r.Assets, x => x.Kind == AssetKind.Firewall);
        Assert.Equal(("74:ac:b9:00:00:01", "UDM-Pro-Office", Criticality.Critical), (gw.ExternalId, gw.DisplayName, gw.Criticality));
        Assert.Equal(new[] { "203.0.113.90" }, gw.IpAddresses);
        var fw = r.Software.Where(s => s.AssetExternalId == gw.ExternalId && s.Kind == SoftwareKind.Firmware).ToList();
        Assert.Equal(new[] { "UDM-Pro", "UniFi OS" }, fw.Select(s => s.Product).ToArray()); // the model name and the older "UniFi OS" spelling
        Assert.All(fw, s => Assert.Equal(("Ubiquiti Inc", "4.3.6.28111", "UDMPRO"), (s.Vendor, s.Version, s.Edition)));
        var app = Assert.Single(r.Software, s => s.Product == "UniFi Network Application");
        Assert.Equal((gw.ExternalId, "9.4.19"), (app.AssetExternalId, app.Version));

        Assert.Equal(AssetKind.Switch, r.Assets.Single(x => x.DisplayName == "Switch 24 PoE").Kind);
        Assert.Equal(AssetKind.AccessPoint, r.Assets.Single(x => x.DisplayName == "AP Reception").Kind);
        Assert.Equal(3, r.Assets.Count);
        Assert.Empty(r.Warnings);

        // session: login once, cookie and CSRF token on every read, logout at the end
        Assert.Equal("api/auth/login", h.Calls.First().Path.TrimStart('/'));
        Assert.Equal("api/auth/logout", h.Calls.Last().Path.TrimStart('/'));
        var reads = h.Calls.Skip(1).SkipLast(1).ToList();
        Assert.All(reads, c => Assert.Equal(HttpMethod.Get, c.Method));
        Assert.All(reads, c => Assert.Equal("TOKEN=eyJhbGciOi.test.token", c.Header("Cookie")));
        Assert.All(reads, c => Assert.Equal("csrf-123", c.Header("X-CSRF-Token")));
        Assert.DoesNotContain("view-only-pw", string.Join(" ", reads.Select(c => c.Url.ToString())));
    }

    [Fact]
    public async Task Port_forwards_and_an_enabled_vpn_server_are_exposure()
    {
        var (a, _) = Classic();
        var r = await a.CollectAsync(LocalCreds, null, null, CancellationToken.None);

        Assert.Equal("port forward 'NAS web' tcp wan:5001 -> 10.150.0.30:5001 from any", r.Exposures.Single(e => e.IpAddress == "10.150.0.30").Evidence);
        Assert.DoesNotContain(r.Exposures, e => e.IpAddress == "10.150.0.31"); // disabled
        var self = Assert.Single(r.Exposures, e => e.AssetExternalId == "74:ac:b9:00:00:01");
        Assert.Equal("WireGuard VPN server 'Staff VPN' on the WAN:51820", self.Evidence); // the disabled L2TP server is not listed
        Assert.Equal(2, r.Exposures.Count);
    }

    [Fact]
    public async Task Self_hosted_application_logs_in_on_the_legacy_path_and_gets_its_own_asset()
    {
        var (a, h) = Classic(selfHosted: true);
        var r = await a.CollectAsync(LocalCreds, null, null, CancellationToken.None);

        Assert.Contains(h.Calls, c => c.Path == "/api/login");
        Assert.Contains(h.Calls, c => c.Path == "/api/s/default/stat/device");
        Assert.All(h.Calls.Where(c => c.Method == HttpMethod.Get), c => Assert.Equal("unifises=sess-456; csrf_token=csrf-456", c.Header("Cookie")));
        Assert.Equal("/api/logout", h.Calls.Last().Path);
        // the gateway is a console, so the application still sits on it
        Assert.Equal("74:ac:b9:00:00:01", r.Software.Single(s => s.Product == "UniFi Network Application").AssetExternalId);
    }

    [Fact]
    public async Task Api_key_reads_devices_with_firmware_over_pages_and_warns_about_port_forwards()
    {
        var (a, h) = Integration();
        var r = await a.CollectAsync(KeyCreds, null, null, CancellationToken.None);

        Assert.Equal(3, r.Assets.Count);
        Assert.Equal(2, h.Calls.Count(c => c.Path.EndsWith("/devices")));
        var gw = Assert.Single(r.Assets, x => x.Kind == AssetKind.Firewall);
        Assert.Equal(("9c:05:d6:00:00:01", "Cloud Gateway"), (gw.ExternalId, gw.DisplayName));
        Assert.Equal(new[] { "UCG-Max", "UniFi OS" }, r.Software.Where(s => s.AssetExternalId == gw.ExternalId && s.Kind == SoftwareKind.Firmware).Select(s => s.Product).ToArray());
        Assert.Equal("5.0.16", r.Software.First(s => s.AssetExternalId == gw.ExternalId).Version);
        Assert.Equal(AssetKind.AccessPoint, r.Assets.Single(x => x.DisplayName == "Loft AP").Kind);
        Assert.Equal(("U7-Pro", "8.0.24"), (r.Software.Single(s => s.AssetExternalId == "9c:05:d6:00:00:02").Product, r.Software.Single(s => s.AssetExternalId == "9c:05:d6:00:00:02").Version));
        Assert.Equal(AssetKind.Switch, r.Assets.Single(x => x.DisplayName == "Desk switch").Kind);
        Assert.Equal("9.4.19", r.Software.Single(s => s.Product == "UniFi Network Application").Version);
        Assert.Empty(r.Exposures);
        Assert.Contains(r.Warnings, w => w.Contains("not in the UniFi Network API"));
        Assert.All(h.Calls, c => Assert.Equal("unifi-api-key-test", c.Header("X-API-KEY")));
        Assert.All(h.Calls, c => Assert.Equal(HttpMethod.Get, c.Method));
    }

    [Fact]
    public async Task Rejected_login_and_unknown_site_fail_clearly()
    {
        var h = new FakeHandler();
        h.On(HttpMethod.Post, "/api/auth/login", "{\"code\":\"AUTHENTICATION_FAILED_INVALID_CREDENTIALS\",\"message\":\"Invalid username or password\"}", HttpStatusCode.Unauthorized);
        var t = await new UniFiGatewayAdapter(new FakeHttpClientFactory(h)).TestAsync(LocalCreds, CancellationToken.None);
        Assert.False(t.Ok);
        Assert.Contains("rejected", t.Message);
        Assert.DoesNotContain("view-only-pw", t.Message);

        var (a, _) = Classic();
        var t2 = await a.TestAsync(new Dictionary<string, string>(LocalCreds) { ["site"] = "branch" }, CancellationToken.None);
        Assert.False(t2.Ok);
        Assert.Contains("site 'branch' not found", t2.Message);

        var (b, _) = Classic();
        var t3 = await b.TestAsync(LocalCreds, CancellationToken.None);
        Assert.Equal("Connected (local account, UniFi OS), UniFi Network 9.4.19, site(s): default.", t3.Message);
    }

    [Theory]
    [InlineData("UDMPRO", "UDM-Pro")]
    [InlineData("UDRULT", "UCG-Ultra")]
    [InlineData("UDM Pro", "UDM-Pro")]
    [InlineData("UDM SE", "UDM-SE")]
    [InlineData("UCG Max", "UCG-Max")]
    [InlineData("Express 7", "Express 7")]
    [InlineData(null, "UniFi device")]
    public void Model_codes_and_display_models_become_the_cve_product_names(string? model, string expected) => Assert.Equal(expected, UniFiGatewayAdapter.ProductName(model));
}
