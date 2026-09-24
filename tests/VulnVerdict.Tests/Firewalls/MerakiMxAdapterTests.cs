using System.Net;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Adapters.Firewalls;
using VulnVerdict.Core.Data;
using static VulnVerdict.Tests.Firewalls.FirewallFixtures;

namespace VulnVerdict.Tests.Firewalls;

/// <summary>Meraki Dashboard API adapter: pagination by Link header, 429 Retry-After, firmware and NAT exposure.</summary>
public class MerakiMxAdapterTests
{
    private static readonly Dictionary<string, string> Creds = new() { ["apiKey"] = "0123456789abcdef-test" };

    private static (MerakiMxAdapter Adapter, FakeHandler Handler, List<TimeSpan> Waits) Build(bool throttleOnce = true)
    {
        var responses = Responses("meraki");
        var h = new FakeHandler();
        var throttled = !throttleOnce;
        h.On(r => true, (r, _) =>
        {
            var path = r.RequestUri!.AbsolutePath.Replace("/api/v1/", "");
            var q = Query(r);
            if (path == "organizations") return FakeHandler.Json(responses["organizations"]);
            if (path == "organizations/500000/devices")
            {
                if (q.Contains("startingAfter=Q2XX-AAAA-0001")) return FakeHandler.Json(responses["devices-page2"]);
                var first = FakeHandler.Json(responses["devices-page1"]);
                first.Headers.TryAddWithoutValidation("Link", "<https://api.meraki.com/api/v1/organizations/500000/devices?productTypes%5B%5D=appliance&perPage=1000&startingAfter=a000000>; rel=first, <https://api.meraki.com/api/v1/organizations/500000/devices?productTypes%5B%5D=appliance&perPage=1000&startingAfter=Q2XX-AAAA-0001>; rel=next");
                return first;
            }
            if (path == "organizations/500000/devices/statuses")
            {
                if (!throttled)
                {
                    throttled = true;
                    var busy = FakeHandler.Json("{\"errors\":[\"API rate limit exceeded for organization\"]}", (HttpStatusCode)429);
                    busy.Headers.TryAddWithoutValidation("Retry-After", "2");
                    return busy;
                }
                return FakeHandler.Json(responses["statuses"]);
            }
            var parts = path.Split('/'); // networks/{id}/appliance/firewall/{what}
            if (parts.Length == 5 && responses.TryGetValue(parts[4] + "-" + parts[1], out var json)) return FakeHandler.Json(json);
            return FakeHandler.Json("{\"errors\":[\"Not found\"]}", HttpStatusCode.NotFound);
        });
        var waits = new List<TimeSpan>();
        var a = new MerakiMxAdapter(new FakeHttpClientFactory(h)) { Delay = (t, _) => { waits.Add(t); return Task.CompletedTask; } };
        return (a, h, waits);
    }

    [Fact]
    public async Task Pages_through_devices_and_maps_appliances_with_firmware()
    {
        var (a, h, _) = Build();
        var r = await a.CollectAsync(Creds, null, null, CancellationToken.None);

        Assert.Equal(3, r.Assets.Count);
        Assert.Equal(2, h.Calls.Count(c => c.Path.EndsWith("/organizations/500000/devices")));
        var hq = Assert.Single(r.Assets, x => x.ExternalId == "Q2XX-AAAA-0001");
        Assert.Equal(("HQ-MX", AssetKind.Firewall, Criticality.Critical), (hq.DisplayName, hq.Kind, hq.Criticality));
        Assert.Equal(new[] { "10.60.0.1", "203.0.113.30" }, hq.IpAddresses);
        Assert.Equal(new[] { "e0:55:3d:00:00:01" }, hq.MacAddresses);
        var fw = Assert.Single(r.Software, s => s.AssetExternalId == "Q2XX-AAAA-0001");
        Assert.Equal(("Cisco", "Cisco Meraki MX Firmware", "18.211.2", "MX85"), (fw.Vendor, fw.Product, fw.Version, fw.Edition));
        Assert.Equal("19.1.4", r.Software.Single(s => s.AssetExternalId == "Q2XX-BBBB-0002").Version);

        // an unnamed spare that is not on its configured firmware: named by MAC, version blank, one warning
        var spare = Assert.Single(r.Assets, x => x.ExternalId == "Q2XX-CCCC-0003");
        Assert.Equal("e0:55:3d:00:00:03", spare.DisplayName);
        Assert.Equal("", r.Software.Single(s => s.AssetExternalId == "Q2XX-CCCC-0003").Version);
        Assert.Contains(r.Warnings, w => w.Contains("Not running configured version"));

        Assert.All(h.Calls, c => Assert.Equal("Bearer 0123456789abcdef-test", c.Auth?.ToString()));
        Assert.All(h.Calls, c => Assert.Equal(HttpMethod.Get, c.Method));
    }

    [Fact]
    public async Task Waits_for_retry_after_on_429_then_carries_on()
    {
        var (a, h, waits) = Build();
        var r = await a.CollectAsync(Creds, null, null, CancellationToken.None);
        Assert.Equal(new[] { TimeSpan.FromSeconds(2) }, waits);
        Assert.Equal(2, h.Calls.Count(c => c.Path.EndsWith("/devices/statuses")));
        Assert.Contains("203.0.113.30", r.Assets.Single(x => x.ExternalId == "Q2XX-AAAA-0001").IpAddresses); // statuses arrived after the retry
    }

    [Fact]
    public async Task Port_forwards_one_to_one_and_one_to_many_nat_expose_the_lan_hosts()
    {
        var (a, _, _) = Build(throttleOnce: false);
        var r = await a.CollectAsync(Creds, null, null, CancellationToken.None);

        Assert.Equal("port forward Web server tcp internet1:443 -> 10.60.0.20:443 from any", r.Exposures.Single(e => e.IpAddress == "10.60.0.20").Evidence);
        Assert.Equal("port forward RDP for supplier tcp both:3390 -> 10.60.0.21:3389 from 198.51.100.0/24", r.Exposures.Single(e => e.IpAddress == "10.60.0.21").Evidence);
        Assert.Equal("1:1 NAT Mail 203.0.113.31 -> 10.60.0.25 allows tcp 25 from any", r.Exposures.Single(e => e.IpAddress == "10.60.0.25").Evidence);
        Assert.DoesNotContain(r.Exposures, e => e.IpAddress == "10.60.0.26"); // 1:1 with no allowed inbound is outbound only
        Assert.Equal("1:many NAT VoIP 203.0.113.33:5060 -> 10.60.0.40:5060 from any", r.Exposures.Single(e => e.IpAddress == "10.60.0.40").Evidence);
        Assert.All(r.Exposures, e => Assert.Equal(Exposure.Internet, e.Exposure));
    }

    [Fact]
    public async Task Unrestricted_appliance_web_service_marks_the_mx_internet_facing_restricted_does_not()
    {
        var (a, _, _) = Build(throttleOnce: false);
        var r = await a.CollectAsync(Creds, null, null, CancellationToken.None);

        var hq = Assert.Single(r.Exposures, e => e.AssetExternalId == "Q2XX-AAAA-0001");
        Assert.Equal("appliance web service on the WAN is unrestricted", hq.Evidence);
        Assert.Contains(r.Exposures, e => e.AssetExternalId == "Q2XX-CCCC-0003"); // the spare in the same network
        Assert.DoesNotContain(r.Exposures, e => e.AssetExternalId == "Q2XX-BBBB-0002");
        var z = r.Software.Single(s => s.AssetExternalId == "Q2XX-BBBB-0002");
        Assert.Contains(z.Listeners!, l => l.Process == "appliance web service"); // still recorded as a listener
    }

    [Fact]
    public async Task Rejected_key_and_disabled_api_access_fail_the_test_clearly()
    {
        var h = new FakeHandler();
        h.On(HttpMethod.Get, "/organizations", "{\"errors\":[\"Invalid API key\"]}", HttpStatusCode.Unauthorized);
        var t = await new MerakiMxAdapter(new FakeHttpClientFactory(h)).TestAsync(Creds, CancellationToken.None);
        Assert.False(t.Ok);
        Assert.Contains("rejected the API key", t.Message);
        Assert.DoesNotContain("0123456789abcdef", t.Message);

        var h2 = new FakeHandler();
        h2.On(HttpMethod.Get, "/organizations/999", "{\"errors\":[\"Not found\"]}", HttpStatusCode.NotFound);
        var t2 = await new MerakiMxAdapter(new FakeHttpClientFactory(h2)).TestAsync(new Dictionary<string, string>(Creds) { ["organizationId"] = "999" }, CancellationToken.None);
        Assert.False(t2.Ok);
        Assert.Contains("API access is enabled", t2.Message);

        var (ok, _, _) = Build(throttleOnce: false);
        var t3 = await ok.TestAsync(Creds, CancellationToken.None);
        Assert.True(t3.Ok, t3.Message);
        Assert.Equal("Connected: Example Estates Ltd; 3 appliance(s).", t3.Message);
    }

    [Theory]
    [InlineData("wired-18-211-2", "18.211.2")]
    [InlineData("wired-19-1-4", "19.1.4")]
    [InlineData("wired-18-107-12-1", "18.107.12.1")]
    [InlineData("Not running configured version", null)]
    [InlineData(null, null)]
    public void Firmware_names_become_dotted_versions(string? firmware, string? expected) => Assert.Equal(expected, MerakiMxAdapter.FirmwareVersion(firmware));

    [Fact]
    public void Metadata_is_honest_about_client_vpn()
    {
        var m = new MerakiMxAdapter(new FakeHttpClientFactory(new FakeHandler())).Metadata;
        Assert.Equal("meraki-mx", m.Id);
        Assert.Contains("AnyConnect settings are not in the Dashboard API", m.Description);
        Assert.Contains("read-only", m.MinimumPermission);
        Assert.Equal(CredentialTypes.Password, m.Form.Single(f => f.Key == "apiKey").Type);
    }
}
