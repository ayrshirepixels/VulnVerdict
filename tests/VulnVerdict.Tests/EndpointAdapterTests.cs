using System.Net;
using VulnVerdict.Core.Adapters.Endpoints;

namespace VulnVerdict.Tests;

/// <summary>Endpoint-management adapters against a fake HTTP layer: partial reads must never look like uninstalls or resolved findings.</summary>
public class EndpointAdapterTests
{
    private const string Token = "{\"access_token\":\"t\",\"expires_in\":3600}";
    private static readonly Dictionary<string, string> EntraCreds = new() { ["tenantId"] = "t", ["clientId"] = "c", ["clientSecret"] = "s" };
    private static string Recent => DateTime.UtcNow.AddDays(-1).ToString("O");

    private static bool Path(HttpRequestMessage r, string path) => r.RequestUri!.AbsolutePath.Equals(path, StringComparison.OrdinalIgnoreCase);

    [Fact]
    public async Task Intune_404_for_one_device_does_not_stop_app_collection_for_the_rest()
    {
        var h = new FakeHandler()
            .On(HttpMethod.Post, "oauth2", Token)
            .On(r => Path(r, "/v1.0/deviceManagement/managedDevices"), (_, _) => FakeHandler.Json("{\"value\":["
                + "{\"id\":\"d1\",\"deviceName\":\"PC1\",\"operatingSystem\":\"Windows\",\"osVersion\":\"10.0.22631.4037\",\"lastSyncDateTime\":\"" + Recent + "\"},"
                + "{\"id\":\"d2\",\"deviceName\":\"PC2\",\"operatingSystem\":\"Windows\",\"osVersion\":\"10.0.22631.4037\",\"lastSyncDateTime\":\"" + Recent + "\"},"
                + "{\"id\":\"d3\",\"deviceName\":\"PC3\",\"operatingSystem\":\"Windows\",\"osVersion\":\"10.0.22631.4037\",\"lastSyncDateTime\":\"" + Recent + "\"}]}"))
            .On(HttpMethod.Get, "/managedDevices/d2?", "{\"id\":\"d2\",\"detectedApps\":[{\"displayName\":\"7-Zip\",\"publisher\":\"Igor Pavlov\",\"version\":\"23.01\"}]}")
            .On(HttpMethod.Get, "/managedDevices/d3?", "{\"id\":\"d3\",\"detectedApps\":[{\"displayName\":\"7-Zip\",\"publisher\":\"Igor Pavlov\",\"version\":\"24.08\"}]}");
        // d1 is unrouted: 404
        var r = await new IntuneAdapter(new FakeHttpClientFactory(h)) { Delay = (_, _) => Task.CompletedTask }.CollectAsync(EntraCreds, null, null, CancellationToken.None);
        Assert.Equal(3, r.Assets.Count);
        Assert.Contains(r.Software, s => s.AssetExternalId == "d2" && s.Version == "23.01");
        Assert.Contains(r.Software, s => s.AssetExternalId == "d3" && s.Version == "24.08");
        Assert.Equal(new[] { "d1" }, r.IncompleteSoftware);
    }

    [Fact]
    public async Task Intune_403_stops_asking_for_apps_and_marks_every_later_device_incomplete()
    {
        var h = new FakeHandler()
            .On(HttpMethod.Post, "oauth2", Token)
            .On(r => Path(r, "/v1.0/deviceManagement/managedDevices"), (_, _) => FakeHandler.Json("{\"value\":["
                + "{\"id\":\"d1\",\"deviceName\":\"PC1\",\"operatingSystem\":\"Windows\",\"osVersion\":\"10.0.22631.4037\",\"lastSyncDateTime\":\"" + Recent + "\"},"
                + "{\"id\":\"d2\",\"deviceName\":\"PC2\",\"operatingSystem\":\"Windows\",\"osVersion\":\"10.0.22631.4037\",\"lastSyncDateTime\":\"" + Recent + "\"}]}"))
            .On(HttpMethod.Get, "/managedDevices/", "{}", HttpStatusCode.Forbidden);
        var r = await new IntuneAdapter(new FakeHttpClientFactory(h)).CollectAsync(EntraCreds, null, null, CancellationToken.None);
        Assert.Equal(2, r.IncompleteSoftware.Count);
        Assert.Single(h.Calls, c => c.Path.StartsWith("/beta/", StringComparison.Ordinal));
    }

    private static FakeHandler Defender(HttpStatusCode vulnStatus, string software)
    {
        return new FakeHandler()
            .On(HttpMethod.Post, "oauth2", Token)
            .On(r => Path(r, "/api/machines/SoftwareInventoryByMachine"), (_, _) => FakeHandler.Json(software))
            .On(r => Path(r, "/api/machines/SoftwareVulnerabilitiesByMachine"), (_, _) => FakeHandler.Json(
                "{\"value\":[{\"deviceId\":\"m1\",\"cveId\":\"CVE-2026-1234\",\"softwareVendor\":\"google\",\"softwareName\":\"chrome\",\"softwareVersion\":\"128.0\"}]}", vulnStatus))
            .On(r => Path(r, "/api/machines"), (_, _) => FakeHandler.Json("{\"value\":["
                + "{\"id\":\"m1\",\"computerDnsName\":\"pc1.corp.local\",\"osPlatform\":\"Windows11\",\"osBuild\":22631,\"lastSeen\":\"" + Recent + "\"},"
                + "{\"id\":\"m2\",\"computerDnsName\":\"pc2.corp.local\",\"osPlatform\":\"Windows11\",\"osBuild\":22631,\"lastSeen\":\"" + Recent + "\"}]}"));
    }

    private const string OneMachineSoftware = "{\"value\":[{\"deviceId\":\"m1\",\"softwareVendor\":\"google\",\"softwareName\":\"chrome\",\"softwareVersion\":\"128.0\"}]}";

    [Fact]
    public async Task Defender_findings_refused_keeps_earlier_findings_and_a_machine_without_rows_is_incomplete()
    {
        var r = await new DefenderEndpointAdapter(new FakeHttpClientFactory(Defender(HttpStatusCode.Forbidden, OneMachineSoftware))).CollectAsync(EntraCreds, null, null, CancellationToken.None);
        Assert.Equal(2, r.Assets.Count);
        Assert.True(r.FindingsIncomplete);
        Assert.Empty(r.Findings);
        Assert.Equal(new[] { "m2" }, r.IncompleteSoftware);

        var ok = await new DefenderEndpointAdapter(new FakeHttpClientFactory(Defender(HttpStatusCode.OK, OneMachineSoftware))).CollectAsync(EntraCreds, null, null, CancellationToken.None);
        Assert.False(ok.FindingsIncomplete);
        Assert.Single(ok.Findings);
    }

    [Fact]
    public async Task Defender_row_cap_is_reported_and_blocks_removals()
    {
        var two = "{\"value\":[{\"deviceId\":\"m1\",\"softwareVendor\":\"google\",\"softwareName\":\"chrome\",\"softwareVersion\":\"128.0\"},"
                + "{\"deviceId\":\"m2\",\"softwareVendor\":\"google\",\"softwareName\":\"chrome\",\"softwareVersion\":\"128.0\"}],"
                + "\"@odata.nextLink\":\"https://api.security.microsoft.com/api/machines/SoftwareInventoryByMachine?page=2\"}";
        var r = await new DefenderEndpointAdapter(new FakeHttpClientFactory(Defender(HttpStatusCode.OK, two))) { MaxRows = 2 }.CollectAsync(EntraCreds, null, null, CancellationToken.None);
        Assert.Contains(r.Warnings, w => w.StartsWith("The software inventory stopped at"));
        Assert.Equal(2, r.IncompleteSoftware.Count);
    }

    [Fact]
    public async Task NinjaOne_pages_past_a_short_page_and_os_only_devices_are_incomplete()
    {
        var h = new FakeHandler()
            .On(HttpMethod.Post, "/ws/oauth/token", Token)
            .On(r => r.RequestUri!.Query.Contains("after=2"), (_, _) => FakeHandler.Json("[{\"id\":3,\"systemName\":\"PC3\",\"nodeClass\":\"WINDOWS_WORKSTATION\",\"os\":{\"name\":\"Windows 11 Pro\"}}]"))
            .On(r => r.RequestUri!.Query.Contains("after=3"), (_, _) => FakeHandler.Json("[]"))
            .On(HttpMethod.Get, "/v2/devices-detailed", "[{\"id\":1,\"systemName\":\"PC1\",\"nodeClass\":\"WINDOWS_WORKSTATION\",\"os\":{\"name\":\"Windows 11 Pro\"}},"
                + "{\"id\":2,\"systemName\":\"PC2\",\"nodeClass\":\"WINDOWS_WORKSTATION\",\"os\":{\"name\":\"Windows 11 Pro\"}}]")
            .On(r => r.RequestUri!.Query.Contains("cursor=c1"), (_, _) => FakeHandler.Json("{\"cursor\":{\"name\":\"c2\"},\"results\":[{\"deviceId\":2,\"name\":\"7-Zip\",\"publisher\":\"Igor Pavlov\",\"version\":\"23.01\"}]}"))
            .On(r => r.RequestUri!.Query.Contains("cursor=c2"), (_, _) => FakeHandler.Json("{\"cursor\":{\"name\":\"c2\"},\"results\":[]}"))
            .On(HttpMethod.Get, "/v2/queries/software", "{\"cursor\":{\"name\":\"c1\"},\"results\":[{\"deviceId\":1,\"name\":\"7-Zip\",\"publisher\":\"Igor Pavlov\",\"version\":\"23.01\"}]}");
        var creds = new Dictionary<string, string> { ["clientId"] = "c", ["clientSecret"] = "s" };
        var r = await new NinjaOneAdapter(new FakeHttpClientFactory(h)).CollectAsync(creds, null, null, CancellationToken.None);
        Assert.Equal(3, r.Assets.Count);
        Assert.Contains(r.Software, s => s.AssetExternalId == "2" && s.Product.Contains("7-Zip"));
        Assert.Equal(new[] { "3" }, r.IncompleteSoftware);
    }
}
