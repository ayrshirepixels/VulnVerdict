using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Adapters.Endpoints;
using VulnVerdict.Core.Adapters.Linux;
using VulnVerdict.Core.Adapters.VMware;
using VulnVerdict.Core.Adapters.Windows;
using VulnVerdict.Core.Data;
using VulnVerdict.Tests.Firewalls;

namespace VulnVerdict.Tests;

/// <summary>
/// Adapters reporting what they could not read: a failed command, a failed collector section, one host's 503, a
/// missing software array or a short page is "unknown" (incomplete or partial), never "nothing installed".
/// </summary>
public class PartialReadAdapterTests
{
    private static bool Path(HttpRequestMessage r, string path) => r.RequestUri!.AbsolutePath.Equals(path, StringComparison.OrdinalIgnoreCase);
    private static string Recent => DateTime.UtcNow.AddDays(-1).ToString("O");

    // ------------------------------------------------------------------ Linux over SSH

    private static FakeCli Ubuntu(string packages = "bash\t5.1-6ubuntu1.1\tamd64\t\tinstalled\ncurl\t7.81.0-1ubuntu1.20\tamd64\t\tinstalled\n", int dpkgExit = 0, string dpkgError = "", int dockerExit = 0) => new FakeCli()
        .On("os-release", "ID=ubuntu\nVERSION_ID=\"22.04\"\nNAME=\"Ubuntu\"\nVERSION=\"22.04.4 LTS (Jammy Jellyfish)\"\nPRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\n")
        .On("command -v", "dpkg-query\nss\ndocker\n") // before the tool rules: rules match by substring
        .On("hostname -f", "web01.example.com\n")
        .On("hostname -I", "10.20.0.11\n")
        .On("ip -o", "")
        .On("dpkg-query", packages, dpkgExit, dpkgError)
        .On("ss -tlnp", "")
        .On("docker ps", dockerExit == 0 ? "web\tnginx:1.25.3\n" : "", dockerExit, dockerExit == 0 ? "" : "permission denied while trying to connect to the Docker daemon socket");

    private static Task<CollectResult> CollectLinux(FakeCli cli) =>
        new SshLinuxAdapter(NullLogger<SshLinuxAdapter>.Instance) { SessionFactory = (_, _, _) => Task.FromResult<ISshSession>(cli) }
            .CollectAsync(new Dictionary<string, string> { ["hosts"] = "web01.example.com", ["username"] = "vv", ["password"] = "x", ["acceptAny"] = "true" }, null, null, CancellationToken.None);

    [Fact]
    public async Task Linux_package_listing_that_exits_non_zero_or_comes_back_empty_makes_the_host_incomplete()
    {
        var ok = await CollectLinux(Ubuntu());
        Assert.Empty(ok.IncompleteSoftware);
        Assert.Empty(ok.IncompleteRows);
        Assert.DoesNotContain("2>/dev/null", SshLinuxAdapter.DpkgCommand); // stderr is captured, not discarded

        // a locked database: half the list came out before dpkg-query gave up
        var failed = await CollectLinux(Ubuntu("bash\t5.1-6ubuntu1.1\tamd64\t\tinstalled\n", dpkgExit: 2, dpkgError: "dpkg-query: error: failed to open package info file '/var/lib/dpkg/status' for reading: Permission denied\n"));
        Assert.Equal(new[] { "web01.example.com" }, failed.IncompleteSoftware);
        Assert.Contains(failed.Software, s => s.Product == "bash");                // what was read is still recorded
        Assert.Contains(failed.Warnings, w => w.Contains("dpkg failed (exit 2: dpkg-query: error: failed to open package info file") && w.Contains("nothing is marked removed"));

        var empty = await CollectLinux(Ubuntu(packages: ""));
        Assert.Equal(new[] { "web01.example.com" }, empty.IncompleteSoftware);
        Assert.Contains(empty.Warnings, w => w.Contains("dpkg returned no packages"));
    }

    [Fact]
    public async Task Linux_unreadable_docker_keeps_container_rows_without_freezing_the_package_list()
    {
        var r = await CollectLinux(Ubuntu(dockerExit: 1));
        Assert.Empty(r.IncompleteSoftware);
        Assert.Equal(new[] { "container:" }, r.IncompleteRows["web01.example.com"]);
        Assert.DoesNotContain(r.Software, s => s.Vendor == "container");
        Assert.Contains(r.Warnings, w => w.Contains("containers collected earlier are kept"));
    }

    // ------------------------------------------------------------------ Windows collector

    private static JsonObject WindowsFixture()
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 8 && dir is not null; i++)
        {
            var candidate = System.IO.Path.Combine(dir, "Fixtures", "windows-collector-sample.json");
            if (File.Exists(candidate)) return JsonNode.Parse(File.ReadAllText(candidate))!.AsObject();
            dir = System.IO.Path.GetDirectoryName(dir);
        }
        throw new FileNotFoundException("windows-collector-sample.json");
    }

    private static JsonElement Element(JsonNode node) => JsonDocument.Parse(node.ToJsonString()).RootElement;

    [Fact]
    public void Windows_failed_section_marks_the_host_incomplete_and_an_unread_uninstall_key_keeps_only_its_row()
    {
        var plain = new CollectResult();
        WindowsCollectorMapper.Map("srv1", Element(WindowsFixture()), plain);
        Assert.Empty(plain.IncompleteSoftware);                                    // a document from before the field existed is complete

        var doc = WindowsFixture();
        doc["failedSections"] = new JsonArray("features", "sql");
        var failed = new CollectResult();
        WindowsCollectorMapper.Map("srv1", Element(doc), failed);
        Assert.Equal(new[] { "srv1" }, failed.IncompleteSoftware);
        Assert.Contains(failed.Warnings, w => w == "srv1: the collector could not read features, sql; nothing is marked removed from this host this run");

        var keyed = WindowsFixture();
        keyed["softwareUnread"] = new JsonArray("x64:{BAD-KEY}");
        var kept = new CollectResult();
        WindowsCollectorMapper.Map("srv1", Element(keyed), kept);
        Assert.Empty(kept.IncompleteSoftware);
        Assert.Equal(new[] { "app:x64:{BAD-KEY}" }, kept.IncompleteRows["srv1"]);

        var noList = WindowsFixture();
        noList["software"] = null;
        var unknown = new CollectResult();
        WindowsCollectorMapper.Map("srv1", Element(noList), unknown);
        Assert.Contains("srv1", unknown.IncompleteSoftware);

        // the collector names the sections it could not read, in the one JSON object it prints
        Assert.Contains("$o.failedSections = @($fs | Select-Object -Unique)", WindowsCollectorScript.Source);
        Assert.Contains("$fs += 'software'", WindowsCollectorScript.Compact);
        Assert.DoesNotContain("catch { }\n}\n$o.software", WindowsCollectorScript.Compact);
    }

    [Fact]
    public void Windows_document_that_fails_to_map_leaves_no_partial_row_set_behind()
    {
        var doc = WindowsFixture();
        doc["rdpEnabled"] = 1.5; // not a boolean: the mapper throws after the Uninstall rows were built
        var result = new CollectResult();
        Assert.ThrowsAny<Exception>(() => WindowsCollectorMapper.Map("srv1", Element(doc), result));
        Assert.Empty(result.Assets);
        Assert.Empty(result.Software);
        Assert.Empty(result.Warnings);
    }

    // ------------------------------------------------------------------ vCenter

    private sealed class StatusVCenter : IVCenterSession
    {
        private readonly Dictionary<string, (string? Json, int Status)> _routes = new();
        public List<string> Paths { get; } = new();
        public StatusVCenter Route(string path, string json) { _routes[path] = (json, 200); return this; }
        public StatusVCenter Fail(string path, int status) { _routes[path] = (null, status); return this; }
        public async Task<JsonDocument?> GetAsync(string path, CancellationToken ct) => (await GetWithStatusAsync(path, ct)).Doc;
        public Task<(JsonDocument? Doc, int Status)> GetWithStatusAsync(string path, CancellationToken ct)
        {
            lock (Paths) Paths.Add(path);
            var (json, status) = _routes.TryGetValue(path, out var r) ? r : (null, 404);
            return Task.FromResult<(JsonDocument? Doc, int Status)>((json is null ? null : JsonDocument.Parse(json), status));
        }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private const string ThreeHosts = "[{\"host\":\"host-1\",\"name\":\"esxi01.example.com\",\"connection_state\":\"CONNECTED\"},"
        + "{\"host\":\"host-2\",\"name\":\"esxi02.example.com\",\"connection_state\":\"DISCONNECTED\"},"
        + "{\"host\":\"host-3\",\"name\":\"esxi03.example.com\",\"connection_state\":\"CONNECTED\"}]";

    [Fact]
    public async Task Vcenter_one_host_detail_failure_does_not_switch_off_esxi_versions_for_the_rest()
    {
        var fake = new StatusVCenter()
            .Route("/api/appliance/system/version", "{\"version\":\"8.0.2.00100\",\"build\":\"22617221\"}")
            .Route("/api/vcenter/host", ThreeHosts)
            .Fail("/api/vcenter/host/host-1", 503)                      // the first host asked: this used to disable the lot
            .Fail("/rest/vcenter/host/host-1", 503)
            .Route("/api/vcenter/host/host-2", "{\"version\":\"8.0.2\"}")
            .Route("/api/vcenter/host/host-3", "{\"version\":\"8.0.3\"}")
            .Route("/api/vcenter/vm", "[]");
        var r = await VCenterAdapter.CollectFromAsync(fake, "vc.example.com", 4, null, CancellationToken.None);

        Assert.Equal(new[] { "host-2", "host-3" }, r.Software.Where(s => s.Product == "ESXi").Select(s => s.AssetExternalId).OrderBy(x => x).ToArray());
        Assert.Equal(new[] { "host-1" }, r.IncompleteSoftware);
        Assert.Contains(r.Warnings, w => w.StartsWith("ESXi version not read for 1 of 3 hosts (esxi01.example.com: HTTP 503)"));
        Assert.DoesNotContain(r.Warnings, w => w.Contains("not exposed"));
        Assert.False(r.Partial);
    }

    [Fact]
    public async Task Vcenter_vm_list_over_the_limit_is_read_host_by_host_and_an_unreadable_list_is_partial()
    {
        StatusVCenter Base() => new StatusVCenter()
            .Route("/api/appliance/system/version", "{\"version\":\"8.0.2.00100\",\"build\":\"22617221\"}")
            .Route("/api/vcenter/host", ThreeHosts)
            .Fail("/api/vcenter/vm", 400);

        var paged = Base()
            .Route("/api/vcenter/vm?hosts=host-1", "[{\"vm\":\"vm-1\",\"name\":\"web01\",\"power_state\":\"POWERED_ON\"}]")
            .Route("/api/vcenter/vm?hosts=host-2", "[{\"vm\":\"vm-2\",\"name\":\"db01\",\"power_state\":\"POWERED_ON\"}]")
            .Route("/api/vcenter/vm?hosts=host-3", "[]");
        var r = await VCenterAdapter.CollectFromAsync(paged, "vc.example.com", 4, null, CancellationToken.None);
        Assert.Equal(new[] { "vm-1", "vm-2" }, r.Assets.Where(a => a.Kind == AssetKind.VirtualMachine).Select(a => a.ExternalId).OrderBy(x => x).ToArray());
        Assert.False(r.Partial);
        Assert.Contains(r.Warnings, w => w.Contains("read host by host: 2 VMs"));

        // one host's VMs cannot be listed either: the VM set is partial, so nothing ages out
        var oneRefused = Base()
            .Route("/api/vcenter/vm?hosts=host-1", "[{\"vm\":\"vm-1\",\"name\":\"web01\",\"power_state\":\"POWERED_ON\"}]")
            .Fail("/api/vcenter/vm?hosts=host-2", 503)
            .Route("/api/vcenter/vm?hosts=host-3", "[]");
        var r2 = await VCenterAdapter.CollectFromAsync(oneRefused, "vc.example.com", 4, null, CancellationToken.None);
        Assert.True(r2.Partial);
        Assert.Contains(r2.Warnings, w => w.StartsWith("VMs could not be listed for 1 of 3 hosts (esxi02.example.com: HTTP 503)"));

        var unreadable = new StatusVCenter().Route("/api/vcenter/host", "[]").Fail("/api/vcenter/vm", 503);
        var r3 = await VCenterAdapter.CollectFromAsync(unreadable, "vc.example.com", 4, null, CancellationToken.None);
        Assert.True(r3.Partial);
        Assert.Contains(r3.Warnings, w => w.StartsWith("VM list not readable (/api/vcenter/vm, HTTP 503)"));
    }

    // ------------------------------------------------------------------ endpoint managers: missing arrays and paging

    private const string Token = "{\"access_token\":\"t\",\"expires_in\":3600}";

    private static string JamfComputer(int id, string? applications) =>
        "{\"id\":\"" + id + "\",\"general\":{\"name\":\"MAC" + id + "\",\"lastContactTime\":\"" + Recent + "\"},\"operatingSystem\":{\"name\":\"macOS\",\"version\":\"14.6.1\"}"
        + (applications is null ? "" : ",\"applications\":" + applications) + "}";

    [Fact]
    public async Task Jamf_pages_to_the_total_past_a_short_page_and_a_missing_application_list_is_incomplete()
    {
        var h = new FakeHandler()
            .On(HttpMethod.Post, JamfProAdapter.TokenPath, Token)
            // the server caps the page at one row although a hundred were asked for
            .On(r => Path(r, "/api/v1/computers-inventory") && r.RequestUri!.Query.Contains("page=0"), (_, _) => FakeHandler.Json("{\"totalCount\":3,\"results\":["
                + JamfComputer(1, "[{\"name\":\"Firefox.app\",\"version\":\"128.0\",\"bundleId\":\"org.mozilla.firefox\"}]") + "]}"))
            .On(r => Path(r, "/api/v1/computers-inventory") && r.RequestUri!.Query.Contains("page=1"), (_, _) => FakeHandler.Json("{\"totalCount\":3,\"results\":[" + JamfComputer(2, null) + "]}"))
            .On(r => Path(r, "/api/v1/computers-inventory") && r.RequestUri!.Query.Contains("page=2"), (_, _) => FakeHandler.Json("{\"totalCount\":3,\"results\":[" + JamfComputer(3, "[]") + "]}"));
        var creds = new Dictionary<string, string> { ["url"] = "https://jamf.example.test", ["clientId"] = "c", ["clientSecret"] = "s", ["includeMobile"] = "false" };
        var r = await new JamfProAdapter(new FakeHttpClientFactory(h)).CollectAsync(creds, null, null, CancellationToken.None);

        Assert.Equal(3, r.Assets.Count);
        Assert.Equal(new[] { "computer:2" }, r.IncompleteSoftware);                // no applications section: unknown
        Assert.DoesNotContain("computer:3", r.IncompleteSoftware);                 // an explicitly empty list is an answer
        Assert.False(r.Partial);
        Assert.Equal(3, h.Calls.Count(c => c.Path == "/api/v1/computers-inventory"));

        // the listing stops short of the stated total, and a page cap is hit: both are partial runs
        var shortOfTotal = new FakeHandler()
            .On(HttpMethod.Post, JamfProAdapter.TokenPath, Token)
            .On(r => Path(r, "/api/v1/computers-inventory") && r.RequestUri!.Query.Contains("page=0"), (_, _) => FakeHandler.Json("{\"totalCount\":3,\"results\":[" + JamfComputer(1, "[]") + "]}"))
            .On(r => Path(r, "/api/v1/computers-inventory"), (_, _) => FakeHandler.Json("{\"totalCount\":3,\"results\":[]}"));
        var r2 = await new JamfProAdapter(new FakeHttpClientFactory(shortOfTotal)).CollectAsync(creds, null, null, CancellationToken.None);
        Assert.True(r2.Partial);
        Assert.Contains(r2.Warnings, w => w.StartsWith("The computers listing ended at 1 of 3"));

        var r3 = await new JamfProAdapter(new FakeHttpClientFactory(h)) { MaxPages = 2 }.CollectAsync(creds, null, null, CancellationToken.None);
        Assert.True(r3.Partial);
        Assert.Contains(r3.Warnings, w => w.StartsWith("Stopped reading computers after 2 pages"));
    }

    [Fact]
    public async Task Pdq_keeps_paging_after_a_short_page_and_a_missing_software_array_is_incomplete()
    {
        static string Device(string id, string? software) => "{\"id\":\"" + id + "\",\"hostname\":\"" + id.ToUpperInvariant() + "\",\"osName\":\"Windows 11 Pro\",\"osVersion\":\"10.0.22631.4037\",\"lastSeenAt\":\"" + Recent + "\""
            + (software is null ? "" : ",\"software\":" + software) + "}";
        var h = new FakeHandler()
            .On(r => r.RequestUri!.Query.EndsWith("&page=1"), (_, _) => FakeHandler.Json("{\"data\":[" + Device("pc1", "[{\"name\":\"7-Zip\",\"publisher\":\"Igor Pavlov\",\"version\":\"24.08\"}]") + "]}"))
            .On(r => r.RequestUri!.Query.EndsWith("&page=2"), (_, _) => FakeHandler.Json("{\"data\":[" + Device("pc2", null) + "," + Device("pc3", "[]") + "]}"))
            .On(r => r.RequestUri!.Query.EndsWith("&page=3"), (_, _) => FakeHandler.Json("{\"data\":[]}"));
        var creds = new Dictionary<string, string> { ["apiKey"] = "k" };
        var r = await new PdqConnectAdapter(new FakeHttpClientFactory(h)).CollectAsync(creds, null, null, CancellationToken.None);

        Assert.Equal(new[] { "pc1", "pc2", "pc3" }, r.Assets.Select(a => a.ExternalId).ToArray());
        Assert.Equal(new[] { "pc2" }, r.IncompleteSoftware);
        Assert.False(r.Partial);

        var capped = await new PdqConnectAdapter(new FakeHttpClientFactory(h)) { MaxPages = 1 }.CollectAsync(creds, null, null, CancellationToken.None);
        Assert.True(capped.Partial);
        Assert.Single(capped.Assets);
    }

    [Fact]
    public async Task Lansweeper_missing_softwares_is_incomplete_and_a_listing_short_of_its_total_is_partial()
    {
        static string Page(int total, string? next, params string[] items) =>
            "{\"data\":{\"site\":{\"assetResources\":{\"total\":" + total + ",\"pagination\":{\"limit\":100,\"current\":\"c\",\"next\":" + (next is null ? "null" : "\"" + next + "\"") + "},\"items\":[" + string.Join(",", items) + "]}}}}";
        static string Asset(string key, string? softwares) => "{\"key\":\"" + key + "\",\"assetBasicInfo\":{\"name\":\"" + key.ToUpperInvariant() + "\",\"type\":\"Windows\",\"lastSeen\":\"" + Recent + "\"},"
            + "\"operatingSystem\":{\"caption\":\"Microsoft Windows 11 Pro\",\"version\":\"10.0.22631\",\"buildNumber\":\"22631\"}" + (softwares is null ? "" : ",\"softwares\":" + softwares) + "}";
        var creds = new Dictionary<string, string> { ["siteId"] = "site-1", ["apiToken"] = "t" };

        var h = new FakeHandler().On(_ => true, (_, body) => FakeHandler.Json(body!.Contains("\"cursor\":\"n1\"")
            ? Page(2, null, Asset("pc2", null))
            : Page(2, "n1", Asset("pc1", "[{\"name\":\"7-Zip\",\"version\":\"24.08\",\"publisher\":\"Igor Pavlov\"}]"))));
        var r = await new LansweeperAdapter(new FakeHttpClientFactory(h)).CollectAsync(creds, null, null, CancellationToken.None);
        Assert.Equal(2, r.Assets.Count);
        Assert.Equal(new[] { "pc2" }, r.IncompleteSoftware);
        Assert.False(r.Partial);

        // three assets promised, one delivered and no cursor to carry on with
        var cut = new FakeHandler().On(_ => true, (_, _) => FakeHandler.Json(Page(3, null, Asset("pc1", "[]"))));
        var r2 = await new LansweeperAdapter(new FakeHttpClientFactory(cut)).CollectAsync(creds, null, null, CancellationToken.None);
        Assert.True(r2.Partial);
        Assert.Contains(r2.Warnings, w => w.StartsWith("The asset listing ended at 1 of 3"));
    }

    [Fact]
    public async Task Ncentral_follows_total_pages_past_a_short_page_and_kandji_pages_until_an_empty_page()
    {
        static string NcDevice(int id) => "{\"deviceId\":" + id + ",\"longName\":\"SRV" + id + "\",\"deviceClass\":\"Servers - Windows\",\"supportedOs\":\"Microsoft Windows Server 2022 Standard\"}";
        var nc = new FakeHandler()
            .On(HttpMethod.Post, NCentralAdapter.AuthPath, "{\"tokens\":{\"access\":{\"token\":\"t\",\"expirySeconds\":3600}}}")
            // one row on a page of five hundred, and two pages promised: the short page must not end the listing
            .On(r => Path(r, "/api/devices") && r.RequestUri!.Query.Contains("pageNumber=1"), (_, _) => FakeHandler.Json("{\"data\":[" + NcDevice(1) + "],\"totalPages\":2}"))
            .On(r => Path(r, "/api/devices") && r.RequestUri!.Query.Contains("pageNumber=2"), (_, _) => FakeHandler.Json("{\"data\":[" + NcDevice(2) + "],\"totalPages\":2}"));
        var r = await new NCentralAdapter(new FakeHttpClientFactory(nc)).CollectAsync(new Dictionary<string, string> { ["host"] = "nc.example.test", ["apiToken"] = "jwt" }, null, null, CancellationToken.None);
        Assert.Equal(new[] { "1", "2" }, r.Assets.Select(a => a.ExternalId).ToArray());
        Assert.False(r.Partial);
        Assert.Equal(2, nc.Calls.Count(c => c.Path == "/api/devices"));

        static string KDevice(string id) => "{\"device_id\":\"" + id + "\",\"device_name\":\"" + id + "\",\"platform\":\"Mac\",\"os_version\":\"14.6.1\",\"last_check_in\":\"" + Recent + "\"}";
        var k = new FakeHandler()
            .On(r => Path(r, "/api/v1/devices") && r.RequestUri!.Query.EndsWith("offset=0"), (_, _) => FakeHandler.Json("[" + KDevice("k1") + "]"))
            .On(r => Path(r, "/api/v1/devices") && r.RequestUri!.Query.EndsWith("offset=1"), (_, _) => FakeHandler.Json("[" + KDevice("k2") + "]"))
            .On(r => Path(r, "/api/v1/devices"), (_, _) => FakeHandler.Json("[]"));
        var kr = await new KandjiAdapter(new FakeHttpClientFactory(k)).CollectAsync(new Dictionary<string, string> { ["apiUrl"] = "https://acme.api.kandji.io", ["apiToken"] = "t", ["includeApps"] = "false" }, null, null, CancellationToken.None);
        Assert.Equal(new[] { "k1", "k2" }, kr.Assets.Select(a => a.ExternalId).ToArray());
        Assert.False(kr.Partial);
    }

    // ------------------------------------------------------------------ the contract itself

    [Fact]
    public void Exposure_not_read_is_said_first_once_and_marks_the_run_partial()
    {
        var r = new CollectResult();
        r.Warnings.Add("something informational");
        Assert.False(r.Partial);                                                   // warnings alone never make a run partial
        r.ExposureNotRead("virtual IPs");
        r.ExposureNotRead("address objects");
        Assert.True(r.Partial);
        Assert.True(r.ExposureUnknown);
        Assert.Equal(2, r.Warnings.Count);
        Assert.Equal("Exposure could not be read (virtual IPs): newly published servers will not be marked internet-facing until it can be", r.Warnings[0]);
    }
}
