using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;
using static VulnVerdict.Core.Adapters.Fortinet.FortinetJson;

namespace VulnVerdict.Core.Adapters.Firewalls;

/// <summary>
/// Cisco Meraki MX (and Z-series teleworker) appliances over the Meraki Dashboard API v1 with an API key. Firmware
/// and addresses from the organisation's device inventory and statuses; exposure from each appliance network's port
/// forwarding, 1:1 and 1:many NAT rules, and whether the appliance's own web service is open on the WAN.
/// Pagination follows the Link header; 429 answers are retried after Retry-After.
///
/// Read-only: GET only. A read-only organisation administrator's API key is enough.
/// </summary>
public sealed partial class MerakiMxAdapter : IInventoryAdapter
{
    public const string DefaultBase = "https://api.meraki.com/api/v1";
    public const int PageSize = 1000;

    private readonly IHttpClientFactory _http;
    private readonly ILogger _log;

    public MerakiMxAdapter(IHttpClientFactory http, ILogger<MerakiMxAdapter>? log = null)
    {
        _http = http; _log = log ?? NullLogger<MerakiMxAdapter>.Instance;
    }

    /// <summary>Test seam: how the adapter waits after a 429.</summary>
    public Func<TimeSpan, CancellationToken, Task>? Delay { get; set; }

    public AdapterMetadata Metadata { get; } = new(
        Id: "meraki-mx",
        DisplayName: "Cisco Meraki MX (firmware, NAT exposure)",
        Vendor: "Cisco Meraki",
        Description: "Reads MX and Z-series appliances with their firmware, WAN and LAN addresses from the Meraki Dashboard API, and port forwarding, 1:1 NAT, 1:many NAT and appliance web-service rules per network for exposure. Client VPN and AnyConnect settings are not in the Dashboard API, so a VPN listening on the WAN is not detected. Read-only.",
        Kinds: new[] { AssetKind.Firewall },
        Form: new[]
        {
            new CredentialField("apiKey", "Dashboard API key", CredentialTypes.Password, "API key of a dashboard user who is a read-only organisation administrator. Generate it under My profile > API access; API access must be enabled for the organisation (Organization > Settings)."),
            new CredentialField("organizationId", "Organisation ID", CredentialTypes.Text, "Optional. Blank reads every organisation the key can see.", Required: false),
            new CredentialField("baseUrl", "API base URL", CredentialTypes.Text, "Only for the China or other regional dashboards.", Required: false, Default: DefaultBase),
        },
        MinimumPermission: "the API key of a read-only organisation administrator, with API access enabled for the organisation",
        DocsUrl: "https://developer.cisco.com/meraki/api-v1/authorization/",
        DefaultIntervalMinutes: 240);

    // ------------------------------------------------------------------ contract

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            var api = Api(credentials);
            var orgs = await OrganisationsAsync(api, credentials, ct);
            var count = 0;
            foreach (var (id, _) in orgs) count += (await PagesAsync(api, "organizations/" + id + "/devices?productTypes[]=appliance&perPage=" + PageSize, ct)).Count;
            return new TestResult(true, "Connected: " + string.Join(", ", orgs.Select(o => o.Name)) + "; " + count + " appliance(s).");
        }
        catch (Exception ex) when (ex is FirewallApiException or HttpRequestException or JsonException or TaskCanceledException or InvalidOperationException)
        {
            return new TestResult(false, ex.Message);
        }
    }

    public async Task<CollectResult> CollectAsync(IReadOnlyDictionary<string, string> credentials, DateTime? since, IProgress<string>? progress, CancellationToken ct)
    {
        var r = new CollectResult { FullSnapshot = true };
        var api = Api(credentials);
        foreach (var (orgId, orgName) in await OrganisationsAsync(api, credentials, ct))
        {
            progress?.Report("Reading appliances in " + orgName);
            var devices = await PagesAsync(api, "organizations/" + orgId + "/devices?productTypes[]=appliance&perPage=" + PageSize, ct);
            var statuses = (await PagesAsync(api, "organizations/" + orgId + "/devices/statuses?productTypes[]=appliance&perPage=" + PageSize, ct))
                .Where(s => Str(s, "serial") is not null).GroupBy(s => Str(s, "serial")!).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

            var networkExposure = new Dictionary<string, DeviceExposure>(StringComparer.Ordinal);
            foreach (var net in devices.Select(d => Str(d, "networkId")).Where(n => n is not null).Distinct())
            {
                progress?.Report("Reading NAT rules for network " + net);
                var device = networkExposure[net!] = new DeviceExposure();
                foreach (var svc in await ListAsync(api, "networks/" + net + "/appliance/firewall/firewalledServices", null, r, ct))
                {
                    var name = Str(svc, "service") ?? "";
                    if (!name.Equals("web", StringComparison.OrdinalIgnoreCase)) continue;
                    var access = (Str(svc, "access") ?? "blocked").ToLowerInvariant();
                    if (access == "blocked") continue;
                    var allowed = Names(svc, "allowedIps");
                    device.Add(443, "tcp", "WAN", "appliance web service", access == "unrestricted",
                        "appliance web service on the WAN is " + access + (allowed.Count > 0 ? " (allowed: " + string.Join(", ", allowed) + ")" : ""));
                }
                r.Exposures.AddRange(PortForwardExposures(await ListAsync(api, "networks/" + net + "/appliance/firewall/portForwardingRules", "rules", r, ct)));
                r.Exposures.AddRange(OneToOneExposures(await ListAsync(api, "networks/" + net + "/appliance/firewall/oneToOneNatRules", "rules", r, ct)));
                r.Exposures.AddRange(OneToManyExposures(await ListAsync(api, "networks/" + net + "/appliance/firewall/oneToManyNatRules", "rules", r, ct)));
            }

            foreach (var d in devices)
            {
                var serial = Str(d, "serial");
                if (serial is null) continue;
                var st = statuses.GetValueOrDefault(serial);
                var name = Str(d, "name") ?? Str(d, "mac") ?? serial;
                var version = FirmwareVersion(Str(d, "firmware"));
                var ips = new[] { Str(d, "lanIp"), Str(st, "lanIp"), Str(st, "wan1Ip"), Str(st, "wan2Ip"), Str(st, "publicIp") };
                var device = Str(d, "networkId") is { } net && networkExposure.TryGetValue(net, out var ne) ? ne : new DeviceExposure();
                r.Assets.Add(EdgeRecords.Firewall(serial, name, ips, new[] { Str(d, "mac") }, CnaNames.Cisco, CnaNames.MerakiMx, version));
                r.Software.AddRange(EdgeRecords.Firmware(serial, CnaNames.Cisco, CnaNames.MerakiMx, version ?? "", "meraki-mx", listeners: device.Listeners, edition: Str(d, "model")));
                if (device.Record(serial) is { } self) r.Exposures.Add(self);
                if (version is null) r.Warnings.Add(name + ": firmware '" + (Str(d, "firmware") ?? "") + "' has no version number");
            }
        }
        _log.LogInformation("Meraki: {Assets} appliances, {Exposures} exposure records", r.Assets.Count, r.Exposures.Count);
        return r;
    }

    // ------------------------------------------------------------------ mapping

    [GeneratedRegex(@"(\d+)-(\d+)(?:-(\d+))?(?:-(\d+))?")] private static partial Regex FirmwareRx();

    /// <summary>"wired-18-211-2" to "18.211.2"; "wired-19-1-4-1" to "19.1.4.1"; null when there is no version in it.</summary>
    public static string? FirmwareVersion(string? firmware)
    {
        if (string.IsNullOrWhiteSpace(firmware)) return null;
        var m = FirmwareRx().Match(firmware);
        if (!m.Success) return null;
        return string.Join(".", Enumerable.Range(1, 4).Where(i => m.Groups[i].Success).Select(i => m.Groups[i].Value));
    }

    private static string Allowed(JsonElement e) { var a = Names(e, "allowedIps"); return a.Count == 0 || a.Any(x => x.Equals("any", StringComparison.OrdinalIgnoreCase)) ? "any" : string.Join(", ", a); }

    public static IEnumerable<ExposureRecord> PortForwardExposures(IEnumerable<JsonElement> rules)
    {
        foreach (var p in rules)
        {
            var lan = EdgeRecords.SingleHost(Str(p, "lanIp"));
            if (lan is null) continue;
            yield return new ExposureRecord(Exposure.Internet,
                "port forward " + (Str(p, "name") ?? "(unnamed)") + " " + (Str(p, "protocol") ?? "tcp") + " " + (Str(p, "uplink") ?? "internet") + ":" + (Str(p, "publicPort") ?? "?") + " -> " + lan + ":" + (Str(p, "localPort") ?? "?") + " from " + Allowed(p),
                IpAddress: lan);
        }
    }

    public static IEnumerable<ExposureRecord> OneToOneExposures(IEnumerable<JsonElement> rules)
    {
        foreach (var n in rules)
        {
            var lan = EdgeRecords.SingleHost(Str(n, "lanIp"));
            var inbound = Array(n, "allowedInbound").ToList();
            if (lan is null || inbound.Count == 0) continue; // no allowed inbound: the mapping is outbound only
            var ports = string.Join(", ", inbound.Select(i => (Str(i, "protocol") ?? "any") + " " + string.Join("/", Names(i, "destinationPorts")) + " from " + Allowed(i)));
            yield return new ExposureRecord(Exposure.Internet, "1:1 NAT " + (Str(n, "name") ?? "(unnamed)") + " " + (Str(n, "publicIp") ?? "?") + " -> " + lan + " allows " + ports, IpAddress: lan);
        }
    }

    public static IEnumerable<ExposureRecord> OneToManyExposures(IEnumerable<JsonElement> rules)
    {
        foreach (var n in rules)
            foreach (var p in Array(n, "portRules"))
            {
                var lan = EdgeRecords.SingleHost(Str(p, "localIp"));
                if (lan is null) continue;
                yield return new ExposureRecord(Exposure.Internet,
                    "1:many NAT " + (Str(p, "name") ?? "(unnamed)") + " " + (Str(n, "publicIp") ?? "?") + ":" + (Str(p, "publicPort") ?? "?") + " -> " + lan + ":" + (Str(p, "localPort") ?? "?") + " from " + Allowed(p),
                    IpAddress: lan);
            }
    }

    // ------------------------------------------------------------------ Dashboard API

    private EdgeHttp Api(IReadOnlyDictionary<string, string> c)
    {
        var key = FwCreds.Secret(c, "apiKey").Trim();
        if (key.Length == 0) throw new InvalidOperationException("Dashboard API key is required");
        var baseUrl = FwCreds.Get(c, "baseUrl") is { Length: > 0 } b ? b : DefaultBase;
        if (!baseUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("The API base URL must start with https://");
        var http = new EdgeHttp(_http, true, baseUrl, req => req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", key), Explain);
        if (Delay is not null) http.Delay = Delay;
        return http;
    }

    private static string? Explain(int status) => status switch
    {
        401 => "the dashboard rejected the API key",
        403 => "the API key's administrator has no access to this organisation or network",
        404 => "not found: check the organisation ID, and that API access is enabled for the organisation (Organization > Settings > Dashboard API access)",
        429 => "rate limited by the dashboard; try again later",
        _ => null
    };

    private static async Task<List<(string Id, string Name)>> OrganisationsAsync(EdgeHttp api, IReadOnlyDictionary<string, string> c, CancellationToken ct)
    {
        var wanted = FwCreds.Get(c, "organizationId");
        if (wanted.Length > 0)
        {
            var org = Parse(await api.GetAsync("organizations/" + Uri.EscapeDataString(wanted), ct));
            return new() { (wanted, Str(org, "name") ?? wanted) };
        }
        var list = (await PagesAsync(api, "organizations?perPage=" + PageSize, ct)).Where(o => Str(o, "id") is not null).Select(o => (Str(o, "id")!, Str(o, "name") ?? Str(o, "id")!)).ToList();
        if (list.Count == 0) throw new FirewallApiException("GET organizations", 200, "the API key can see no organisation");
        return list;
    }

    /// <summary>Every page of a list endpoint, following Link: &lt;...&gt;; rel=next until there is none.</summary>
    public static async Task<List<JsonElement>> PagesAsync(EdgeHttp api, string path, CancellationToken ct)
    {
        var all = new List<JsonElement>();
        string? next = path;
        var guard = 0;
        while (next is not null && guard++ < 500)
        {
            var (body, headers) = await api.SendAsync(HttpMethod.Get, next, null, null, ct);
            var root = Parse(body);
            if (root.ValueKind == JsonValueKind.Array) all.AddRange(root.EnumerateArray().Select(e => e.Clone()));
            next = NextLink(headers);
        }
        return all;
    }

    [GeneratedRegex(@"<([^>]+)>\s*;\s*rel=""?next""?", RegexOptions.IgnoreCase)] private static partial Regex NextRx();

    public static string? NextLink(HttpResponseHeaders headers)
    {
        if (!headers.TryGetValues("Link", out var values)) return null;
        foreach (var v in values)
        {
            var m = NextRx().Match(v);
            if (m.Success) return m.Groups[1].Value;
        }
        return null;
    }

    /// <summary>A per-network settings endpoint: {"rules":[...]} or a bare array. Failures other than auth become a warning.</summary>
    private static async Task<List<JsonElement>> ListAsync(EdgeHttp api, string path, string? property, CollectResult r, CancellationToken ct)
    {
        try
        {
            var root = Parse(await api.GetAsync(path, ct));
            var arr = root.ValueKind == JsonValueKind.Array ? root
                : property is not null && root.ValueKind == JsonValueKind.Object && root.TryGetProperty(property, out var p) ? p : default;
            return arr.ValueKind == JsonValueKind.Array ? arr.EnumerateArray().Select(e => e.Clone()).ToList() : new();
        }
        catch (FirewallApiException ex) when (ex.Status is not (401 or 429))
        {
            r.Warnings.Add("Skipped " + path + ": " + ex.Message);
            return new();
        }
    }
}
