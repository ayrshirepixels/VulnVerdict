using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;
using static VulnVerdict.Core.Adapters.Fortinet.FortinetJson;

namespace VulnVerdict.Core.Adapters.Fortinet;

/// <summary>
/// Section 9.2 step 4: FortiGate over the FortiOS REST API v2 with a REST API administrator token
/// (Authorization: Bearer). Firmware of the FortiGate, its managed FortiSwitches and FortiAPs, and exposure for
/// free: SSL-VPN or admin access on a WAN interface marks the FortiGate itself internet-facing; a virtual IP on a
/// WAN interface that an accept policy from a WAN interface points at marks the mapped host internet-facing.
///
/// Read-only: only GET requests; nothing is ever written to the FortiGate.
/// </summary>
public sealed class FortiGateAdapter : IInventoryAdapter
{
    public static class Paths
    {
        public const string Status = "api/v2/monitor/system/status";
        public const string Global = "api/v2/cmdb/system/global";
        public const string Interface = "api/v2/cmdb/system/interface";
        public const string SslVpnSettings = "api/v2/cmdb/vpn.ssl/settings";
        public const string Vip = "api/v2/cmdb/firewall/vip";
        public const string VipGroup = "api/v2/cmdb/firewall/vipgrp";
        public const string Policy = "api/v2/cmdb/firewall/policy";
        public const string Address = "api/v2/cmdb/firewall/address";
        public const string AddressGroup = "api/v2/cmdb/firewall/addrgrp";
        /// <summary>FortiOS 7.2+ path; older releases answer on <see cref="ManagedSwitchLegacy"/>.</summary>
        public const string ManagedSwitch = "api/v2/monitor/switch-controller/managed-switch/status";
        public const string ManagedSwitchLegacy = "api/v2/monitor/switch-controller/managed-switch";
        public const string ManagedAp = "api/v2/monitor/wifi/managed_ap";
    }

    private readonly IHttpClientFactory? _http;
    private readonly Func<string, CancellationToken, Task<string>>? _fetch;
    private readonly ILogger _log;

    public FortiGateAdapter(IHttpClientFactory http, ILogger<FortiGateAdapter> log)
    {
        _http = http; _log = log;
    }

    /// <summary>Test seam: every GET goes through <paramref name="fetch"/> (path in, JSON out).</summary>
    public FortiGateAdapter(Func<string, CancellationToken, Task<string>> fetch, ILogger<FortiGateAdapter>? log = null)
    {
        _fetch = fetch; _log = log ?? NullLogger<FortiGateAdapter>.Instance;
    }

    public AdapterMetadata Metadata { get; } = new(
        Id: "fortigate",
        DisplayName: "FortiGate firewall (firmware, switches, APs, exposure)",
        Vendor: "Fortinet",
        Description: "Reads FortiOS firmware, managed FortiSwitch and FortiAP firmware, interfaces, SSL-VPN, virtual IPs and policies from a FortiGate over the REST API. Read-only.",
        Kinds: new[] { AssetKind.Firewall, AssetKind.Switch, AssetKind.AccessPoint },
        Form: new[]
        {
            new CredentialField("host", "FortiGate host", CredentialTypes.Text, "Management address, e.g. fw.example.local or 10.0.0.1:8443 (the admin HTTPS port if it is not 443)."),
            new CredentialField("apiToken", "REST API token", CredentialTypes.Password, "Token of a REST API administrator whose profile is read-only. Create it under System > Administrators > Create New > REST API Admin; see the linked Fortinet page."),
            new CredentialField("verifyTls", "Verify TLS certificate", CredentialTypes.Bool, "Turn off only for the factory self-signed certificate.", Required: false, Default: "true"),
            new CredentialField("vdom", "VDOM", CredentialTypes.Text, "Multi-VDOM units only: the VDOM to read (added as ?vdom=). Leave blank for a single-VDOM unit.", Required: false),
        },
        MinimumPermission: "a REST API admin with a read-only profile (accprofile with all permissions 'read'), trusted host set to the console's IP",
        DocsUrl: "https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/399023/rest-api-administrator",
        DefaultIntervalMinutes: 240);

    // ------------------------------------------------------------------ contract

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            var get = MakeFetch(credentials);
            var status = Parse(await get(Paths.Status, ct));
            var res = Results(status).FirstOrDefault();
            var hostname = Str(res, "hostname") ?? "(unknown)";
            var version = FirmwareVersion(Str(status, "version")) ?? "?";
            return new TestResult(true, "Connected to " + hostname + " (" + (Str(res, "model_name") ?? "FortiGate") + " " + (Str(res, "model_number") ?? "") + ") FortiOS " + version + ", serial " + (Str(status, "serial") ?? "?") + ".");
        }
        catch (Exception ex) when (ex is FortinetApiException or HttpRequestException or JsonException or TaskCanceledException or InvalidOperationException)
        {
            return new TestResult(false, ex.Message);
        }
    }

    public async Task<CollectResult> CollectAsync(IReadOnlyDictionary<string, string> credentials, DateTime? since, IProgress<string>? progress, CancellationToken ct)
    {
        var get = MakeFetch(credentials);
        var r = new CollectResult { FullSnapshot = true };

        progress?.Report("Reading system status");
        var status = Parse(await get(Paths.Status, ct));
        var serial = Str(status, "serial") ?? throw new FortinetApiException(Paths.Status, 200, "the response has no serial number");
        var version = FirmwareVersion(Str(status, "version")) ?? "";
        var build = Str(status, "build");
        var statusRes = Results(status).FirstOrDefault();
        var hostname = Str(statusRes, "hostname") ?? serial;

        progress?.Report("Reading interfaces and admin settings");
        var global = (await Optional(get, Paths.Global, r, ct)).FirstOrDefault();
        var adminHttps = Int(global, "admin-sport") ?? 443;
        var adminHttp = Int(global, "admin-port") ?? 80;
        var adminSsh = Int(global, "admin-ssh-port") ?? 22;
        var adminTelnet = Int(global, "admin-telnet-port") ?? 23;

        var interfaces = Results(Parse(await get(Paths.Interface, ct))).Select(ParseInterface).Where(i => i.Name.Length > 0).ToList();
        var wan = WanInterfaces(interfaces, r);

        var sslvpn = (await Optional(get, Paths.SslVpnSettings, r, ct)).FirstOrDefault();

        // ---- the FortiGate itself
        var ips = interfaces.Select(i => i.Ip).Where(ip => ip is not null).Distinct().Select(ip => ip!).ToArray();
        var macs = interfaces.Select(i => i.Mac).Where(m => !IsZeroMac(m)).Distinct(StringComparer.OrdinalIgnoreCase).Select(m => m!).ToArray();
        r.Assets.Add(new AssetRecord(serial, hostname, AssetKind.Firewall, new[] { hostname }, ips, macs,
            OsVendor: "Fortinet", OsProduct: "FortiOS", OsVersion: version, OsBuild: build, Criticality: Criticality.Critical));

        var listeners = new List<Listener>();
        var evidence = new List<string>();
        var sslEnabled = sslvpn.ValueKind == JsonValueKind.Object && Enabled(sslvpn, "status", true);
        var sslPort = Int(sslvpn, "port") ?? 443;
        if (sslEnabled)
            foreach (var src in Names(sslvpn, "source-interface"))
            {
                listeners.Add(new Listener(sslPort, "tcp", src, "sslvpnd"));
                if (wan.Contains(src)) evidence.Add("SSL-VPN on " + src + ":" + sslPort);
            }
        foreach (var i in interfaces)
        {
            if (i.AllowAccess.Contains("https")) { listeners.Add(new Listener(adminHttps, "tcp", i.Name, "httpsd")); if (wan.Contains(i.Name)) evidence.Add("admin HTTPS on " + i.Name + ":" + adminHttps); }
            if (i.AllowAccess.Contains("ssh")) { listeners.Add(new Listener(adminSsh, "tcp", i.Name, "sshd")); if (wan.Contains(i.Name)) evidence.Add("admin SSH on " + i.Name + ":" + adminSsh); }
            if (i.AllowAccess.Contains("http")) { listeners.Add(new Listener(adminHttp, "tcp", i.Name, "httpsd")); if (wan.Contains(i.Name)) evidence.Add("admin HTTP on " + i.Name + ":" + adminHttp); }
            if (i.AllowAccess.Contains("telnet")) { listeners.Add(new Listener(adminTelnet, "tcp", i.Name, "telnetd")); if (wan.Contains(i.Name)) evidence.Add("admin Telnet on " + i.Name + ":" + adminTelnet); }
        }
        r.Software.Add(new SoftwareRecord(serial, "Fortinet", "FortiOS", version, SoftwareKind.Firmware, ExternalId: "fortios", Listeners: listeners.Count > 0 ? listeners.ToArray() : null));
        if (evidence.Count > 0) r.Exposures.Add(new ExposureRecord(Exposure.Internet, string.Join("; ", evidence), AssetExternalId: serial));

        // ---- what the internet can reach through it
        progress?.Report("Reading virtual IPs and policies");
        var vips = (await Optional(get, Paths.Vip, r, ct)).Select(ParseVip).Where(v => v.Name.Length > 0).ToList();
        var vipGroups = (await Optional(get, Paths.VipGroup, r, ct)).ToDictionary(g => Str(g, "name") ?? "", g => Names(g, "member"), StringComparer.OrdinalIgnoreCase);
        var addresses = (await Optional(get, Paths.Address, r, ct)).Where(a => Str(a, "name") is not null).ToDictionary(a => Str(a, "name")!, a => a, StringComparer.OrdinalIgnoreCase);
        var addrGroups = (await Optional(get, Paths.AddressGroup, r, ct)).ToDictionary(g => Str(g, "name") ?? "", g => Names(g, "member"), StringComparer.OrdinalIgnoreCase);
        var policies = Results(Parse(await get(Paths.Policy, ct))).Select(ParsePolicy).ToList();
        r.Exposures.AddRange(InternetExposures(wan, vips, vipGroups, addresses, addrGroups, policies));

        // ---- managed switches and access points
        progress?.Report("Reading managed switches and access points");
        var switches = await Optional(get, Paths.ManagedSwitch, r, ct, fallback: Paths.ManagedSwitchLegacy);
        foreach (var s in switches)
        {
            var sw = MapSwitch(s);
            if (sw is null) continue;
            r.Assets.Add(sw.Value.Asset); r.Software.Add(sw.Value.Firmware);
        }
        foreach (var a in await Optional(get, Paths.ManagedAp, r, ct))
        {
            var ap = MapAccessPoint(a);
            if (ap is null) continue;
            r.Assets.Add(ap.Value.Asset); r.Software.Add(ap.Value.Firmware);
        }
        _log.LogInformation("FortiGate {Host}: {Assets} assets, {Exposures} exposure records", hostname, r.Assets.Count, r.Exposures.Count);
        return r;
    }

    // ------------------------------------------------------------------ parsed shapes

    public sealed record Iface(string Name, string Role, string? Ip, HashSet<string> AllowAccess, string? Mac, bool Up, string? Alias);
    public sealed record Vip(string Name, string? ExtIp, string ExtIntf, string? MappedIp, string? ExtPort, string? MappedPort, bool PortForward, string? Protocol);
    public sealed record Policy(string Id, string? Name, List<string> SrcIntf, List<string> DstIntf, List<string> DstAddr, List<string> Service, bool Accept, bool Enabled, bool MatchVip);

    public static Iface ParseInterface(JsonElement e) => new(
        Str(e, "name") ?? "",
        (Str(e, "role") ?? "undefined").ToLowerInvariant(),
        FirstIp(Str(e, "ip")),
        new HashSet<string>(SplitList(Str(e, "allowaccess")).Select(a => a.ToLowerInvariant())),
        Str(e, "macaddr"),
        Enabled(e, "status", true),
        Str(e, "alias"));

    public static Vip ParseVip(JsonElement e)
    {
        var mapped = Names(e, "mappedip").FirstOrDefault();
        if (mapped is not null && mapped.Contains('-')) mapped = mapped.Split('-')[0].Trim();
        var ext = Str(e, "extip");
        if (ext is not null && ext.Contains('-')) ext = ext.Split('-')[0].Trim();
        return new Vip(Str(e, "name") ?? "", ext, Str(e, "extintf") ?? "any", mapped, Str(e, "extport"), Str(e, "mappedport"), Enabled(e, "portforward", false), Str(e, "protocol"));
    }

    public static Policy ParsePolicy(JsonElement e) => new(
        Str(e, "policyid") ?? "?",
        Str(e, "name"),
        Names(e, "srcintf"), Names(e, "dstintf"), Names(e, "dstaddr"), Names(e, "service"),
        (Str(e, "action") ?? "deny").Equals("accept", StringComparison.OrdinalIgnoreCase),
        Enabled(e, "status", true),
        Enabled(e, "match-vip", false));

    /// <summary>Interfaces with role "wan"; when the unit has none, interfaces named wan*/ppp* as a fallback (noted in the warnings).</summary>
    public static HashSet<string> WanInterfaces(IReadOnlyList<Iface> interfaces, CollectResult? warnings = null)
    {
        var wan = new HashSet<string>(interfaces.Where(i => i.Role == "wan").Select(i => i.Name), StringComparer.OrdinalIgnoreCase);
        if (wan.Count == 0)
        {
            foreach (var i in interfaces.Where(i => i.Name.StartsWith("wan", StringComparison.OrdinalIgnoreCase) || i.Name.StartsWith("ppp", StringComparison.OrdinalIgnoreCase)))
                wan.Add(i.Name);
            if (wan.Count > 0) warnings?.Warnings.Add("No interface has role 'wan'; treated " + string.Join(", ", wan) + " as WAN by name.");
            else warnings?.Warnings.Add("No interface has role 'wan' and none is named wan*; internet exposure could not be derived. Set the interface role on the FortiGate.");
        }
        return wan;
    }

    /// <summary>
    /// Every VIP whose external interface is WAN (or any) and that an enabled accept policy from a WAN interface points at
    /// gives an Internet exposure for the mapped IP. A policy from WAN to a single-host address object does the same.
    /// </summary>
    public static List<ExposureRecord> InternetExposures(HashSet<string> wan, IReadOnlyList<Vip> vips, IReadOnlyDictionary<string, List<string>> vipGroups,
        IReadOnlyDictionary<string, JsonElement> addresses, IReadOnlyDictionary<string, List<string>> addrGroups, IReadOnlyList<Policy> policies)
    {
        var result = new List<ExposureRecord>();
        var vipByName = vips.ToDictionary(v => v.Name, StringComparer.OrdinalIgnoreCase);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in policies)
        {
            if (!p.Accept || !p.Enabled) continue;
            if (!p.SrcIntf.Any(s => s.Equals("any", StringComparison.OrdinalIgnoreCase) || wan.Contains(s))) continue;
            var dst = Expand(p.DstAddr, vipGroups, addrGroups);
            var all = dst.Any(d => d.Equals("all", StringComparison.OrdinalIgnoreCase));
            var services = p.Service.Count > 0 ? string.Join(",", p.Service) : "ALL";

            foreach (var v in vips)
            {
                if (!(dst.Contains(v.Name) || (all && p.MatchVip))) continue;
                if (!(v.ExtIntf.Equals("any", StringComparison.OrdinalIgnoreCase) || v.ExtIntf.Length == 0 || wan.Contains(v.ExtIntf))) continue;
                if (v.MappedIp is null || !seen.Add("vip:" + v.Name + ":" + p.Id)) continue;
                var target = v.ExtIp ?? "?";
                if (v.PortForward && v.ExtPort is not null) target += ":" + v.ExtPort;
                result.Add(new ExposureRecord(Exposure.Internet, "VIP " + v.Name + " " + target + " policy " + p.Id, IpAddress: v.MappedIp));
            }
            foreach (var name in dst)
            {
                if (vipByName.ContainsKey(name) || name.Equals("all", StringComparison.OrdinalIgnoreCase) || !addresses.TryGetValue(name, out var addr)) continue;
                var host = SingleHost(addr);
                if (host is null || !seen.Add("addr:" + name + ":" + p.Id)) continue;
                result.Add(new ExposureRecord(Exposure.Internet, "policy " + p.Id + " " + string.Join(",", p.SrcIntf) + "->" + string.Join(",", p.DstIntf) + " to " + name + " " + host + " service " + services, IpAddress: host));
            }
        }
        return result;
    }

    private static HashSet<string> Expand(IEnumerable<string> names, IReadOnlyDictionary<string, List<string>> vipGroups, IReadOnlyDictionary<string, List<string>> addrGroups)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var queue = new Queue<string>(names);
        while (queue.Count > 0)
        {
            var n = queue.Dequeue();
            if (!set.Add(n)) continue;
            if (vipGroups.TryGetValue(n, out var vm)) foreach (var m in vm) queue.Enqueue(m);
            if (addrGroups.TryGetValue(n, out var am)) foreach (var m in am) queue.Enqueue(m);
        }
        return set;
    }

    public static (AssetRecord Asset, SoftwareRecord Firmware)? MapSwitch(JsonElement s)
    {
        var serial = Str(s, "serial");
        if (serial is null) return null;
        var name = Str(s, "name", "switch-id") ?? serial;
        var image = Str(s, "os_version", "version");
        var version = FirmwareVersion(image) ?? "";
        var ip = FirstIp(Str(s, "connecting_from", "ip", "fortilink_ip"));
        var mac = Str(s, "mac", "switch_mac");
        var asset = new AssetRecord(serial, name, AssetKind.Switch, new[] { name }, ip is null ? System.Array.Empty<string>() : new[] { ip },
            IsZeroMac(mac) ? System.Array.Empty<string>() : new[] { mac! },
            OsVendor: "Fortinet", OsProduct: "FortiSwitch", OsVersion: version, OsBuild: ImageModel(image));
        return (asset, new SoftwareRecord(serial, "Fortinet", "FortiSwitch", version, SoftwareKind.Firmware, ExternalId: "fortiswitch", Edition: ImageModel(image)));
    }

    public static (AssetRecord Asset, SoftwareRecord Firmware)? MapAccessPoint(JsonElement a)
    {
        var serial = Str(a, "serial", "wtp_id");
        if (serial is null) return null;
        var name = Str(a, "name") ?? serial;
        var image = Str(a, "os_version");
        var version = FirmwareVersion(image) ?? "";
        var ips = new[] { FirstIp(Str(a, "connecting_from")), FirstIp(Str(a, "local_ipv4_addr")) }.Where(ip => ip is not null).Distinct().Select(ip => ip!).ToArray();
        var mac = Str(a, "board_mac");
        var asset = new AssetRecord(serial, name, AssetKind.AccessPoint, new[] { name }, ips, IsZeroMac(mac) ? System.Array.Empty<string>() : new[] { mac! },
            OsVendor: "Fortinet", OsProduct: "FortiAP", OsVersion: version, OsBuild: ImageModel(image));
        return (asset, new SoftwareRecord(serial, "Fortinet", "FortiAP", version, SoftwareKind.Firmware, ExternalId: "fortiap", Edition: ImageModel(image)));
    }

    // ------------------------------------------------------------------ envelopes

    /// <summary>The "results" of a FortiOS envelope: an array's items, a single object, or every envelope's results when vdom=* returned an array of envelopes.</summary>
    public static List<JsonElement> Results(JsonElement root)
    {
        var list = new List<JsonElement>();
        if (root.ValueKind == JsonValueKind.Array)
        {
            foreach (var env in root.EnumerateArray()) list.AddRange(Results(env));
            return list;
        }
        if (root.ValueKind != JsonValueKind.Object) return list;
        if (!root.TryGetProperty("results", out var res)) return list;
        if (res.ValueKind == JsonValueKind.Array) list.AddRange(res.EnumerateArray());
        else if (res.ValueKind == JsonValueKind.Object) list.Add(res);
        return list;
    }

    /// <summary>Endpoints that are absent on some models or FortiOS builds (no switch controller, no WiFi, no SSL-VPN) become a warning, not a failure.</summary>
    private async Task<List<JsonElement>> Optional(Func<string, CancellationToken, Task<string>> get, string path, CollectResult r, CancellationToken ct, string? fallback = null)
    {
        try { return Results(Parse(await get(path, ct))); }
        catch (Exception ex) when (ex is FortinetApiException or JsonException or HttpRequestException)
        {
            if (fallback is not null)
            {
                try { return Results(Parse(await get(fallback, ct))); }
                catch (Exception ex2) when (ex2 is FortinetApiException or JsonException or HttpRequestException) { ex = ex2; }
            }
            r.Warnings.Add("Skipped " + path + ": " + ex.Message);
            _log.LogWarning("FortiGate {Path} skipped: {Error}", path, ex.Message);
            return new List<JsonElement>();
        }
    }

    // ------------------------------------------------------------------ HTTP

    private Func<string, CancellationToken, Task<string>> MakeFetch(IReadOnlyDictionary<string, string> creds)
    {
        if (_fetch is not null) return _fetch;
        var host = FortinetCreds.Host(FortinetCreds.Get(creds, "host"));
        if (host.Length == 0) throw new InvalidOperationException("FortiGate host is required");
        var token = FortinetCreds.Get(creds, "apiToken");
        if (token.Length == 0) throw new InvalidOperationException("REST API token is required");
        var vdom = FortinetCreds.Get(creds, "vdom");
        var client = _http!.CreateClient(FortinetCreds.Bool(creds, "verifyTls", true) ? "adapter" : "adapter-insecure");
        return async (path, ct) =>
        {
            var url = "https://" + host + "/" + path.TrimStart('/');
            if (vdom.Length > 0) url += (url.Contains('?') ? "&" : "?") + "vdom=" + Uri.EscapeDataString(vdom);
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            if (resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                throw new FortinetApiException("GET " + path, (int)resp.StatusCode, "the FortiGate rejected the API token, or the console's IP is not a trusted host for the REST API admin");
            if (resp.StatusCode == HttpStatusCode.NotFound)
                throw new FortinetApiException("GET " + path, 404, "not found (feature not present on this model or FortiOS version)");
            if (!resp.IsSuccessStatusCode)
                throw new FortinetApiException("GET " + path, (int)resp.StatusCode, resp.ReasonPhrase ?? "");
            return await resp.Content.ReadAsStringAsync(ct);
        };
    }
}
