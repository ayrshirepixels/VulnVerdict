using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;
using static VulnVerdict.Core.Adapters.Fortinet.FortinetJson;

namespace VulnVerdict.Core.Adapters.Firewalls;

/// <summary>
/// OPNsense (Deciso) over its official REST API with an API key and secret (HTTP Basic). Version and hostname from
/// the system information endpoint (firmware status as a fallback); interfaces for addresses; exposure from
/// destination NAT (port forward) and 1:1 NAT rules on WAN interfaces, and from firewall rules on a WAN interface
/// that pass traffic to the firewall itself (web GUI, SSH, VPN).
///
/// Read-only: GET only. OPNsense 25.7 or later exposes port forwards through the API; on older releases the port
/// forward list is skipped with a warning.
/// </summary>
public sealed partial class OpnSenseAdapter : IInventoryAdapter
{
    public static class Paths
    {
        public const string SystemInformation = "api/diagnostics/system/system_information";
        public const string FirmwareStatus = "api/core/firmware/status";
        public const string Interfaces = "api/interfaces/overview/interfaces_info";
        public const string DNat = "api/firewall/d_nat/search_rule";
        public const string OneToOne = "api/firewall/one_to_one/search_rule";
        public const string Filter = "api/firewall/filter/search_rule";
    }

    private readonly IHttpClientFactory _http;
    private readonly ILogger _log;

    public OpnSenseAdapter(IHttpClientFactory http, ILogger<OpnSenseAdapter>? log = null)
    {
        _http = http; _log = log ?? NullLogger<OpnSenseAdapter>.Instance;
    }

    public AdapterMetadata Metadata { get; } = new(
        Id: "opnsense",
        DisplayName: "OPNsense firewall (version, NAT exposure)",
        Vendor: "Deciso",
        Description: "Reads the OPNsense version, interfaces, destination NAT (port forwards), 1:1 NAT and WAN firewall rules to the firewall itself over the OPNsense REST API. Port forwards are read on OPNsense 25.7 and later. Most OPNsense CVEs are published with vendor and product 'n/a', so expect few automatic matches and use Needs mapping or the watchlist. Read-only.",
        Kinds: new[] { AssetKind.Firewall },
        Form: new[]
        {
            new CredentialField("host", "OPNsense host", CredentialTypes.Text, "Web GUI address, e.g. opnsense.example.local or 192.0.2.1:8443."),
            new CredentialField("apiKey", "API key", CredentialTypes.Text, "Key of a user whose only privileges are the read pages the connector uses (Diagnostics: System Activity/Information, Interfaces: Overview, Firewall: Rules and NAT). Create it under System > Access > Users > API keys."),
            new CredentialField("apiSecret", "API secret", CredentialTypes.Password, "The secret from the same downloaded key file."),
            FwCreds.VerifyTlsField("firewall"),
            new CredentialField("wanInterfaces", "WAN interfaces", CredentialTypes.Text, "Comma-separated interface identifiers that face the internet (wan, opt1, ...).", Required: false, Default: "wan"),
        },
        MinimumPermission: "an API key for a user with only the read privileges the connector uses (no administrator group)",
        DocsUrl: "https://docs.opnsense.org/development/how-tos/api.html",
        DefaultIntervalMinutes: 240);

    // ------------------------------------------------------------------ contract

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            var api = Api(credentials);
            var (name, version) = await IdentityAsync(api, null, ct);
            return new TestResult(true, "Connected to " + (name ?? "OPNsense") + ", OPNsense " + (version ?? "?") + ".");
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
        var host = FwCreds.HostOnly(FwCreds.Get(credentials, "host"));

        progress?.Report("Reading system information");
        var (name, version) = await IdentityAsync(api, r, ct);
        var id = name ?? host;
        var wan = new HashSet<string>(FwJson.SplitCsv(FwCreds.Get(credentials, "wanInterfaces") is { Length: > 0 } w ? w : "wan"), StringComparer.OrdinalIgnoreCase);

        progress?.Report("Reading interfaces and rules");
        var ifaces = Rows(await OptionalAsync(api, Paths.Interfaces, r, ct));
        var ips = ifaces.Select(i => EdgeRecords.FirstIp(Str(i, "addr4", "ipv4"))).ToList();
        var macs = ifaces.Select(i => Str(i, "macaddr", "macaddr_hw")).ToList();
        var wanIps = new HashSet<string>(ifaces.Where(i => wan.Contains(Str(i, "identifier") ?? "")).Select(i => EdgeRecords.FirstIp(Str(i, "addr4", "ipv4"))).Where(ip => ip is not null).Select(ip => ip!));

        var device = new DeviceExposure();
        foreach (var rule in Rows(await OptionalAsync(api, Paths.Filter, r, ct)))
            if (SelfPassRule(rule, wan, wanIps) is { } svc)
                device.Add(svc.Port, svc.Protocol, svc.Interface, "firewall rule", !svc.Restricted, svc.Evidence);

        r.Assets.Add(EdgeRecords.Firewall(id, name ?? host, ips, macs, CnaNames.Deciso, CnaNames.OpnSense, version, hostnames: new[] { name }));
        r.Software.AddRange(EdgeRecords.Firmware(id, CnaNames.Deciso, CnaNames.OpnSense, version ?? "", "opnsense", listeners: device.Listeners, kind: SoftwareKind.OperatingSystem));
        if (device.Record(id) is { } self) r.Exposures.Add(self);

        foreach (var rule in Rows(await OptionalAsync(api, Paths.DNat, r, ct, "port forwards need OPNsense 25.7 or later")))
            if (PortForward(rule, wan) is { } ex) r.Exposures.Add(ex);
        foreach (var rule in Rows(await OptionalAsync(api, Paths.OneToOne, r, ct)))
            if (OneToOne(rule, wan) is { } ex) r.Exposures.Add(ex);

        _log.LogInformation("OPNsense {Host}: {Exposures} exposure records", id, r.Exposures.Count);
        return r;
    }

    // ------------------------------------------------------------------ mapping

    [GeneratedRegex(@"OPNsense\s+(\d+(?:\.\d+)+(?:_\d+)?)", RegexOptions.IgnoreCase)] private static partial Regex VersionRx();

    /// <summary>"OPNsense 25.7.3_1-amd64" to "25.7.3_1".</summary>
    public static string? VersionFrom(string? s) => s is null ? null : VersionRx().Match(s) is { Success: true } m ? m.Groups[1].Value : null;

    private static bool On(JsonElement e, string name) => (Str(e, name) ?? "0") is "1" or "true";
    private static List<string> Ifaces(JsonElement e) => FwJson.SplitCsv(Str(e, "interface")).ToList();

    /// <summary>A service on the firewall a WAN rule lets through. Restricted: the rule only admits named sources, so it is a listener, not internet exposure.</summary>
    public sealed record SelfService(int Port, string Protocol, string Interface, string Evidence, bool Restricted = false);

    /// <summary>An enabled pass rule on a WAN interface whose destination is the firewall itself ("(self)", "wanip" or the WAN address).</summary>
    public static SelfService? SelfPassRule(JsonElement rule, HashSet<string> wan, HashSet<string> wanIps)
    {
        if (!On(rule, "enabled") || !(Str(rule, "action") ?? "").Equals("pass", StringComparison.OrdinalIgnoreCase)) return null;
        if ((Str(rule, "direction") ?? "in") != "in") return null;
        var iface = Ifaces(rule).FirstOrDefault(wan.Contains);
        if (iface is null) return null;
        var dest = Str(rule, "destination_net") ?? "any";
        var toSelf = dest is "(self)" or "This Firewall" || dest.Equals(iface + "ip", StringComparison.OrdinalIgnoreCase) || wanIps.Contains(dest);
        if (!toSelf) return null;
        var portText = Str(rule, "destination_port") ?? "";
        var proto = (Str(rule, "protocol") ?? "any").ToLowerInvariant();
        var port = int.TryParse(portText.Split('-', ':')[0], out var p) ? p : 0;
        var source = Str(rule, "source_net") ?? "any";
        var restricted = !source.Equals("any", StringComparison.OrdinalIgnoreCase) || On(rule, "source_not");
        return new SelfService(port, proto.Contains("udp") && !proto.Contains("tcp") ? "udp" : "tcp", iface,
            "firewall rule '" + (Str(rule, "description") ?? Str(rule, "uuid") ?? "?") + "' passes " + proto + " " + (portText.Length > 0 ? portText : "any port") + " to the firewall on " + iface + (restricted ? " from " + source : ""), restricted);
    }

    public static ExposureRecord? PortForward(JsonElement rule, HashSet<string> wan)
    {
        if (On(rule, "disabled") || On(rule, "nordr")) return null;
        var iface = Ifaces(rule).FirstOrDefault(wan.Contains);
        var target = EdgeRecords.SingleHost(Str(rule, "target"));
        if (iface is null || target is null) return null;
        return new ExposureRecord(Exposure.Internet,
            "port forward '" + (Str(rule, "descr") ?? "?") + "' on " + iface + " " + (Str(rule, "protocol") ?? "any") + " " + (Str(rule, "destination.network") ?? "any") + ":" + (Str(rule, "destination.port") ?? "any") + " -> " + target + ":" + (Str(rule, "local-port") ?? Str(rule, "destination.port") ?? "any"),
            IpAddress: target);
    }

    public static ExposureRecord? OneToOne(JsonElement rule, HashSet<string> wan)
    {
        if (!On(rule, "enabled")) return null;
        var iface = Ifaces(rule).FirstOrDefault(wan.Contains);
        var inside = EdgeRecords.SingleHost(Str(rule, "source_net"));
        if (iface is null || inside is null) return null;
        return new ExposureRecord(Exposure.Internet, "1:1 NAT '" + (Str(rule, "description") ?? "?") + "' on " + iface + " " + (Str(rule, "external") ?? "?") + " <-> " + inside, IpAddress: inside);
    }

    private static List<JsonElement> Rows(JsonElement root) =>
        root.ValueKind == JsonValueKind.Object && root.TryGetProperty("rows", out var rows) && rows.ValueKind == JsonValueKind.Array ? rows.EnumerateArray().ToList()
        : root.ValueKind == JsonValueKind.Array ? root.EnumerateArray().ToList() : new();

    // ------------------------------------------------------------------ REST

    private EdgeHttp Api(IReadOnlyDictionary<string, string> c)
    {
        var host = FwCreds.Host(FwCreds.Get(c, "host"));
        if (host.Length == 0) throw new InvalidOperationException("OPNsense host is required");
        var key = FwCreds.Get(c, "apiKey"); var secret = FwCreds.Secret(c, "apiSecret").Trim();
        if (key.Length == 0 || secret.Length == 0) throw new InvalidOperationException("API key and secret are required");
        var basic = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(key + ":" + secret)));
        return new EdgeHttp(_http, FwCreds.Bool(c, "verifyTls", true), "https://" + host, req => req.Headers.Authorization = basic, Explain);
    }

    private static string? Explain(int status) => status switch
    {
        401 => "OPNsense rejected the API key and secret",
        403 => "the API key's user lacks the privilege for this page (add it under System > Access > Users > Effective privileges)",
        404 => "not found on this OPNsense version",
        _ => null
    };

    private static async Task<(string? Name, string? Version)> IdentityAsync(EdgeHttp api, CollectResult? r, CancellationToken ct)
    {
        try
        {
            var info = Parse(await api.GetAsync(Paths.SystemInformation, ct));
            var versions = Names(info, "versions");
            var v = versions.Select(VersionFrom).FirstOrDefault(x => x is not null);
            if (v is not null) return (Str(info, "name"), v);
        }
        catch (FirewallApiException ex) when (ex.Status is 404 or 403) { /* older release, or no dashboard privilege: try firmware status */ }
        var fw = Parse(await api.GetAsync(Paths.FirmwareStatus, ct));
        var product = fw.ValueKind == JsonValueKind.Object && fw.TryGetProperty("product", out var p) ? p : fw;
        var version = Str(product, "product_version") ?? Str(fw, "product_version");
        if (version is null) r?.Warnings.Add("The firmware status did not include a product version.");
        return (null, version);
    }

    private static async Task<JsonElement> OptionalAsync(EdgeHttp api, string path, CollectResult r, CancellationToken ct, string? hint404 = null)
    {
        try { return Parse(await api.GetAsync(path, ct)); }
        catch (Exception ex) when (ex is FirewallApiException { Status: not 401 } or JsonException)
        {
            r.Warnings.Add("Skipped " + path + ": " + (ex is FirewallApiException { Status: 404 } && hint404 is not null ? hint404 : ex.Message));
            return default;
        }
    }
}
