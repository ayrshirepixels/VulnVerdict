using System.Net;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Firewalls;

/// <summary>
/// Palo Alto Networks PA-series (and VM-series) over the PAN-OS XML API, without Panorama. `show system info` gives
/// the PAN-OS version, model and serial; the running configuration gives exposure: a management profile allowing
/// HTTPS/SSH on an interface in an internet zone, or a GlobalProtect portal or gateway on one, marks the firewall
/// internet-facing; a destination NAT rule from an internet zone that an allow rule from that zone matches marks the
/// translated host internet-facing.
///
/// Read-only: only type=op "show" commands and type=config action=show (running configuration) are sent, plus
/// type=keygen when a username and password are given instead of a key.
/// </summary>
public sealed class PanOsAdapter : IInventoryAdapter
{
    public const string ShowSystemInfo = "<show><system><info></info></system></show>";
    public static string DeviceXpath => "/config/devices/entry[@name='localhost.localdomain']";
    public static string VsysXpath(string vsys) => DeviceXpath + "/vsys/entry[@name='" + vsys + "']";

    private static readonly string[] DefaultInternetZones = { "untrust", "outside", "internet", "wan", "external", "untrusted" };

    private readonly IHttpClientFactory _http;
    private readonly ILogger _log;

    public PanOsAdapter(IHttpClientFactory http, ILogger<PanOsAdapter>? log = null)
    {
        _http = http; _log = log ?? NullLogger<PanOsAdapter>.Instance;
    }

    /// <summary>Test seam for 429 back-off.</summary>
    public Func<TimeSpan, CancellationToken, Task>? Delay { get; set; }

    public AdapterMetadata Metadata { get; } = new(
        Id: "panos",
        DisplayName: "Palo Alto Networks firewall (PAN-OS, exposure)",
        Vendor: "Palo Alto Networks",
        Description: "Reads the PAN-OS version, model and serial, interfaces, zones, management profiles, GlobalProtect portals and gateways, NAT and security rules from a PA-series or VM-series firewall over the XML API (no Panorama needed). Read-only.",
        Kinds: new[] { AssetKind.Firewall },
        Form: new[]
        {
            new CredentialField("host", "Firewall host", CredentialTypes.Text, "Management address, e.g. pa.example.local or 192.0.2.1:8443 (the management HTTPS port if it is not 443)."),
            new CredentialField("apiKey", "API key", CredentialTypes.Password, "A key generated for a read-only administrator (type=keygen). Leave blank to use the username and password below instead.", Required: false),
            new CredentialField("username", "Username", CredentialTypes.Text, "Only when no API key is given: an administrator with the Superuser (read-only) role, or an Admin Role profile with XML API Configuration and Operational Requests enabled and everything else read-only or off.", Required: false),
            new CredentialField("password", "Password", CredentialTypes.Password, "Only when no API key is given. Sent once in the body of a keygen request, never in a URL.", Required: false),
            FwCreds.VerifyTlsField("firewall"),
            new CredentialField("vsys", "Virtual system", CredentialTypes.Text, "The vsys to read. vsys1 on firewalls without multiple virtual systems.", Required: false, Default: "vsys1"),
            new CredentialField("internetZones", "Internet-facing zones", CredentialTypes.Text, "Comma-separated zone names that face the internet. Blank: zones named untrust, outside, internet, wan or external.", Required: false),
        },
        MinimumPermission: "an administrator with the Superuser (read-only) dynamic role, or a custom Admin Role with XML API Configuration and Operational Requests only",
        DocsUrl: "https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/get-your-api-key",
        DefaultIntervalMinutes: 240);

    // ------------------------------------------------------------------ contract

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            var api = await ConnectAsync(credentials, ct);
            var info = SystemInfo(await api.OpAsync(ShowSystemInfo, ct));
            return new TestResult(true, "Connected to " + (info.Hostname ?? "(unknown)") + " (" + (info.Model ?? "PAN-OS firewall") + ") PAN-OS " + (info.Version ?? "?") + ", serial " + (info.Serial ?? "?") + ".");
        }
        catch (Exception ex) when (ex is FirewallApiException or HttpRequestException or TaskCanceledException or InvalidOperationException or System.Xml.XmlException)
        {
            return new TestResult(false, ex.Message);
        }
    }

    public async Task<CollectResult> CollectAsync(IReadOnlyDictionary<string, string> credentials, DateTime? since, IProgress<string>? progress, CancellationToken ct)
    {
        var r = new CollectResult { FullSnapshot = true };
        var api = await ConnectAsync(credentials, ct);
        var vsys = FwCreds.Get(credentials, "vsys") is { Length: > 0 } v ? v : "vsys1";

        progress?.Report("Reading system info");
        var info = SystemInfo(await api.OpAsync(ShowSystemInfo, ct));
        var serial = info.Serial ?? throw new FirewallApiException("show system info", 200, "the response has no serial number");
        var hostname = info.Hostname ?? serial;

        progress?.Report("Reading interfaces, zones and management profiles");
        var interfaces = ParseInterfaces(await api.ConfigAsync(DeviceXpath + "/network/interface", r, ct));
        var profiles = ParseProfiles(await api.ConfigAsync(DeviceXpath + "/network/profiles/interface-management-profile", r, ct));
        var zones = ParseZones(await api.ConfigAsync(VsysXpath(vsys) + "/zone", r, ct));
        var internetZones = InternetZones(FwCreds.Get(credentials, "internetZones"), zones.Keys, r);
        var zoneOf = zones.SelectMany(z => z.Value.Select(i => (Iface: i, Zone: z.Key))).GroupBy(x => x.Iface, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First().Zone, StringComparer.OrdinalIgnoreCase);
        bool Internet(string iface) => zoneOf.TryGetValue(iface, out var z) && internetZones.Contains(z);

        // ---- the firewall itself
        var device = new DeviceExposure();
        foreach (var i in interfaces)
        {
            if (i.Profile is null || !profiles.TryGetValue(i.Profile, out var services)) continue;
            var zone = zoneOf.GetValueOrDefault(i.Name) ?? "no zone";
            foreach (var (svc, port) in new[] { ("https", 443), ("ssh", 22), ("http", 80), ("telnet", 23) })
                if (services.Contains(svc)) device.Add(port, "tcp", i.Name, "management " + svc, Internet(i.Name), "management " + svc.ToUpperInvariant() + " on " + i.Name + " (zone " + zone + ")");
        }
        progress?.Report("Reading GlobalProtect");
        foreach (var gp in ParseGlobalProtect(await api.ConfigAsync(VsysXpath(vsys) + "/global-protect/global-protect-portal", r, ct), "portal")
                     .Concat(ParseGlobalProtect(await api.ConfigAsync(VsysXpath(vsys) + "/global-protect/global-protect-gateway", r, ct), "gateway")))
        {
            var zone = zoneOf.GetValueOrDefault(gp.Interface) ?? "no zone";
            device.Add(443, "tcp", gp.Interface, "GlobalProtect " + gp.Role, Internet(gp.Interface), "GlobalProtect " + gp.Role + " " + gp.Name + " on " + gp.Interface + " (zone " + zone + ")");
        }

        var ips = new List<string?> { info.IpAddress };
        ips.AddRange(interfaces.Select(i => i.Ip));
        r.Assets.Add(EdgeRecords.Firewall(serial, hostname, ips, new[] { info.Mac }, CnaNames.PaloAlto, CnaNames.PanOs, info.Version, hostnames: new[] { hostname }));
        r.Software.AddRange(EdgeRecords.Firmware(serial, CnaNames.PaloAlto, CnaNames.PanOs, info.Version ?? "", "pan-os", listeners: device.Listeners, edition: info.Model));
        if (device.Record(serial) is { } self) r.Exposures.Add(self);

        // ---- what the internet can reach through it
        progress?.Report("Reading NAT and security rules");
        var addresses = ParseAddresses(await api.ConfigAsync(VsysXpath(vsys) + "/address", r, ct));
        foreach (var kv in ParseAddresses(await api.ConfigAsync("/config/shared/address", r, ct))) addresses.TryAdd(kv.Key, kv.Value);
        var nat = ParseNatRules(await api.ConfigAsync(VsysXpath(vsys) + "/rulebase/nat/rules", r, ct));
        var security = ParseSecurityRules(await api.ConfigAsync(VsysXpath(vsys) + "/rulebase/security/rules", r, ct));
        r.Exposures.AddRange(InternetExposures(internetZones, nat, security, addresses));

        _log.LogInformation("PAN-OS {Host}: {Exposures} exposure records", hostname, r.Exposures.Count);
        return r;
    }

    // ------------------------------------------------------------------ parsed shapes

    public sealed record SysInfo(string? Hostname, string? Model, string? Serial, string? Version, string? IpAddress, string? Mac);
    public sealed record Iface(string Name, string? Ip, string? Profile);
    public sealed record GpListener(string Name, string Role, string Interface);
    public sealed record NatRule(string Name, List<string> From, List<string> To, List<string> Destination, string? Service, string? TranslatedAddress, string? TranslatedPort, bool Disabled);
    public sealed record SecurityRule(string Name, List<string> From, List<string> Destination, List<string> Service, bool Allow, bool Disabled);

    public static SysInfo SystemInfo(XElement result)
    {
        var s = result.Descendants("system").FirstOrDefault() ?? result;
        string? V(string n) => s.Element(n)?.Value is { Length: > 0 } x ? x.Trim() : null;
        return new SysInfo(V("hostname"), V("model"), V("serial"), V("sw-version"), V("ip-address"), V("mac-address"));
    }

    private static List<string> Members(XElement? e)
    {
        if (e is null) return new();
        var list = e.Elements("member").Select(m => m.Value.Trim()).Where(m => m.Length > 0).ToList();
        if (list.Count == 0 && !e.HasElements && e.Value.Trim().Length > 0) list.Add(e.Value.Trim());
        return list;
    }

    private static bool Yes(XElement? e) => e is not null && e.Value.Trim().Equals("yes", StringComparison.OrdinalIgnoreCase);

    /// <summary>Layer-3 ethernet, aggregate and VLAN interfaces and their sub-interfaces, with the first IP and management profile.</summary>
    public static List<Iface> ParseInterfaces(XElement result)
    {
        var list = new List<Iface>();
        foreach (var entry in result.Descendants("entry"))
        {
            var name = entry.Attribute("name")?.Value;
            if (name is null) continue;
            // physical and aggregate interfaces carry a <layer3> block; sub-interfaces and vlan/loopback/tunnel units carry the settings directly
            var l3 = entry.Element("layer3") ?? (entry.Parent?.Name.LocalName == "units" ? entry : null);
            if (l3 is null) continue;
            var ip = l3.Element("ip")?.Elements("entry").Select(x => x.Attribute("name")?.Value).FirstOrDefault(x => x is not null);
            var profile = l3.Element("interface-management-profile")?.Value.Trim();
            list.Add(new Iface(name, EdgeRecords.FirstIp(ip), string.IsNullOrEmpty(profile) ? null : profile));
        }
        return list.GroupBy(i => i.Name, StringComparer.OrdinalIgnoreCase).Select(g => g.First()).ToList();
    }

    /// <summary>Management profile name to the services it allows (https, ssh, http, telnet).</summary>
    public static Dictionary<string, HashSet<string>> ParseProfiles(XElement result)
    {
        var d = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in result.Descendants("entry"))
        {
            var name = entry.Attribute("name")?.Value;
            if (name is null) continue;
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var svc in new[] { "https", "ssh", "http", "telnet" }) if (Yes(entry.Element(svc))) set.Add(svc);
            d[name] = set;
        }
        return d;
    }

    /// <summary>Zone name to its layer-3 member interfaces.</summary>
    public static Dictionary<string, List<string>> ParseZones(XElement result)
    {
        var d = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in result.Descendants("entry").Where(e => e.Element("network") is not null))
        {
            var name = entry.Attribute("name")?.Value;
            if (name is null) continue;
            var net = entry.Element("network")!;
            d[name] = Members(net.Element("layer3")).Concat(Members(net.Element("virtual-wire"))).Concat(Members(net.Element("tap"))).ToList();
        }
        return d;
    }

    public static HashSet<string> InternetZones(string configured, IEnumerable<string> zones, CollectResult? warnings = null)
    {
        var all = zones.ToList();
        if (configured.Length > 0)
        {
            var set = new HashSet<string>(FwJson.SplitCsv(configured), StringComparer.OrdinalIgnoreCase);
            var unknown = set.Where(z => !all.Contains(z, StringComparer.OrdinalIgnoreCase)).ToList();
            if (unknown.Count > 0) warnings?.Warnings.Add("Internet-facing zone(s) not found on the firewall: " + string.Join(", ", unknown));
            return set;
        }
        var guess = new HashSet<string>(all.Where(z => DefaultInternetZones.Contains(z, StringComparer.OrdinalIgnoreCase)), StringComparer.OrdinalIgnoreCase);
        if (guess.Count > 0) warnings?.Warnings.Add("Internet-facing zones guessed by name: " + string.Join(", ", guess) + ". Set them on the connector to be sure.");
        else warnings?.Warnings.Add("No zone is named untrust, outside, internet, wan or external; internet exposure could not be derived. Name the internet-facing zones on the connector.");
        return guess;
    }

    public static List<GpListener> ParseGlobalProtect(XElement result, string role)
    {
        var list = new List<GpListener>();
        foreach (var entry in result.Descendants("entry").Where(e => e.Parent?.Name.LocalName is "global-protect-portal" or "global-protect-gateway"))
        {
            var name = entry.Attribute("name")?.Value ?? role;
            // portal: portal-config/local-address/interface; gateway: local-address/interface
            var iface = entry.Descendants("local-address").Select(l => l.Element("interface")?.Value.Trim()).FirstOrDefault(i => !string.IsNullOrEmpty(i));
            if (iface is not null) list.Add(new GpListener(name, role, iface));
        }
        return list;
    }

    public static Dictionary<string, string> ParseAddresses(XElement result)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in result.Descendants("entry"))
        {
            var name = entry.Attribute("name")?.Value;
            var ip = entry.Element("ip-netmask")?.Value.Trim();
            if (name is not null && ip is not null) d[name] = ip;
        }
        return d;
    }

    public static List<NatRule> ParseNatRules(XElement result) => result.Descendants("entry").Where(e => e.Element("from") is not null).Select(e =>
    {
        var dt = e.Element("destination-translation") ?? e.Element("dynamic-destination-translation");
        return new NatRule(e.Attribute("name")?.Value ?? "?", Members(e.Element("from")), Members(e.Element("to")), Members(e.Element("destination")),
            e.Element("service")?.Value.Trim(), dt?.Element("translated-address")?.Value.Trim(), dt?.Element("translated-port")?.Value.Trim(), Yes(e.Element("disabled")));
    }).ToList();

    public static List<SecurityRule> ParseSecurityRules(XElement result) => result.Descendants("entry").Where(e => e.Element("action") is not null).Select(e =>
        new SecurityRule(e.Attribute("name")?.Value ?? "?", Members(e.Element("from")), Members(e.Element("destination")), Members(e.Element("service")),
            e.Element("action")!.Value.Trim().Equals("allow", StringComparison.OrdinalIgnoreCase), Yes(e.Element("disabled")))).ToList();

    /// <summary>
    /// A destination NAT rule from an internet zone (or any) whose translated address is a single host is exposure when an
    /// enabled allow rule from an internet zone (or any) matches its original destination (PAN-OS security rules see the
    /// pre-NAT destination address).
    /// </summary>
    public static List<ExposureRecord> InternetExposures(HashSet<string> internetZones, IReadOnlyList<NatRule> nat, IReadOnlyList<SecurityRule> security, IReadOnlyDictionary<string, string> addresses)
    {
        bool FromInternet(List<string> from) => from.Any(z => z.Equals("any", StringComparison.OrdinalIgnoreCase) || internetZones.Contains(z));
        string? Resolve(string? nameOrIp) => nameOrIp is null ? null : EdgeRecords.SingleHost(addresses.TryGetValue(nameOrIp, out var a) ? a : nameOrIp);
        var result = new List<ExposureRecord>();
        foreach (var n in nat)
        {
            if (n.Disabled || n.TranslatedAddress is null || !FromInternet(n.From)) continue;
            var target = Resolve(n.TranslatedAddress);
            if (target is null) continue;
            var allow = security.FirstOrDefault(s => s.Allow && !s.Disabled && FromInternet(s.From)
                && s.Destination.Any(d => d.Equals("any", StringComparison.OrdinalIgnoreCase) || n.Destination.Contains(d, StringComparer.OrdinalIgnoreCase)
                                          || (Resolve(d) is { } dip && n.Destination.Select(Resolve).Contains(dip))));
            if (allow is null) continue;
            var original = string.Join(",", n.Destination.Select(d => Resolve(d) ?? d));
            var evidence = "NAT rule " + n.Name + " " + original + (n.Service is { Length: > 0 } svc && svc != "any" ? " " + svc : "") + " -> " + target + (n.TranslatedPort is { Length: > 0 } p ? ":" + p : "") + " allowed by security rule " + allow.Name;
            result.Add(new ExposureRecord(Exposure.Internet, evidence, IpAddress: target));
        }
        return result;
    }

    // ------------------------------------------------------------------ XML API

    private async Task<Api> ConnectAsync(IReadOnlyDictionary<string, string> c, CancellationToken ct)
    {
        var host = FwCreds.Host(FwCreds.Get(c, "host"));
        if (host.Length == 0) throw new InvalidOperationException("Firewall host is required");
        var key = FwCreds.Secret(c, "apiKey").Trim();
        var http = new EdgeHttp(_http, FwCreds.Bool(c, "verifyTls", true), "https://" + host, null, Explain);
        if (Delay is not null) http.Delay = Delay;
        if (key.Length == 0)
        {
            var user = FwCreds.Get(c, "username"); var pw = FwCreds.Secret(c, "password");
            if (user.Length == 0 || pw.Length == 0) throw new InvalidOperationException("Enter an API key, or a username and password to generate one");
            var (body, _) = await http.SendAsync(HttpMethod.Post, "api/?type=keygen", () => new FormUrlEncodedContent(new Dictionary<string, string> { ["user"] = user, ["password"] = pw }), null, ct);
            key = Envelope("keygen", body).Element("key")?.Value.Trim() ?? throw new FirewallApiException("keygen", 200, "no key in the response");
        }
        return new Api(http, key);
    }

    private static string? Explain(int status) => status switch
    {
        401 or 403 => "the firewall rejected the API key or credentials, or the administrator's role does not allow the XML API",
        404 => "not found: is this the firewall's management address?",
        _ => null
    };

    /// <summary>The &lt;result&gt; of a PAN-OS &lt;response&gt;; status="error" becomes an exception with the firewall's message.</summary>
    public static XElement Envelope(string what, string xml)
    {
        var doc = XDocument.Parse(xml);
        var resp = doc.Root ?? throw new FirewallApiException(what, 200, "empty response");
        if (!(resp.Attribute("status")?.Value ?? "").Equals("success", StringComparison.OrdinalIgnoreCase))
        {
            var msg = string.Join(" ", resp.Descendants("msg").Concat(resp.Descendants("line")).Select(m => m.Value.Trim()).Where(m => m.Length > 0).Distinct());
            throw new FirewallApiException(what, int.TryParse(resp.Attribute("code")?.Value, out var code) ? code : 200, msg.Length > 0 ? msg : "the firewall returned an error");
        }
        return resp.Element("result") ?? new XElement("result");
    }

    private sealed class Api
    {
        private readonly EdgeHttp _http; private readonly string _key;
        public Api(EdgeHttp http, string key) { _http = http; _key = key; }

        private async Task<string> Get(string query, CancellationToken ct) =>
            (await _http.SendAsync(HttpMethod.Get, "api/?" + query, null, req => req.Headers.TryAddWithoutValidation("X-PAN-KEY", _key), ct)).Body;

        public async Task<XElement> OpAsync(string cmd, CancellationToken ct) => Envelope("op " + cmd, await Get("type=op&cmd=" + Uri.EscapeDataString(cmd), ct));

        /// <summary>Running configuration at an xpath; a missing node (feature not configured) is an empty result, other errors a warning.</summary>
        public async Task<XElement> ConfigAsync(string xpath, CollectResult r, CancellationToken ct)
        {
            try { return Envelope("config " + xpath, await Get("type=config&action=show&xpath=" + Uri.EscapeDataString(xpath), ct)); }
            catch (FirewallApiException ex) when (ex.Status is 7 or 200 && ex.Message.Contains("No such node", StringComparison.OrdinalIgnoreCase)) { return new XElement("result"); }
            catch (FirewallApiException ex) when (ex.Status != 401 && ex.Status != 403) { r.Warnings.Add("Skipped " + xpath + ": " + ex.Message); return new XElement("result"); }
        }
    }
}

/// <summary>Small string helpers shared by the firewall adapters.</summary>
public static class FwJson
{
    public static string[] SplitCsv(string? s) => string.IsNullOrWhiteSpace(s)
        ? Array.Empty<string>()
        : s.Split(new[] { ',', ';', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
