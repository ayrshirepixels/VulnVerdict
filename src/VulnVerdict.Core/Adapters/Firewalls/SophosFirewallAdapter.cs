using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Firewalls;

/// <summary>
/// Sophos Firewall (XGS, and XG on SFOS) over the on-box XML API (webconsole/APIController, the admin port 4444 by
/// default) for exposure, and SNMP for the firmware version, which the XML API does not report. Exposure: device
/// access on a WAN-type zone (web admin, SSH, user portal, VPN portal, SSL VPN, IPsec) marks the firewall
/// internet-facing; an enabled DNAT rule arriving on a WAN interface (or on any interface to a WAN interface's
/// address) and translating to a single host marks that host internet-facing.
///
/// Read-only: only &lt;Get&gt; requests are sent to the XML API, and SNMP GET for the firmware.
/// </summary>
public sealed partial class SophosFirewallAdapter : IInventoryAdapter
{
    public const string SfosDeviceName = "1.3.6.1.4.1.2604.5.1.1.1.0";
    public const string SfosDeviceType = "1.3.6.1.4.1.2604.5.1.1.2.0";
    public const string SfosDeviceFwVersion = "1.3.6.1.4.1.2604.5.1.1.3.0";
    public const string SfosDeviceAppKey = "1.3.6.1.4.1.2604.5.1.1.4.0";
    public static readonly string[] Entities = { "Zone", "Interface", "NATRule", "IPHost", "AdminSettings" };

    private readonly IHttpClientFactory _http;
    private readonly ILogger _log;

    public SophosFirewallAdapter(IHttpClientFactory http, ILogger<SophosFirewallAdapter>? log = null)
    {
        _http = http; _log = log ?? NullLogger<SophosFirewallAdapter>.Instance;
    }

    /// <summary>SNMP read of the SFOS MIB (host, credentials, oids). Tests replace it.</summary>
    public Func<string, IReadOnlyDictionary<string, string>, string[], CancellationToken, Task<Dictionary<string, string>?>> Snmp { get; set; } =
        (host, c, oids, ct) => Adapters.Snmp.SnmpAdapter.QueryAsync(host, FwCreds.SnmpFields(c), oids, Array.Empty<string>(), ct);

    public AdapterMetadata Metadata { get; } = new(
        Id: "sophos-firewall",
        DisplayName: "Sophos Firewall (SFOS firmware, exposure)",
        Vendor: "Sophos",
        Description: "Reads zones and their device-access services, interfaces, NAT rules and host objects from a Sophos Firewall (XGS or XG on SFOS) over the XML API, and the SFOS firmware version over SNMP (the XML API does not report it). Without SNMP the firewall and its exposure are still recorded, but the firmware version is blank. Read-only.",
        Kinds: new[] { AssetKind.Firewall },
        Form: new[]
        {
            new CredentialField("host", "Firewall host", CredentialTypes.Text, "Admin address, e.g. fw.example.local or 192.0.2.1:4444 (the web admin port, 4444 unless changed)."),
            new CredentialField("username", "API username", CredentialTypes.Text, "An administrator whose profile is read-only (a custom device access profile with every area set to Read-only). Enable the API under Backup & firmware > API and add the console's IP address to 'Allowed IP address'."),
            new CredentialField("password", "Password", CredentialTypes.Password, "Sent in the body of each API request over HTTPS, never in a URL."),
            FwCreds.VerifyTlsField("firewall"),
        }.Concat(FwCreds.SnmpFormFields("For the firmware version (SFOS-FIREWALL-MIB sfosDeviceFWVersion).")).ToArray(),
        MinimumPermission: "an administrator with a read-only device access profile, API access enabled for the console's IP address, and a read-only SNMP community or SNMPv3 user for the firmware version",
        DocsUrl: "https://docs.sophos.com/nsg/sophos-firewall/21.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/BackupAndFirmware/API/index.html",
        DefaultIntervalMinutes: 240);

    // ------------------------------------------------------------------ contract

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            var resp = await RequestAsync(credentials, new[] { "AdminSettings" }, ct);
            var hostname = Val(resp.Descendants("HostName").FirstOrDefault());
            var msg = "Connected to " + (hostname ?? FwCreds.Host(FwCreds.Get(credentials, "host"))) + " (XML API " + (resp.Attribute("APIVersion")?.Value ?? "?") + ").";
            if (FwCreds.HasSnmp(credentials))
            {
                var snmp = await Snmp(FwCreds.HostOnly(FwCreds.Get(credentials, "host")), credentials, new[] { SfosDeviceFwVersion, SfosDeviceType }, ct);
                msg += snmp?.GetValueOrDefault(SfosDeviceFwVersion) is { } fw ? " SNMP: " + (snmp.GetValueOrDefault(SfosDeviceType) ?? "Sophos Firewall") + " " + fw + "." : " SNMP did not answer: the firmware version will be blank.";
            }
            else msg += " No SNMP credentials: the firmware version will be blank.";
            return new TestResult(true, msg);
        }
        catch (Exception ex) when (ex is FirewallApiException or HttpRequestException or TaskCanceledException or InvalidOperationException or System.Xml.XmlException or ArgumentException)
        {
            return new TestResult(false, ex.Message);
        }
    }

    public async Task<CollectResult> CollectAsync(IReadOnlyDictionary<string, string> credentials, DateTime? since, IProgress<string>? progress, CancellationToken ct)
    {
        var r = new CollectResult { FullSnapshot = true };
        var host = FwCreds.Host(FwCreds.Get(credentials, "host"));

        progress?.Report("Reading zones, interfaces and NAT rules");
        var resp = await RequestAsync(credentials, Entities, ct);
        foreach (var e in Entities)
            if (EntityStatus(resp, e) is { } problem) r.Warnings.Add(e + ": " + problem);

        Dictionary<string, string>? snmp = null;
        if (FwCreds.HasSnmp(credentials))
        {
            progress?.Report("Reading firmware over SNMP");
            try { snmp = await Snmp(FwCreds.HostOnly(host), credentials, new[] { SfosDeviceName, SfosDeviceType, SfosDeviceFwVersion, SfosDeviceAppKey }, ct); }
            catch (Exception ex) when (ex is not OperationCanceledException) { r.Warnings.Add("SNMP: " + ex.Message); }
            if (snmp is null) r.Warnings.Add("SNMP did not answer; the firmware version is blank.");
        }
        else r.Warnings.Add("No SNMP credentials; the firmware version is blank (the XML API does not report it).");

        var fwText = snmp?.GetValueOrDefault(SfosDeviceFwVersion);
        var (version, build) = FirmwareVersion(fwText);
        var hostname = snmp?.GetValueOrDefault(SfosDeviceName) ?? Val(resp.Descendants("HostName").FirstOrDefault()) ?? FwCreds.HostOnly(host);
        var id = snmp?.GetValueOrDefault(SfosDeviceAppKey) ?? FwCreds.HostOnly(host);

        var zones = ParseZones(resp);
        var interfaces = ParseInterfaces(resp);
        var wanZones = new HashSet<string>(zones.Where(z => z.Type.Equals("WAN", StringComparison.OrdinalIgnoreCase)).Select(z => z.Name), StringComparer.OrdinalIgnoreCase);
        var wanIfaces = new HashSet<string>(interfaces.Where(i => i.Zone is not null && wanZones.Contains(i.Zone)).Select(i => i.Name), StringComparer.OrdinalIgnoreCase);
        if (wanIfaces.Count == 0) r.Warnings.Add("No interface is in a WAN-type zone; internet exposure could not be derived.");

        var admin = resp.Descendants("WebAdminSettings").FirstOrDefault();
        var adminPort = Int(admin, "HTTPSport") ?? 4444;
        var userPortalPort = Int(admin, "UserPortalHTTPSPort") ?? 443;
        var vpnPortalPort = Int(admin, "VPNPortalHTTPSPort") ?? 443;

        var device = new DeviceExposure();
        foreach (var z in zones)
        {
            var wan = wanZones.Contains(z.Name);
            void Svc(string service, int port, string proto, string label) { if (z.Services.Contains(service)) device.Add(port, proto, z.Name, label, wan, label + " on zone " + z.Name + ":" + port); }
            Svc("HTTPS", adminPort, "tcp", "web admin console");
            Svc("SSH", 22, "tcp", "admin SSH");
            Svc("UserPortal", userPortalPort, "tcp", "user portal");
            Svc("VPNPortal", vpnPortalPort, "tcp", "VPN portal");
            Svc("SSLVPN", 8443, "tcp", "SSL VPN");
            Svc("IPsec", 500, "udp", "IPsec VPN");
        }

        r.Assets.Add(EdgeRecords.Firewall(id, hostname, interfaces.Select(i => i.Ip), interfaces.Select(i => i.Mac), CnaNames.Sophos, CnaNames.SophosFirewall, version, build, new[] { hostname }));
        r.Software.AddRange(EdgeRecords.Firmware(id, CnaNames.Sophos, CnaNames.SophosFirewall, version ?? "", "sfos", listeners: device.Listeners, edition: snmp?.GetValueOrDefault(SfosDeviceType)));
        if (device.Record(id) is { } self) r.Exposures.Add(self);

        var hosts = resp.Descendants("IPHost").Select(h => (Name: Val(h.Element("Name")), Ip: Val(h.Element("IPAddress"))))
            .Where(h => h.Name is not null && h.Ip is not null).GroupBy(h => h.Name!, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First().Ip!, StringComparer.OrdinalIgnoreCase);
        var wanIps = new HashSet<string>(interfaces.Where(i => wanIfaces.Contains(i.Name) && i.Ip is not null).Select(i => i.Ip!));
        r.Exposures.AddRange(InternetExposures(wanIfaces, wanIps, ParseNatRules(resp), hosts));

        _log.LogInformation("Sophos Firewall {Host}: {Exposures} exposure records", hostname, r.Exposures.Count);
        return r;
    }

    // ------------------------------------------------------------------ parsing

    public sealed record Zone(string Name, string Type, HashSet<string> Services);
    public sealed record Iface(string Name, string? Zone, string? Ip, string? Mac);
    public sealed record NatRule(string Name, bool Enabled, List<string> Inbound, List<string> OriginalDestinations, List<string> Services, string? TranslatedDestination);

    private static string? Val(XElement? e) => e is null || string.IsNullOrWhiteSpace(e.Value) ? null : e.Value.Trim();
    private static int? Int(XElement? parent, string name) => int.TryParse(Val(parent?.Element(name)), out var i) ? i : null;

    [GeneratedRegex(@"(\d+)\.(\d+)\.(\d+)")] private static partial Regex SfosRx();
    [GeneratedRegex(@"Build\s*-?(\d+)", RegexOptions.IgnoreCase)] private static partial Regex BuildRx();

    /// <summary>
    /// "SFOS 21.0.1 MR-1-Build272" to ("21.0 MR1", "272") and "SFOS 21.5.0 GA-Build171" to ("21.5 GA", "171"): the
    /// form the Sophos CNA writes in affected ranges ("21.0 MR1 (21.0.1)", "18.5 MR3"), so ranges compare correctly.
    /// </summary>
    public static (string? Version, string? Build) FirmwareVersion(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return (null, null);
        var m = SfosRx().Match(text);
        var b = BuildRx().Match(text);
        var build = b.Success ? b.Groups[1].Value : null;
        if (!m.Success) return (null, build);
        var mr = int.Parse(m.Groups[3].Value);
        return (m.Groups[1].Value + "." + m.Groups[2].Value + (mr == 0 ? " GA" : " MR" + mr), build);
    }

    public static List<Zone> ParseZones(XElement resp) => resp.Elements("Zone").Where(z => z.Element("Name") is not null).Select(z =>
    {
        var services = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in z.Element("ApplianceAccess")?.Descendants() ?? Enumerable.Empty<XElement>())
            if (!s.HasElements && Val(s) is { } v && !v.Equals("Disable", StringComparison.OrdinalIgnoreCase)) services.Add(s.Name.LocalName);
        return new Zone(Val(z.Element("Name"))!, Val(z.Element("Type")) ?? "", services);
    }).ToList();

    public static List<Iface> ParseInterfaces(XElement resp) => resp.Elements("Interface").Where(i => i.Element("Name") is not null).Select(i =>
        new Iface(Val(i.Element("Name"))!, Val(i.Element("NetworkZone")), EdgeRecords.FirstIp(Val(i.Element("IPAddress"))), Val(i.Element("MACAddress")))).ToList();

    public static List<NatRule> ParseNatRules(XElement resp) => resp.Elements("NATRule").Where(n => n.Element("Name") is not null).Select(n =>
        new NatRule(Val(n.Element("Name"))!, !(Val(n.Element("Status")) ?? "Enable").Equals("Disable", StringComparison.OrdinalIgnoreCase),
            n.Element("InboundInterfaces")?.Elements("Interface").Select(Val).Where(v => v is not null).Select(v => v!).ToList() ?? new(),
            n.Element("OriginalDestinationNetworks")?.Elements("Network").Select(Val).Where(v => v is not null).Select(v => v!).ToList() ?? new(),
            n.Element("OriginalServices")?.Elements("Service").Select(Val).Where(v => v is not null).Select(v => v!).ToList() ?? new(),
            Val(n.Element("TranslatedDestination")))).ToList();

    /// <summary>
    /// An enabled NAT rule that translates the destination to a single host is internet exposure when it arrives on a
    /// WAN interface, or on any interface ("Any" or none listed) to a WAN interface's address ("#Port2" or its IP).
    /// </summary>
    public static List<ExposureRecord> InternetExposures(HashSet<string> wanIfaces, HashSet<string> wanIps, IReadOnlyList<NatRule> nat, IReadOnlyDictionary<string, string> hosts)
    {
        string? Resolve(string name) => hosts.TryGetValue(name, out var ip) ? ip : name;
        bool IsWanAddress(string dest)
        {
            var d = dest.TrimStart('#');
            if (wanIfaces.Contains(d)) return true;
            return Resolve(dest) is { } ip && wanIps.Contains(ip);
        }
        var result = new List<ExposureRecord>();
        foreach (var n in nat)
        {
            if (!n.Enabled || n.TranslatedDestination is null || n.TranslatedDestination.Equals("Original", StringComparison.OrdinalIgnoreCase)) continue;
            var anyInbound = n.Inbound.Count == 0 || n.Inbound.Any(i => i.Equals("Any", StringComparison.OrdinalIgnoreCase));
            var fromWan = n.Inbound.Any(wanIfaces.Contains) || (anyInbound && n.OriginalDestinations.Any(IsWanAddress));
            if (!fromWan) continue;
            var target = EdgeRecords.SingleHost(Resolve(n.TranslatedDestination));
            if (target is null) continue;
            result.Add(new ExposureRecord(Exposure.Internet,
                "NAT rule " + n.Name + " " + string.Join(",", n.OriginalDestinations) + " " + (n.Services.Count > 0 ? string.Join(",", n.Services) : "any") + " -> " + n.TranslatedDestination + " " + target,
                IpAddress: target));
        }
        return result;
    }

    /// <summary>An entity's own status line when it is an error or an empty result is fine (null); otherwise the message.</summary>
    public static string? EntityStatus(XElement resp, string entity)
    {
        foreach (var e in resp.Elements(entity))
        {
            var st = e.Element("Status");
            if (st is null) continue;
            var code = st.Attribute("code")?.Value;
            if (code is null || code == "200" || (Val(st) ?? "").Contains("records Zero", StringComparison.OrdinalIgnoreCase)) return null;
            return "status " + code + " " + Val(st);
        }
        return null;
    }

    // ------------------------------------------------------------------ XML API

    /// <summary>One POST with &lt;Login&gt; and a &lt;Get&gt; for each entity; login and IP-allow-list failures become exceptions.</summary>
    private async Task<XElement> RequestAsync(IReadOnlyDictionary<string, string> c, IEnumerable<string> entities, CancellationToken ct)
    {
        var host = FwCreds.HostWithPort(FwCreds.Get(c, "host"), 4444);
        if (host.Length == 0) throw new InvalidOperationException("Firewall host is required");
        var user = FwCreds.Get(c, "username"); var pw = FwCreds.Secret(c, "password");
        if (user.Length == 0 || pw.Length == 0) throw new InvalidOperationException("API username and password are required");
        var request = new XElement("Request",
            new XElement("Login", new XElement("Username", user), new XElement("Password", pw)),
            new XElement("Get", entities.Select(e => new XElement(e))));
        var http = new EdgeHttp(_http, FwCreds.Bool(c, "verifyTls", true), "https://" + host, null, Explain);
        var (body, _) = await http.SendAsync(HttpMethod.Post, "webconsole/APIController",
            () => new FormUrlEncodedContent(new Dictionary<string, string> { ["reqxml"] = request.ToString(SaveOptions.DisableFormatting) }), null, ct);
        return CheckResponse(body);
    }

    public static XElement CheckResponse(string body)
    {
        const string notApi = "the answer is not API XML: is the API enabled under Backup & firmware > API, and is this the web admin port?";
        XElement resp;
        try { resp = XElement.Parse(body); }
        catch (System.Xml.XmlException) { throw new FirewallApiException("APIController", 200, notApi); }
        if (resp.Name.LocalName != "Response") throw new FirewallApiException("APIController", 200, notApi);
        var top = resp.Element("Status");
        if (top is not null)
        {
            var code = top.Attribute("code")?.Value ?? "";
            var hint = code == "534" ? " Add the console's IP address to the allowed list under Backup & firmware > API." : "";
            throw new FirewallApiException("APIController", 0, "status " + code + " " + top.Value.Trim() + "." + hint);
        }
        var login = Val(resp.Element("Login")?.Element("status"));
        if (login is not null && !login.Contains("Successful", StringComparison.OrdinalIgnoreCase))
            throw new FirewallApiException("APIController", 0, "login: " + login + " (check the API username and password, and that the administrator's profile allows API access)");
        return resp;
    }

    private static string? Explain(int status) => status switch
    {
        401 or 403 => "the firewall refused the request; check that API access is enabled and allows the console's IP address",
        404 => "no XML API here: check the host and the web admin port (4444 by default)",
        _ => null
    };
}
