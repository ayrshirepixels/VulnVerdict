using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;
using static VulnVerdict.Core.Adapters.Fortinet.FortinetJson;

namespace VulnVerdict.Core.Adapters.Firewalls;

/// <summary>
/// SonicWall TZ / NSa / NSsp on SonicOS 7 over the SonicOS API (/api/sonicos) with HTTP Basic authentication.
/// Firmware, model and serial from /version; exposure from interfaces (HTTPS/SSH management or user login on a WAN
/// interface), SSL VPN access on a WAN zone, and inbound NAT policies on a WAN interface translating to a single host.
///
/// Read-only: GET only, apart from opening (POST /auth) and closing (DELETE /auth) the API session. It never sets
/// "override", so it cannot push out an administrator who is logged in.
/// </summary>
public sealed class SonicWallAdapter : IInventoryAdapter
{
    public static class Paths
    {
        public const string Auth = "auth";
        public const string Version = "version";
        public const string Admin = "administration/global";
        public const string Interfaces = "interfaces/ipv4";
        public const string Zones = "zones";
        public const string Nat = "nat-policies/ipv4";
        public const string Addresses = "address-objects/ipv4";
        public const string SslVpnBase = "ssl-vpn/server/base";
        public const string SslVpnAccess = "ssl-vpn/server/accesses";
    }

    private readonly IHttpClientFactory _http;
    private readonly ILogger _log;

    public SonicWallAdapter(IHttpClientFactory http, ILogger<SonicWallAdapter>? log = null)
    {
        _http = http; _log = log ?? NullLogger<SonicWallAdapter>.Instance;
    }

    public AdapterMetadata Metadata { get; } = new(
        Id: "sonicwall",
        DisplayName: "SonicWall firewall (SonicOS 7, exposure)",
        Vendor: "SonicWall",
        Description: "Reads SonicOS firmware, model and serial, interface management and user-login settings, zones, SSL VPN access and NAT policies from a TZ, NSa or NSsp firewall over the SonicOS API. Read-only.",
        Kinds: new[] { AssetKind.Firewall },
        Form: new[]
        {
            new CredentialField("host", "Firewall host", CredentialTypes.Text, "Management address, e.g. fw.example.local or 192.0.2.1:8443 (the HTTPS management port if it is not 443)."),
            new CredentialField("username", "Username", CredentialTypes.Text, "An administrator allowed to use the SonicOS API. SonicWall's API guide says API sessions need a full administrator; the connector only reads."),
            new CredentialField("password", "Password", CredentialTypes.Password, "Sent as HTTP Basic authentication over HTTPS. Turn on 'Enable SonicOS API' and 'Enable RFC-2617 HTTP Basic Access authentication' under Device > Settings > Administration > Audit/SonicOS API."),
            FwCreds.VerifyTlsField("firewall"),
        },
        MinimumPermission: "an administrator account that can use the SonicOS API (SonicWall requires administrator rights for API sessions); the connector only sends GET requests and never overrides another admin session",
        DocsUrl: "https://www.sonicwall.com/support/knowledge-base/introduction-to-sonicos-api/kA1VN0000000FGr0AM",
        DefaultIntervalMinutes: 240);

    // ------------------------------------------------------------------ contract

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            await using var api = await Session.OpenAsync(this, credentials, ct);
            var v = Parse(await api.GetAsync(Paths.Version, ct));
            return new TestResult(true, "Connected to " + (Str(v, "model") ?? "SonicWall") + " " + (Str(v, "firmware_version") ?? "?") + ", serial " + (Str(v, "serial_number") ?? "?") + ".");
        }
        catch (Exception ex) when (ex is FirewallApiException or HttpRequestException or JsonException or TaskCanceledException or InvalidOperationException)
        {
            return new TestResult(false, ex.Message);
        }
    }

    public async Task<CollectResult> CollectAsync(IReadOnlyDictionary<string, string> credentials, DateTime? since, IProgress<string>? progress, CancellationToken ct)
    {
        var r = new CollectResult { FullSnapshot = true };
        await using var api = await Session.OpenAsync(this, credentials, ct);

        progress?.Report("Reading version");
        var v = Parse(await api.GetAsync(Paths.Version, ct));
        var serial = Str(v, "serial_number") ?? throw new FirewallApiException("GET " + Paths.Version, 200, "the response has no serial number");
        var firmware = Str(v, "firmware_version");
        var version = EdgeVersions.Dotted(firmware) ?? "";
        var model = Str(v, "model");

        progress?.Report("Reading interfaces, zones and SSL VPN");
        var admin = Obj(await api.OptionalAsync(Paths.Admin, r, ct), "administration");
        var name = Str(admin, "firewall_name") ?? serial;
        var httpsPort = Int(admin, "https_port") ?? 443;
        var httpPort = Int(admin, "http_port") ?? 80;
        var sshPort = Int(Obj(admin, "ssh"), "port") ?? 22;

        var interfaces = Array(Parse(await api.GetAsync(Paths.Interfaces, ct)), "interfaces").Select(i => Obj(i, "ipv4")).Select(ParseInterface).Where(i => i.Name.Length > 0).ToList();
        var untrustedZones = new HashSet<string>(Array(await api.OptionalAsync(Paths.Zones, r, ct), "zones")
            .Where(z => (Str(z, "security_type") ?? "").Equals("untrusted", StringComparison.OrdinalIgnoreCase)).Select(z => Str(z, "name") ?? ""), StringComparer.OrdinalIgnoreCase) { "WAN" };
        var wan = new HashSet<string>(interfaces.Where(i => i.Zone is not null && untrustedZones.Contains(i.Zone)).Select(i => i.Name), StringComparer.OrdinalIgnoreCase);
        if (wan.Count == 0) r.Warnings.Add("No interface is in the WAN zone (or another untrusted zone); internet exposure could not be derived.");

        var device = new DeviceExposure();
        foreach (var i in interfaces)
        {
            var onWan = wan.Contains(i.Name);
            var where = i.Name + " (zone " + (i.Zone ?? "none") + ")";
            if (i.Https) device.Add(httpsPort, "tcp", i.Name, "management https", onWan, "management HTTPS on " + where + ":" + httpsPort);
            if (i.Ssh) device.Add(sshPort, "tcp", i.Name, "management ssh", onWan, "management SSH on " + where + ":" + sshPort);
            if (i.Http) device.Add(httpPort, "tcp", i.Name, "management http", onWan, "management HTTP on " + where + ":" + httpPort);
            if (i.UserLoginHttps) device.Add(httpsPort, "tcp", i.Name, "user login https", onWan, "user login HTTPS on " + where);
        }
        var sslBase = Obj(Obj(await api.OptionalAsync(Paths.SslVpnBase, r, ct), "ssl_vpn"), "server");
        var sslPort = Int(sslBase, "port") ?? 4433;
        foreach (var access in Array(Obj(Obj(await api.OptionalAsync(Paths.SslVpnAccess, r, ct), "ssl_vpn"), "server"), "access"))
        {
            var zone = Str(access, "zone");
            if (zone is null || !Enabled(access, "enable", false)) continue;
            device.Add(sslPort, "tcp", zone, "ssl vpn", untrustedZones.Contains(zone), "SSL VPN on zone " + zone + ":" + sslPort);
        }

        r.Assets.Add(EdgeRecords.Firewall(serial, name, interfaces.Select(i => i.Ip), interfaces.Select(i => i.Mac), CnaNames.SonicWall, CnaNames.SonicOs, version, hostnames: new[] { name }));
        r.Software.AddRange(EdgeRecords.Firmware(serial, CnaNames.SonicWall, CnaNames.SonicOs, version, "sonicos", listeners: device.Listeners, edition: model));
        if (device.Record(serial) is { } self) r.Exposures.Add(self);

        progress?.Report("Reading NAT policies");
        var addresses = Array(await api.OptionalAsync(Paths.Addresses, r, ct), "address_objects").Select(a => Obj(a, "ipv4"))
            .Select(a => (Name: Str(a, "name"), Ip: Str(Obj(a, "host"), "ip")))
            .Where(a => a.Name is not null && a.Ip is not null).GroupBy(a => a.Name!, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First().Ip!, StringComparer.OrdinalIgnoreCase);
        var nat = Array(Parse(await api.GetAsync(Paths.Nat, ct)), "nat_policies").Select(p => Obj(p, "ipv4")).Select(ParseNat).ToList();
        r.Exposures.AddRange(InternetExposures(wan, nat, addresses));

        _log.LogInformation("SonicWall {Host}: {Exposures} exposure records", name, r.Exposures.Count);
        return r;
    }

    // ------------------------------------------------------------------ parsing

    public sealed record Iface(string Name, string? Zone, string? Ip, string? Mac, bool Https, bool Ssh, bool Http, bool UserLoginHttps);
    public sealed record NatPolicy(string Name, bool Enabled, string Inbound, string? Destination, string? TranslatedDestination, string? Service);

    public static JsonElement Obj(JsonElement e, string name) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) ? v : default;

    public static Iface ParseInterface(JsonElement i)
    {
        var ipa = Obj(i, "ip_assignment");
        var mode = Obj(ipa, "mode");
        var ip = Str(Obj(mode, "static"), "ip");
        var mgmt = Obj(i, "management");
        var mac = Obj(i, "mac");
        return new Iface(Str(i, "name") ?? "", Str(ipa, "zone"), EdgeRecords.FirstIp(ip), Str(mac, "address") ?? (mac.ValueKind == JsonValueKind.String ? mac.GetString() : null),
            Enabled(mgmt, "https", false), Enabled(mgmt, "ssh", false), Enabled(mgmt, "http", false), Enabled(Obj(i, "user_login"), "https", false));
    }

    /// <summary>An address-object reference: {"name": ...}, {"group": ...}, or {"any"/"original": true} (null).</summary>
    private static string? Ref(JsonElement e) => Str(e, "name") ?? Str(e, "group");

    public static NatPolicy ParseNat(JsonElement p) => new(
        Str(p, "name") ?? "?", Enabled(p, "enable", true), Str(p, "inbound") ?? "any",
        Ref(Obj(p, "destination")), Ref(Obj(p, "translated_destination")), Ref(Obj(p, "service")));

    /// <summary>An enabled NAT policy whose inbound interface is on the WAN side and whose translated destination is a single-host object exposes that host.</summary>
    public static List<ExposureRecord> InternetExposures(HashSet<string> wan, IReadOnlyList<NatPolicy> nat, IReadOnlyDictionary<string, string> addresses)
    {
        var result = new List<ExposureRecord>();
        foreach (var n in nat)
        {
            if (!n.Enabled || !wan.Contains(n.Inbound) || n.TranslatedDestination is null) continue;
            var target = EdgeRecords.SingleHost(addresses.TryGetValue(n.TranslatedDestination, out var ip) ? ip : n.TranslatedDestination);
            if (target is null) continue;
            result.Add(new ExposureRecord(Exposure.Internet, "NAT policy " + n.Name + " on " + n.Inbound + " " + (n.Destination ?? "any") + " " + (n.Service ?? "any") + " -> " + n.TranslatedDestination + " " + target, IpAddress: target));
        }
        return result;
    }

    /// <summary>SonicOS API status envelope: {"status":{"success":false,"info":[{"message":...}]}} becomes an exception.</summary>
    public static void ThrowOnFailure(string what, int httpStatus, string body)
    {
        if (string.IsNullOrWhiteSpace(body)) return;
        JsonElement root;
        try { root = Parse(body); } catch (JsonException) { return; }
        var st = Obj(root, "status");
        if (st.ValueKind != JsonValueKind.Object || Enabled(st, "success", true)) return;
        var msg = string.Join(" ", Array(st, "info").Select(i => Str(i, "message")).Where(m => m is not null));
        throw new FirewallApiException(what, httpStatus, msg.Length > 0 ? msg : "the firewall reported a failure");
    }

    // ------------------------------------------------------------------ session

    private sealed class Session : IAsyncDisposable
    {
        private readonly EdgeHttp _http;
        private Session(EdgeHttp http) { _http = http; }

        public static async Task<Session> OpenAsync(SonicWallAdapter a, IReadOnlyDictionary<string, string> c, CancellationToken ct)
        {
            var host = FwCreds.Host(FwCreds.Get(c, "host"));
            if (host.Length == 0) throw new InvalidOperationException("Firewall host is required");
            var user = FwCreds.Get(c, "username"); var pw = FwCreds.Secret(c, "password");
            if (user.Length == 0 || pw.Length == 0) throw new InvalidOperationException("Username and password are required");
            var basic = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(user + ":" + pw)));
            var http = new EdgeHttp(a._http, FwCreds.Bool(c, "verifyTls", true), "https://" + host + "/api/sonicos", req => req.Headers.Authorization = basic, Explain);
            try
            {
                var (body, _) = await http.SendAsync(HttpMethod.Post, Paths.Auth, () => new StringContent("{}", Encoding.UTF8, "application/json"), null, ct);
                ThrowOnFailure("POST " + Paths.Auth, 200, body);
            }
            catch (FirewallApiException ex) when (ex.Status == 404)
            {
                throw new FirewallApiException("POST " + Paths.Auth, 404, "the SonicOS API is not enabled (Device > Settings > Administration > Audit/SonicOS API), or this is not SonicOS 7");
            }
            return new Session(http);
        }

        public async Task<string> GetAsync(string path, CancellationToken ct)
        {
            var body = await _http.GetAsync(path, ct);
            ThrowOnFailure("GET " + path, 200, body);
            return body;
        }

        /// <summary>Endpoints some models or licences lack (SSL VPN, zones) become a warning, not a failure.</summary>
        public async Task<JsonElement> OptionalAsync(string path, CollectResult r, CancellationToken ct)
        {
            try { return Parse(await GetAsync(path, ct)); }
            catch (Exception ex) when (ex is FirewallApiException { Status: not (401 or 403) } or JsonException)
            {
                r.Warnings.Add("Skipped " + path + ": " + ex.Message);
                return default;
            }
        }

        public async ValueTask DisposeAsync()
        {
            try { await _http.SendAsync(HttpMethod.Delete, Paths.Auth, null, null, CancellationToken.None); } catch { /* logging out is best effort */ }
        }
    }

    private static string? Explain(int status) => status switch
    {
        401 => "the firewall rejected the username or password, or HTTP Basic authentication is not enabled for the SonicOS API",
        403 => "the account is not allowed to use the SonicOS API, or another administrator holds the configuration session",
        _ => null
    };
}
