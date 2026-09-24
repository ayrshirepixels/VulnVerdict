using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;
using static VulnVerdict.Core.Adapters.Fortinet.FortinetJson;

namespace VulnVerdict.Core.Adapters.Firewalls;

/// <summary>
/// Ubiquiti UniFi gateways (Dream Machine, Cloud Gateway, Dream Router, UXG, USG) and the devices they manage, from
/// the UniFi Network application on the console or a self-hosted controller. Two ways in:
/// an API key (the official UniFi Network API, Network 9.0 and later) gives every device with its firmware and the
/// application version, but no port forwards; a local view-only account (the application's own web API, which the
/// UniFi web interface uses) also gives port forwards and remote-access VPN servers for exposure.
///
/// Read-only: GET requests, plus logging in and out when a local account is used.
/// </summary>
public sealed class UniFiGatewayAdapter : IInventoryAdapter
{
    public const string IntegrationBase = "proxy/network/integration/v1";
    public const int PageSize = 200;

    /// <summary>
    /// UniFi device model codes (as the application's device list reports them) to the names Ubiquiti's CVE records use
    /// for UniFi OS consoles (CVE-2026-34908 lists "UDM", "UDM-Pro", "UCG-Max", ...). Unknown codes are kept as they are.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> ModelNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["UDM"] = "UDM", ["UDMPRO"] = "UDM-Pro", ["UDMPROSE"] = "UDM-SE", ["UDMPROMAX"] = "UDM-Pro-Max", ["UDMBEAST"] = "UDM-Beast",
        ["UDR"] = "UDR", ["UDR7"] = "UDR7", ["UDR5G"] = "UDR-5G", ["UDRULT"] = "UCG-Ultra", ["UCGMAX"] = "UCG-Max", ["UCGF"] = "UCG-Fiber",
        ["UCGIND"] = "UCG-Industrial", ["EFG"] = "EFG", ["UDW"] = "UDW", ["UX7"] = "Express 7",
        ["UXGPRO"] = "UXG-Pro", ["UXG"] = "UXG-Lite", ["UXGB"] = "UXG-Max", ["UXGENT"] = "UXG-Enterprise",
        ["UGW3"] = "USG", ["UGW4"] = "USG-Pro-4", ["UGWXG"] = "USG-XG-8",
    };

    private static readonly string[] ConsolePrefixes = { "UDM", "UDR", "UCG", "EFG", "UDW", "Express" };

    private readonly IHttpClientFactory _http;
    private readonly ILogger _log;

    public UniFiGatewayAdapter(IHttpClientFactory http, ILogger<UniFiGatewayAdapter>? log = null)
    {
        _http = http; _log = log ?? NullLogger<UniFiGatewayAdapter>.Instance;
    }

    public AdapterMetadata Metadata { get; } = new(
        Id: "unifi-gateway",
        DisplayName: "Ubiquiti UniFi gateway (UniFi OS, devices, port forwards)",
        Vendor: "Ubiquiti",
        Description: "Reads the UniFi gateway and every device it manages, with firmware, and the UniFi Network application version, from a UniFi console (Dream Machine, Cloud Gateway, Dream Router) or a self-hosted UniFi Network application. With a local view-only account it also reads port forwards and remote-access VPN servers for exposure; with an API key (official UniFi Network API) port forwards are not available. Read-only.",
        Kinds: new[] { AssetKind.Firewall, AssetKind.Switch, AssetKind.AccessPoint },
        Form: new[]
        {
            new CredentialField("host", "Console or controller address", CredentialTypes.Text, "e.g. 192.0.2.1 for a UniFi console, or unifi.example.local:8443 for a self-hosted Network application."),
            new CredentialField("apiKey", "API key", CredentialTypes.Password, "UniFi Network 9.0 or later: create one under Settings > Control Plane > Integrations. Leave blank to use a local account instead (needed for port forwards).", Required: false),
            new CredentialField("username", "Local username", CredentialTypes.Text, "Only when no API key is given: a local (not UI account) administrator with the View Only role for the Network application.", Required: false),
            new CredentialField("password", "Password", CredentialTypes.Password, "Only with a local username.", Required: false),
            new CredentialField("site", "Site", CredentialTypes.Text, "Optional site name (the short name, e.g. default). Blank reads every site.", Required: false),
            FwCreds.VerifyTlsField("console"),
        },
        MinimumPermission: "a UniFi Network API key, or a local administrator with the View Only role (a local account is needed for port forwards)",
        DocsUrl: "https://help.ui.com/hc/en-us/articles/30076656117655-Getting-Started-with-the-Official-UniFi-API",
        DefaultIntervalMinutes: 240);

    // ------------------------------------------------------------------ contract

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            await using var s = await Session.OpenAsync(this, credentials, ct);
            var sites = await s.SitesAsync(credentials, ct);
            return new TestResult(true, "Connected (" + (s.ApiKey ? "API key" : s.UniFiOs ? "local account, UniFi OS" : "local account, self-hosted") + "), UniFi Network " + (await s.AppVersionAsync(ct) ?? "?") + ", site(s): " + string.Join(", ", sites.Select(x => x.Name)) + "."
                + (s.ApiKey ? " Port forwards are not available with an API key." : ""));
        }
        catch (Exception ex) when (ex is FirewallApiException or HttpRequestException or JsonException or TaskCanceledException or InvalidOperationException)
        {
            return new TestResult(false, ex.Message);
        }
    }

    public async Task<CollectResult> CollectAsync(IReadOnlyDictionary<string, string> credentials, DateTime? since, IProgress<string>? progress, CancellationToken ct)
    {
        var r = new CollectResult { FullSnapshot = true };
        await using var s = await Session.OpenAsync(this, credentials, ct);
        var appVersion = await s.AppVersionAsync(ct);
        string? appHost = null;
        foreach (var site in await s.SitesAsync(credentials, ct))
        {
            progress?.Report("Reading devices in site " + site.Name);
            var devices = s.ApiKey ? await s.IntegrationDevicesAsync(site.Id, ct) : await s.ClassicDevicesAsync(site.Id, ct);
            var gateway = devices.FirstOrDefault(d => d.Gateway);
            var device = new DeviceExposure();
            if (!s.ApiKey)
            {
                progress?.Report("Reading port forwards and VPN servers in site " + site.Name);
                foreach (var pf in await s.ClassicListAsync(site.Id, "rest/portforward", r, ct))
                    if (PortForward(pf) is { } ex) r.Exposures.Add(ex);
                foreach (var net in await s.ClassicListAsync(site.Id, "rest/networkconf", r, ct))
                    if (VpnServer(net) is { } vpn) device.Add(vpn.Port, vpn.Protocol, "WAN", vpn.Label, true, vpn.Label + " on the WAN:" + vpn.Port);
            }
            foreach (var d in devices)
            {
                r.Assets.Add(new AssetRecord(d.Id, d.Name, d.Kind, new[] { d.Name }.Where(n => !System.Net.IPAddress.TryParse(n, out _)).ToArray(),
                    d.Ips.Where(EdgeRecords.IsUsableIp).Distinct().ToArray(), d.Mac is null ? System.Array.Empty<string>() : new[] { d.Mac.ToLowerInvariant() },
                    OsVendor: CnaNames.Ubiquiti, OsProduct: d.Product, OsVersion: d.Version, Criticality: d.Gateway ? Criticality.Critical : null));
                var alts = d.Gateway && IsConsole(d.Product) ? new[] { CnaNames.UniFiOs } : null;
                r.Software.AddRange(EdgeRecords.Firmware(d.Id, CnaNames.Ubiquiti, d.Product, d.Version ?? "", "unifi-firmware", alts,
                    listeners: d == gateway ? device.Listeners : null, edition: d.ModelCode));
                if (d.Version is null) r.Warnings.Add(d.Name + ": no firmware version reported");
            }
            if (gateway is not null && device.Record(gateway.Id) is { } self) r.Exposures.Add(self);
            else if (gateway is null && device.InternetFacing) r.Warnings.Add("Site " + site.Name + " has a VPN server but no gateway in the device list.");
            appHost ??= gateway is not null && IsConsole(gateway.Product) ? gateway.Id : null;
        }

        // the Network application itself: on the console when there is one, otherwise the self-hosted controller
        if (appVersion is not null)
        {
            if (appHost is null)
            {
                appHost = FwCreds.HostOnly(FwCreds.Get(credentials, "host"));
                r.Assets.Add(new AssetRecord(appHost, appHost, AssetKind.Server, System.Net.IPAddress.TryParse(appHost, out _) ? System.Array.Empty<string>() : new[] { appHost },
                    System.Net.IPAddress.TryParse(appHost, out _) ? new[] { appHost } : System.Array.Empty<string>(), System.Array.Empty<string>()));
            }
            r.Software.Add(new SoftwareRecord(appHost, CnaNames.Ubiquiti, CnaNames.UniFiNetworkApplication, appVersion, SoftwareKind.Application, ExternalId: "unifi-network-application"));
        }
        if (s.ApiKey) r.Warnings.Add("Port forwards and VPN servers are not in the UniFi Network API; use a local view-only account for exposure.");
        _log.LogInformation("UniFi: {Assets} devices, {Exposures} exposure records", r.Assets.Count, r.Exposures.Count);
        return r;
    }

    // ------------------------------------------------------------------ mapping

    public sealed record Device(string Id, string Name, AssetKind Kind, string Product, string? ModelCode, string? Version, string? Mac, List<string?> Ips, bool Gateway);

    /// <summary>Model code or display model ("UDMPRO", "UDM Pro", "UCG Ultra") to the CVE product name ("UDM-Pro", "UCG-Ultra").</summary>
    public static string ProductName(string? model)
    {
        if (string.IsNullOrWhiteSpace(model)) return "UniFi device";
        var m = model.Trim();
        if (ModelNames.TryGetValue(m, out var n)) return n;
        // the official API reports display models ("UDM Pro", "UCG Ultra"); the CVE records hyphenate them
        return m.StartsWith("Express", StringComparison.OrdinalIgnoreCase) ? m : m.Replace(' ', '-');
    }

    public static bool IsConsole(string product) => ConsolePrefixes.Any(p => product.StartsWith(p, StringComparison.OrdinalIgnoreCase));

    private static AssetKind KindFromType(string? type, string product) => (type ?? "").ToLowerInvariant() switch
    {
        "udm" or "ugw" or "uxg" => AssetKind.Firewall,
        "usw" => AssetKind.Switch,
        "uap" => AssetKind.AccessPoint,
        _ => IsConsole(product) || product.StartsWith("UXG", StringComparison.OrdinalIgnoreCase) || product.StartsWith("USG", StringComparison.OrdinalIgnoreCase) ? AssetKind.Firewall
            : product.StartsWith("USW", StringComparison.OrdinalIgnoreCase) || product.StartsWith("US-", StringComparison.OrdinalIgnoreCase) ? AssetKind.Switch
            : product.StartsWith("U6", StringComparison.OrdinalIgnoreCase) || product.StartsWith("U7", StringComparison.OrdinalIgnoreCase) || product.StartsWith("UAP", StringComparison.OrdinalIgnoreCase) ? AssetKind.AccessPoint
            : AssetKind.NetworkDevice
    };

    /// <summary>A device from the application's own device list (stat/device).</summary>
    public static Device FromClassic(JsonElement d)
    {
        var code = Str(d, "model");
        var product = ProductName(code);
        var kind = KindFromType(Str(d, "type"), product);
        var mac = Str(d, "mac")?.ToLowerInvariant();
        var id = mac ?? Str(d, "serial") ?? Str(d, "_id") ?? "?"; // the MAC, as in API-key mode, so switching modes keeps the asset
        var ips = new List<string?> { Str(d, "ip"), Str(Obj(d, "wan1"), "ip"), Str(Obj(d, "wan2"), "ip"), Str(Obj(d, "config_network"), "ip") };
        return new Device(id, Str(d, "name") ?? mac ?? id, kind, product, code, Str(d, "version"), mac, ips, kind == AssetKind.Firewall);
    }

    /// <summary>A device from the official API: the list entry merged with its details (which carry firmwareVersion).</summary>
    public static Device FromIntegration(JsonElement listed, JsonElement detail)
    {
        var model = Str(detail, "model") ?? Str(listed, "model");
        var product = ProductName(model);
        var features = Names(listed, "features").Concat(Names(detail, "features")).ToList();
        if (detail.ValueKind == JsonValueKind.Object && detail.TryGetProperty("features", out var f) && f.ValueKind == JsonValueKind.Object)
            features.AddRange(f.EnumerateObject().Select(p => p.Name));
        var gateway = features.Any(x => x.Equals("gateway", StringComparison.OrdinalIgnoreCase)) || IsConsole(product) || product.StartsWith("UXG", StringComparison.OrdinalIgnoreCase);
        var kind = gateway ? AssetKind.Firewall : KindFromType(null, product);
        if (!gateway && kind == AssetKind.NetworkDevice && features.Any(x => x.Equals("accessPoint", StringComparison.OrdinalIgnoreCase))) kind = AssetKind.AccessPoint;
        if (!gateway && kind == AssetKind.NetworkDevice && features.Any(x => x.Equals("switching", StringComparison.OrdinalIgnoreCase))) kind = AssetKind.Switch;
        var mac = (Str(detail, "macAddress") ?? Str(listed, "macAddress"))?.ToLowerInvariant();
        var id = mac ?? Str(listed, "id") ?? "?";
        return new Device(id, Str(detail, "name") ?? Str(listed, "name") ?? id, kind, product, model, Str(detail, "firmwareVersion"), mac,
            new List<string?> { Str(detail, "ipAddress") ?? Str(listed, "ipAddress") }, gateway);
    }

    public static JsonElement Obj(JsonElement e, string name) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) ? v : default;

    public static ExposureRecord? PortForward(JsonElement pf)
    {
        if (!Enabled(pf, "enabled", true)) return null;
        var target = EdgeRecords.SingleHost(Str(pf, "fwd"));
        if (target is null) return null;
        var src = Str(pf, "src") ?? "any";
        return new ExposureRecord(Exposure.Internet,
            "port forward '" + (Str(pf, "name") ?? "?") + "' " + (Str(pf, "proto") ?? "tcp_udp") + " " + (Str(pf, "pfwd_interface") ?? "wan") + ":" + (Str(pf, "dst_port") ?? "?") + " -> " + target + ":" + (Str(pf, "fwd_port") ?? "?") + " from " + src,
            IpAddress: target);
    }

    public sealed record Vpn(int Port, string Protocol, string Label);

    /// <summary>An enabled remote-user VPN server (WireGuard, OpenVPN, L2TP) listens on the gateway's WAN.</summary>
    public static Vpn? VpnServer(JsonElement net)
    {
        if (!(Str(net, "purpose") ?? "").Equals("remote-user-vpn", StringComparison.OrdinalIgnoreCase) || !Enabled(net, "enabled", true)) return null;
        var type = (Str(net, "vpn_type") ?? "").ToLowerInvariant();
        if (type.Contains("wireguard")) return new Vpn(Int(net, "wireguard_local_wan_port", "local_port") ?? 51820, "udp", "WireGuard VPN server '" + (Str(net, "name") ?? "?") + "'");
        if (type.Contains("openvpn")) return new Vpn(Int(net, "openvpn_local_port", "local_port") ?? 1194, (Str(net, "openvpn_protocol") ?? "udp").ToLowerInvariant().Contains("tcp") ? "tcp" : "udp", "OpenVPN server '" + (Str(net, "name") ?? "?") + "'");
        if (type.Contains("l2tp")) return new Vpn(1701, "udp", "L2TP VPN server '" + (Str(net, "name") ?? "?") + "'");
        return new Vpn(0, "udp", "remote-access VPN server '" + (Str(net, "name") ?? "?") + "' (" + type + ")");
    }

    // ------------------------------------------------------------------ session

    private sealed class Session : IAsyncDisposable
    {
        private readonly EdgeHttp _http;
        private readonly string _prefix; // "proxy/network/" on UniFi OS, "" on a self-hosted application
        private string? _cookie; private string? _csrf;
        public bool ApiKey { get; }
        public bool UniFiOs { get; }

        private Session(EdgeHttp http, bool apiKey, bool unifiOs) { _http = http; ApiKey = apiKey; UniFiOs = unifiOs; _prefix = unifiOs ? "proxy/network/" : ""; }

        public static async Task<Session> OpenAsync(UniFiGatewayAdapter a, IReadOnlyDictionary<string, string> c, CancellationToken ct)
        {
            var host = FwCreds.Host(FwCreds.Get(c, "host"));
            if (host.Length == 0) throw new InvalidOperationException("Console or controller address is required");
            var key = FwCreds.Secret(c, "apiKey").Trim();
            var verify = FwCreds.Bool(c, "verifyTls", true);
            if (key.Length > 0)
                return new Session(new EdgeHttp(a._http, verify, "https://" + host, req => req.Headers.TryAddWithoutValidation("X-API-KEY", key), Explain), true, true);

            var user = FwCreds.Get(c, "username"); var pw = FwCreds.Secret(c, "password");
            if (user.Length == 0 || pw.Length == 0) throw new InvalidOperationException("Enter an API key, or a local username and password");
            Session? s = null;
            var http = new EdgeHttp(a._http, verify, "https://" + host, req => s?.Authorise(req), Explain);
            var body = JsonSerializer.Serialize(new { username = user, password = pw, rememberMe = false });
            HttpResponseHeaders headers; bool unifiOs = true;
            try { (_, headers) = await http.SendAsync(HttpMethod.Post, "api/auth/login", () => new StringContent(body, Encoding.UTF8, "application/json"), null, ct); }
            catch (FirewallApiException ex) when (ex.Status == 404)
            {
                unifiOs = false; // a self-hosted Network application
                (_, headers) = await http.SendAsync(HttpMethod.Post, "api/login", () => new StringContent(body, Encoding.UTF8, "application/json"), null, ct);
            }
            s = new Session(http, false, unifiOs);
            var cookies = new List<string>();
            if (headers.TryGetValues("Set-Cookie", out var set))
                foreach (var sc in set)
                {
                    var pair = sc.Split(';')[0].Trim();
                    var eq = pair.IndexOf('=');
                    if (eq <= 0) continue;
                    cookies.Add(pair);
                    if (pair[..eq].Equals("csrf_token", StringComparison.OrdinalIgnoreCase)) s._csrf = pair[(eq + 1)..];
                }
            if (headers.TryGetValues("X-CSRF-Token", out var csrf)) s._csrf = csrf.FirstOrDefault() ?? s._csrf;
            if (cookies.Count == 0) throw new FirewallApiException("POST login", 200, "the console did not return a session cookie");
            s._cookie = string.Join("; ", cookies);
            return s;
        }

        private void Authorise(HttpRequestMessage req)
        {
            if (_cookie is not null) req.Headers.TryAddWithoutValidation("Cookie", _cookie);
            if (_csrf is not null) req.Headers.TryAddWithoutValidation("X-CSRF-Token", _csrf);
        }

        public async Task<string?> AppVersionAsync(CancellationToken ct)
        {
            try
            {
                if (ApiKey) return Str(Parse(await _http.GetAsync(IntegrationBase + "/info", ct)), "applicationVersion");
                var sys = Data(Parse(await _http.GetAsync(_prefix + "api/s/default/stat/sysinfo", ct))).FirstOrDefault();
                return Str(sys, "version");
            }
            catch (FirewallApiException ex) when (ex.Status is 404 or 400) { return null; }
        }

        public async Task<List<(string Id, string Name)>> SitesAsync(IReadOnlyDictionary<string, string> c, CancellationToken ct)
        {
            var wanted = FwCreds.Get(c, "site");
            List<(string Id, string Name)> sites;
            if (ApiKey)
                sites = (await PagedAsync(IntegrationBase + "/sites", ct)).Select(x => (Str(x, "id") ?? "", Str(x, "internalReference") ?? Str(x, "name") ?? "")).ToList();
            else
                sites = Data(Parse(await _http.GetAsync(_prefix + "api/self/sites", ct))).Select(x => (Str(x, "name") ?? "", Str(x, "name") ?? "")).ToList();
            sites = sites.Where(x => x.Id.Length > 0).ToList();
            if (wanted.Length > 0)
            {
                sites = sites.Where(x => x.Name.Equals(wanted, StringComparison.OrdinalIgnoreCase) || x.Id.Equals(wanted, StringComparison.OrdinalIgnoreCase)).ToList();
                if (sites.Count == 0) throw new FirewallApiException("sites", 200, "site '" + wanted + "' not found");
            }
            return sites;
        }

        public async Task<List<Device>> ClassicDevicesAsync(string site, CancellationToken ct) =>
            Data(Parse(await _http.GetAsync(_prefix + "api/s/" + Uri.EscapeDataString(site) + "/stat/device", ct))).Select(FromClassic).ToList();

        public async Task<List<Device>> IntegrationDevicesAsync(string siteId, CancellationToken ct)
        {
            var list = new List<Device>();
            foreach (var d in await PagedAsync(IntegrationBase + "/sites/" + siteId + "/devices", ct))
            {
                var detail = Str(d, "id") is { } id ? Parse(await _http.GetAsync(IntegrationBase + "/sites/" + siteId + "/devices/" + id, ct)) : default;
                list.Add(FromIntegration(d, detail));
            }
            return list;
        }

        public async Task<List<JsonElement>> ClassicListAsync(string site, string what, CollectResult r, CancellationToken ct)
        {
            try { return Data(Parse(await _http.GetAsync(_prefix + "api/s/" + Uri.EscapeDataString(site) + "/" + what, ct))); }
            catch (FirewallApiException ex) when (ex.Status != 401) { r.Warnings.Add("Skipped " + what + ": " + ex.Message); return new(); }
        }

        /// <summary>The official API's offset/limit pages until totalCount is reached.</summary>
        private async Task<List<JsonElement>> PagedAsync(string path, CancellationToken ct)
        {
            var all = new List<JsonElement>();
            for (var offset = 0; offset < 100_000;)
            {
                var page = Parse(await _http.GetAsync(path + "?offset=" + offset + "&limit=" + PageSize, ct));
                var data = Array(page, "data").ToList();
                all.AddRange(data);
                var total = Int(page, "totalCount") ?? all.Count;
                offset += data.Count;
                if (data.Count == 0 || offset >= total) break;
            }
            return all;
        }

        /// <summary>The application's own API envelope: {"meta":{"rc":"ok"},"data":[...]}; rc "error" becomes an exception.</summary>
        private static List<JsonElement> Data(JsonElement root)
        {
            var meta = Obj(root, "meta");
            if ((Str(meta, "rc") ?? "ok") != "ok") throw new FirewallApiException("UniFi", 200, Str(meta, "msg") ?? "the application returned an error");
            return Array(root, "data").ToList();
        }

        public async ValueTask DisposeAsync()
        {
            if (ApiKey || _cookie is null) return;
            try { await _http.SendAsync(HttpMethod.Post, UniFiOs ? "api/auth/logout" : "api/logout", () => new StringContent("{}", Encoding.UTF8, "application/json"), null, CancellationToken.None); }
            catch { /* logging out is best effort */ }
        }
    }

    private static string? Explain(int status) => status switch
    {
        401 => "the console rejected the API key or the username and password (a UI account with two-factor sign-in cannot be used; create a local account)",
        403 => "the account's role does not allow this (give it the View Only role for the Network application)",
        429 => "too many login attempts; the console is rate-limiting",
        _ => null
    };
}
