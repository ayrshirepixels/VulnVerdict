using System.Net;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Firewalls;

/// <summary>A call to a firewall's management interface failed. The message never contains credentials.</summary>
public sealed class FirewallApiException : Exception
{
    public string Path { get; }
    public int Status { get; }
    public FirewallApiException(string path, int status, string detail) : base(path + (status > 0 ? ": HTTP " + status : ":") + (detail.Length > 0 ? " " + detail : ""))
    {
        Path = path; Status = status;
    }
}

/// <summary>Credential-form access shared by the firewall adapters.</summary>
public static class FwCreds
{
    public static string Get(IReadOnlyDictionary<string, string> creds, string key) => creds.TryGetValue(key, out var v) && v is not null ? v.Trim() : "";

    /// <summary>The raw value (not trimmed): passwords may legitimately start or end with a space.</summary>
    public static string Secret(IReadOnlyDictionary<string, string> creds, string key) => creds.TryGetValue(key, out var v) && v is not null ? v : "";

    public static bool Bool(IReadOnlyDictionary<string, string> creds, string key, bool dflt)
    {
        var v = Get(creds, key);
        if (v.Length == 0) return dflt;
        return v.Equals("true", StringComparison.OrdinalIgnoreCase) || v == "1" || v.Equals("yes", StringComparison.OrdinalIgnoreCase) || v.Equals("on", StringComparison.OrdinalIgnoreCase);
    }

    public static int Int(IReadOnlyDictionary<string, string> creds, string key, int dflt) => int.TryParse(Get(creds, key), out var i) && i > 0 ? i : dflt;

    /// <summary>"https://fw.example.local:4444/" or "fw.example.local:4444" to "fw.example.local:4444".</summary>
    public static string Host(string raw)
    {
        var h = raw.Trim();
        if (h.Contains("://", StringComparison.Ordinal)) h = h[(h.IndexOf("://", StringComparison.Ordinal) + 3)..];
        var slash = h.IndexOf('/');
        if (slash >= 0) h = h[..slash];
        return h;
    }

    /// <summary>Host with <paramref name="defaultPort"/> appended when the form value has no port.</summary>
    public static string HostWithPort(string raw, int defaultPort)
    {
        var h = Host(raw);
        if (h.Length == 0) return h;
        if (h.StartsWith('[')) return h.Contains("]:", StringComparison.Ordinal) ? h : h + ":" + defaultPort;
        return h.Contains(':') ? h : h + ":" + defaultPort;
    }

    /// <summary>The host part only (no port), for SNMP and SSH.</summary>
    public static string HostOnly(string raw)
    {
        var h = Host(raw);
        if (h.StartsWith('[')) { var end = h.IndexOf(']'); return end > 0 ? h[1..end] : h; }
        var colon = h.LastIndexOf(':');
        return colon > 0 && h.IndexOf(':') == colon ? h[..colon] : h;
    }

    /// <summary>True when the form carries enough to try SNMP (a community, or an SNMPv3 user name).</summary>
    public static bool HasSnmp(IReadOnlyDictionary<string, string> creds) => Secret(creds, "community").Length > 0 || Get(creds, "snmpUser").Length > 0;

    /// <summary>The SNMP fields of a firewall form, renamed to what <see cref="Snmp.SnmpAdapter.QueryAsync"/> reads.</summary>
    public static Dictionary<string, string> SnmpFields(IReadOnlyDictionary<string, string> creds)
    {
        var d = new Dictionary<string, string>(StringComparer.Ordinal);
        var community = Secret(creds, "community");
        var user = Get(creds, "snmpUser");
        d["version"] = community.Length > 0 && user.Length == 0 ? "2c" : "3";
        d["community"] = community;
        d["username"] = user;
        d["authProtocol"] = Get(creds, "snmpAuthProtocol") is { Length: > 0 } ap ? ap : "SHA";
        d["authPassword"] = Secret(creds, "snmpAuthPassword");
        d["privProtocol"] = Get(creds, "snmpPrivProtocol") is { Length: > 0 } pp ? pp : (Secret(creds, "snmpPrivPassword").Length > 0 ? "AES" : "");
        d["privPassword"] = Secret(creds, "snmpPrivPassword");
        d["timeoutMs"] = Get(creds, "snmpTimeoutMs") is { Length: > 0 } t ? t : "3000";
        return d;
    }

    /// <summary>The optional SNMP credential fields a firewall form offers when firmware comes over SNMP.</summary>
    public static CredentialField[] SnmpFormFields(string purpose) => new[]
    {
        new CredentialField("community", "SNMP community (v2c)", CredentialTypes.Password, purpose + " Read-only community. Leave blank when using SNMPv3 or when SNMP is not enabled.", Required: false),
        new CredentialField("snmpUser", "SNMPv3 user name", CredentialTypes.Text, "Only for SNMPv3; leave blank for v2c.", Required: false),
        new CredentialField("snmpAuthProtocol", "SNMPv3 authentication protocol", CredentialTypes.Text, "SHA, SHA256 or MD5", Required: false, Default: "SHA"),
        new CredentialField("snmpAuthPassword", "SNMPv3 authentication password", CredentialTypes.Password, null, Required: false),
        new CredentialField("snmpPrivProtocol", "SNMPv3 privacy protocol", CredentialTypes.Text, "AES or DES; blank for authNoPriv", Required: false),
        new CredentialField("snmpPrivPassword", "SNMPv3 privacy password", CredentialTypes.Password, null, Required: false),
    };

    public static CredentialField VerifyTlsField(string device) =>
        new("verifyTls", "Verify TLS certificate", CredentialTypes.Bool, "Turn off only for the " + device + "'s factory self-signed certificate.", Required: false, Default: "true");
}

/// <summary>
/// Vendor and product names exactly as the CNAs write them in CVE List V5 "affected" entries, so firmware records
/// resolve to the CVE catalogue without a mapping step. Each constant names the CVE records it was checked against.
/// Where a CNA spells the same product more than one way, the adapters emit the firmware once per spelling
/// (see <see cref="EdgeRecords.Firmware"/>); the secondary spellings are listed next to the primary one.
/// </summary>
public static class CnaNames
{
    // Sophos CNA: CVE-2022-1040, CVE-2022-3236, CVE-2024-12727, CVE-2024-12728, CVE-2025-6704, CVE-2025-7624
    public const string Sophos = "Sophos";
    public const string SophosFirewall = "Sophos Firewall";

    // WatchGuard CNA: CVE-2025-9242, CVE-2025-14733
    public const string WatchGuard = "WatchGuard";
    public const string Fireware = "Fireware OS";

    // Cisco CNA: CVE-2025-20271, CVE-2025-20212, CVE-2024-20509
    public const string Cisco = "Cisco";
    public const string MerakiMx = "Cisco Meraki MX Firmware";

    // Palo Alto Networks CNA: CVE-2024-3400, CVE-2024-0012, CVE-2025-0108
    public const string PaloAlto = "Palo Alto Networks";
    public const string PanOs = "PAN-OS";

    // Check Point CNA (vendor written "checkpoint", which normalises the same as "Check Point"):
    // CVE-2026-50751 "Spark Firewalls"; CVE-2024-24919 "Check Point Quantum Gateway, Spark Gateway and CloudGuard Network"
    public const string CheckPoint = "Check Point";
    public const string SparkFirewalls = "Spark Firewalls";
    public const string SparkLegacy = "Check Point Quantum Gateway, Spark Gateway and CloudGuard Network";

    // SonicWall CNA: CVE-2024-40766, CVE-2024-53704
    public const string SonicWall = "SonicWall";
    public const string SonicOs = "SonicOS";

    // Zyxel CNA: series names in CVE-2023-28771, CVE-2024-11667, CVE-2024-42057, CVE-2024-7203, CVE-2025-9133;
    // per-model names ("USG FLEX 100(W) firmware") in CVE-2022-30525; uOS in CVE-2025-1731, CVE-2025-1732
    public const string Zyxel = "Zyxel";
    public const string ZyxelUsgFlexSeries = "USG FLEX series firmware";
    public const string ZyxelAtpSeries = "ATP series firmware";
    public const string ZyxelUsgFlex50Series = "USG FLEX 50(W) series firmware";
    public const string ZyxelUsg20VpnSeries = "USG20(W)-VPN series firmware";
    public const string ZyxelVpnSeries = "VPN series firmware";
    public const string ZyxelUsgFlexHuOs = "USG FLEX H series uOS firmware";

    // HackerOne as CNA for Ubiquiti (vendor "Ubiquiti Inc", normalises to "ubiquiti"): CVE-2023-31997 "UniFi OS";
    // CVE-2026-34908, CVE-2026-34911 per console model ("UDM-Pro", "UCG-Max", ...); CVE-2024-42028 "UniFi Network Application"
    public const string Ubiquiti = "Ubiquiti Inc";
    public const string UniFiOs = "UniFi OS";
    public const string UniFiNetworkApplication = "UniFi Network Application";

    // pfSense and OPNsense CVEs are mostly assigned by MITRE with vendor and product "n/a" (CVE-2023-42325,
    // CVE-2023-48123, CVE-2024-57273 for pfSense; CVE-2023-27152, CVE-2023-44275, CVE-2023-38999 for OPNsense), so no
    // spelling matches those. VulnCheck writes "Netgate" / "pfSense CE" (CVE-2025-34173, a package); the CISA ADP
    // container sometimes adds "pfsense" / "pfsense" (CVE-2024-46538).
    public const string Netgate = "Netgate";
    public const string PfSenseCe = "pfSense CE";
    public const string PfSensePlus = "pfSense Plus";
    public const string Deciso = "Deciso";
    public const string OpnSense = "OPNsense";
}

/// <summary>Builders for the records every firewall adapter emits, so they all look the same to the inventory service.</summary>
public static class EdgeRecords
{
    /// <summary>
    /// The firmware software record for an asset, plus one record per secondary CNA spelling (external ids
    /// "<paramref name="externalId"/>", "<paramref name="externalId"/>:alt1", ...). Listeners go on the primary only.
    /// </summary>
    public static IEnumerable<SoftwareRecord> Firmware(string assetId, string vendor, string product, string version, string externalId,
        IEnumerable<string>? alsoKnownAs = null, Listener[]? listeners = null, string? edition = null, SoftwareKind kind = SoftwareKind.Firmware)
    {
        yield return new SoftwareRecord(assetId, vendor, product, version, kind, ExternalId: externalId, Edition: edition, Listeners: listeners is { Length: > 0 } ? listeners : null);
        var i = 0;
        foreach (var alt in alsoKnownAs ?? Enumerable.Empty<string>())
        {
            if (alt.Equals(product, StringComparison.OrdinalIgnoreCase)) continue;
            yield return new SoftwareRecord(assetId, vendor, alt, version, kind, ExternalId: externalId + ":alt" + (++i), Edition: edition);
        }
    }

    public static AssetRecord Firewall(string id, string name, IEnumerable<string?> ips, IEnumerable<string?> macs, string osVendor, string osProduct, string? osVersion, string? osBuild = null, IEnumerable<string?>? hostnames = null) =>
        new(id, name, AssetKind.Firewall,
            (hostnames ?? new[] { name }).Where(h => !string.IsNullOrWhiteSpace(h) && !IPAddress.TryParse(h, out _)).Select(h => h!.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            ips.Where(ip => IsUsableIp(ip)).Select(ip => ip!.Trim()).Distinct().ToArray(),
            macs.Where(m => !Fortinet.FortinetJson.IsZeroMac(m)).Select(m => m!.Trim().ToLowerInvariant().Replace('-', ':')).Distinct().ToArray(),
            OsVendor: osVendor, OsProduct: osProduct, OsVersion: osVersion, OsBuild: osBuild, Criticality: Criticality.Critical);

    public static bool IsUsableIp(string? ip) => !string.IsNullOrWhiteSpace(ip) && IPAddress.TryParse(ip.Trim(), out var a)
        && !a.Equals(IPAddress.Any) && !a.Equals(IPAddress.IPv6Any) && !IPAddress.IsLoopback(a);

    /// <summary>First address of "192.0.2.1/24", "192.0.2.1 255.255.255.0" or "192.0.2.1-192.0.2.9"; null when it is not an address.</summary>
    public static string? FirstIp(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        var t = s.Trim().Split(new[] { ' ', '/', '-' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        return t is not null && IsUsableIp(t) ? t : null;
    }

    /// <summary>A single host address: a bare IP or /32; null for networks, ranges and names.</summary>
    public static string? SingleHost(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        var t = s.Trim();
        if (t.EndsWith("/32", StringComparison.Ordinal)) t = t[..^3];
        return IPAddress.TryParse(t, out var a) && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && IsUsableIp(t) ? t : null;
    }
}

/// <summary>
/// Collects what listens on the firewall itself and which of it faces the internet, then emits the listeners on the
/// firmware record and one Internet exposure record for the device (same shape as the FortiGate adapter).
/// </summary>
public sealed class DeviceExposure
{
    private readonly List<Listener> _listeners = new();
    private readonly List<string> _evidence = new();

    public void Add(int port, string protocol, string bind, string process, bool internetFacing, string evidence)
    {
        if (!_listeners.Any(l => l.Port == port && l.Protocol == protocol && l.Bind == bind && l.Process == process))
            _listeners.Add(new Listener(port, protocol, bind, process));
        if (internetFacing && !_evidence.Contains(evidence)) _evidence.Add(evidence);
    }

    public void Evidence(string evidence) { if (!_evidence.Contains(evidence)) _evidence.Add(evidence); }

    public Listener[] Listeners => _listeners.ToArray();
    public bool InternetFacing => _evidence.Count > 0;

    public ExposureRecord? Record(string assetId) => _evidence.Count == 0 ? null : new ExposureRecord(Exposure.Internet, string.Join("; ", _evidence), AssetExternalId: assetId);
}

/// <summary>Version strings as the vendors print them, turned into the form the CNAs compare against.</summary>
public static partial class EdgeVersions
{
    [GeneratedRegex(@"(\d+(?:\.\d+)+(?:-h\d+)?(?:-\d+[a-z]?)?)", RegexOptions.IgnoreCase)] private static partial Regex DottedRx();

    /// <summary>First dotted version in the text: "SonicOS 7.1.1-7058" to "7.1.1-7058", "Fireware 12.10.4 B698735" to "12.10.4".</summary>
    public static string? Dotted(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        var m = DottedRx().Match(s);
        return m.Success ? m.Groups[1].Value : null;
    }
}

/// <summary>
/// GET/POST with a shared named HttpClient ("adapter" or "adapter-insecure"), status codes mapped to
/// <see cref="FirewallApiException"/> with a vendor-specific hint, and 429 Retry-After honoured.
/// </summary>
public sealed class EdgeHttp
{
    private readonly HttpClient _client;
    private readonly string _base;
    private readonly Action<HttpRequestMessage>? _authorise;
    private readonly Func<int, string?> _explain;

    /// <summary>How long to wait before a retry after 429 or 503; tests replace it so nothing sleeps.</summary>
    public Func<TimeSpan, CancellationToken, Task> Delay { get; set; } = (t, ct) => Task.Delay(t, ct);
    public int MaxRetries { get; set; } = 4;

    public EdgeHttp(IHttpClientFactory factory, bool verifyTls, string baseUrl, Action<HttpRequestMessage>? authorise, Func<int, string?> explain)
    {
        _client = factory.CreateClient(verifyTls ? "adapter" : "adapter-insecure");
        _base = baseUrl.TrimEnd('/');
        _authorise = authorise; _explain = explain;
    }

    public string Url(string path) => path.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? path : _base + "/" + path.TrimStart('/');

    public async Task<string> GetAsync(string path, CancellationToken ct) => (await SendAsync(HttpMethod.Get, path, null, null, ct)).Body;

    public async Task<(string Body, HttpResponseHeaders Headers)> SendAsync(HttpMethod method, string path, Func<HttpContent>? content, Action<HttpRequestMessage>? extra, CancellationToken ct)
    {
        for (var attempt = 0; ; attempt++)
        {
            using var req = new HttpRequestMessage(method, Url(path));
            if (content is not null) req.Content = content();
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            _authorise?.Invoke(req);
            extra?.Invoke(req);
            using var resp = await _client.SendAsync(req, HttpCompletionOption.ResponseContentRead, ct);
            var status = (int)resp.StatusCode;
            if ((status == 429 || status == 503) && attempt < MaxRetries)
            {
                TimeSpan? fromDate = resp.Headers.RetryAfter?.Date is { } d ? d - DateTimeOffset.UtcNow : null;
                var wait = resp.Headers.RetryAfter?.Delta ?? fromDate ?? TimeSpan.FromSeconds(1 << attempt);
                if (wait < TimeSpan.Zero) wait = TimeSpan.Zero;
                if (wait > TimeSpan.FromSeconds(60)) wait = TimeSpan.FromSeconds(60);
                await Delay(wait, ct);
                continue;
            }
            var body = await resp.Content.ReadAsStringAsync(ct);
            if (!resp.IsSuccessStatusCode)
                throw new FirewallApiException(method.Method + " " + StripQuery(path), status, _explain(status) ?? resp.ReasonPhrase ?? "");
            return (body, resp.Headers);
        }
    }

    /// <summary>Paths can carry secrets in the query string on some APIs; errors show the path only.</summary>
    public static string StripQuery(string path)
    {
        var q = path.IndexOf('?');
        return q >= 0 ? path[..q] : path;
    }
}
