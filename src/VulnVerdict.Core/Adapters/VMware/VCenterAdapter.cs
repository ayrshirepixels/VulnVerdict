using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.VMware;

/// <summary>
/// An authenticated vSphere Automation API session. GetAsync returns null when the endpoint answers 404, 503 or 400
/// (typical for guest endpoints on a powered-off VM or one without VMware Tools) and throws on authentication or
/// server failures. Tests substitute a dictionary-backed fake.
/// </summary>
public interface IVCenterSession : IAsyncDisposable
{
    Task<JsonDocument?> GetAsync(string path, CancellationToken ct);
}

/// <summary>
/// VMware vCenter through the vSphere Automation REST API. Emits the vCenter appliance, every
/// ESXi host and the complete VM list (the coverage reconciliation set: a VM with no WinRM or SSH record shows as
/// "unknown coverage"). Only GET calls are made after the session is created; nothing is written to vCenter.
/// </summary>
public sealed class VCenterAdapter : IInventoryAdapter
{
    public const string Id = "vcenter";

    private readonly IHttpClientFactory _http;
    private readonly ILogger<VCenterAdapter> _log;

    public VCenterAdapter(IHttpClientFactory http, ILogger<VCenterAdapter> log)
    {
        _http = http; _log = log;
        SessionFactory = (baseUrl, user, password, verifyTls, ct) => RestSession.LoginAsync(_http.CreateClient(verifyTls ? "adapter" : "adapter-insecure"), baseUrl, user, password, ct);
    }

    /// <summary>(baseUrl, username, password, verifyTls, ct) to session. Tests substitute a fake.</summary>
    public Func<string, string, string, bool, CancellationToken, Task<IVCenterSession>> SessionFactory { get; set; }

    public int MaxParallelVmCalls { get; set; } = 4;

    public AdapterMetadata Metadata { get; } = new(
        Id,
        "VMware vCenter (hosts and VM list)",
        "VMware",
        "Reads the vCenter version, the ESXi host list and the complete virtual machine list with guest hostnames, IP and MAC addresses through the vSphere Automation REST API. VMs that no server collector has seen appear on the dashboard as unknown coverage.",
        new[] { AssetKind.Server, AssetKind.Hypervisor, AssetKind.VirtualMachine },
        new[]
        {
            new CredentialField("host", "vCenter host", CredentialTypes.Text, "Hostname or IP of the vCenter Server appliance (https is assumed)."),
            new CredentialField("username", "Username", CredentialTypes.Text, "For example vulnverdict@vsphere.local. Assign the Read-Only role at the vCenter root, propagated to children."),
            new CredentialField("password", "Password", CredentialTypes.Password),
            new CredentialField("verifyTls", "Verify TLS certificate", CredentialTypes.Bool, "Turn off only for a vCenter with a self-signed certificate.", Required: false, Default: "true"),
        },
        "a vCenter user with the Read-Only role at the vCenter root",
        "https://developer.broadcom.com/xapis/vsphere-automation-api/latest/",
        DefaultIntervalMinutes: 240);

    // ------------------------------------------------------------------ IInventoryAdapter

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        var host = Get(credentials, "host");
        if (host == "") return new(false, "Enter the vCenter host.");
        if (Get(credentials, "username") == "" || Get(credentials, "password") == "") return new(false, "Enter a username and password.");
        try
        {
            await using var s = await SessionFactory(BaseUrl(host), Get(credentials, "username"), Get(credentials, "password"), GetBool(credentials, "verifyTls", true), ct);
            using var version = await s.GetAsync("/api/appliance/system/version", ct);
            using var hosts = await s.GetAsync("/api/vcenter/host", ct);
            using var vms = await s.GetAsync("/api/vcenter/vm", ct);
            var (ver, build) = version is null ? (null, null) : ParseVersion(version.RootElement);
            var hostCount = hosts is null ? 0 : Unwrap(hosts.RootElement).GetArrayLength();
            var vmCount = vms is null ? 0 : Unwrap(vms.RootElement).GetArrayLength();
            return new(true, "Connected to vCenter Server " + (ver ?? "(version not readable)") + (build is null ? "" : " build " + build) + ": " + hostCount + " ESXi hosts, " + vmCount + " VMs.");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { return new(false, ex.Message); }
    }

    public async Task<CollectResult> CollectAsync(IReadOnlyDictionary<string, string> credentials, DateTime? since, IProgress<string>? progress, CancellationToken ct)
    {
        var host = Get(credentials, "host");
        await using var s = await SessionFactory(BaseUrl(host), Get(credentials, "username"), Get(credentials, "password"), GetBool(credentials, "verifyTls", true), ct);
        return await CollectFromAsync(s, host, MaxParallelVmCalls, progress, ct);
    }

    // ------------------------------------------------------------------ collection against a session

    public static async Task<CollectResult> CollectFromAsync(IVCenterSession s, string vcenterHost, int parallel, IProgress<string>? progress, CancellationToken ct)
    {
        var r = new CollectResult();
        var hostName = HostPart(vcenterHost);
        var vcId = "vcenter:" + hostName.ToLowerInvariant();

        // the appliance itself
        string? ver = null, build = null;
        using (var version = await s.GetAsync("/api/appliance/system/version", ct))
        {
            if (version is not null) (ver, build) = ParseVersion(version.RootElement);
            else r.Warnings.Add("vCenter version not readable (/api/appliance/system/version); the appliance is listed without a version");
        }
        var hostIsIp = IsIp(hostName);
        r.Assets.Add(new AssetRecord(vcId, hostName, AssetKind.Server,
            hostIsIp ? Array.Empty<string>() : new[] { hostName }, hostIsIp ? new[] { hostName } : Array.Empty<string>(), Array.Empty<string>(),
            "VMware", "vCenter Server Appliance", ver, build, Criticality.Critical));
        if (ver is not null) r.Software.Add(new SoftwareRecord(vcId, "VMware", "vCenter Server", ver, SoftwareKind.Application, ExternalId: "vcenter-server"));

        // ESXi hosts
        var esxiVersionChecked = false; var esxiVersionAvailable = false;
        using (var hosts = await s.GetAsync("/api/vcenter/host", ct))
        {
            if (hosts is null) r.Warnings.Add("ESXi host list not readable (/api/vcenter/host)");
            else
            {
                var list = Unwrap(hosts.RootElement);
                progress?.Report(list.GetArrayLength() + " ESXi hosts");
                foreach (var h in list.EnumerateArray())
                {
                    var asset = MapHost(h);
                    r.Assets.Add(asset);
                    if (esxiVersionChecked && !esxiVersionAvailable) continue;
                    string? v = null;
                    using (var detail = await s.GetAsync("/api/vcenter/host/" + asset.ExternalId, ct) ?? await s.GetAsync("/rest/vcenter/host/" + asset.ExternalId, ct))
                        if (detail is not null) v = FindVersion(detail.RootElement);
                    if (!esxiVersionChecked)
                    {
                        esxiVersionChecked = true; esxiVersionAvailable = v is not null;
                        if (v is null) r.Warnings.Add("ESXi version is not exposed by the vCenter REST API on this release; ESXi hosts are listed without a software version");
                    }
                    if (v is not null) r.Software.Add(new SoftwareRecord(asset.ExternalId, "VMware", "ESXi", v, SoftwareKind.OperatingSystem, ExternalId: "esxi"));
                }
            }
        }

        // virtual machines
        using (var vms = await s.GetAsync("/api/vcenter/vm", ct))
        {
            if (vms is null) { r.Warnings.Add("VM list not readable (/api/vcenter/vm)"); return r; }
            var list = Unwrap(vms.RootElement).EnumerateArray().ToList();
            var mapped = new AssetRecord?[list.Count];
            var noIdentity = 0; var done = 0;
            using var gate = new SemaphoreSlim(Math.Max(1, parallel));
            await Task.WhenAll(list.Select(async (vm, i) =>
            {
                await gate.WaitAsync(ct);
                try
                {
                    var id = Str(vm, "vm");
                    if (id == "") return;
                    using var detail = await s.GetAsync("/api/vcenter/vm/" + id, ct);
                    using var identity = await s.GetAsync("/api/vcenter/vm/" + id + "/guest/identity", ct);
                    using var interfaces = await s.GetAsync("/api/vcenter/vm/" + id + "/guest/networking/interfaces", ct);
                    if (identity is null) Interlocked.Increment(ref noIdentity);
                    mapped[i] = MapVm(vm, identity?.RootElement, interfaces?.RootElement, detail?.RootElement);
                }
                finally
                {
                    gate.Release();
                    var n = Interlocked.Increment(ref done);
                    if (n % 25 == 0 || n == list.Count) progress?.Report(n + "/" + list.Count + " VMs");
                }
            }));
            foreach (var m in mapped) if (m is not null) r.Assets.Add(m);
            if (noIdentity > 0) r.Warnings.Add(noIdentity + " of " + list.Count + " VMs report no guest identity (VMware Tools not running or VM powered off); they are listed by name and MAC address only");
        }
        return r;
    }

    // ------------------------------------------------------------------ mapping

    public static AssetRecord MapHost(JsonElement h)
    {
        var id = Str(h, "host");
        var name = Str(h, "name");
        var isIp = IsIp(name);
        return new AssetRecord(id, name, AssetKind.Hypervisor,
            isIp || name == "" ? Array.Empty<string>() : new[] { name },
            isIp ? new[] { name } : Array.Empty<string>(),
            Array.Empty<string>(),
            "VMware", "ESXi", null, null, Criticality.Critical);
    }

    /// <summary>VM list entry plus optional guest identity, guest interfaces and the VM detail (nics, guest_OS).</summary>
    public static AssetRecord MapVm(JsonElement vm, JsonElement? identity, JsonElement? interfaces, JsonElement? detail)
    {
        var id = Str(vm, "vm");
        var name = Str(vm, "name");
        var hostnames = new List<string>(); var ips = new List<string>(); var macs = new List<string>();
        string? osProduct = null;

        if (identity is { } idn && idn.ValueKind == JsonValueKind.Object)
        {
            var idnU = Unwrap(idn);
            var hn = Str(idnU, "host_name");
            if (hn != "" && !IsIp(hn)) hostnames.Add(hn);
            AddIp(ips, Str(idnU, "ip_address"));
            if (idnU.TryGetProperty("full_name", out var fn))
                osProduct = fn.ValueKind == JsonValueKind.Object ? Str(fn, "default_message") : fn.ValueKind == JsonValueKind.String ? fn.GetString() : null;
            if (string.IsNullOrWhiteSpace(osProduct)) osProduct = Str(idnU, "name") is { Length: > 0 } code ? code : null;
        }
        if (interfaces is { } ifs)
        {
            var arr = Unwrap(ifs);
            if (arr.ValueKind == JsonValueKind.Array)
                foreach (var nic in arr.EnumerateArray())
                {
                    AddMac(macs, Str(nic, "mac_address"));
                    if (nic.TryGetProperty("ip", out var ip) && ip.ValueKind == JsonValueKind.Object && ip.TryGetProperty("ip_addresses", out var addrs) && addrs.ValueKind == JsonValueKind.Array)
                        foreach (var a in addrs.EnumerateArray()) AddIp(ips, Str(a, "ip_address"));
                }
        }
        if (detail is { } d)
        {
            var dU = Unwrap(d);
            if (dU.ValueKind == JsonValueKind.Object)
            {
                if (dU.TryGetProperty("nics", out var nics) && nics.ValueKind == JsonValueKind.Object)
                    foreach (var p in nics.EnumerateObject()) AddMac(macs, Str(p.Value, "mac_address"));
                if (osProduct is null && Str(dU, "guest_OS") is { Length: > 0 } g) osProduct = g;
            }
        }
        return new AssetRecord(id, name, AssetKind.VirtualMachine, hostnames.ToArray(), ips.ToArray(), macs.ToArray(), GuessOsVendor(osProduct), osProduct, null);
    }

    /// <summary>/api/appliance/system/version: "8.0.2.00100" becomes "8.0.2"; the build number is returned separately.</summary>
    public static (string? Version, string? Build) ParseVersion(JsonElement root)
    {
        var e = Unwrap(root);
        var v = Str(e, "version");
        var build = Str(e, "build");
        if (v == "") return (null, build == "" ? null : build);
        var parts = v.Split('.');
        var shortV = parts.Length > 3 ? string.Join(".", parts.Take(3)) : v;
        return (shortV, build == "" ? null : build);
    }

    private static string? FindVersion(JsonElement root)
    {
        var e = Unwrap(root);
        if (e.ValueKind != JsonValueKind.Object) return null;
        foreach (var key in new[] { "version", "product_version", "esxi_version" })
            if (Str(e, key) is { Length: > 0 } v) return v;
        return null;
    }

    public static string? GuessOsVendor(string? osName)
    {
        if (string.IsNullOrWhiteSpace(osName)) return null;
        var s = osName.ToLowerInvariant();
        if (s.Contains("windows")) return "Microsoft";
        if (s.Contains("ubuntu")) return "Canonical";
        if (s.Contains("debian")) return "Debian";
        if (s.Contains("red hat") || s.Contains("rhel")) return "Red Hat";
        if (s.Contains("centos")) return "CentOS";
        if (s.Contains("almalinux") || s.Contains("alma")) return "AlmaLinux";
        if (s.Contains("rocky")) return "Rocky Linux";
        if (s.Contains("suse")) return "SUSE";
        if (s.Contains("oracle")) return "Oracle";
        if (s.Contains("photon")) return "VMware";
        if (s.Contains("freebsd")) return "FreeBSD";
        if (s.Contains("fedora")) return "Fedora Project";
        if (s.Contains("linux")) return "Linux";
        return null;
    }

    // ------------------------------------------------------------------ helpers

    public static string BaseUrl(string host)
    {
        var h = host.Trim().TrimEnd('/');
        if (!h.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !h.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) h = "https://" + h;
        return h;
    }

    private static string HostPart(string host) => Uri.TryCreate(BaseUrl(host), UriKind.Absolute, out var u) ? u.Host : host.Trim();

    private static JsonElement Unwrap(JsonElement e) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty("value", out var v) ? v : e;

    private static string Str(JsonElement e, string prop)
    {
        if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(prop, out var v)) return "";
        return v.ValueKind switch
        {
            JsonValueKind.String => v.GetString() ?? "",
            JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False => v.ToString(),
            _ => ""
        };
    }

    private static bool IsIp(string s) => IPAddress.TryParse(s, out _);

    private static void AddIp(List<string> ips, string s)
    {
        if (s == "" || !IPAddress.TryParse(s, out var ip)) return;
        if (IPAddress.IsLoopback(ip) || ip.IsIPv6LinkLocal || IPAddress.Any.Equals(ip) || IPAddress.IPv6Any.Equals(ip) || s.StartsWith("169.254.", StringComparison.Ordinal)) return;
        if (!ips.Contains(s, StringComparer.OrdinalIgnoreCase)) ips.Add(s);
    }

    private static void AddMac(List<string> macs, string s)
    {
        var m = s.Trim().ToLowerInvariant();
        if (m.Length < 12 || m == "00:00:00:00:00:00") return;
        if (!macs.Contains(m)) macs.Add(m);
    }

    private static string Get(IReadOnlyDictionary<string, string> c, string key) => c.TryGetValue(key, out var v) && v is not null ? v.Trim() : "";

    private static bool GetBool(IReadOnlyDictionary<string, string> c, string key, bool fallback)
    {
        var v = Get(c, key).ToLowerInvariant();
        return v == "" ? fallback : v is "true" or "1" or "yes" or "on";
    }

    // ------------------------------------------------------------------ REST session

    private sealed class RestSession : IVCenterSession
    {
        private readonly HttpClient _client;
        private readonly string _base;
        private readonly string _token;
        private readonly bool _legacy;

        private RestSession(HttpClient client, string baseUrl, string token, bool legacy) { _client = client; _base = baseUrl; _token = token; _legacy = legacy; }

        /// <summary>POST /api/session with basic authentication (vSphere 7+), falling back to the /rest CIS session endpoint (6.x).</summary>
        public static async Task<IVCenterSession> LoginAsync(HttpClient client, string baseUrl, string user, string password, CancellationToken ct)
        {
            var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes(user + ":" + password));
            foreach (var (path, legacy) in new[] { ("/api/session", false), ("/rest/com/vmware/cis/session", true) })
            {
                using var req = new HttpRequestMessage(HttpMethod.Post, baseUrl + path);
                req.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic);
                using var resp = await client.SendAsync(req, ct);
                if (resp.StatusCode == HttpStatusCode.NotFound && !legacy) continue;
                if (resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                    throw new InvalidOperationException("vCenter rejected the username or password (HTTP " + (int)resp.StatusCode + ")");
                if (!resp.IsSuccessStatusCode)
                    throw new InvalidOperationException("vCenter login failed with HTTP " + (int)resp.StatusCode);
                var body = await resp.Content.ReadAsStringAsync(ct);
                using var doc = JsonDocument.Parse(body);
                var token = doc.RootElement.ValueKind == JsonValueKind.String ? doc.RootElement.GetString()
                    : doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty("value", out var v) ? v.GetString() : null;
                if (string.IsNullOrEmpty(token)) throw new InvalidOperationException("vCenter login returned no session token");
                return new RestSession(client, baseUrl, token, legacy);
            }
            throw new InvalidOperationException("vCenter did not answer the session endpoint");
        }

        public async Task<JsonDocument?> GetAsync(string path, CancellationToken ct)
        {
            var p = _legacy && path.StartsWith("/api/", StringComparison.Ordinal) ? "/rest" + path[4..] : path;
            using var req = new HttpRequestMessage(HttpMethod.Get, _base + p);
            req.Headers.Add("vmware-api-session-id", _token);
            using var resp = await _client.SendAsync(req, ct);
            if (resp.StatusCode is HttpStatusCode.NotFound or HttpStatusCode.ServiceUnavailable or HttpStatusCode.BadRequest) return null;
            if (resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                throw new InvalidOperationException("vCenter refused " + p + " (HTTP " + (int)resp.StatusCode + "): the session expired or the account lacks the Read-Only role");
            if (!resp.IsSuccessStatusCode) throw new HttpRequestException("vCenter " + p + " returned HTTP " + (int)resp.StatusCode);
            var body = await resp.Content.ReadAsStringAsync(ct);
            if (string.IsNullOrWhiteSpace(body)) return null;
            return JsonDocument.Parse(body);
        }

        public async ValueTask DisposeAsync()
        {
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Delete, _base + (_legacy ? "/rest/com/vmware/cis/session" : "/api/session"));
                req.Headers.Add("vmware-api-session-id", _token);
                using var resp = await _client.SendAsync(req, CancellationToken.None);
            }
            catch { /* the session expires on its own */ }
        }
    }
}
