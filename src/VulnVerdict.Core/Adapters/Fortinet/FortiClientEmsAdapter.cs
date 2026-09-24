using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;
using static VulnVerdict.Core.Adapters.Fortinet.FortinetJson;

namespace VulnVerdict.Core.Adapters.Fortinet;

/// <summary>
/// Section 9.2 step 2: FortiClient EMS 7.x REST API. One pull returns the endpoint inventory, each endpoint's
/// installed software and the findings of EMS's own vulnerability scan.
///
/// Sign-in is POST /api/v1/auth/signin with {"name","password"}; EMS answers with a session cookie and a
/// "csrftoken" cookie that is echoed back as the X-CSRFToken header (with a Referer header) on later requests.
/// Multi-site EMS scopes a request with the "Site" header. Listings are paged with offset/count and wrapped as
/// {"result":{"retval":1,"message":...},"data":{"<collection>":[...],"total":N}}.
///
/// Read-only: only GET requests after sign-in; nothing is ever written to EMS.
/// </summary>
public sealed class FortiClientEmsAdapter : IInventoryAdapter
{
    public const string SignInPath = "/api/v1/auth/signin";
    /// <summary>Endpoint listing (data.endpoints, data.total). Documented in the FortiSOAR EMS connector output schema.</summary>
    public const string EndpointsPath = "/api/v1/endpoints/index";
    /// <summary>Per-endpoint software inventory. The path is the FortiAPI default for the Software Inventory pane; see the class remarks.</summary>
    public const string SoftwarePath = "/api/v1/software_inventory/index";
    /// <summary>Per-endpoint vulnerability scan results. The path is the FortiAPI default for the Vulnerability Scan pane; see the class remarks.</summary>
    public const string VulnerabilitiesPath = "/api/v1/vulnerabilities/index";
    public const int PageSize = 100;
    private const int MaxItems = 200_000;

    private readonly IHttpClientFactory? _http;
    private readonly Func<string, CancellationToken, Task<string>>? _fetch;
    private readonly ILogger _log;

    public FortiClientEmsAdapter(IHttpClientFactory http, ILogger<FortiClientEmsAdapter> log)
    {
        _http = http; _log = log;
    }

    /// <summary>Test seam: every GET goes through <paramref name="fetch"/> (path with query string in, JSON out); no sign-in happens.</summary>
    public FortiClientEmsAdapter(Func<string, CancellationToken, Task<string>> fetch, ILogger<FortiClientEmsAdapter>? log = null)
    {
        _fetch = fetch; _log = log ?? NullLogger<FortiClientEmsAdapter>.Instance;
    }

    public AdapterMetadata Metadata { get; } = new(
        Id: "forticlient-ems",
        DisplayName: "FortiClient EMS (endpoints, software, scan findings)",
        Vendor: "Fortinet",
        Description: "Reads the endpoint inventory, installed software and vulnerability scan results from a FortiClient EMS 7.x server over its REST API. Read-only.",
        Kinds: new[] { AssetKind.Endpoint, AssetKind.Server },
        Form: new[]
        {
            new CredentialField("host", "EMS host", CredentialTypes.Text, "Host name or IP of the EMS server, e.g. ems.example.local (port 443 unless given as host:port)."),
            new CredentialField("username", "User name", CredentialTypes.Text, "An EMS administrator with a read-only custom role."),
            new CredentialField("password", "Password", CredentialTypes.Password),
            new CredentialField("verifyTls", "Verify TLS certificate", CredentialTypes.Bool, "Turn off only for a self-signed EMS certificate.", Required: false, Default: "true"),
            new CredentialField("site", "Site", CredentialTypes.Text, "Multi-site EMS only: the site to read (sent as the Site header). Leave blank for the default site.", Required: false),
        },
        MinimumPermission: "an EMS administrator account with a custom read-only role (view endpoints, software inventory, vulnerabilities)",
        DocsUrl: "https://docs.fortinet.com/document/forticlient/7.4.3/ems-administration-guide/30768/forticlient-ems-api",
        DefaultIntervalMinutes: 240);

    // ------------------------------------------------------------------ contract

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            var get = await SignInAsync(credentials, ct);
            var root = Parse(await get(EndpointsPath + "?offset=0&count=1", ct));
            CheckResult(root, EndpointsPath);
            var data = root.TryGetProperty("data", out var d) ? d : root;
            var total = Int(data, "total") ?? Collection(data, "endpoints").Count();
            return new TestResult(true, "Signed in to EMS; " + total + " endpoint(s) visible to this account.");
        }
        catch (Exception ex) when (ex is FortinetApiException or HttpRequestException or JsonException or TaskCanceledException or InvalidOperationException)
        {
            return new TestResult(false, ex.Message);
        }
    }

    public async Task<CollectResult> CollectAsync(IReadOnlyDictionary<string, string> credentials, DateTime? since, IProgress<string>? progress, CancellationToken ct)
    {
        var get = await SignInAsync(credentials, ct);
        var result = new CollectResult { FullSnapshot = true };

        progress?.Report("Listing endpoints");
        var endpoints = await PageAsync(get, EndpointsPath, "", "endpoints", ct);
        _log.LogInformation("EMS returned {Count} endpoints", endpoints.Count);

        var n = 0;
        foreach (var e in endpoints)
        {
            ct.ThrowIfCancellationRequested();
            n++;
            var mapped = MapEndpoint(e);
            if (mapped is null) { result.Warnings.Add("Endpoint without a device id skipped: " + (Str(e, "name") ?? "(unnamed)")); continue; }
            var (asset, os, agent) = mapped.Value;
            result.Assets.Add(asset);
            if (os is not null) result.Software.Add(os);
            if (agent is not null) result.Software.Add(agent);
            progress?.Report("Endpoint " + n + "/" + endpoints.Count + ": " + asset.DisplayName);

            var idQuery = "device_id=" + Uri.EscapeDataString(asset.ExternalId);
            try
            {
                foreach (var s in await PageAsync(get, SoftwarePath, idQuery, "software", ct))
                {
                    var rec = MapSoftware(asset.ExternalId, s);
                    if (rec is not null) result.Software.Add(rec);
                }
            }
            catch (FortinetApiException ex) { Warn(result, "software inventory", asset.DisplayName, ex); if (ex.Status is 404 or 403) break; }
            catch (JsonException ex) { Warn(result, "software inventory", asset.DisplayName, ex); }

            try
            {
                foreach (var v in await PageAsync(get, VulnerabilitiesPath, idQuery, "vulnerabilities", ct))
                {
                    var rec = MapVulnerability(asset.ExternalId, v);
                    if (rec is not null) result.Findings.Add(rec);
                }
            }
            catch (FortinetApiException ex) { Warn(result, "vulnerabilities", asset.DisplayName, ex); if (ex.Status is 404 or 403) break; }
            catch (JsonException ex) { Warn(result, "vulnerabilities", asset.DisplayName, ex); }
        }
        return result;
    }

    private void Warn(CollectResult r, string what, string endpoint, Exception ex)
    {
        var msg = "Could not read " + what + " for " + endpoint + ": " + ex.Message;
        if (r.Warnings.Count < 200) r.Warnings.Add(msg);
        _log.LogWarning("{Message}", msg);
    }

    // ------------------------------------------------------------------ mapping (pure; tested with fixtures)

    /// <summary>One EMS endpoint to an asset, its operating system and the FortiClient agent itself.</summary>
    public static (AssetRecord Asset, SoftwareRecord? Os, SoftwareRecord? Agent)? MapEndpoint(JsonElement e)
    {
        var id = Str(e, "device_id", "id", "endpoint_id", "client_id");
        if (id is null) return null;
        var name = Str(e, "name", "host_name", "hostname", "computer_name") ?? id;
        var osText = Str(e, "os_version", "os", "operating_system");
        var os = FortinetOsNames.Parse(osText, Str(e, "os_type", "os_family", "platform"));

        var hostnames = new List<string>();
        foreach (var h in new[] { name, Str(e, "host_name", "hostname"), Str(e, "fqdn", "dns_name") })
            if (!string.IsNullOrWhiteSpace(h) && !hostnames.Contains(h, StringComparer.OrdinalIgnoreCase)) hostnames.Add(h);
        var ips = SplitList(Str(e, "ip_addr", "ip", "ip_address", "ipv4_addr")).Concat(SplitList(Str(e, "ip_addrs", "ip_addresses", "ipv6_addr")))
            .Where(ip => ip != "0.0.0.0" && !ip.StartsWith("127.") && !ip.StartsWith("169.254.")).Distinct().ToArray();
        var macs = SplitList(Str(e, "mac_addr", "mac", "mac_address", "mac_addrs")).Where(m => !IsZeroMac(m)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

        string? owner = null;
        foreach (var u in Array(e, "fct_users"))
        {
            owner = Str(u, "auth_user_name", "machine_user_name", "user_email");
            if (owner is not null) break;
        }
        owner ??= Str(e, "user", "username", "last_user");

        var kind = os.Family is "windows-server" or "linux" ? AssetKind.Server : AssetKind.Endpoint;
        var asset = new AssetRecord(id, name, kind, hostnames.ToArray(), ips, macs,
            OsVendor: os.Vendor, OsProduct: os.Product, OsVersion: os.Version, OsBuild: os.Build, Owner: owner);

        SoftwareRecord? osRec = os.Vendor is not null
            ? new SoftwareRecord(id, os.Vendor, os.Product, os.Version ?? "", SoftwareKind.OperatingSystem, ExternalId: "os")
            : null;

        var fct = Str(e, "fct_version", "forticlient_version", "client_version");
        SoftwareRecord? agent = null;
        if (fct is not null)
        {
            var product = os.Family switch
            {
                "windows" or "windows-server" => "FortiClientWindows",
                "macos" => "FortiClientMac",
                "linux" => "FortiClientLinux",
                "ios" => "FortiClientiOS",
                "android" => "FortiClientAndroid",
                _ => "FortiClient"
            };
            agent = new SoftwareRecord(id, "Fortinet", product, ShortVersion(fct), SoftwareKind.Application, ExternalId: "forticlient");
        }
        return (asset, osRec, agent);
    }

    /// <summary>One software inventory row to a record; the version is stripped from the product name. FortiClient itself is skipped (added from the endpoint record).</summary>
    public static SoftwareRecord? MapSoftware(string assetExternalId, JsonElement s)
    {
        var name = Str(s, "name", "app_name", "software_name", "application", "product");
        if (name is null) return null;
        var product = StripVersion(name);
        if (product.Length == 0 || product.StartsWith("FortiClient", StringComparison.OrdinalIgnoreCase)) return null;
        var vendor = Str(s, "vendor", "publisher", "company", "manufacturer") ?? "";
        var version = Str(s, "version", "app_version", "software_version") ?? "";
        return new SoftwareRecord(assetExternalId, vendor, product, version, SoftwareKind.Application, ExternalId: Str(s, "id", "app_id", "software_id"));
    }

    /// <summary>One vulnerability scan row to a finding. Rows without a CVE id are dropped (the console keys findings by CVE).</summary>
    public static FindingRecord? MapVulnerability(string assetExternalId, JsonElement v)
    {
        var ids = new List<string>();
        foreach (var key in new[] { "cve_id", "cve", "cves", "cve_ids", "cve_list" })
        {
            if (!v.TryGetProperty(key, out var c)) continue;
            if (c.ValueKind == JsonValueKind.String) ids.AddRange(Normalizer.ExtractCveIds(c.GetString()));
            else if (c.ValueKind == JsonValueKind.Array)
                foreach (var item in c.EnumerateArray())
                    ids.AddRange(Normalizer.ExtractCveIds(item.ValueKind == JsonValueKind.String ? item.GetString() : Str(item, "cve_id", "cve", "id", "name")));
        }
        var title = Str(v, "name", "vuln_name", "title", "vulnerability_name");
        if (ids.Count == 0) ids.AddRange(Normalizer.ExtractCveIds(title).Concat(Normalizer.ExtractCveIds(Str(v, "description"))));
        ids = ids.Select(Normalizer.CveIdUpper).Distinct().ToList();
        if (ids.Count == 0) return null;
        var rawRef = Str(v, "vuln_id", "fortiguard_id", "vulnerability_id", "id");
        return new FindingRecord(assetExternalId, ids.ToArray(), Severity(Str(v, "severity", "risk", "severity_level", "risk_level")), title, rawRef is null ? null : "ems-vuln-" + rawRef);
    }

    private static string? Severity(string? s) => s?.ToLowerInvariant() switch
    {
        null => null,
        "4" or "critical" => "Critical",
        "3" or "high" => "High",
        "2" or "medium" or "med" => "Medium",
        "1" or "low" => "Low",
        "0" or "info" or "informational" => "Info",
        _ => s
    };

    // ------------------------------------------------------------------ paging

    private static async Task<List<JsonElement>> PageAsync(Func<string, CancellationToken, Task<string>> get, string path, string query, string collection, CancellationToken ct)
    {
        var items = new List<JsonElement>();
        for (var offset = 0; ; offset += PageSize)
        {
            var url = path + "?" + (query.Length > 0 ? query + "&" : "") + "offset=" + offset + "&count=" + PageSize;
            var root = Parse(await get(url, ct));
            CheckResult(root, path);
            var data = root.TryGetProperty("data", out var d) ? d : root;
            var page = Collection(data, collection).ToList();
            items.AddRange(page);
            var total = Int(data, "total");
            if (page.Count == 0 || page.Count < PageSize || (total is not null && items.Count >= total) || items.Count >= MaxItems) break;
        }
        return items;
    }

    /// <summary>data.&lt;collection&gt; when present, else the first array-valued property, else data itself when it is an array.</summary>
    private static IEnumerable<JsonElement> Collection(JsonElement data, string collection)
    {
        if (data.ValueKind == JsonValueKind.Array) return data.EnumerateArray();
        if (data.ValueKind != JsonValueKind.Object) return Enumerable.Empty<JsonElement>();
        if (data.TryGetProperty(collection, out var c) && c.ValueKind == JsonValueKind.Array) return c.EnumerateArray();
        foreach (var p in data.EnumerateObject())
            if (p.Value.ValueKind == JsonValueKind.Array) return p.Value.EnumerateArray();
        return Enumerable.Empty<JsonElement>();
    }

    private static void CheckResult(JsonElement root, string path)
    {
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("result", out var r) || r.ValueKind != JsonValueKind.Object) return;
        var retval = Int(r, "retval");
        if (retval is not null && retval != 1)
            throw new FortinetApiException(path, 200, "EMS result " + retval + (Str(r, "message") is { } m ? ": " + m : ""));
    }

    // ------------------------------------------------------------------ HTTP session

    private async Task<Func<string, CancellationToken, Task<string>>> SignInAsync(IReadOnlyDictionary<string, string> creds, CancellationToken ct)
    {
        if (_fetch is not null) return _fetch;
        var host = FortinetCreds.Host(FortinetCreds.Get(creds, "host"));
        if (host.Length == 0) throw new InvalidOperationException("EMS host is required");
        var user = FortinetCreds.Get(creds, "username");
        var password = FortinetCreds.Get(creds, "password");
        var site = FortinetCreds.Get(creds, "site");
        var baseUrl = "https://" + host;
        var client = _http!.CreateClient(FortinetCreds.Bool(creds, "verifyTls", true) ? "adapter" : "adapter-insecure");

        string cookieHeader; string? csrf;
        using (var req = new HttpRequestMessage(HttpMethod.Post, baseUrl + SignInPath))
        {
            req.Content = new StringContent(JsonSerializer.Serialize(new { name = user, password }), Encoding.UTF8, "application/json");
            req.Headers.Referrer = new Uri(baseUrl + "/");
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            if (site.Length > 0) req.Headers.TryAddWithoutValidation("Site", site);
            using var resp = await client.SendAsync(req, ct);
            if (resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                throw new FortinetApiException("POST " + SignInPath, (int)resp.StatusCode, "EMS rejected the user name or password");
            if (!resp.IsSuccessStatusCode)
                throw new FortinetApiException("POST " + SignInPath, (int)resp.StatusCode, resp.ReasonPhrase ?? "");
            var body = await resp.Content.ReadAsStringAsync(ct);
            if (body.TrimStart().StartsWith('{'))
            {
                try { CheckResult(Parse(body), "POST " + SignInPath); }
                catch (JsonException) { /* not JSON; the status code already said the sign-in worked */ }
            }
            var cookies = new List<string>(); csrf = null;
            if (resp.Headers.TryGetValues("Set-Cookie", out var setCookies))
            {
                foreach (var sc in setCookies)
                {
                    var pair = sc.Split(';')[0].Trim();
                    var eq = pair.IndexOf('=');
                    if (eq <= 0) continue;
                    cookies.Add(pair);
                    if (pair[..eq].Equals("csrftoken", StringComparison.OrdinalIgnoreCase)) csrf = pair[(eq + 1)..];
                }
            }
            cookieHeader = string.Join("; ", cookies);
            if (cookieHeader.Length == 0) throw new FortinetApiException("POST " + SignInPath, (int)resp.StatusCode, "EMS did not return a session cookie");
        }
        _log.LogDebug("Signed in to EMS {Host}", host);

        return async (path, ct2) =>
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, baseUrl + path);
            req.Headers.Referrer = new Uri(baseUrl + "/");
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            req.Headers.TryAddWithoutValidation("Cookie", cookieHeader);
            if (csrf is not null) req.Headers.TryAddWithoutValidation("X-CSRFToken", csrf);
            if (site.Length > 0) req.Headers.TryAddWithoutValidation("Site", site);
            using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct2);
            var shortPath = path.Split('?')[0];
            if (resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                throw new FortinetApiException("GET " + shortPath, (int)resp.StatusCode, "EMS refused the request (does the account's role include view permission for this data?)");
            if (resp.StatusCode == HttpStatusCode.NotFound)
                throw new FortinetApiException("GET " + shortPath, 404, "not found (this EMS version does not expose the path)");
            if (!resp.IsSuccessStatusCode)
                throw new FortinetApiException("GET " + shortPath, (int)resp.StatusCode, resp.ReasonPhrase ?? "");
            return await resp.Content.ReadAsStringAsync(ct2);
        };
    }
}
