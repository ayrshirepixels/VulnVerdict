using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using VulnVerdict.Core.Adapters.Fortinet;
using VulnVerdict.Core.Adapters.Windows;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Endpoints;

/// <summary>A call to an endpoint-management or MDM API failed. The message never contains credentials or tokens.</summary>
public sealed class EndpointApiException : Exception
{
    public string Path { get; }
    public int Status { get; }
    public EndpointApiException(string path, int status, string detail) : base(path + (status > 0 ? ": HTTP " + status : ":") + (detail.Length > 0 ? " " + detail : ""))
    {
        Path = path; Status = status;
    }
}

/// <summary>Credential-form access shared by the endpoint-management adapters.</summary>
public static class EpCreds
{
    public static string Get(IReadOnlyDictionary<string, string> creds, string key) => creds.TryGetValue(key, out var v) && v is not null ? v.Trim() : "";

    /// <summary>The raw value (not trimmed): secrets may legitimately start or end with a space.</summary>
    public static string Secret(IReadOnlyDictionary<string, string> creds, string key) => creds.TryGetValue(key, out var v) && v is not null ? v : "";

    public static bool Bool(IReadOnlyDictionary<string, string> creds, string key, bool dflt)
    {
        var v = Get(creds, key);
        if (v.Length == 0) return dflt;
        return v.Equals("true", StringComparison.OrdinalIgnoreCase) || v == "1" || v.Equals("yes", StringComparison.OrdinalIgnoreCase) || v.Equals("on", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>"tenant.jamfcloud.com", "https://tenant.jamfcloud.com/" or "https://host:8443/x" to "https://host[:port]" (https unless http is given).</summary>
    public static string BaseUrl(string raw)
    {
        var h = raw.Trim();
        if (h.Length == 0) return "";
        var scheme = "https://";
        if (h.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) { scheme = "http://"; h = h[7..]; }
        else if (h.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) h = h[8..];
        var slash = h.IndexOf('/');
        if (slash >= 0) h = h[..slash];
        return h.Length == 0 ? "" : scheme + h;
    }

    public static CredentialField VerifyTls(string system) =>
        new("verifyTls", "Verify TLS certificate", CredentialTypes.Bool, "Turn off only when the " + system + " uses a certificate from a private CA the appliance does not trust.", Required: false, Default: "true");
}

/// <summary>
/// JSON over HTTP for the endpoint adapters: authorisation per request, 429/503 Retry-After honoured,
/// one token refresh on 401, and status codes turned into <see cref="EndpointApiException"/> with a product-specific hint.
/// </summary>
public sealed class EndpointHttp
{
    private readonly HttpClient _client;
    private readonly string _base;
    private readonly Func<int, string?> _explain;

    /// <summary>
    /// Sets the Authorization header on a request. The flag is true when the previous attempt came back 401 and a
    /// fresh token should be fetched before this one is sent.
    /// </summary>
    public Func<HttpRequestMessage, bool, CancellationToken, Task>? Authorise { get; set; }
    /// <summary>How long to wait before a retry after 429 or 503; tests replace it so nothing sleeps.</summary>
    public Func<TimeSpan, CancellationToken, Task> Delay { get; set; } = (t, ct) => Task.Delay(t, ct);
    public int MaxRetries { get; set; } = 5;

    public EndpointHttp(HttpClient client, string baseUrl, Func<int, string?> explain)
    {
        _client = client; _base = baseUrl.TrimEnd('/'); _explain = explain;
    }

    public string Url(string path) => path.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? path : _base + "/" + path.TrimStart('/');

    public async Task<JsonElement> GetJsonAsync(string path, CancellationToken ct) => EpJson.Parse(await SendAsync(HttpMethod.Get, path, null, ct));

    public async Task<JsonElement> PostJsonAsync(string path, object body, CancellationToken ct) =>
        EpJson.Parse(await SendAsync(HttpMethod.Post, path, () => new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json"), ct));

    public async Task<string> SendAsync(HttpMethod method, string path, Func<HttpContent>? content, CancellationToken ct)
    {
        var refresh = false; var refreshed = false;
        for (var attempt = 0; ; attempt++)
        {
            using var req = new HttpRequestMessage(method, Url(path));
            if (content is not null) req.Content = content();
            req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            if (Authorise is not null) await Authorise(req, refresh, ct);
            refresh = false;
            using var resp = await _client.SendAsync(req, HttpCompletionOption.ResponseContentRead, ct);
            var status = (int)resp.StatusCode;
            if ((status == 429 || status == 503) && attempt < MaxRetries)
            {
                TimeSpan? fromDate = resp.Headers.RetryAfter?.Date is { } d ? d - DateTimeOffset.UtcNow : null;
                var wait = resp.Headers.RetryAfter?.Delta ?? fromDate ?? TimeSpan.FromSeconds(1 << Math.Min(attempt, 5));
                if (wait < TimeSpan.Zero) wait = TimeSpan.Zero;
                if (wait > TimeSpan.FromSeconds(120)) wait = TimeSpan.FromSeconds(120);
                await Delay(wait, ct);
                continue;
            }
            if (status == 401 && !refreshed && Authorise is not null)
            {
                // tokens can expire during a long collection: fetch a new one once and repeat the request
                refresh = refreshed = true;
                continue;
            }
            var body = await resp.Content.ReadAsStringAsync(ct);
            if (!resp.IsSuccessStatusCode)
                throw new EndpointApiException(method.Method + " " + StripQuery(path), status, _explain(status) ?? resp.ReasonPhrase ?? "");
            return body;
        }
    }

    /// <summary>Errors show the path only: some APIs put identifiers or cursors in the query string.</summary>
    public static string StripQuery(string path)
    {
        if (path.StartsWith("http", StringComparison.OrdinalIgnoreCase) && Uri.TryCreate(path, UriKind.Absolute, out var u)) path = u.AbsolutePath;
        var q = path.IndexOf('?');
        return q >= 0 ? path[..q] : path;
    }
}

/// <summary>A bearer token that is fetched on first use and again when it expires or the API answers 401.</summary>
public sealed class BearerToken
{
    private readonly Func<CancellationToken, Task<OAuthTokens.Token>> _fetch;
    private OAuthTokens.Token? _token;
    public string Scheme { get; init; } = "Bearer";

    public BearerToken(Func<CancellationToken, Task<OAuthTokens.Token>> fetch) => _fetch = fetch;

    public async Task<string> GetAsync(bool forceRefresh, CancellationToken ct)
    {
        if (forceRefresh || _token is null || _token.ExpiresAt <= DateTime.UtcNow) _token = await _fetch(ct);
        return _token.AccessToken;
    }

    public async Task Apply(HttpRequestMessage req, bool forceRefresh, CancellationToken ct) =>
        req.Headers.Authorization = new AuthenticationHeaderValue(Scheme, await GetAsync(forceRefresh, ct));
}

/// <summary>OAuth 2.0 token requests. Secrets go in the form body (or Basic header) only, never in URLs or messages.</summary>
public static class OAuthTokens
{
    public sealed record Token(string AccessToken, DateTime ExpiresAt);

    public static async Task<Token> RequestAsync(HttpClient client, string tokenUrl, IEnumerable<KeyValuePair<string, string>>? form, CancellationToken ct,
        AuthenticationHeaderValue? auth = null, string what = "token request")
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, tokenUrl);
        if (form is not null) req.Content = new FormUrlEncodedContent(form);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (auth is not null) req.Headers.Authorization = auth;
        using var resp = await client.SendAsync(req, ct);
        var body = await resp.Content.ReadAsStringAsync(ct);
        var path = "POST " + EndpointHttp.StripQuery(tokenUrl);
        JsonElement root = default;
        try { root = EpJson.Parse(body); } catch (JsonException) { /* not JSON: the status decides */ }
        if (!resp.IsSuccessStatusCode)
        {
            // error_description is written by the identity provider for people (AADSTS codes, "invalid_client") and holds no secrets
            var detail = root.ValueKind == JsonValueKind.Object ? EpJson.Str(root, "error_description", "error", "message") : null;
            if (detail is not null) detail = detail.Split('\n')[0].Trim();
            if (detail is { Length: > 300 }) detail = detail[..300];
            throw new EndpointApiException(path, (int)resp.StatusCode, what + " refused" + (detail is null ? "" : ": " + detail));
        }
        var token = root.ValueKind == JsonValueKind.Object ? EpJson.Str(root, "access_token", "token", "accessToken", "tokens.access.token") : null;
        if (token is null) throw new EndpointApiException(path, (int)resp.StatusCode, what + " returned no access token");
        var expires = EpJson.Int(root, "expires_in", "expiresIn", "tokens.access.expirySeconds") ?? 3600;
        return new Token(token, DateTime.UtcNow.AddSeconds(Math.Max(60, expires - 60)));
    }

    public static AuthenticationHeaderValue Basic(string user, string password) =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(user + ":" + password)));

    public static IEnumerable<KeyValuePair<string, string>> Form(params (string Key, string Value)[] pairs) =>
        pairs.Select(p => new KeyValuePair<string, string>(p.Key, p.Value));
}

/// <summary>Tolerant JSON access: dotted paths ("general.name"), several candidate names, numbers and booleans read as strings.</summary>
public static class EpJson
{
    public static JsonElement Parse(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return default;
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    public static JsonElement? At(JsonElement e, string path)
    {
        // a name that itself contains a dot ("@odata.nextLink") wins over the dotted reading
        if (e.ValueKind == JsonValueKind.Object && path.Contains('.') && e.TryGetProperty(path, out var literal))
            return literal.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null ? null : literal;
        var cur = e;
        foreach (var part in path.Split('.'))
        {
            if (cur.ValueKind != JsonValueKind.Object) return null;
            if (cur.TryGetProperty(part, out var next)) { cur = next; continue; }
            var found = false;
            foreach (var p in cur.EnumerateObject())
                if (p.Name.Equals(part, StringComparison.OrdinalIgnoreCase)) { cur = p.Value; found = true; break; }
            if (!found) return null;
        }
        return cur.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null ? null : cur;
    }

    public static string? Str(JsonElement e, params string[] paths)
    {
        foreach (var p in paths)
        {
            if (At(e, p) is not { } v) continue;
            var s = v.ValueKind switch
            {
                JsonValueKind.String => v.GetString(),
                JsonValueKind.Number => v.GetRawText(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                _ => null
            };
            if (!string.IsNullOrWhiteSpace(s)) return s.Trim();
        }
        return null;
    }

    public static long? Int(JsonElement e, params string[] paths)
    {
        foreach (var p in paths)
        {
            if (At(e, p) is not { } v) continue;
            if (v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var n)) return n;
            if (v.ValueKind == JsonValueKind.String && long.TryParse(v.GetString(), out n)) return n;
        }
        return null;
    }

    public static bool? Bool(JsonElement e, params string[] paths)
    {
        foreach (var p in paths)
        {
            if (At(e, p) is not { } v) continue;
            if (v.ValueKind == JsonValueKind.True) return true;
            if (v.ValueKind == JsonValueKind.False) return false;
            if (v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var n)) return n != 0;
            if (v.ValueKind == JsonValueKind.String && bool.TryParse(v.GetString(), out var b)) return b;
        }
        return null;
    }

    public static List<JsonElement> Arr(JsonElement e, params string[] paths)
    {
        foreach (var p in paths)
            if (At(e, p) is { ValueKind: JsonValueKind.Array } a) return a.EnumerateArray().ToList();
        return new();
    }

    /// <summary>A list of strings from an array of strings, an array of objects (first of <paramref name="itemKeys"/>), or one delimited string.</summary>
    public static List<string> Strings(JsonElement e, string path, params string[] itemKeys)
    {
        var list = new List<string>();
        if (At(e, path) is not { } v) return list;
        if (v.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in v.EnumerateArray())
            {
                var s = item.ValueKind == JsonValueKind.String ? item.GetString() : itemKeys.Length > 0 ? Str(item, itemKeys) : null;
                if (!string.IsNullOrWhiteSpace(s)) list.AddRange(Split(s));
            }
        }
        else if (v.ValueKind == JsonValueKind.String) list.AddRange(Split(v.GetString()));
        return list;
    }

    private static IEnumerable<string> Split(string? s) =>
        (s ?? "").Split(new[] { ',', ';', ' ', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>The records of a listing: the root array, or the first of the named arrays, or "value"/"results"/"data"/"items".</summary>
    public static List<JsonElement> Items(JsonElement root, params string[] names)
    {
        if (root.ValueKind == JsonValueKind.Array) return root.EnumerateArray().ToList();
        if (root.ValueKind != JsonValueKind.Object) return new();
        foreach (var n in names.Concat(new[] { "value", "results", "data", "items" }))
            if (At(root, n) is { ValueKind: JsonValueKind.Array } a) return a.EnumerateArray().ToList();
        return new();
    }
}

/// <summary>
/// Operating-system and application naming for endpoint sources, written the way the CNAs name products so the
/// records resolve without a mapping step: Microsoft's "Windows 11 Version 23H2", Apple's "macOS" and "iOS and iPadOS".
/// </summary>
public static partial class EndpointNaming
{
    /// <summary>
    /// <paramref name="PatchLevelKnown"/> is false when the source gives the OS release but not its patch level (a Windows
    /// build without the update revision, an Android version without the security patch date). Such an OS is recorded
    /// on the asset but not emitted as software: matching "10.0.22631" against CVE ranges would call every Windows
    /// CVE of the year affected. A source that does know the patch level (WinRM, Intune, Defender) supplies it instead.
    /// </summary>
    public sealed record OsInfo(string? Vendor, string? Product, string? Version, string? Build, string Family, bool PatchLevelKnown);

    [GeneratedRegex(@"\b(10\.0\.\d{4,5}(?:\.\d+)?|6\.[0-3]\.\d{4}(?:\.\d+)?)\b")] private static partial Regex WindowsBuildRx();
    [GeneratedRegex(@"^\d{4,5}(?:\.\d+)?$")] private static partial Regex BareBuildRx();
    [GeneratedRegex(@"\b(\d{2}H\d)\b")] private static partial Regex FeatureReleaseRx();
    [GeneratedRegex(@"(\d+(?:\.\d+)+|\b\d+\b)")] private static partial Regex DottedRx();
    [GeneratedRegex(@"(?<=[a-z])(?=[A-Z0-9])|(?<=[0-9])(?=[A-Z])")] private static partial Regex CamelRx();
    [GeneratedRegex(@"(^|[^a-z])ios([^a-z]|$)")] private static partial Regex AppleIosRx();

    /// <summary>
    /// Name an OS from what an endpoint tool reports: a name ("Windows 11 Enterprise", "Windows11", "macOS", "iPadOS"),
    /// a version ("10.0.22631.3447", "14.4.1"), optionally a separate build ("22631", "22631.3447") and a feature release ("23H2").
    /// </summary>
    public static OsInfo Os(string? name, string? version, string? build = null, string? displayVersion = null, bool? server = null)
    {
        var n = (name ?? "").Trim();
        // "WindowsServer2022", "Windows11" (Defender's osPlatform) to words
        if (!n.Contains(' ') && n.StartsWith("Windows", StringComparison.OrdinalIgnoreCase)) n = CamelRx().Replace(n, " ");
        var lower = (n + " " + version + " " + build).ToLowerInvariant();

        if (lower.Contains("windows") || (WindowsBuildRx().IsMatch(version ?? "") && !lower.Contains("mac")))
        {
            var full = WindowsBuildRx().Match(version ?? "") is { Success: true } m1 ? m1.Value
                     : WindowsBuildRx().Match(build ?? "") is { Success: true } m2 ? m2.Value
                     : WindowsBuildRx().Match(n) is { Success: true } m3 ? m3.Value : null;
            var b = (build ?? "").Trim();
            if (BareBuildRx().IsMatch(b) && (full is null || full.Split('.').Length < 4))
            {
                // a separate build ("22631.3447" or "22631") refines a "10.0" or "10.0.22631" version
                var major = full is not null ? string.Join('.', full.Split('.').Take(2)) : "10.0";
                var candidate = major + "." + b;
                if (full is null || candidate.StartsWith(full, StringComparison.Ordinal)) full = candidate;
            }
            var dv = displayVersion;
            if (string.IsNullOrWhiteSpace(dv) && FeatureReleaseRx().Match(n) is { Success: true } dm) dv = dm.Value;
            var isServer = server ?? lower.Contains("server");
            var caption = isServer && !n.Contains("server", StringComparison.OrdinalIgnoreCase) ? "Windows Server " + n : n;
            if (!caption.Contains("windows", StringComparison.OrdinalIgnoreCase)) caption = "Windows " + caption;
            var product = WindowsCollectorMapper.OsProductName(caption, dv, full, isServer ? "Server" : null);
            var known = full is not null && full.Split('.').Length >= 4;
            return new OsInfo("Microsoft", product, full, full, isServer ? "windows-server" : "windows", known);
        }
        if (lower.Contains("cisco") || lower.Contains("ios-xe") || lower.Contains("ios xe") || lower.Contains("ios xr"))
            return new OsInfo(null, n.Length > 0 ? n : null, First(version) ?? First(n), null, "network", false);
        if (lower.Contains("ipados") || AppleIosRx().IsMatch(lower) || lower.Contains("iphone") || lower.Contains("ipad"))
            return Apple("iOS and iPadOS", "ios", version, n);
        if (lower.Contains("tvos") || lower.Contains("apple tv") || lower.Contains("appletv")) return Apple("tvOS", "tvos", version, n);
        if (lower.Contains("watchos")) return Apple("watchOS", "watchos", version, n);
        if (lower.Contains("visionos")) return Apple("visionOS", "visionos", version, n);
        if (lower.Contains("mac") || lower.Contains("os x") || lower.Contains("darwin"))
            return Apple("macOS", "macos", version, n);
        if (lower.Contains("android"))
            return new OsInfo("Google", "Android", First(version) ?? First(n), null, "android", false);
        if (lower.Contains("chrome os") || lower.Contains("chromeos"))
            return new OsInfo("Google", "ChromeOS", First(version), null, "chromeos", false);
        if (lower.Contains("linux") || lower.Contains("ubuntu") || lower.Contains("debian") || lower.Contains("red hat") || lower.Contains("rhel")
            || lower.Contains("centos") || lower.Contains("suse") || lower.Contains("rocky") || lower.Contains("alma"))
        {
            var os = FortinetOsNames.Parse((n + " " + version).Trim(), "linux");
            return new OsInfo(os.Vendor, os.Product, os.Version, null, "linux", false);
        }
        return new OsInfo(null, n.Length > 0 ? n : null, version, build, "other", false);
    }

    private static OsInfo Apple(string product, string family, string? version, string name)
    {
        var v = First(version) ?? First(name);
        return new OsInfo("Apple", product, v, null, family, v is not null);
    }

    private static string? First(string? s) => s is null ? null : DottedRx().Match(s) is { Success: true } m ? m.Value : null;

    /// <summary>The OS as a software record, or null when it is unnamed or its patch level is unknown (see <see cref="OsInfo"/>).</summary>
    public static SoftwareRecord? OsRecord(string assetExternalId, OsInfo os) =>
        os.Vendor is not null && os.Product is not null && os.PatchLevelKnown && !string.IsNullOrWhiteSpace(os.Version)
            ? new SoftwareRecord(assetExternalId, os.Vendor, os.Product, os.Version!, SoftwareKind.OperatingSystem, ExternalId: "os")
            : null;

    public static AssetRecord Asset(string externalId, string displayName, OsInfo os, IEnumerable<string?> hostnames, IEnumerable<string?> ips, IEnumerable<string?> macs,
        string? owner = null, string? kindHint = null)
    {
        var names = new List<string>();
        foreach (var h in hostnames.Prepend(displayName))
            if (!string.IsNullOrWhiteSpace(h) && !names.Contains(h.Trim(), StringComparer.OrdinalIgnoreCase)) names.Add(h.Trim());
        return new AssetRecord(externalId, displayName, Kind(os, kindHint), names.ToArray(), Ips(ips), Macs(macs),
            OsVendor: os.Vendor, OsProduct: os.Product, OsVersion: os.Version, OsBuild: os.Build, Owner: string.IsNullOrWhiteSpace(owner) ? null : owner.Trim());
    }

    /// <summary>Servers by OS or by the tool's own device class ("WINDOWS_SERVER", "Servers - Windows", "Server"); everything else is an endpoint.</summary>
    public static AssetKind Kind(OsInfo os, string? hint)
    {
        var h = (hint ?? "").ToLowerInvariant();
        if (h.Contains("esxi") || h.Contains("vmware") || h.Contains("hyper-v host") || h.Contains("hypervisor")) return AssetKind.Hypervisor;
        if (h.Contains("printer")) return AssetKind.Printer;
        if (h.Contains("switch")) return AssetKind.Switch;
        if (h.Contains("firewall")) return AssetKind.Firewall;
        if (h.Contains("access point") || h.Contains("wireless") || h == "wap") return AssetKind.AccessPoint;
        if (h.Contains("router") || h.Contains("network device")) return AssetKind.NetworkDevice;
        if (h is "nas" or "san" || h.Contains("storage")) return AssetKind.Storage;
        if (h.Contains("ilo") || h.Contains("idrac") || h.Contains("ipmi")) return AssetKind.OutOfBandManagement;
        if (h.Contains("server") || os.Family == "windows-server") return AssetKind.Server;
        if (os.Family == "linux" && !h.Contains("workstation") && !h.Contains("desktop") && !h.Contains("laptop")) return AssetKind.Server;
        return AssetKind.Endpoint;
    }

    public static string[] Ips(IEnumerable<string?> raw) => raw
        .SelectMany(s => (s ?? "").Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        .Select(s => s.Split('/')[0])
        .Where(s => IPAddress.TryParse(s, out var ip) && !IPAddress.IsLoopback(ip) && !s.StartsWith("169.254.") && !s.StartsWith("fe80", StringComparison.OrdinalIgnoreCase) && s != "0.0.0.0" && s != "::")
        .Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

    public static string[] Macs(IEnumerable<string?> raw) => raw
        .SelectMany(s => (s ?? "").Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        .Select(NormaliseMac).Where(m => m is not null).Select(m => m!)
        .Distinct().ToArray();

    /// <summary>"00-15-5D-01-02-03", "00155d010203" or "0015.5d01.0203" to "00:15:5d:01:02:03"; null for all-zero or malformed.</summary>
    public static string? NormaliseMac(string mac)
    {
        var hex = new string(mac.Where(Uri.IsHexDigit).ToArray()).ToLowerInvariant();
        if (hex.Length != 12 || hex.All(c => c == '0') || hex == "ffffffffffff") return null;
        return string.Join(":", Enumerable.Range(0, 6).Select(i => hex.Substring(i * 2, 2)));
    }

    /// <summary>
    /// An installed application as a software record: architecture, locale and a repeated version stripped from the name
    /// ("Mozilla Firefox (x64 en-GB)" 128.0 to "Mozilla Firefox"), ".app" dropped, and the vendor taken from the
    /// publisher or, for Apple platforms, from the bundle id ("com.google.Chrome" to "google").
    /// </summary>
    public static SoftwareRecord? App(string assetExternalId, string? displayName, string? publisher, string? version, string? externalId = null, string? bundleId = null)
    {
        if (string.IsNullOrWhiteSpace(displayName)) return null;
        var name = displayName.Trim();
        if (name.EndsWith(".app", StringComparison.OrdinalIgnoreCase)) name = name[..^4].TrimEnd();
        name = LocaleSuffix().Replace(name, "");
        var ver = (version ?? "").Trim();
        var (product, arch) = WindowsCollectorMapper.CleanProductName(name, ver);
        if (product.Length == 0) return null;
        var vendor = (publisher ?? "").Trim();
        if (vendor.Length == 0 && !string.IsNullOrWhiteSpace(bundleId)) vendor = BundleVendor(bundleId) ?? "";
        if (vendor.Length == 0) vendor = VendorFromName(product) ?? "";
        // The id deliberately leaves the version out: an upgrade must update this record in place, so the evaluator sees
        // the new version on the same software instance and closes its verdicts as "fixed version observed".
        return new SoftwareRecord(assetExternalId, vendor, product, ver, SoftwareKind.Application, Architecture: arch,
            ExternalId: externalId ?? "app:" + (string.IsNullOrWhiteSpace(bundleId) ? product : bundleId).ToLowerInvariant() + (arch is null ? "" : ":" + arch));
    }

    /// <summary>
    /// Makes software ids unique per asset when one product is installed at two versions side by side (two Java
    /// runtimes): the lowest version keeps the plain id, the others get "#2", "#3" in version order.
    /// </summary>
    public static void UniqueIds(List<SoftwareRecord> records)
    {
        foreach (var group in records.Select((r, i) => (r, i)).GroupBy(x => (x.r.AssetExternalId, x.r.ExternalId)).Where(g => g.Key.ExternalId is not null && g.Count() > 1))
        {
            var ordered = group.OrderBy(x => x.r.Version, Comparer<string>.Create((a, b) => Engine.VersionCompare.Compare(a, b) ?? string.CompareOrdinal(a, b))).ToList();
            for (var n = 1; n < ordered.Count; n++)
                records[ordered[n].i] = ordered[n].r with { ExternalId = ordered[n].r.ExternalId + "#" + (n + 1) };
        }
    }

    private static readonly HashSet<string> KnownVendors = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft", "Google", "Mozilla", "Adobe", "Oracle", "Apple", "Zoom", "Cisco", "VMware", "Citrix", "Fortinet", "Dell", "HP", "Lenovo", "Intel",
        "NVIDIA", "Autodesk", "Atlassian", "Docker", "GitHub", "OpenVPN", "WireGuard", "Wireshark", "Notepad++", "PuTTY", "WinSCP", "WinRAR", "VLC",
        "TeamViewer", "AnyDesk", "Splashtop", "ConnectWise", "Veeam", "Sophos", "ESET", "Bitdefender", "Malwarebytes", "SonicWall", "WatchGuard",
        "Ivanti", "SolarWinds", "Progress", "Foxit", "Slack", "Webex", "Dropbox", "Salesforce", "SAP", "Python", "Node.js",
    };

    /// <summary>
    /// For sources that report no publisher (Datto RMM's software audit): the first word of the product when it is a
    /// well-known vendor ("Google Chrome" to "Google"). Anything else stays unvendored and goes to Needs mapping.
    /// </summary>
    public static string? VendorFromName(string product)
    {
        var first = product.Split(' ', 2)[0];
        return product.Contains(' ') && KnownVendors.Contains(first) ? first : null;
    }

    /// <summary>
    /// Devices a tool has not heard from in <see cref="StaleDays"/> days are left out: consoles keep retired laptops for
    /// months, and a verdict against a machine that no longer exists is noise. Accepts ISO 8601 or Unix seconds/milliseconds.
    /// </summary>
    public const int StaleDays = 90;

    public static bool IsStale(string? lastSeen, DateTime? now = null)
    {
        var when = ParseTime(lastSeen);
        return when is not null && when.Value < (now ?? DateTime.UtcNow).AddDays(-StaleDays);
    }

    public static DateTime? ParseTime(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        if (double.TryParse(s, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var n) && n > 0)
            return (n > 1e11 ? DateTimeOffset.FromUnixTimeMilliseconds((long)n) : DateTimeOffset.FromUnixTimeSeconds((long)n)).UtcDateTime;
        return DateTimeOffset.TryParse(s, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var d) ? d.UtcDateTime : null;
    }

    /// <summary>"com.google.Chrome" to "google"; "org.mozilla.firefox" to "mozilla"; null when the id has no reverse-DNS prefix.</summary>
    public static string? BundleVendor(string bundleId)
    {
        var parts = bundleId.Split('.');
        return parts.Length >= 3 && parts[0].ToLowerInvariant() is "com" or "org" or "net" or "io" or "us" or "co" or "de" or "uk" ? parts[1] : null;
    }

    // " en-GB" inside "(x64 en-GB)": the locale half of the Firefox and Thunderbird naming, removed before the architecture
    [GeneratedRegex(@"\s+[a-z]{2}-[A-Z]{2}(?=\))")] private static partial Regex LocaleSuffix();
}
