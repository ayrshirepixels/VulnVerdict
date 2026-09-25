using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Endpoints;

/// <summary>
/// N-able N-central REST API: the device list and each device's asset record (OS, network adapters, applications).
/// The user-API token (a JWT generated for an API-only user) is exchanged for a short-lived access token at
/// /api/auth/authenticate and exchanged again when it expires. The asset record's section names vary between
/// N-central releases, so applications and adapters are found by shape rather than by one fixed path.
/// Read-only: GET requests only after authentication.
/// </summary>
public sealed class NCentralAdapter : IInventoryAdapter
{
    public const string AuthPath = "/api/auth/authenticate";
    public const int PageSize = 500;
    public static string DevicesPath(int page) => "/api/devices?pageNumber=" + page + "&pageSize=" + PageSize;
    public static string AssetsPath(string id) => "/api/devices/" + Uri.EscapeDataString(id) + "/assets";

    private readonly IHttpClientFactory _http;
    private readonly ILogger _log;
    public Func<TimeSpan, CancellationToken, Task>? Delay { get; set; }

    public NCentralAdapter(IHttpClientFactory http, ILogger<NCentralAdapter>? log = null)
    {
        _http = http; _log = (ILogger?)log ?? NullLogger.Instance;
    }

    public AdapterMetadata Metadata { get; } = new(
        Id: "n-central",
        DisplayName: "N-able N-central (devices and asset inventory)",
        Vendor: "N-able",
        Description: "Reads devices and their asset inventory (OS, network adapters, installed applications) from the N-central REST API. Read-only.",
        Kinds: new[] { AssetKind.Endpoint, AssetKind.Server },
        Form: new[]
        {
            new CredentialField("host", "N-central server", CredentialTypes.Text, "e.g. ncentral.example.com or your hosted N-central address."),
            new CredentialField("apiToken", "User-API token (JWT)", CredentialTypes.Password, "Administration > User Management > Users > an API-only user > API Access > Generate JSON Web Token."),
            EpCreds.VerifyTls("N-central server"),
        },
        MinimumPermission: "an API-only N-central user with a read-only role over the customers and sites to read, and MFA not required for API access",
        DocsUrl: "https://developer.n-able.com/n-central/docs/getting-started-with-the-n-central-api",
        DefaultIntervalMinutes: 480);

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            var api = Open(credentials);
            var root = await api.GetJsonAsync("/api/devices?pageNumber=1&pageSize=1", ct);
            return new TestResult(true, "Signed in to N-central; " + (EpJson.Int(root, "totalItems") ?? EpJson.Items(root).Count) + " device(s) visible.");
        }
        catch (Exception ex) when (ex is EndpointApiException or HttpRequestException or JsonException or InvalidOperationException or TaskCanceledException)
        {
            return new TestResult(false, ex.Message);
        }
    }

    public async Task<CollectResult> CollectAsync(IReadOnlyDictionary<string, string> credentials, DateTime? since, IProgress<string>? progress, CancellationToken ct)
    {
        var api = Open(credentials);
        var result = new CollectResult { FullSnapshot = true };
        progress?.Report("Listing devices");
        var devices = new List<JsonElement>();
        for (var page = 1; page < 5000; page++)
        {
            var root = await api.GetJsonAsync(DevicesPath(page), ct);
            var batch = EpJson.Items(root);
            devices.AddRange(batch);
            var pages = EpJson.Int(root, "totalPages");
            if (batch.Count < PageSize || (pages is not null && page >= pages)) break;
        }

        var noPatchLevel = 0; var n = 0; var assetsReadable = true;
        foreach (var d in devices)
        {
            ct.ThrowIfCancellationRequested();
            if (EpJson.Bool(d, "isProbe") == true) continue;
            var id = EpJson.Str(d, "deviceId");
            if (id is null) continue;
            n++;
            progress?.Report("Device " + n + "/" + devices.Count);
            JsonElement assets = default;
            if (assetsReadable)
            {
                try { assets = await api.GetJsonAsync(AssetsPath(id), ct); }
                catch (EndpointApiException ex) when (ex.Status is 403 or 404)
                {
                    if (ex.Status == 403) { assetsReadable = false; result.Warnings.Add("Device asset records are not readable (" + ex.Message + "); devices were still read."); }
                }
            }
            var (asset, os, apps) = Map(d, assets);
            // no asset record this run: keep what an earlier run reported rather than marking it removed
            if (assets.ValueKind != System.Text.Json.JsonValueKind.Object) result.IncompleteSoftware.Add(asset.ExternalId);
            result.Assets.Add(asset);
            if (os is not null) result.Software.Add(os);
            else if (asset.OsVendor == "Microsoft") noPatchLevel++;
            result.Software.AddRange(apps);
        }
        if (noPatchLevel > 0) result.Warnings.Add(noPatchLevel + " Windows device(s) without the update revision in N-central's asset record: their OS CVEs are assessed only where another connector (WinRM, Intune, Defender, ConfigMgr) sees them.");
        _log.LogInformation("N-central: {Devices} devices, {Software} software records", result.Assets.Count, result.Software.Count);
        return result;
    }

    // ------------------------------------------------------------------ mapping (pure; tested with fixtures)

    public static (AssetRecord Asset, SoftwareRecord? Os, List<SoftwareRecord> Apps) Map(JsonElement d, JsonElement assetsRoot)
    {
        var id = EpJson.Str(d, "deviceId")!;
        var name = EpJson.Str(d, "longName", "discoveredName") ?? id;
        var deviceClass = EpJson.Str(d, "deviceClass", "deviceClassLabel") ?? "";
        var a = assetsRoot.ValueKind == JsonValueKind.Object && EpJson.At(assetsRoot, "data") is { ValueKind: JsonValueKind.Object } data ? data : assetsRoot;
        var hasAssets = a.ValueKind == JsonValueKind.Object;

        string? osName = EpJson.Str(d, "supportedOs", "osName"), osVersion = null, osBuild = null;
        if (hasAssets && EpJson.At(a, "os") is { } osNode)
        {
            var o = osNode.ValueKind == JsonValueKind.Array ? osNode.EnumerateArray().FirstOrDefault() : osNode;
            if (o.ValueKind == JsonValueKind.Object)
            {
                osName = EpJson.Str(o, "reportedos", "reportedOs", "name", "caption") ?? osName;
                osVersion = EpJson.Str(o, "version");
                osBuild = EpJson.Str(o, "buildnumber", "buildNumber");
            }
        }
        var os = EndpointNaming.Os(osName, osVersion, osBuild, null, deviceClass.Contains("Server", StringComparison.OrdinalIgnoreCase) ? true : null);

        var ips = new List<string?> { EpJson.Str(d, "uri") };
        var macs = new List<string?>();
        var apps = new List<SoftwareRecord>();
        if (hasAssets)
        {
            foreach (var nic in Section(a, "networkadapter", "networkAdapter", "network"))
            {
                ips.AddRange(EpJson.Strings(nic, "ipaddress").Concat(EpJson.Strings(nic, "ipAddress")));
                macs.Add(EpJson.Str(nic, "macaddress", "macAddress"));
            }
            foreach (var app in Section(a, "application", "applications", "software"))
            {
                var rec = EndpointNaming.App(id, EpJson.Str(app, "displayname", "displayName", "name"), EpJson.Str(app, "publisher", "vendor"), EpJson.Str(app, "version"));
                if (rec is not null) apps.Add(rec);
            }
        }
        EndpointNaming.UniqueIds(apps);
        var asset = EndpointNaming.Asset(id, name, os, new[] { name, EpJson.Str(d, "discoveredName") }, ips, macs,
            owner: EpJson.Str(d, "lastLoggedInUser"), kindHint: deviceClass);
        return (asset, EndpointNaming.OsRecord(id, os), apps);
    }

    /// <summary>An asset section as a list: an array, an object holding one array, or a single object.</summary>
    private static List<JsonElement> Section(JsonElement a, params string[] names)
    {
        foreach (var n in names)
        {
            if (EpJson.At(a, n) is not { } v) continue;
            if (v.ValueKind == JsonValueKind.Array) return v.EnumerateArray().ToList();
            if (v.ValueKind == JsonValueKind.Object)
            {
                foreach (var p in v.EnumerateObject())
                    if (p.Value.ValueKind == JsonValueKind.Array) return p.Value.EnumerateArray().ToList();
                return new List<JsonElement> { v };
            }
        }
        return new();
    }

    private EndpointHttp Open(IReadOnlyDictionary<string, string> creds)
    {
        var baseUrl = EpCreds.BaseUrl(EpCreds.Get(creds, "host"));
        var jwt = EpCreds.Secret(creds, "apiToken").Trim();
        if (baseUrl.Length == 0 || jwt.Length == 0) throw new InvalidOperationException("N-central server and user-API token are required");
        var client = _http.CreateClient(EpCreds.Bool(creds, "verifyTls", true) ? "adapter" : "adapter-insecure");
        var token = new BearerToken(ct => OAuthTokens.RequestAsync(client, baseUrl + AuthPath, null, ct, new AuthenticationHeaderValue("Bearer", jwt), "N-central authentication"));
        var api = new EndpointHttp(client, baseUrl, status => status switch
        {
            401 => "N-central rejected the token (a regenerated JWT invalidates the old one)",
            403 => "the API user's role cannot read these devices",
            _ => null
        }) { Authorise = token.Apply };
        if (Delay is not null) api.Delay = Delay;
        return api;
    }
}
