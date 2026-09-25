using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Endpoints;

/// <summary>
/// Kandji (Iru) Apple device management: devices with their OS versions, each device's network details and its
/// installed apps. Auth is an API token scoped to the device list, device details and device apps endpoints.
/// Read-only: GET requests only.
/// </summary>
public sealed class KandjiAdapter : IInventoryAdapter
{
    public const int PageSize = 300;
    public static string DevicesPath(int offset) => "/api/v1/devices?limit=" + PageSize + "&offset=" + offset;
    public static string DetailsPath(string id) => "/api/v1/devices/" + Uri.EscapeDataString(id) + "/details";
    public static string AppsPath(string id) => "/api/v1/devices/" + Uri.EscapeDataString(id) + "/apps";

    private readonly IHttpClientFactory _http;
    private readonly ILogger _log;
    public Func<TimeSpan, CancellationToken, Task>? Delay { get; set; }

    public KandjiAdapter(IHttpClientFactory http, ILogger<KandjiAdapter>? log = null)
    {
        _http = http; _log = (ILogger?)log ?? NullLogger.Instance;
    }

    public AdapterMetadata Metadata { get; } = new(
        Id: "kandji",
        DisplayName: "Kandji (Apple devices and apps)",
        Vendor: "Kandji",
        Description: "Reads Macs, iPhones, iPads and Apple TVs with their OS versions, network addresses and installed apps from the Kandji API. Read-only.",
        Kinds: new[] { AssetKind.Endpoint },
        Form: new[]
        {
            new CredentialField("apiUrl", "API URL", CredentialTypes.Text, "Settings > Access > API URL, e.g. https://yourcompany.api.kandji.io (EU tenants: .api.eu.kandji.io)."),
            new CredentialField("apiToken", "API token", CredentialTypes.Password, "A token with only the Device list, Device details and Device apps permissions."),
            new CredentialField("includeApps", "Read installed apps", CredentialTypes.Bool, "One extra call per device.", Required: false, Default: "true"),
        },
        MinimumPermission: "an API token limited to Device list, Device details and Device apps (read)",
        DocsUrl: "https://api-docs.kandji.io/",
        DefaultIntervalMinutes: 360);

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            var api = Open(credentials);
            await api.GetJsonAsync("/api/v1/devices?limit=1&offset=0", ct);
            return new TestResult(true, "Connected to the Kandji API; device listing readable.");
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
        for (var offset = 0; offset < 500_000; offset += PageSize)
        {
            var page = EpJson.Items(await api.GetJsonAsync(DevicesPath(offset), ct), "results");
            devices.AddRange(page);
            if (page.Count < PageSize) break;
        }
        var includeApps = EpCreds.Bool(credentials, "includeApps", true);
        var stale = 0; var n = 0;
        foreach (var d in devices)
        {
            ct.ThrowIfCancellationRequested();
            var id = EpJson.Str(d, "device_id");
            if (id is null) continue;
            if (EndpointNaming.IsStale(EpJson.Str(d, "last_check_in"))) { stale++; continue; }
            n++;
            progress?.Report("Device " + n + "/" + devices.Count);
            JsonElement details = default;
            try { details = await api.GetJsonAsync(DetailsPath(id), ct); }
            catch (EndpointApiException ex) when (ex.Status is 403 or 404) { if (result.Warnings.Count < 50) result.Warnings.Add("Device details not readable for " + id + ": " + ex.Message); }
            var (asset, os) = MapDevice(d, details);
            result.Assets.Add(asset);
            if (os is not null) result.Software.Add(os);
            if (!includeApps) continue;
            try
            {
                var apps = MapApps(asset.ExternalId, await api.GetJsonAsync(AppsPath(id), ct));
                result.Software.AddRange(apps);
            }
            catch (EndpointApiException ex) when (ex.Status is 403)
            {
                result.Warnings.Add("Device apps are not readable (" + ex.Message + "); devices were still read.");
                includeApps = false;
            }
        }
        if (stale > 0) result.Warnings.Add(stale + " device(s) that have not checked in for " + EndpointNaming.StaleDays + " days were left out.");
        _log.LogInformation("Kandji: {Devices} devices, {Software} software records", result.Assets.Count, result.Software.Count);
        return result;
    }

    // ------------------------------------------------------------------ mapping (pure; tested with fixtures)

    public static (AssetRecord Asset, SoftwareRecord? Os) MapDevice(JsonElement d, JsonElement details)
    {
        var id = EpJson.Str(d, "device_id")!;
        var name = EpJson.Str(d, "device_name") ?? id;
        var platform = EpJson.Str(d, "platform") ?? "Mac";
        var os = EndpointNaming.Os(platform switch { "Mac" => "macOS", "iPhone" or "iPad" => "iOS", "AppleTV" => "tvOS", _ => platform }, EpJson.Str(d, "os_version"));
        var hasDetails = details.ValueKind == JsonValueKind.Object;
        var ips = hasDetails ? new[] { EpJson.Str(details, "network.ip_address") } : Array.Empty<string?>();
        var macs = hasDetails ? new[] { EpJson.Str(details, "network.mac_address") } : Array.Empty<string?>();
        var hostnames = new[] { name, hasDetails ? EpJson.Str(details, "network.local_hostname") : null };
        string? owner = null;
        if (EpJson.At(d, "user") is { ValueKind: JsonValueKind.Object } u) owner = EpJson.Str(u, "email", "name");
        var asset = EndpointNaming.Asset(id, name, os, hostnames, ips, macs, owner);
        return (asset, EndpointNaming.OsRecord(id, os));
    }

    public static List<SoftwareRecord> MapApps(string assetId, JsonElement root)
    {
        var apps = new List<SoftwareRecord>();
        foreach (var a in EpJson.Items(root, "apps"))
        {
            var rec = EndpointNaming.App(assetId, EpJson.Str(a, "app_name", "name"), null, EpJson.Str(a, "version"), bundleId: EpJson.Str(a, "bundle_id"));
            if (rec is not null) apps.Add(rec);
        }
        EndpointNaming.UniqueIds(apps);
        return apps;
    }

    private EndpointHttp Open(IReadOnlyDictionary<string, string> creds)
    {
        var baseUrl = EpCreds.BaseUrl(EpCreds.Get(creds, "apiUrl"));
        var token = EpCreds.Secret(creds, "apiToken").Trim();
        if (baseUrl.Length == 0 || token.Length == 0) throw new InvalidOperationException("API URL and API token are required");
        var api = new EndpointHttp(_http.CreateClient("adapter"), baseUrl, status => status switch
        {
            401 => "Kandji rejected the API token",
            403 => "the API token lacks the Device list, Device details or Device apps permission",
            _ => null
        })
        {
            Authorise = (req, _, _) => { req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token); return Task.CompletedTask; }
        };
        if (Delay is not null) api.Delay = Delay;
        return api;
    }
}
