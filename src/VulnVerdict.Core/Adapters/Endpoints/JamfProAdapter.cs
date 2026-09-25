using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Endpoints;

/// <summary>
/// Jamf Pro (cloud or on-premises): computers with their macOS version and installed applications from the
/// computers-inventory API, and mobile devices with their iOS / iPadOS version. macOS and iOS versions are exact
/// ("14.4.1"), so the OS is matched at its patch level. Application vendors come from the bundle id.
///
/// Auth is a Jamf Pro API client (client credentials) whose API role grants Read Computers and Read Mobile Devices.
/// Read-only: GET requests only after the token request.
/// </summary>
public sealed class JamfProAdapter : IInventoryAdapter
{
    public const string TokenPath = "/api/oauth/token";
    public const int PageSize = 100;
    public static string ComputersPath(int page) => "/api/v1/computers-inventory?section=GENERAL&section=HARDWARE&section=OPERATING_SYSTEM&section=APPLICATIONS&section=USER_AND_LOCATION&page=" + page + "&page-size=" + PageSize + "&sort=id%3Aasc";
    public static string MobilePath(int page) => "/api/v2/mobile-devices/detail?section=GENERAL&section=HARDWARE&section=USER_AND_LOCATION&page=" + page + "&page-size=" + PageSize + "&sort=mobileDeviceId%3Aasc";

    private readonly IHttpClientFactory _http;
    private readonly ILogger _log;
    public Func<TimeSpan, CancellationToken, Task>? Delay { get; set; }

    public JamfProAdapter(IHttpClientFactory http, ILogger<JamfProAdapter>? log = null)
    {
        _http = http; _log = (ILogger?)log ?? NullLogger.Instance;
    }

    public AdapterMetadata Metadata { get; } = new(
        Id: "jamf-pro",
        DisplayName: "Jamf Pro (Macs, iPhones and iPads)",
        Vendor: "Jamf",
        Description: "Reads computers with macOS versions and installed applications, and mobile devices with iOS and iPadOS versions, from the Jamf Pro API. Read-only.",
        Kinds: new[] { AssetKind.Endpoint },
        Form: new[]
        {
            new CredentialField("url", "Jamf Pro URL", CredentialTypes.Text, "e.g. https://yourcompany.jamfcloud.com or https://jamf.example.local:8443"),
            new CredentialField("clientId", "API client ID", CredentialTypes.Text, "Settings > API roles and clients > API clients."),
            new CredentialField("clientSecret", "API client secret", CredentialTypes.Password),
            new CredentialField("includeMobile", "Read mobile devices", CredentialTypes.Bool, "iPhones and iPads with their OS versions.", Required: false, Default: "true"),
            EpCreds.VerifyTls("Jamf Pro server"),
        },
        MinimumPermission: "a Jamf Pro API client whose API role has only Read Computers and Read Mobile Devices",
        DocsUrl: "https://developer.jamf.com/jamf-pro/reference/get_v1-computers-inventory",
        DefaultIntervalMinutes: 360);

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            var api = Open(credentials);
            var root = await api.GetJsonAsync("/api/v1/computers-inventory?section=GENERAL&page=0&page-size=1", ct);
            return new TestResult(true, "Signed in to Jamf Pro; " + (EpJson.Int(root, "totalCount") ?? 0) + " computer(s) visible to this API client.");
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
        var stale = 0;

        progress?.Report("Reading computers");
        foreach (var c in await PagesAsync(api, ComputersPath, ct))
        {
            if (EndpointNaming.IsStale(EpJson.Str(c, "general.lastContactTime", "general.reportDate"))) { stale++; continue; }
            var mapped = MapComputer(c);
            if (mapped is null) continue;
            result.Assets.Add(mapped.Value.Asset);
            if (mapped.Value.Os is not null) result.Software.Add(mapped.Value.Os);
            result.Software.AddRange(mapped.Value.Apps);
        }
        if (EpCreds.Bool(credentials, "includeMobile", true))
        {
            progress?.Report("Reading mobile devices");
            try
            {
                foreach (var m in await PagesAsync(api, MobilePath, ct))
                {
                    if (EndpointNaming.IsStale(EpJson.Str(m, "general.lastInventoryUpdateDate", "general.lastInventoryUpdateTimestamp"))) { stale++; continue; }
                    var mapped = MapMobile(m);
                    if (mapped is null) continue;
                    result.Assets.Add(mapped.Value.Asset);
                    if (mapped.Value.Os is not null) result.Software.Add(mapped.Value.Os);
                }
            }
            catch (EndpointApiException ex) when (ex.Status is 403 or 404)
            {
                result.Warnings.Add("Mobile devices are not readable (" + ex.Message + "); computers were still read.");
            }
        }
        if (stale > 0) result.Warnings.Add(stale + " device(s) that have not checked in for " + EndpointNaming.StaleDays + " days were left out.");
        _log.LogInformation("Jamf Pro: {Devices} devices, {Software} software records", result.Assets.Count, result.Software.Count);
        return result;
    }

    private static async Task<List<JsonElement>> PagesAsync(EndpointHttp api, Func<int, string> path, CancellationToken ct)
    {
        var items = new List<JsonElement>();
        for (var page = 0; page < 5000; page++)
        {
            var root = await api.GetJsonAsync(path(page), ct);
            var batch = EpJson.Items(root, "results");
            items.AddRange(batch);
            var total = EpJson.Int(root, "totalCount");
            if (batch.Count < PageSize || (total is not null && items.Count >= total)) break;
        }
        return items;
    }

    // ------------------------------------------------------------------ mapping (pure; tested with fixtures)

    public static (AssetRecord Asset, SoftwareRecord? Os, List<SoftwareRecord> Apps)? MapComputer(JsonElement c)
    {
        var id = EpJson.Str(c, "id");
        if (id is null) return null;
        var extId = "computer:" + id;
        var name = EpJson.Str(c, "general.name") ?? extId;
        var os = EndpointNaming.Os(EpJson.Str(c, "operatingSystem.name") ?? "macOS", EpJson.Str(c, "operatingSystem.version"), EpJson.Str(c, "operatingSystem.build"));
        var asset = EndpointNaming.Asset(extId, name, os, new[] { name },
            new[] { EpJson.Str(c, "general.lastIpAddress") },
            new[] { EpJson.Str(c, "hardware.macAddress"), EpJson.Str(c, "hardware.altMacAddress") },
            owner: EpJson.Str(c, "userAndLocation.email", "userAndLocation.username"));
        var apps = new List<SoftwareRecord>();
        foreach (var a in EpJson.Arr(c, "applications"))
        {
            var rec = EndpointNaming.App(extId, EpJson.Str(a, "name"), null, EpJson.Str(a, "version", "shortVersion"), bundleId: EpJson.Str(a, "bundleId"));
            if (rec is not null) apps.Add(rec);
        }
        EndpointNaming.UniqueIds(apps);
        return (asset, EndpointNaming.OsRecord(extId, os), apps);
    }

    public static (AssetRecord Asset, SoftwareRecord? Os)? MapMobile(JsonElement m)
    {
        var id = EpJson.Str(m, "mobileDeviceId", "id");
        if (id is null) return null;
        var extId = "mobile:" + id;
        var name = EpJson.Str(m, "general.displayName", "general.deviceName", "name") ?? extId;
        var type = EpJson.Str(m, "deviceType") ?? "iOS";
        var os = EndpointNaming.Os(type, EpJson.Str(m, "general.osVersion"), EpJson.Str(m, "general.osBuild"));
        var asset = EndpointNaming.Asset(extId, name, os, new[] { name },
            new[] { EpJson.Str(m, "general.ipAddress") },
            new[] { EpJson.Str(m, "hardware.wifiMacAddress") },
            owner: EpJson.Str(m, "userAndLocation.emailAddress", "userAndLocation.email", "userAndLocation.username"));
        return (asset, EndpointNaming.OsRecord(extId, os));
    }

    // ------------------------------------------------------------------ session

    private EndpointHttp Open(IReadOnlyDictionary<string, string> creds)
    {
        var baseUrl = EpCreds.BaseUrl(EpCreds.Get(creds, "url"));
        var clientId = EpCreds.Get(creds, "clientId");
        var secret = EpCreds.Secret(creds, "clientSecret");
        if (baseUrl.Length == 0 || clientId.Length == 0 || secret.Length == 0) throw new InvalidOperationException("Jamf Pro URL, client ID and client secret are required");
        var client = _http.CreateClient(EpCreds.Bool(creds, "verifyTls", true) ? "adapter" : "adapter-insecure");
        var token = new BearerToken(ct => OAuthTokens.RequestAsync(client, baseUrl + TokenPath,
            OAuthTokens.Form(("grant_type", "client_credentials"), ("client_id", clientId), ("client_secret", secret)), ct, what: "Jamf Pro token request"));
        var api = new EndpointHttp(client, baseUrl, status => status switch
        {
            401 => "Jamf Pro rejected the API client token",
            403 => "the API client's role lacks Read Computers or Read Mobile Devices",
            _ => null
        }) { Authorise = token.Apply };
        if (Delay is not null) api.Delay = Delay;
        return api;
    }
}
