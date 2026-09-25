using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Endpoints;

/// <summary>
/// Datto RMM (Kaseya): account device list and each device's software audit. Datto reports the Windows version as
/// part of the OS text ("Microsoft Windows 11 Pro 10.0.22631") without the update revision, so Windows OS CVEs are
/// left to a source that knows the patch level. The software audit has names and versions but no publisher; well-known
/// vendors are recognised from the product name and the rest go to Needs mapping.
///
/// Auth is the account's API key and secret exchanged for a token at the platform's API URL. Read-only: GET requests
/// only after the token request.
/// </summary>
public sealed class DattoRmmAdapter : IInventoryAdapter
{
    public const string TokenPath = "/auth/oauth/token";
    public const int PageSize = 250;
    public const string DevicesPath = "/api/v2/account/devices?max=250";
    public static string SoftwarePath(string uid) => "/api/v2/audit/device/" + Uri.EscapeDataString(uid) + "/software?max=250";

    private readonly IHttpClientFactory _http;
    private readonly ILogger _log;
    public Func<TimeSpan, CancellationToken, Task>? Delay { get; set; }

    public DattoRmmAdapter(IHttpClientFactory http, ILogger<DattoRmmAdapter>? log = null)
    {
        _http = http; _log = (ILogger?)log ?? NullLogger.Instance;
    }

    public AdapterMetadata Metadata { get; } = new(
        Id: "datto-rmm",
        DisplayName: "Datto RMM (devices and software audit)",
        Vendor: "Kaseya",
        Description: "Reads devices and each device's software audit from the Datto RMM API. Datto does not report the Windows update revision, so Windows OS CVEs come from another source. Read-only.",
        Kinds: new[] { AssetKind.Endpoint, AssetKind.Server },
        Form: new[]
        {
            new CredentialField("apiUrl", "API URL", CredentialTypes.Text, "Setup > Global Settings > Access Control shows it, e.g. https://pinotage-api.centrastage.net (the host depends on your platform)."),
            new CredentialField("apiKey", "API key", CredentialTypes.Text, "From the API user's page (Setup > Users > the user > Generate API keys)."),
            new CredentialField("apiSecret", "API secret key", CredentialTypes.Password),
        },
        MinimumPermission: "an API-enabled user whose security level allows viewing devices and audit data only (no job, component or settings rights)",
        DocsUrl: "https://rmm.datto.com/help/en/Content/2SETUP/APIv2.htm",
        DefaultIntervalMinutes: 480);

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            var api = Open(credentials);
            var root = await api.GetJsonAsync("/api/v2/account/devices?max=1", ct);
            return new TestResult(true, "Signed in to Datto RMM; " + (EpJson.Int(root, "pageDetails.totalCount") ?? EpJson.Items(root, "devices").Count) + " device(s) visible.");
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
        var devices = await PagesAsync(api, DevicesPath, "devices", ct);

        var stale = 0; var noPatchLevel = 0; var n = 0;
        foreach (var d in devices)
        {
            ct.ThrowIfCancellationRequested();
            if (EpJson.Bool(d, "deleted") == true) continue;
            if (EndpointNaming.IsStale(EpJson.Str(d, "lastSeen"))) { stale++; continue; }
            var mapped = MapDevice(d);
            if (mapped is null) continue;
            var (asset, os) = mapped.Value;
            result.Assets.Add(asset);
            if (os is not null) result.Software.Add(os);
            else if (asset.OsVendor == "Microsoft") noPatchLevel++;
            n++;
            progress?.Report("Device " + n + "/" + devices.Count + ": " + asset.DisplayName);
            var uid = EpJson.Str(d, "uid")!;
            try
            {
                var apps = (await PagesAsync(api, SoftwarePath(uid), "software", ct)).Select(s => EndpointNaming.App(asset.ExternalId, EpJson.Str(s, "name"), null, EpJson.Str(s, "version")))
                    .Where(s => s is not null).Select(s => s!).ToList();
                EndpointNaming.UniqueIds(apps);
                result.Software.AddRange(apps);
            }
            catch (EndpointApiException ex) when (ex.Status is 404)
            {
                // devices that have never been audited (new, or ESXi hosts and network nodes) have no software audit;
                // whatever an earlier audit reported is kept rather than marked removed
                result.IncompleteSoftware.Add(asset.ExternalId);
            }
        }
        if (stale > 0) result.Warnings.Add(stale + " device(s) not seen for " + EndpointNaming.StaleDays + " days were left out.");
        if (noPatchLevel > 0) result.Warnings.Add(noPatchLevel + " Windows device(s): Datto RMM does not report the update revision, so their OS CVEs are assessed only where another connector (WinRM, Intune, Defender, ConfigMgr) sees them.");
        _log.LogInformation("Datto RMM: {Devices} devices, {Software} software records", result.Assets.Count, result.Software.Count);
        return result;
    }

    /// <summary>Datto pages carry pageDetails.nextPageUrl (absolute, or null on the last page).</summary>
    private static async Task<List<JsonElement>> PagesAsync(EndpointHttp api, string path, string collection, CancellationToken ct)
    {
        var items = new List<JsonElement>();
        string? next = path;
        for (var pages = 0; next is not null && pages < 10_000; pages++)
        {
            var root = await api.GetJsonAsync(next, ct);
            items.AddRange(EpJson.Items(root, collection));
            var url = EpJson.Str(root, "pageDetails.nextPageUrl");
            next = url is null || url == next ? null : url;
        }
        return items;
    }

    // ------------------------------------------------------------------ mapping (pure; tested with fixtures)

    public static (AssetRecord Asset, SoftwareRecord? Os)? MapDevice(JsonElement d)
    {
        var uid = EpJson.Str(d, "uid");
        if (uid is null) return null;
        var name = EpJson.Str(d, "hostname") ?? uid;
        var category = EpJson.Str(d, "deviceType.category") ?? "";
        var osText = EpJson.Str(d, "operatingSystem") ?? "";
        var os = EndpointNaming.Os(osText, osText, null, null, category.Contains("Server", StringComparison.OrdinalIgnoreCase) ? true : null);
        var asset = EndpointNaming.Asset(uid, name, os, new[] { name }, new[] { EpJson.Str(d, "intIpAddress") }, Array.Empty<string?>(),
            owner: EpJson.Str(d, "lastLoggedInUser"), kindHint: category);
        return (asset, EndpointNaming.OsRecord(uid, os));
    }

    private EndpointHttp Open(IReadOnlyDictionary<string, string> creds)
    {
        var baseUrl = EpCreds.BaseUrl(EpCreds.Get(creds, "apiUrl"));
        var key = EpCreds.Get(creds, "apiKey");
        var secret = EpCreds.Secret(creds, "apiSecret");
        if (baseUrl.Length == 0 || key.Length == 0 || secret.Length == 0) throw new InvalidOperationException("API URL, API key and API secret are required");
        var client = _http.CreateClient("adapter");
        // Datto's documented token exchange: the fixed public client "public-client:public" with the password grant
        var token = new BearerToken(ct => OAuthTokens.RequestAsync(client, baseUrl + TokenPath,
            OAuthTokens.Form(("grant_type", "password"), ("username", key), ("password", secret)), ct, OAuthTokens.Basic("public-client", "public"), "Datto RMM token request"));
        var api = new EndpointHttp(client, baseUrl, status => status switch
        {
            401 => "Datto RMM rejected the token",
            403 => "the API user's security level does not allow reading devices or audit data",
            _ => null
        }) { Authorise = token.Apply };
        if (Delay is not null) api.Delay = Delay;
        return api;
    }
}
