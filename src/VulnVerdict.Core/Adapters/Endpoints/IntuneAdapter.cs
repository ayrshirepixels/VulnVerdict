using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Core.Adapters.Endpoints;

/// <summary>
/// Microsoft Intune through Microsoft Graph: managed devices (Windows, macOS, iOS/iPadOS, Android) and the apps Intune
/// detected on each. Windows devices report the full build with the update revision ("10.0.22631.3447"), so the OS
/// is matched at its patch level.
///
/// Auth is an Entra ID app registration with the client-credentials grant and the application permission
/// DeviceManagementManagedDevices.Read.All. Devices come from v1.0; detected apps per device come from the beta
/// endpoint ($expand=detectedApps), the only per-device route Graph offers for them. Read-only: GET requests only.
/// </summary>
public sealed class IntuneAdapter : IInventoryAdapter
{
    public const string LoginHost = "https://login.microsoftonline.com";
    public const string GraphHost = "https://graph.microsoft.com";
    public const string DevicesPath = "/v1.0/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,osVersion,wiFiMacAddress,ethernetMacAddress,userPrincipalName,emailAddress,lastSyncDateTime,azureADDeviceId,model,manufacturer,serialNumber,managedDeviceOwnerType";
    public static string AppsPath(string id) => "/beta/deviceManagement/managedDevices/" + Uri.EscapeDataString(id) + "?$select=id&$expand=detectedApps";

    private readonly IHttpClientFactory _http;
    private readonly ILogger _log;
    public Func<TimeSpan, CancellationToken, Task>? Delay { get; set; }

    public IntuneAdapter(IHttpClientFactory http, ILogger<IntuneAdapter>? log = null)
    {
        _http = http; _log = (ILogger?)log ?? NullLogger.Instance;
    }

    public AdapterMetadata Metadata { get; } = new(
        Id: "intune",
        DisplayName: "Microsoft Intune (managed devices and detected apps)",
        Vendor: "Microsoft",
        Description: "Reads Intune managed devices and the apps Intune detected on each through Microsoft Graph. Windows builds include the update revision, so the OS is matched at its patch level. Read-only.",
        Kinds: new[] { AssetKind.Endpoint, AssetKind.Server },
        Form: new[]
        {
            new CredentialField("tenantId", "Tenant ID", CredentialTypes.Text, "Directory (tenant) ID from the app registration's overview page."),
            new CredentialField("clientId", "Application (client) ID", CredentialTypes.Text),
            new CredentialField("clientSecret", "Client secret", CredentialTypes.Password, "A client secret value (not its ID) from Certificates & secrets."),
            new CredentialField(HealthNotices.SecretExpiresKey, "Client secret expires on", CredentialTypes.Date, "Optional. The console warns 30 days before, on screen and in the digest; the setup script prints this date.", Required: false),
            new CredentialField("includeApps", "Read detected apps", CredentialTypes.Bool, "One Graph call per device. Turn off to read devices and OS versions only.", Required: false, Default: "true"),
        },
        MinimumPermission: "an Entra ID app registration with the Microsoft Graph application permission DeviceManagementManagedDevices.Read.All (admin consent granted)",
        DocsUrl: "https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list",
        DefaultIntervalMinutes: 360);

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            var api = Open(credentials);
            var root = await api.GetJsonAsync(GraphHost + DevicesPath + "&$top=1", ct);
            return new TestResult(true, "Signed in to Microsoft Graph; Intune device listing readable" + (EpJson.Items(root).Count == 0 ? " (no managed devices yet)." : "."));
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
        progress?.Report("Listing Intune managed devices");
        var devices = new List<JsonElement>();
        string? next = GraphHost + DevicesPath;
        while (next is not null && devices.Count < 200_000)
        {
            var page = await api.GetJsonAsync(next, ct);
            devices.AddRange(EpJson.Items(page));
            next = EpJson.Str(page, "@odata.nextLink");
        }
        var includeApps = EpCreds.Bool(credentials, "includeApps", true); var appsFailed = false;
        var stale = 0; var n = 0;
        foreach (var d in devices)
        {
            ct.ThrowIfCancellationRequested();
            if (EndpointNaming.IsStale(EpJson.Str(d, "lastSyncDateTime"))) { stale++; continue; }
            var mapped = MapDevice(d);
            if (mapped is null) continue;
            var (asset, os) = mapped.Value;
            result.Assets.Add(asset);
            if (os is not null) result.Software.Add(os);
            n++;
            if (!includeApps) { if (appsFailed) result.IncompleteSoftware.Add(asset.ExternalId); continue; }
            progress?.Report("Device " + n + "/" + devices.Count + ": " + asset.DisplayName);
            try
            {
                var detail = await api.GetJsonAsync(GraphHost + AppsPath(asset.ExternalId), ct);
                var apps = EpJson.Arr(detail, "detectedApps").Select(a => MapApp(asset.ExternalId, a)).Where(a => a is not null).Select(a => a!).ToList();
                EndpointNaming.UniqueIds(apps);
                result.Software.AddRange(apps);
            }
            catch (EndpointApiException ex) when (ex.Status is 403 or 404)
            {
                result.Warnings.Add("Detected apps are not readable (" + ex.Message + "); devices and OS versions were still read.");
                includeApps = false; appsFailed = true; result.IncompleteSoftware.Add(asset.ExternalId);
            }
        }
        if (stale > 0) result.Warnings.Add(stale + " device(s) not synced with Intune for " + EndpointNaming.StaleDays + " days were left out.");
        _log.LogInformation("Intune: {Devices} devices, {Software} software records", result.Assets.Count, result.Software.Count);
        return result;
    }

    // ------------------------------------------------------------------ mapping (pure; tested with fixtures)

    public static (AssetRecord Asset, SoftwareRecord? Os)? MapDevice(JsonElement d)
    {
        var id = EpJson.Str(d, "id");
        if (id is null) return null;
        var name = EpJson.Str(d, "deviceName") ?? id;
        var os = EndpointNaming.Os(EpJson.Str(d, "operatingSystem"), EpJson.Str(d, "osVersion"));
        var asset = EndpointNaming.Asset(id, name, os, new[] { name }, Array.Empty<string>(),
            new[] { EpJson.Str(d, "wiFiMacAddress"), EpJson.Str(d, "ethernetMacAddress") },
            owner: EpJson.Str(d, "userPrincipalName", "emailAddress"));
        return (asset, EndpointNaming.OsRecord(id, os));
    }

    public static SoftwareRecord? MapApp(string assetId, JsonElement a) =>
        EndpointNaming.App(assetId, EpJson.Str(a, "displayName"), EpJson.Str(a, "publisher"), EpJson.Str(a, "version"));

    // ------------------------------------------------------------------ session

    private EndpointHttp Open(IReadOnlyDictionary<string, string> creds)
    {
        var tenant = EpCreds.Get(creds, "tenantId");
        var clientId = EpCreds.Get(creds, "clientId");
        var secret = EpCreds.Secret(creds, "clientSecret");
        if (tenant.Length == 0 || clientId.Length == 0 || secret.Length == 0) throw new InvalidOperationException("Tenant ID, client ID and client secret are required");
        var client = _http.CreateClient("adapter");
        var token = new BearerToken(ct => OAuthTokens.RequestAsync(client, LoginHost + "/" + Uri.EscapeDataString(tenant) + "/oauth2/v2.0/token",
            OAuthTokens.Form(("grant_type", "client_credentials"), ("client_id", clientId), ("client_secret", secret), ("scope", GraphHost + "/.default")), ct, what: "Entra ID token request"));
        var api = new EndpointHttp(client, GraphHost, status => status switch
        {
            401 => "Graph rejected the token",
            403 => "the app registration lacks DeviceManagementManagedDevices.Read.All, or admin consent has not been granted",
            _ => null
        }) { Authorise = token.Apply };
        if (Delay is not null) api.Delay = Delay;
        return api;
    }
}
