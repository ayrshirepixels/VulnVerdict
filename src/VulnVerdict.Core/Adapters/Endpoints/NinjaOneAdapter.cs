using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Endpoints;

/// <summary>
/// NinjaOne RMM: detailed device list and the estate-wide software query. NinjaOne reports the Windows build
/// ("22631") and feature release ("23H2") but not the update revision, so Windows devices are recorded with their OS
/// but their OS CVEs are left to a source that knows the patch level (WinRM, Intune, Defender, ConfigMgr);
/// installed software is matched as usual. macOS versions are exact.
///
/// Auth is a NinjaOne API client application (client credentials, scope "monitoring"). Read-only: GET requests only
/// after the token request.
/// </summary>
public sealed class NinjaOneAdapter : IInventoryAdapter
{
    public const string TokenPath = "/ws/oauth/token";
    public const int DevicePageSize = 500;
    public const int SoftwarePageSize = 1000;
    public static string DevicesPath(long? after) => "/v2/devices-detailed?pageSize=" + DevicePageSize + (after is null ? "" : "&after=" + after);
    public static string SoftwarePath(string? cursor) => "/v2/queries/software?pageSize=" + SoftwarePageSize + (cursor is null ? "" : "&cursor=" + Uri.EscapeDataString(cursor));

    private readonly IHttpClientFactory _http;
    private readonly ILogger _log;
    public Func<TimeSpan, CancellationToken, Task>? Delay { get; set; }

    public NinjaOneAdapter(IHttpClientFactory http, ILogger<NinjaOneAdapter>? log = null)
    {
        _http = http; _log = (ILogger?)log ?? NullLogger.Instance;
    }

    public AdapterMetadata Metadata { get; } = new(
        Id: "ninjaone",
        DisplayName: "NinjaOne RMM (devices and installed software)",
        Vendor: "NinjaOne",
        Description: "Reads managed devices and installed software from the NinjaOne public API. NinjaOne does not report the Windows update revision, so Windows OS CVEs come from another source. Read-only.",
        Kinds: new[] { AssetKind.Endpoint, AssetKind.Server },
        Form: new[]
        {
            new CredentialField("instance", "Instance", CredentialTypes.Text, "The region host you sign in to: app.ninjarmm.com, eu.ninjarmm.com, ca.ninjarmm.com, oc.ninjarmm.com or us2.ninjarmm.com.", Default: "app.ninjarmm.com"),
            new CredentialField("clientId", "Client ID", CredentialTypes.Text, "Administration > Apps > API > Client app IDs: an API Services (machine-to-machine) application."),
            new CredentialField("clientSecret", "Client secret", CredentialTypes.Password),
        },
        MinimumPermission: "an API Services client application with the Monitoring scope only and the Client Credentials grant",
        DocsUrl: "https://app.ninjarmm.com/apidocs/?links.active=core",
        DefaultIntervalMinutes: 360);

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            var api = Open(credentials);
            await api.GetJsonAsync("/v2/devices?pageSize=1", ct);
            return new TestResult(true, "Signed in to NinjaOne; device listing readable.");
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
        long? after = null;
        while (devices.Count < 500_000)
        {
            var page = EpJson.Items(await api.GetJsonAsync(DevicesPath(after), ct));
            devices.AddRange(page);
            var last = page.Count > 0 ? EpJson.Int(page[^1], "id") : null;
            if (page.Count < DevicePageSize || last is null || last == after) break;
            after = last;
        }

        var stale = 0; var noPatchLevel = 0;
        var kept = new HashSet<string>();
        foreach (var d in devices)
        {
            if (EndpointNaming.IsStale(EpJson.Str(d, "lastContact"))) { stale++; continue; }
            var mapped = MapDevice(d);
            if (mapped is null) continue;
            result.Assets.Add(mapped.Value.Asset);
            kept.Add(mapped.Value.Asset.ExternalId);
            if (mapped.Value.Os is not null) result.Software.Add(mapped.Value.Os);
            else if (mapped.Value.Asset.OsVendor == "Microsoft") noPatchLevel++;
        }

        progress?.Report("Reading installed software");
        var software = new List<SoftwareRecord>();
        string? cursor = null;
        for (var pages = 0; pages < 10_000; pages++)
        {
            var root = await api.GetJsonAsync(SoftwarePath(cursor), ct);
            var rows = EpJson.Items(root, "results");
            foreach (var r in rows)
            {
                var rec = MapSoftware(r);
                if (rec is not null && kept.Contains(rec.AssetExternalId)) software.Add(rec);
            }
            var nextCursor = EpJson.Str(root, "cursor.name");
            if (rows.Count < SoftwarePageSize || nextCursor is null || nextCursor == cursor) break;
            cursor = nextCursor;
        }
        EndpointNaming.UniqueIds(software);
        result.Software.AddRange(software);

        if (stale > 0) result.Warnings.Add(stale + " device(s) not in contact for " + EndpointNaming.StaleDays + " days were left out.");
        if (noPatchLevel > 0) result.Warnings.Add(noPatchLevel + " Windows device(s): NinjaOne does not report the update revision, so their OS CVEs are assessed only where another connector (WinRM, Intune, Defender, ConfigMgr) sees them.");
        _log.LogInformation("NinjaOne: {Devices} devices, {Software} software records", result.Assets.Count, result.Software.Count);
        return result;
    }

    // ------------------------------------------------------------------ mapping (pure; tested with fixtures)

    public static (AssetRecord Asset, SoftwareRecord? Os)? MapDevice(JsonElement d)
    {
        var id = EpJson.Str(d, "id");
        if (id is null) return null;
        var name = EpJson.Str(d, "systemName", "displayName", "dnsName") ?? id;
        var nodeClass = EpJson.Str(d, "nodeClass") ?? "";
        var osName = EpJson.Str(d, "os.name") ?? (nodeClass.StartsWith("MAC") ? "macOS" : nodeClass.StartsWith("LINUX") ? "Linux" : nodeClass.StartsWith("WINDOWS") ? "Windows" : null);
        var os = EndpointNaming.Os(osName, EpJson.Str(d, "os.version"), EpJson.Str(d, "os.buildNumber"), EpJson.Str(d, "os.releaseId"),
            nodeClass.Contains("SERVER") ? true : null);
        var asset = EndpointNaming.Asset(id, name, os, new[] { name, EpJson.Str(d, "dnsName") }, EpJson.Strings(d, "ipAddresses"), EpJson.Strings(d, "macAddresses"),
            owner: EpJson.Str(d, "lastLoggedInUser"), kindHint: nodeClass.Replace('_', ' '));
        return (asset, EndpointNaming.OsRecord(id, os));
    }

    public static SoftwareRecord? MapSoftware(JsonElement r)
    {
        var device = EpJson.Str(r, "deviceId");
        if (device is null) return null;
        return EndpointNaming.App(device, EpJson.Str(r, "name"), EpJson.Str(r, "publisher"), EpJson.Str(r, "version"),
            EpJson.Str(r, "productCode") is { } pc ? "app:" + pc.ToLowerInvariant() : null);
    }

    private EndpointHttp Open(IReadOnlyDictionary<string, string> creds)
    {
        var baseUrl = EpCreds.BaseUrl(EpCreds.Get(creds, "instance") is { Length: > 0 } i ? i : "app.ninjarmm.com");
        var clientId = EpCreds.Get(creds, "clientId");
        var secret = EpCreds.Secret(creds, "clientSecret");
        if (clientId.Length == 0 || secret.Length == 0) throw new InvalidOperationException("Client ID and client secret are required");
        var client = _http.CreateClient("adapter");
        var token = new BearerToken(ct => OAuthTokens.RequestAsync(client, baseUrl + TokenPath,
            OAuthTokens.Form(("grant_type", "client_credentials"), ("client_id", clientId), ("client_secret", secret), ("scope", "monitoring")), ct, what: "NinjaOne token request"));
        var api = new EndpointHttp(client, baseUrl, status => status switch
        {
            401 => "NinjaOne rejected the token",
            403 => "the client application lacks the Monitoring scope",
            _ => null
        }) { Authorise = token.Apply };
        if (Delay is not null) api.Delay = Delay;
        return api;
    }
}
