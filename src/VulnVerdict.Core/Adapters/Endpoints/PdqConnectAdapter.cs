using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Endpoints;

/// <summary>
/// PDQ Connect (the cloud agent product): devices with their OS, network adapters and installed software from the
/// public API, paged by page number. PDQ Inventory (on-premises) has no API and is not covered; its data can be
/// exported and brought in another way. Auth is an API key as a bearer token. Read-only: GET requests only.
/// </summary>
public sealed class PdqConnectAdapter : IInventoryAdapter
{
    public const string BaseUrl = "https://app.pdq.com";
    public const int PageSize = 100;
    public static string DevicesPath(int page) => "/v1/api/devices?includes=software,networking&pageSize=" + PageSize + "&page=" + page;

    private readonly IHttpClientFactory _http;
    private readonly ILogger _log;
    public Func<TimeSpan, CancellationToken, Task>? Delay { get; set; }

    public PdqConnectAdapter(IHttpClientFactory http, ILogger<PdqConnectAdapter>? log = null)
    {
        _http = http; _log = (ILogger?)log ?? NullLogger.Instance;
    }

    public AdapterMetadata Metadata { get; } = new(
        Id: "pdq-connect",
        DisplayName: "PDQ Connect (devices and installed software)",
        Vendor: "PDQ",
        Description: "Reads devices, network adapters and installed software from the PDQ Connect API. PDQ Inventory (on-premises) has no API and is not covered. Read-only.",
        Kinds: new[] { AssetKind.Endpoint, AssetKind.Server },
        Form: new[]
        {
            new CredentialField("apiKey", "API key", CredentialTypes.Password, "Settings > API keys in PDQ Connect."),
        },
        MinimumPermission: "a PDQ Connect API key (keys are organisation-wide; keep this one for VulnVerdict alone so it can be revoked on its own)",
        DocsUrl: "https://connect.pdq.com/hc/en-us/articles/12450287436315-PDQ-Connect-API",
        DefaultIntervalMinutes: 480);

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            var api = Open(credentials);
            await api.GetJsonAsync("/v1/api/devices?pageSize=1&page=1", ct);
            return new TestResult(true, "Connected to the PDQ Connect API; device listing readable.");
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
        var noPatchLevel = 0; var stale = 0;
        for (var page = 1; page < 10_000; page++)
        {
            progress?.Report("Reading devices, page " + page);
            var batch = EpJson.Items(await api.GetJsonAsync(DevicesPath(page), ct));
            foreach (var d in batch)
            {
                if (EndpointNaming.IsStale(EpJson.Str(d, "lastSeenAt", "lastSeen", "lastOnlineAt"))) { stale++; continue; }
                var mapped = MapDevice(d);
                if (mapped is null) continue;
                result.Assets.Add(mapped.Value.Asset);
                if (mapped.Value.Os is not null) result.Software.Add(mapped.Value.Os);
                else if (mapped.Value.Asset.OsVendor == "Microsoft") noPatchLevel++;
                result.Software.AddRange(mapped.Value.Apps);
            }
            if (batch.Count < PageSize) break;
        }
        if (stale > 0) result.Warnings.Add(stale + " device(s) not seen for " + EndpointNaming.StaleDays + " days were left out.");
        if (noPatchLevel > 0) result.Warnings.Add(noPatchLevel + " Windows device(s) without the update revision: their OS CVEs are assessed only where another connector (WinRM, Intune, Defender, ConfigMgr) sees them.");
        _log.LogInformation("PDQ Connect: {Devices} devices, {Software} software records", result.Assets.Count, result.Software.Count);
        return result;
    }

    // ------------------------------------------------------------------ mapping (pure; tested with fixtures)

    public static (AssetRecord Asset, SoftwareRecord? Os, List<SoftwareRecord> Apps)? MapDevice(JsonElement d)
    {
        var id = EpJson.Str(d, "id");
        if (id is null) return null;
        var name = EpJson.Str(d, "hostname", "name") ?? id;
        var os = EndpointNaming.Os(EpJson.Str(d, "osName", "os.name"), EpJson.Str(d, "osVersion", "os.version"), EpJson.Str(d, "osBuild", "os.build"));
        var ips = new List<string?>(); var macs = new List<string?>();
        foreach (var nic in EpJson.Arr(d, "networking", "networkAdapters"))
        {
            ips.AddRange(EpJson.Strings(nic, "ipAddresses").Concat(EpJson.Strings(nic, "ipAddress")));
            macs.Add(EpJson.Str(nic, "macAddress"));
        }
        var asset = EndpointNaming.Asset(id, name, os, new[] { name, EpJson.Str(d, "name") }, ips, macs, owner: EpJson.Str(d, "lastUser", "currentUser"));
        var apps = new List<SoftwareRecord>();
        foreach (var s in EpJson.Arr(d, "software"))
        {
            var rec = EndpointNaming.App(id, EpJson.Str(s, "name"), EpJson.Str(s, "publisher"), EpJson.Str(s, "versionRaw", "version"));
            if (rec is not null) apps.Add(rec);
        }
        EndpointNaming.UniqueIds(apps);
        return (asset, EndpointNaming.OsRecord(id, os), apps);
    }

    private EndpointHttp Open(IReadOnlyDictionary<string, string> creds)
    {
        var key = EpCreds.Secret(creds, "apiKey").Trim();
        if (key.Length == 0) throw new InvalidOperationException("API key is required");
        var api = new EndpointHttp(_http.CreateClient("adapter"), BaseUrl, status => status switch
        {
            401 => "PDQ Connect rejected the API key",
            _ => null
        })
        {
            Authorise = (req, _, _) => { req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", key); return Task.CompletedTask; }
        };
        if (Delay is not null) api.Delay = Delay;
        return api;
    }
}
