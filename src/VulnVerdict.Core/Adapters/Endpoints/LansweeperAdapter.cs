using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Endpoints;

/// <summary>
/// Lansweeper (Lansweeper Sites, including on-premises installations synced to the cloud) through the Data API
/// (GraphQL): every asset with its basic info, operating system and installed software, paged with a cursor.
/// Lansweeper sees more than computers (switches, printers, NAS), so the asset kind follows Lansweeper's asset type.
///
/// Auth is a personal access token or an application token authorised for the site ("Authorization: Token ...").
/// Read-only: GraphQL queries only, never mutations.
/// </summary>
public sealed class LansweeperAdapter : IInventoryAdapter
{
    public const string DefaultApiUrl = "https://api.lansweeper.com/api/v2/graphql";
    public const int PageSize = 100;

    public static readonly string[] Fields =
    {
        "assetBasicInfo.name", "assetBasicInfo.type", "assetBasicInfo.ipAddress", "assetBasicInfo.mac", "assetBasicInfo.domain", "assetBasicInfo.fqdn",
        "assetBasicInfo.userName", "assetBasicInfo.lastSeen", "assetCustom.manufacturer", "assetCustom.model",
        "operatingSystem.caption", "operatingSystem.version", "operatingSystem.buildNumber",
        "softwares.name", "softwares.version", "softwares.publisher",
    };

    public const string Query = """
        query VulnVerdictAssets($siteId: ID!, $limit: Int!, $cursor: String, $fields: [String!]!) {
          site(id: $siteId) {
            assetResources(assetPagination: { limit: $limit, cursor: $cursor, page: PAGE }, fields: $fields) {
              total
              pagination { limit current next page }
              items
            }
          }
        }
        """;

    private readonly IHttpClientFactory _http;
    private readonly ILogger _log;
    public Func<TimeSpan, CancellationToken, Task>? Delay { get; set; }

    public LansweeperAdapter(IHttpClientFactory http, ILogger<LansweeperAdapter>? log = null)
    {
        _http = http; _log = (ILogger?)log ?? NullLogger.Instance;
    }

    public AdapterMetadata Metadata { get; } = new(
        Id: "lansweeper",
        DisplayName: "Lansweeper (assets, OS and installed software)",
        Vendor: "Lansweeper",
        Description: "Reads assets, operating systems and installed software from the Lansweeper Data API (GraphQL). Covers on-premises Lansweeper installations synced to Lansweeper Sites. Read-only.",
        Kinds: new[] { AssetKind.Endpoint, AssetKind.Server, AssetKind.NetworkDevice, AssetKind.Printer, AssetKind.Switch },
        Form: new[]
        {
            new CredentialField("siteId", "Site ID", CredentialTypes.Text, "The site's ID from the Lansweeper Sites URL or the API's authorizedSites query."),
            new CredentialField("apiToken", "API token", CredentialTypes.Password, "A personal access token (Developer tools > Personal access tokens) or an application token authorised for this site."),
            new CredentialField("apiUrl", "API URL", CredentialTypes.Text, "Leave as is unless Lansweeper gave you a different endpoint.", Required: false, Default: DefaultApiUrl),
        },
        MinimumPermission: "a personal access token of a user with read access to the site, or an application token authorised for the site",
        DocsUrl: "https://developer.lansweeper.com/docs/data-api/get-started/quickstart/",
        DefaultIntervalMinutes: 480);

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            var (api, siteId, url) = Open(credentials);
            var page = await PageAsync(api, url, siteId, null, 1, ct);
            return new TestResult(true, "Connected to the Lansweeper Data API; " + (EpJson.Int(page, "total") ?? 0) + " asset(s) in the site.");
        }
        catch (Exception ex) when (ex is EndpointApiException or HttpRequestException or JsonException or InvalidOperationException or TaskCanceledException)
        {
            return new TestResult(false, ex.Message);
        }
    }

    public async Task<CollectResult> CollectAsync(IReadOnlyDictionary<string, string> credentials, DateTime? since, IProgress<string>? progress, CancellationToken ct)
    {
        var (api, siteId, url) = Open(credentials);
        var result = new CollectResult { FullSnapshot = true };
        string? cursor = null; var stale = 0; var noPatchLevel = 0;
        for (var pages = 0; pages < 50_000; pages++)
        {
            var page = await PageAsync(api, url, siteId, cursor, PageSize, ct);
            var items = EpJson.Arr(page, "items");
            foreach (var item in items)
            {
                if (EndpointNaming.IsStale(EpJson.Str(item, "assetBasicInfo.lastSeen"))) { stale++; continue; }
                var mapped = MapAsset(item);
                if (mapped is null) continue;
                result.Assets.Add(mapped.Value.Asset);
                if (mapped.Value.Os is not null) result.Software.Add(mapped.Value.Os);
                else if (mapped.Value.Asset.OsVendor == "Microsoft") noPatchLevel++;
                result.Software.AddRange(mapped.Value.Apps);
            }
            progress?.Report(result.Assets.Count + " of " + (EpJson.Int(page, "total")?.ToString() ?? "?") + " assets");
            var next = EpJson.Str(page, "pagination.next");
            if (items.Count == 0 || next is null || next == cursor) break;
            cursor = next;
        }
        if (stale > 0) result.Warnings.Add(stale + " asset(s) not seen by Lansweeper for " + EndpointNaming.StaleDays + " days were left out.");
        if (noPatchLevel > 0) result.Warnings.Add(noPatchLevel + " Windows asset(s) without the update revision: their OS CVEs are assessed only where another connector (WinRM, Intune, Defender, ConfigMgr) sees them.");
        _log.LogInformation("Lansweeper: {Assets} assets, {Software} software records", result.Assets.Count, result.Software.Count);
        return result;
    }

    private static async Task<JsonElement> PageAsync(EndpointHttp api, string url, string siteId, string? cursor, int limit, CancellationToken ct)
    {
        var body = new
        {
            query = Query.Replace("PAGE", cursor is null ? "FIRST" : "NEXT"),
            variables = new Dictionary<string, object?> { ["siteId"] = siteId, ["limit"] = limit, ["cursor"] = cursor, ["fields"] = Fields },
        };
        var root = await api.PostJsonAsync(url, body, ct);
        var errors = EpJson.Arr(root, "errors");
        if (errors.Count > 0)
            throw new EndpointApiException("POST " + EndpointHttp.StripQuery(url), 200, "Lansweeper answered: " + string.Join("; ", errors.Select(e => EpJson.Str(e, "message") ?? "error").Take(3)));
        return EpJson.At(root, "data.site.assetResources") ?? throw new EndpointApiException("POST " + EndpointHttp.StripQuery(url), 200, "no assetResources in the response (is the site ID right?)");
    }

    // ------------------------------------------------------------------ mapping (pure; tested with fixtures)

    public static (AssetRecord Asset, SoftwareRecord? Os, List<SoftwareRecord> Apps)? MapAsset(JsonElement item)
    {
        var key = EpJson.Str(item, "key", "_id", "assetId");
        var name = EpJson.Str(item, "assetBasicInfo.name");
        if (key is null && name is null) return null;
        var id = key ?? name!;
        var type = EpJson.Str(item, "assetBasicInfo.type") ?? "";
        var os = EndpointNaming.Os(EpJson.Str(item, "operatingSystem.caption", "operatingSystem.name") ?? (type.Equals("Macintosh", StringComparison.OrdinalIgnoreCase) ? "macOS" : type),
            EpJson.Str(item, "operatingSystem.version"), EpJson.Str(item, "operatingSystem.buildNumber"));
        var display = name ?? id;
        var fqdn = EpJson.Str(item, "assetBasicInfo.fqdn");
        var asset = EndpointNaming.Asset(id, display, os, new[] { display, fqdn }, new[] { EpJson.Str(item, "assetBasicInfo.ipAddress") }, new[] { EpJson.Str(item, "assetBasicInfo.mac") },
            owner: EpJson.Str(item, "assetBasicInfo.userName"), kindHint: type);
        var apps = new List<SoftwareRecord>();
        foreach (var s in EpJson.Arr(item, "softwares"))
        {
            var rec = EndpointNaming.App(id, EpJson.Str(s, "name"), EpJson.Str(s, "publisher"), EpJson.Str(s, "version"));
            if (rec is not null) apps.Add(rec);
        }
        EndpointNaming.UniqueIds(apps);
        return (asset, EndpointNaming.OsRecord(id, os), apps);
    }

    private (EndpointHttp Api, string SiteId, string Url) Open(IReadOnlyDictionary<string, string> creds)
    {
        var siteId = EpCreds.Get(creds, "siteId");
        var token = EpCreds.Secret(creds, "apiToken").Trim();
        var url = EpCreds.Get(creds, "apiUrl") is { Length: > 0 } u ? u : DefaultApiUrl;
        if (!url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) url = "https://" + url.TrimStart('/');
        if (siteId.Length == 0 || token.Length == 0) throw new InvalidOperationException("Site ID and API token are required");
        var api = new EndpointHttp(_http.CreateClient("adapter"), url, status => status switch
        {
            401 => "Lansweeper rejected the token",
            403 => "the token is not authorised for this site",
            _ => null
        })
        {
            Authorise = (req, _, _) => { req.Headers.Authorization = new AuthenticationHeaderValue("Token", token); return Task.CompletedTask; }
        };
        if (Delay is not null) api.Delay = Delay;
        return (api, siteId, url);
    }
}
