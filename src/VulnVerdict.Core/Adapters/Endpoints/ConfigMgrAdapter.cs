using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Adapters.Windows;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Endpoints;

/// <summary>
/// Microsoft Configuration Manager (SCCM / MECM) through the AdminService REST API on the SMS Provider (ConfigMgr
/// 1810 and later). Reads SMS_R_System for the devices, SMS_G_System_OPERATING_SYSTEM for the OS caption and
/// SMS_G_System_INSTALLED_SOFTWARE per device. SMS_R_System.BuildExt carries the update revision ("10.0.22631.3447"),
/// so the OS is matched at its patch level; clients older than 2010 without BuildExt are recorded without an OS match.
///
/// Stays on-premises: Windows authentication (Negotiate/NTLM, the same managed implementation the WinRM adapter uses)
/// from the appliance to the SMS Provider over HTTPS. Read-only: GET requests only, WMI classes are only queried.
/// </summary>
public sealed class ConfigMgrAdapter : IInventoryAdapter
{
    public const string SystemsPath = "/AdminService/wmi/SMS_R_System?$select=ResourceId,Name,ResourceNames,IPAddresses,MACAddresses,OperatingSystemNameandVersion,Build,BuildExt,LastLogonUserName,Client,Obsolete,Decommissioned,Active,FullDomainName";
    public const string OsPath = "/AdminService/wmi/SMS_G_System_OPERATING_SYSTEM?$select=ResourceID,Caption,Version,BuildNumber";
    public static string MembersPath(string collectionId) => "/AdminService/wmi/SMS_FullCollectionMembership?$filter=CollectionID eq '" + collectionId.Replace("'", "''") + "'&$select=ResourceID";
    public static string SoftwarePath(long resourceId) => "/AdminService/wmi/SMS_G_System_INSTALLED_SOFTWARE?$filter=ResourceID eq " + resourceId + "&$select=ResourceID,ARPDisplayName,ProductName,ProductVersion,Publisher,SoftwareCode";

    private readonly ILogger _log;
    /// <summary>Builds the HTTP client for a connector's credentials; tests replace it with a fake handler.</summary>
    public Func<IReadOnlyDictionary<string, string>, HttpClient> ClientFactory { get; set; }
    public Func<TimeSpan, CancellationToken, Task>? Delay { get; set; }

    public ConfigMgrAdapter(ILogger<ConfigMgrAdapter>? log = null)
    {
        _log = (ILogger?)log ?? NullLogger.Instance;
        ClientFactory = DefaultClient;
    }

    public AdapterMetadata Metadata { get; } = new(
        Id: "configmgr",
        DisplayName: "Microsoft Configuration Manager (SCCM) AdminService",
        Vendor: "Microsoft",
        Description: "Reads devices, OS builds and installed software from Configuration Manager's AdminService on the SMS Provider, with Windows authentication. Stays on-premises. Read-only.",
        Kinds: new[] { AssetKind.Endpoint, AssetKind.Server },
        Form: new[]
        {
            new CredentialField("host", "SMS Provider", CredentialTypes.Text, "Host name of the site server or SMS Provider, e.g. cm01.corp.example (HTTPS, port 443 unless given as host:port)."),
            new CredentialField("username", "User name", CredentialTypes.Text, "DOMAIN\\user or user@domain."),
            new CredentialField("password", "Password", CredentialTypes.Password),
            new CredentialField("collectionId", "Collection ID", CredentialTypes.Text, "Only read members of this collection. SMS00001 is All Systems.", Required: false, Default: "SMS00001"),
            new CredentialField("includeSoftware", "Read installed software", CredentialTypes.Bool, "One query per device. Turn off to read devices and OS builds only.", Required: false, Default: "true"),
            EpCreds.VerifyTls("SMS Provider"),
        },
        MinimumPermission: "a domain account with the Read-only Analyst security role (or a custom role with Read on Collection and Read Resource) scoped to the collection",
        DocsUrl: "https://learn.microsoft.com/en-us/intune/configmgr/develop/adminservice/overview",
        DefaultIntervalMinutes: 480);

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            var api = Open(credentials);
            var root = await api.GetJsonAsync(SystemsPath.Replace("$select=", "$top=1&$select="), ct);
            return new TestResult(true, "Connected to the AdminService; device listing readable" + (EpJson.Items(root).Count == 0 ? " (no devices returned)." : "."));
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
        var systems = await AllAsync(api, SystemsPath, ct);
        HashSet<long>? members = null;
        var collection = EpCreds.Get(credentials, "collectionId");
        if (collection.Length > 0 && !collection.Equals("SMS00001", StringComparison.OrdinalIgnoreCase))
            members = (await AllAsync(api, MembersPath(collection), ct)).Select(m => EpJson.Int(m, "ResourceID") ?? -1).ToHashSet();
        var captions = new Dictionary<long, string>();
        foreach (var o in await AllAsync(api, OsPath, ct))
            if (EpJson.Int(o, "ResourceID") is { } rid && EpJson.Str(o, "Caption") is { } cap) captions[rid] = cap;

        var includeSoftware = EpCreds.Bool(credentials, "includeSoftware", true);
        var n = 0; var skipped = 0;
        foreach (var s in systems)
        {
            ct.ThrowIfCancellationRequested();
            var rid = EpJson.Int(s, "ResourceId");
            if (rid is null || (members is not null && !members.Contains(rid.Value))) continue;
            if (EpJson.Bool(s, "Obsolete") == true || EpJson.Bool(s, "Decommissioned") == true || EpJson.Int(s, "Client") is 0) { skipped++; continue; }
            var mapped = MapSystem(s, captions.TryGetValue(rid.Value, out var c) ? c : null);
            if (mapped is null) continue;
            var (asset, os) = mapped.Value;
            result.Assets.Add(asset);
            if (os is not null) result.Software.Add(os);
            n++;
            if (!includeSoftware) continue;
            progress?.Report("Device " + n + ": " + asset.DisplayName);
            try
            {
                var apps = (await AllAsync(api, SoftwarePath(rid.Value), ct)).Select(a => MapSoftware(asset.ExternalId, a)).Where(a => a is not null).Select(a => a!).ToList();
                EndpointNaming.UniqueIds(apps);
                result.Software.AddRange(apps);
            }
            catch (EndpointApiException ex) when (ex.Status is 403 or 404)
            {
                result.Warnings.Add("Installed software is not readable (" + ex.Message + "); devices and OS builds were still read.");
                includeSoftware = false;
            }
        }
        if (skipped > 0) result.Warnings.Add(skipped + " obsolete, decommissioned or client-less record(s) were left out.");
        _log.LogInformation("ConfigMgr: {Devices} devices, {Software} software records", result.Assets.Count, result.Software.Count);
        return result;
    }

    private static async Task<List<JsonElement>> AllAsync(EndpointHttp api, string path, CancellationToken ct)
    {
        var items = new List<JsonElement>();
        string? next = path;
        while (next is not null && items.Count < 2_000_000)
        {
            var page = await api.GetJsonAsync(next, ct);
            items.AddRange(EpJson.Items(page));
            next = EpJson.Str(page, "@odata.nextLink");
        }
        return items;
    }

    // ------------------------------------------------------------------ mapping (pure; tested with fixtures)

    public static (AssetRecord Asset, SoftwareRecord? Os)? MapSystem(JsonElement s, string? osCaption)
    {
        var rid = EpJson.Int(s, "ResourceId");
        if (rid is null) return null;
        var id = rid.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var name = EpJson.Str(s, "Name") ?? id;
        var nameVersion = EpJson.Str(s, "OperatingSystemNameandVersion") ?? "";
        var server = nameVersion.Contains("Server", StringComparison.OrdinalIgnoreCase) || (osCaption ?? "").Contains("Server", StringComparison.OrdinalIgnoreCase);
        var os = EndpointNaming.Os(osCaption ?? nameVersion, EpJson.Str(s, "BuildExt") ?? EpJson.Str(s, "Build"), null, null, server);
        var hostnames = EpJson.Strings(s, "ResourceNames").Prepend(name).ToList();
        var domain = EpJson.Str(s, "FullDomainName");
        if (domain is not null && !hostnames.Any(h => h.Contains('.'))) hostnames.Add(name + "." + domain.ToLowerInvariant());
        var asset = EndpointNaming.Asset(id, name, os, hostnames, EpJson.Strings(s, "IPAddresses"), EpJson.Strings(s, "MACAddresses"), owner: EpJson.Str(s, "LastLogonUserName"));
        return (asset, EndpointNaming.OsRecord(id, os));
    }

    public static SoftwareRecord? MapSoftware(string assetId, JsonElement a)
    {
        var name = EpJson.Str(a, "ARPDisplayName", "ProductName");
        var rec = EndpointNaming.App(assetId, name, EpJson.Str(a, "Publisher"), EpJson.Str(a, "ProductVersion"));
        // the software code (MSI product code or ARP key) survives upgrades for most per-machine installs
        return rec is null ? null : EpJson.Str(a, "SoftwareCode") is { } code ? rec with { ExternalId = "app:" + code.ToLowerInvariant() } : rec;
    }

    // ------------------------------------------------------------------ session

    private EndpointHttp Open(IReadOnlyDictionary<string, string> creds)
    {
        var host = EpCreds.BaseUrl(EpCreds.Get(creds, "host"));
        if (host.Length == 0) throw new InvalidOperationException("SMS Provider host is required");
        var api = new EndpointHttp(ClientFactory(creds), host, status => status switch
        {
            401 => "the SMS Provider rejected the credentials (check the account, and that Windows authentication reaches IIS on the provider)",
            403 => "the account has no ConfigMgr security role that can read these devices",
            404 => "no AdminService here: it needs ConfigMgr 1810 or later and the SMS Provider host name",
            _ => null
        });
        if (Delay is not null) api.Delay = Delay;
        return api;
    }

    private static HttpClient DefaultClient(IReadOnlyDictionary<string, string> creds)
    {
        var user = EpCreds.Get(creds, "username");
        var password = EpCreds.Secret(creds, "password");
        if (user.Length == 0 || password.Length == 0) throw new InvalidOperationException("User name and password are required");
        var handler = new HttpClientHandler { UseDefaultCredentials = false, PreAuthenticate = true, AllowAutoRedirect = false, UseCookies = false,
            Credentials = WsManClient.ToNetworkCredential(user, password) };
        if (!EpCreds.Bool(creds, "verifyTls", true)) handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        var client = new HttpClient(handler, disposeHandler: true) { Timeout = TimeSpan.FromMinutes(5) };
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("VulnVerdict", "0.2"));
        return client;
    }
}
