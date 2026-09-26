using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Services;
using VulnVerdict.Core.Engine;

namespace VulnVerdict.Core.Adapters.Endpoints;

/// <summary>
/// Microsoft Defender for Endpoint: onboarded machines, Defender Vulnerability Management's software inventory and
/// its per-machine CVE findings. Software comes as CPE-style vendor and product names ("google" / "chrome"), which are
/// passed on as a CPE so they map straight to the CNA names; the findings are kept as a second opinion.
///
/// Auth is an Entra ID app registration with the WindowsDefenderATP application permissions Machine.Read.All,
/// Software.Read.All and Vulnerability.Read.All. The export-style "ByMachine" endpoints return the whole estate in a
/// few large pages. Read-only: GET requests only.
/// </summary>
public sealed class DefenderEndpointAdapter : IInventoryAdapter
{
    public const string LoginHost = "https://login.microsoftonline.com";
    public const string DefaultApiHost = "api.security.microsoft.com";
    public const string Scope = "https://api.securitycenter.microsoft.com/.default";
    public const string MachinesPath = "/api/machines";
    public const string SoftwarePath = "/api/machines/SoftwareInventoryByMachine?pageSize=50000";
    public const string VulnerabilitiesPath = "/api/machines/SoftwareVulnerabilitiesByMachine?pageSize=50000";

    private readonly IHttpClientFactory _http;
    private readonly ILogger _log;
    public Func<TimeSpan, CancellationToken, Task>? Delay { get; set; }

    public DefenderEndpointAdapter(IHttpClientFactory http, ILogger<DefenderEndpointAdapter>? log = null)
    {
        _http = http; _log = (ILogger?)log ?? NullLogger.Instance;
    }

    public AdapterMetadata Metadata { get; } = new(
        Id: "defender-endpoint",
        DisplayName: "Microsoft Defender for Endpoint (machines, software, vulnerabilities)",
        Vendor: "Microsoft",
        Description: "Reads onboarded machines, the Defender Vulnerability Management software inventory and its CVE findings per machine. Read-only.",
        Kinds: new[] { AssetKind.Endpoint, AssetKind.Server },
        Form: new[]
        {
            new CredentialField("tenantId", "Tenant ID", CredentialTypes.Text, "Directory (tenant) ID from the app registration's overview page."),
            new CredentialField("clientId", "Application (client) ID", CredentialTypes.Text),
            new CredentialField("clientSecret", "Client secret", CredentialTypes.Password),
            new CredentialField(HealthNotices.SecretExpiresKey, "Client secret expires on", CredentialTypes.Date, "Optional. The console warns 30 days before, on screen and in the digest; the setup script prints this date.", Required: false),
            new CredentialField("apiHost", "API host", CredentialTypes.Text, "Leave as is unless you pin a region, e.g. eu.api.security.microsoft.com or uk.api.security.microsoft.com.", Required: false, Default: DefaultApiHost),
            new CredentialField("includeFindings", "Read Defender's CVE findings", CredentialTypes.Bool, "Stored as a second opinion next to the verdict.", Required: false, Default: "true"),
        },
        MinimumPermission: "an Entra ID app registration with the WindowsDefenderATP application permissions Machine.Read.All, Software.Read.All and Vulnerability.Read.All (admin consent granted); Defender Vulnerability Management must be licensed",
        DocsUrl: "https://learn.microsoft.com/en-us/defender-endpoint/api/get-assessment-software-inventory",
        DefaultIntervalMinutes: 360);

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            var api = Open(credentials);
            var root = await api.GetJsonAsync(MachinesPath + "?$top=1", ct);
            return new TestResult(true, "Signed in to the Defender for Endpoint API; machine listing readable" + (EpJson.Items(root).Count == 0 ? " (no machines onboarded yet)." : "."));
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

        progress?.Report("Listing machines");
        var machines = await AllPagesAsync(api, MachinesPath, ct);
        progress?.Report("Reading the software inventory");
        var software = await AllPagesAsync(api, SoftwarePath, ct);
        var byMachine = software.GroupBy(s => EpJson.Str(s, "deviceId") ?? "").ToDictionary(g => g.Key, g => g.ToList());

        var kept = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var stale = 0;
        foreach (var m in machines)
        {
            ct.ThrowIfCancellationRequested();
            var id = EpJson.Str(m, "id");
            if (id is null) continue;
            if (EndpointNaming.IsStale(EpJson.Str(m, "lastSeen"))) { stale++; continue; }
            var rows = byMachine.TryGetValue(id, out var r) ? r : new List<JsonElement>();
            var (asset, os, apps) = MapMachine(m, rows);
            result.Assets.Add(asset);
            if (os is not null) result.Software.Add(os);
            result.Software.AddRange(apps);
            kept.Add(id);
        }
        if (stale > 0) result.Warnings.Add(stale + " machine(s) not seen by Defender for " + EndpointNaming.StaleDays + " days were left out.");

        if (EpCreds.Bool(credentials, "includeFindings", true))
        {
            progress?.Report("Reading vulnerability findings");
            try
            {
                foreach (var v in await AllPagesAsync(api, VulnerabilitiesPath, ct))
                {
                    var f = MapVulnerability(v);
                    if (f is not null && kept.Contains(f.AssetExternalId)) result.Findings.Add(f);
                }
                // one row per software per CVE: keep one finding per machine and CVE
                var distinct = result.Findings.DistinctBy(f => (f.AssetExternalId, f.CveIds[0])).ToList();
                result.Findings.Clear(); result.Findings.AddRange(distinct);
            }
            catch (EndpointApiException ex) when (ex.Status is 403 or 404)
            {
                result.Warnings.Add("Vulnerability findings are not readable (" + ex.Message + "); machines and software were still read.");
            }
        }
        _log.LogInformation("Defender for Endpoint: {Machines} machines, {Software} software, {Findings} findings", result.Assets.Count, result.Software.Count, result.Findings.Count);
        return result;
    }

    private static async Task<List<JsonElement>> AllPagesAsync(EndpointHttp api, string path, CancellationToken ct)
    {
        var items = new List<JsonElement>();
        string? next = path;
        while (next is not null && items.Count < 5_000_000)
        {
            var page = await api.GetJsonAsync(next, ct);
            items.AddRange(EpJson.Items(page));
            next = EpJson.Str(page, "@odata.nextLink");
        }
        return items;
    }

    // ------------------------------------------------------------------ mapping (pure; tested with fixtures)

    /// <summary>The OS row in Defender's software inventory ("microsoft" / "windows_11", "apple" / "macos") carries the full build.</summary>
    public static bool IsOsRow(JsonElement s)
    {
        var vendor = (EpJson.Str(s, "softwareVendor") ?? "").ToLowerInvariant();
        var name = (EpJson.Str(s, "softwareName") ?? "").ToLowerInvariant();
        return (vendor == "microsoft" && name.StartsWith("windows_") && (name.Contains("10") || name.Contains("11") || name.Contains("server")))
            || (vendor == "apple" && name is "macos" or "mac_os_x" or "ios" or "ipados");
    }

    public static (AssetRecord Asset, SoftwareRecord? Os, List<SoftwareRecord> Apps) MapMachine(JsonElement m, IReadOnlyList<JsonElement> software)
    {
        var id = EpJson.Str(m, "id")!;
        var dns = EpJson.Str(m, "computerDnsName") ?? id;
        var shortName = dns.Split('.')[0];
        var osRow = software.FirstOrDefault(IsOsRow);
        var osRowVersion = osRow.ValueKind == JsonValueKind.Object ? EpJson.Str(osRow, "softwareVersion") : null;
        var build = EpJson.Str(m, "osBuild");
        var os = EndpointNaming.Os(EpJson.Str(m, "osPlatform"), osRowVersion ?? EpJson.Str(m, "osVersion"), build, EpJson.Str(m, "version"));

        var ips = new List<string?> { EpJson.Str(m, "lastIpAddress") };
        var macs = new List<string?>();
        foreach (var a in EpJson.Arr(m, "ipAddresses"))
        {
            if ((EpJson.Str(a, "operationalStatus") ?? "Up").Equals("Down", StringComparison.OrdinalIgnoreCase)) continue;
            ips.Add(EpJson.Str(a, "ipAddress")); macs.Add(EpJson.Str(a, "macAddress"));
        }
        var asset = EndpointNaming.Asset(id, shortName, os, new[] { shortName, dns }, ips, macs);

        var apps = new List<SoftwareRecord>();
        foreach (var s in software)
        {
            if (IsOsRow(s)) continue;
            var rec = MapSoftware(id, s);
            if (rec is not null) apps.Add(rec);
        }
        EndpointNaming.UniqueIds(apps);
        return (asset, EndpointNaming.OsRecord(id, os), apps);
    }

    /// <summary>
    /// "google" / "chrome" / "128.0.6613.120" to Google Chrome with a CPE, which the mapping step resolves against the
    /// CNA product list before anything else.
    /// </summary>
    public static SoftwareRecord? MapSoftware(string assetId, JsonElement s)
    {
        var vendor = EpJson.Str(s, "softwareVendor");
        var name = EpJson.Str(s, "softwareName");
        var version = EpJson.Str(s, "softwareVersion") ?? "";
        if (name is null) return null;
        var cpe = vendor is null ? null : "cpe:2.3:a:" + CpePart(vendor) + ":" + CpePart(name) + ":" + (version.Length > 0 ? CpePart(version) : "*") + ":*:*:*:*:*:*:*";
        return new SoftwareRecord(assetId, Pretty(vendor ?? ""), Pretty(name), version, SoftwareKind.Application, Cpe: cpe,
            ExternalId: "mdvm:" + (vendor ?? "") + ":" + name);
    }

    public static FindingRecord? MapVulnerability(JsonElement v)
    {
        var device = EpJson.Str(v, "deviceId");
        var cve = EpJson.Str(v, "cveId");
        if (device is null || cve is null || !cve.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)) return null;
        var title = string.Join(" ", new[] { Pretty(EpJson.Str(v, "softwareVendor") ?? ""), Pretty(EpJson.Str(v, "softwareName") ?? ""), EpJson.Str(v, "softwareVersion") }.Where(x => !string.IsNullOrWhiteSpace(x)));
        return new FindingRecord(device, new[] { Normalizer.CveIdUpper(cve) }, EpJson.Str(v, "vulnerabilitySeverityLevel"), title.Length > 0 ? title : null,
            "mdvm:" + Normalizer.CveIdUpper(cve));
    }

    private static string CpePart(string s) => s.Trim().ToLowerInvariant().Replace(' ', '_').Replace(":", "\\:");
    private static string Pretty(string s) => CultureInfo.InvariantCulture.TextInfo.ToTitleCase(s.Replace('_', ' ').Trim());

    // ------------------------------------------------------------------ session

    private EndpointHttp Open(IReadOnlyDictionary<string, string> creds)
    {
        var tenant = EpCreds.Get(creds, "tenantId");
        var clientId = EpCreds.Get(creds, "clientId");
        var secret = EpCreds.Secret(creds, "clientSecret");
        if (tenant.Length == 0 || clientId.Length == 0 || secret.Length == 0) throw new InvalidOperationException("Tenant ID, client ID and client secret are required");
        var host = EpCreds.BaseUrl(EpCreds.Get(creds, "apiHost") is { Length: > 0 } h ? h : DefaultApiHost);
        var client = _http.CreateClient("adapter");
        var token = new BearerToken(ct => OAuthTokens.RequestAsync(client, LoginHost + "/" + Uri.EscapeDataString(tenant) + "/oauth2/v2.0/token",
            OAuthTokens.Form(("grant_type", "client_credentials"), ("client_id", clientId), ("client_secret", secret), ("scope", Scope)), ct, what: "Entra ID token request"));
        var api = new EndpointHttp(client, host, status => status switch
        {
            401 => "the Defender API rejected the token",
            403 => "the app registration lacks Machine.Read.All, Software.Read.All or Vulnerability.Read.All, or admin consent has not been granted",
            _ => null
        }) { Authorise = token.Apply };
        if (Delay is not null) api.Delay = Delay;
        return api;
    }
}
