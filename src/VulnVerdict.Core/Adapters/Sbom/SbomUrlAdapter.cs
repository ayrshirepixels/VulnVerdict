using System.Net.Http.Headers;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Sbom;

/// <summary>
/// The API side of SBOM import: the console fetches the latest CycloneDX or SPDX JSON from a
/// CI artifact URL on the connector schedule, so the application layer stays current without a manual upload.
/// </summary>
public sealed class SbomUrlAdapter : IInventoryAdapter
{
    private readonly IHttpClientFactory _http;
    private readonly ILogger<SbomUrlAdapter> _log;

    public SbomUrlAdapter(IHttpClientFactory http, ILogger<SbomUrlAdapter> log) { _http = http; _log = log; }

    public AdapterMetadata Metadata { get; } = new(
        Id: "sbom-url",
        DisplayName: "SBOM from a URL (CI artifact)",
        Vendor: "CycloneDX / SPDX",
        Description: "Fetches a CycloneDX (1.4 to 1.6) or SPDX (2.2, 2.3) JSON SBOM published by the build pipeline and joins it to the named site or server, so a library CVE lands on a named, exposure-tagged asset.",
        Kinds: new[] { AssetKind.Server, AssetKind.Other },
        Form: new[]
        {
            new CredentialField("url", "SBOM URL", CredentialTypes.Text, "https://ci.example.com/artifacts/webshop/sbom.json"),
            new CredentialField("assetName", "Asset name", CredentialTypes.Text, "The hostname or site name the SBOM describes, exactly as the web-server or server adapter reports it, so the libraries land on that asset."),
            new CredentialField("bearerToken", "Bearer token", CredentialTypes.Password, "Optional token sent as Authorization: Bearer for private artifact stores.", Required: false),
            new CredentialField("verifyTls", "Verify TLS certificate", CredentialTypes.Bool, null, Required: false, Default: "true"),
        },
        MinimumPermission: "read access to the artifact URL (optional bearer token)",
        DefaultIntervalMinutes: 1440);

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            var (json, asset) = await FetchAsync(credentials, ct);
            var parsed = SbomParser.Parse(json, asset);
            return new TestResult(true, parsed.Format + " with " + parsed.Software.Count + " software records" + (parsed.ApplicationName is null ? "" : " for " + parsed.ApplicationName + " " + parsed.ApplicationVersion) + "; applies to asset " + asset);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { return new TestResult(false, ex.Message); }
    }

    public async Task<CollectResult> CollectAsync(IReadOnlyDictionary<string, string> credentials, DateTime? since, IProgress<string>? progress, CancellationToken ct)
    {
        progress?.Report("Fetching SBOM");
        var (json, asset) = await FetchAsync(credentials, ct);
        var parsed = SbomParser.Parse(json, asset);
        progress?.Report(parsed.Format + ": " + parsed.Software.Count + " software records");
        return SbomImportService.BuildResult(asset, parsed);
    }

    private async Task<(string Json, string AssetName)> FetchAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        var url = credentials.GetValueOrDefault("url")?.Trim() ?? "";
        var asset = credentials.GetValueOrDefault("assetName")?.Trim() ?? "";
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || (uri.Scheme != "https" && uri.Scheme != "http")) throw new ArgumentException("SBOM URL must be an absolute http(s) URL.");
        if (asset == "") throw new ArgumentException("Asset name is required.");
        var verify = !string.Equals(credentials.GetValueOrDefault("verifyTls"), "false", StringComparison.OrdinalIgnoreCase);
        var client = _http.CreateClient(verify ? "adapter" : "adapter-insecure");
        using var req = new HttpRequestMessage(HttpMethod.Get, uri);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*"));
        var token = credentials.GetValueOrDefault("bearerToken");
        if (!string.IsNullOrWhiteSpace(token)) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Trim());
        using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        if (!resp.IsSuccessStatusCode) throw new HttpRequestException("SBOM URL answered " + (int)resp.StatusCode + " " + resp.ReasonPhrase);
        if (resp.Content.Headers.ContentLength is > 64 * 1024 * 1024) throw new InvalidOperationException("SBOM is larger than 64 MB.");
        var json = await resp.Content.ReadAsStringAsync(ct);
        _log.LogDebug("Fetched SBOM for {Asset} ({Bytes} bytes)", asset, json.Length);
        return (json, asset);
    }
}
