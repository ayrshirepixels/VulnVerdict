using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace VulnVerdict.Core.Adapters.Packages;

/// <summary>One affected entry of an OSV record: ecosystem, package name, purl and the fixed versions it lists.</summary>
public sealed record OsvAffected(string? Ecosystem, string? Name, string? Purl, string[] Fixed);

/// <summary>The parts of an OSV record the source needs.</summary>
public sealed record OsvVuln(string Id, string[] CveIds, OsvAffected[] Affected, bool Withdrawn);

/// <summary>
/// OSV.dev as the package vulnerability source. Sends up to 1000 queries per
/// /v1/querybatch call, then fetches each returned record once (in-memory cache, 8 fetches at a time, HTTP 429
/// honoured with a short backoff) to read its CVE ids and the fixed version for the queried package.
/// Records without a CVE id are skipped.
///
/// Query strategy, checked against the live API: distribution records are keyed by source package name and
/// scoped by release, so a query is sent as ecosystem + name + version whenever the ecosystem is known
/// ("Ubuntu:22.04:LTS", "Debian:12", "Alpine:v3.20", "Red Hat:enterprise_linux:9::baseos", "AlmaLinux:9",
/// "Rocky Linux:9"). Otherwise the purl is sent with its qualifiers removed, because OSV does not match a purl
/// that carries ?arch=...&amp;distro=... qualifiers.
/// </summary>
public sealed class OsvPackageVulnSource : IPackageVulnSource
{
    public const string QueryBatchUrl = "https://api.osv.dev/v1/querybatch";
    public const string VulnUrl = "https://api.osv.dev/v1/vulns/";

    private static readonly Regex CveIdPattern = new(@"^CVE-\d{4}-\d{4,}$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    private static readonly Regex EmbeddedCve = new(@"(CVE-\d{4}-\d{4,})$", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private readonly Func<HttpClient> _client;
    private readonly ILogger? _log;
    private readonly ConcurrentDictionary<string, (DateTime At, OsvVuln? Vuln)> _cache = new(StringComparer.OrdinalIgnoreCase);
    private int _requests;

    public OsvPackageVulnSource(IHttpClientFactory http, ILogger<OsvPackageVulnSource> log) : this(() => http.CreateClient("feeds"), log) { }

    /// <summary>For tests and tools: a source bound to one HttpClient.</summary>
    public OsvPackageVulnSource(HttpClient client, ILogger? log = null) : this(() => client, log) { }

    private OsvPackageVulnSource(Func<HttpClient> client, ILogger? log) { _client = client; _log = log; }

    public int BatchSize { get; set; } = 1000;
    public int MaxConcurrentDetailFetches { get; set; } = 8;
    public int MaxPagesPerQuery { get; set; } = 5;
    public int MaxAttempts { get; set; } = 5;
    public TimeSpan CacheTtl { get; set; } = TimeSpan.FromHours(24);

    /// <summary>HTTP requests sent since construction (retries included). Used by tests.</summary>
    public int Requests => _requests;

    // ------------------------------------------------------------------ IPackageVulnSource

    public async Task<IReadOnlyList<PackageVuln>> LookupAsync(IEnumerable<PackageQuery> queries, CancellationToken ct)
    {
        var list = new List<(PackageQuery Query, JsonObject Body)>();
        foreach (var q in queries)
        {
            var body = BuildQuery(q);
            if (body is not null) list.Add((q, body));
        }
        if (list.Count == 0) return Array.Empty<PackageVuln>();

        var ids = new List<string>[list.Count];
        for (var i = 0; i < ids.Length; i++) ids[i] = new List<string>();

        var pending = Enumerable.Range(0, list.Count).Select(i => (Index: i, Token: (string?)null)).ToList();
        var page = 0;
        while (pending.Count > 0 && page++ < Math.Max(1, MaxPagesPerQuery))
        {
            var next = new List<(int Index, string? Token)>();
            foreach (var chunk in pending.Chunk(Math.Max(1, BatchSize)))
            {
                var arr = new JsonArray();
                foreach (var (index, token) in chunk)
                {
                    var b = (JsonObject)list[index].Body.DeepClone();
                    if (token is not null) b["page_token"] = token;
                    arr.Add(b);
                }
                var body = new JsonObject { ["queries"] = arr }.ToJsonString();
                var json = await SendAsync(() => new HttpRequestMessage(HttpMethod.Post, QueryBatchUrl) { Content = new StringContent(body, Encoding.UTF8, "application/json") }, ct)
                           ?? throw new HttpRequestException("OSV querybatch returned no body");
                var results = ParseBatchResponse(json);
                for (var k = 0; k < chunk.Length && k < results.Count; k++)
                {
                    ids[chunk[k].Index].AddRange(results[k].Ids);
                    if (results[k].NextPageToken is { } t) next.Add((chunk[k].Index, t));
                }
            }
            pending = next;
        }

        var details = await FetchDetailsAsync(ids.SelectMany(x => x).Distinct(StringComparer.OrdinalIgnoreCase).ToList(), ct);

        var output = new Dictionary<(string Key, string Cve), PackageVuln>();
        for (var i = 0; i < list.Count; i++)
        {
            var q = list[i].Query;
            foreach (var id in ids[i].Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (!details.TryGetValue(id, out var v) || v is null || v.Withdrawn || v.CveIds.Length == 0) continue;
                var fixedIn = FindFixedVersion(v, q);
                foreach (var cve in v.CveIds)
                {
                    var key = (q.Key, cve);
                    if (!output.TryGetValue(key, out var existing) || (existing.FixedIn is null && fixedIn is not null))
                        output[key] = new PackageVuln(q.Key, cve, fixedIn, "OSV " + v.Id);
                }
            }
        }
        return output.Values.ToList();
    }

    // ------------------------------------------------------------------ request building and parsing

    /// <summary>
    /// The querybatch entry for one package: {package:{name, ecosystem}, version} when the ecosystem is known,
    /// otherwise {package:{purl}} with the purl's qualifiers removed (plus a version field when the purl has none).
    /// Null when the query carries too little to ask anything.
    /// </summary>
    public static JsonObject? BuildQuery(PackageQuery q)
    {
        if (!string.IsNullOrWhiteSpace(q.Ecosystem) && !string.IsNullOrWhiteSpace(q.Name) && !string.IsNullOrWhiteSpace(q.Version))
            return new JsonObject
            {
                ["package"] = new JsonObject { ["name"] = q.Name.Trim(), ["ecosystem"] = q.Ecosystem.Trim() },
                ["version"] = q.Version.Trim()
            };
        if (!string.IsNullOrWhiteSpace(q.Purl))
        {
            var purl = StripPurlQualifiers(q.Purl);
            if (!purl.StartsWith("pkg:", StringComparison.OrdinalIgnoreCase)) return null;
            if (purl.Contains('@')) return new JsonObject { ["package"] = new JsonObject { ["purl"] = purl } };
            if (!string.IsNullOrWhiteSpace(q.Version)) return new JsonObject { ["package"] = new JsonObject { ["purl"] = purl }, ["version"] = q.Version.Trim() };
        }
        return null;
    }

    public static string StripPurlQualifiers(string purl)
    {
        var i = purl.IndexOfAny(new[] { '?', '#' });
        return (i >= 0 ? purl[..i] : purl).Trim();
    }

    /// <summary>Name segment of a purl (after the last "/" of the path, before "@").</summary>
    public static string PurlName(string purl)
    {
        var p = StripPurlQualifiers(purl);
        var at = p.IndexOf('@');
        if (at >= 0) p = p[..at];
        var slash = p.LastIndexOf('/');
        var name = slash >= 0 ? p[(slash + 1)..] : p;
        return Uri.UnescapeDataString(name);
    }

    /// <summary>Per query, in request order: the vulnerability ids and the next page token when OSV paginated.</summary>
    public static List<(List<string> Ids, string? NextPageToken)> ParseBatchResponse(string json)
    {
        var list = new List<(List<string>, string?)>();
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("results", out var results) || results.ValueKind != JsonValueKind.Array) return list;
        foreach (var r in results.EnumerateArray())
        {
            var ids = new List<string>();
            if (r.TryGetProperty("vulns", out var vulns) && vulns.ValueKind == JsonValueKind.Array)
                foreach (var v in vulns.EnumerateArray())
                    if (v.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.String && id.GetString() is { Length: > 0 } s) ids.Add(s);
            string? next = r.TryGetProperty("next_page_token", out var t) && t.ValueKind == JsonValueKind.String && t.GetString() is { Length: > 0 } tok ? tok : null;
            list.Add((ids, next));
        }
        return list;
    }

    /// <summary>Reads id, CVE ids, withdrawn flag and affected entries (with fixed versions) from a /v1/vulns record.</summary>
    public static OsvVuln? ParseVuln(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object) return null;
        var id = Str(root, "id");
        if (id == "") return null;
        var withdrawn = root.TryGetProperty("withdrawn", out var w) && w.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(w.GetString());
        var affected = new List<OsvAffected>();
        if (root.TryGetProperty("affected", out var aff) && aff.ValueKind == JsonValueKind.Array)
        {
            foreach (var a in aff.EnumerateArray())
            {
                string? eco = null, name = null, purl = null;
                if (a.TryGetProperty("package", out var pkg) && pkg.ValueKind == JsonValueKind.Object)
                {
                    eco = NullIfEmpty(Str(pkg, "ecosystem")); name = NullIfEmpty(Str(pkg, "name")); purl = NullIfEmpty(Str(pkg, "purl"));
                }
                var fixedVersions = new List<string>();
                if (a.TryGetProperty("ranges", out var ranges) && ranges.ValueKind == JsonValueKind.Array)
                    foreach (var r in ranges.EnumerateArray())
                        if (r.TryGetProperty("events", out var events) && events.ValueKind == JsonValueKind.Array)
                            foreach (var e in events.EnumerateArray())
                                if (Str(e, "fixed") is { Length: > 0 } f) fixedVersions.Add(f);
                foreach (var extra in new[] { "ecosystem_specific", "database_specific" })
                    if (a.TryGetProperty(extra, out var spec) && spec.ValueKind == JsonValueKind.Object)
                        foreach (var key in new[] { "fixed", "fixed_version", "fixed_in" })
                            if (Str(spec, key) is { Length: > 0 } f && !fixedVersions.Contains(f)) fixedVersions.Add(f);
                affected.Add(new OsvAffected(eco, name, purl, fixedVersions.ToArray()));
            }
        }
        return new OsvVuln(id, ExtractCveIds(root), affected.ToArray(), withdrawn);
    }

    /// <summary>
    /// CVE ids of a record: aliases, upstream (distribution records point at the CVE there) and a CVE embedded in
    /// the record id (UBUNTU-CVE-2023-2975, DEBIAN-CVE-..., ALPINE-CVE-...). Only when none of those name a CVE
    /// are the "related" entries used, which is where AlmaLinux advisories list the CVEs they fix.
    /// </summary>
    public static string[] ExtractCveIds(JsonElement root)
    {
        var set = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        void AddFrom(string prop)
        {
            if (!root.TryGetProperty(prop, out var arr) || arr.ValueKind != JsonValueKind.Array) return;
            foreach (var e in arr.EnumerateArray())
                if (e.ValueKind == JsonValueKind.String && e.GetString() is { } s && CveIdPattern.IsMatch(s.Trim())) set.Add(s.Trim().ToUpperInvariant());
        }
        AddFrom("aliases");
        AddFrom("upstream");
        var m = EmbeddedCve.Match(Str(root, "id"));
        if (m.Success) set.Add(m.Groups[1].Value.ToUpperInvariant());
        if (set.Count == 0) AddFrom("related");
        return set.ToArray();
    }

    /// <summary>
    /// The fixed version for the queried package: the affected entry whose ecosystem matches exactly is preferred,
    /// then one in the same ecosystem family (Debian:11 for a plain Debian purl), then any entry for the package.
    /// </summary>
    public static string? FindFixedVersion(OsvVuln v, PackageQuery q)
    {
        var name = string.IsNullOrWhiteSpace(q.Name) && q.Purl is not null ? PurlName(q.Purl) : (q.Name ?? "").Trim();
        var eco = (q.Ecosystem ?? "").Trim();
        var ecoBase = eco.Split(':')[0];
        var purlBase = q.Purl is null ? null : StripPurlQualifiers(q.Purl).Split('@')[0];

        var candidates = v.Affected.Where(a =>
            name == ""
            || string.Equals(a.Name, name, StringComparison.OrdinalIgnoreCase)
            || (purlBase is not null && a.Purl is not null && string.Equals(StripPurlQualifiers(a.Purl).Split('@')[0], purlBase, StringComparison.OrdinalIgnoreCase)));

        var ordered = candidates.OrderBy(a =>
            eco != "" && string.Equals(a.Ecosystem, eco, StringComparison.OrdinalIgnoreCase) ? 0
            : ecoBase != "" && (a.Ecosystem ?? "").StartsWith(ecoBase, StringComparison.OrdinalIgnoreCase) ? 1
            : 2);

        foreach (var a in ordered)
        {
            var f = a.Fixed.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x));
            if (f is not null) return f.Trim();
        }
        return null;
    }

    // ------------------------------------------------------------------ HTTP

    private async Task<Dictionary<string, OsvVuln?>> FetchDetailsAsync(List<string> ids, CancellationToken ct)
    {
        var result = new ConcurrentDictionary<string, OsvVuln?>(StringComparer.OrdinalIgnoreCase);
        var now = DateTime.UtcNow;
        var toFetch = new List<string>();
        foreach (var id in ids)
        {
            if (_cache.TryGetValue(id, out var c) && now - c.At < CacheTtl) result[id] = c.Vuln;
            else toFetch.Add(id);
        }
        if (_cache.Count > 50_000) _cache.Clear();
        using var gate = new SemaphoreSlim(Math.Max(1, MaxConcurrentDetailFetches));
        await Task.WhenAll(toFetch.Select(async id =>
        {
            await gate.WaitAsync(ct);
            try
            {
                var json = await SendAsync(() => new HttpRequestMessage(HttpMethod.Get, VulnUrl + id), ct, allowNotFound: true);
                OsvVuln? v = null;
                if (json is not null)
                {
                    try { v = ParseVuln(json); }
                    catch (JsonException ex) { _log?.LogWarning("OSV record {Id} could not be parsed: {Message}", id, ex.Message); }
                }
                result[id] = v;
                _cache[id] = (DateTime.UtcNow, v);
            }
            finally { gate.Release(); }
        }));
        return new Dictionary<string, OsvVuln?>(result, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Sends a request, retrying HTTP 429 and 5xx with Retry-After or an exponential delay.</summary>
    private async Task<string?> SendAsync(Func<HttpRequestMessage> make, CancellationToken ct, bool allowNotFound = false)
    {
        var client = _client();
        for (var attempt = 0; ; attempt++)
        {
            using var req = make();
            Interlocked.Increment(ref _requests);
            using var resp = await client.SendAsync(req, ct);
            if (resp.IsSuccessStatusCode) return await resp.Content.ReadAsStringAsync(ct);
            if (allowNotFound && resp.StatusCode == HttpStatusCode.NotFound) return null;
            var retry = resp.StatusCode == HttpStatusCode.TooManyRequests || (int)resp.StatusCode >= 500;
            if (!retry || attempt + 1 >= Math.Max(1, MaxAttempts))
                throw new HttpRequestException("OSV " + req.Method + " " + req.RequestUri + " returned HTTP " + (int)resp.StatusCode);
            var delay = resp.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(Math.Min(20, 1 << attempt));
            if (delay > TimeSpan.FromMinutes(2)) delay = TimeSpan.FromMinutes(2);
            _log?.LogWarning("OSV returned HTTP {Status}; retrying in {Delay}s", (int)resp.StatusCode, delay.TotalSeconds);
            await Task.Delay(delay, ct);
        }
    }

    private static string Str(JsonElement e, string prop)
    {
        if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(prop, out var v)) return "";
        return v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
    }

    private static string? NullIfEmpty(string s) => s == "" ? null : s;
}
