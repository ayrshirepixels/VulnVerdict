using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Tickets;

/// <summary>
/// Section 11.3: shared plumbing for the native helpdesk adapters. Every adapter is one credential form with a
/// "verify TLS" switch, puts the correlation key at the front of the title ("[VV:CVE-...:xxxxxxxx] ..."), stores it in
/// a vendor field where one exists (label, tag, correlation id), puts the verdict URL in the body, and searches by the
/// key before creating so a re-run never raises a duplicate for an open ticket.
/// </summary>
public abstract class TicketAdapterBase : ITicketAdapter
{
    public const string VerifyTlsKey = "verifyTls";
    public const string HttpClientName = "adapter";
    public const string InsecureHttpClientName = "adapter-insecure";

    protected static readonly CredentialField VerifyTlsField = new(VerifyTlsKey, "Verify TLS certificate", CredentialTypes.Bool,
        "Leave on. Turn off only for an on-premises instance with a private certificate.", Required: false, Default: "true");

    protected static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web) { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    protected readonly IHttpClientFactory Http;
    protected readonly ILogger Log;

    protected TicketAdapterBase(IHttpClientFactory http, ILogger log)
    {
        Http = http; Log = log;
    }

    public abstract AdapterMetadata Metadata { get; }
    public abstract Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct);
    public abstract Task<(string ExternalRef, string? Url)> CreateAsync(IReadOnlyDictionary<string, string> credentials, TicketRequest request, CancellationToken ct);
    public abstract Task<string?> StatusAsync(IReadOnlyDictionary<string, string> credentials, string externalRef, CancellationToken ct);

    // ------------------------------------------------------------------ credentials

    /// <summary>The "verify TLS" switch: anything but an explicit false/0/no/off means verify.</summary>
    public static bool VerifyTls(IReadOnlyDictionary<string, string> credentials)
    {
        if (!credentials.TryGetValue(VerifyTlsKey, out var v) || string.IsNullOrWhiteSpace(v)) return true;
        var t = v.Trim();
        return !(t.Equals("false", StringComparison.OrdinalIgnoreCase) || t == "0" || t.Equals("no", StringComparison.OrdinalIgnoreCase) || t.Equals("off", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Named client "adapter" verifies certificates; "adapter-insecure" accepts any (private CAs on customer systems).</summary>
    protected HttpClient Client(IReadOnlyDictionary<string, string> credentials) =>
        Http.CreateClient(VerifyTls(credentials) ? HttpClientName : InsecureHttpClientName);

    protected static string Get(IReadOnlyDictionary<string, string> credentials, string key, string fallback = "") =>
        credentials.TryGetValue(key, out var v) && !string.IsNullOrWhiteSpace(v) ? v.Trim() : fallback;

    protected static string Require(IReadOnlyDictionary<string, string> credentials, string key, string label)
    {
        var v = Get(credentials, key);
        if (v.Length == 0) throw new ArgumentException(label + " is required");
        return v;
    }

    protected static int? GetInt(IReadOnlyDictionary<string, string> credentials, string key)
    {
        var v = Get(credentials, key);
        return v.Length > 0 && int.TryParse(v, out var n) ? n : null;
    }

    /// <summary>Normalise a site/instance URL: add https:// when no scheme was given, drop a trailing slash.</summary>
    protected static string BaseUrl(string raw)
    {
        var s = raw.Trim().TrimEnd('/');
        if (!s.Contains("://", StringComparison.Ordinal)) s = "https://" + s;
        return s;
    }

    // ------------------------------------------------------------------ ticket content

    /// <summary>Title with the correlation key in front, "[VV:CVE-2024-1234:0a1b2c3d] Fix today: ...", never doubled.</summary>
    public static string Prefixed(TicketRequest r)
    {
        var prefix = "[" + r.CorrelationKey + "]";
        return r.Title.StartsWith(prefix, StringComparison.Ordinal) ? r.Title : prefix + " " + r.Title;
    }

    /// <summary>
    /// Label/tag form of the key for vendors whose tags cannot hold colons or upper case:
    /// "VV:CVE-2024-1234:0a1b2c3d" becomes "vv-cve-2024-1234-0a1b2c3d".
    /// </summary>
    public static string Tag(string correlationKey)
    {
        var k = correlationKey.Trim();
        if (k.StartsWith("VV:", StringComparison.OrdinalIgnoreCase)) k = k[3..];
        var sb = new StringBuilder("vv-");
        foreach (var ch in k) sb.Append(char.IsLetterOrDigit(ch) ? char.ToLowerInvariant(ch) : '-');
        return sb.ToString();
    }

    /// <summary>Plain-text body: the request body, the verdict URL (added when the body does not already carry it) and the key.</summary>
    public static string BodyText(TicketRequest r)
    {
        var sb = new StringBuilder(r.Body.TrimEnd());
        if (!string.IsNullOrWhiteSpace(r.Url) && !r.Body.Contains(r.Url, StringComparison.Ordinal))
            sb.Append("\n\nDetails and evidence: ").Append(r.Url);
        sb.Append("\n\nCorrelation key ").Append(r.CorrelationKey).Append(". Raised automatically by VulnVerdict.");
        return sb.ToString();
    }

    /// <summary>HTML body for vendors whose description field is HTML: paragraphs per blank line, the URL as a link.</summary>
    public static string BodyHtml(TicketRequest r)
    {
        var sb = new StringBuilder();
        foreach (var para in r.Body.Replace("\r\n", "\n").Split("\n\n", StringSplitOptions.RemoveEmptyEntries))
            sb.Append("<p>").Append(WebUtility.HtmlEncode(para.Trim()).Replace("\n", "<br>")).Append("</p>");
        if (!string.IsNullOrWhiteSpace(r.Url))
            sb.Append("<p><a href=\"").Append(WebUtility.HtmlEncode(r.Url)).Append("\">Details and evidence</a></p>");
        sb.Append("<p>Correlation key ").Append(WebUtility.HtmlEncode(r.CorrelationKey)).Append(". Raised automatically by VulnVerdict.</p>");
        return sb.ToString();
    }

    /// <summary>Map the verdict tier to a vendor priority: Fix today is the vendor's highest, Fix this week the next one down.</summary>
    protected static T Priority<T>(VerdictTier tier, T fixToday, T fixThisWeek, T other) => tier switch
    {
        VerdictTier.FixToday => fixToday,
        VerdictTier.FixThisWeek => fixThisWeek,
        _ => other
    };

    // ------------------------------------------------------------------ http

    protected static AuthenticationHeaderValue Basic(string user, string secret) =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(user + ":" + secret)));

    protected static HttpRequestMessage JsonRequest(HttpMethod method, string url, object? body = null, string mediaType = "application/json")
    {
        var req = new HttpRequestMessage(method, url);
        req.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (body is not null) req.Content = new StringContent(JsonSerializer.Serialize(body, JsonOpts), Encoding.UTF8, mediaType);
        return req;
    }

    /// <summary>Send, fail with a readable message on a non-2xx status, and parse the JSON body (null when empty).</summary>
    protected static async Task<JsonNode?> SendJsonAsync(HttpClient client, HttpRequestMessage req, CancellationToken ct)
    {
        using var resp = await client.SendAsync(req, ct);
        var text = resp.Content is null ? "" : await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode) throw new HttpRequestException(Describe(req, resp.StatusCode, text), null, resp.StatusCode);
        return ParseJson(text);
    }

    protected static JsonNode? ParseJson(string text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        try { return JsonNode.Parse(text); }
        catch (JsonException) { return null; }
    }

    protected static string Describe(HttpRequestMessage req, HttpStatusCode status, string body)
    {
        var snippet = body.Length > 300 ? body[..300] + "..." : body;
        var reason = status switch
        {
            HttpStatusCode.Unauthorized => "authentication failed (check the credential)",
            HttpStatusCode.Forbidden => "permission denied (check the minimum permission on the form)",
            HttpStatusCode.NotFound => "not found (check the URL, project or table)",
            _ => "request failed"
        };
        return req.Method + " " + req.RequestUri?.PathAndQuery + ": " + (int)status + " " + reason + (snippet.Length > 0 ? " - " + snippet.Trim() : "");
    }

    protected static string? Str(JsonNode? node)
    {
        if (node is null) return null;
        try
        {
            return node is JsonValue v ? (v.TryGetValue<string>(out var s) ? s : v.ToJsonString().Trim('"')) : node.ToJsonString();
        }
        catch { return null; }
    }

    protected static int? Int(JsonNode? node)
    {
        if (node is not JsonValue v) return null;
        if (v.TryGetValue<int>(out var i)) return i;
        if (v.TryGetValue<long>(out var l)) return (int)l;
        if (v.TryGetValue<double>(out var d)) return (int)d;
        return v.TryGetValue<string>(out var s) && int.TryParse(s, out var p) ? p : null;
    }
}
