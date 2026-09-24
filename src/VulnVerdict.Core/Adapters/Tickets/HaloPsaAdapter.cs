using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Tickets;

/// <summary>
/// HaloPSA (and HaloITSM) REST API with OAuth2 client credentials. One ticket per verdict; Halo has no free tag
/// field, so the correlation key lives in the summary prefix and details, and search-before-create uses the
/// ticket search on the key with open_only=true. Priority ids follow Halo's defaults (1 Critical, 2 High, 3 Medium).
/// Docs: https://haloservicedesk.com/apidoc/info
/// </summary>
public sealed class HaloPsaAdapter : TicketAdapterBase
{
    public const string AdapterId = "halopsa";

    // status id -> name, learned from /api/Status on first use per instance
    private readonly ConcurrentDictionary<string, Dictionary<int, string>> _statusNames = new();

    public HaloPsaAdapter(IHttpClientFactory http, ILogger<HaloPsaAdapter> log) : base(http, log) { }

    public override AdapterMetadata Metadata { get; } = new(
        AdapterId, "HaloPSA", "Halo",
        "Raises one HaloPSA ticket per Fix today / Fix this week verdict, with the correlation key in the summary.",
        Array.Empty<AssetKind>(),
        new[]
        {
            new CredentialField("baseUrl", "Halo URL", CredentialTypes.Text, "https://yourcompany.halopsa.com"),
            new CredentialField("clientId", "Client ID", CredentialTypes.Text, "From Configuration, Integrations, HaloPSA API, Applications (client credentials)."),
            new CredentialField("clientSecret", "Client secret", CredentialTypes.Password),
            new CredentialField("tenant", "Tenant", CredentialTypes.Text, "Only for hosted instances that need a tenant name on the token request.", Required: false),
            new CredentialField("ticketTypeId", "Ticket type id", CredentialTypes.Number, "The id of the ticket type to raise (Configuration, Tickets, Ticket Types)."),
            new CredentialField("customerId", "Customer (client) id", CredentialTypes.Number, "Optional Halo client id to raise tickets against.", Required: false),
            VerifyTlsField
        },
        "An API application using client credentials with ticket read and write permissions (login as an agent).",
        "https://haloservicedesk.com/apidoc/info");

    private sealed record Creds(string Site, string ClientId, string ClientSecret, string? Tenant, int TicketTypeId, int? CustomerId)
    {
        public string Api(string path) => Site + "/api/" + path;
    }

    private static Creds Read(IReadOnlyDictionary<string, string> c) => new(
        BaseUrl(Require(c, "baseUrl", "Halo URL")), Require(c, "clientId", "Client ID"), Require(c, "clientSecret", "Client secret"),
        Get(c, "tenant") is { Length: > 0 } t ? t : null,
        GetInt(c, "ticketTypeId") ?? throw new ArgumentException("Ticket type id must be a number"),
        GetInt(c, "customerId"));

    private async Task<HttpClient> ClientAsync(IReadOnlyDictionary<string, string> credentials, Creds c, CancellationToken ct)
    {
        var client = Client(credentials);
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = c.ClientId,
            ["client_secret"] = c.ClientSecret,
            ["scope"] = "all"
        };
        var url = c.Site + "/auth/token" + (c.Tenant is null ? "" : "?tenant=" + Uri.EscapeDataString(c.Tenant));
        var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = new FormUrlEncodedContent(form) };
        var token = await SendJsonAsync(client, req, ct);
        var access = Str(token?["access_token"]) ?? throw new InvalidOperationException("Halo did not return an access token");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", access);
        return client;
    }

    public override async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        var c = Read(credentials);
        var client = await ClientAsync(credentials, c, ct);
        var type = await SendJsonAsync(client, JsonRequest(HttpMethod.Get, c.Api("TicketType/" + c.TicketTypeId)), ct);
        return new TestResult(true, "Connected to " + c.Site + "; ticket type " + (Str(type?["name"]) ?? c.TicketTypeId.ToString()) + " is available.");
    }

    public override async Task<(string ExternalRef, string? Url)> CreateAsync(IReadOnlyDictionary<string, string> credentials, TicketRequest request, CancellationToken ct)
    {
        var c = Read(credentials);
        var client = await ClientAsync(credentials, c, ct);

        // idempotency: an open ticket whose summary carries our key
        var found = await SendJsonAsync(client, JsonRequest(HttpMethod.Get, c.Api("Tickets?search=" + Uri.EscapeDataString(request.CorrelationKey) + "&open_only=true&page_size=5&pageinate=true")), ct);
        if (found?["tickets"] is JsonArray tickets)
        {
            var hit = tickets.FirstOrDefault(t => (Str(t?["summary"]) ?? "").Contains(request.CorrelationKey, StringComparison.OrdinalIgnoreCase));
            if (hit is not null && Str(hit["id"]) is { Length: > 0 } existing)
            {
                Log.LogInformation("Halo ticket {Id} already open for {Correlation}", existing, request.CorrelationKey);
                return (existing, Url(c, existing));
            }
        }

        var ticket = new Dictionary<string, object?>
        {
            ["summary"] = Prefixed(request),
            ["details"] = BodyText(request),
            ["tickettype_id"] = c.TicketTypeId,
            ["priority_id"] = Priority(request.Tier, 1, 2, 3)
        };
        if (c.CustomerId is not null) ticket["client_id"] = c.CustomerId;
        var created = await SendJsonAsync(client, JsonRequest(HttpMethod.Post, c.Api("Tickets"), new[] { ticket }), ct);
        var node = created is JsonArray arr ? (arr.Count > 0 ? arr[0] : null) : created;
        var id = Str(node?["id"]) ?? throw new InvalidOperationException("Halo did not return a ticket id");
        return (id, Url(c, id));
    }

    private static string Url(Creds c, string id) => c.Site + "/tickets?id=" + id;

    public override async Task<string?> StatusAsync(IReadOnlyDictionary<string, string> credentials, string externalRef, CancellationToken ct)
    {
        var c = Read(credentials);
        var client = await ClientAsync(credentials, c, ct);
        var t = await SendJsonAsync(client, JsonRequest(HttpMethod.Get, c.Api("Tickets/" + Uri.EscapeDataString(externalRef))), ct);
        if (t is null) return null;
        var name = Str(t["status_name"]) ?? Str(t["status"]?["name"]);
        if (name is not null) return name;
        var statusId = Int(t["status_id"]);
        if (statusId is null) return null;
        var names = await StatusNamesAsync(client, c, ct);
        return names.TryGetValue(statusId.Value, out var n) ? n : "status " + statusId;
    }

    private async Task<Dictionary<int, string>> StatusNamesAsync(HttpClient client, Creds c, CancellationToken ct)
    {
        if (_statusNames.TryGetValue(c.Site, out var cached)) return cached;
        var map = new Dictionary<int, string>();
        try
        {
            var list = await SendJsonAsync(client, JsonRequest(HttpMethod.Get, c.Api("Status")), ct);
            if (list is JsonArray arr)
                foreach (var s in arr)
                    if (Int(s?["id"]) is { } id && Str(s?["name"]) is { } name) map[id] = name;
        }
        catch (Exception ex) { Log.LogDebug(ex, "Halo status list not readable"); }
        if (map.Count > 0) _statusNames[c.Site] = map;
        return map;
    }
}
