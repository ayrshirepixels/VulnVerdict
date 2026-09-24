using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Tickets;

/// <summary>
/// Zendesk Support API. One ticket per verdict, tagged with the correlation key; search-before-create runs
/// "type:ticket tags:vv-... status&lt;solved" and returns the existing ticket when there is one.
/// Docs: https://developer.zendesk.com/api-reference/ticketing/tickets/tickets/#create-ticket
/// </summary>
public sealed class ZendeskAdapter : TicketAdapterBase
{
    public const string AdapterId = "zendesk";

    public ZendeskAdapter(IHttpClientFactory http, ILogger<ZendeskAdapter> log) : base(http, log) { }

    public override AdapterMetadata Metadata { get; } = new(
        AdapterId, "Zendesk", "Zendesk",
        "Raises one Zendesk ticket per Fix today / Fix this week verdict, tagged with the correlation key.",
        Array.Empty<AssetKind>(),
        new[]
        {
            new CredentialField("subdomain", "Subdomain", CredentialTypes.Text, "The part before .zendesk.com, or the full URL."),
            new CredentialField("email", "Agent email", CredentialTypes.Text, "The agent the API token belongs to."),
            new CredentialField("apiToken", "API token", CredentialTypes.Password, "Admin Center, Apps and integrations, APIs: https://support.zendesk.com/hc/en-us/articles/4408889192858"),
            VerifyTlsField
        },
        "An agent with API token access enabled in Admin Center.",
        "https://developer.zendesk.com/api-reference/ticketing/tickets/tickets/#create-ticket");

    private static readonly HashSet<string> OpenStatuses = new(StringComparer.OrdinalIgnoreCase) { "new", "open", "pending", "hold" };

    private sealed record Creds(string Site, string Email, string Token)
    {
        public string Api(string path) => Site + "/api/v2/" + path;
    }

    private static Creds Read(IReadOnlyDictionary<string, string> c)
    {
        var sub = Require(c, "subdomain", "Subdomain");
        var site = sub.Contains('.') ? BaseUrl(sub) : "https://" + sub + ".zendesk.com";
        return new(site, Require(c, "email", "Email"), Require(c, "apiToken", "API token"));
    }

    private HttpClient Client(IReadOnlyDictionary<string, string> credentials, Creds c)
    {
        var client = Client(credentials);
        client.DefaultRequestHeaders.Authorization = Basic(c.Email + "/token", c.Token);
        return client;
    }

    public override async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        var c = Read(credentials);
        var client = Client(credentials, c);
        var me = await SendJsonAsync(client, JsonRequest(HttpMethod.Get, c.Api("users/me.json")), ct);
        var role = Str(me?["user"]?["role"]);
        if (role is null || role.Equals("end-user", StringComparison.OrdinalIgnoreCase))
            return new TestResult(false, "Authenticated, but " + c.Email + " is not an agent (role " + (role ?? "unknown") + ").");
        return new TestResult(true, "Connected as " + (Str(me?["user"]?["name"]) ?? c.Email) + " (" + role + ") on " + c.Site + ".");
    }

    public override async Task<(string ExternalRef, string? Url)> CreateAsync(IReadOnlyDictionary<string, string> credentials, TicketRequest request, CancellationToken ct)
    {
        var c = Read(credentials);
        var client = Client(credentials, c);
        var tag = Tag(request.CorrelationKey);

        // idempotency: an unsolved ticket already carries our tag
        var query = "type:ticket tags:" + tag + " status<solved";
        var found = await SendJsonAsync(client, JsonRequest(HttpMethod.Get, c.Api("search.json?query=" + Uri.EscapeDataString(query))), ct);
        if (found?["results"] is JsonArray results)
        {
            var open = results.FirstOrDefault(t => Str(t?["status"]) is { } s && OpenStatuses.Contains(s));
            if (open is not null && Str(open["id"]) is { Length: > 0 } existing)
            {
                Log.LogInformation("Zendesk ticket {Id} already open for {Correlation}", existing, request.CorrelationKey);
                return (existing, Url(c, existing));
            }
        }

        var body = new
        {
            ticket = new
            {
                subject = Prefixed(request),
                comment = new { body = BodyText(request) },
                priority = Priority(request.Tier, "urgent", "high", "normal"),
                tags = new[] { tag },
                type = "incident"
            }
        };
        var created = await SendJsonAsync(client, JsonRequest(HttpMethod.Post, c.Api("tickets.json"), body), ct);
        var id = Str(created?["ticket"]?["id"]) ?? throw new InvalidOperationException("Zendesk did not return a ticket id");
        return (id, Url(c, id));
    }

    private static string Url(Creds c, string id) => c.Site + "/agent/tickets/" + id;

    public override async Task<string?> StatusAsync(IReadOnlyDictionary<string, string> credentials, string externalRef, CancellationToken ct)
    {
        var c = Read(credentials);
        var client = Client(credentials, c);
        var r = await SendJsonAsync(client, JsonRequest(HttpMethod.Get, c.Api("tickets/" + Uri.EscapeDataString(externalRef) + ".json")), ct);
        return Str(r?["ticket"]?["status"]);
    }
}
