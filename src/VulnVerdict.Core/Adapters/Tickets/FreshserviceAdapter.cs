using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Tickets;

/// <summary>
/// Freshservice API v2. One ticket per verdict, tagged with the correlation key ("vv-cve-2024-1234-0a1b2c3d");
/// search-before-create uses the ticket filter on that tag and treats Open (2) and Pending (3) as still open.
/// Docs: https://api.freshservice.com/#create_ticket
/// </summary>
public sealed class FreshserviceAdapter : TicketAdapterBase
{
    public const string AdapterId = "freshservice";

    public FreshserviceAdapter(IHttpClientFactory http, ILogger<FreshserviceAdapter> log) : base(http, log) { }

    public override AdapterMetadata Metadata { get; } = new(
        AdapterId, "Freshservice", "Freshworks",
        "Raises one Freshservice ticket per Fix today / Fix this week verdict, tagged with the correlation key.",
        Array.Empty<AssetKind>(),
        new[]
        {
            new CredentialField("domain", "Helpdesk domain", CredentialTypes.Text, "yourcompany.freshservice.com"),
            new CredentialField("apiKey", "Agent API key", CredentialTypes.Password, "Profile settings, right-hand panel: https://support.freshservice.com/support/solutions/articles/50000000306"),
            new CredentialField("requesterEmail", "Requester email", CredentialTypes.Text, "The requester shown on tickets VulnVerdict raises, for example it-security@yourcompany.com."),
            new CredentialField("groupId", "Group id", CredentialTypes.Number, "Optional agent group to assign new tickets to.", Required: false),
            VerifyTlsField
        },
        "An agent API key with permission to create and view tickets.",
        "https://api.freshservice.com/#create_ticket");

    public static string StatusText(int? code) => code switch
    {
        2 => "Open",
        3 => "Pending",
        4 => "Resolved",
        5 => "Closed",
        null => "unknown",
        _ => "status " + code
    };

    private sealed record Creds(string Site, string ApiKey, string Requester, int? GroupId)
    {
        public string Api(string path) => Site + "/api/v2/" + path;
    }

    private static Creds Read(IReadOnlyDictionary<string, string> c) => new(
        BaseUrl(Require(c, "domain", "Helpdesk domain")), Require(c, "apiKey", "API key"), Require(c, "requesterEmail", "Requester email"), GetInt(c, "groupId"));

    private HttpClient Client(IReadOnlyDictionary<string, string> credentials, Creds c)
    {
        var client = Client(credentials);
        client.DefaultRequestHeaders.Authorization = Basic(c.ApiKey, "X");
        return client;
    }

    public override async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        var c = Read(credentials);
        var client = Client(credentials, c);
        await SendJsonAsync(client, JsonRequest(HttpMethod.Get, c.Api("tickets?per_page=1")), ct);
        return new TestResult(true, "Connected to " + c.Site + "; tickets are readable.");
    }

    public override async Task<(string ExternalRef, string? Url)> CreateAsync(IReadOnlyDictionary<string, string> credentials, TicketRequest request, CancellationToken ct)
    {
        var c = Read(credentials);
        var client = Client(credentials, c);
        var tag = Tag(request.CorrelationKey);

        // idempotency: an open or pending ticket already carries our tag
        var query = "\"tag:'" + tag + "'\"";
        var found = await SendJsonAsync(client, JsonRequest(HttpMethod.Get, c.Api("tickets/filter?query=" + Uri.EscapeDataString(query))), ct);
        if (found?["tickets"] is JsonArray tickets)
        {
            var open = tickets.FirstOrDefault(t => Int(t?["status"]) is 2 or 3);
            if (open is not null && Str(open["id"]) is { Length: > 0 } existing)
            {
                Log.LogInformation("Freshservice ticket {Id} already open for {Correlation}", existing, request.CorrelationKey);
                return (existing, Url(c, existing));
            }
        }

        var body = new Dictionary<string, object?>
        {
            ["subject"] = Prefixed(request),
            ["description"] = BodyHtml(request),
            ["email"] = c.Requester,
            ["priority"] = Priority(request.Tier, 4, 3, 2),
            ["status"] = 2,
            ["tags"] = new[] { tag }
        };
        if (c.GroupId is not null) body["group_id"] = c.GroupId;
        var created = await SendJsonAsync(client, JsonRequest(HttpMethod.Post, c.Api("tickets"), body), ct);
        var id = Str(created?["ticket"]?["id"]) ?? throw new InvalidOperationException("Freshservice did not return a ticket id");
        return (id, Url(c, id));
    }

    private static string Url(Creds c, string id) => c.Site + "/a/tickets/" + id;

    public override async Task<string?> StatusAsync(IReadOnlyDictionary<string, string> credentials, string externalRef, CancellationToken ct)
    {
        var c = Read(credentials);
        var client = Client(credentials, c);
        var r = await SendJsonAsync(client, JsonRequest(HttpMethod.Get, c.Api("tickets/" + Uri.EscapeDataString(externalRef))), ct);
        var code = Int(r?["ticket"]?["status"]);
        return code is null ? null : StatusText(code);
    }
}
