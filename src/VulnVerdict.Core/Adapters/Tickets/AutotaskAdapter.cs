using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Tickets;

/// <summary>
/// Datto Autotask PSA REST API (V1.0). One ticket per verdict against the configured company; Autotask has no tag
/// field on tickets, so the correlation key lives in the title prefix and search-before-create queries
/// title contains key excluding Complete. Priority follows the default picklist 1 High, 2 Medium, 3 Low.
/// Docs: https://ww4.autotask.net/help/developerhelp/Content/APIs/REST/Entities/TicketsEntity.htm
/// </summary>
public sealed class AutotaskAdapter : TicketAdapterBase
{
    public const string AdapterId = "autotask";
    private const int StatusComplete = 5;

    public AutotaskAdapter(IHttpClientFactory http, ILogger<AutotaskAdapter> log) : base(http, log) { }

    public override AdapterMetadata Metadata { get; } = new(
        AdapterId, "Autotask", "Datto (Kaseya)",
        "Raises one Autotask ticket per Fix today / Fix this week verdict against a company, with the correlation key in the title.",
        Array.Empty<AssetKind>(),
        new[]
        {
            new CredentialField("zoneUrl", "Zone API URL", CredentialTypes.Text, "https://webservices5.autotask.net/ATServicesRest/V1.0/ (find your zone at https://webservices.autotask.net/atservicesrest/v1.0/zoneInformation?user=<api user>)"),
            new CredentialField("apiIntegrationCode", "API integration code", CredentialTypes.Text, "The tracking identifier of the API user's integration vendor."),
            new CredentialField("username", "API user name", CredentialTypes.Text),
            new CredentialField("secret", "API user secret", CredentialTypes.Password),
            new CredentialField("companyId", "Company id", CredentialTypes.Number, "The Autotask company tickets are raised against (your own organisation, or the customer)."),
            new CredentialField("queueId", "Queue id", CredentialTypes.Number, "Optional service desk queue for new tickets.", Required: false),
            VerifyTlsField
        },
        "An API user (integration) whose security level allows ticket create and read.",
        "https://ww4.autotask.net/help/developerhelp/Content/APIs/REST/Entities/TicketsEntity.htm");

    /// <summary>Default Autotask status picklist; instances can add their own, which fall back to "status N".</summary>
    public static string StatusText(int? code) => code switch
    {
        1 => "New",
        5 => "Complete",
        7 => "Waiting Customer",
        8 => "In Progress",
        9 => "Waiting Materials",
        10 => "Dispatched",
        11 => "Escalate",
        12 => "Waiting Vendor",
        13 => "Waiting Approval",
        14 => "Customer Note Added",
        null => "unknown",
        _ => "status " + code
    };

    private sealed record Creds(string Zone, string IntegrationCode, string User, string Secret, int CompanyId, int? QueueId)
    {
        public string Api(string path) => Zone + "/" + path;
    }

    private static Creds Read(IReadOnlyDictionary<string, string> c)
    {
        var zone = BaseUrl(Require(c, "zoneUrl", "Zone API URL"));
        if (!zone.Contains("/ATServicesRest", StringComparison.OrdinalIgnoreCase)) zone += "/ATServicesRest/V1.0";
        return new(zone, Require(c, "apiIntegrationCode", "API integration code"), Require(c, "username", "API user name"), Require(c, "secret", "API user secret"),
            GetInt(c, "companyId") ?? throw new ArgumentException("Company id must be a number"), GetInt(c, "queueId"));
    }

    private HttpClient Client(IReadOnlyDictionary<string, string> credentials, Creds c)
    {
        var client = Client(credentials);
        client.DefaultRequestHeaders.Add("ApiIntegrationCode", c.IntegrationCode);
        client.DefaultRequestHeaders.Add("UserName", c.User);
        client.DefaultRequestHeaders.Add("Secret", c.Secret);
        return client;
    }

    public override async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        var c = Read(credentials);
        var client = Client(credentials, c);
        var r = await SendJsonAsync(client, JsonRequest(HttpMethod.Get, c.Api("Companies/" + c.CompanyId)), ct);
        var name = r?["item"] is JsonNode item ? Str(item["companyName"]) : null;
        if (name is null) return new TestResult(false, "Connected, but company " + c.CompanyId + " was not found or is not visible to this API user.");
        return new TestResult(true, "Connected to " + c.Zone + "; tickets will be raised against " + name + " (" + c.CompanyId + ").");
    }

    public override async Task<(string ExternalRef, string? Url)> CreateAsync(IReadOnlyDictionary<string, string> credentials, TicketRequest request, CancellationToken ct)
    {
        var c = Read(credentials);
        var client = Client(credentials, c);

        // idempotency: a ticket whose title carries our key and is not Complete
        var query = new
        {
            filter = new object[]
            {
                new { field = "title", op = "contains", value = request.CorrelationKey },
                new { field = "status", op = "noteq", value = StatusComplete }
            }
        };
        var found = await SendJsonAsync(client, JsonRequest(HttpMethod.Post, c.Api("Tickets/query"), query), ct);
        if (found?["items"] is JsonArray items && items.Count > 0 && Str(items[0]?["id"]) is { Length: > 0 } existing)
        {
            Log.LogInformation("Autotask ticket {Id} already open for {Correlation}", existing, request.CorrelationKey);
            return (existing, Url(c, existing));
        }

        var dueDays = Priority(request.Tier, 1, 7, 30);
        var body = new Dictionary<string, object?>
        {
            ["title"] = Prefixed(request),
            ["description"] = BodyText(request),
            ["status"] = 1,
            ["priority"] = Priority(request.Tier, 1, 2, 3),
            ["companyID"] = c.CompanyId,
            ["dueDateTime"] = DateTime.UtcNow.AddDays(dueDays).ToString("yyyy-MM-ddTHH:mm:ssZ")
        };
        if (c.QueueId is not null) body["queueID"] = c.QueueId;
        var created = await SendJsonAsync(client, JsonRequest(HttpMethod.Post, c.Api("Tickets"), body), ct);
        var id = Str(created?["itemId"]) ?? throw new InvalidOperationException("Autotask did not return a ticket id");
        return (id, Url(c, id));
    }

    /// <summary>The web UI lives on the "ww" host that pairs with the "webservices" API zone; null when the zone URL does not follow that pattern.</summary>
    private static string? Url(Creds c, string id)
    {
        if (!Uri.TryCreate(c.Zone, UriKind.Absolute, out var u)) return null;
        var host = u.Host;
        if (!host.StartsWith("webservices", StringComparison.OrdinalIgnoreCase)) return null;
        return "https://ww" + host["webservices".Length..] + "/Mvc/ServiceDesk/TicketDetail.mvc?workspace=False&mode=0&ticketId=" + id;
    }

    public override async Task<string?> StatusAsync(IReadOnlyDictionary<string, string> credentials, string externalRef, CancellationToken ct)
    {
        var c = Read(credentials);
        var client = Client(credentials, c);
        var r = await SendJsonAsync(client, JsonRequest(HttpMethod.Get, c.Api("Tickets/" + Uri.EscapeDataString(externalRef))), ct);
        var code = Int(r?["item"]?["status"]);
        return code is null ? null : StatusText(code);
    }
}
