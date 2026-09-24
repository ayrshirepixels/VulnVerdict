using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Tickets;

/// <summary>
/// ServiceNow Table API. One record per verdict on the configured task table (incident by default) with the
/// correlation key in short_description and in correlation_id; search-before-create finds an active record by
/// correlation_id. Urgency and impact come from the tier (1/1 = P1 Critical for Fix today).
/// Docs: https://www.servicenow.com/docs/bundle/latest-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html
/// </summary>
public sealed class ServiceNowAdapter : TicketAdapterBase
{
    public const string AdapterId = "servicenow";

    public ServiceNowAdapter(IHttpClientFactory http, ILogger<ServiceNowAdapter> log) : base(http, log) { }

    public override AdapterMetadata Metadata { get; } = new(
        AdapterId, "ServiceNow", "ServiceNow",
        "Raises one record per Fix today / Fix this week verdict on a task table, keyed by correlation_id.",
        Array.Empty<AssetKind>(),
        new[]
        {
            new CredentialField("instanceUrl", "Instance URL", CredentialTypes.Text, "https://yourcompany.service-now.com"),
            new CredentialField("username", "Username", CredentialTypes.Text, "A dedicated integration user is recommended."),
            new CredentialField("password", "Password", CredentialTypes.Password),
            new CredentialField("table", "Table", CredentialTypes.Text, "A table that extends task: incident, sc_task, problem.", Required: false, Default: "incident"),
            new CredentialField("assignmentGroup", "Assignment group", CredentialTypes.Text, "Optional group name or sys_id to route new records to.", Required: false),
            VerifyTlsField
        },
        "A user with the itil role, or a role limited to create and read on the chosen table.",
        "https://www.servicenow.com/docs/bundle/latest-api-reference/page/integrate/inbound-rest/concept/c_TableAPI.html");

    private sealed record Creds(string Instance, string User, string Password, string Table, string? AssignmentGroup)
    {
        public string Api(string query = "") => Instance + "/api/now/table/" + Table + query;
    }

    private static Creds Read(IReadOnlyDictionary<string, string> c) => new(
        BaseUrl(Require(c, "instanceUrl", "Instance URL")), Require(c, "username", "Username"), Require(c, "password", "Password"),
        Get(c, "table", "incident").ToLowerInvariant(), Get(c, "assignmentGroup") is { Length: > 0 } g ? g : null);

    private HttpClient Client(IReadOnlyDictionary<string, string> credentials, Creds c)
    {
        var client = Client(credentials);
        client.DefaultRequestHeaders.Authorization = Basic(c.User, c.Password);
        return client;
    }

    public override async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        var c = Read(credentials);
        var client = Client(credentials, c);
        var r = await SendJsonAsync(client, JsonRequest(HttpMethod.Get, c.Api("?sysparm_limit=1&sysparm_fields=sys_id")), ct);
        var n = r?["result"] is JsonArray a ? a.Count : 0;
        return new TestResult(true, "Connected to " + c.Instance + "; table " + c.Table + " is readable" + (n == 0 ? " (no records visible yet)" : "") + ".");
    }

    public override async Task<(string ExternalRef, string? Url)> CreateAsync(IReadOnlyDictionary<string, string> credentials, TicketRequest request, CancellationToken ct)
    {
        var c = Read(credentials);
        var client = Client(credentials, c);

        // idempotency: an active record already carries our correlation id
        var query = "correlation_id=" + request.CorrelationKey + "^active=true";
        var found = await SendJsonAsync(client, JsonRequest(HttpMethod.Get, c.Api("?sysparm_query=" + Uri.EscapeDataString(query) + "&sysparm_fields=sys_id,number,state&sysparm_display_value=true&sysparm_limit=1")), ct);
        if (found?["result"] is JsonArray rows && rows.Count > 0 && Ref(rows[0]) is { } existing)
        {
            Log.LogInformation("ServiceNow {Table} {Ref} already active for {Correlation}", c.Table, existing.Ref, request.CorrelationKey);
            return (existing.Ref, Url(c, existing.SysId));
        }

        var (urgency, impact) = Priority(request.Tier, ("1", "1"), ("2", "2"), ("3", "3"));
        var body = new Dictionary<string, object?>
        {
            ["short_description"] = Prefixed(request),
            ["description"] = BodyText(request),
            ["urgency"] = urgency,
            ["impact"] = impact,
            ["correlation_id"] = request.CorrelationKey,
            ["correlation_display"] = "VulnVerdict"
        };
        if (c.AssignmentGroup is not null) body["assignment_group"] = c.AssignmentGroup;
        var created = await SendJsonAsync(client, JsonRequest(HttpMethod.Post, c.Api(), body), ct);
        var rec = Ref(created?["result"]) ?? throw new InvalidOperationException("ServiceNow did not return the created record");
        return (rec.Ref, Url(c, rec.SysId));
    }

    private static (string Ref, string SysId)? Ref(JsonNode? row)
    {
        var sysId = Str(row?["sys_id"]);
        if (string.IsNullOrEmpty(sysId)) return null;
        var number = Str(row?["number"]);
        return (string.IsNullOrEmpty(number) ? sysId : number, sysId);
    }

    private static string Url(Creds c, string sysId) => c.Instance + "/nav_to.do?uri=" + Uri.EscapeDataString("/" + c.Table + ".do?sys_id=" + sysId);

    /// <summary>The external reference is the record number (INC0010001) when the table has one, else the sys_id; both resolve here.</summary>
    public override async Task<string?> StatusAsync(IReadOnlyDictionary<string, string> credentials, string externalRef, CancellationToken ct)
    {
        var c = Read(credentials);
        var client = Client(credentials, c);
        var query = "number=" + externalRef + "^ORsys_id=" + externalRef;
        var r = await SendJsonAsync(client, JsonRequest(HttpMethod.Get, c.Api("?sysparm_query=" + Uri.EscapeDataString(query) + "&sysparm_fields=state&sysparm_display_value=true&sysparm_limit=1")), ct);
        return r?["result"] is JsonArray rows && rows.Count > 0 ? Str(rows[0]?["state"]) : null;
    }
}
