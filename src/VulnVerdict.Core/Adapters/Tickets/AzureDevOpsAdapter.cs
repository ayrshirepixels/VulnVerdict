using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Tickets;

/// <summary>
/// Azure DevOps Services work items (REST 7.1). One work item per verdict with the correlation key in the title
/// and in System.Tags; search-before-create is a WIQL query on the tag excluding finished states. Priority is
/// Microsoft.VSTS.Common.Priority 1 (Fix today) to 3.
/// Docs: https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-items/create
/// </summary>
public sealed class AzureDevOpsAdapter : TicketAdapterBase
{
    public const string AdapterId = "azure-devops";
    private const string ApiVersion = "api-version=7.1";

    public AzureDevOpsAdapter(IHttpClientFactory http, ILogger<AzureDevOpsAdapter> log) : base(http, log) { }

    public override AdapterMetadata Metadata { get; } = new(
        AdapterId, "Azure DevOps", "Microsoft",
        "Raises one work item per Fix today / Fix this week verdict, tagged with the correlation key.",
        Array.Empty<AssetKind>(),
        new[]
        {
            new CredentialField("organisationUrl", "Organisation URL", CredentialTypes.Text, "https://dev.azure.com/yourorg (or your Azure DevOps Server collection URL)"),
            new CredentialField("project", "Project", CredentialTypes.Text, "Project name or id."),
            new CredentialField("pat", "Personal access token", CredentialTypes.Password, "Create one with the Work Items (Read & Write) scope: https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate"),
            new CredentialField("workItemType", "Work item type", CredentialTypes.Text, "Issue (Basic), Task, Bug or a custom type in the project's process.", Required: false, Default: "Issue"),
            VerifyTlsField
        },
        "A personal access token with the Work Items (Read & Write) scope.",
        "https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-items/create");

    private static readonly string[] FinishedStates = { "Closed", "Done", "Removed", "Resolved", "Completed" };

    private sealed record Creds(string Org, string Project, string Pat, string Type)
    {
        public string Api(string path) => Org + "/" + Uri.EscapeDataString(Project) + "/_apis/wit/" + path + (path.Contains('?') ? "&" : "?") + ApiVersion;
    }

    private static Creds Read(IReadOnlyDictionary<string, string> c) => new(
        BaseUrl(Require(c, "organisationUrl", "Organisation URL")), Require(c, "project", "Project"), Require(c, "pat", "Personal access token"), Get(c, "workItemType", "Issue"));

    private HttpClient Client(IReadOnlyDictionary<string, string> credentials, Creds c)
    {
        var client = Client(credentials);
        client.DefaultRequestHeaders.Authorization = Basic("", c.Pat);
        return client;
    }

    public override async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        var c = Read(credentials);
        var client = Client(credentials, c);
        var types = await SendJsonAsync(client, JsonRequest(HttpMethod.Get, c.Api("workitemtypes")), ct);
        var names = (types?["value"] as JsonArray)?.Select(t => Str(t?["name"])).Where(n => n is not null).ToList() ?? new List<string?>();
        if (!names.Contains(c.Type, StringComparer.OrdinalIgnoreCase))
            return new TestResult(false, "Connected, but work item type \"" + c.Type + "\" is not in project " + c.Project + " (available: " + string.Join(", ", names) + ").");
        return new TestResult(true, "Connected to " + c.Org + ", project " + c.Project + "; work item type " + c.Type + " is available.");
    }

    public override async Task<(string ExternalRef, string? Url)> CreateAsync(IReadOnlyDictionary<string, string> credentials, TicketRequest request, CancellationToken ct)
    {
        var c = Read(credentials);
        var client = Client(credentials, c);
        var tag = Tag(request.CorrelationKey);

        // idempotency: WIQL on the tag, ignoring finished states
        var wiql = "SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = @project AND [System.Tags] CONTAINS '" + tag + "' AND [System.State] NOT IN ('" + string.Join("', '", FinishedStates) + "') ORDER BY [System.CreatedDate] DESC";
        var found = await SendJsonAsync(client, JsonRequest(HttpMethod.Post, c.Api("wiql"), new { query = wiql }), ct);
        if (found?["workItems"] is JsonArray items && items.Count > 0 && Str(items[0]?["id"]) is { Length: > 0 } existing)
        {
            Log.LogInformation("Azure DevOps work item {Id} already open for {Correlation}", existing, request.CorrelationKey);
            return (existing, Url(c, existing));
        }

        var patch = new object[]
        {
            new { op = "add", path = "/fields/System.Title", value = Prefixed(request) },
            new { op = "add", path = "/fields/System.Description", value = BodyHtml(request) },
            new { op = "add", path = "/fields/Microsoft.VSTS.Common.Priority", value = Priority(request.Tier, 1, 2, 3) },
            new { op = "add", path = "/fields/System.Tags", value = tag }
        };
        var created = await SendJsonAsync(client, JsonRequest(HttpMethod.Post, c.Api("workitems/$" + Uri.EscapeDataString(c.Type)), patch, "application/json-patch+json"), ct);
        var id = Str(created?["id"]) ?? throw new InvalidOperationException("Azure DevOps did not return a work item id");
        return (id, Str(created?["_links"]?["html"]?["href"]) ?? Url(c, id));
    }

    private static string Url(Creds c, string id) => c.Org + "/" + Uri.EscapeDataString(c.Project) + "/_workitems/edit/" + id;

    public override async Task<string?> StatusAsync(IReadOnlyDictionary<string, string> credentials, string externalRef, CancellationToken ct)
    {
        var c = Read(credentials);
        var client = Client(credentials, c);
        var r = await SendJsonAsync(client, JsonRequest(HttpMethod.Get, c.Api("workitems/" + Uri.EscapeDataString(externalRef) + "?fields=System.State")), ct);
        return Str(r?["fields"]?["System.State"]);
    }
}
