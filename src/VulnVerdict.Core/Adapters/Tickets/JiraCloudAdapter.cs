using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Tickets;

/// <summary>
/// Jira Cloud, REST API v3. One issue per verdict with the correlation key in the summary prefix and as a label
/// ("vv-cve-2024-1234-0a1b2c3d"). Search-before-create: an unresolved issue carrying the label is returned instead of
/// a duplicate. Description is Atlassian Document Format.
/// Docs: https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/#api-rest-api-3-issue-post
/// </summary>
public sealed class JiraCloudAdapter : TicketAdapterBase
{
    public const string AdapterId = "jira";

    public JiraCloudAdapter(IHttpClientFactory http, ILogger<JiraCloudAdapter> log) : base(http, log) { }

    public override AdapterMetadata Metadata { get; } = new(
        AdapterId, "Jira Cloud", "Atlassian",
        "Raises one Jira issue per Fix today / Fix this week verdict, labelled with the correlation key.",
        Array.Empty<AssetKind>(),
        new[]
        {
            new CredentialField("siteUrl", "Site URL", CredentialTypes.Text, "https://yourcompany.atlassian.net"),
            new CredentialField("email", "Atlassian account email", CredentialTypes.Text, "The account the API token belongs to."),
            new CredentialField("apiToken", "API token", CredentialTypes.Password, "Create one at https://id.atlassian.com/manage-profile/security/api-tokens"),
            new CredentialField("projectKey", "Project key", CredentialTypes.Text, "For example SEC or ITOPS."),
            new CredentialField("issueType", "Issue type", CredentialTypes.Text, "Must exist in the project.", Required: false, Default: "Task"),
            VerifyTlsField
        },
        "A user with Browse Projects and Create Issues in the project; API token from id.atlassian.com.",
        "https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/#api-rest-api-3-issue-post");

    private sealed record Creds(string Site, string Email, string Token, string Project, string IssueType)
    {
        public string Api(string path) => Site + "/rest/api/3/" + path;
    }

    private static Creds Read(IReadOnlyDictionary<string, string> c) => new(
        BaseUrl(Require(c, "siteUrl", "Site URL")), Require(c, "email", "Email"), Require(c, "apiToken", "API token"),
        Require(c, "projectKey", "Project key").ToUpperInvariant(), Get(c, "issueType", "Task"));

    private HttpClient Client(IReadOnlyDictionary<string, string> credentials, Creds c)
    {
        var client = Client(credentials);
        client.DefaultRequestHeaders.Authorization = Basic(c.Email, c.Token);
        return client;
    }

    public override async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        var c = Read(credentials);
        var client = Client(credentials, c);
        var me = await SendJsonAsync(client, JsonRequest(HttpMethod.Get, c.Api("myself")), ct);
        var project = await SendJsonAsync(client, JsonRequest(HttpMethod.Get, c.Api("project/" + Uri.EscapeDataString(c.Project))), ct);
        return new TestResult(true, "Connected as " + (Str(me?["displayName"]) ?? c.Email) + "; project " + (Str(project?["name"]) ?? c.Project) + " (" + c.Project + ") is visible.");
    }

    public override async Task<(string ExternalRef, string? Url)> CreateAsync(IReadOnlyDictionary<string, string> credentials, TicketRequest request, CancellationToken ct)
    {
        var c = Read(credentials);
        var client = Client(credentials, c);
        var label = Tag(request.CorrelationKey);

        // idempotency: an unresolved issue with our label already exists
        var jql = "project = \"" + c.Project + "\" AND labels = \"" + label + "\" AND statusCategory != Done ORDER BY created DESC";
        var found = await SendJsonAsync(client, JsonRequest(HttpMethod.Get, c.Api("search/jql?jql=" + Uri.EscapeDataString(jql) + "&fields=key,status&maxResults=1")), ct);
        if (found?["issues"] is JsonArray issues && issues.Count > 0 && Str(issues[0]?["key"]) is { Length: > 0 } existing)
        {
            Log.LogInformation("Jira issue {Key} already open for {Correlation}", existing, request.CorrelationKey);
            return (existing, c.Site + "/browse/" + existing);
        }

        var priority = Priority(request.Tier, "Highest", "High", "Medium");
        var body = Build(c, request, label, priority);
        JsonNode? created;
        try
        {
            created = await SendJsonAsync(client, JsonRequest(HttpMethod.Post, c.Api("issue"), body), ct);
        }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.BadRequest && ex.Message.Contains("priority", StringComparison.OrdinalIgnoreCase))
        {
            // priority is not on the project's create screen: raise without it rather than fail
            Log.LogWarning("Jira project {Project} does not accept priority on create; retrying without it", c.Project);
            created = await SendJsonAsync(client, JsonRequest(HttpMethod.Post, c.Api("issue"), Build(c, request, label, null)), ct);
        }
        var key = Str(created?["key"]) ?? throw new InvalidOperationException("Jira did not return an issue key");
        return (key, c.Site + "/browse/" + key);
    }

    private static object Build(Creds c, TicketRequest r, string label, string? priority)
    {
        var fields = new Dictionary<string, object?>
        {
            ["project"] = new { key = c.Project },
            ["issuetype"] = new { name = c.IssueType },
            ["summary"] = Prefixed(r),
            ["labels"] = new[] { label },
            ["description"] = Adf(r)
        };
        if (priority is not null) fields["priority"] = new { name = priority };
        return new { fields };
    }

    /// <summary>Atlassian Document Format: one paragraph per blank-line-separated block, the verdict URL as a link.</summary>
    public static object Adf(TicketRequest r)
    {
        var content = new List<object>();
        foreach (var para in r.Body.Replace("\r\n", "\n").Split("\n\n", StringSplitOptions.RemoveEmptyEntries))
            content.Add(new { type = "paragraph", content = new object[] { new { type = "text", text = para.Trim() } } });
        if (!string.IsNullOrWhiteSpace(r.Url))
            content.Add(new
            {
                type = "paragraph",
                content = new object[]
                {
                    new { type = "text", text = "Details and evidence: " },
                    new { type = "text", text = r.Url, marks = new object[] { new { type = "link", attrs = new { href = r.Url } } } }
                }
            });
        content.Add(new { type = "paragraph", content = new object[] { new { type = "text", text = "Correlation key " + r.CorrelationKey + ". Raised automatically by VulnVerdict." } } });
        return new { type = "doc", version = 1, content };
    }

    public override async Task<string?> StatusAsync(IReadOnlyDictionary<string, string> credentials, string externalRef, CancellationToken ct)
    {
        var c = Read(credentials);
        var client = Client(credentials, c);
        var issue = await SendJsonAsync(client, JsonRequest(HttpMethod.Get, c.Api("issue/" + Uri.EscapeDataString(externalRef) + "?fields=status")), ct);
        return Str(issue?["fields"]?["status"]?["name"]);
    }
}
