using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Adapters.Tickets;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Tests;

public class TicketAdapterTests
{
    private const string Key = "VV:CVE-2024-1234:0a1b2c3d";
    private const string ExpectedTag = "vv-cve-2024-1234-0a1b2c3d";
    private const string VerdictUrl = "https://vv.example.com/verdicts/7c9e6679-7425-40de-944b-e07fc1f90ae7";

    private static TicketRequest Req(VerdictTier tier = VerdictTier.FixToday) => new(
        Key, tier.Plain() + ": CVE-2024-1234 on FW-EDGE-01",
        "Fortinet FortiOS 7.2.5 on FW-EDGE-01 is affected by CVE-2024-1234, exploited in the wild.\n\nVerdict: " + tier.Plain() + ", due 26 Sep 2026",
        tier == VerdictTier.FixToday ? "Highest" : "High", VerdictUrl, tier, "CVE-2024-1234");

    private static Dictionary<string, string> Creds(params (string Key, string Value)[] pairs)
    {
        var d = new Dictionary<string, string>();
        foreach (var (k, v) in pairs) d[k] = v;
        return d;
    }

    private static string Base64(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s));

    private static (FakeHandler Handler, FakeHttpClientFactory Factory) Fakes()
    {
        var h = new FakeHandler();
        return (h, new FakeHttpClientFactory(h));
    }

    // ------------------------------------------------------------------ common

    public static IEnumerable<object[]> AllAdapters()
    {
        var (_, f) = Fakes();
        yield return new object[] { new JiraCloudAdapter(f, NullLogger<JiraCloudAdapter>.Instance) };
        yield return new object[] { new ServiceNowAdapter(f, NullLogger<ServiceNowAdapter>.Instance) };
        yield return new object[] { new FreshserviceAdapter(f, NullLogger<FreshserviceAdapter>.Instance) };
        yield return new object[] { new ZendeskAdapter(f, NullLogger<ZendeskAdapter>.Instance) };
        yield return new object[] { new AzureDevOpsAdapter(f, NullLogger<AzureDevOpsAdapter>.Instance) };
        yield return new object[] { new HaloPsaAdapter(f, NullLogger<HaloPsaAdapter>.Instance) };
        yield return new object[] { new AutotaskAdapter(f, NullLogger<AutotaskAdapter>.Instance) };
    }

    [Theory]
    [MemberData(nameof(AllAdapters))]
    public void Every_adapter_is_one_credential_form_with_permission_docs_and_tls_switch(ITicketAdapter adapter)
    {
        var m = adapter.Metadata;
        Assert.False(string.IsNullOrWhiteSpace(m.Id));
        Assert.False(string.IsNullOrWhiteSpace(m.MinimumPermission));
        Assert.StartsWith("https://", m.DocsUrl);
        Assert.Contains(m.Form, f => f.Key == TicketAdapterBase.VerifyTlsKey && f.Type == CredentialTypes.Bool);
        Assert.Contains(m.Form, f => f.Type == CredentialTypes.Password);
        Assert.Equal(m.Form.Length, m.Form.Select(f => f.Key).Distinct().Count());
    }

    [Fact]
    public void Adapter_ids_are_unique_and_match_the_documented_contract()
    {
        var ids = AllAdapters().Select(a => ((ITicketAdapter)a[0]).Metadata.Id).ToList();
        Assert.Equal(new[] { "jira", "servicenow", "freshservice", "zendesk", "azure-devops", "halopsa", "autotask" }, ids);
    }

    [Fact]
    public void Title_prefix_and_tag_and_body_helpers()
    {
        var r = Req();
        Assert.StartsWith("[" + Key + "] Fix today:", TicketAdapterBase.Prefixed(r));
        Assert.Equal(TicketAdapterBase.Prefixed(r), TicketAdapterBase.Prefixed(r with { Title = TicketAdapterBase.Prefixed(r) }));
        Assert.Equal(ExpectedTag, TicketAdapterBase.Tag(Key));
        Assert.Contains(VerdictUrl, TicketAdapterBase.BodyText(r));
        Assert.Contains(Key, TicketAdapterBase.BodyText(r));
        Assert.Contains("href=\"" + VerdictUrl + "\"", TicketAdapterBase.BodyHtml(r));
        Assert.True(TicketAdapterBase.VerifyTls(Creds()));
        Assert.True(TicketAdapterBase.VerifyTls(Creds(("verifyTls", "true"))));
        Assert.False(TicketAdapterBase.VerifyTls(Creds(("verifyTls", "false"))));
    }

    [Fact]
    public async Task VerifyTls_false_uses_the_insecure_client()
    {
        var (h, f) = Fakes();
        h.On(HttpMethod.Get, "/rest/api/3/issue/SEC-1", "{\"fields\":{\"status\":{\"name\":\"Done\"}}}");
        var jira = new JiraCloudAdapter(f, NullLogger<JiraCloudAdapter>.Instance);
        await jira.StatusAsync(JiraCreds(("verifyTls", "false")), "SEC-1", CancellationToken.None);
        Assert.Equal(new[] { TicketAdapterBase.InsecureHttpClientName }, f.Names);
        await jira.StatusAsync(JiraCreds(), "SEC-1", CancellationToken.None);
        Assert.Equal(TicketAdapterBase.HttpClientName, f.Names[1]);
    }

    [Fact]
    public async Task Http_errors_become_readable_messages()
    {
        var (h, f) = Fakes();
        h.On(HttpMethod.Get, "/rest/api/3/myself", "{\"errorMessages\":[\"Client must be authenticated\"]}", HttpStatusCode.Unauthorized);
        var jira = new JiraCloudAdapter(f, NullLogger<JiraCloudAdapter>.Instance);
        var ex = await Assert.ThrowsAsync<HttpRequestException>(() => jira.TestAsync(JiraCreds(), CancellationToken.None));
        Assert.Contains("401", ex.Message);
        Assert.Contains("authentication failed", ex.Message);
    }

    // ------------------------------------------------------------------ Jira

    private static Dictionary<string, string> JiraCreds(params (string, string)[] extra)
    {
        var c = Creds(("siteUrl", "https://acme.atlassian.net/"), ("email", "bob@acme.com"), ("apiToken", "tok123"), ("projectKey", "sec"));
        foreach (var (k, v) in extra) c[k] = v;
        return c;
    }

    [Fact]
    public async Task Jira_searches_by_label_then_creates_with_adf_and_priority()
    {
        var (h, f) = Fakes();
        h.On(HttpMethod.Get, "/rest/api/3/search/jql", "{\"issues\":[]}");
        h.On(HttpMethod.Post, "/rest/api/3/issue", "{\"id\":\"10001\",\"key\":\"SEC-42\"}", HttpStatusCode.Created);
        var jira = new JiraCloudAdapter(f, NullLogger<JiraCloudAdapter>.Instance);

        var (r, url) = await jira.CreateAsync(JiraCreds(), Req(), CancellationToken.None);

        Assert.Equal("SEC-42", r);
        Assert.Equal("https://acme.atlassian.net/browse/SEC-42", url);
        Assert.Equal(2, h.Calls.Count);
        var search = h.Calls[0];
        Assert.Equal(HttpMethod.Get, search.Method);
        Assert.Equal("/rest/api/3/search/jql", search.Path);
        Assert.Contains("project = \"SEC\" AND labels = \"" + ExpectedTag + "\" AND statusCategory != Done", search.DecodedQuery);
        var create = h.Calls[1];
        Assert.Equal("https://acme.atlassian.net/rest/api/3/issue", create.Url.ToString());
        Assert.Equal("Basic", create.Auth!.Scheme);
        Assert.Equal(Base64("bob@acme.com:tok123"), create.Auth.Parameter);
        var fields = create.Json!["fields"]!;
        Assert.StartsWith("[" + Key + "] Fix today: CVE-2024-1234", fields["summary"]!.GetValue<string>());
        Assert.Equal("SEC", fields["project"]!["key"]!.GetValue<string>());
        Assert.Equal("Task", fields["issuetype"]!["name"]!.GetValue<string>());
        Assert.Equal("Highest", fields["priority"]!["name"]!.GetValue<string>());
        Assert.Equal(ExpectedTag, fields["labels"]![0]!.GetValue<string>());
        Assert.Equal("doc", fields["description"]!["type"]!.GetValue<string>());
        Assert.Contains(VerdictUrl, fields["description"]!.ToJsonString());
    }

    [Fact]
    public async Task Jira_fix_this_week_is_high_and_existing_open_issue_is_returned()
    {
        var (h, f) = Fakes();
        h.On(HttpMethod.Get, "/rest/api/3/search/jql", "{\"issues\":[{\"key\":\"SEC-7\",\"fields\":{\"status\":{\"name\":\"To Do\"}}}]}");
        var jira = new JiraCloudAdapter(f, NullLogger<JiraCloudAdapter>.Instance);
        var (r, url) = await jira.CreateAsync(JiraCreds(), Req(VerdictTier.FixThisWeek), CancellationToken.None);
        Assert.Equal("SEC-7", r);
        Assert.Equal("https://acme.atlassian.net/browse/SEC-7", url);
        Assert.Single(h.Calls);

        h.Calls.Clear();
        var (h2, f2) = Fakes();
        h2.On(HttpMethod.Get, "/rest/api/3/search/jql", "{\"issues\":[]}");
        h2.On(HttpMethod.Post, "/rest/api/3/issue", "{\"key\":\"SEC-8\"}", HttpStatusCode.Created);
        await new JiraCloudAdapter(f2, NullLogger<JiraCloudAdapter>.Instance).CreateAsync(JiraCreds(("issueType", "Bug")), Req(VerdictTier.FixThisWeek), CancellationToken.None);
        Assert.Equal("High", h2.Calls[1].Json!["fields"]!["priority"]!["name"]!.GetValue<string>());
        Assert.Equal("Bug", h2.Calls[1].Json!["fields"]!["issuetype"]!["name"]!.GetValue<string>());
    }

    [Fact]
    public async Task Jira_retries_without_priority_when_the_create_screen_rejects_it()
    {
        var (h, f) = Fakes();
        h.On(HttpMethod.Get, "/rest/api/3/search/jql", "{\"issues\":[]}");
        h.On(r => r.Method == HttpMethod.Post, (_, body) => body!.Contains("\"priority\"")
            ? FakeHandler.Json("{\"errors\":{\"priority\":\"Field 'priority' cannot be set. It is not on the appropriate screen, or unknown.\"}}", HttpStatusCode.BadRequest)
            : FakeHandler.Json("{\"key\":\"SEC-9\"}", HttpStatusCode.Created));
        var (r, _) = await new JiraCloudAdapter(f, NullLogger<JiraCloudAdapter>.Instance).CreateAsync(JiraCreds(), Req(), CancellationToken.None);
        Assert.Equal("SEC-9", r);
        Assert.Equal(3, h.Calls.Count);
        Assert.Null(h.Calls[2].Json!["fields"]!["priority"]);
    }

    [Fact]
    public async Task Jira_status_and_test()
    {
        var (h, f) = Fakes();
        h.On(HttpMethod.Get, "/rest/api/3/issue/SEC-42", "{\"key\":\"SEC-42\",\"fields\":{\"status\":{\"name\":\"In Progress\"}}}");
        h.On(HttpMethod.Get, "/rest/api/3/myself", "{\"displayName\":\"Bob\"}");
        h.On(HttpMethod.Get, "/rest/api/3/project/SEC", "{\"key\":\"SEC\",\"name\":\"Security\"}");
        var jira = new JiraCloudAdapter(f, NullLogger<JiraCloudAdapter>.Instance);
        Assert.Equal("In Progress", await jira.StatusAsync(JiraCreds(), "SEC-42", CancellationToken.None));
        Assert.Contains("fields=status", h.Calls[0].Url.Query);
        var t = await jira.TestAsync(JiraCreds(), CancellationToken.None);
        Assert.True(t.Ok);
        Assert.Contains("Bob", t.Message);
        Assert.Contains("Security", t.Message);
    }

    // ------------------------------------------------------------------ ServiceNow

    private static Dictionary<string, string> SnowCreds(params (string, string)[] extra)
    {
        var c = Creds(("instanceUrl", "acme.service-now.com"), ("username", "vv.integration"), ("password", "pw"));
        foreach (var (k, v) in extra) c[k] = v;
        return c;
    }

    [Fact]
    public async Task ServiceNow_searches_correlation_id_then_creates_with_urgency_and_impact()
    {
        var (h, f) = Fakes();
        h.On(r => r.Method == HttpMethod.Get, (_, _) => FakeHandler.Json("{\"result\":[]}"));
        h.On(HttpMethod.Post, "/api/now/table/incident", "{\"result\":{\"sys_id\":\"a1b2c3\",\"number\":\"INC0010001\",\"state\":\"1\"}}", HttpStatusCode.Created);
        var snow = new ServiceNowAdapter(f, NullLogger<ServiceNowAdapter>.Instance);

        var (r, url) = await snow.CreateAsync(SnowCreds(("assignmentGroup", "Security Ops")), Req(), CancellationToken.None);

        Assert.Equal("INC0010001", r);
        Assert.Contains("https://acme.service-now.com/nav_to.do?uri=", url);
        Assert.Contains("sys_id%3Da1b2c3", url);
        var search = h.Calls[0];
        Assert.Equal("/api/now/table/incident", search.Path);
        Assert.Contains("sysparm_query=correlation_id=" + Key + "^active=true", search.DecodedQuery);
        var create = h.Calls[1];
        Assert.Equal("https://acme.service-now.com/api/now/table/incident", create.Url.ToString());
        Assert.Equal(Base64("vv.integration:pw"), create.Auth!.Parameter);
        var j = create.Json!;
        Assert.StartsWith("[" + Key + "]", j["short_description"]!.GetValue<string>());
        Assert.Equal("1", j["urgency"]!.GetValue<string>());
        Assert.Equal("1", j["impact"]!.GetValue<string>());
        Assert.Equal(Key, j["correlation_id"]!.GetValue<string>());
        Assert.Equal("Security Ops", j["assignment_group"]!.GetValue<string>());
        Assert.Contains(VerdictUrl, j["description"]!.GetValue<string>());
    }

    [Fact]
    public async Task ServiceNow_fix_this_week_and_existing_record_and_status()
    {
        var (h, f) = Fakes();
        h.On(r => r.Method == HttpMethod.Get && r.RequestUri!.Query.Contains("correlation_id"), (_, _) => FakeHandler.Json("{\"result\":[{\"sys_id\":\"zz9\",\"number\":\"INC0009\",\"state\":\"In Progress\"}]}"));
        h.On(r => r.Method == HttpMethod.Get && r.RequestUri!.Query.Contains("number%3DINC0009"), (_, _) => FakeHandler.Json("{\"result\":[{\"state\":\"On Hold\"}]}"));
        var snow = new ServiceNowAdapter(f, NullLogger<ServiceNowAdapter>.Instance);
        var (r, _) = await snow.CreateAsync(SnowCreds(("table", "sc_task")), Req(VerdictTier.FixThisWeek), CancellationToken.None);
        Assert.Equal("INC0009", r);
        Assert.Single(h.Calls);
        Assert.Equal("/api/now/table/sc_task", h.Calls[0].Path);

        Assert.Equal("On Hold", await snow.StatusAsync(SnowCreds(), "INC0009", CancellationToken.None));
        Assert.Contains("number=INC0009^ORsys_id=INC0009", h.Calls[1].DecodedQuery);

        var (h2, f2) = Fakes();
        h2.On(HttpMethod.Get, "/api/now/table/incident", "{\"result\":[]}");
        h2.On(HttpMethod.Post, "/api/now/table/incident", "{\"result\":{\"sys_id\":\"s1\",\"number\":\"INC1\"}}", HttpStatusCode.Created);
        await new ServiceNowAdapter(f2, NullLogger<ServiceNowAdapter>.Instance).CreateAsync(SnowCreds(), Req(VerdictTier.FixThisWeek), CancellationToken.None);
        Assert.Equal("2", h2.Calls[1].Json!["urgency"]!.GetValue<string>());
        Assert.Equal("2", h2.Calls[1].Json!["impact"]!.GetValue<string>());
        Assert.Null(h2.Calls[1].Json!["assignment_group"]);
    }

    // ------------------------------------------------------------------ Freshservice

    private static Dictionary<string, string> FreshCreds(params (string, string)[] extra)
    {
        var c = Creds(("domain", "acme.freshservice.com"), ("apiKey", "fskey"), ("requesterEmail", "it-security@acme.com"));
        foreach (var (k, v) in extra) c[k] = v;
        return c;
    }

    [Fact]
    public async Task Freshservice_filters_by_tag_then_creates_with_priority_4()
    {
        var (h, f) = Fakes();
        h.On(HttpMethod.Get, "/api/v2/tickets/filter", "{\"tickets\":[]}");
        h.On(HttpMethod.Post, "/api/v2/tickets", "{\"ticket\":{\"id\":123,\"status\":2}}", HttpStatusCode.Created);
        var fs = new FreshserviceAdapter(f, NullLogger<FreshserviceAdapter>.Instance);

        var (r, url) = await fs.CreateAsync(FreshCreds(("groupId", "17")), Req(), CancellationToken.None);

        Assert.Equal("123", r);
        Assert.Equal("https://acme.freshservice.com/a/tickets/123", url);
        Assert.Equal("/api/v2/tickets/filter", h.Calls[0].Path);
        Assert.Equal("query=\"tag:'" + ExpectedTag + "'\"", h.Calls[0].DecodedQuery);
        var create = h.Calls[1];
        Assert.Equal("https://acme.freshservice.com/api/v2/tickets", create.Url.ToString());
        Assert.Equal(Base64("fskey:X"), create.Auth!.Parameter);
        var j = create.Json!;
        Assert.StartsWith("[" + Key + "]", j["subject"]!.GetValue<string>());
        Assert.Equal(4, j["priority"]!.GetValue<int>());
        Assert.Equal(2, j["status"]!.GetValue<int>());
        Assert.Equal("it-security@acme.com", j["email"]!.GetValue<string>());
        Assert.Equal(17, j["group_id"]!.GetValue<int>());
        Assert.Equal(ExpectedTag, j["tags"]![0]!.GetValue<string>());
        Assert.Contains(VerdictUrl, j["description"]!.GetValue<string>());
    }

    [Fact]
    public async Task Freshservice_ignores_resolved_matches_returns_open_ones_and_parses_status()
    {
        var (h, f) = Fakes();
        h.On(HttpMethod.Get, "/api/v2/tickets/filter", "{\"tickets\":[{\"id\":50,\"status\":4},{\"id\":55,\"status\":3}]}");
        h.On(HttpMethod.Get, "/api/v2/tickets/55", "{\"ticket\":{\"id\":55,\"status\":3}}");
        var fs = new FreshserviceAdapter(f, NullLogger<FreshserviceAdapter>.Instance);
        var (r, _) = await fs.CreateAsync(FreshCreds(), Req(VerdictTier.FixThisWeek), CancellationToken.None);
        Assert.Equal("55", r);
        Assert.Single(h.Calls);
        Assert.Equal("Pending", await fs.StatusAsync(FreshCreds(), "55", CancellationToken.None));

        var (h2, f2) = Fakes();
        h2.On(HttpMethod.Get, "/api/v2/tickets/filter", "{\"tickets\":[{\"id\":50,\"status\":5}]}");
        h2.On(HttpMethod.Post, "/api/v2/tickets", "{\"ticket\":{\"id\":124}}", HttpStatusCode.Created);
        var (r2, _) = await new FreshserviceAdapter(f2, NullLogger<FreshserviceAdapter>.Instance).CreateAsync(FreshCreds(), Req(VerdictTier.FixThisWeek), CancellationToken.None);
        Assert.Equal("124", r2);
        Assert.Equal(3, h2.Calls[1].Json!["priority"]!.GetValue<int>());
        Assert.Null(h2.Calls[1].Json!["group_id"]);
    }

    // ------------------------------------------------------------------ Zendesk

    private static Dictionary<string, string> ZdCreds() => Creds(("subdomain", "acme"), ("email", "agent@acme.com"), ("apiToken", "zdtok"));

    [Fact]
    public async Task Zendesk_searches_by_tag_then_creates_urgent()
    {
        var (h, f) = Fakes();
        h.On(HttpMethod.Get, "/api/v2/search.json", "{\"results\":[]}");
        h.On(HttpMethod.Post, "/api/v2/tickets.json", "{\"ticket\":{\"id\":9001,\"status\":\"new\"}}", HttpStatusCode.Created);
        var zd = new ZendeskAdapter(f, NullLogger<ZendeskAdapter>.Instance);

        var (r, url) = await zd.CreateAsync(ZdCreds(), Req(), CancellationToken.None);

        Assert.Equal("9001", r);
        Assert.Equal("https://acme.zendesk.com/agent/tickets/9001", url);
        Assert.Equal("query=type:ticket tags:" + ExpectedTag + " status<solved", h.Calls[0].DecodedQuery);
        var create = h.Calls[1];
        Assert.Equal("https://acme.zendesk.com/api/v2/tickets.json", create.Url.ToString());
        Assert.Equal(Base64("agent@acme.com/token:zdtok"), create.Auth!.Parameter);
        var t = create.Json!["ticket"]!;
        Assert.StartsWith("[" + Key + "]", t["subject"]!.GetValue<string>());
        Assert.Equal("urgent", t["priority"]!.GetValue<string>());
        Assert.Equal(ExpectedTag, t["tags"]![0]!.GetValue<string>());
        Assert.Contains(VerdictUrl, t["comment"]!["body"]!.GetValue<string>());
    }

    [Fact]
    public async Task Zendesk_fix_this_week_is_high_existing_open_returned_and_status_parsed()
    {
        var (h, f) = Fakes();
        h.On(HttpMethod.Get, "/api/v2/search.json", "{\"results\":[{\"id\":42,\"status\":\"solved\"},{\"id\":43,\"status\":\"pending\"}]}");
        h.On(HttpMethod.Get, "/api/v2/tickets/43.json", "{\"ticket\":{\"id\":43,\"status\":\"hold\"}}");
        var zd = new ZendeskAdapter(f, NullLogger<ZendeskAdapter>.Instance);
        var (r, _) = await zd.CreateAsync(ZdCreds(), Req(VerdictTier.FixThisWeek), CancellationToken.None);
        Assert.Equal("43", r);
        Assert.Single(h.Calls);
        Assert.Equal("hold", await zd.StatusAsync(ZdCreds(), "43", CancellationToken.None));

        var (h2, f2) = Fakes();
        h2.On(HttpMethod.Get, "/api/v2/search.json", "{\"results\":[]}");
        h2.On(HttpMethod.Post, "/api/v2/tickets.json", "{\"ticket\":{\"id\":9002}}", HttpStatusCode.Created);
        await new ZendeskAdapter(f2, NullLogger<ZendeskAdapter>.Instance).CreateAsync(ZdCreds(), Req(VerdictTier.FixThisWeek), CancellationToken.None);
        Assert.Equal("high", h2.Calls[1].Json!["ticket"]!["priority"]!.GetValue<string>());
    }

    [Fact]
    public async Task Zendesk_test_rejects_end_users()
    {
        var (h, f) = Fakes();
        h.On(HttpMethod.Get, "/api/v2/users/me.json", "{\"user\":{\"name\":\"Bob\",\"role\":\"end-user\"}}");
        var t = await new ZendeskAdapter(f, NullLogger<ZendeskAdapter>.Instance).TestAsync(ZdCreds(), CancellationToken.None);
        Assert.False(t.Ok);
        Assert.Contains("not an agent", t.Message);
    }

    // ------------------------------------------------------------------ Azure DevOps

    private static Dictionary<string, string> AdoCreds(params (string, string)[] extra)
    {
        var c = Creds(("organisationUrl", "https://dev.azure.com/acme"), ("project", "Security"), ("pat", "patsecret"));
        foreach (var (k, v) in extra) c[k] = v;
        return c;
    }

    [Fact]
    public async Task AzureDevOps_runs_wiql_then_posts_json_patch()
    {
        var (h, f) = Fakes();
        h.On(HttpMethod.Post, "/_apis/wit/wiql", "{\"workItems\":[]}");
        h.On(HttpMethod.Post, "/_apis/wit/workitems/$Issue", "{\"id\":77,\"fields\":{\"System.State\":\"To Do\"},\"_links\":{\"html\":{\"href\":\"https://dev.azure.com/acme/Security/_workitems/edit/77\"}}}");
        var ado = new AzureDevOpsAdapter(f, NullLogger<AzureDevOpsAdapter>.Instance);

        var (r, url) = await ado.CreateAsync(AdoCreds(), Req(), CancellationToken.None);

        Assert.Equal("77", r);
        Assert.Equal("https://dev.azure.com/acme/Security/_workitems/edit/77", url);
        var wiql = h.Calls[0];
        Assert.Equal("https://dev.azure.com/acme/Security/_apis/wit/wiql?api-version=7.1", wiql.Url.ToString());
        var q = wiql.Json!["query"]!.GetValue<string>();
        Assert.Contains("[System.Tags] CONTAINS '" + ExpectedTag + "'", q);
        Assert.Contains("[System.State] NOT IN", q);
        var create = h.Calls[1];
        Assert.Equal("https://dev.azure.com/acme/Security/_apis/wit/workitems/$Issue?api-version=7.1", create.Url.ToString());
        Assert.Equal("application/json-patch+json", create.ContentType);
        Assert.Equal(Base64(":patsecret"), create.Auth!.Parameter);
        var ops = create.Json!.AsArray().ToDictionary(o => o!["path"]!.GetValue<string>(), o => o!);
        Assert.All(ops.Values, o => Assert.Equal("add", o["op"]!.GetValue<string>()));
        Assert.StartsWith("[" + Key + "]", ops["/fields/System.Title"]["value"]!.GetValue<string>());
        Assert.Equal(1, ops["/fields/Microsoft.VSTS.Common.Priority"]["value"]!.GetValue<int>());
        Assert.Equal(ExpectedTag, ops["/fields/System.Tags"]["value"]!.GetValue<string>());
        Assert.Contains(VerdictUrl, ops["/fields/System.Description"]["value"]!.GetValue<string>());
    }

    [Fact]
    public async Task AzureDevOps_existing_item_priority_2_and_state()
    {
        var (h, f) = Fakes();
        h.On(HttpMethod.Post, "/_apis/wit/wiql", "{\"workItems\":[{\"id\":70,\"url\":\"https://dev.azure.com/acme/_apis/wit/workItems/70\"}]}");
        h.On(HttpMethod.Get, "/_apis/wit/workitems/70", "{\"id\":70,\"fields\":{\"System.State\":\"Active\"}}");
        var ado = new AzureDevOpsAdapter(f, NullLogger<AzureDevOpsAdapter>.Instance);
        var (r, url) = await ado.CreateAsync(AdoCreds(), Req(VerdictTier.FixThisWeek), CancellationToken.None);
        Assert.Equal("70", r);
        Assert.Equal("https://dev.azure.com/acme/Security/_workitems/edit/70", url);
        Assert.Single(h.Calls);
        Assert.Equal("Active", await ado.StatusAsync(AdoCreds(), "70", CancellationToken.None));
        Assert.Contains("fields=System.State", h.Calls[1].Url.Query);
        Assert.Contains("api-version=7.1", h.Calls[1].Url.Query);

        var (h2, f2) = Fakes();
        h2.On(HttpMethod.Post, "/_apis/wit/wiql", "{\"workItems\":[]}");
        h2.On(HttpMethod.Post, "/_apis/wit/workitems/$Task", "{\"id\":78}");
        var (r2, url2) = await new AzureDevOpsAdapter(f2, NullLogger<AzureDevOpsAdapter>.Instance).CreateAsync(AdoCreds(("workItemType", "Task")), Req(VerdictTier.FixThisWeek), CancellationToken.None);
        Assert.Equal("78", r2);
        Assert.Equal("https://dev.azure.com/acme/Security/_workitems/edit/78", url2);
        var ops = h2.Calls[1].Json!.AsArray().ToDictionary(o => o!["path"]!.GetValue<string>(), o => o!);
        Assert.Equal(2, ops["/fields/Microsoft.VSTS.Common.Priority"]["value"]!.GetValue<int>());
    }

    // ------------------------------------------------------------------ HaloPSA

    private static Dictionary<string, string> HaloCreds(params (string, string)[] extra)
    {
        var c = Creds(("baseUrl", "https://acme.halopsa.com"), ("clientId", "cid"), ("clientSecret", "csecret"), ("ticketTypeId", "12"));
        foreach (var (k, v) in extra) c[k] = v;
        return c;
    }

    [Fact]
    public async Task Halo_gets_a_token_searches_then_posts_an_array_of_one()
    {
        var (h, f) = Fakes();
        h.On(HttpMethod.Post, "/auth/token", "{\"access_token\":\"bearer123\",\"token_type\":\"Bearer\"}");
        h.On(HttpMethod.Get, "/api/Tickets?search=", "{\"record_count\":0,\"tickets\":[]}");
        h.On(HttpMethod.Post, "/api/Tickets", "{\"id\":501,\"summary\":\"x\"}", HttpStatusCode.Created);
        var halo = new HaloPsaAdapter(f, NullLogger<HaloPsaAdapter>.Instance);

        var (r, url) = await halo.CreateAsync(HaloCreds(("customerId", "3"), ("tenant", "acme")), Req(), CancellationToken.None);

        Assert.Equal("501", r);
        Assert.Equal("https://acme.halopsa.com/tickets?id=501", url);
        var token = h.Calls[0];
        Assert.Equal("https://acme.halopsa.com/auth/token?tenant=acme", token.Url.ToString());
        Assert.Equal("application/x-www-form-urlencoded", token.ContentType);
        Assert.Contains("grant_type=client_credentials", token.Body);
        Assert.Contains("client_id=cid", token.Body);
        Assert.Contains("client_secret=csecret", token.Body);
        Assert.Contains("scope=all", token.Body);
        var search = h.Calls[1];
        Assert.Equal("Bearer", search.Auth!.Scheme);
        Assert.Equal("bearer123", search.Auth.Parameter);
        Assert.Contains("search=" + Key, search.DecodedQuery);
        Assert.Contains("open_only=true", search.DecodedQuery);
        var create = h.Calls[2];
        Assert.Equal("https://acme.halopsa.com/api/Tickets", create.Url.ToString());
        var arr = create.Json!.AsArray();
        Assert.Single(arr);
        var t = arr[0]!;
        Assert.StartsWith("[" + Key + "]", t["summary"]!.GetValue<string>());
        Assert.Equal(12, t["tickettype_id"]!.GetValue<int>());
        Assert.Equal(1, t["priority_id"]!.GetValue<int>());
        Assert.Equal(3, t["client_id"]!.GetValue<int>());
        Assert.Contains(VerdictUrl, t["details"]!.GetValue<string>());
    }

    [Fact]
    public async Task Halo_existing_open_ticket_priority_2_and_status_name_lookup()
    {
        var (h, f) = Fakes();
        h.On(HttpMethod.Post, "/auth/token", "{\"access_token\":\"tok\"}");
        h.On(HttpMethod.Get, "/api/Tickets?search=", "{\"tickets\":[{\"id\":400,\"summary\":\"[" + Key + "] Fix this week: CVE-2024-1234\",\"status_id\":2}]}");
        h.On(HttpMethod.Get, "/api/Tickets/400", "{\"id\":400,\"status_id\":2}");
        h.On(HttpMethod.Get, "/api/Status", "[{\"id\":1,\"name\":\"New\"},{\"id\":2,\"name\":\"In Progress\"}]");
        var halo = new HaloPsaAdapter(f, NullLogger<HaloPsaAdapter>.Instance);
        var (r, _) = await halo.CreateAsync(HaloCreds(), Req(VerdictTier.FixThisWeek), CancellationToken.None);
        Assert.Equal("400", r);
        Assert.Equal(2, h.Calls.Count);
        Assert.Equal("In Progress", await halo.StatusAsync(HaloCreds(), "400", CancellationToken.None));
        Assert.Equal("https://acme.halopsa.com/auth/token", h.Calls[2].Url.ToString());

        var (h2, f2) = Fakes();
        h2.On(HttpMethod.Post, "/auth/token", "{\"access_token\":\"tok\"}");
        h2.On(HttpMethod.Get, "/api/Tickets?search=", "{\"tickets\":[]}");
        h2.On(HttpMethod.Post, "/api/Tickets", "[{\"id\":502}]", HttpStatusCode.Created);
        var (r2, _) = await new HaloPsaAdapter(f2, NullLogger<HaloPsaAdapter>.Instance).CreateAsync(HaloCreds(), Req(VerdictTier.FixThisWeek), CancellationToken.None);
        Assert.Equal("502", r2);
        Assert.Equal(2, h2.Calls[2].Json!.AsArray()[0]!["priority_id"]!.GetValue<int>());
        Assert.Null(h2.Calls[2].Json!.AsArray()[0]!["client_id"]);
    }

    // ------------------------------------------------------------------ Autotask

    private static Dictionary<string, string> AtCreds(params (string, string)[] extra)
    {
        var c = Creds(("zoneUrl", "https://webservices5.autotask.net/ATServicesRest/V1.0/"), ("apiIntegrationCode", "INTCODE"), ("username", "api@acme.com"), ("secret", "atsecret"), ("companyId", "10"));
        foreach (var (k, v) in extra) c[k] = v;
        return c;
    }

    [Fact]
    public async Task Autotask_queries_by_title_then_creates_with_headers_and_company()
    {
        var (h, f) = Fakes();
        h.On(HttpMethod.Post, "/ATServicesRest/V1.0/Tickets/query", "{\"items\":[],\"pageDetails\":{\"count\":0}}");
        h.On(HttpMethod.Post, "/ATServicesRest/V1.0/Tickets", "{\"itemId\":8001}");
        var at = new AutotaskAdapter(f, NullLogger<AutotaskAdapter>.Instance);

        var (r, url) = await at.CreateAsync(AtCreds(("queueId", "5")), Req(), CancellationToken.None);

        Assert.Equal("8001", r);
        Assert.Equal("https://ww5.autotask.net/Mvc/ServiceDesk/TicketDetail.mvc?workspace=False&mode=0&ticketId=8001", url);
        var query = h.Calls[0];
        Assert.Equal("https://webservices5.autotask.net/ATServicesRest/V1.0/Tickets/query", query.Url.ToString());
        Assert.Equal("INTCODE", query.Header("ApiIntegrationCode"));
        Assert.Equal("api@acme.com", query.Header("UserName"));
        Assert.Equal("atsecret", query.Header("Secret"));
        var filter = query.Json!["filter"]!.AsArray();
        Assert.Equal("title", filter[0]!["field"]!.GetValue<string>());
        Assert.Equal("contains", filter[0]!["op"]!.GetValue<string>());
        Assert.Equal(Key, filter[0]!["value"]!.GetValue<string>());
        var create = h.Calls[1];
        Assert.Equal("https://webservices5.autotask.net/ATServicesRest/V1.0/Tickets", create.Url.ToString());
        var j = create.Json!;
        Assert.StartsWith("[" + Key + "]", j["title"]!.GetValue<string>());
        Assert.Equal(1, j["status"]!.GetValue<int>());
        Assert.Equal(1, j["priority"]!.GetValue<int>());
        Assert.Equal(10, j["companyID"]!.GetValue<int>());
        Assert.Equal(5, j["queueID"]!.GetValue<int>());
        Assert.NotNull(j["dueDateTime"]);
        Assert.Contains(VerdictUrl, j["description"]!.GetValue<string>());
    }

    [Fact]
    public async Task Autotask_existing_ticket_priority_2_and_status_names()
    {
        var (h, f) = Fakes();
        h.On(HttpMethod.Post, "/Tickets/query", "{\"items\":[{\"id\":7000,\"status\":8}]}");
        h.On(HttpMethod.Get, "/Tickets/7000", "{\"item\":{\"id\":7000,\"status\":8}}");
        var at = new AutotaskAdapter(f, NullLogger<AutotaskAdapter>.Instance);
        var (r, _) = await at.CreateAsync(AtCreds(("zoneUrl", "webservices2.autotask.net")), Req(VerdictTier.FixThisWeek), CancellationToken.None);
        Assert.Equal("7000", r);
        Assert.Single(h.Calls);
        Assert.Equal("https://webservices2.autotask.net/ATServicesRest/V1.0/Tickets/query", h.Calls[0].Url.ToString());
        Assert.Equal("In Progress", await at.StatusAsync(AtCreds(), "7000", CancellationToken.None));
        Assert.Equal("Complete", AutotaskAdapter.StatusText(5));
        Assert.Equal("status 99", AutotaskAdapter.StatusText(99));

        var (h2, f2) = Fakes();
        h2.On(HttpMethod.Post, "/Tickets/query", "{\"items\":[]}");
        h2.On(HttpMethod.Post, "/Tickets", "{\"itemId\":8002}");
        await new AutotaskAdapter(f2, NullLogger<AutotaskAdapter>.Instance).CreateAsync(AtCreds(), Req(VerdictTier.FixThisWeek), CancellationToken.None);
        Assert.Equal(2, h2.Calls[1].Json!["priority"]!.GetValue<int>());
        Assert.Null(h2.Calls[1].Json!["queueID"]);
    }
}
