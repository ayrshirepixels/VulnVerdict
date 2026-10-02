using System.Net;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

/// <summary>Teams and Slack messages: the wire formats, what is left out of them, when they are not sent at all.</summary>
public class ChatNotificationTests : IDisposable
{
    private const string TeamsUrl = "https://prod-12.westeurope.logic.azure.com/workflows/abc123/triggers/manual/paths/invoke?sig=TEAMS-SECRET";
    private const string SlackUrl = "https://hooks.slack.com/services/T000/B000/SLACK-SECRET";

    private readonly NotificationFixture _fx = new();

    public ChatNotificationTests()
    {
        _fx.Http.On(r => r.RequestUri!.Host.EndsWith("logic.azure.com"), (_, _) => new HttpResponseMessage(HttpStatusCode.Accepted));
        _fx.Http.On(r => r.RequestUri!.Host == "hooks.slack.com", (_, _) => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("ok") });
    }

    public void Dispose() => _fx.Dispose();

    private Task TeamsAsync(Action<AppSettings>? change = null) => _fx.ConfigureAsync(s => { s.TeamsWebhookUrl = TeamsUrl; change?.Invoke(s); });
    private Task SlackAsync(Action<AppSettings>? change = null) => _fx.ConfigureAsync(s => { s.SlackWebhookUrl = SlackUrl; change?.Invoke(s); });

    private async Task<FakeHandler.Call> SendOneAsync(params (string Event, Guid VerdictId)[] events)
    {
        var svc = _fx.Outbox();
        await _fx.EnqueueAsync(svc, events);
        Assert.Empty(await svc.FlushPendingAsync(CancellationToken.None));
        return Assert.Single(_fx.Http.Calls);
    }

    private static void AssertJson(string expected, string? actual) =>
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(expected), JsonNode.Parse(actual!)), "Expected:\n" + expected + "\nActual:\n" + JsonNode.Parse(actual!)!.ToJsonString(new() { WriteIndented = true }));

    // ------------------------------------------------------------------ wire formats

    [Fact]
    public async Task Teams_message_is_a_workflows_adaptive_card()
    {
        await TeamsAsync();
        var v = _fx.AddVerdict();

        var call = await SendOneAsync((WebhookService.EventCreated, v.Id));

        Assert.Equal(TeamsUrl, call.Url.ToString());
        Assert.Equal("application/json", call.ContentType);
        AssertJson($$"""
            {
              "type": "message",
              "attachments": [
                {
                  "contentType": "application/vnd.microsoft.card.adaptive",
                  "contentUrl": null,
                  "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                      { "type": "TextBlock", "text": "Fix today: CVE-2024-1234", "weight": "Bolder", "size": "Medium", "wrap": true, "color": "Attention" },
                      { "type": "TextBlock", "text": "Exploited in the wild, works over the network with no login, reachable from the internet. Fixed in 7.2.8.", "wrap": true },
                      { "type": "FactSet", "facts": [
                          { "title": "Product", "value": "Fortinet FortiOS 7.2.5" },
                          { "title": "Verdict", "value": "Fix today" },
                          { "title": "Fix by", "value": "26 Sep 2026" },
                          { "title": "Affected assets", "value": "1" }
                      ] }
                    ],
                    "actions": [ { "type": "Action.OpenUrl", "title": "Open in VulnVerdict", "url": "https://vv.example.com/verdicts/{{v.Id}}" } ]
                  }
                }
              ]
            }
            """, call.Body);
    }

    [Fact]
    public async Task Slack_message_is_block_kit_with_a_plain_text_fallback()
    {
        await SlackAsync();
        var v = _fx.AddVerdict();

        var call = await SendOneAsync((WebhookService.EventCreated, v.Id));

        Assert.Equal(SlackUrl, call.Url.ToString());
        AssertJson($$"""
            {
              "text": "Fix today: CVE-2024-1234 - Exploited in the wild, works over the network with no login, reachable from the internet. Fixed in 7.2.8.",
              "blocks": [
                { "type": "header", "text": { "type": "plain_text", "text": "Fix today: CVE-2024-1234", "emoji": false } },
                { "type": "section", "text": { "type": "mrkdwn", "text": "Exploited in the wild, works over the network with no login, reachable from the internet. Fixed in 7.2.8." } },
                { "type": "section", "fields": [
                    { "type": "mrkdwn", "text": "*Product*\nFortinet FortiOS 7.2.5" },
                    { "type": "mrkdwn", "text": "*Verdict*\nFix today" },
                    { "type": "mrkdwn", "text": "*Fix by*\n26 Sep 2026" },
                    { "type": "mrkdwn", "text": "*Affected assets*\n1" }
                ] },
                { "type": "section", "text": { "type": "mrkdwn", "text": "<https://vv.example.com/verdicts/{{v.Id}}|Open in VulnVerdict>" } }
              ]
            }
            """, call.Body);
    }

    [Fact]
    public void Slack_text_is_escaped_and_no_link_is_sent_without_a_console_address()
    {
        var card = new ChatCard { Title = "A <b> & c", Text = "x < y & z > w", Facts = { new("Name", "<!channel>") } };
        var j = JsonNode.Parse(ChatMessages.BuildSlack(card))!;
        Assert.Equal("A <b> & c", j["blocks"]![0]!["text"]!["text"]!.GetValue<string>());   // plain_text is literal
        Assert.Equal("x &lt; y &amp; z &gt; w", j["blocks"]![1]!["text"]!["text"]!.GetValue<string>());
        Assert.Equal("*Name*\n&lt;!channel&gt;", j["blocks"]![2]!["fields"]![0]!["text"]!.GetValue<string>());
        Assert.Equal(3, j["blocks"]!.AsArray().Count);

        var teams = JsonNode.Parse(ChatMessages.BuildTeams(card))!["attachments"]![0]!["content"]!;
        Assert.Null(teams["actions"]);
        Assert.Equal("Default", teams["body"]![0]!["color"]!.GetValue<string>());
    }

    // ------------------------------------------------------------------ what stays on the box

    [Fact]
    public async Task Asset_names_are_left_out_by_default_and_one_cve_is_one_message()
    {
        await TeamsAsync(s => s.SlackWebhookUrl = SlackUrl);
        var a = _fx.AddVerdict(asset: "FW-EDGE-01");
        var b = _fx.AddVerdict(asset: "FW-BRANCH-07");
        // a compensating control is described in its owner's words, which can name a host
        var c = _fx.AddVerdict(asset: "FW-DR-02", change: v => v.Sentence = v.Subject + ": exploited in the wild, works over the network with no login, reachable from the internet. Fixed in 7.2.8. Lowered one step because WAF in front (waf01.corp.local fronts FW-DR-02).");

        var svc = _fx.Outbox();
        await _fx.EnqueueAsync(svc, (WebhookService.EventCreated, a.Id), (WebhookService.EventCreated, b.Id), (WebhookService.EventCreated, c.Id));
        await svc.FlushPendingAsync(CancellationToken.None);

        Assert.Equal(2, _fx.Http.Calls.Count);   // one to Teams, one to Slack, not one per asset
        foreach (var call in _fx.Http.Calls)
        {
            Assert.DoesNotContain("FW-EDGE-01", call.Body);
            Assert.DoesNotContain("FW-BRANCH-07", call.Body);
            Assert.DoesNotContain("FW-DR-02", call.Body);
            Assert.DoesNotContain("waf01", call.Body);
            Assert.DoesNotContain("Assets", call.Body!.Replace("Affected assets", ""));
            Assert.Contains("Fortinet FortiOS 7.2.5", call.Body);
        }
        var facts = _fx.Http.Calls.Single(x => x.Url.Host.EndsWith("logic.azure.com")).Json!["attachments"]![0]!["content"]!["body"]![2]!["facts"]!.AsArray();
        Assert.Equal("3", facts.Single(f => f!["title"]!.GetValue<string>() == "Affected assets")!["value"]!.GetValue<string>());
        // nothing identifying is kept in the queue either
        Assert.All(_fx.OutboxRows(), r => { Assert.DoesNotContain("FW-", r.PayloadJson); Assert.NotNull(r.DeliveredAt); });
    }

    [Fact]
    public async Task Compensating_control_wording_is_replaced()
    {
        await TeamsAsync();
        var v = _fx.AddVerdict(asset: "FW-DR-02", change: x => x.Sentence = x.Subject + ": public exploit code exists, works over the network with no login, reachable from the internet. Fixed in 7.2.8. Lowered one step because WAF in front (waf01.corp.local).");
        var call = await SendOneAsync((WebhookService.EventCreated, v.Id));
        var text = call.Json!["attachments"]![0]!["content"]!["body"]![1]!["text"]!.GetValue<string>();
        Assert.Equal("Public exploit code exists, works over the network with no login, reachable from the internet. Fixed in 7.2.8. Lowered one step by a compensating control.", text);
    }

    [Fact]
    public async Task An_explanation_that_still_names_an_asset_is_dropped()
    {
        await TeamsAsync();
        // a sentence that does not open with the subject, so the asset name cannot be cut off the front
        var v = _fx.AddVerdict(change: x => x.Sentence = "Affected: FW-EDGE-01 runs a vulnerable FortiOS.");
        var call = await SendOneAsync((WebhookService.EventCreated, v.Id));
        Assert.DoesNotContain("FW-EDGE-01", call.Body);
        Assert.Contains("Open the verdict for the details.", call.Body);
    }

    [Fact]
    public async Task Asset_names_are_included_when_switched_on()
    {
        await TeamsAsync(s => s.ChatIncludeAssetNames = true);
        var a = _fx.AddVerdict(asset: "FW-EDGE-01");
        var b = _fx.AddVerdict(asset: "FW-BRANCH-07");

        var call = await SendOneAsync((WebhookService.EventCreated, a.Id), (WebhookService.EventCreated, b.Id));

        var facts = call.Json!["attachments"]![0]!["content"]!["body"]![2]!["facts"]!.AsArray();
        Assert.Equal("FW-BRANCH-07, FW-EDGE-01", facts.Single(f => f!["title"]!.GetValue<string>() == "Assets")!["value"]!.GetValue<string>());
        Assert.Equal("2", facts.Single(f => f!["title"]!.GetValue<string>() == "Affected assets")!["value"]!.GetValue<string>());
    }

    [Fact]
    public async Task The_webhook_address_is_never_stored_with_a_message_or_its_error()
    {
        var failing = new NotificationFixture();
        try
        {
            failing.Http.On(r => true, (r, _) => throw new HttpRequestException("No such host is known. (" + r.RequestUri!.Host + ":443)"));
            await failing.ConfigureAsync(s => s.TeamsWebhookUrl = TeamsUrl);
            var v = failing.AddVerdict();
            var svc = failing.Outbox(TimeSpan.FromMinutes(1));
            svc.MaxAttempts = 1;
            await failing.EnqueueAsync(svc, (WebhookService.EventCreated, v.Id));
            var gaveUp = Assert.Single(await svc.FlushPendingAsync(CancellationToken.None));

            var row = Assert.Single(failing.OutboxRows());
            Assert.NotNull(row.FailedAt);
            foreach (var text in new[] { row.PayloadJson, row.LastError!, gaveUp })
            {
                Assert.DoesNotContain("TEAMS-SECRET", text);
                Assert.DoesNotContain("abc123", text);
            }
            var notice = Assert.Single(await WebhookService.FailureNoticesAsync(failing.Factory));
            Assert.Contains("Teams messages are not being delivered", notice.Text);
            Assert.DoesNotContain("TEAMS-SECRET", notice.Text);
            // and the settings row is encrypted at rest
            await using var db = await failing.Factory.CreateDbContextAsync();
            var stored = await db.Settings.AsNoTracking().FirstAsync(x => x.Key == nameof(AppSettings.TeamsWebhookUrl));
            Assert.True(stored.Encrypted);
            Assert.DoesNotContain("TEAMS-SECRET", stored.Value);
            Assert.Contains(nameof(AppSettings.TeamsWebhookUrl), SettingsService.SecretNames);
            Assert.Contains(nameof(AppSettings.SlackWebhookUrl), SettingsService.SecretNames);
        }
        finally { failing.Dispose(); }
    }

    // ------------------------------------------------------------------ when nothing is sent

    [Fact]
    public async Task Air_gap_mode_sends_nothing()
    {
        await TeamsAsync(s => s.SlackWebhookUrl = SlackUrl);
        var v = _fx.AddVerdict();
        var svc = _fx.Outbox();
        var chat = new ChatNotificationService(_fx.Factory, _fx.Settings, svc);
        Assert.False(await chat.IsAirGappedAsync());
        await _fx.EnqueueAsync(svc, (WebhookService.EventCreated, v.Id));
        Assert.Equal(2, _fx.OutboxRows().Count);

        // a bundle carried in by hand, no central service: the site has no route out by choice
        await using (var db = await _fx.Factory.CreateDbContextAsync())
        {
            db.Bundles.Add(new BundleState { Version = "2026.10.01", BuiltAt = DateTime.UtcNow, AppliedAt = DateTime.UtcNow, Source = "upload by admin" });
            await db.SaveChangesAsync();
        }
        Assert.True(await chat.IsAirGappedAsync());

        Assert.Empty(await svc.FlushPendingAsync(CancellationToken.None));
        Assert.Empty(_fx.Http.Calls);
        Assert.Empty(_fx.OutboxRows());   // dropped, not left to go out days later

        Assert.Contains("air-gap", await chat.SendTestAsync(WebhookService.KindTeams));
        Assert.Empty(_fx.Http.Calls);
        Assert.Empty(_fx.OutboxRows());

        // fed by the central service instead: there is a route out, so messages go
        await _fx.ConfigureAsync(s => s.BundleUrl = "https://central.example.com");
        Assert.False(await chat.IsAirGappedAsync());
        Assert.Null(await chat.SendTestAsync(WebhookService.KindSlack));
        Assert.Single(_fx.Http.Calls);
    }

    [Fact]
    public async Task Only_the_events_switched_on_are_queued()
    {
        await TeamsAsync(s => { s.ChatNotifyFixToday = false; s.ChatNotifyChanges = false; });
        var today = _fx.AddVerdict();
        var svc = _fx.Outbox();
        Assert.Empty(await _fx.EnqueueAsync(svc, (WebhookService.EventCreated, today.Id), (WebhookService.EventPromoted, today.Id)));

        await TeamsAsync(s => { s.ChatNotifyFixToday = true; s.ChatNotifyChanges = true; });
        var week = _fx.AddVerdict(cve: "CVE-2024-2000", tier: VerdictTier.FixThisWeek);
        var cycle = _fx.AddVerdict(cve: "CVE-2024-3000", tier: VerdictTier.NextPatchCycle);
        var unsure = _fx.AddVerdict(cve: "CVE-2024-4000", change: v => v.Confidence = MatchConfidence.Possible);
        var rows = await _fx.EnqueueAsync(svc,
            (WebhookService.EventCreated, today.Id),      // a new Fix today
            (WebhookService.EventCreated, week.Id),       // new, but not Fix today: the digest covers it
            (WebhookService.EventPromoted, week.Id),      // promoted to Fix this week
            (WebhookService.EventPromoted, cycle.Id),     // promoted, but below Fix this week
            (WebhookService.EventCreated, unsure.Id),     // "check these" are never announced
            (WebhookService.EventClosed, today.Id));
        Assert.Equal(new[] { ChatMessages.EventFixToday, ChatMessages.EventChanged }, rows.Select(r => r.Event));
        Assert.All(rows, r => Assert.Equal(WebhookService.KindTeams, r.Kind));
    }

    [Fact]
    public async Task A_re_open_says_why()
    {
        await SlackAsync();
        var v = _fx.AddVerdict(tier: VerdictTier.FixThisWeek, change: x => x.TierChangeReason = "re-opened: now in CISA KEV");
        var call = await SendOneAsync((WebhookService.EventPromoted, v.Id));
        Assert.Equal("Re-opened as Fix this week: CVE-2024-1234", call.Json!["blocks"]![0]!["text"]!["text"]!.GetValue<string>());
        Assert.Contains("*Why now*\\nre-opened: now in CISA KEV", call.Body);
    }

    [Fact]
    public async Task A_verdict_closed_before_the_message_goes_is_not_announced()
    {
        await TeamsAsync();
        var v = _fx.AddVerdict();
        var svc = _fx.Outbox();
        await _fx.EnqueueAsync(svc, (WebhookService.EventCreated, v.Id));
        await _fx.Workflow(svc).CloseAsync(v.Id, "tester", "patched");

        await svc.FlushPendingAsync(CancellationToken.None);
        Assert.Empty(_fx.Http.Calls);
        Assert.Empty(_fx.OutboxRows());
    }

    [Fact]
    public async Task A_failed_message_is_retried_from_the_outbox_by_another_instance()
    {
        await TeamsAsync();
        var up = false;
        var other = new FakeHandler().On(r => true, (_, _) => up ? new HttpResponseMessage(HttpStatusCode.Accepted) : new HttpResponseMessage(HttpStatusCode.TooManyRequests) { Headers = { { "Retry-After", "600" } } });
        var v = _fx.AddVerdict();
        WebhookService Instance() => new(_fx.Factory, _fx.Settings, new FakeHttpClientFactory(other), NullLogger<WebhookService>.Instance) { RetryDelay = TimeSpan.FromSeconds(30) };

        var first = Instance();
        await _fx.EnqueueAsync(first, (WebhookService.EventCreated, v.Id));
        await first.FlushPendingAsync(CancellationToken.None);
        var row = Assert.Single(_fx.OutboxRows());
        Assert.Contains("HTTP 429", row.LastError);
        // the receiver asked for ten minutes, which is longer than the backoff
        Assert.InRange(row.NextAttemptAt - DateTime.UtcNow, TimeSpan.FromMinutes(9), TimeSpan.FromMinutes(10.1));

        up = true;
        _fx.MakeDue();
        await Instance().FlushPendingAsync(CancellationToken.None);
        row = Assert.Single(_fx.OutboxRows());
        Assert.NotNull(row.DeliveredAt);
        Assert.Equal(2, row.Attempts);
        Assert.Equal(2, other.Calls.Count);
    }

    // ------------------------------------------------------------------ test button, digest, feed health

    [Fact]
    public async Task Test_button_sends_now_and_does_not_retry_a_failure()
    {
        await TeamsAsync();
        var chat = new ChatNotificationService(_fx.Factory, _fx.Settings, _fx.Outbox());
        Assert.Equal("Enter the webhook address first.", await chat.SendTestAsync(WebhookService.KindSlack));

        Assert.Null(await chat.SendTestAsync(WebhookService.KindTeams));
        var call = Assert.Single(_fx.Http.Calls);
        Assert.Equal("VulnVerdict test message", call.Json!["attachments"]![0]!["content"]!["body"]![0]!["text"]!.GetValue<string>());

        await _fx.ConfigureAsync(s => s.SlackWebhookUrl = "https://hooks.slack.invalid/services/nope");
        var problem = await chat.SendTestAsync(WebhookService.KindSlack);
        Assert.Contains("HTTP 404", problem);
        Assert.DoesNotContain(_fx.OutboxRows(), r => r.Kind == WebhookService.KindSlack);

        await _fx.ConfigureAsync(s => s.SlackWebhookUrl = "http://hooks.slack.com/services/plain");
        Assert.Equal("The webhook address must start with https://", await chat.SendTestAsync(WebhookService.KindSlack));
    }

    [Fact]
    public async Task Daily_digest_queues_a_summary_without_asset_names()
    {
        await _fx.ConfigureMailAsync(s => s.SlackWebhookUrl = SlackUrl);
        _fx.Http.On(HttpMethod.Post, "/v3/mail/send", "");
        _fx.AddVerdict();
        _fx.AddVerdict(cve: "CVE-2024-2000", asset: "SRV-FILE-01", tier: VerdictTier.FixThisWeek);

        var run = await _fx.Digest().SendDigestAsync(DigestKind.Daily);
        Assert.NotNull(run.SentAt);
        var row = Assert.Single(_fx.OutboxRows());
        Assert.Equal(ChatMessages.EventDigest, row.Event);
        Assert.Equal(WebhookService.KindSlack, row.Kind);

        _fx.Http.Calls.Clear();
        await _fx.Outbox().FlushPendingAsync(CancellationToken.None);
        var call = Assert.Single(_fx.Http.Calls);
        Assert.Equal("VulnVerdict daily digest", call.Json!["blocks"]![0]!["text"]!["text"]!.GetValue<string>());
        Assert.StartsWith("1 to fix today, 1 this week.", call.Json!["blocks"]![1]!["text"]!["text"]!.GetValue<string>());
        Assert.Contains("*Fix today*\\n1", call.Body);
        Assert.Equal("<https://vv.example.com/|Open VulnVerdict>", call.Json!["blocks"]![3]!["text"]!["text"]!.GetValue<string>());
        Assert.DoesNotContain("FW-EDGE-01", call.Body);
        Assert.DoesNotContain("SRV-FILE-01", call.Body);

        // a digest sent by hand from the console is not announced, and switching the event off stops the daily one
        await _fx.Digest().SendDigestAsync(DigestKind.Manual);
        await _fx.ConfigureAsync(s => s.ChatNotifyDigest = false);
        await _fx.Digest().SendDigestAsync(DigestKind.Daily);
        Assert.Equal(0, await _fx.Outbox().PendingCountAsync());
    }

    [Fact]
    public async Task Digest_summary_is_queued_without_mail_when_asked_for()
    {
        // no mail set up: the worker generates the day's digest without sending it, and asks for the chat summary on its own
        await TeamsAsync();
        _fx.AddVerdict();
        Assert.Equal(1, await _fx.Digest().QueueChatSummaryAsync());
        var row = Assert.Single(_fx.OutboxRows());
        Assert.Equal((WebhookService.KindTeams, ChatMessages.EventDigest), (row.Kind, row.Event));

        await TeamsAsync(s => s.ChatNotifyDigest = false);
        Assert.Equal(0, await _fx.Digest().QueueChatSummaryAsync());
    }

    [Fact]
    public async Task Feed_health_is_announced_at_most_once_a_day()
    {
        await TeamsAsync();
        var chat = new ChatNotificationService(_fx.Factory, _fx.Settings, _fx.Outbox());
        Assert.False(await chat.QueueFeedHealthAsync(Array.Empty<string>()));
        Assert.True(await chat.QueueFeedHealthAsync(new[] { "CISA KEV", "EPSS" }));
        Assert.False(await chat.QueueFeedHealthAsync(new[] { "CISA KEV", "EPSS" }));

        await _fx.Outbox().FlushPendingAsync(CancellationToken.None);
        var body = Assert.Single(_fx.Http.Calls).Json!["attachments"]![0]!["content"]!["body"]!;
        Assert.Equal("2 feeds are overdue", body[0]!["text"]!.GetValue<string>());
        Assert.Equal("Not updated on schedule: CISA KEV, EPSS. Verdicts may be out of date until they recover.", body[1]!["text"]!.GetValue<string>());
    }

    // ------------------------------------------------------------------ end to end from an evaluation

    [Fact]
    public async Task A_watchlist_save_in_the_web_process_reaches_teams_and_the_webhook_through_the_worker()
    {
        await TeamsAsync(s => { s.WebhookUrl = "https://hooks.example.com/vv"; s.WebhookSecret = "s3cret"; });
        _fx.Http.On(HttpMethod.Post, "/vv", "");
        await using (var db = await _fx.Factory.CreateDbContextAsync())
        {
            db.Cves.Add(new Cve { Id = "CVE-2099-1001", State = "PUBLISHED", RetrievedAt = DateTime.UtcNow, Description = "test record", CvssV31Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CvssV31Score = 9.8 });
            db.CveAffected.Add(new CveAffected
            {
                CveId = "CVE-2099-1001", Vendor = "Fortinet", Product = "FortiOS", VendorNorm = Normalizer.Norm("Fortinet"), ProductNorm = Normalizer.Norm("FortiOS"), DefaultStatus = "unaffected",
                VersionsJson = "[{\"version\":\"7.2.0\",\"status\":\"affected\",\"lessThan\":\"7.2.8\",\"versionType\":\"semver\"}]",
            });
            db.Kev.Add(new KevEntry { CveId = "CVE-2099-1001", DateAdded = DateTime.UtcNow, RetrievedAt = DateTime.UtcNow });
            await db.SaveChangesAsync();
        }

        // the web process (Role=web): saving the entry evaluates it there, and no worker loop runs in that process
        var web = _fx.Outbox();
        var evaluator = new VerdictEvaluator(_fx.Factory, _fx.Settings, new ServiceCollection().BuildServiceProvider(), web, NullLogger<VerdictEvaluator>.Instance);
        await new WatchlistService(_fx.Factory, evaluator).UpsertAsync(new WatchlistEntry
        {
            Vendor = "Fortinet", Product = "FortiOS", Version = "7.2.5", AssetName = "FW-EDGE-01", Exposure = Exposure.Internet, Criticality = Criticality.Critical,
        }, "test");
        Assert.Empty(_fx.Http.Calls);
        Assert.Equal(new[] { WebhookService.KindWebhook, WebhookService.KindTeams }, _fx.OutboxRows().Select(r => r.Kind));

        // the worker process: its own instance, the same table
        await _fx.Outbox().FlushPendingAsync(CancellationToken.None);

        Assert.Equal(2, _fx.Http.Calls.Count);
        var webhook = _fx.Http.Calls.Single(c => c.Url.Host == "hooks.example.com");
        Assert.Equal(WebhookService.EventCreated, webhook.Header(WebhookService.EventHeader));
        Assert.Equal("Fix today", webhook.Json!["verdict"]!["verdict"]!.GetValue<string>());
        var teams = _fx.Http.Calls.Single(c => c.Url.Host.EndsWith("logic.azure.com"));
        Assert.Contains("Fix today: CVE-2099-1001", teams.Body);
        Assert.DoesNotContain("FW-EDGE-01", teams.Body);
        Assert.All(_fx.OutboxRows(), r => Assert.NotNull(r.DeliveredAt));
    }
}
