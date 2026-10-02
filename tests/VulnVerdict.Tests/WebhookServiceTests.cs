using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Digest;
using VulnVerdict.Core.Engine;
using VulnVerdict.Core.Feeds;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

/// <summary>Webhooks through the durable outbox: queued with the change, sent by whichever process drains, retried with backoff, given up after the cap.</summary>
public class WebhookServiceTests : IDisposable
{
    private readonly NotificationFixture _fx = new();
    private readonly Verdict _verdict;

    public WebhookServiceTests() => _verdict = _fx.AddVerdict();

    public void Dispose() => _fx.Dispose();

    private Task ConfigureAsync(string url, string secret = "s3cret") => _fx.ConfigureAsync(s => { s.WebhookUrl = url; s.WebhookSecret = secret; });

    private List<WebhookDelivery> Deliveries()
    {
        using var db = _fx.Factory.CreateDbContext();
        return db.WebhookDeliveries.OrderBy(d => d.Id).ToList();
    }

    [Fact]
    public async Task Posts_signed_payload_and_records_delivery()
    {
        await ConfigureAsync("https://hooks.example.com/vv");
        _fx.Http.On(HttpMethod.Post, "/vv", "{\"ok\":true}");
        var svc = _fx.Outbox();

        var row = Assert.Single(await _fx.EnqueueAsync(svc, (WebhookService.EventCreated, _verdict.Id)));
        Assert.Empty(await svc.FlushPendingAsync(CancellationToken.None));

        var call = Assert.Single(_fx.Http.Calls);
        Assert.Equal("https://hooks.example.com/vv", call.Url.ToString());
        Assert.Equal("application/json", call.ContentType);
        Assert.Equal(WebhookService.EventCreated, call.Header(WebhookService.EventHeader));
        Assert.Equal(row.Id.ToString(), call.Header(WebhookService.DeliveryHeader));

        // the original signature is HMAC-SHA256 of the exact bytes on the wire, computed here independently
        var key = Encoding.UTF8.GetBytes("s3cret");
        var expected = "sha256=" + Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(call.Body!))).ToLowerInvariant();
        Assert.Equal(expected, call.Header(WebhookService.SignatureHeader));
        Assert.Equal(expected, WebhookService.Sign("s3cret", call.Body!));

        // the timestamped signature covers "timestamp.body", so a captured delivery cannot be replayed with a new time
        var timestamp = call.Header(WebhookService.TimestampHeader)!;
        Assert.InRange(long.Parse(timestamp), DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 60, DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 5);
        var expectedV2 = "sha256=" + Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(timestamp + "." + call.Body))).ToLowerInvariant();
        Assert.Equal(expectedV2, call.Header(WebhookService.TimestampedSignatureHeader));
        Assert.NotEqual(expected, expectedV2);

        var j = JsonNode.Parse(call.Body!)!;
        Assert.Equal("verdict.created", j["event"]!.GetValue<string>());
        Assert.NotNull(j["sentAt"]);
        var v = j["verdict"]!;
        Assert.Equal(_verdict.Id.ToString(), v["id"]!.GetValue<string>());
        Assert.Equal("CVE-2024-1234", v["cveId"]!.GetValue<string>());
        Assert.Equal("Fortinet FortiOS 7.2.5 on FW-EDGE-01", v["subject"]!.GetValue<string>());
        Assert.Equal("Fix today", v["verdict"]!.GetValue<string>());
        Assert.Equal(2, v["rule"]!.GetValue<int>());
        Assert.Equal("Exact", v["confidence"]!.GetValue<string>());
        Assert.Equal("Open", v["state"]!.GetValue<string>());
        Assert.Equal("2026-09-26T12:00:00Z", v["slaDue"]!.GetValue<string>());
        Assert.Equal("7.2.8", v["fixedIn"]!.GetValue<string>());
        Assert.StartsWith("Fortinet FortiOS 7.2.5", v["sentence"]!.GetValue<string>());
        Assert.Equal("https://vv.example.com/verdicts/" + _verdict.Id, v["url"]!.GetValue<string>());

        var d = Assert.Single(Deliveries());
        Assert.Equal(WebhookService.EventCreated, d.Event);
        Assert.Equal(_verdict.Id, d.VerdictId);
        Assert.Equal("https://hooks.example.com/vv", d.Url);
        Assert.Equal(200, d.StatusCode);
        Assert.Null(d.Error);

        var sent = Assert.Single(_fx.OutboxRows());
        Assert.NotNull(sent.DeliveredAt);
        Assert.Equal(1, sent.Attempts);
        Assert.Equal(0, await svc.PendingCountAsync());
    }

    [Fact]
    public async Task Blank_url_means_nothing_queued_and_no_call()
    {
        await ConfigureAsync("");
        var svc = _fx.Outbox();
        Assert.Empty(await _fx.EnqueueAsync(svc, (WebhookService.EventClosed, _verdict.Id)));
        await svc.FlushPendingAsync(CancellationToken.None);
        Assert.Empty(_fx.Http.Calls);
        Assert.Empty(_fx.OutboxRows());
        Assert.Empty(Deliveries());
    }

    [Fact]
    public async Task Url_removed_after_queueing_drops_the_row()
    {
        await ConfigureAsync("https://hooks.example.com/vv");
        var svc = _fx.Outbox();
        await _fx.EnqueueAsync(svc, (WebhookService.EventClosed, _verdict.Id));
        await ConfigureAsync("");
        await svc.FlushPendingAsync(CancellationToken.None);
        Assert.Empty(_fx.Http.Calls);
        Assert.Empty(_fx.OutboxRows());
    }

    [Fact]
    public async Task Queued_by_one_instance_and_sent_by_another()
    {
        await ConfigureAsync("https://hooks.example.com/vv");
        _fx.Http.On(HttpMethod.Post, "/vv", "");

        // the web process: saves the change and the outbox row together, then goes away
        var web = _fx.Outbox();
        await _fx.EnqueueAsync(web, (WebhookService.EventPromoted, _verdict.Id), (WebhookService.EventClosed, Guid.NewGuid()));   // an unknown verdict is skipped quietly
        Assert.Empty(_fx.Http.Calls);
        Assert.Equal(1, await web.PendingCountAsync());

        // the worker: a different instance that never saw the event, only the table
        var worker = _fx.Outbox();
        await worker.FlushPendingAsync(CancellationToken.None);

        var call = Assert.Single(_fx.Http.Calls);
        Assert.Equal(WebhookService.EventPromoted, call.Header(WebhookService.EventHeader));
        Assert.Equal("verdict.promoted", JsonNode.Parse(call.Body!)!["event"]!.GetValue<string>());
        Assert.Equal(0, await worker.PendingCountAsync());
        Assert.Single(Deliveries());

        // and nothing is sent twice
        await web.FlushPendingAsync(CancellationToken.None);
        await worker.FlushPendingAsync(CancellationToken.None);
        Assert.Single(_fx.Http.Calls);
    }

    [Fact]
    public async Task The_outbox_row_is_written_in_the_same_save_as_the_change()
    {
        await ConfigureAsync("https://hooks.example.com/vv");
        var svc = _fx.Outbox();
        await using (var db = await _fx.Factory.CreateDbContextAsync())
        {
            var v = await db.Verdicts.FirstAsync(x => x.Id == _verdict.Id);
            v.Tier = VerdictTier.FixThisWeek;
            await svc.EnqueueAsync(db, new[] { (WebhookService.EventPromoted, v.Id) });
            // the save never happens: neither the change nor the event exists
        }
        Assert.Empty(_fx.OutboxRows());
        Assert.Equal(VerdictTier.FixToday, _fx.Reload(_verdict.Id).Tier);

        await using (var db = await _fx.Factory.CreateDbContextAsync())
        {
            var v = await db.Verdicts.FirstAsync(x => x.Id == _verdict.Id);
            v.Tier = VerdictTier.FixThisWeek;
            await svc.EnqueueAsync(db, new[] { (WebhookService.EventPromoted, v.Id) });
            await db.SaveChangesAsync();
        }
        // the payload carries the verdict as it was saved, not as it was before
        Assert.Equal("Fix this week", JsonNode.Parse(Assert.Single(_fx.OutboxRows()).PayloadJson)!["verdict"]!["verdict"]!.GetValue<string>());
    }

    [Fact]
    public async Task Failure_backs_off_exponentially_then_is_given_up()
    {
        await ConfigureAsync("https://hooks.example.com/vv");
        _fx.Http.On(HttpMethod.Post, "/vv", "{\"error\":\"boom\"}", HttpStatusCode.InternalServerError);
        var svc = _fx.Outbox(TimeSpan.FromMinutes(1));
        svc.MaxAttempts = 3;
        await _fx.EnqueueAsync(svc, (WebhookService.EventCreated, _verdict.Id));

        Assert.Empty(await svc.FlushPendingAsync(CancellationToken.None));
        var row = Assert.Single(_fx.OutboxRows());
        Assert.Equal(1, row.Attempts);
        Assert.InRange(row.NextAttemptAt - DateTime.UtcNow, TimeSpan.FromSeconds(50), TimeSpan.FromSeconds(61));
        Assert.Contains("HTTP 500", row.LastError);
        Assert.DoesNotContain("boom", row.LastError);   // what the receiver replied is logged, not shown

        // not due yet: a flush does nothing
        await svc.FlushPendingAsync(CancellationToken.None);
        Assert.Single(_fx.Http.Calls);

        _fx.MakeDue();
        Assert.Empty(await svc.FlushPendingAsync(CancellationToken.None));
        row = Assert.Single(_fx.OutboxRows());
        Assert.Equal(2, row.Attempts);
        Assert.InRange(row.NextAttemptAt - DateTime.UtcNow, TimeSpan.FromSeconds(110), TimeSpan.FromSeconds(121));   // doubled
        Assert.Null(row.FailedAt);

        _fx.MakeDue();
        var gaveUp = Assert.Single(await svc.FlushPendingAsync(CancellationToken.None));
        Assert.Contains("Webhook", gaveUp);
        Assert.Contains("3 attempts", gaveUp);
        row = Assert.Single(_fx.OutboxRows());
        Assert.NotNull(row.FailedAt);
        Assert.Null(row.DeliveredAt);

        // given up means given up
        _fx.MakeDue();
        await svc.FlushPendingAsync(CancellationToken.None);
        Assert.Equal(3, _fx.Http.Calls.Count);
        Assert.Equal(0, await svc.PendingCountAsync());

        var rows = Deliveries();
        Assert.Equal(3, rows.Count);
        Assert.All(rows, r => { Assert.Equal(500, r.StatusCode); Assert.Contains("HTTP 500", r.Error); });

        // and it shows as a health notice until something gets through again
        var notice = Assert.Single(await WebhookService.FailureNoticesAsync(_fx.Factory));
        Assert.True(notice.Error);
        Assert.Contains("Webhooks are not being delivered", notice.Text);
        Assert.Contains("1 given up", notice.Text);
    }

    [Fact]
    public void Backoff_doubles_up_to_the_cap()
    {
        var svc = _fx.Outbox(TimeSpan.FromSeconds(30));
        Assert.Equal(TimeSpan.FromSeconds(30), svc.Backoff(1));
        Assert.Equal(TimeSpan.FromSeconds(60), svc.Backoff(2));
        Assert.Equal(TimeSpan.FromMinutes(4), svc.Backoff(4));
        Assert.Equal(TimeSpan.FromHours(1), svc.Backoff(9));
        Assert.Equal(TimeSpan.FromHours(1), svc.Backoff(500));
    }

    [Fact]
    public async Task A_later_success_clears_the_health_notice()
    {
        await ConfigureAsync("https://hooks.example.com/vv");
        var healthy = false;
        _fx.Http.On(r => true, (_, _) => healthy ? FakeHandler.Json("") : throw new HttpRequestException("connection refused"));
        var svc = _fx.Outbox();
        svc.MaxAttempts = 1;
        await _fx.EnqueueAsync(svc, (WebhookService.EventCreated, _verdict.Id));
        Assert.Single(await svc.FlushPendingAsync(CancellationToken.None));
        Assert.Equal("connection refused", Assert.Single(_fx.OutboxRows()).LastError);
        Assert.Single(await WebhookService.FailureNoticesAsync(_fx.Factory));

        healthy = true;
        await _fx.EnqueueAsync(svc, (WebhookService.EventPromoted, _verdict.Id));
        Assert.Empty(await svc.FlushPendingAsync(CancellationToken.None));
        Assert.Empty(await WebhookService.FailureNoticesAsync(_fx.Factory));
    }

    [Fact]
    public async Task A_row_another_process_has_started_on_is_left_alone()
    {
        await ConfigureAsync("https://hooks.example.com/vv");
        var svc = _fx.Outbox();
        var rows = await _fx.EnqueueAsync(svc, (WebhookService.EventCreated, _verdict.Id), (WebhookService.EventPromoted, _verdict.Id));
        Assert.Equal(2, rows.Count);

        // both rows are read as due; while the first is on the wire another process claims the second (its attempt
        // counted, the lease pushed out), so this one must not send it as well
        _fx.Http.On(r => true, (_, _) =>
        {
            using var db = _fx.Factory.CreateDbContext();
            db.Outbox.Where(o => o.Id == rows[1].Id).ExecuteUpdate(u => u.SetProperty(o => o.Attempts, 1).SetProperty(o => o.NextAttemptAt, DateTime.UtcNow.AddMinutes(5)));
            return FakeHandler.Json("");
        });

        await svc.FlushPendingAsync(CancellationToken.None);

        Assert.Equal(WebhookService.EventCreated, Assert.Single(_fx.Http.Calls).Header(WebhookService.EventHeader));
        var after = _fx.OutboxRows();
        Assert.NotNull(after[0].DeliveredAt);
        Assert.Null(after[1].DeliveredAt);
        Assert.Equal(1, after[1].Attempts);
    }

    [Fact]
    public async Task No_signature_headers_without_a_secret()
    {
        await ConfigureAsync("https://hooks.example.com/vv", secret: "");
        _fx.Http.On(HttpMethod.Post, "/vv", "");
        var svc = _fx.Outbox();
        await _fx.EnqueueAsync(svc, (WebhookService.EventClosed, _verdict.Id));
        await svc.FlushPendingAsync(CancellationToken.None);
        var call = Assert.Single(_fx.Http.Calls);
        Assert.Null(call.Header(WebhookService.SignatureHeader));
        Assert.Null(call.Header(WebhookService.TimestampedSignatureHeader));
        Assert.Equal(WebhookService.EventClosed, call.Header(WebhookService.EventHeader));
    }

    [Fact]
    public async Task Marking_done_in_the_console_queues_the_closed_event_and_sends_it_straight_away()
    {
        await ConfigureAsync("https://hooks.example.com/vv");
        _fx.Http.On(HttpMethod.Post, "/vv", "");
        var web = _fx.Outbox();

        await _fx.Workflow(web).CloseAsync(_verdict.Id, "tester", "patched");

        var call = Assert.Single(_fx.Http.Calls);
        Assert.Equal(WebhookService.EventClosed, call.Header(WebhookService.EventHeader));
        Assert.Equal("Closed", JsonNode.Parse(call.Body!)!["verdict"]!["state"]!.GetValue<string>());
        Assert.NotNull(Assert.Single(_fx.OutboxRows()).DeliveredAt);
    }

    [Fact]
    public async Task A_closed_event_the_web_process_could_not_send_is_sent_by_the_worker()
    {
        await ConfigureAsync("https://hooks.example.com/vv");
        var up = false;
        _fx.Http.On(r => true, (_, _) => up ? FakeHandler.Json("") : throw new HttpRequestException("connection refused"));

        await _fx.Workflow(_fx.Outbox()).CloseAsync(_verdict.Id, "tester", "patched");
        Assert.Null(Assert.Single(_fx.OutboxRows()).DeliveredAt);
        Assert.Equal(VerdictState.Closed, _fx.Reload(_verdict.Id).State);   // the close itself is not held up

        up = true;
        _fx.MakeDue();
        await _fx.Outbox().FlushPendingAsync(CancellationToken.None);
        Assert.NotNull(Assert.Single(_fx.OutboxRows()).DeliveredAt);
        Assert.Equal(2, _fx.Http.Calls.Count);
    }

    [Fact]
    public async Task Worker_pass_sends_what_the_evaluation_queued_using_the_registered_services()
    {
        var path = Path.Combine(Path.GetTempPath(), "vv-outbox-" + Guid.NewGuid().ToString("N") + ".db");
        var http = new FakeHandler().On(HttpMethod.Post, "/vv", "");
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
        services.AddVulnVerdictCore("sqlite", "Data Source=" + path + ";Pooling=False", new WorkerOptions { DataDir = Path.GetTempPath() }, "web");
        services.RemoveAll<IFeed>();
        services.RemoveAll<IPackageVulnSource>();
        services.AddSingleton<IHttpClientFactory>(new FakeHttpClientFactory(http));
        await using var sp = services.BuildServiceProvider();
        try
        {
            var factory = sp.GetRequiredService<IDbContextFactory<VvDbContext>>();
            await using (var db = await factory.CreateDbContextAsync())
            {
                await db.Database.EnsureCreatedAsync();
                db.Cves.Add(new Cve { Id = "CVE-2099-1001", State = "PUBLISHED", RetrievedAt = DateTime.UtcNow, Description = "test record", CvssV31Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CvssV31Score = 9.8 });
                db.CveAffected.Add(new CveAffected
                {
                    CveId = "CVE-2099-1001", Vendor = "Fortinet", Product = "FortiOS", VendorNorm = Normalizer.Norm("Fortinet"), ProductNorm = Normalizer.Norm("FortiOS"), DefaultStatus = "unaffected",
                    VersionsJson = "[{\"version\":\"7.2.0\",\"status\":\"affected\",\"lessThan\":\"7.2.8\",\"versionType\":\"semver\"}]",
                });
                db.Watchlist.Add(new WatchlistEntry
                {
                    Id = Guid.NewGuid(), Vendor = "Fortinet", Product = "FortiOS", VendorNorm = Normalizer.Norm("Fortinet"), ProductNorm = Normalizer.Norm("FortiOS"), Version = "7.2.5",
                    AssetName = "FW-EDGE-01", Exposure = Exposure.Internet, Criticality = Criticality.Critical, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow
                });
                await db.SaveChangesAsync();
            }
            var settings = sp.GetRequiredService<SettingsService>();
            var s = await settings.LoadAsync();
            s.WebhookUrl = "https://hooks.example.com/vv"; s.WebhookSecret = "s3cret";
            await settings.SaveAsync(s, "test");

            await new WorkerService(sp, NullLogger<WorkerService>.Instance, sp.GetRequiredService<WorkerOptions>()).RunPassAsync(CancellationToken.None);

            var call = Assert.Single(http.Calls);
            Assert.Equal(WebhookService.EventCreated, call.Header(WebhookService.EventHeader));
            Assert.Equal("CVE-2099-1001", call.Json!["verdict"]!["cveId"]!.GetValue<string>());
            await using (var db = await factory.CreateDbContextAsync())
                Assert.NotNull((await db.Outbox.AsNoTracking().SingleAsync()).DeliveredAt);

            // everything this feature registers resolves, and the digest gets its link signer from the container
            Assert.NotNull(sp.GetRequiredService<ChatNotificationService>());
            Assert.NotNull(sp.GetRequiredService<DigestActionService>());
            Assert.Empty(await sp.GetRequiredService<HealthNotices>().GetAsync());
            s.BaseUrl = "https://vv.example.com";
            await settings.SaveAsync(s, "test");
            var digest = await sp.GetRequiredService<DigestService>().BuildAsync(Guid.NewGuid());
            Assert.NotEmpty(digest.Actions);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            foreach (var f in new[] { path, path + "-wal", path + "-shm" }) try { File.Delete(f); } catch (IOException) { }
        }
    }
}
