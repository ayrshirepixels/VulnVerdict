using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

public class WebhookServiceTests : IDisposable
{
    private readonly SqliteConnection _conn;
    private readonly TestDbFactory _factory;
    private readonly SettingsService _settings;
    private readonly Verdict _verdict;

    public WebhookServiceTests()
    {
        _conn = new SqliteConnection("DataSource=:memory:");
        _conn.Open();
        var options = new DbContextOptionsBuilder<VvDbContext>().UseSqlite(_conn).Options;
        _factory = new TestDbFactory(options);
        using (var db = _factory.CreateDbContext())
        {
            db.Database.EnsureCreated();
            db.Cves.Add(new Cve { Id = "CVE-2024-1234", State = "PUBLISHED", RetrievedAt = DateTime.UtcNow });
            _verdict = new Verdict
            {
                Id = Guid.NewGuid(), CveId = "CVE-2024-1234", Subject = "Fortinet FortiOS 7.2.5 on FW-EDGE-01", Tier = VerdictTier.FixToday, RuleNumber = 2,
                Confidence = MatchConfidence.Exact, State = VerdictState.Open, SlaDue = new DateTime(2026, 9, 26, 0, 0, 0, DateTimeKind.Utc),
                Sentence = "FortiOS 7.2.5 on FW-EDGE-01 is affected by CVE-2024-1234, exploited in the wild. Fix today.", FixedIn = "7.2.6",
                CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow, LastEvaluatedAt = DateTime.UtcNow
            };
            db.Verdicts.Add(_verdict);
            db.SaveChanges();
        }
        _settings = new SettingsService(_factory, new PassthroughProtectionProvider());
    }

    public void Dispose() => _conn.Dispose();

    private async Task ConfigureAsync(string url, string secret = "s3cret")
    {
        var s = await _settings.LoadAsync();
        s.WebhookUrl = url; s.WebhookSecret = secret; s.BaseUrl = "https://vv.example.com";
        await _settings.SaveAsync(s, "test");
    }

    private WebhookService Service(FakeHandler handler) =>
        new(_factory, _settings, new FakeHttpClientFactory(handler), NullLogger<WebhookService>.Instance) { RetryDelay = TimeSpan.Zero };

    private List<WebhookDelivery> Deliveries()
    {
        using var db = _factory.CreateDbContext();
        return db.WebhookDeliveries.OrderBy(d => d.Id).ToList();
    }

    [Fact]
    public async Task Posts_signed_payload_and_records_delivery()
    {
        await ConfigureAsync("https://hooks.example.com/vv");
        var h = new FakeHandler().On(HttpMethod.Post, "/vv", "{\"ok\":true}");
        var svc = Service(h);

        await svc.NotifyAsync(WebhookService.EventCreated, _verdict, CancellationToken.None);

        var call = Assert.Single(h.Calls);
        Assert.Equal("https://hooks.example.com/vv", call.Url.ToString());
        Assert.Equal("application/json", call.ContentType);
        Assert.Equal(WebhookService.EventCreated, call.Header(WebhookService.EventHeader));

        // signature is HMAC-SHA256 of the exact bytes on the wire, computed here independently
        var expected = "sha256=" + Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes("s3cret"), Encoding.UTF8.GetBytes(call.Body!))).ToLowerInvariant();
        Assert.Equal(expected, call.Header(WebhookService.SignatureHeader));
        Assert.Equal(expected, WebhookService.Sign("s3cret", call.Body!));

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
        Assert.Equal("2026-09-26T00:00:00Z", v["slaDue"]!.GetValue<string>());
        Assert.Equal("7.2.6", v["fixedIn"]!.GetValue<string>());
        Assert.StartsWith("FortiOS 7.2.5", v["sentence"]!.GetValue<string>());
        Assert.Equal("https://vv.example.com/verdicts/" + _verdict.Id, v["url"]!.GetValue<string>());

        var d = Assert.Single(Deliveries());
        Assert.Equal(WebhookService.EventCreated, d.Event);
        Assert.Equal(_verdict.Id, d.VerdictId);
        Assert.Equal("https://hooks.example.com/vv", d.Url);
        Assert.Equal(200, d.StatusCode);
        Assert.Null(d.Error);
        Assert.Equal(0, svc.PendingCount);
    }

    [Fact]
    public async Task Blank_url_means_no_call_and_no_row()
    {
        await ConfigureAsync("");
        var h = new FakeHandler();
        var svc = Service(h);
        await svc.NotifyAsync(WebhookService.EventPromoted, _verdict, CancellationToken.None);
        svc.Enqueue(WebhookService.EventClosed, _verdict.Id);
        await svc.FlushPendingAsync(CancellationToken.None);
        Assert.Empty(h.Calls);
        Assert.Empty(Deliveries());
        Assert.Equal(0, svc.PendingCount);
    }

    [Fact]
    public async Task Enqueue_then_flush_loads_the_verdict_and_posts()
    {
        await ConfigureAsync("https://hooks.example.com/vv");
        var h = new FakeHandler().On(HttpMethod.Post, "/vv", "");
        var svc = Service(h);
        svc.Enqueue(WebhookService.EventPromoted, _verdict.Id);
        svc.Enqueue(WebhookService.EventClosed, Guid.NewGuid()); // unknown verdict is skipped quietly
        Assert.Equal(2, svc.PendingCount);

        await svc.FlushPendingAsync(CancellationToken.None);

        var call = Assert.Single(h.Calls);
        Assert.Equal(WebhookService.EventPromoted, call.Header(WebhookService.EventHeader));
        Assert.Equal("verdict.promoted", JsonNode.Parse(call.Body!)!["event"]!.GetValue<string>());
        Assert.Equal(0, svc.PendingCount);
        Assert.Single(Deliveries());
    }

    [Fact]
    public async Task Failure_is_recorded_retried_once_then_given_up()
    {
        await ConfigureAsync("https://hooks.example.com/vv");
        var h = new FakeHandler().On(HttpMethod.Post, "/vv", "{\"error\":\"boom\"}", HttpStatusCode.InternalServerError);
        var svc = Service(h);

        await svc.NotifyAsync(WebhookService.EventCreated, _verdict, CancellationToken.None);
        Assert.Single(h.Calls);
        Assert.Equal(1, svc.PendingCount);

        await svc.FlushPendingAsync(CancellationToken.None);
        Assert.Equal(2, h.Calls.Count);
        Assert.Equal(0, svc.PendingCount);

        await svc.FlushPendingAsync(CancellationToken.None);
        Assert.Equal(2, h.Calls.Count);

        var rows = Deliveries();
        Assert.Equal(2, rows.Count);
        Assert.All(rows, r => { Assert.Equal(500, r.StatusCode); Assert.Contains("HTTP 500", r.Error); Assert.Contains("boom", r.Error); });
    }

    [Fact]
    public async Task Retry_waits_for_the_delay()
    {
        await ConfigureAsync("https://hooks.example.com/vv");
        var h = new FakeHandler().On(r => true, (_, _) => throw new HttpRequestException("connection refused"));
        var svc = Service(h);
        svc.RetryDelay = TimeSpan.FromMinutes(5);
        await svc.NotifyAsync(WebhookService.EventCreated, _verdict, CancellationToken.None);
        Assert.Equal(1, svc.PendingCount);
        await svc.FlushPendingAsync(CancellationToken.None);
        Assert.Single(h.Calls); // not due yet
        Assert.Equal(1, svc.PendingCount);
        var d = Assert.Single(Deliveries());
        Assert.Null(d.StatusCode);
        Assert.Equal("connection refused", d.Error);
    }

    [Fact]
    public async Task No_signature_header_without_a_secret()
    {
        await ConfigureAsync("https://hooks.example.com/vv", secret: "");
        var h = new FakeHandler().On(HttpMethod.Post, "/vv", "");
        await Service(h).NotifyAsync(WebhookService.EventClosed, _verdict, CancellationToken.None);
        var call = Assert.Single(h.Calls);
        Assert.Null(call.Header(WebhookService.SignatureHeader));
        Assert.Equal(WebhookService.EventClosed, call.Header(WebhookService.EventHeader));
    }

    // ------------------------------------------------------------------ test doubles

    private sealed class TestDbFactory : IDbContextFactory<VvDbContext>
    {
        private readonly DbContextOptions<VvDbContext> _options;
        public TestDbFactory(DbContextOptions<VvDbContext> options) => _options = options;
        public VvDbContext CreateDbContext() => new(_options);
        public Task<VvDbContext> CreateDbContextAsync(CancellationToken ct = default) => Task.FromResult(CreateDbContext());
    }

    private sealed class PassthroughProtectionProvider : IDataProtectionProvider, IDataProtector
    {
        public IDataProtector CreateProtector(string purpose) => this;
        public byte[] Protect(byte[] plaintext) => plaintext;
        public byte[] Unprotect(byte[] protectedData) => protectedData;
    }
}
