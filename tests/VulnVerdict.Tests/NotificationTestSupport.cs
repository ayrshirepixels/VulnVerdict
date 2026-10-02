using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Digest;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

/// <summary>
/// One in-memory SQLite database (EnsureCreated) with the notification services wired over a fake HTTP handler.
/// A second <see cref="WebhookService"/> over the same database stands in for the other process: the web queues,
/// the worker sends.
/// </summary>
public sealed class NotificationFixture : IDisposable
{
    private readonly SqliteConnection _conn;
    public IDbContextFactory<VvDbContext> Factory { get; }
    public SettingsService Settings { get; }
    public FakeHandler Http { get; } = new();
    /// <summary>The real ASP.NET Data Protection implementation with throwaway keys, so tampering is actually detected.</summary>
    public IDataProtectionProvider Protection { get; } = new EphemeralDataProtectionProvider();

    public NotificationFixture()
    {
        _conn = new SqliteConnection("DataSource=:memory:");
        _conn.Open();
        Factory = new DbFactory(new DbContextOptionsBuilder<VvDbContext>().UseSqlite(_conn).Options);
        using (var db = Factory.CreateDbContext()) db.Database.EnsureCreated();
        Settings = new SettingsService(Factory, Protection);
    }

    public void Dispose() => _conn.Dispose();

    /// <summary>A fresh service instance over the same database: nothing is shared with any other instance but the tables.</summary>
    public WebhookService Outbox(TimeSpan? retryDelay = null) =>
        new(Factory, Settings, new FakeHttpClientFactory(Http), NullLogger<WebhookService>.Instance) { RetryDelay = retryDelay ?? TimeSpan.Zero };

    public VerdictWorkflow Workflow(WebhookService outbox)
    {
        var evaluator = new VerdictEvaluator(Factory, Settings, new ServiceCollection().BuildServiceProvider(), outbox, NullLogger<VerdictEvaluator>.Instance);
        return new VerdictWorkflow(Factory, Settings, outbox, new WatchlistService(Factory, evaluator));
    }

    public DigestService Digest(DigestActionTokens? tokens = null)
    {
        var http = new FakeHttpClientFactory(Http);
        var connectors = new ConnectorService(Factory, Array.Empty<IInventoryAdapter>(), Array.Empty<ITicketAdapter>(), new InventoryService(Factory, NullLogger<InventoryService>.Instance), Protection, NullLogger<ConnectorService>.Instance);
        return new DigestService(Factory, Settings, new EmailService(Settings, http, NullLogger<EmailService>.Instance), connectors,
            new HealthNotices(Settings, Factory, connectors), NullLogger<DigestService>.Instance, tokens);
    }

    public async Task ConfigureAsync(Action<AppSettings> change)
    {
        var s = await Settings.LoadAsync();
        s.BaseUrl = "https://vv.example.com";
        change(s);
        await Settings.SaveAsync(s, "test");
    }

    /// <summary>Mail through the SendGrid API, which the fake handler answers.</summary>
    public Task ConfigureMailAsync(Action<AppSettings>? change = null) => ConfigureAsync(s =>
    {
        s.MailTransport = "sendgrid"; s.MailApiKey = "SG.test"; s.SmtpFrom = "vv@example.com"; s.DigestRecipients = "it@example.com, desk@example.com";
        change?.Invoke(s);
    });

    public Verdict AddVerdict(string cve = "CVE-2024-1234", string asset = "FW-EDGE-01", VerdictTier tier = VerdictTier.FixToday, string version = "7.2.5", Action<Verdict>? change = null)
    {
        using var db = Factory.CreateDbContext();
        if (!db.Cves.Any(c => c.Id == cve)) db.Cves.Add(new Cve { Id = cve, State = "PUBLISHED", RetrievedAt = DateTime.UtcNow });
        var entry = new WatchlistEntry
        {
            Id = Guid.NewGuid(), Vendor = "Fortinet", Product = "FortiOS", VendorNorm = "fortinet", ProductNorm = "fortios", Version = version, AssetName = asset,
            Exposure = Exposure.Internet, Criticality = Criticality.Critical, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow
        };
        db.Watchlist.Add(entry);
        var subject = "Fortinet FortiOS " + version + " on " + asset;
        var v = new Verdict
        {
            Id = Guid.NewGuid(), CveId = cve, WatchlistEntryId = entry.Id, Subject = subject, Tier = tier, RuleNumber = 2,
            Confidence = MatchConfidence.Exact, State = VerdictState.Open, SlaDue = new DateTime(2026, 9, 26, 12, 0, 0, DateTimeKind.Utc),
            Sentence = subject + ": exploited in the wild, works over the network with no login, reachable from the internet. Fixed in 7.2.8.", FixedIn = "7.2.8",
            Exploitation = Exploitation.Active, InKev = true,
            CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow, LastEvaluatedAt = DateTime.UtcNow
        };
        change?.Invoke(v);
        db.Verdicts.Add(v);
        db.SaveChanges();
        return v;
    }

    /// <summary>Queue verdict events the way the evaluator does: rows added to the caller's context and saved with it.</summary>
    public async Task<List<OutboxMessage>> EnqueueAsync(WebhookService outbox, params (string Event, Guid VerdictId)[] events)
    {
        await using var db = await Factory.CreateDbContextAsync();
        var rows = await outbox.EnqueueAsync(db, events);
        await db.SaveChangesAsync();
        return rows;
    }

    public List<OutboxMessage> OutboxRows()
    {
        using var db = Factory.CreateDbContext();
        return db.Outbox.AsNoTracking().OrderBy(o => o.Id).ToList();
    }

    /// <summary>Make every waiting row due, as if the backoff had passed.</summary>
    public void MakeDue()
    {
        using var db = Factory.CreateDbContext();
        db.Outbox.Where(o => o.DeliveredAt == null && o.FailedAt == null).ExecuteUpdate(u => u.SetProperty(o => o.NextAttemptAt, DateTime.UtcNow.AddSeconds(-1)));
    }

    public Verdict Reload(Guid id)
    {
        using var db = Factory.CreateDbContext();
        return db.Verdicts.AsNoTracking().Include(v => v.History).First(v => v.Id == id);
    }

    private sealed class DbFactory : IDbContextFactory<VvDbContext>
    {
        private readonly DbContextOptions<VvDbContext> _options;
        public DbFactory(DbContextOptions<VvDbContext> options) => _options = options;
        public VvDbContext CreateDbContext() => new(_options);
        public Task<VvDbContext> CreateDbContextAsync(CancellationToken ct = default) => Task.FromResult(CreateDbContext());
    }
}
