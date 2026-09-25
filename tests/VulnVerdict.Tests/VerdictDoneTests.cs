using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;
using VulnVerdict.Core.Services;
using Xunit;

namespace VulnVerdict.Tests;

/// <summary>
/// Marking a watchlist verdict done at a version: the entry moves to that version and every other CVE the upgrade
/// fixes closes with it, while anything still affecting the new version stays open.
/// </summary>
public class VerdictDoneTests : IDisposable
{
    private readonly SqliteConnection _conn;
    private readonly TestDbFactory _factory;
    private readonly VerdictWorkflow _workflow;
    private readonly WatchlistService _watchlist;
    private readonly Guid _entryId;

    public VerdictDoneTests()
    {
        _conn = new SqliteConnection("DataSource=:memory:");
        _conn.Open();
        _factory = new TestDbFactory(new DbContextOptionsBuilder<VvDbContext>().UseSqlite(_conn).Options);
        using (var db = _factory.CreateDbContext())
        {
            db.Database.EnsureCreated();
            Add(db, "CVE-2099-1001", "7.2.6");   // fixed by 7.2.6
            Add(db, "CVE-2099-1002", "7.2.8");   // fixed by 7.2.8: the one marked done
            Add(db, "CVE-2099-1003", "7.4.3");   // still affects everything below 7.4.3
            Add(db, "CVE-2099-1004", "7.2.7");   // fixed by 7.2.7, snoozed before the upgrade
            db.SaveChanges();
        }
        var settings = new SettingsService(_factory, new PassthroughProtectionProvider());
        var webhooks = new WebhookService(_factory, settings, new FakeHttpClientFactory(new FakeHandler()), NullLogger<WebhookService>.Instance);
        var evaluator = new VerdictEvaluator(_factory, settings, new ServiceCollection().BuildServiceProvider(), webhooks, NullLogger<VerdictEvaluator>.Instance);
        _watchlist = new WatchlistService(_factory, evaluator);
        _workflow = new VerdictWorkflow(_factory, settings, webhooks, _watchlist);
        _entryId = _watchlist.UpsertAsync(new WatchlistEntry
        {
            Vendor = "Fortinet", Product = "FortiOS", Version = "7.2.5", AssetName = "FW-EDGE-01",
            Exposure = Exposure.Internet, Criticality = Criticality.Critical,
        }, "test").GetAwaiter().GetResult().Id;
    }

    public void Dispose() => _conn.Dispose();

    private static void Add(VvDbContext db, string cve, string fixedIn)
    {
        db.Cves.Add(new Cve { Id = cve, State = "PUBLISHED", RetrievedAt = DateTime.UtcNow, Description = "test record", CvssV31Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CvssV31Score = 9.8 });
        db.CveAffected.Add(new CveAffected
        {
            CveId = cve, Vendor = "Fortinet", Product = "FortiOS", VendorNorm = Normalizer.Norm("Fortinet"), ProductNorm = Normalizer.Norm("FortiOS"),
            DefaultStatus = "unaffected",
            VersionsJson = "[{\"version\":\"7.2.0\",\"status\":\"affected\",\"lessThan\":\"" + fixedIn + "\",\"versionType\":\"semver\"}]",
        });
    }

    private async Task<Dictionary<string, Verdict>> Verdicts()
    {
        await using var db = await _factory.CreateDbContextAsync();
        return await db.Verdicts.AsNoTracking().Include(v => v.History).Where(v => v.WatchlistEntryId == _entryId).ToDictionaryAsync(v => v.CveId);
    }

    private async Task<string?> EntryVersion()
    {
        await using var db = await _factory.CreateDbContextAsync();
        return (await db.Watchlist.AsNoTracking().FirstAsync(w => w.Id == _entryId)).Version;
    }

    [Fact]
    public async Task Upgrading_the_watchlist_closes_every_verdict_the_new_version_fixes()
    {
        var before = await Verdicts();
        Assert.Equal(4, before.Count);
        Assert.All(before.Values, v => Assert.True(v.Tier > VerdictTier.NotAffected, v.CveId + " should affect 7.2.5"));
        await _workflow.SnoozeAsync(before["CVE-2099-1004"].Id, "tester", DateTime.UtcNow.AddDays(7), "change window");

        var r = await _workflow.DoneAsync(before["CVE-2099-1002"].Id, "tester", "7.2.8", updateWatchlist: true, note: null);

        Assert.True(r.WatchlistUpdated);
        Assert.Equal("7.2.5", r.FromVersion);
        Assert.Equal("7.2.8", r.ToVersion);
        Assert.Equal(2, r.OthersClosed);      // 1001 and the snoozed 1004
        Assert.Equal(1, r.StillAffected);     // 1003
        Assert.False(r.ThisStillListed);
        Assert.Equal("7.2.8", await EntryVersion());

        var after = await Verdicts();
        Assert.Equal(VerdictState.Closed, after["CVE-2099-1002"].State);
        Assert.Equal("tester", after["CVE-2099-1002"].StateOwner);
        Assert.Contains("now running 7.2.8", after["CVE-2099-1002"].StateReason);

        foreach (var cve in new[] { "CVE-2099-1001", "CVE-2099-1004" })
        {
            Assert.Equal(VerdictState.Closed, after[cve].State);
            Assert.Equal("system", after[cve].StateOwner);
            Assert.Equal("watchlist now records: 7.2.8", after[cve].StateReason);
            Assert.Contains(after[cve].History, h => h.Kind == "state" && h.To == "Closed" && h.Reason!.Contains("patched, closed"));
        }
        Assert.Null(after["CVE-2099-1004"].SnoozedUntil);

        Assert.Equal(VerdictState.Open, after["CVE-2099-1003"].State);
        Assert.True(after["CVE-2099-1003"].Tier > VerdictTier.NotAffected);
    }

    [Fact]
    public async Task Done_without_updating_the_watchlist_closes_only_that_verdict()
    {
        var before = await Verdicts();
        var r = await _workflow.DoneAsync(before["CVE-2099-1002"].Id, "tester", "7.2.8", updateWatchlist: false, note: "change CHG-1042");

        Assert.False(r.WatchlistUpdated);
        Assert.Equal("7.2.5", await EntryVersion());
        var after = await Verdicts();
        Assert.Equal(VerdictState.Closed, after["CVE-2099-1002"].State);
        Assert.Equal("change CHG-1042 (now running 7.2.8)", after["CVE-2099-1002"].StateReason);
        Assert.All(new[] { "CVE-2099-1001", "CVE-2099-1003", "CVE-2099-1004" }, cve => Assert.Equal(VerdictState.Open, after[cve].State));
    }

    [Fact]
    public async Task A_version_the_record_still_lists_as_affected_is_flagged()
    {
        var before = await Verdicts();
        var r = await _workflow.DoneAsync(before["CVE-2099-1002"].Id, "tester", "7.2.7", updateWatchlist: true, note: null);

        Assert.True(r.WatchlistUpdated);
        Assert.True(r.ThisStillListed);        // 1002 is fixed only in 7.2.8
        Assert.Equal(2, r.OthersClosed);       // 1001 (fixed 7.2.6) and 1004 (fixed 7.2.7)
        Assert.Equal(1, r.StillAffected);      // 1003
        var after = await Verdicts();
        Assert.Equal(VerdictState.Closed, after["CVE-2099-1002"].State);   // still closed: the person said it is done
    }

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
