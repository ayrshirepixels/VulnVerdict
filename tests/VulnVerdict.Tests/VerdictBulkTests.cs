using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;
using VulnVerdict.Core.Services;
using Xunit;
using static VulnVerdict.Core.Services.VerdictWorkflow;

namespace VulnVerdict.Tests;

/// <summary>
/// Bulk verdict actions: the role is checked in the service, each verdict gets its own history line and audit entry,
/// anything that moved on since the page loaded is skipped and counted, and the batch is saved as one.
/// </summary>
public class VerdictBulkTests : IDisposable
{
    private static readonly string[] Cves = { "CVE-2099-1001", "CVE-2099-1002", "CVE-2099-1003", "CVE-2099-1004" };
    private readonly SqliteConnection _conn;
    private readonly TestDbFactory _factory;
    private readonly SettingsService _settings;
    private readonly FakeHandler _http = new FakeHandler().On(HttpMethod.Post, "/vv", "{\"ok\":true}");
    private readonly VerdictWorkflow _workflow;

    public VerdictBulkTests()
    {
        _conn = new SqliteConnection("DataSource=:memory:");
        _conn.Open();
        _factory = new TestDbFactory(new DbContextOptionsBuilder<VvDbContext>().UseSqlite(_conn).Options);
        using (var db = _factory.CreateDbContext())
        {
            db.Database.EnsureCreated();
            foreach (var cve in Cves)
            {
                db.Cves.Add(new Cve { Id = cve, State = "PUBLISHED", RetrievedAt = DateTime.UtcNow, Description = "test record", CvssV31Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CvssV31Score = 9.8 });
                db.CveAffected.Add(new CveAffected
                {
                    CveId = cve, Vendor = "Fortinet", Product = "FortiOS", VendorNorm = Normalizer.Norm("Fortinet"), ProductNorm = Normalizer.Norm("FortiOS"),
                    DefaultStatus = "unaffected", VersionsJson = "[{\"version\":\"7.2.0\",\"status\":\"affected\",\"lessThan\":\"7.2.8\",\"versionType\":\"semver\"}]",
                });
            }
            db.SaveChanges();
        }
        _settings = new SettingsService(_factory, new PassthroughProtectionProvider());
        var webhooks = new WebhookService(_factory, _settings, new FakeHttpClientFactory(_http), NullLogger<WebhookService>.Instance);
        var evaluator = new VerdictEvaluator(_factory, _settings, new ServiceCollection().BuildServiceProvider(), webhooks, NullLogger<VerdictEvaluator>.Instance);
        var watchlist = new WatchlistService(_factory, evaluator);
        _workflow = new VerdictWorkflow(_factory, _settings, webhooks, watchlist);
        watchlist.UpsertAsync(new WatchlistEntry
        {
            Vendor = "Fortinet", Product = "FortiOS", Version = "7.2.5", AssetName = "FW-EDGE-01", Exposure = Exposure.Internet, Criticality = Criticality.Critical,
        }, "test").GetAwaiter().GetResult();
    }

    public void Dispose() => _conn.Dispose();

    private static ClaimsPrincipal User(string name, UserRole role) =>
        new(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, name), new Claim(ClaimTypes.Role, role.ToString()) }, "test", ClaimTypes.Name, ClaimTypes.Role));

    private static readonly ClaimsPrincipal Olga = User("olga", UserRole.Operator);

    private async Task<Dictionary<string, Verdict>> Verdicts()
    {
        await using var db = await _factory.CreateDbContextAsync();
        return await db.Verdicts.AsNoTracking().Include(v => v.History).ToDictionaryAsync(v => v.CveId);
    }

    /// <summary>The selection as the page holds it: every verdict as it looks now.</summary>
    private async Task<List<BulkItem>> Selection() =>
        (await Verdicts()).Values.OrderBy(v => v.CveId).Select(v => new BulkItem(v.Id, v.State, v.StateChangedAt, v.Tier)).ToList();

    private async Task<List<AuditEntry>> Audit(string action)
    {
        await using var db = await _factory.CreateDbContextAsync();
        return await db.Audit.AsNoTracking().Where(a => a.Action == action).ToListAsync();
    }

    [Fact]
    public async Task A_viewer_or_an_anonymous_caller_is_refused_and_nothing_changes()
    {
        var items = await Selection();
        var req = new BulkRequest(BulkAction.Done, items);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => _workflow.BulkAsync(User("vic", UserRole.Viewer), req));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => _workflow.BulkAsync(null, req));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => _workflow.BulkAsync(new ClaimsPrincipal(new ClaimsIdentity()), req));

        Assert.All((await Verdicts()).Values, v => Assert.Equal(VerdictState.Open, v.State));
        Assert.Empty(await Audit("verdict.closed"));
    }

    [Fact]
    public async Task An_administrator_is_allowed()
    {
        var r = await _workflow.BulkAsync(User("ada", UserRole.Administrator), new BulkRequest(BulkAction.Done, await Selection()));
        Assert.Equal(4, r.Changed);
    }

    [Fact]
    public async Task Done_gives_each_verdict_its_own_history_line_and_audit_entry_and_sends_each_webhook()
    {
        var s = await _settings.LoadAsync();
        s.WebhookUrl = "https://hooks.example.com/vv"; s.BaseUrl = "https://vv.example.com";
        await _settings.SaveAsync(s, "test");

        var r = await _workflow.BulkAsync(Olga, new BulkRequest(BulkAction.Done, await Selection(), Reason: " change CHG-1042 "));

        Assert.Equal(4, r.Changed);
        Assert.Empty(r.Skipped);
        Assert.Equal("4 marked done.", r.Summary);
        var after = await Verdicts();
        foreach (var v in after.Values)
        {
            Assert.Equal(VerdictState.Closed, v.State);
            Assert.Equal("olga", v.StateOwner);
            Assert.Equal("change CHG-1042", v.StateReason);
            var h = Assert.Single(v.History, h => h.Kind == "state");
            Assert.Equal(("olga", "Open", "Closed", "change CHG-1042"), (h.Actor, h.From, h.To, h.Reason));
        }
        var audit = await Audit("verdict.closed");
        Assert.Equal(4, audit.Count);
        Assert.All(audit, a => Assert.Equal("olga", a.Actor));
        Assert.Equal(Cves, audit.Select(a => a.Target[..13]).OrderBy(x => x).ToArray());
        // the same webhook a single Done sends, once per verdict
        Assert.Equal(4, _http.Calls.Count);
        Assert.All(_http.Calls, c => Assert.Equal(WebhookService.EventClosed, c.Header(WebhookService.EventHeader)));
    }

    [Fact]
    public async Task Verdicts_that_changed_since_the_page_loaded_are_skipped_and_reported()
    {
        var items = await Selection();
        var before = await Verdicts();
        // after the page loaded: someone else closes one, and the evaluator promotes another
        await _workflow.CloseAsync(before["CVE-2099-1001"].Id, "someone-else", "marked done");
        await using (var db = await _factory.CreateDbContextAsync())
            await db.Verdicts.Where(v => v.CveId == "CVE-2099-1002").ExecuteUpdateAsync(u => u.SetProperty(v => v.Tier, VerdictTier.FixToday));

        var r = await _workflow.BulkAsync(Olga, new BulkRequest(BulkAction.Snooze, items, "change window", DateTime.UtcNow.AddDays(7)));

        Assert.Equal(2, r.Changed);
        Assert.Equal(new[] { ("already closed", 1), ("now Fix today", 1) }, r.Skipped.OrderBy(x => x.Why).ToArray());
        Assert.Equal("2 snoozed. 2 skipped: 1 already closed, 1 now Fix today.", r.Summary);
        var after = await Verdicts();
        Assert.Equal(VerdictState.Closed, after["CVE-2099-1001"].State);
        Assert.Equal("someone-else", after["CVE-2099-1001"].StateOwner);
        Assert.Single(after["CVE-2099-1001"].History, h => h.Kind == "state");
        Assert.Equal(VerdictState.Open, after["CVE-2099-1002"].State);
        Assert.Equal(VerdictState.Snoozed, after["CVE-2099-1003"].State);
        Assert.Equal(VerdictState.Snoozed, after["CVE-2099-1004"].State);
    }

    [Fact]
    public async Task One_reason_for_skipping_reads_without_a_count_and_a_changed_again_verdict_is_caught_by_its_timestamp()
    {
        var before = await Verdicts();
        await _workflow.SnoozeAsync(before["CVE-2099-1001"].Id, "olga", DateTime.UtcNow.AddDays(1), "first");
        var items = await Selection();
        // snoozed again by someone else with a different date: the same state, but not what the page showed
        await _workflow.ReopenAsync(before["CVE-2099-1001"].Id, "someone-else");
        await _workflow.SnoozeAsync(before["CVE-2099-1001"].Id, "someone-else", DateTime.UtcNow.AddDays(30), "second");

        var r = await _workflow.BulkAsync(Olga, new BulkRequest(BulkAction.Reopen, items.Where(i => i.State == VerdictState.Snoozed).ToList()));

        Assert.Equal(0, r.Changed);
        Assert.Equal("0 re-opened. 1 skipped: changed since the page loaded.", r.Summary);
        Assert.Equal(VerdictState.Snoozed, (await Verdicts())["CVE-2099-1001"].State);
    }

    [Fact]
    public async Task Snooze_and_accept_risk_record_the_same_fields_as_the_single_actions_and_leave_what_is_not_open()
    {
        var before = await Verdicts();
        await _workflow.CloseAsync(before["CVE-2099-1004"].Id, "olga", "marked done");
        var items = await Selection();
        var until = new DateTime(2099, 3, 30, 0, 0, 0, DateTimeKind.Utc);

        var snoozed = await _workflow.BulkAsync(Olga, new BulkRequest(BulkAction.Snooze, items.Where(i => i.Id == before["CVE-2099-1001"].Id || i.Id == before["CVE-2099-1004"].Id).ToList(), null, until));
        var accepted = await _workflow.BulkAsync(Olga, new BulkRequest(BulkAction.AcceptRisk, items.Where(i => i.Id == before["CVE-2099-1002"].Id || i.Id == before["CVE-2099-1003"].Id).ToList(), "WAF in front", until, ""));

        Assert.Equal("1 snoozed. 1 skipped: not open.", snoozed.Summary);
        Assert.Equal("2 accepted as risk.", accepted.Summary);
        var after = await Verdicts();
        Assert.Equal(VerdictState.Snoozed, after["CVE-2099-1001"].State);
        Assert.Equal(until, after["CVE-2099-1001"].SnoozedUntil);
        Assert.Equal("snoozed (until " + until.ToString("d MMM yyyy") + ")", after["CVE-2099-1001"].StateReason);
        foreach (var cve in new[] { "CVE-2099-1002", "CVE-2099-1003" })
        {
            Assert.Equal(VerdictState.AcceptedRisk, after[cve].State);
            Assert.Equal("olga", after[cve].StateOwner);   // blank owner: the person doing it
            Assert.Equal("WAF in front", after[cve].StateReason);
            Assert.Equal(until, after[cve].AcceptedRiskExpiry);
            Assert.Contains(after[cve].History, h => h.Kind == "state" && h.To == "AcceptedRisk" && h.Actor == "olga");
        }
        Assert.Equal(2, (await Audit("verdict.acceptedrisk")).Count);
        Assert.Single(await Audit("verdict.snoozed"));

        await Assert.ThrowsAsync<ArgumentException>(() => _workflow.BulkAsync(Olga, new BulkRequest(BulkAction.Snooze, items)));   // no date
    }

    [Fact]
    public async Task Reopen_clears_what_parked_the_verdict()
    {
        await _workflow.BulkAsync(Olga, new BulkRequest(BulkAction.AcceptRisk, await Selection(), "accepted", DateTime.UtcNow.AddDays(30), "the board"));

        var r = await _workflow.BulkAsync(Olga, new BulkRequest(BulkAction.Reopen, await Selection()));

        Assert.Equal(4, r.Changed);
        Assert.All((await Verdicts()).Values, v =>
        {
            Assert.Equal(VerdictState.Open, v.State);
            Assert.Null(v.AcceptedRiskExpiry);
            Assert.Null(v.StateOwner);
            Assert.Contains(v.History, h => h.Kind == "state" && h.From == "AcceptedRisk" && h.To == "Open" && h.Reason == "re-opened manually");
        });
        Assert.Equal(4, (await Audit("verdict.open")).Count);
    }

    [Fact]
    public async Task The_batch_is_saved_as_one_so_a_failure_part_way_changes_nothing()
    {
        var items = await Selection();
        // the third audit entry cannot be written
        await using (var db = await _factory.CreateDbContextAsync())
            await db.Database.ExecuteSqlRawAsync("CREATE TRIGGER fail_one BEFORE INSERT ON \"Audit\" WHEN NEW.Target LIKE 'CVE-2099-1003%' BEGIN SELECT RAISE(ABORT, 'disk full'); END;");

        await Assert.ThrowsAnyAsync<Exception>(() => _workflow.BulkAsync(Olga, new BulkRequest(BulkAction.Done, items)));

        Assert.All((await Verdicts()).Values, v =>
        {
            Assert.Equal(VerdictState.Open, v.State);
            Assert.DoesNotContain(v.History, h => h.Kind == "state");
        });
        Assert.Empty(await Audit("verdict.closed"));
        Assert.Empty(_http.Calls);
    }

    [Fact]
    public async Task More_than_the_limit_is_refused()
    {
        var many = Enumerable.Range(0, MaxBulk + 1).Select(_ => new BulkItem(Guid.NewGuid(), VerdictState.Open, null, VerdictTier.FixToday)).ToList();
        await Assert.ThrowsAsync<ArgumentException>(() => _workflow.BulkAsync(Olga, new BulkRequest(BulkAction.Done, many)));
    }

    [Fact]
    public async Task A_verdict_removed_since_the_page_loaded_is_counted_as_skipped()
    {
        var items = await Selection();
        items.Add(new BulkItem(Guid.NewGuid(), VerdictState.Open, null, VerdictTier.FixThisWeek));
        var r = await _workflow.BulkAsync(Olga, new BulkRequest(BulkAction.Done, items));
        Assert.Equal("4 marked done. 1 skipped: removed since the page loaded.", r.Summary);
    }

    [Fact]
    public void The_confirmation_summarises_by_tier_most_urgent_first()
    {
        var tiers = Enumerable.Repeat(VerdictTier.FixThisWeek, 9).Concat(Enumerable.Repeat(VerdictTier.FixToday, 3));
        Assert.Equal("12 verdicts: 3 Fix today, 9 Fix this week", TierSummary(tiers));
        Assert.Equal("1 verdict: 1 Next patch cycle", TierSummary(new[] { VerdictTier.NextPatchCycle }));
    }

    [Fact]
    public void An_action_applies_in_the_same_states_as_the_single_buttons()
    {
        Assert.True(Applies(BulkAction.Done, VerdictState.Snoozed));
        Assert.False(Applies(BulkAction.Done, VerdictState.Closed));
        Assert.True(Applies(BulkAction.Snooze, VerdictState.Open));
        Assert.False(Applies(BulkAction.AcceptRisk, VerdictState.Snoozed));
        Assert.True(Applies(BulkAction.Reopen, VerdictState.Closed));
        Assert.False(Applies(BulkAction.Reopen, VerdictState.Open));
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
