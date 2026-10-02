using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

/// <summary>
/// A partial, truncated or collapsed run must never read as "this is gone": no software marked removed, no finding
/// purged, no asset aged out, until a complete run (or the same reduced list three times) says so.
/// </summary>
public class PartialRunTests : IDisposable
{
    private readonly SqliteConnection _conn;
    private readonly TestDbFactory _factory;

    public PartialRunTests()
    {
        _conn = new SqliteConnection("DataSource=:memory:");
        _conn.Open();
        _factory = new TestDbFactory(new DbContextOptionsBuilder<VvDbContext>().UseSqlite(_conn).Options);
        using var db = _factory.CreateDbContext();
        db.Database.EnsureCreated();
    }

    public void Dispose() => _conn.Dispose();

    private InventoryService Svc() => new(_factory, NullLogger<InventoryService>.Instance);

    private VerdictEvaluator Evaluator()
    {
        var settings = new SettingsService(_factory, new PassthroughProtectionProvider());
        var webhooks = new WebhookService(_factory, settings, new FakeHttpClientFactory(new FakeHandler()), NullLogger<WebhookService>.Instance);
        return new VerdictEvaluator(_factory, settings, new ServiceCollection().BuildServiceProvider(), webhooks, NullLogger<VerdictEvaluator>.Instance);
    }

    /// <summary>A connector that exists in the database, as it does when the worker runs it.</summary>
    private Connector Conn(string adapter, string name)
    {
        var c = new Connector { Id = Guid.NewGuid(), AdapterId = adapter, DisplayName = name, Enabled = true, CreatedAt = DateTime.UtcNow };
        using var db = _factory.CreateDbContext();
        db.Connectors.Add(c);
        db.SaveChanges();
        return c;
    }

    private static void AddHost(CollectResult r, string id, params string[] products)
    {
        r.Assets.Add(new AssetRecord(id, id.ToUpperInvariant(), AssetKind.Server, new[] { id + ".corp.local" }, Array.Empty<string>(), Array.Empty<string>()));
        r.Software.Add(new SoftwareRecord(id, "Microsoft", "Windows Server 2022", "10.0.20348.2000", SoftwareKind.OperatingSystem, ExternalId: "os"));
        foreach (var p in products) r.Software.Add(new SoftwareRecord(id, "Acme", p, "1.0", ExternalId: "app:" + p));
    }

    private static string[] Apps(int n) => Enumerable.Range(1, n).Select(i => "Tool " + i).ToArray();

    private async Task<List<string>> ActiveProducts(string host)
    {
        await using var db = _factory.CreateDbContext();
        var asset = await db.Assets.FirstAsync(a => a.DisplayName == host.ToUpperInvariant());
        return await db.Software.Where(s => s.AssetId == asset.Id).Select(s => s.Product).OrderBy(p => p).ToListAsync();
    }

    // ------------------------------------------------------------------ A1: the Partial flag

    [Fact]
    public async Task Partial_run_removes_nothing_purges_nothing_and_does_not_age_out_the_assets_it_missed()
    {
        var svc = Svc(); var c = Conn("pdq-connect", "PDQ");
        var full = new CollectResult();
        AddHost(full, "a", "Chrome", "7-Zip"); AddHost(full, "b", "Chrome");
        full.Findings.Add(new FindingRecord("a", new[] { "CVE-2026-0001" }));
        full.Findings.Add(new FindingRecord("b", new[] { "CVE-2026-0002" }));
        await svc.ApplyAsync(c, full);

        // a truncated listing: host B is missing, host A lost a row and its finding
        var partial = new CollectResult { Partial = true };
        AddHost(partial, "a", "Chrome");
        await svc.ApplyAsync(c, partial);
        Assert.Contains("7-Zip", await ActiveProducts("a"));

        Guid verdictId;
        await using (var db = _factory.CreateDbContext())
        {
            Assert.Equal(2, await db.Findings.CountAsync());
            // B has not been seen for 100 days as far as the asset row says: stale and archive territory
            var b = await db.Assets.FirstAsync(x => x.DisplayName == "B");
            b.LastSeen = DateTime.UtcNow.AddDays(-100);
            var v = new Verdict { Id = Guid.NewGuid(), CveId = "CVE-2026-0002", AssetId = b.Id, Subject = "Chrome on B", Tier = VerdictTier.FixToday, Sentence = "x", CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow, LastEvaluatedAt = DateTime.UtcNow };
            db.Cves.Add(new Cve { Id = v.CveId, State = "PUBLISHED", RetrievedAt = DateTime.UtcNow });
            db.Verdicts.Add(v); verdictId = v.Id;
            await db.SaveChangesAsync();
            Assert.Contains(b.Id, await InventoryService.HeldByPartialRunsAsync(db));
        }
        await Evaluator().EvaluateAllAsync();
        Assert.Equal(0, (await svc.HousekeepAsync()).Archived);
        await using (var db = _factory.CreateDbContext())
            Assert.Equal(VerdictState.Open, (await db.Verdicts.FirstAsync(v => v.Id == verdictId)).State);

        // a complete run that still does not list B: now it has really been missed, and A's list is the whole list
        var complete = new CollectResult();
        AddHost(complete, "a", "Chrome");
        await svc.ApplyAsync(c, complete);
        Assert.DoesNotContain("7-Zip", await ActiveProducts("a"));
        await using (var db = _factory.CreateDbContext())
        {
            Assert.Empty(await InventoryService.HeldByPartialRunsAsync(db));
            // A was listed in full without its finding (resolved); B was not listed, so its finding stays
            Assert.Equal("CVE-2026-0002", Assert.Single(await db.Findings.ToListAsync()).RawRef);
        }
        await Evaluator().EvaluateAllAsync();
        await using (var db = _factory.CreateDbContext())
        {
            var v = await db.Verdicts.FirstAsync(x => x.Id == verdictId);
            Assert.Equal(VerdictState.Closed, v.State);
            Assert.Contains("asset not seen since", v.StateReason);
        }
        Assert.Equal(1, (await svc.HousekeepAsync()).Archived);
    }

    [Fact]
    public async Task Partial_hold_does_not_cover_a_disabled_connector_or_an_asset_a_complete_run_already_missed()
    {
        var svc = Svc(); var c = Conn("pdq-connect", "PDQ");
        var both = new CollectResult(); AddHost(both, "a"); AddHost(both, "b");
        await svc.ApplyAsync(c, both);
        var onlyA = new CollectResult(); AddHost(onlyA, "a");
        await svc.ApplyAsync(c, onlyA);                 // complete: B is missed for real
        var partial = new CollectResult { Partial = true }; AddHost(partial, "a");
        await svc.ApplyAsync(c, partial);

        await using var db = _factory.CreateDbContext();
        var a = await db.Assets.FirstAsync(x => x.DisplayName == "A");
        var held = await InventoryService.HeldByPartialRunsAsync(db);
        Assert.Equal(new[] { a.Id }, held);             // A is held (seen since), B is not

        await db.Connectors.ExecuteUpdateAsync(u => u.SetProperty(x => x.Enabled, false));
        Assert.Empty(await InventoryService.HeldByPartialRunsAsync(db));
    }

    // ------------------------------------------------------------------ A2: the per-asset floor

    [Fact]
    public async Task A_list_that_loses_more_than_half_its_rows_is_held_until_the_same_list_is_seen_three_times()
    {
        var svc = Svc(); var c = Conn("winrm", "WinRM");
        var full = new CollectResult(); AddHost(full, "srv", Apps(12));
        await svc.ApplyAsync(c, full);
        Assert.Equal(13, (await ActiveProducts("srv")).Count);

        for (var run = 1; run <= 2; run++)
        {
            var reduced = new CollectResult(); AddHost(reduced, "srv", "Tool 1", "Tool 2");
            await svc.ApplyAsync(c, reduced);
            Assert.Equal(13, (await ActiveProducts("srv")).Count);
            var w = Assert.Single(reduced.Warnings);
            Assert.Contains("SRV (13 to 3 rows, run " + run + " of 3)", w);
            Assert.Contains("nothing was marked removed", w);
        }

        // third run in a row with the same reduced list: a real mass uninstall, accepted
        var third = new CollectResult(); AddHost(third, "srv", "Tool 1", "Tool 2");
        await svc.ApplyAsync(c, third);
        Assert.Empty(third.Warnings);
        Assert.Equal(new[] { "Tool 1", "Tool 2", "Windows Server 2022" }, await ActiveProducts("srv"));
    }

    [Fact]
    public async Task The_floor_counts_consecutive_runs_of_the_same_list_and_a_recovered_list_resets_it()
    {
        var svc = Svc(); var c = Conn("winrm", "WinRM");
        var full = new CollectResult(); AddHost(full, "srv", Apps(12));
        await svc.ApplyAsync(c, full);

        var reduced = new CollectResult(); AddHost(reduced, "srv", "Tool 1");
        await svc.ApplyAsync(c, reduced);
        Assert.Contains("run 1 of 3", Assert.Single(reduced.Warnings));

        // a different reduced list starts the count again
        var other = new CollectResult(); AddHost(other, "srv", "Tool 2");
        await svc.ApplyAsync(c, other);
        Assert.Contains("run 1 of 3", Assert.Single(other.Warnings));

        // the full list comes back (the read had failed): nothing was ever removed, and the hold is cleared
        var back = new CollectResult(); AddHost(back, "srv", Apps(12));
        await svc.ApplyAsync(c, back);
        Assert.Empty(back.Warnings);
        Assert.Equal(13, (await ActiveProducts("srv")).Count);

        var again = new CollectResult(); AddHost(again, "srv", "Tool 1");
        await svc.ApplyAsync(c, again);
        Assert.Contains("run 1 of 3", Assert.Single(again.Warnings));
    }

    [Fact]
    public async Task A_list_that_comes_back_as_the_operating_system_alone_is_held_and_small_changes_are_not()
    {
        var svc = Svc(); var c = Conn("ninjaone", "NinjaOne");
        var full = new CollectResult(); AddHost(full, "pc", Apps(6));            // 7 rows: under the ten-row floor
        AddHost(full, "kiosk", "Chrome", "7-Zip");
        await svc.ApplyAsync(c, full);

        var osOnly = new CollectResult(); AddHost(osOnly, "pc"); AddHost(osOnly, "kiosk", "Chrome");
        await svc.ApplyAsync(c, osOnly);
        Assert.Equal(7, (await ActiveProducts("pc")).Count);                      // held
        Assert.Contains("PC (7 to 1 rows", Assert.Single(osOnly.Warnings));
        Assert.Equal(new[] { "Chrome", "Windows Server 2022" }, await ActiveProducts("kiosk")); // an ordinary uninstall goes through
    }

    // ------------------------------------------------------------------ A3: findings purge scope, and scoped keeps

    [Fact]
    public async Task Findings_are_purged_only_for_assets_listed_completely_this_run_or_dropped_long_ago()
    {
        var svc = Svc(); var c = Conn("defender-endpoint", "Defender");
        var first = new CollectResult();
        foreach (var id in new[] { "a", "b", "c", "d" })
        {
            AddHost(first, id, "Chrome");
            first.Findings.Add(new FindingRecord(id, new[] { "CVE-2026-100" + id[0] % 10 }, RawRef: "f-" + id));
        }
        await svc.ApplyAsync(c, first);
        await using (var db = _factory.CreateDbContext())
        {
            // D left the source long ago: its link to this connector is older than the stale horizon
            var d = await db.Assets.FirstAsync(x => x.DisplayName == "D");
            await db.AssetSources.Where(s => s.AssetId == d.Id).ExecuteUpdateAsync(u => u.SetProperty(s => s.LastSeen, DateTime.UtcNow.AddDays(-40)));
        }

        // A: listed in full, finding gone -> purged. B: listed but incomplete -> kept. C: not listed this run -> kept. D: purged.
        var second = new CollectResult();
        AddHost(second, "a", "Chrome"); AddHost(second, "b", "Chrome");
        second.IncompleteSoftware.Add("b");
        await svc.ApplyAsync(c, second);
        await using (var db = _factory.CreateDbContext())
            Assert.Equal(new[] { "f-b", "f-c" }, (await db.Findings.Select(f => f.RawRef!).ToListAsync()).OrderBy(x => x).ToArray());
    }

    [Fact]
    public async Task Rows_under_an_unread_prefix_are_kept_while_the_rest_of_the_asset_is_still_a_full_snapshot()
    {
        var svc = Svc(); var c = Conn("ssh-linux", "Linux");
        CollectResult Run(bool containers, bool curl)
        {
            var r = new CollectResult();
            r.Assets.Add(new AssetRecord("web01", "WEB01", AssetKind.Server, new[] { "web01" }, Array.Empty<string>(), Array.Empty<string>()));
            r.Software.Add(new SoftwareRecord("web01", "Canonical", "Ubuntu", "22.04", SoftwareKind.OperatingSystem, ExternalId: "os"));
            if (curl) r.Software.Add(new SoftwareRecord("web01", "Ubuntu", "curl", "7.81.0", SoftwareKind.Package, ExternalId: "deb:curl:amd64"));
            if (containers) r.Software.Add(new SoftwareRecord("web01", "container", "nginx", "1.25.3", ExternalId: "container:web"));
            return r;
        }
        await svc.ApplyAsync(c, Run(containers: true, curl: true));

        // docker unreadable this run: the container row stays, the uninstalled package still goes
        var unread = Run(containers: false, curl: false);
        unread.KeepRows("web01", "container:");
        await svc.ApplyAsync(c, unread);
        Assert.Equal(new[] { "Ubuntu", "nginx" }, await ActiveProducts("web01"));

        // docker readable again and the container is gone: removed
        await svc.ApplyAsync(c, Run(containers: false, curl: false));
        Assert.Equal(new[] { "Ubuntu" }, await ActiveProducts("web01"));
    }

    // ------------------------------------------------------------------ fakes

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
