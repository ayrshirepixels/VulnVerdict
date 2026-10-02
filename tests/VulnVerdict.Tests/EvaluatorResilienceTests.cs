using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;
using VulnVerdict.Core.Feeds;
using VulnVerdict.Core.Services;
using Xunit;

namespace VulnVerdict.Tests;

/// <summary>
/// The evaluator under failure and change: OSV down does not stop the run (or the worker's digest), closed verdicts
/// re-open when they are affected again, a vendor's exploited-in-the-wild flag counts from any advisory, and the
/// attack story works for inventory verdicts.
/// </summary>
public class EvaluatorResilienceTests : IDisposable
{
    private const string Purl = "pkg:npm/lodash@4.17.20";
    private readonly SqliteConnection _conn;
    private readonly TestDbFactory _factory;
    private readonly SettingsService _settings;
    private readonly WebhookService _webhooks;

    public EvaluatorResilienceTests()
    {
        _conn = new SqliteConnection("DataSource=:memory:");
        _conn.Open();
        _factory = new TestDbFactory(new DbContextOptionsBuilder<VvDbContext>().UseSqlite(_conn).Options);
        using (var db = _factory.CreateDbContext()) db.Database.EnsureCreated();
        _settings = new SettingsService(_factory, new PassthroughProtectionProvider());
        _webhooks = new WebhookService(_factory, _settings, new FakeHttpClientFactory(new FakeHandler()), NullLogger<WebhookService>.Instance);
    }

    public void Dispose() => _conn.Dispose();

    private VerdictEvaluator Evaluator(IPackageVulnSource? osv = null, BundleService? bundles = null)
    {
        var services = new ServiceCollection();
        if (osv is not null) services.AddSingleton(osv);
        if (bundles is not null) services.AddSingleton(bundles);
        return new VerdictEvaluator(_factory, _settings, services.BuildServiceProvider(), _webhooks, NullLogger<VerdictEvaluator>.Instance);
    }

    private static void AddFortiOs(VvDbContext db, string cve, string fixedIn)
    {
        db.Cves.Add(new Cve { Id = cve, State = "PUBLISHED", RetrievedAt = DateTime.UtcNow, Description = "test record", CvssV31Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CvssV31Score = 9.8 });
        db.CveAffected.Add(new CveAffected
        {
            CveId = cve, Vendor = "Fortinet", Product = "FortiOS", VendorNorm = Normalizer.Norm("Fortinet"), ProductNorm = Normalizer.Norm("FortiOS"),
            DefaultStatus = "unaffected",
            VersionsJson = "[{\"version\":\"7.2.0\",\"status\":\"affected\",\"lessThan\":\"" + fixedIn + "\",\"versionType\":\"semver\"}]",
        });
    }

    private static Guid AddWatchlist(VvDbContext db, string version = "7.2.5")
    {
        var e = new WatchlistEntry
        {
            Id = Guid.NewGuid(), Vendor = "Fortinet", Product = "FortiOS", VendorNorm = Normalizer.Norm("Fortinet"), ProductNorm = Normalizer.Norm("FortiOS"),
            Version = version, AssetName = "FW-EDGE-01", Exposure = Exposure.Internet, Criticality = Criticality.Critical, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow,
        };
        db.Watchlist.Add(e);
        return e.Id;
    }

    /// <summary>An npm package seen on a live asset: evaluated through OSV.</summary>
    private static Guid AddPackage(VvDbContext db)
    {
        var asset = new Asset { Id = Guid.NewGuid(), DisplayName = "web-07.corp.example", Exposure = Exposure.Internet, Criticality = Criticality.Standard, FirstSeen = DateTime.UtcNow, LastSeen = DateTime.UtcNow };
        var sw = new SoftwareInstance
        {
            Id = Guid.NewGuid(), AssetId = asset.Id, Vendor = "", Product = "lodash", Version = "4.17.20", VendorNorm = "", ProductNorm = "lodash",
            Purl = Purl, Ecosystem = "npm", MappingStatus = MappingStatus.Package, ConnectorId = "test", FirstSeen = DateTime.UtcNow, LastSeen = DateTime.UtcNow,
        };
        db.Assets.Add(asset); db.Software.Add(sw);
        db.Cves.Add(new Cve { Id = "CVE-2099-2001", State = "PUBLISHED", RetrievedAt = DateTime.UtcNow, CvssV31Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" });
        return sw.Id;
    }

    private async Task<List<Verdict>> AllVerdicts()
    {
        await using var db = await _factory.CreateDbContextAsync();
        return await db.Verdicts.AsNoTracking().Include(v => v.History).ToListAsync();
    }

    // ------------------------------------------------------------------ 1: OSV down

    [Fact]
    public async Task OSV_failing_skips_only_the_package_and_is_retried_later()
    {
        Guid entry, sw;
        await using (var db = await _factory.CreateDbContextAsync())
        {
            AddFortiOs(db, "CVE-2099-1001", "7.2.8");
            entry = AddWatchlist(db); sw = AddPackage(db);
            await db.SaveChangesAsync();
        }
        var osv = new FakeOsv { Throw = true };

        var summary = await Evaluator(osv).EvaluateAllAsync();

        Assert.Equal(1, osv.Calls);   // one batch for the run, not one per package
        var verdicts = await AllVerdicts();
        Assert.Contains(verdicts, v => v.WatchlistEntryId == entry && v.CveId == "CVE-2099-1001");
        Assert.DoesNotContain(verdicts, v => v.SoftwareInstanceId == sw);
        Assert.NotNull(await _settings.GetStateAsync(SettingsService.Keys.LastEvaluation));
        var failed = JsonSerializer.Deserialize<VerdictEvaluator.FailedSubjects>((await _settings.GetStateAsync(VerdictEvaluator.FailedSubjectsKey))!)!;
        Assert.Equal(new[] { sw }, failed.Software);
        Assert.Empty(failed.Entries);
        Assert.True(failed.RetryAt > DateTime.UtcNow);

        // not yet due: nothing happens; once due and OSV is back, the package is evaluated and the failure cleared
        Assert.Null(await Evaluator(osv).RetryFailedAsync());
        await _settings.SetStateAsync(VerdictEvaluator.FailedSubjectsKey, JsonSerializer.Serialize(failed with { RetryAt = DateTime.UtcNow.AddMinutes(-1) }));
        osv.Throw = false;
        var retry = await Evaluator(osv).RetryFailedAsync();
        Assert.NotNull(retry);
        Assert.Equal(1, retry!.Entries);
        Assert.Contains(await AllVerdicts(), v => v.SoftwareInstanceId == sw && v.CveId == "CVE-2099-2001");
        Assert.Null(await _settings.GetStateAsync(VerdictEvaluator.FailedSubjectsKey));
    }

    [Fact]
    public async Task OSV_failing_falls_back_to_the_cached_result()
    {
        Guid sw;
        await using (var db = await _factory.CreateDbContextAsync())
        {
            sw = AddPackage(db);
            db.PackageVulns.Add(new PackageVulnCache
            {
                Key = Purl + "@4.17.20", FetchedAt = DateTime.UtcNow.AddDays(-3),
                ResultJson = JsonSerializer.Serialize(new List<PackageVuln> { new(Purl + "@4.17.20", "CVE-2099-2001", "4.17.21", "OSV GHSA-test") }),
            });
            await db.SaveChangesAsync();
        }

        await Evaluator(new FakeOsv { Throw = true }).EvaluateAllAsync();

        Assert.Contains(await AllVerdicts(), v => v.SoftwareInstanceId == sw && v.CveId == "CVE-2099-2001" && v.FixedIn == "4.17.21");
        Assert.Null(await _settings.GetStateAsync(VerdictEvaluator.FailedSubjectsKey));
    }

    [Fact]
    public async Task Bundle_mode_never_calls_OSV()
    {
        await using (var db = await _factory.CreateDbContextAsync()) { AddPackage(db); await db.SaveChangesAsync(); }
        var s = await _settings.LoadAsync();
        s.BundleUrl = "https://bundles.example.invalid";
        await _settings.SaveAsync(s, "test");
        var bundles = new BundleService(_factory, _settings, new FakeHttpClientFactory(new FakeHandler()), new WorkerOptions(), NullLogger<BundleService>.Instance);
        var osv = new FakeOsv();

        await Evaluator(osv, bundles).EvaluateAllAsync();

        Assert.Equal(0, osv.Calls);
        Assert.Null(await _settings.GetStateAsync(VerdictEvaluator.FailedSubjectsKey));
    }

    [Fact]
    public async Task Worker_pass_still_runs_the_digest_when_OSV_is_down()
    {
        var path = Path.Combine(Path.GetTempPath(), "vv-worker-" + Guid.NewGuid().ToString("N") + ".db");
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IDataProtectionProvider>(new PassthroughProtectionProvider());
        services.AddVulnVerdictCore("sqlite", "Data Source=" + path + ";Pooling=False", new WorkerOptions { DataDir = Path.GetTempPath() }, "web");
        services.RemoveAll<IFeed>();
        services.RemoveAll<IPackageVulnSource>();
        services.AddSingleton<IPackageVulnSource>(new FakeOsv { Throw = true });
        services.AddSingleton<IHttpClientFactory>(new FakeHttpClientFactory(new FakeHandler()));
        await using var sp = services.BuildServiceProvider();
        try
        {
            await CoreServices.InitialiseDatabaseAsync(sp);
            var factory = sp.GetRequiredService<IDbContextFactory<VvDbContext>>();
            await using (var db = await factory.CreateDbContextAsync())
            {
                AddFortiOs(db, "CVE-2099-1001", "7.2.8");
                AddWatchlist(db); AddPackage(db);
                await db.SaveChangesAsync();
            }
            var settings = sp.GetRequiredService<SettingsService>();
            var s = await settings.LoadAsync();
            s.DigestTime = "00:00"; s.DigestWeekdaysOnly = false;
            await settings.SaveAsync(s, "test");

            var worker = new WorkerService(sp, NullLogger<WorkerService>.Instance, sp.GetRequiredService<WorkerOptions>());
            await worker.RunPassAsync(CancellationToken.None);

            await using (var db = await factory.CreateDbContextAsync())
                Assert.True(await db.Verdicts.AnyAsync(v => v.CveId == "CVE-2099-1001"));
            Assert.NotNull(await settings.GetStateAsync(SettingsService.Keys.LastEvaluation));
            Assert.NotNull(await settings.GetStateAsync(SettingsService.Keys.LastDailyDigest));
            Assert.NotNull(await settings.GetStateAsync(VerdictEvaluator.FailedSubjectsKey));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            foreach (var f in new[] { path, path + "-wal", path + "-shm" }) try { File.Delete(f); } catch (IOException) { }
        }
    }

    // ------------------------------------------------------------------ 2: re-opening

    [Fact]
    public async Task Auto_closed_verdict_reopens_when_affected_again()
    {
        Guid entry;
        await using (var db = await _factory.CreateDbContextAsync())
        {
            AddFortiOs(db, "CVE-2099-1001", "7.2.8");
            entry = AddWatchlist(db, "7.2.5");
            await db.SaveChangesAsync();
        }
        var evaluator = Evaluator();
        await evaluator.EvaluateAllAsync();
        // upgraded to the fixed version: the system closes it as patched
        await using (var db = await _factory.CreateDbContextAsync()) await db.Watchlist.Where(w => w.Id == entry).ExecuteUpdateAsync(u => u.SetProperty(w => w.Version, "7.2.8"));
        await evaluator.EvaluateAllAsync();
        var closed = Assert.Single(await AllVerdicts());
        Assert.Equal(VerdictState.Closed, closed.State);
        Assert.Equal("system", closed.StateOwner);

        // the CNA widens the range: 7.2.8 is affected after all
        await using (var db = await _factory.CreateDbContextAsync())
            await db.CveAffected.ExecuteUpdateAsync(u => u.SetProperty(a => a.VersionsJson, "[{\"version\":\"7.2.0\",\"status\":\"affected\",\"lessThan\":\"7.2.9\",\"versionType\":\"semver\"}]"));
        await evaluator.EvaluateAllAsync();

        var v = Assert.Single(await AllVerdicts());
        Assert.Equal(VerdictState.Open, v.State);
        Assert.True(v.Tier > VerdictTier.NotAffected);
        Assert.Null(v.StateOwner);
        Assert.Contains(v.History, h => h.Kind == "state" && h.From == "Closed" && h.To == "Open" && h.Reason == "re-opened: affected again at 7.2.8");
        Assert.Contains(v.History, h => h.Kind == "tier" && h.From == nameof(VerdictTier.NotAffected) && h.Reason!.Contains("(re-opened)"));
        Assert.Null(v.ImmediateEmailSentAt);
    }

    [Fact]
    public async Task Human_done_reopens_when_added_to_KEV_and_not_before()
    {
        Guid entry;
        await using (var db = await _factory.CreateDbContextAsync())
        {
            AddFortiOs(db, "CVE-2099-1001", "7.2.8");
            entry = AddWatchlist(db);
            await db.SaveChangesAsync();
        }
        var evaluator = Evaluator();
        await evaluator.EvaluateAllAsync();
        var workflow = new VerdictWorkflow(_factory, _settings, _webhooks, new WatchlistService(_factory, evaluator));
        var before = Assert.Single(await AllVerdicts());
        Assert.True(before.Tier < VerdictTier.FixToday);
        await workflow.DoneAsync(before.Id, "tester", null, updateWatchlist: false, note: null);

        // nothing new: a person's "done" stands
        await evaluator.EvaluateAllAsync();
        Assert.Equal(VerdictState.Closed, Assert.Single(await AllVerdicts()).State);

        await using (var db = await _factory.CreateDbContextAsync())
        {
            db.Kev.Add(new KevEntry { CveId = "CVE-2099-1001", DateAdded = DateTime.UtcNow.Date, RetrievedAt = DateTime.UtcNow });
            await db.SaveChangesAsync();
        }
        await evaluator.EvaluateAllAsync();

        var v = Assert.Single(await AllVerdicts());
        Assert.Equal(VerdictState.Open, v.State);
        Assert.Equal(VerdictTier.FixToday, v.Tier);
        Assert.Contains(v.History, h => h.Kind == "state" && h.To == "Open" && h.Reason == "re-opened: now in CISA KEV");
        Assert.Contains(v.History, h => h.Kind == "tier" && h.To == nameof(VerdictTier.FixToday) && h.Reason == "now in CISA KEV (re-opened)");
    }

    // ------------------------------------------------------------------ 3: vendor exploited-in-the-wild

    [Fact]
    public async Task Exploited_in_the_wild_counts_from_any_vendor_advisory()
    {
        await using (var db = await _factory.CreateDbContextAsync())
        {
            AddFortiOs(db, "CVE-2099-1001", "7.2.8");
            AddWatchlist(db);
            for (var i = 0; i < 3; i++)
                db.Advisories.Add(new Advisory
                {
                    Vendor = "fortinet", AdvisoryId = "FG-IR-99-00" + i, Title = "advisory " + i, CveIdsJson = "[\"CVE-2099-1001\"]",
                    Published = DateTime.UtcNow.AddDays(-30 + i * 10), ExploitedInTheWild = i == 0, RetrievedAt = DateTime.UtcNow,
                });
            await db.SaveChangesAsync();
        }

        await Evaluator().EvaluateAllAsync();

        var v = Assert.Single(await AllVerdicts());
        Assert.Equal(Exploitation.Active, v.Exploitation);
        Assert.Contains("FG-IR-99-000", v.EvidenceJson);   // the oldest, flagged one, is in the evidence
        Assert.Contains("FG-IR-99-002", v.EvidenceJson);
    }

    // ------------------------------------------------------------------ 4: attack story for inventory verdicts

    [Fact]
    public async Task Attack_story_for_an_inventory_verdict_sends_product_not_asset()
    {
        var verdictId = Guid.NewGuid();
        await using (var db = await _factory.CreateDbContextAsync())
        {
            var sw = AddPackage(db);
            await db.SaveChangesAsync();
            var assetId = (await db.Software.FirstAsync(s => s.Id == sw)).AssetId;
            db.Verdicts.Add(new Verdict
            {
                Id = verdictId, CveId = "CVE-2099-2001", SoftwareInstanceId = sw, AssetId = assetId, Tier = VerdictTier.FixThisWeek, State = VerdictState.Open,
                DeclaredExposure = Exposure.Internet, EffectiveExposure = Exposure.Internet, Criticality = Criticality.Standard, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow,
            });
            await db.SaveChangesAsync();
        }
        var s = await _settings.LoadAsync();
        s.LlmProvider = "openai-compatible"; s.LlmModel = "test-model"; s.LlmBaseUrl = "http://llm.test/v1";
        await _settings.SaveAsync(s, "test");
        var handler = new FakeHandler().On(HttpMethod.Post, "/chat/completions", "{\"choices\":[{\"message\":{\"content\":\"An attacker on the internet could try.\"}}]}");
        var llm = new LlmService(_factory, _settings, new FakeHttpClientFactory(handler), NullLogger<LlmService>.Instance);

        var story = await llm.AttackStoryAsync(verdictId);

        Assert.Equal("An attacker on the internet could try.", story.Text);
        var sent = Assert.Single(handler.Calls).Body!;
        Assert.Contains("The organisation runs: lodash 4.17.20", sent);
        Assert.DoesNotContain("web-07", sent);
    }

    // ------------------------------------------------------------------ fakes

    private sealed class FakeOsv : IPackageVulnSource
    {
        public bool Throw;
        public int Calls;
        public Task<IReadOnlyList<PackageVuln>> LookupAsync(IEnumerable<PackageQuery> queries, CancellationToken ct)
        {
            Calls++;
            if (Throw) throw new HttpRequestException("OSV POST https://api.osv.dev/v1/querybatch returned HTTP 503");
            return Task.FromResult<IReadOnlyList<PackageVuln>>(queries.Select(q => new PackageVuln(q.Key, "CVE-2099-2001", "4.17.21", "OSV GHSA-test")).ToList());
        }
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
