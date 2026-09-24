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
/// Which CVE records a watchlist entry is matched against. Found on the demo estate: "Jenkins" was
/// matched to 1,400 Jenkins plugin CVEs and "GitLab" to GitLab Runner, because the "contains" fallback
/// ran even when the product's exact name had matched.
/// </summary>
public class ProductMatchingTests : IDisposable
{
    private readonly SqliteConnection _conn;
    private readonly TestDbFactory _factory;
    private readonly VerdictEvaluator _evaluator;

    public ProductMatchingTests()
    {
        _conn = new SqliteConnection("DataSource=:memory:");
        _conn.Open();
        _factory = new TestDbFactory(new DbContextOptionsBuilder<VvDbContext>().UseSqlite(_conn).Options);
        using (var db = _factory.CreateDbContext())
        {
            db.Database.EnsureCreated();
            Add(db, "CVE-2099-0001", "Jenkins Project", "Jenkins", "2.441");                        // core
            Add(db, "CVE-2099-0002", "Jenkins Project", "Jenkins Azure CLI Plugin", "0.10");        // a plugin
            Add(db, "CVE-2099-0003", "Jenkins Project", "Jenkins Pipeline: Groovy Plugin", "3000"); // another plugin
            Add(db, "CVE-2099-0004", "Microsoft", "Microsoft Exchange Server 2019 Cumulative Update 14", "15.02.1544.013");
            Add(db, "CVE-2099-0010", "Fortinet", "FortiOS", "7.2.6");                              // exact
            Add(db, "CVE-2099-0011", "Fortinet", "Fortinet FortiOS", "7.2.6");                     // vendor-prefixed: same product
            Add(db, "CVE-2099-0012", "Fortinet", "Fortinet FortiOS, FortiProxy", "7.2.6");         // a list naming it
            Add(db, "CVE-2099-0013", "Fortinet", "FortiOS and FortiProxy", "7.2.6");               // "and" list
            Add(db, "CVE-2099-0014", "Fortinet", "FortiOS-6K7K", "7.2.6");                         // a different product line
            db.SaveChanges();
        }
        var settings = new SettingsService(_factory, new PassthroughProtectionProvider());
        var webhooks = new WebhookService(_factory, settings, new FakeHttpClientFactory(new FakeHandler()), NullLogger<WebhookService>.Instance);
        _evaluator = new VerdictEvaluator(_factory, settings, new ServiceCollection().BuildServiceProvider(), webhooks, NullLogger<VerdictEvaluator>.Instance);
    }

    public void Dispose() => _conn.Dispose();

    private static void Add(VvDbContext db, string cve, string vendor, string product, string lessThan)
    {
        db.Cves.Add(new Cve { Id = cve, State = "PUBLISHED", RetrievedAt = DateTime.UtcNow, Description = "test record", CvssV31Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CvssV31Score = 9.8 });
        db.CveAffected.Add(new CveAffected
        {
            CveId = cve, Vendor = vendor, Product = product, VendorNorm = Normalizer.Norm(vendor), ProductNorm = Normalizer.Norm(product),
            DefaultStatus = "unaffected",
            VersionsJson = "[{\"version\":\"0\",\"status\":\"affected\",\"lessThan\":\"" + lessThan + "\",\"versionType\":\"custom\"}]",
        });
    }

    private async Task<List<string>> VerdictsFor(string vendor, string product, string? version)
    {
        var entry = new WatchlistEntry
        {
            Id = Guid.NewGuid(), Vendor = vendor, Product = product, VendorNorm = Normalizer.Norm(vendor), ProductNorm = Normalizer.Norm(product),
            Version = version, AssetName = "TEST-01", Exposure = Exposure.Internal, Criticality = Criticality.Standard,
        };
        await using (var db = await _factory.CreateDbContextAsync())
        {
            db.Watchlist.Add(entry);
            await db.SaveChangesAsync();
        }
        await _evaluator.EvaluateEntryAsync(entry.Id);
        await using var read = await _factory.CreateDbContextAsync();
        return await read.Verdicts.Where(v => v.WatchlistEntryId == entry.Id).Select(v => v.CveId).OrderBy(c => c).ToListAsync();
    }

    [Fact]
    public async Task Exact_product_match_does_not_pull_in_same_vendor_plugins()
    {
        var cves = await VerdictsFor("Jenkins Project", "Jenkins", "2.440");
        Assert.Equal(new[] { "CVE-2099-0001" }, cves);
    }

    [Fact]
    public async Task Vendor_prefixed_and_listed_names_still_match_alongside_the_exact_name()
    {
        var cves = await VerdictsFor("Fortinet", "FortiOS", "7.2.5");
        Assert.Equal(new[] { "CVE-2099-0010", "CVE-2099-0011", "CVE-2099-0012", "CVE-2099-0013" }, cves);
    }

    [Fact]
    public async Task Contains_fallback_still_finds_a_product_with_no_exact_match()
    {
        var cves = await VerdictsFor("Microsoft", "Exchange Server 2019", "15.02.1544.004");
        Assert.Equal(new[] { "CVE-2099-0004" }, cves);
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
