using System.Runtime.CompilerServices;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

/// <summary>Contexts over one open SQLite connection, for services that take a factory.</summary>
internal sealed class SharedDbFactory : IDbContextFactory<VvDbContext>
{
    private readonly DbContextOptions<VvDbContext> _options;
    public SharedDbFactory(System.Data.Common.DbConnection connection) => _options = new DbContextOptionsBuilder<VvDbContext>().UseSqlite(connection).Options;
    public VvDbContext CreateDbContext() => new(_options);
    public Task<VvDbContext> CreateDbContextAsync(CancellationToken ct = default) => Task.FromResult(CreateDbContext());
}

/// <summary>A reversible stand-in for data protection whose output is visibly not the input, so a test can tell a stored secret was encrypted.</summary>
internal sealed class MarkingProtectionProvider : IDataProtectionProvider, IDataProtector
{
    private static readonly byte[] Mark = "ENC:"u8.ToArray();
    public IDataProtector CreateProtector(string purpose) => this;
    public byte[] Protect(byte[] plaintext) => Mark.Concat(plaintext.Reverse()).ToArray();
    public byte[] Unprotect(byte[] protectedData)
    {
        if (!protectedData.AsSpan().StartsWith(Mark)) throw new System.Security.Cryptography.CryptographicException("not protected by this provider");
        return protectedData.Skip(Mark.Length).Reverse().ToArray();
    }
}

internal static class TestSettings
{
    /// <summary>A settings service over the same in-memory database as <paramref name="db"/>.</summary>
    public static SettingsService For(VvDbContext db) => new(new SharedDbFactory(db.Database.GetDbConnection()), new MarkingProtectionProvider());
}

/// <summary>An in-memory database with the services the evaluator needs, and helpers to seed the usual FortiOS watchlist case.</summary>
internal sealed class EvaluatorHarness : IDisposable
{
    private readonly SqliteConnection _conn;
    public SharedDbFactory Factory { get; }
    public SettingsService Settings { get; }
    public WebhookService Webhooks { get; }

    public EvaluatorHarness()
    {
        _conn = new SqliteConnection("DataSource=:memory:");
        _conn.Open();
        Factory = new SharedDbFactory(_conn);
        using (var db = Factory.CreateDbContext()) db.Database.EnsureCreated();
        Settings = new SettingsService(Factory, new MarkingProtectionProvider());
        Webhooks = new WebhookService(Factory, Settings, new FakeHttpClientFactory(new FakeHandler()), NullLogger<WebhookService>.Instance);
    }

    public void Dispose() => _conn.Dispose();

    public VerdictEvaluator Evaluator(Action<IServiceCollection>? configure = null)
    {
        var services = new ServiceCollection();
        configure?.Invoke(services);
        return new VerdictEvaluator(Factory, Settings, services.BuildServiceProvider(), Webhooks, NullLogger<VerdictEvaluator>.Instance);
    }

    public const string Cve = "CVE-2099-1001";

    /// <summary>A network-reachable CVE in a product, affected by <paramref name="versionsJson"/>.</summary>
    public static void AddCve(VvDbContext db, string cve, string vendor, string product, string versionsJson)
    {
        db.Cves.Add(new Cve { Id = cve, State = "PUBLISHED", RetrievedAt = DateTime.UtcNow, Description = "test record", CvssV31Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CvssV31Score = 9.8 });
        db.CveAffected.Add(new CveAffected { CveId = cve, Vendor = vendor, Product = product, VendorNorm = Normalizer.Norm(vendor), ProductNorm = Normalizer.Norm(product), DefaultStatus = "unaffected", VersionsJson = versionsJson });
    }

    public static void AddFortiOs(VvDbContext db, string cve = Cve, string fixedIn = "7.2.8") =>
        AddCve(db, cve, "Fortinet", "FortiOS", "[{\"version\":\"7.2.0\",\"status\":\"affected\",\"lessThan\":\"" + fixedIn + "\",\"versionType\":\"semver\"}]");

    public static Guid AddWatchlist(VvDbContext db, string vendor = "Fortinet", string product = "FortiOS", string? version = "7.2.5", string asset = "FW-EDGE-01")
    {
        var e = new WatchlistEntry
        {
            Id = Guid.NewGuid(), Vendor = vendor, Product = product, VendorNorm = Normalizer.Norm(vendor), ProductNorm = Normalizer.Norm(product),
            Version = version, AssetName = asset, Exposure = Exposure.Internet, Criticality = Criticality.Critical, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow,
        };
        db.Watchlist.Add(e);
        return e.Id;
    }

    public async Task<List<Verdict>> VerdictsAsync()
    {
        await using var db = await Factory.CreateDbContextAsync();
        return await db.Verdicts.AsNoTracking().Include(v => v.History).ToListAsync();
    }

    public async Task SeedAsync(Action<VvDbContext> seed)
    {
        await using var db = await Factory.CreateDbContextAsync();
        seed(db);
        await db.SaveChangesAsync();
    }
}

internal static class Fixtures
{
    public static string Read(string folder, string name, [CallerFilePath] string path = "") => File.ReadAllText(Path.Combine(Path.GetDirectoryName(path)!, "Fixtures", folder, name));
}
