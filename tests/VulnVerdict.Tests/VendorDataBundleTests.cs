using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Digest;
using VulnVerdict.Core.Engine;
using VulnVerdict.Core.Feeds;
using VulnVerdict.Core.Feeds.Psirt;
using VulnVerdict.Core.Feeds.Vex;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

/// <summary>
/// Vendor VEX statements and end-of-life dates in signed bundles, the feeds staying silent when the console is fed by
/// bundles, the digest line, and the Cisco credentials moving into the encrypted settings.
/// </summary>
public class VendorDataBundleTests
{
    private static readonly DateTime Built = new(2026, 10, 2, 8, 0, 0, DateTimeKind.Utc);

    private sealed class Db : IDisposable
    {
        private readonly SqliteConnection _conn;
        public VvDbContext Context { get; }
        public Db()
        {
            _conn = new SqliteConnection("Data Source=:memory:");
            _conn.Open();
            Context = new VvDbContext(new DbContextOptionsBuilder<VvDbContext>().UseSqlite(_conn).Options);
            Context.Database.EnsureCreated();
        }
        public void Dispose() { Context.Dispose(); _conn.Dispose(); }
    }

    private sealed class TempDir : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "vv-extras-test-" + Guid.NewGuid().ToString("N"));
        public TempDir() => Directory.CreateDirectory(Path);
        public void Dispose() { try { Directory.Delete(Path, true); } catch { } }
    }

    private static ECDsa PublicOf(ECDsa key)
    {
        var pub = ECDsa.Create();
        pub.ImportFromPem(key.ExportSubjectPublicKeyInfoPem());
        return pub;
    }

    private static VexStatement Statement(string cve, string product, VexStatus status, string? version = null, string? platform = null) => new()
    {
        Provider = "redhat", DocumentId = cve, CveId = cve, Status = status, Vendor = "Red Hat", VendorNorm = "redhat", Product = product, ProductNorm = Normalizer.Norm(product), Version = version,
        Platform = platform, PlatformNorm = platform is null ? null : Normalizer.Norm(platform), PlatformCpe = platform is null ? null : "cpe:/o:redhat:enterprise_linux:9",
        Purl = "pkg:rpm/redhat/" + product, Justification = status == VexStatus.KnownNotAffected ? "vulnerable_code_not_present" : null, Detail = status == VexStatus.Fixed ? "vendor_fix: https://access.redhat.com/errata/RHSA-2099:4312" : null,
        Url = "https://security.access.redhat.com/data/csaf/v2/vex/2099/" + cve.ToLowerInvariant() + ".json", DocumentDate = Built.AddDays(-3), Revision = "2", RetrievedAt = Built
    };

    /// <summary>The central service's side: every statement it has, and the end-of-life data.</summary>
    private static async Task SeedSourceAsync(VvDbContext db)
    {
        db.VexStatements.AddRange(
            Statement("CVE-2099-1001", "openssl", VexStatus.Fixed, "3.0.7-28.el9_4", "Red Hat Enterprise Linux 9"),
            Statement("CVE-2099-1001", "openssl-libs", VexStatus.Fixed, "3.0.7-28.el9_4", "Red Hat Enterprise Linux 9"),
            Statement("CVE-2099-1002", "curl", VexStatus.KnownNotAffected, platform: "Red Hat Enterprise Linux 9"),
            Statement("CVE-2099-1003", "zlib", VexStatus.KnownAffected, platform: "Red Hat Enterprise Linux 9"));
        using var doc = JsonDocument.Parse(Fixtures.Read("eol", "products_full.json"));
        db.EolCycles.AddRange(EndOfLifeFeed.Parse(doc.RootElement, Built));
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
    }

    /// <summary>The console's side: openssl and curl installed, nothing else.</summary>
    private static async Task SeedConsoleAsync(VvDbContext db)
    {
        var asset = new Asset { Id = Guid.NewGuid(), DisplayName = "web-01", FirstSeen = Built, LastSeen = Built };
        db.Assets.Add(asset);
        foreach (var name in new[] { "openssl", "curl" })
            db.Software.Add(new SoftwareInstance { Id = Guid.NewGuid(), AssetId = asset.Id, Vendor = "Red Hat Enterprise Linux", Product = name, Version = "1.0", VendorNorm = "redhatenterpriselinux", ProductNorm = name, Ecosystem = "Red Hat:enterprise_linux:9::baseos", ConnectorId = "test", FirstSeen = Built, LastSeen = Built });
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
    }

    // ---- bundles -----------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Bundle_carries_vex_statements_and_end_of_life_dates_and_the_console_keeps_what_concerns_it()
    {
        using var src = new Db(); using var dst = new Db(); using var dir = new TempDir(); using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await SeedSourceAsync(src.Context);
        await SeedConsoleAsync(dst.Context);
        // something older, stored by the console's own feed before it was switched to bundles
        dst.Context.VexStatements.Add(Statement("CVE-2098-0001", "openssl", VexStatus.KnownNotAffected, platform: "Red Hat Enterprise Linux 9"));
        dst.Context.VexDocuments.Add(new VexDocument { Provider = "redhat", Path = "2098/cve-2098-0001.json", Scope = "openssl" });
        await dst.Context.SaveChangesAsync();
        dst.Context.ChangeTracker.Clear();

        var written = await TestBundleWriter.WriteAsync(src.Context, dir.Path, key, CancellationToken.None, version: "202610020800", builtAt: Built);
        Assert.Equal(new[] { BundleFiles.Vex, BundleFiles.Eol }, written.Extras.Select(f => f.Name));
        var manifest = BundleManifest.Parse(await File.ReadAllTextAsync(Path.Combine(dir.Path, BundleFiles.Manifest)))!;
        using (var pub = PublicOf(key)) Assert.True(manifest.Verify(pub));

        var result = await BundleApplier.ApplyAsync(dst.Context, manifest, dir.Path, "central test", CancellationToken.None);

        Assert.Equal((3, 32), (result.Vex, result.Eol));
        var statements = await dst.Context.VexStatements.AsNoTracking().OrderBy(s => s.CveId).ThenBy(s => s.Product).ToListAsync();
        Assert.Equal(new[] { "openssl", "openssl-libs", "curl" }, statements.Select(s => s.Product));   // zlib is not installed here; the older statement was replaced
        Assert.Equal(0, await dst.Context.VexDocuments.CountAsync());
        var fix = statements[0];
        Assert.Equal((VexStatus.Fixed, "3.0.7-28.el9_4", "Red Hat Enterprise Linux 9", "cpe:/o:redhat:enterprise_linux:9", "2", Built.AddDays(-3)), (fix.Status, fix.Version, fix.Platform, fix.PlatformCpe, fix.Revision, fix.DocumentDate!.Value));
        Assert.Equal("vulnerable_code_not_present", statements[2].Justification);
        Assert.Equal(32, await dst.Context.EolCycles.CountAsync());
        var cycle = await dst.Context.EolCycles.AsNoTracking().SingleAsync(c => c.Slug == "fortios" && c.Cycle == "7.2");
        Assert.Equal((new DateTime(2026, 9, 30), true, "https://endoflife.date/fortios"), (cycle.EolFrom!.Value, cycle.IsEol, cycle.Link));

        // the Sources page shows both as current from the bundle, so neither is reported overdue
        var feeds = await dst.Context.FeedStatuses.AsNoTracking().Where(f => f.Name == CsafVexFeed.FeedName || f.Name == EndOfLifeFeed.FeedName).ToListAsync();
        Assert.Equal(2, feeds.Count);
        Assert.All(feeds, f => { Assert.Equal(Built, f.LastSuccess); Assert.Equal("bundle 202610020800", f.Cursor); Assert.Null(f.LastError); });
    }

    [Fact]
    public async Task A_bundle_with_the_new_files_still_verifies_and_applies_on_a_console_that_does_not_know_them()
    {
        using var src = new Db(); using var dir = new TempDir(); using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await SeedSourceAsync(src.Context);
        var manifest = await TestBundleWriter.WriteAsync(src.Context, dir.Path, key, CancellationToken.None, version: "202610020800", builtAt: Built);

        // files, which every console checks one by one against what it unpacked, lists the original six and nothing else
        Assert.Equal(BundleFiles.Required.OrderBy(n => n), manifest.Files.Select(f => f.Name).OrderBy(n => n));
        // an older console reads the manifest without the two new properties: same canonical text, same signature
        var asOldConsoleReadsIt = new BundleManifest { Version = manifest.Version, BuiltAt = manifest.BuiltAt, Files = manifest.Files, Signer = manifest.Signer, Signature = manifest.Signature };
        Assert.Equal(manifest.Canonical(), asOldConsoleReadsIt.Canonical());
        using var pub = PublicOf(key);
        Assert.True(asOldConsoleReadsIt.Verify(pub));
        // and it unpacks only the six, so the optional files are simply not there
        File.Delete(Path.Combine(dir.Path, BundleFiles.Vex));
        File.Delete(Path.Combine(dir.Path, BundleFiles.Eol));
        Assert.Null(await BundleApplier.VerifyFilesAsync(asOldConsoleReadsIt, dir.Path, CancellationToken.None));
    }

    [Fact]
    public async Task Optional_files_are_verified_like_the_others()
    {
        using var src = new Db(); using var dst = new Db(); using var dir = new TempDir(); using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await SeedSourceAsync(src.Context);
        await SeedConsoleAsync(dst.Context);
        var manifest = await TestBundleWriter.WriteAsync(src.Context, dir.Path, key, CancellationToken.None, version: "202610020800", builtAt: Built);
        using var pub = PublicOf(key);

        // a statement slipped into the file after signing
        var vexPath = Path.Combine(dir.Path, BundleFiles.Vex);
        var original = await File.ReadAllTextAsync(vexPath);
        await File.WriteAllTextAsync(vexPath, original.Replace("\"status\":1", "\"status\":3"));
        Assert.Contains("vex.jsonl does not match its manifest hash", await BundleApplier.VerifyFilesAsync(manifest, dir.Path, CancellationToken.None));
        await Assert.ThrowsAsync<BundleRejectedException>(() => BundleApplier.ApplyAsync(dst.Context, manifest, dir.Path, "central test", CancellationToken.None));
        Assert.Equal(0, await dst.Context.VexStatements.CountAsync());

        // the manifest edited to match the tampered file: the extras signature no longer holds
        var forged = BundleManifest.Parse(manifest.ToJson())!;
        forged.Extras = forged.Extras.Select(f => f.Name == BundleFiles.Vex ? new BundleFile(f.Name, BundleHash.FileSha256Async(vexPath, CancellationToken.None).Result, new FileInfo(vexPath).Length) : f).ToList();
        Assert.False(forged.Verify(pub));
        // extras with no signature at all, or the extras of one bundle moved into another
        var unsigned = BundleManifest.Parse(manifest.ToJson())!;
        unsigned.ExtrasSignature = null;
        Assert.False(unsigned.Verify(pub));
        var moved = BundleManifest.Parse(manifest.ToJson())!;
        moved.Version = "202610030800";
        moved.Signature = Convert.ToBase64String(key.SignData(System.Text.Encoding.UTF8.GetBytes(moved.Canonical()), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        Assert.False(moved.Verify(pub));

        // a missing optional file that the manifest lists is refused; one from a format this console does not know is ignored
        await File.WriteAllTextAsync(vexPath, original);
        Assert.Null(await BundleApplier.VerifyFilesAsync(manifest, dir.Path, CancellationToken.None));
        manifest.Extras.Add(new BundleFile("advisories.jsonl", new string('0', 64), 123));
        TestBundleWriter.SignExtras(manifest, key);
        Assert.True(manifest.Verify(pub));
        Assert.Null(await BundleApplier.VerifyFilesAsync(manifest, dir.Path, CancellationToken.None));
        File.Delete(Path.Combine(dir.Path, BundleFiles.Eol));
        Assert.Equal("Bundle is missing eol.json", await BundleApplier.VerifyFilesAsync(manifest, dir.Path, CancellationToken.None));
    }

    [Fact]
    public async Task A_bundle_without_the_optional_files_leaves_stored_vex_and_end_of_life_data_alone()
    {
        using var src = new Db(); using var dst = new Db(); using var dir = new TempDir(); using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        await SeedSourceAsync(dst.Context);   // the console already holds data, from its own feeds or an earlier bundle
        var manifest = await TestBundleWriter.WriteAsync(src.Context, dir.Path, key, CancellationToken.None, version: "202610020800", builtAt: Built);
        Assert.Empty(manifest.Extras);
        Assert.Null(manifest.ExtrasSignature);

        var result = await BundleApplier.ApplyAsync(dst.Context, manifest, dir.Path, "central test", CancellationToken.None);
        Assert.Null(result.Vex);
        Assert.Null(result.Eol);
        Assert.Equal(4, await dst.Context.VexStatements.CountAsync());
        Assert.Equal(32, await dst.Context.EolCycles.CountAsync());
        Assert.False(await dst.Context.FeedStatuses.AnyAsync(f => f.Name == CsafVexFeed.FeedName));
    }

    // ---- bundle mode: the feeds do not call out ----------------------------------------------------------------------

    /// <summary>The whole core over a scratch SQLite file, with only the two new feeds registered and every request recorded.</summary>
    private static async Task WithCoreAsync(FakeHandler http, Func<ServiceProvider, Task> body)
    {
        var path = Path.Combine(Path.GetTempPath(), "vv-vendor-data-" + Guid.NewGuid().ToString("N") + ".db");
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IDataProtectionProvider>(new MarkingProtectionProvider());
        services.AddVulnVerdictCore("sqlite", "Data Source=" + path + ";Pooling=False", new WorkerOptions { DataDir = Path.GetTempPath() }, "web");
        services.RemoveAll<IFeed>();
        services.AddSingleton<IFeed, CsafVexFeed>();
        services.AddSingleton<IFeed, EndOfLifeFeed>();
        services.AddSingleton<IHttpClientFactory>(new FakeHttpClientFactory(http));
        await using var sp = services.BuildServiceProvider();
        try
        {
            var factory = sp.GetRequiredService<IDbContextFactory<VvDbContext>>();
            await using (var db = await factory.CreateDbContextAsync())
            {
                await db.Database.EnsureCreatedAsync();
                foreach (var f in sp.GetServices<IFeed>()) db.FeedStatuses.Add(new FeedStatus { Name = f.Name, DisplayName = f.DisplayName, IntervalMinutes = f.IntervalMinutes });
                EvaluatorHarness.AddWatchlist(db, "Red Hat", "Red Hat Enterprise Linux", "9.4", "app-01");
                await db.SaveChangesAsync();
            }
            await body(sp);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            foreach (var f in new[] { path, path + "-wal", path + "-shm" }) try { File.Delete(f); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task Neither_feed_calls_out_when_the_console_is_fed_by_bundles()
    {
        var http = new FakeHandler();
        await WithCoreAsync(http, async sp =>
        {
            var worker = new WorkerService(sp, NullLogger<WorkerService>.Instance, sp.GetRequiredService<WorkerOptions>());

            // pulling the public feeds: both go out (and get the fake's 404)
            await worker.RunPassAsync(CancellationToken.None);
            Assert.Contains(http.Calls, c => c.Url.Host == "endoflife.date");
            Assert.Contains(http.Calls, c => c.Url.Host == "security.access.redhat.com");

            var settings = sp.GetRequiredService<SettingsService>();
            var s = await settings.LoadAsync();
            s.BundleUrl = "https://bundles.example.test";
            await settings.SaveAsync(s, "test");
            await using (var db = await sp.GetRequiredService<IDbContextFactory<VvDbContext>>().CreateDbContextAsync())
                await db.FeedStatuses.ExecuteUpdateAsync(u => u.SetProperty(f => f.RunRequested, true));   // even "Run now" does not
            http.Calls.Clear();

            await worker.RunPassAsync(CancellationToken.None);
            Assert.All(http.Calls, c => Assert.Equal("bundles.example.test", c.Url.Host));
            Assert.NotEmpty(http.Calls);
        });
    }

    // ---- digest ------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Digest_carries_one_end_of_life_line()
    {
        await WithCoreAsync(new FakeHandler(), async sp =>
        {
            var digest = sp.GetRequiredService<DigestService>();
            Assert.DoesNotContain("vendor support", (await digest.BuildAsync()).Text);

            var d = DateTime.UtcNow.Date;
            await using (var db = await sp.GetRequiredService<IDbContextFactory<VvDbContext>>().CreateDbContextAsync())
            {
                db.EolCycles.AddRange(
                    new EolCycle { Slug = "rhel", ProductLabel = "Red Hat Enterprise Linux", Cycle = "9", CycleLabel = "9", EolFrom = d.AddDays(60), RetrievedAt = d },
                    new EolCycle { Slug = "fortios", ProductLabel = "FortiOS", Cycle = "7.0", CycleLabel = "7.0", EolFrom = d.AddDays(-10), IsEol = true, RetrievedAt = d });
                EvaluatorHarness.AddWatchlist(db, version: "7.0.14");
                await db.SaveChangesAsync();
            }
            var content = await digest.BuildAsync();
            const string line = "1 product is past vendor support; 1 reaches end of support within 90 days.";
            Assert.EndsWith(line, content.CoverageLine);
            Assert.Contains(line, content.Text);
            Assert.Contains(line, content.Html);
        });
    }

    // ---- Cisco credentials -------------------------------------------------------------------------------------------

    private static async Task<(VvDbContext Db, SettingsService Settings)> OpenWithSettingsAsync()
    {
        var conn = new SqliteConnection("DataSource=:memory:");
        await conn.OpenAsync();
        var db = new VvDbContext(new DbContextOptionsBuilder<VvDbContext>().UseSqlite(conn).Options);
        await db.Database.EnsureCreatedAsync();
        return (db, TestSettings.For(db));
    }

    [Fact]
    public async Task Cisco_credentials_in_plain_state_rows_move_into_encrypted_settings_on_first_read()
    {
        var (db, settings) = await OpenWithSettingsAsync();
        await using var _ = db;
        db.Settings.AddRange(
            new AppSetting { Key = "psirt:cisco:clientId", Value = " cisco-client-id ", UpdatedAt = Built },
            new AppSetting { Key = "psirt:cisco:clientSecret", Value = "s3cret-from-2025", UpdatedAt = Built });
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();

        var first = await settings.LoadAsync();
        Assert.Equal(("cisco-client-id", "s3cret-from-2025"), (first.CiscoClientId, first.CiscoClientSecret));

        var rows = await db.Settings.AsNoTracking().ToDictionaryAsync(r => r.Key);
        Assert.DoesNotContain("psirt:cisco:clientId", rows.Keys);
        Assert.DoesNotContain("psirt:cisco:clientSecret", rows.Keys);
        Assert.True(rows[nameof(AppSettings.CiscoClientId)].Encrypted);
        Assert.True(rows[nameof(AppSettings.CiscoClientSecret)].Encrypted);
        Assert.DoesNotContain(rows.Values, r => r.Value is not null && (r.Value.Contains("s3cret-from-2025") || r.Value.Contains("cisco-client-id")));   // nothing left in plain text

        var second = await settings.LoadAsync();
        Assert.Equal(("cisco-client-id", "s3cret-from-2025"), (second.CiscoClientId, second.CiscoClientSecret));
        Assert.Contains(nameof(AppSettings.CiscoClientSecret), SettingsService.SecretNames);
        Assert.Contains(nameof(AppSettings.CiscoClientId), SettingsService.SecretNames);
    }

    [Fact]
    public async Task A_cisco_secret_already_saved_in_settings_is_not_overwritten_by_the_old_row()
    {
        var (db, settings) = await OpenWithSettingsAsync();
        await using var _ = db;
        var s = await settings.LoadAsync();
        s.CiscoClientId = "new-id"; s.CiscoClientSecret = "new-secret";
        await settings.SaveAsync(s, "admin");
        db.Settings.Add(new AppSetting { Key = "psirt:cisco:clientSecret", Value = "old-secret", UpdatedAt = Built });
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();

        var loaded = await settings.LoadAsync();
        Assert.Equal(("new-id", "new-secret"), (loaded.CiscoClientId, loaded.CiscoClientSecret));
        Assert.False(await db.Settings.AnyAsync(r => r.Key == "psirt:cisco:clientSecret"));
        Assert.Equal("new-secret", (await settings.LoadAsync()).CiscoClientSecret);
    }

    [Fact]
    public async Task Cisco_feed_signs_in_with_the_migrated_credentials()
    {
        var (db, settings) = await OpenWithSettingsAsync();
        await using var _ = db;
        db.Settings.AddRange(
            new AppSetting { Key = "psirt:cisco:clientId", Value = "cisco-client-id", UpdatedAt = Built },
            new AppSetting { Key = "psirt:cisco:clientSecret", Value = "s3cret-from-2025", UpdatedAt = Built });
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
        var http = new FakeHandler()
            .On(HttpMethod.Post, "/oauth2/default/v1/token", "{\"access_token\":\"token-1\"}")
            .On(HttpMethod.Get, "/security/advisories/v2/all/lastpublished", Fixtures.Read("psirt", "cisco_openvuln_sample.json"));

        var result = await new CiscoOpenVulnFeed(settings).RunAsync(new FeedContext { Db = db, Http = new HttpClient(http), Log = NullLogger.Instance, DataDir = Path.GetTempPath() }, CancellationToken.None);

        Assert.True(result.Records > 0);
        var token = http.Calls.Single(c => c.Method == HttpMethod.Post);
        Assert.Contains("client_id=cisco-client-id", token.Body);
        Assert.Contains("client_secret=s3cret-from-2025", token.Body);
        Assert.Equal("token-1", http.Calls.Single(c => c.Method == HttpMethod.Get).Auth!.Parameter);
        Assert.True(await db.Advisories.AnyAsync(a => a.Vendor == CiscoOpenVulnFeed.Vendor));
    }
}
