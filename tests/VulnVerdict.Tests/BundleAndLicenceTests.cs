using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Feeds;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

/// <summary>Section 10.2: signed feed bundles and licence keys, end to end against in-memory SQLite.</summary>
public class BundleAndLicenceTests
{
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
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "vv-bundle-test-" + Guid.NewGuid().ToString("N"));
        public TempDir() => Directory.CreateDirectory(Path);
        public void Dispose() { try { Directory.Delete(Path, true); } catch { } }
    }

    private static ECDsa NewKey() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    private static ECDsa PublicOf(ECDsa key)
    {
        var pub = ECDsa.Create();
        pub.ImportFromPem(key.ExportSubjectPublicKeyInfoPem());
        return pub;
    }

    private static async Task SeedAsync(VvDbContext db)
    {
        var now = new DateTime(2026, 9, 24, 8, 0, 0, DateTimeKind.Utc);
        db.Cves.AddRange(
            new Cve
            {
                Id = "CVE-2026-0001", State = "PUBLISHED", Published = now.AddDays(-3), LastModified = now.AddDays(-1), Assigner = "fortinet", Title = "FortiOS SSL-VPN overflow",
                Description = "A heap overflow in sslvpnd.", CvssV31Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CvssV31Score = 9.8, SsvcExploitation = "active", SsvcAutomatable = "yes",
                ReferencesJson = "[\"https://fortiguard.com/psirt/FG-IR-26-001\"]", RetrievedAt = now, SourceRef = "cve_2026-09-24_0700Z",
                Affected = { new CveAffected { Vendor = "Fortinet", Product = "FortiOS", VendorNorm = "fortinet", ProductNorm = "fortios", DefaultStatus = "unaffected", VersionsJson = "[{\"version\":\"7.2.0\",\"lessThan\":\"7.2.8\",\"status\":\"affected\",\"versionType\":\"semver\"}]" } }
            },
            new Cve
            {
                Id = "CVE-2026-0002", State = "PUBLISHED", Published = now.AddDays(-10), LastModified = now.AddDays(-2), Assigner = "veeam", Title = "Veeam B&R deserialisation",
                Description = "Remote code execution by an authenticated domain user.", CvssV40Vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", CvssV40Score = 8.7, RetrievedAt = now,
                Affected =
                {
                    new CveAffected { Vendor = "Veeam", Product = "Backup & Replication", VendorNorm = "veeam", ProductNorm = "backup replication", VersionsJson = "[{\"version\":\"12\",\"lessThan\":\"12.3.1\",\"status\":\"affected\"}]" },
                    new CveAffected { Vendor = "Veeam", Product = "Backup Enterprise Manager", VendorNorm = "veeam", ProductNorm = "backup enterprise manager" }
                }
            });
        db.Kev.Add(new KevEntry { CveId = "CVE-2026-0001", VendorProject = "Fortinet", Product = "FortiOS", VulnerabilityName = "FortiOS heap overflow", DateAdded = now.AddDays(-1), RequiredAction = "Apply updates", DueDate = now.AddDays(13), KnownRansomwareUse = "Known", RetrievedAt = now });
        db.Epss.AddRange(
            new EpssScore { CveId = "CVE-2026-0001", Score = 0.93, Percentile = 0.998, ScoreDate = now.Date, RetrievedAt = now },
            new EpssScore { CveId = "CVE-2026-0002", Score = 0.12, Percentile = 0.95, ScoreDate = now.Date, RetrievedAt = now });
        db.ExploitSignals.AddRange(
            new ExploitSignal { CveId = "CVE-2026-0001", Source = "exploitdb", Title = "FortiOS sslvpnd RCE", Url = "https://www.exploit-db.com/exploits/60001", PublishedAt = now.AddDays(-1), RetrievedAt = now },
            new ExploitSignal { CveId = "CVE-2026-0001", Source = "metasploit", Title = "fortios_sslvpn_rce", Url = "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/fortios_sslvpn_rce.rb", RetrievedAt = now },
            new ExploitSignal { CveId = "CVE-2026-0002", Source = "nuclei", Title = "veeam-cve-2026-0002", Url = "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-0002.yaml", RetrievedAt = now });
        db.Aliases.AddRange(
            new ProductAlias { AliasNorm = "fortigate", VendorNorm = "fortinet", ProductNorm = "fortios" },
            new ProductAlias { AliasNorm = "veeam", VendorNorm = "veeam", ProductNorm = "backup replication" });
        db.Narratives.AddRange(
            new Narrative { Key = "cve:CVE-2026-0001", Text = "An attacker on the internet sends one crafted request to the VPN login page and gets a shell.", Provider = "anthropic", Model = "claude-opus-5", PromptVersion = "v3", CreatedAt = now },
            new Narrative { Key = "verdict:" + Guid.NewGuid(), Text = "customer-specific attack story that must not travel", Provider = "anthropic", Model = "claude-opus-5", PromptVersion = "v3", CreatedAt = now });
        foreach (var name in new[] { FeedNames.CveList, FeedNames.Kev, FeedNames.Epss, FeedNames.ExploitDb, FeedNames.Metasploit, FeedNames.Nuclei })
            db.FeedStatuses.Add(new FeedStatus { Name = name, DisplayName = name, IntervalMinutes = 60 });
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
    }

    // ------------------------------------------------------------------ bundle signature and hashes

    [Fact]
    public async Task Bundle_signature_verifies_with_the_public_key_and_nothing_else()
    {
        using var src = new Db();
        using var dir = new TempDir();
        using var key = NewKey();
        await SeedAsync(src.Context);

        var written = await TestBundleWriter.WriteAsync(src.Context, dir.Path, key, CancellationToken.None, "Test signer", "202609240800");
        var manifest = BundleManifest.Parse(await File.ReadAllTextAsync(Path.Combine(dir.Path, BundleFiles.Manifest)));

        Assert.NotNull(manifest);
        Assert.Equal("202609240800", manifest!.Version);
        Assert.Equal("Test signer", manifest.Signer);
        Assert.Equal(written.Signature, manifest.Signature);
        Assert.Equal(BundleFiles.Required.Length, manifest.Files.Count);
        Assert.All(BundleFiles.Required, f => Assert.Contains(manifest.Files, x => x.Name == f));

        using var pub = PublicOf(key);
        Assert.True(manifest.Verify(pub));
        Assert.Null(await BundleApplier.VerifyFilesAsync(manifest, dir.Path, CancellationToken.None));

        using var otherKey = NewKey();
        using var otherPub = PublicOf(otherKey);
        Assert.False(manifest.Verify(otherPub));

        var unsigned = BundleManifest.Parse(manifest.ToJson())!;
        unsigned.Signature = null;
        Assert.False(unsigned.Verify(pub));

        var edited = BundleManifest.Parse(manifest.ToJson())!;
        edited.Version = "202609240900";
        Assert.False(edited.Verify(pub));

        // the customer-specific attack story never travels
        var narratives = await File.ReadAllTextAsync(Path.Combine(dir.Path, BundleFiles.Narratives));
        Assert.Contains("cve:CVE-2026-0001", narratives);
        Assert.DoesNotContain("verdict:", narratives);
    }

    [Fact]
    public async Task Tampered_file_is_detected_and_refused()
    {
        using var src = new Db();
        using var dst = new Db();
        using var dir = new TempDir();
        using var key = NewKey();
        await SeedAsync(src.Context);
        var manifest = await TestBundleWriter.WriteAsync(src.Context, dir.Path, key, CancellationToken.None, version: "202609240800");

        // same length so only the hash gives it away
        var kevPath = Path.Combine(dir.Path, BundleFiles.Kev);
        var kev = await File.ReadAllTextAsync(kevPath);
        await File.WriteAllTextAsync(kevPath, kev.Replace("CVE-2026-0001", "CVE-2026-9999"));

        var reason = await BundleApplier.VerifyFilesAsync(manifest, dir.Path, CancellationToken.None);
        Assert.NotNull(reason);
        Assert.Contains(BundleFiles.Kev, reason);

        var ex = await Assert.ThrowsAsync<BundleRejectedException>(() => BundleApplier.ApplyAsync(dst.Context, manifest, dir.Path, "test", CancellationToken.None));
        Assert.Contains(BundleFiles.Kev, ex.Message);
        Assert.Equal(0, await dst.Context.Cves.CountAsync());
        Assert.Equal(0, await dst.Context.Bundles.CountAsync());
    }

    // ------------------------------------------------------------------ apply, downgrade, upsert

    [Fact]
    public async Task Bundle_round_trips_into_a_fresh_database_and_refuses_downgrades()
    {
        using var src = new Db();
        using var dst = new Db();
        using var dir = new TempDir();
        using var key = NewKey();
        await SeedAsync(src.Context);
        var v1 = await TestBundleWriter.WriteAsync(src.Context, dir.Path, key, CancellationToken.None, version: "202609240800", builtAt: new DateTime(2026, 9, 24, 8, 0, 0, DateTimeKind.Utc));

        var result = await BundleApplier.ApplyAsync(dst.Context, v1, dir.Path, "upload by test", CancellationToken.None);
        Assert.Equal(2, result.Cves);
        Assert.Equal(1, result.Kev);
        Assert.Equal(2, result.Epss);
        Assert.Equal(3, result.Signals);
        Assert.Equal(2, result.AliasesAdded);
        Assert.Equal(1, result.Narratives);

        var db = dst.Context;
        Assert.Equal(2, await db.Cves.CountAsync());
        Assert.Equal(3, await db.CveAffected.CountAsync());
        Assert.Equal(3, await db.CnaProducts.CountAsync());
        var forti = await db.Cves.Include(c => c.Affected).FirstAsync(c => c.Id == "CVE-2026-0001");
        Assert.Equal("active", forti.SsvcExploitation);
        Assert.Equal(9.8, forti.CvssV31Score);
        Assert.Single(forti.Affected);
        Assert.Contains("7.2.8", forti.Affected[0].VersionsJson);
        Assert.Equal(0.93, (await db.Epss.FindAsync("CVE-2026-0001"))!.Score);
        Assert.Equal("Known", (await db.Kev.FindAsync("CVE-2026-0001"))!.KnownRansomwareUse);
        Assert.Equal(1, await db.ExploitSignals.CountAsync(s => s.Source == "metasploit"));
        Assert.Equal(1, await db.Narratives.CountAsync());

        var state = await BundleApplier.CurrentAsync(db, CancellationToken.None);
        Assert.NotNull(state);
        Assert.Equal("202609240800", state!.Version);
        Assert.Equal("upload by test", state.Source);
        Assert.Equal(TestBundleWriter.DefaultSigner, state.Signer);
        Assert.Equal(new DateTime(2026, 9, 24, 8, 0, 0), state.BuiltAt);

        var feeds = await db.FeedStatuses.ToListAsync();
        Assert.Equal(6, feeds.Count);
        Assert.All(feeds, f => Assert.Equal("bundle 202609240800", f.Cursor));
        Assert.All(feeds, f => Assert.Equal(new DateTime(2026, 9, 24, 8, 0, 0), f.LastSuccess));
        Assert.Equal(2, feeds.First(f => f.Name == FeedNames.CveList).RecordsLastRun);
        Assert.Equal(1, feeds.First(f => f.Name == FeedNames.Nuclei).RecordsLastRun);

        // same version again: refused as already applied
        var same = await Assert.ThrowsAsync<BundleRejectedException>(() => BundleApplier.ApplyAsync(db, v1, dir.Path, "test", CancellationToken.None));
        Assert.Contains("already applied", same.Message);

        // an older version: refused as a downgrade, nothing changes
        using var older = new TempDir();
        var v0 = await TestBundleWriter.WriteAsync(src.Context, older.Path, key, CancellationToken.None, version: "202609240700");
        var down = await Assert.ThrowsAsync<BundleRejectedException>(() => BundleApplier.ApplyAsync(db, v0, older.Path, "test", CancellationToken.None));
        Assert.Contains("downgrade", down.Message);
        Assert.Equal("202609240800", (await BundleApplier.CurrentAsync(db, CancellationToken.None))!.Version);
        Assert.Null(BundleApplier.CheckDowngrade("202609240900", "202609240800"));
        Assert.NotNull(BundleApplier.CheckDowngrade("2026-09-24", "202609240800"));

        // a newer bundle takes the upsert path (the database already holds CVEs): a verdict referencing a CVE survives
        var watch = new WatchlistEntry { Id = Guid.NewGuid(), Vendor = "Fortinet", Product = "FortiOS", VendorNorm = "fortinet", ProductNorm = "fortios", Version = "7.2.5", CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow };
        db.Watchlist.Add(watch);
        db.Verdicts.Add(new Verdict { Id = Guid.NewGuid(), CveId = "CVE-2026-0001", WatchlistEntryId = watch.Id, Subject = "Fortinet FortiOS 7.2.5 on FW-EDGE-01", Tier = VerdictTier.FixToday, Sentence = "x", CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow, LastEvaluatedAt = DateTime.UtcNow });
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();

        var srcForti = await src.Context.Cves.FirstAsync(c => c.Id == "CVE-2026-0001");
        srcForti.Title = "FortiOS SSL-VPN overflow (updated)";
        src.Context.Cves.Add(new Cve { Id = "CVE-2026-0003", State = "PUBLISHED", RetrievedAt = DateTime.UtcNow, Affected = { new CveAffected { Vendor = "Cisco", Product = "IOS XE", VendorNorm = "cisco", ProductNorm = "ios xe" } } });
        src.Context.Kev.Add(new KevEntry { CveId = "CVE-2026-0003", DateAdded = DateTime.UtcNow, RetrievedAt = DateTime.UtcNow });
        await src.Context.SaveChangesAsync();
        src.Context.ChangeTracker.Clear();
        using var newer = new TempDir();
        var v2 = await TestBundleWriter.WriteAsync(src.Context, newer.Path, key, CancellationToken.None, version: "202609240900");
        var r2 = await BundleApplier.ApplyAsync(db, v2, newer.Path, "central test", CancellationToken.None);
        Assert.Equal(3, r2.Cves);
        Assert.Equal(3, await db.Cves.CountAsync());
        Assert.Equal(4, await db.CveAffected.CountAsync());
        Assert.Equal(2, await db.Kev.CountAsync());
        Assert.Equal("FortiOS SSL-VPN overflow (updated)", (await db.Cves.FindAsync("CVE-2026-0001"))!.Title);
        Assert.Equal(1, await db.Verdicts.CountAsync());
        Assert.Equal("202609240900", (await BundleApplier.CurrentAsync(db, CancellationToken.None))!.Version);
        Assert.Equal(4, await db.CnaProducts.CountAsync());
    }

    // ------------------------------------------------------------------ licence keys

    [Fact]
    public void Licence_key_round_trips_and_rejects_expired_or_tampered_keys()
    {
        using var key = NewKey();
        using var pub = PublicOf(key);
        var now = new DateTime(2026, 9, 24, 12, 0, 0, DateTimeKind.Utc);

        var issued = TestLicence.Issue(new LicenceClaims { Customer = "Ayrshire Widgets Ltd", Tier = LicenseService.Business, AssetCap = 250, Expires = now.AddYears(1), IssuedAt = now }, key);
        Assert.Contains(".", issued);
        Assert.DoesNotContain("=", issued);

        var info = LicenseService.Parse(issued, pub, now);
        Assert.True(info.Present);
        Assert.True(info.Valid);
        Assert.Equal("Ayrshire Widgets Ltd", info.Customer);
        Assert.Equal("business", info.Tier);
        Assert.Equal("Business", info.TierName);
        Assert.Equal(250, info.AssetCap);
        Assert.Equal(250, info.EnforcedCap);
        Assert.Equal(now.AddYears(1), info.Expires);
        Assert.Null(info.TenantToken);

        // expired: not valid, but the genuine claims (and so the cap) are still readable
        var expired = LicenseService.Parse(issued, pub, now.AddYears(2));
        Assert.True(expired.Present);
        Assert.False(expired.Valid);
        Assert.True(expired.Expired);
        Assert.Contains("expired", expired.Reason);
        Assert.Equal(250, expired.EnforcedCap);
        Assert.Equal("Ayrshire Widgets Ltd", expired.Customer);

        // tampered claims: signature no longer matches
        var dot = issued.IndexOf('.');
        var payload = issued[..dot];
        var tampered = payload[..^2] + (payload[^2] == 'A' ? 'B' : 'A') + payload[^1] + issued[dot..];
        var bad = LicenseService.Parse(tampered, pub, now);
        Assert.True(bad.Present);
        Assert.False(bad.Valid);
        Assert.Null(bad.Customer);
        Assert.Contains("signature", bad.Reason);

        // signed by somebody else
        using var otherKey = NewKey();
        var foreign = TestLicence.Issue(new LicenceClaims { Customer = "Impostor", Tier = LicenseService.Starter, AssetCap = 50, Expires = now.AddYears(1) }, otherKey);
        Assert.False(LicenseService.Parse(foreign, pub, now).Valid);

        // garbage and blank
        Assert.False(LicenseService.Parse("not-a-key", pub, now).Valid);
        Assert.False(LicenseService.Parse("abc.def", pub, now).Valid);
        var none = LicenseService.Parse("", pub, now);
        Assert.False(none.Present);
        Assert.Null(none.EnforcedCap);
        Assert.Equal("Internal build", none.TierName);

        // MSP keys carry the tenant token; starter defaults
        var msp = LicenseService.Parse(TestLicence.Issue(new LicenceClaims { Customer = "Client A", Tier = LicenseService.Msp, AssetCap = 80, Expires = now.AddMonths(1), TenantToken = "tok-0123456789abcdef" }, key), pub, now);
        Assert.True(msp.Valid);
        Assert.Equal("MSP", msp.TierName);
        Assert.Equal("tok-0123456789abcdef", msp.TenantToken);
        Assert.Equal(80, msp.AssetCap);
        Assert.Equal(50, LicenseService.DefaultCap(LicenseService.Starter));
        Assert.Equal(250, LicenseService.DefaultCap(LicenseService.Business));
        Assert.Throws<ArgumentException>(() => TestLicence.Issue(new LicenceClaims { Customer = "x", Tier = "enterprise", Expires = now }, key));
    }

    [Fact]
    public void Msp_report_strips_asset_names_from_subjects()
    {
        Assert.Equal("Fortinet FortiOS 7.2.5", MspReportService.StripAssetName("Fortinet FortiOS 7.2.5 on FW-EDGE-01"));
        Assert.Equal("Veeam Backup & Replication 12.1", MspReportService.StripAssetName("Veeam Backup & Replication 12.1"));
        Assert.Equal("A product", MspReportService.StripAssetName(""));
    }
}
