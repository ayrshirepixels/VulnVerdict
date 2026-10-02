using System.IO.Compression;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Feeds;
using VulnVerdict.Core.Feeds.Psirt;

namespace VulnVerdict.Tests;

/// <summary>Cursors and whole-set replacements must never move past, or wipe, work that was not completed.</summary>
public class FeedCursorTests
{
    private static readonly DateTime Now = new(2026, 9, 24, 12, 0, 0, DateTimeKind.Utc);

    private static string Fixture(string name, [CallerFilePath] string path = "") => File.ReadAllText(Path.Combine(Path.GetDirectoryName(path)!, "Fixtures", "psirt", name));

    private static async Task<VvDbContext> OpenDbAsync()
    {
        var conn = new SqliteConnection("DataSource=:memory:");
        await conn.OpenAsync();
        var db = new VvDbContext(new DbContextOptionsBuilder<VvDbContext>().UseSqlite(conn).Options);
        await db.Database.EnsureCreatedAsync();
        return db;
    }

    private static FeedContext Ctx(VvDbContext db, FakeHandler http, string? cursor) =>
        new() { Db = db, Http = new HttpClient(http), Log = NullLogger.Instance, DataDir = Path.GetTempPath(), Cursor = cursor };

    // ---- Ubuntu: capped runs resume ------------------------------------------------------------------------------------

    /// <summary>A fake cves.json over a list sorted newest-updated first, paged by the offset query parameter.</summary>
    private static FakeHandler UbuntuApi(List<(string Id, DateTime Updated)> cves) => new FakeHandler().On(
        r => r.RequestUri!.Host == "ubuntu.com",
        (r, _) =>
        {
            var q = System.Web.HttpUtility.ParseQueryString(r.RequestUri!.Query);
            var offset = int.Parse(q["offset"]!);
            var limit = int.Parse(q["limit"]!);
            var page = cves.OrderByDescending(c => c.Updated).Skip(offset).Take(limit)
                .Select(c => new { id = c.Id, updated_at = c.Updated.ToString("o"), priority = "high", packages = Array.Empty<object>() });
            return FakeHandler.Json(JsonSerializer.Serialize(new { cves = page }));
        });

    private static List<(string Id, DateTime Updated)> UbuntuCves(int n) =>
        Enumerable.Range(1, n).Select(i => ($"CVE-2026-{i:D4}", Now.AddHours(-i))).ToList();

    [Fact]
    public async Task Ubuntu_first_run_over_the_cap_resumes_the_backfill_until_every_cve_is_stored()
    {
        await using var db = await OpenDbAsync();
        var cves = UbuntuCves(100);
        var http = UbuntuApi(cves);
        var feed = new UbuntuSecurityFeed { PageSize = 20, MaxRecords = 40 };

        var r1 = await feed.RunAsync(Ctx(db, http, null), CancellationToken.None);
        Assert.Equal(40, r1.Records);
        Assert.True(r1.MoreSoon);
        Assert.Equal((Now.AddHours(-1), 40, (DateTime?)null), UbuntuSecurityFeed.ParseCursor(r1.Cursor));

        // a CVE updated between runs moves to the top: the forward pass takes it, the backfill carries on
        cves.Add(("CVE-2026-9999", Now.AddMinutes(30)));
        var r2 = await feed.RunAsync(Ctx(db, http, r1.Cursor), CancellationToken.None);
        Assert.True(r2.MoreSoon);
        var r3 = await feed.RunAsync(Ctx(db, http, r2.Cursor), CancellationToken.None);
        var r4 = await feed.RunAsync(Ctx(db, http, r3.Cursor), CancellationToken.None);
        Assert.False(r4.MoreSoon);
        Assert.Null(UbuntuSecurityFeed.ParseCursor(r4.Cursor).Resume);
        Assert.Equal(Now.AddMinutes(30), UbuntuSecurityFeed.ParseCursor(r4.Cursor).Forward);
        Assert.Equal(101, await db.Advisories.CountAsync(a => a.Vendor == UbuntuSecurityFeed.Vendor));
    }

    [Fact]
    public async Task Ubuntu_backlog_over_the_cap_backfills_down_to_the_old_cursor_only()
    {
        await using var db = await OpenDbAsync();
        var http = UbuntuApi(UbuntuCves(100));
        var feed = new UbuntuSecurityFeed { PageSize = 20, MaxRecords = 40 };
        var old = Now.AddHours(-60); // CVE 1..59 are newer than the cursor
        var r1 = await feed.RunAsync(Ctx(db, http, old.ToString("o")), CancellationToken.None);
        Assert.Equal((Now.AddHours(-1), 40, (DateTime?)old), UbuntuSecurityFeed.ParseCursor(r1.Cursor));

        var r2 = await feed.RunAsync(Ctx(db, http, r1.Cursor), CancellationToken.None);
        Assert.False(r2.MoreSoon);
        Assert.Equal(Now.AddHours(-1).ToString("o"), r2.Cursor);
        Assert.Equal(59, await db.Advisories.CountAsync());
        Assert.False(await db.Advisories.AnyAsync(a => a.AdvisoryId == "CVE-2026-0060"));
    }

    [Fact]
    public void Ubuntu_cursor_reads_the_old_plain_form()
    {
        Assert.Equal((Now, (int?)null, (DateTime?)null), UbuntuSecurityFeed.ParseCursor(Now.ToString("o")));
        var s = UbuntuSecurityFeed.FormatCursor(Now, 2000, Now.AddDays(-3));
        Assert.Equal((Now, (int?)2000, (DateTime?)Now.AddDays(-3)), UbuntuSecurityFeed.ParseCursor(s));
    }

    // ---- MSRC: an older document must not roll back a newer one ------------------------------------------------------

    private static Advisory MsrcRow(DateTime updated, bool exploited, string build) => new()
    {
        AdvisoryId = "CVE-2026-21001", Title = "Windows Kernel Elevation of Privilege", Updated = updated, Published = new DateTime(2026, 3, 10, 0, 0, 0, DateTimeKind.Utc),
        CveIdsJson = "[\"CVE-2026-21001\"]", ExploitedInTheWild = exploited, Severity = "Important", RetrievedAt = Now,
        AffectedJson = PsirtStore.AffectedJson(new[] { new AffectedRow("Windows 11 Version 24H2 for x64-based Systems", "", build) })
    };

    [Fact]
    public async Task Upsert_of_an_older_document_keeps_the_newer_fix_and_exploitation()
    {
        await using var db = await OpenDbAsync();
        var newer = MsrcRow(new DateTime(2026, 9, 9, 0, 0, 0, DateTimeKind.Utc), true, "10.0.26100.6584 (KB5065426)");
        var older = MsrcRow(new DateTime(2026, 3, 10, 0, 0, 0, DateTimeKind.Utc), false, "10.0.26100.3476 (KB5053598)");
        await PsirtStore.UpsertAsync(db, MsrcFeed.Vendor, new[] { newer }, CancellationToken.None);
        await PsirtStore.UpsertAsync(db, MsrcFeed.Vendor, new[] { older }, CancellationToken.None);

        var stored = await db.Advisories.AsNoTracking().SingleAsync();
        Assert.True(stored.ExploitedInTheWild);
        Assert.Contains("6584", stored.AffectedJson);
        Assert.Equal(new DateTime(2026, 9, 9, 0, 0, 0, DateTimeKind.Utc), stored.Updated);

        // a still newer revision replaces the fix; exploitation stays set even when that revision omits it
        await PsirtStore.UpsertAsync(db, MsrcFeed.Vendor, new[] { MsrcRow(new DateTime(2026, 10, 14, 0, 0, 0, DateTimeKind.Utc), false, "10.0.26100.6899") }, CancellationToken.None);
        stored = await db.Advisories.AsNoTracking().SingleAsync();
        Assert.True(stored.ExploitedInTheWild);
        Assert.Contains("6899", stored.AffectedJson);
    }

    [Fact]
    public async Task Upsert_of_an_older_row_still_fills_detail_the_stored_row_lacks()
    {
        await using var db = await OpenDbAsync();
        var bare = MsrcRow(new DateTime(2026, 9, 9, 12, 0, 0, DateTimeKind.Utc), false, "");
        bare.AffectedJson = null;
        bare.CveIdsJson = "[]";
        await PsirtStore.UpsertAsync(db, "fortinet", new[] { bare }, CancellationToken.None);
        await PsirtStore.UpsertAsync(db, "fortinet", new[] { MsrcRow(new DateTime(2026, 9, 9, 0, 0, 0, DateTimeKind.Utc), false, "7.2.7") }, CancellationToken.None);
        var stored = await db.Advisories.AsNoTracking().SingleAsync();
        Assert.Contains("7.2.7", stored.AffectedJson);
        Assert.Equal("[\"CVE-2026-21001\"]", stored.CveIdsJson);
    }

    [Fact]
    public void Msrc_affected_rows_are_deduplicated_and_not_cut_at_300()
    {
        var names = Enumerable.Range(1, 400).Select(i => new { ProductID = i.ToString(), Value = "Product " + i }).ToList();
        var pids = names.Select(n => n.ProductID).ToArray();
        var rem = new { Type = 2, Description = new { Value = "5065426" }, FixedBuild = "10.0.1", ProductID = pids };
        var json = JsonSerializer.Serialize(new
        {
            ProductTree = new { FullProductName = names },
            Vulnerability = new[] { new { CVE = "CVE-2026-21001", Remediations = new[] { rem, rem } } }
        });
        using var doc = JsonDocument.Parse(json);
        var adv = Assert.Single(MsrcFeed.Parse(doc.RootElement, Now, out var capped));
        Assert.Equal(0, capped);
        Assert.Equal(400, PsirtStore.ReadAffected(adv.AffectedJson).Count);
    }

    [Fact]
    public async Task Msrc_rereads_a_document_released_at_the_cursor()
    {
        await using var db = await OpenDbAsync();
        const string at = "2026-09-09T07:00:00Z";
        var http = new FakeHandler()
            .On(HttpMethod.Get, "/cvrf/v3.0/updates", JsonSerializer.Serialize(new { value = new[] { new { ID = "2026-Sep", DocumentTitle = "September 2026 Security Updates", InitialReleaseDate = at, CurrentReleaseDate = at } } }))
            .On(HttpMethod.Get, "/cvrf/v3.0/cvrf/2026-Sep", Fixture("msrc_cvrf_excerpt.json"));
        var feed = new MsrcFeed { HistoryBackfill = false };
        await feed.RunAsync(Ctx(db, http, MsrcFeed.FormatCursor(DateTime.Parse(at).ToUniversalTime(), null, true)), CancellationToken.None);
        Assert.Contains(http.Calls, c => c.Path.EndsWith("/cvrf/2026-Sep", StringComparison.Ordinal));
    }

    // ---- Fortinet: index-only rows are fetched again -----------------------------------------------------------------

    [Fact]
    public async Task Fortinet_advisory_stored_index_only_is_fetched_again_after_the_cursor_moves_on()
    {
        await using var db = await OpenDbAsync();
        const string rss = """
            <rss version="2.0"><channel>
              <item><title>FG-IR-26-200 A newer advisory</title><link>https://fortiguard.fortinet.com/psirt/FG-IR-26-200</link><pubDate>Thu, 24 Sep 2026 00:00:00 -0700</pubDate></item>
              <item><title>FG-IR-24-015 Out-of-bound Write in sslvpnd</title><link>https://fortiguard.fortinet.com/psirt/FG-IR-24-015</link><pubDate>Tue, 08 Sep 2026 00:00:00 -0700</pubDate></item>
            </channel></rss>
            """;
        var page = Fixture("fortinet_FG-IR-24-015.html");
        var olderPageUp = false;
        var http = new FakeHandler()
            .On(r => r.RequestUri!.AbsolutePath.EndsWith("/ir.xml"), (_, _) => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(rss) })
            .On(r => r.RequestUri!.AbsolutePath.EndsWith("FG-IR-24-015"), (_, _) => olderPageUp
                ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(page) }
                : new HttpResponseMessage(HttpStatusCode.ServiceUnavailable))
            .On(r => r.RequestUri!.AbsolutePath.EndsWith("FG-IR-26-200"), (_, _) => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(page) });
        var feed = new FortinetPsirtFeed { DelayMs = 0 };

        var r1 = await feed.RunAsync(Ctx(db, http, null), CancellationToken.None);
        Assert.Equal("2026-09-24", r1.Cursor);
        Assert.Null((await db.Advisories.AsNoTracking().SingleAsync(a => a.AdvisoryId == "FG-IR-24-015")).AffectedJson);

        olderPageUp = true;
        http.Calls.Clear();
        await feed.RunAsync(Ctx(db, http, r1.Cursor), CancellationToken.None);
        Assert.Contains(http.Calls, c => c.Path.EndsWith("FG-IR-24-015", StringComparison.Ordinal));
        var stored = await db.Advisories.AsNoTracking().SingleAsync(a => a.AdvisoryId == "FG-IR-24-015");
        Assert.NotEmpty(PsirtStore.ReadAffected(stored.AffectedJson));
        Assert.Contains("CVE-2024-21762", stored.CveIdsJson);

        // once fetched it is no longer retried
        http.Calls.Clear();
        olderPageUp = false;
        await feed.RunAsync(Ctx(db, http, r1.Cursor), CancellationToken.None);
        Assert.DoesNotContain(http.Calls, c => c.Path.EndsWith("FG-IR-24-015", StringComparison.Ordinal));
    }

    // ---- whole-set feeds: a short download does not wipe the stored set -----------------------------------------------

    private static string KevJson(int n) => JsonSerializer.Serialize(new
    {
        catalogVersion = "2026.09.24",
        vulnerabilities = Enumerable.Range(1, n).Select(i => new { cveID = $"CVE-2026-{i:D4}", vendorProject = "Acme", product = "Widget", dateAdded = "2026-09-01" })
    });

    [Fact]
    public async Task Kev_refuses_a_catalogue_less_than_half_the_stored_one()
    {
        await using var db = await OpenDbAsync();
        var http = new FakeHandler();
        var count = 100;
        http.On(r => r.RequestUri!.AbsoluteUri == KevFeed.Url, (_, _) => FakeHandler.Json(KevJson(count)));
        await new KevFeed().RunAsync(Ctx(db, http, null), CancellationToken.None);
        Assert.Equal(100, await db.Kev.CountAsync());

        count = 0;
        await Assert.ThrowsAsync<InvalidOperationException>(() => new KevFeed().RunAsync(Ctx(db, http, null), CancellationToken.None));
        count = 49;
        await Assert.ThrowsAsync<InvalidOperationException>(() => new KevFeed().RunAsync(Ctx(db, http, null), CancellationToken.None));
        Assert.Equal(100, await db.Kev.CountAsync());

        count = 60;
        await new KevFeed().RunAsync(Ctx(db, http, null), CancellationToken.None);
        Assert.Equal(60, await db.Kev.CountAsync());
    }

    [Fact]
    public async Task Exploit_signal_feed_refuses_an_empty_index()
    {
        await using var db = await OpenDbAsync();
        db.ExploitSignals.AddRange(Enumerable.Range(1, 20).Select(i => new ExploitSignal { CveId = $"CVE-2026-{i:D4}", Source = FeedNames.Metasploit, Url = "https://example.invalid/" + i, RetrievedAt = Now }));
        db.ExploitSignals.Add(new ExploitSignal { CveId = "CVE-2026-0001", Source = FeedNames.Nuclei, Url = "https://example.invalid/n", RetrievedAt = Now });
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
        var http = new FakeHandler().On(HttpMethod.Get, "modules_metadata_base.json", "{}");
        await Assert.ThrowsAsync<InvalidOperationException>(() => new MetasploitFeed().RunAsync(Ctx(db, http, null), CancellationToken.None));
        Assert.Equal(20, await db.ExploitSignals.CountAsync(s => s.Source == FeedNames.Metasploit));
    }

    [Fact]
    public async Task Epss_refuses_a_truncated_file()
    {
        await using var db = await OpenDbAsync();
        db.Epss.AddRange(Enumerable.Range(1, 20).Select(i => new EpssScore { CveId = $"CVE-2026-{i:D4}", Score = 0.1, Percentile = 0.5, ScoreDate = Now.Date, RetrievedAt = Now }));
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
        var csv = "#model_version:v2025.03.14,score_date:2026-09-24T00:00:00+0000\ncve,epss,percentile\nCVE-2026-0001,0.2,0.6\n";
        var gz = new MemoryStream();
        using (var z = new GZipStream(gz, CompressionMode.Compress, leaveOpen: true)) z.Write(Encoding.UTF8.GetBytes(csv));
        var http = new FakeHandler().On(r => r.RequestUri!.AbsoluteUri == EpssFeed.Url, (_, _) => new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(gz.ToArray()) });
        await Assert.ThrowsAsync<InvalidOperationException>(() => new EpssFeed().RunAsync(Ctx(db, http, null), CancellationToken.None));
        Assert.Equal(20, await db.Epss.CountAsync());
    }
}
