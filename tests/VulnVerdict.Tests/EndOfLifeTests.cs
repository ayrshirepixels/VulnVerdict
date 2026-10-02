using System.Net;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;
using VulnVerdict.Core.Feeds;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

/// <summary>End-of-life flags: the endoflife.date response, the product map, the date arithmetic, the verdict and the digest line.</summary>
public class EndOfLifeTests
{
    private static readonly DateTime Today = new(2026, 10, 2, 9, 0, 0, DateTimeKind.Utc);

    private static List<EolCycle> FixtureCycles()
    {
        using var doc = JsonDocument.Parse(Fixtures.Read("eol", "products_full.json"));
        return EndOfLifeFeed.Parse(doc.RootElement, Today);
    }

    private static EolFinding? Find(string vendor, string product, string? version, int warnDays = 180, bool suggest = false) =>
        new EolIndex(FixtureCycles()).Find(vendor, product, version, Today, warnDays, suggest);

    // ---- the response ------------------------------------------------------------------------------------------------

    [Fact]
    public void Response_is_read_into_one_row_per_release_cycle()
    {
        var rows = FixtureCycles();
        Assert.Equal(32, rows.Count);
        Assert.Equal(11, rows.Select(r => r.Slug).Distinct().Count());
        var fortios = rows.Single(r => r.Slug == "fortios" && r.Cycle == "7.2");
        Assert.Equal(("FortiOS", "7.2", true, new DateTime(2026, 9, 30), new DateTime(2025, 3, 31), "https://endoflife.date/fortios"), (fortios.ProductLabel, fortios.CycleLabel, fortios.IsEol, fortios.EolFrom!.Value, fortios.EoasFrom!.Value, fortios.Link));
        var server = rows.Single(r => r.Slug == "windows-server" && r.Cycle == "2012-r2");
        Assert.Equal(("Windows Server 2012 R2 (LTSC)", new DateTime(2026, 10, 13), "windowsserver", "6.3.9600"), (server.CycleLabel, server.EoesFrom!.Value, server.Aliases, server.Latest));
        var nginx = rows.Single(r => r.Slug == "nginx" && r.Cycle == "1.24");
        Assert.True(nginx.IsEol);
        Assert.Null(nginx.EolFrom);
        Assert.Empty(EndOfLifeFeed.Parse(JsonDocument.Parse("{\"message\":\"not found\"}").RootElement, Today));
    }

    // ---- date arithmetic ---------------------------------------------------------------------------------------------

    [Fact]
    public void Dates_decide_end_of_life_ending_soon_or_supported()
    {
        Assert.Equal((EolState.EndOfLife, (int?)null), EolMath.Assess(Today.AddDays(-1), false, Today, 180));
        Assert.Equal((EolState.EndOfLife, (int?)null), EolMath.Assess(Today.Date, false, Today, 180));          // support ends today: no more patches
        Assert.Equal((EolState.EndingSoon, (int?)1), EolMath.Assess(Today.Date.AddDays(1), false, Today, 180));
        Assert.Equal((EolState.EndingSoon, (int?)180), EolMath.Assess(Today.Date.AddDays(180), false, Today, 180));
        Assert.Equal((EolState.Supported, (int?)181), EolMath.Assess(Today.Date.AddDays(181), false, Today, 180));
        Assert.Equal((EolState.Supported, (int?)40), EolMath.Assess(Today.Date.AddDays(40), false, Today, 30));  // the window is a setting
        Assert.Equal((EolState.EndOfLife, (int?)null), EolMath.Assess(null, true, Today, 180));                 // no date, but the source says it is over
        Assert.Equal((EolState.Supported, (int?)null), EolMath.Assess(null, false, Today, 180));                // no date announced
        // a time of day never tips the count
        Assert.Equal((EolState.EndingSoon, (int?)1), EolMath.Assess(Today.Date.AddDays(1), false, Today.Date.AddHours(23), 180));
    }

    [Fact]
    public void Flags_read_as_the_console_shows_them()
    {
        var past = Find("Fortinet", "FortiOS", "7.2.5")!;
        Assert.Equal((EolState.EndOfLife, "End of life", "FortiOS 7.2 is past vendor support (ended 30 Sep 2026)", true), (past.State, past.Flag, past.Describe(), past.Flagged));
        var soon = Find("Fortinet", "FortiOS", "7.4.3")!;
        Assert.Equal((EolState.EndingSoon, 40, "End of life in 40 days", "FortiOS 7.4 reaches the end of vendor support on 11 Nov 2026 (in 40 days)"), (soon.State, soon.Days, soon.Flag, soon.Describe()));
        var fine = Find("Fortinet", "FortiOS", "7.6.0")!;
        Assert.Equal((EolState.Supported, false), (fine.State, fine.Flagged));
        Assert.Equal(EolState.Supported, Find("Fortinet", "FortiOS", "7.4.3", warnDays: 30)!.State);
        Assert.Null(Find("Fortinet", "FortiOS", "5.6.14"));    // a release the source does not list is not guessed at
        Assert.Null(Find("Fortinet", "FortiOS", null));        // nor is an entry with no version
    }

    // ---- mapping the estate to release cycles ------------------------------------------------------------------------

    [Theory]
    [InlineData("Fortinet", "FortiGate", "7.0.14", "fortios", "7.0")]
    [InlineData("Microsoft", "Windows Server 2012 R2 Standard", "6.3.9600", "windows-server", "2012-r2")]
    [InlineData("Microsoft", "Windows Server 2012 Datacenter", "6.2.9200", "windows-server", "2012")]
    [InlineData("Microsoft", "Windows Server 2019 Standard", "10.0.17763.6189", "windows-server", "2019")]
    [InlineData("Microsoft", "Windows Server", "10.0.26100.1742", "windows-server", "2025")]              // told apart by build
    [InlineData("Microsoft", "Windows 10 Version 22H2", "10.0.19045.4894", "windows", "10-22h2")]
    [InlineData("Microsoft", "Windows 11 Version 24H2", "10.0.26100.1742", "windows", "11-24h2-e")]         // the edition supported longest
    [InlineData("Microsoft", "Windows 11 Pro", "10.0.26100.1742", "windows", "11-24h2-e")]
    [InlineData("Microsoft", "Windows 11 IoT Enterprise LTSC", "10.0.26100.1742", "windows", "11-24h2-iot-lts")]
    [InlineData("Microsoft", "Microsoft SQL Server 2016 (64-bit)", "13.0.6435.1", "mssqlserver", "13.0-sp3")]
    [InlineData("Microsoft", "Microsoft SQL Server 2019 (GDR)", null, "mssqlserver", "15.0")]
    [InlineData("Microsoft Corporation", "SQL Server", "16.0.4135.4", "mssqlserver", "16.0")]
    [InlineData("Microsoft", "Microsoft Exchange Server 2019 Cumulative Update 14", "15.2.1544.4", "msexchange", "2019")]
    [InlineData("Microsoft", "Exchange Server", "15.2.1544.4", "msexchange", "2019")]
    [InlineData("Canonical", "Ubuntu 20.04.6 LTS", "20.04", "ubuntu", "20.04")]
    [InlineData("Ubuntu", "Ubuntu", "22.04.4", "ubuntu", "22.04")]
    [InlineData("The PHP Group", "PHP", "8.1.29", "php", "8.1")]
    [InlineData("Microsoft Corporation", "Microsoft .NET Runtime - 6.0.36 (x64)", "48.144.23141", "dotnet", "6")]   // the installer's own version is not the runtime's
    [InlineData("Microsoft", ".NET 8.0", "8.0.8", "dotnet", "8")]
    [InlineData("Oracle Corporation", "Java 8 Update 421 (64-bit)", "8.0.4210.9", "oracle-jdk", "8")]
    [InlineData("Oracle Corporation", "Java SE JDK and JRE", "1.8.0_421", "oracle-jdk", "8")]
    [InlineData("Oracle Corporation", "Java(TM) SE Development Kit 21.0.4 (64-bit)", "21.0.4.0", "oracle-jdk", "21")]
    [InlineData("F5", "NGINX Open Source", "1.24.0", "nginx", "1.24")]
    public void Installed_products_map_to_their_release_cycle(string vendor, string product, string? version, string slug, string cycle)
    {
        var f = Find(vendor, product, version);
        Assert.NotNull(f);
        Assert.Equal((slug, cycle, false), (f!.Slug, f.Cycle, f.Suggestion));
    }

    [Theory]
    [InlineData("Microsoft", "Microsoft 365 Apps for enterprise", "16.0.17726.20160")]   // evergreen: no release to outlive
    [InlineData("Microsoft", "SQL Server Management Studio", "19.3")]
    [InlineData("Microsoft", "Windows Server", "10.0.99999")]                              // a build nobody has mapped
    [InlineData("Python Software Foundation", "Python Launcher", "3.11.4150.0")]
    [InlineData("SonicWall", "SonicOS", "7.0.1")]                                          // endoflife.date does not track it
    [InlineData("Acme", "Widget Server", "4.0")]
    public void Products_with_no_tracked_release_are_left_alone(string vendor, string product, string version) =>
        Assert.Null(Find(vendor, product, version, suggest: true));

    [Fact]
    public void Extended_support_is_mentioned_while_it_still_runs_and_a_release_without_a_date_is_still_flagged()
    {
        var server = Find("Microsoft", "Windows Server 2012 R2 Standard", "6.3.9600")!;
        Assert.Equal("Windows Server 2012 R2 (LTSC) is past vendor support (ended 10 Oct 2023); paid extended support runs to 13 Oct 2026", server.Describe());
        var sql = Find("Microsoft", "Microsoft SQL Server 2016 (64-bit)", "13.0.6435.1")!;
        Assert.Equal("Microsoft SQL Server 2016 SP3 is past vendor support (ended 14 Jul 2026); paid extended support runs to 17 Jul 2029", sql.Describe());
        var nginx = Find("F5", "NGINX Open Source", "1.24.0")!;
        Assert.Equal((EolState.EndOfLife, "nginx 1.24 is past vendor support"), (nginx.State, nginx.Describe()));
    }

    [Fact]
    public void A_name_the_curated_map_does_not_know_is_only_ever_a_suggestion()
    {
        Assert.Null(Find("The Wireshark Foundation", "Wireshark", "4.0.11"));
        var s = Find("The Wireshark Foundation", "Wireshark", "4.0.11", suggest: true)!;
        Assert.Equal(("wireshark", "4.0", EolState.EndOfLife, true, false), (s.Slug, s.Cycle, s.State, s.Suggestion, s.Flagged));
        Assert.Null(s.FixAdvice("4.0.11", null));
    }

    [Fact]
    public void No_fix_advice_unless_the_fix_is_in_the_same_release()
    {
        var fortios = Find("Fortinet", "FortiOS", "7.2.5")!;
        Assert.Equal(EolFinding.NoFixAdvice, fortios.FixAdvice("7.2.5", null));
        Assert.Equal(EolFinding.NoFixAdvice, fortios.FixAdvice("7.2.5", "7.4.4"));
        Assert.Equal(EolFinding.NoFixAdvice, fortios.FixAdvice("7.2.5", "a release later than 7.2.5"));
        Assert.Null(fortios.FixAdvice("7.2.5", "7.2.8"));   // shipped before support ended: "Fixed in 7.2.8" is still true
        var windows = Find("Microsoft", "Windows 10 Version 22H2", "10.0.19045.3803")!;
        Assert.Null(windows.FixAdvice("10.0.19045.3803", "10.0.19045.5131 (KB5046613)"));
        Assert.Equal(EolFinding.NoFixAdvice, windows.FixAdvice("10.0.19045.3803", "10.0.26100.2033"));
        Assert.Null(Find("Fortinet", "FortiOS", "7.4.3")!.FixAdvice("7.4.3", null));   // ending soon is not ended
    }

    // ---- the feed ----------------------------------------------------------------------------------------------------

    private static async Task<VvDbContext> OpenDbAsync()
    {
        var conn = new SqliteConnection("DataSource=:memory:");
        await conn.OpenAsync();
        var db = new VvDbContext(new DbContextOptionsBuilder<VvDbContext>().UseSqlite(conn).Options);
        await db.Database.EnsureCreatedAsync();
        return db;
    }

    [Fact]
    public async Task Feed_replaces_the_stored_cycles_and_refuses_a_response_that_has_shrunk()
    {
        await using var db = await OpenDbAsync();
        var body = Fixtures.Read("eol", "products_full.json");
        var http = new FakeHandler().On(r => r.RequestUri!.AbsoluteUri == EndOfLifeFeed.Url, (_, _) => FakeHandler.Json(body));
        FeedContext Ctx() => new() { Db = db, Http = new HttpClient(http), Log = NullLogger.Instance, DataDir = Path.GetTempPath() };

        var r = await new EndOfLifeFeed { MinProducts = 5 }.RunAsync(Ctx(), CancellationToken.None);
        Assert.Equal(32, r.Records);
        Assert.Equal(32, await db.EolCycles.CountAsync());
        await new EndOfLifeFeed { MinProducts = 5 }.RunAsync(Ctx(), CancellationToken.None);
        Assert.Equal(32, await db.EolCycles.CountAsync());   // replaced, not added to

        // a response with most products gone is not the real list
        using var full = JsonDocument.Parse(body);
        body = JsonSerializer.Serialize(new { result = full.RootElement.GetProperty("result").EnumerateArray().Take(2).ToList() });
        await Assert.ThrowsAsync<InvalidOperationException>(() => new EndOfLifeFeed { MinProducts = 5 }.RunAsync(Ctx(), CancellationToken.None));
        // and one that passes that test but holds under half the stored rows is not swapped in either
        await Assert.ThrowsAsync<InvalidOperationException>(() => new EndOfLifeFeed { MinProducts = 1 }.RunAsync(Ctx(), CancellationToken.None));
        body = "{\"result\":[]}";
        await Assert.ThrowsAsync<InvalidOperationException>(() => new EndOfLifeFeed { MinProducts = 0 }.RunAsync(Ctx(), CancellationToken.None));
        Assert.Equal(32, await db.EolCycles.CountAsync());
    }

    [LiveFact]
    public async Task Live_endoflife_date_products()
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("VulnVerdict/0.2 (tests)");
        using var doc = JsonDocument.Parse(await http.GetStringAsync(EndOfLifeFeed.Url));
        var rows = EndOfLifeFeed.Parse(doc.RootElement, DateTime.UtcNow);
        Assert.True(rows.Select(r => r.Slug).Distinct().Count() >= new EndOfLifeFeed().MinProducts);
        // every slug in the curated map should still exist at the source
        var slugs = rows.Select(r => r.Slug).ToHashSet();
        Assert.Equal(Array.Empty<string>(), EolProductMap.Entries.Select(e => e.Slug).Distinct().Where(s => !slugs.Contains(s)).ToArray());
        // and the usual estate should resolve to a release against the real cycle names
        var index = new EolIndex(rows);
        var estate = new (string Vendor, string Product, string? Version)[]
        {
            ("Fortinet", "FortiOS", "7.0.14"), ("Palo Alto Networks", "PAN-OS", "10.1.11-h4"), ("VMware", "ESXi", "7.0.3"), ("VMware", "vCenter Server", "8.0.2"),
            ("Microsoft", "Windows Server 2012 R2 Standard", "6.3.9600"), ("Microsoft", "Windows Server", "10.0.17763.6189"), ("Microsoft", "Windows 10 Version 22H2", "10.0.19045.4894"),
            ("Microsoft", "Windows 11 Pro", "10.0.26100.1742"), ("Microsoft", "Microsoft Office Professional Plus 2016", "16.0.4266.1001"), ("Microsoft", "Microsoft SQL Server 2016 (64-bit)", "13.0.6435.1"),
            ("Microsoft", "SQL Server", "15.0.2000.5"), ("Microsoft", "Microsoft Exchange Server 2016 Cumulative Update 23", "15.1.2507.39"), ("Microsoft", "Microsoft .NET Runtime - 6.0.36 (x64)", "48.144.23141"),
            ("Microsoft", "Microsoft .NET Framework 4.6.1", "4.6.1"), ("Canonical", "Ubuntu 20.04.6 LTS", "20.04"), ("Debian", "Debian GNU/Linux 11 (bullseye)", "11"), ("Red Hat", "Red Hat Enterprise Linux", "8.10"),
            ("AlmaLinux", "AlmaLinux", "9.4"), ("Rocky Linux", "Rocky Linux", "8.9"), ("Apple", "macOS", "13.6.7"), ("Apple", "iOS", "16.7.8"), ("The PHP Group", "PHP", "7.4.33"), ("Node.js", "Node", "18.20.4"),
            ("Python Software Foundation", "Python 3.8.10 (64-bit)", "3.8.10150.0"), ("Oracle Corporation", "Java 8 Update 421 (64-bit)", "8.0.4210.9"), ("Apache Software Foundation", "Apache HTTP Server", "2.2.34"),
            ("F5", "NGINX Open Source", "1.24.0"), ("Oracle", "MySQL Server", "5.7.44"), ("MariaDB", "MariaDB", "10.4.32"), ("PostgreSQL Global Development Group", "PostgreSQL", "11.22"),
        };
        Assert.Equal(Array.Empty<string>(), estate.Where(e => index.Find(e.Vendor, e.Product, e.Version, DateTime.UtcNow, 180) is null).Select(e => e.Vendor + " " + e.Product + " " + e.Version).ToArray());
    }

    // ---- the estate report and the digest line -----------------------------------------------------------------------

    private static EolCycle Cycle(string slug, string label, string cycle, DateTime? eol, bool isEol = false) =>
        new() { Slug = slug, ProductLabel = label, Cycle = cycle, CycleLabel = cycle, EolFrom = eol, IsEol = isEol || (eol is not null && eol <= DateTime.UtcNow), IsMaintained = true, Link = "https://endoflife.date/" + slug, RetrievedAt = DateTime.UtcNow };

    /// <summary>Cycles dated from today, so the tests hold whenever they run: FortiOS 7.0 ended, 7.2 ends in 45 days, 7.4 in 150, 7.6 in 3 years; PHP 7.4 ended; Ubuntu 20.04 ends in 80 days.</summary>
    private static EolCycle[] RelativeCycles()
    {
        var d = DateTime.UtcNow.Date;
        return new[]
        {
            Cycle("fortios", "FortiOS", "7.0", d.AddDays(-300)), Cycle("fortios", "FortiOS", "7.2", d.AddDays(45)), Cycle("fortios", "FortiOS", "7.4", d.AddDays(150)), Cycle("fortios", "FortiOS", "7.6", d.AddDays(1100)),
            Cycle("php", "PHP", "7.4", d.AddDays(-900)), Cycle("php", "PHP", "8.3", d.AddDays(700)),
            Cycle("ubuntu", "Ubuntu", "20.04", d.AddDays(80)), Cycle("ubuntu", "Ubuntu", "24.04", d.AddDays(1500)),
            Cycle("wireshark", "Wireshark", "4.0", d.AddDays(-30)),
        };
    }

    [Fact]
    public async Task Report_covers_watchlist_operating_systems_and_software_and_the_digest_counts_releases()
    {
        await using var db = await OpenDbAsync();
        var now = DateTime.UtcNow;
        db.EolCycles.AddRange(RelativeCycles());
        EvaluatorHarness.AddWatchlist(db, version: "7.0.14", asset: "FW-BRANCH-01");
        EvaluatorHarness.AddWatchlist(db, version: "7.0.12", asset: "FW-BRANCH-02");   // the same release twice: one product in the digest
        EvaluatorHarness.AddWatchlist(db, version: "7.4.3", asset: "FW-EDGE-01");      // 150 days: flagged, but beyond the digest's 90
        EvaluatorHarness.AddWatchlist(db, version: "7.6.0", asset: "FW-HQ-01");
        var web = new Asset { Id = Guid.NewGuid(), DisplayName = "web-01", OsVendor = "Canonical", OsProduct = "Ubuntu 20.04.6 LTS", OsVersion = "20.04", FirstSeen = now, LastSeen = now };
        var old = new Asset { Id = Guid.NewGuid(), DisplayName = "gone-01", OsVendor = "Canonical", OsProduct = "Ubuntu 20.04.6 LTS", OsVersion = "20.04", FirstSeen = now.AddDays(-90), LastSeen = now.AddDays(-60) };
        db.Assets.AddRange(web, old);
        SoftwareInstance Sw(Asset a, string vendor, string product, string version, string? ecosystem = null) => new()
        {
            Id = Guid.NewGuid(), AssetId = a.Id, Vendor = vendor, Product = product, Version = version, VendorNorm = Normalizer.Norm(vendor), ProductNorm = Normalizer.Norm(product),
            Ecosystem = ecosystem, Kind = ecosystem is null ? SoftwareKind.Application : SoftwareKind.Package, ConnectorId = "test", FirstSeen = now, LastSeen = now
        };
        db.Software.AddRange(
            Sw(web, "The PHP Group", "PHP", "7.4.33"),
            Sw(web, "Ubuntu", "php7.4", "7.4.3-4ubuntu2.24", "Ubuntu:20.04:LTS"),   // a distribution package: supported for as long as the release is
            Sw(web, "The Wireshark Foundation", "Wireshark", "4.0.11"),
            Sw(old, "The PHP Group", "PHP", "7.4.30"));                             // on an asset not seen for 60 days
        await db.SaveChangesAsync();

        var items = await EndOfLifeReport.BuildAsync(db, now, 180, suggestions: true);

        var flagged = items.Where(i => i.Finding.Flagged).ToList();
        Assert.Equal(new[] { "watchlist: FW-BRANCH-01", "watchlist: FW-BRANCH-02", "1 asset", "1 asset", "watchlist: FW-EDGE-01" }.OrderBy(x => x), flagged.Select(i => i.Where).OrderBy(x => x));
        Assert.Equal(EolState.EndOfLife, flagged[0].Finding.State);   // worst first
        var php = flagged.Single(i => i.Product == "The PHP Group PHP");
        Assert.Equal(("7.4.33", 1, "End of life"), (php.Version, php.Assets, php.Finding.Flag));
        var ubuntu = flagged.Single(i => i.Product.Contains("Ubuntu"));
        Assert.Equal("End of life in 80 days", ubuntu.Finding.Flag);
        Assert.Equal("Wireshark", Assert.Single(items, i => i.Finding.Suggestion).Finding.ProductLabel);

        Assert.Equal("2 products are past vendor support; 1 reaches end of support within 90 days.", await EndOfLifeReport.DigestLineAsync(db, now));
    }

    [Fact]
    public void Digest_line_wording()
    {
        static EolItem Item(string cycle, EolState state, int? days, bool suggestion = false) =>
            new("FortiOS", cycle, "watchlist", 0, null, new EolFinding("fortios", "FortiOS", cycle, cycle, state, null, days, null, null, suggestion));
        Assert.Null(EndOfLifeReport.DigestLine(Array.Empty<EolItem>()));
        Assert.Null(EndOfLifeReport.DigestLine(new[] { Item("7.6", EolState.Supported, 900), Item("7.4", EolState.EndingSoon, 150), Item("6.0", EolState.EndOfLife, null, suggestion: true) }));
        Assert.Equal("1 product is past vendor support.", EndOfLifeReport.DigestLine(new[] { Item("7.0", EolState.EndOfLife, null), Item("7.0", EolState.EndOfLife, null) }));
        Assert.Equal("2 products reach end of support within 90 days.", EndOfLifeReport.DigestLine(new[] { Item("7.2", EolState.EndingSoon, 45), Item("7.4", EolState.EndingSoon, 90) }));
        Assert.Equal("3 products are past vendor support; 2 reach end of support within 90 days.", EndOfLifeReport.DigestLine(new[]
        {
            Item("6.0", EolState.EndOfLife, null), Item("6.2", EolState.EndOfLife, null), Item("6.4", EolState.EndOfLife, null), Item("7.0", EolState.EndingSoon, 10), Item("7.2", EolState.EndingSoon, 89), Item("7.4", EolState.EndingSoon, 91)
        }));
    }

    // ---- the verdict -------------------------------------------------------------------------------------------------

    [Fact]
    public async Task End_of_life_changes_the_advice_and_the_evidence_but_never_the_tier()
    {
        using var h = new EvaluatorHarness();
        await h.SeedAsync(db =>
        {
            // fixed in 7.4.4: no fix on the 7.0 line. A second CVE has its fix in 7.0.16, released before support ended.
            EvaluatorHarness.AddCve(db, "CVE-2099-1001", "Fortinet", "FortiOS", "[{\"version\":\"7.0.0\",\"status\":\"affected\",\"lessThan\":\"7.4.4\",\"versionType\":\"semver\"}]");
            EvaluatorHarness.AddCve(db, "CVE-2099-1002", "Fortinet", "FortiOS", "[{\"version\":\"7.0.0\",\"status\":\"affected\",\"lessThan\":\"7.0.16\",\"versionType\":\"semver\"}]");
            EvaluatorHarness.AddWatchlist(db, version: "7.0.14");
        });
        await h.Evaluator().EvaluateAllAsync();
        var before = (await h.VerdictsAsync()).ToDictionary(v => v.CveId);
        Assert.EndsWith("Fixed in 7.4.4.", before["CVE-2099-1001"].Sentence);

        await h.SeedAsync(db => db.EolCycles.AddRange(RelativeCycles()));
        await h.Evaluator().EvaluateAllAsync();
        var after = (await h.VerdictsAsync()).ToDictionary(v => v.CveId);

        var v = after["CVE-2099-1001"];
        Assert.Equal((before[v.CveId].Tier, before[v.CveId].RuleNumber, before[v.CveId].SlaDue), (v.Tier, v.RuleNumber, v.SlaDue));   // not a tier, not an input to the table
        Assert.Empty(v.History);
        Assert.EndsWith("reachable from the internet. No fix will be released for this version: upgrade or replace.", v.Sentence);
        Assert.DoesNotContain("Fixed in", v.Sentence);
        Assert.Equal("7.4.4", v.FixedIn);   // the fact is kept; the advice changed
        var evidence = JsonSerializer.Deserialize<List<EvidenceClaim>>(v.EvidenceJson)!;
        Assert.Contains(evidence, e => e.Claim.StartsWith("End of life: FortiOS 7.0 is past vendor support (ended ") && e.Source == "https://endoflife.date/fortios");

        var sameLine = after["CVE-2099-1002"];
        Assert.EndsWith("Fixed in 7.0.16.", sameLine.Sentence);
        Assert.Contains("End of life: FortiOS 7.0 is past vendor support", sameLine.EvidenceJson);
    }

    [Fact]
    public async Task Ending_soon_is_flagged_in_the_evidence_within_the_configured_window_only()
    {
        using var h = new EvaluatorHarness();
        await h.SeedAsync(db =>
        {
            EvaluatorHarness.AddFortiOs(db);   // affects 7.2.0 up to 7.2.8
            EvaluatorHarness.AddWatchlist(db, version: "7.2.5");
            db.EolCycles.AddRange(RelativeCycles());
        });
        await h.Evaluator().EvaluateAllAsync();
        var v = Assert.Single(await h.VerdictsAsync());
        Assert.EndsWith("Fixed in 7.2.8.", v.Sentence);
        Assert.Contains("End of life in 45 days: FortiOS 7.2 reaches the end of vendor support on ", v.EvidenceJson);

        var s = await h.Settings.LoadAsync();
        s.EolWarnDays = 30;
        await h.Settings.SaveAsync(s, "test");
        await h.Evaluator().EvaluateAllAsync();
        Assert.DoesNotContain("End of life", Assert.Single(await h.VerdictsAsync()).EvidenceJson);
    }
}
