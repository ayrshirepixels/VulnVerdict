using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Feeds;
using VulnVerdict.Core.Feeds.Psirt;

namespace VulnVerdict.Tests;

/// <summary>A fact that runs only when VV_LIVE_TESTS is set: it fetches a real vendor endpoint.</summary>
public sealed class LiveFactAttribute : FactAttribute
{
    public LiveFactAttribute()
    {
        if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable("VV_LIVE_TESTS")))
            Skip = "Live feed test; set VV_LIVE_TESTS=1 to run against the real endpoint.";
    }
}

public class PsirtFeedTests
{
    private static readonly DateTime Now = new(2026, 9, 24, 12, 0, 0, DateTimeKind.Utc);

    private static string FixtureDir([CallerFilePath] string path = "") => Path.Combine(Path.GetDirectoryName(path)!, "Fixtures", "psirt");
    private static string Fixture(string name) => File.ReadAllText(Path.Combine(FixtureDir(), name));
    private static JsonDocument FixtureJson(string name) => JsonDocument.Parse(Fixture(name));
    private static HttpClient Live()
    {
        var c = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        c.DefaultRequestHeaders.UserAgent.ParseAdd("VulnVerdict/0.2 (tests)");
        return c;
    }

    // ---- Fortinet -------------------------------------------------------------------------------------------------

    [Fact]
    public void Fortinet_rss_items_carry_id_link_and_dates()
    {
        var items = FortinetPsirtFeed.ParseRss(Fixture("fortinet_ir.xml"));
        Assert.Equal(3, items.Count);
        var first = items[0];
        Assert.Equal("FG-IR-26-165", first.AdvisoryId);
        Assert.Equal("https://fortiguard.fortinet.com/psirt/FG-IR-26-165", first.Link);
        Assert.Equal("Arbitrary process termination from exposed minifilter communication port", first.Title);
        Assert.Equal(new DateTime(2026, 9, 8), first.Published!.Value.Date);
        Assert.Equal(new DateTime(2026, 9, 8), first.Revised!.Value.Date);
        Assert.All(items, i => Assert.StartsWith("FG-IR-", i.AdvisoryId));
    }

    [Fact]
    public void Fortinet_page_extracts_cves_affected_fixed_severity_and_exploitation()
    {
        var page = FortinetPsirtFeed.ParsePage(Fixture("fortinet_FG-IR-24-015.html"));
        Assert.Equal("Out-of-bound Write in sslvpnd", page.Title);
        Assert.Equal(new[] { "CVE-2024-21762" }, page.CveIds);
        Assert.Equal("Critical", page.Severity);
        Assert.Equal(new DateTime(2024, 2, 8), page.Published!.Value.Date);
        Assert.Equal(new DateTime(2025, 1, 15), page.Updated!.Value.Date);
        // sidebar says "Known Exploited: No" but the summary states "potentially being exploited in the wild"
        Assert.False(page.KnownExploited);
        Assert.True(page.ExploitedInTheWild);

        Assert.Equal(13, page.Affected.Count);
        Assert.Equal(new AffectedRow("FortiOS", "7.4.0 through 7.4.2", "7.4.3 or above"), page.Affected[0]);
        Assert.Contains(new AffectedRow("FortiOS", "7.2.0 through 7.2.6", "7.2.7 or above"), page.Affected);
        Assert.Contains(new AffectedRow("FortiProxy", "1.2 all versions", "Migrate to a fixed release"), page.Affected);
        Assert.DoesNotContain(page.Affected, r => r.Affected.Contains("Not affected", StringComparison.OrdinalIgnoreCase));

        var adv = new Advisory { AdvisoryId = "FG-IR-24-015", RetrievedAt = Now };
        FortinetPsirtFeed.Apply(adv, page);
        Assert.Equal("[\"CVE-2024-21762\"]", adv.CveIdsJson);
        var rows = PsirtStore.ReadAffected(adv.AffectedJson);
        Assert.Contains(rows, r => r.Product == "FortiOS" && r.FixedIn == "7.2.7 or above");
        Assert.Contains("\"fixedIn\"", adv.AffectedJson);
    }

    [Fact]
    public void Fortinet_page_parser_survives_unrelated_html()
    {
        var page = FortinetPsirtFeed.ParsePage("<html><body><p>nothing here</p></body></html>");
        Assert.Empty(page.CveIds);
        Assert.Empty(page.Affected);
        Assert.False(page.ExploitedInTheWild);
        Assert.Null(page.Severity);
    }

    [Theory]
    [InlineData("FortiOS 7.2", "FortiOS", "7.2")]
    [InlineData("FortiClientWindows 7.4", "FortiClientWindows", "7.4")]
    [InlineData("FortiSandbox", "FortiSandbox", null)]
    public void Fortinet_product_cell_splits_branch(string cell, string product, string? branch)
    {
        var (p, b) = FortinetPsirtFeed.SplitProduct(cell);
        Assert.Equal(product, p);
        Assert.Equal(branch, b);
    }

    [Theory]
    [InlineData("Fortinet is aware of an instance where this vulnerability was exploited in the wild.", true)]
    [InlineData("Note: This is potentially being exploited in the wild.", true)]
    [InlineData("Cisco is aware of active exploitation of this vulnerability.", true)]
    [InlineData("Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected", true)]
    [InlineData("Fortinet is not aware of any instance where this vulnerability was exploited in the wild.", false)]
    [InlineData("Publicly Disclosed:No;Exploited:No", false)]
    [InlineData("A buffer overflow may allow an attacker to execute code.", false)]
    [InlineData("", false)]
    public void Exploitation_statement_detection(string text, bool expected) => Assert.Equal(expected, PsirtStore.ExploitationStated(text));

    // ---- MSRC ------------------------------------------------------------------------------------------------------

    [Fact]
    public void Msrc_cvrf_maps_exploit_status_severity_and_fixed_builds()
    {
        using var doc = FixtureJson("msrc_cvrf_excerpt.json");
        var rows = MsrcFeed.Parse(doc.RootElement, Now);
        Assert.Equal(2, rows.Count);

        var exploited = rows.Single(r => r.AdvisoryId == "CVE-2026-81963");
        Assert.True(exploited.ExploitedInTheWild);
        Assert.Equal("Important", exploited.Severity);
        Assert.Equal("Windows Update Stack Elevation of Privilege Vulnerability", exploited.Title);
        Assert.Equal("https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-81963", exploited.Url);
        Assert.Equal("[\"CVE-2026-81963\"]", exploited.CveIdsJson);
        Assert.Equal(new DateTime(2026, 9, 8), exploited.Published!.Value.Date);
        Assert.Equal(new DateTime(2026, 9, 15), exploited.Updated!.Value.Date);
        var affected = PsirtStore.ReadAffected(exploited.AffectedJson);
        Assert.NotEmpty(affected);
        Assert.Contains(affected, r => r.FixedIn == "10.0.26100.33438 (KB5122871)" && r.Product.StartsWith("Windows", StringComparison.Ordinal));
        Assert.All(affected, r => Assert.False(string.IsNullOrEmpty(r.Product)));

        var other = rows.Single(r => r.AdvisoryId != "CVE-2026-81963");
        Assert.False(other.ExploitedInTheWild);
        Assert.NotNull(other.Severity);
        Assert.NotEmpty(PsirtStore.ReadAffected(other.AffectedJson));
    }

    [Fact]
    public void Msrc_updates_list_keeps_monthly_documents_only()
    {
        using var doc = JsonDocument.Parse("""
            {"value":[{"ID":"2026-Sep","InitialReleaseDate":"2026-09-08T07:00:00Z","CurrentReleaseDate":"2026-09-23T07:00:00Z"},
                      {"ID":"1999-Sep","DocumentTitle":"Mariner Release Notes","InitialReleaseDate":"1999-09-02T00:00:00Z","CurrentReleaseDate":"2025-10-01T23:10:48Z"},
                      {"ID":"2026-Aug","InitialReleaseDate":"2026-08-11T07:00:00Z","CurrentReleaseDate":"2026-08-11T07:00:00Z"}]}
            """);
        var docs = MsrcFeed.ParseUpdates(doc.RootElement);
        Assert.Equal(new[] { "2026-Sep", "2026-Aug" }, docs.Select(d => d.Id)); // Mariner release notes dropped
        Assert.Contains(docs, d => d.Id == "2026-Sep" && d.CurrentReleaseDate == new DateTime(2026, 9, 23, 7, 0, 0, DateTimeKind.Utc));
    }

    // ---- Cisco -----------------------------------------------------------------------------------------------------

    [Fact]
    public void Cisco_openvuln_maps_cves_products_severity_and_exploitation()
    {
        using var doc = FixtureJson("cisco_openvuln_sample.json");
        var rows = CiscoOpenVulnFeed.Parse(doc.RootElement, Now);
        Assert.Equal(3, rows.Count);

        var asa = rows.Single(r => r.AdvisoryId == "cisco-sa-asaftd-ssl-vpn-dos-qY7BHpjN");
        Assert.Equal("[\"CVE-2024-20353\"]", asa.CveIdsJson);
        Assert.Equal("High", asa.Severity);
        Assert.True(asa.ExploitedInTheWild);
        Assert.Equal(new DateTime(2024, 4, 24, 16, 0, 0, DateTimeKind.Utc), asa.Published);
        Assert.Equal(2, PsirtStore.ReadAffected(asa.AffectedJson).Count);

        var ios = rows.Single(r => r.AdvisoryId == "cisco-sa-iosxe-webui-privesc-j22SaA4z");
        Assert.Equal("[\"CVE-2023-20198\",\"CVE-2023-20273\"]", ios.CveIdsJson);
        Assert.True(ios.ExploitedInTheWild);
        Assert.Equal(new AffectedRow("Cisco IOS XE Software", "", "17.9.4a, 17.6.6a, 17.3.8a, 16.12.10a"), PsirtStore.ReadAffected(ios.AffectedJson).Single());

        var none = rows.Single(r => r.AdvisoryId == "cisco-sa-example-nofix");
        Assert.Equal("[]", none.CveIdsJson);
        Assert.False(none.ExploitedInTheWild);
    }

    [Fact]
    public async Task Cisco_without_credentials_reports_not_configured()
    {
        await using var db = await OpenDbAsync();
        var feed = new CiscoOpenVulnFeed();
        var result = await feed.RunAsync(new FeedContext { Db = db, Http = new HttpClient(), Log = Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, DataDir = Path.GetTempPath(), Cursor = "2026-01-01" }, CancellationToken.None);
        Assert.Equal(0, result.Records);
        Assert.Equal("2026-01-01", result.Cursor);
        Assert.Equal(CiscoOpenVulnFeed.NotConfigured, result.Note);
    }

    // ---- Ubuntu ----------------------------------------------------------------------------------------------------

    [Fact]
    public void Ubuntu_cves_map_package_release_statuses_to_fixed_versions()
    {
        using var doc = FixtureJson("ubuntu_cves_excerpt.json");
        var rows = UbuntuSecurityFeed.Parse(doc.RootElement, Now);
        var cve = Assert.Single(rows);
        Assert.Equal("CVE-2026-64123", cve.AdvisoryId);
        Assert.Equal("high", cve.Severity);
        Assert.Equal("https://ubuntu.com/security/CVE-2026-64123", cve.Url);
        Assert.Equal(new DateTime(2026, 7, 20), cve.Published!.Value.Date);
        Assert.Equal(new DateTime(2026, 9, 24), cve.Updated!.Value.Date);
        Assert.False(cve.ExploitedInTheWild);
        var affected = PsirtStore.ReadAffected(cve.AffectedJson);
        Assert.Contains(new AffectedRow("linux (resolute)", "", "7.0.0-28.28"), affected);
        Assert.Contains(new AffectedRow("linux (focal)", "needed", ""), affected);
        Assert.DoesNotContain(affected, r => r.Product == "linux (bionic)"); // not-affected
        Assert.Contains(new AffectedRow("linux-hwe (bionic)", "ignored", ""), affected); // won't-fix is still "affected"
        Assert.DoesNotContain(affected, r => r.Product.Contains("(upstream)"));
    }

    [Fact]
    public void Ubuntu_page_url_uses_verified_query_parameters()
    {
        var url = new UbuntuSecurityFeed { PageSize = 50 }.PageUrl(100);
        Assert.Equal("https://ubuntu.com/security/cves.json?limit=50&offset=100&order=descending&sort_by=updated&priority=critical&priority=high&priority=medium", url);
    }

    // ---- Debian ----------------------------------------------------------------------------------------------------

    [Theory]
    [InlineData(1 << 16)]
    [InlineData(64)] // forces many buffer refills and a buffer grow
    public void Debian_tracker_streams_entries_and_keeps_affected_or_fixed_releases(int bufferSize)
    {
        var entries = new List<Advisory>();
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(Fixture("debian_tracker_excerpt.json")));
        var count = DebianTrackerParser.Parse(stream, (pkg, cve, e) =>
        {
            var adv = DebianSecurityFeed.ToAdvisory(pkg, cve, e, Now);
            if (adv is not null) entries.Add(adv);
        }, bufferSize);
        Assert.Equal(5, count); // every CVE object in the fixture is visited
        Assert.Equal(2, entries.Count);

        var ds = entries.Single(a => a.AdvisoryId == "CVE-2012-4450:389-ds-base");
        Assert.Equal("[\"CVE-2012-4450\"]", ds.CveIdsJson);
        Assert.Equal("https://security-tracker.debian.org/tracker/CVE-2012-4450", ds.Url);
        Assert.Contains(new AffectedRow("389-ds-base (bookworm)", "", "1.2.11.15-1"), PsirtStore.ReadAffected(ds.AffectedJson));
        Assert.Null(ds.Severity); // urgency "not yet assigned" is not a severity

        var ssl = entries.Single(a => a.AdvisoryId == "CVE-2024-5535:openssl");
        var rows = PsirtStore.ReadAffected(ssl.AffectedJson);
        Assert.Contains(new AffectedRow("openssl (bookworm)", "open (postponed)", ""), rows);
        Assert.Contains(new AffectedRow("openssl (trixie)", "", "3.2.2-1"), rows);
        Assert.Equal("low", ssl.Severity);

        Assert.DoesNotContain(entries, a => a.AdvisoryId.StartsWith("CVE-2012-0833")); // fixed_version 0 everywhere
        Assert.DoesNotContain(entries, a => a.AdvisoryId.Contains("zzz-not-affected-only"));
        Assert.DoesNotContain(entries, a => a.AdvisoryId.StartsWith("TEMP-"));
    }

    // ---- Red Hat ---------------------------------------------------------------------------------------------------

    [Fact]
    public void RedHat_cve_json_maps_affected_packages_to_name_and_fixed_nevr()
    {
        using var doc = FixtureJson("redhat_cve_excerpt.json");
        var rows = RedHatCsafFeed.Parse(doc.RootElement, Now);
        Assert.Equal(3, rows.Count);
        var a = rows.Single(r => r.AdvisoryId == "CVE-2026-84679");
        Assert.Equal("important", a.Severity);
        Assert.Equal("https://access.redhat.com/security/cve/CVE-2026-84679", a.Url);
        Assert.Equal(new DateTime(2026, 9, 23, 18, 44, 27, DateTimeKind.Utc), a.Published);
        Assert.Equal(new AffectedRow("automation-controller", "", "0:4.7.17-1.el9ap"), PsirtStore.ReadAffected(a.AffectedJson).Single());
        var b = rows.Single(r => r.AdvisoryId == "CVE-2026-75884");
        Assert.Equal(3, PsirtStore.ReadAffected(b.AffectedJson).Count);
        var none = rows.Single(r => r.AdvisoryId == "CVE-2026-59980");
        Assert.Empty(PsirtStore.ReadAffected(none.AffectedJson));
        Assert.StartsWith("hpack:", none.Title);
    }

    [Theory]
    [InlineData("openssl-1:1.1.1k-14.el8_6", "openssl", "1:1.1.1k-14.el8_6")]
    [InlineData("kernel-4.18.0-553.el8_10", "kernel", "4.18.0-553.el8_10")]
    [InlineData("automation-controller-0:4.7.17-1.el9ap", "automation-controller", "0:4.7.17-1.el9ap")]
    [InlineData("python3-0:3.9.18-3.el9_4", "python3", "0:3.9.18-3.el9_4")]
    public void RedHat_nevr_split(string nevr, string name, string version) => Assert.Equal((name, version), RedHatCsafFeed.SplitNevr(nevr));

    // ---- Broadcom / VMware -----------------------------------------------------------------------------------------

    [Fact]
    public void Broadcom_list_maps_vmsa_id_cves_severity_dates_and_products()
    {
        using var doc = FixtureJson("broadcom_vmsa_excerpt.json");
        var rows = BroadcomVmwareFeed.Parse(doc.RootElement, Now, out _);
        Assert.Equal(2, rows.Count);
        var a = rows[0];
        Assert.Equal("VMSA-2026-0007", a.AdvisoryId);
        Assert.Equal("[\"CVE-2026-59346\",\"CVE-2026-59347\"]", a.CveIdsJson);
        Assert.Equal("CRITICAL", a.Severity);
        Assert.Equal(new DateTime(2026, 9, 3), a.Published!.Value.Date);
        Assert.Equal(new DateTime(2026, 9, 3), a.Updated!.Value.Date);
        Assert.Equal("https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/38288", a.Url);
        var products = PsirtStore.ReadAffected(a.AffectedJson);
        Assert.Contains(products, p => p.Product == "VMware Fusion");
        Assert.DoesNotContain(products, p => p.Product.Contains("..."));
        var b = rows[1];
        Assert.Equal("VMSA-2026-0006", b.AdvisoryId); // revision suffix ".1" dropped so updates land on the same row
        Assert.Equal(5, PsirtStore.ReadCveIds(b.CveIdsJson).Count);
    }

    [Fact]
    public void Broadcom_list_skips_non_security_rows()
    {
        using var doc = JsonDocument.Parse("""{"success":true,"data":{"list":[{"alertType":"P","title":"Product Release Advisory - Something","documentId":"X1"}],"pageInfo":{"lastPage":3}}}""");
        var rows = BroadcomVmwareFeed.Parse(doc.RootElement, Now, out var lastPage);
        Assert.Empty(rows);
        Assert.Equal(3, lastPage);
    }

    // ---- store -----------------------------------------------------------------------------------------------------

    private static async Task<VvDbContext> OpenDbAsync()
    {
        var conn = new SqliteConnection("DataSource=:memory:");
        await conn.OpenAsync();
        var db = new VvDbContext(new DbContextOptionsBuilder<VvDbContext>().UseSqlite(conn).Options);
        await db.Database.EnsureCreatedAsync();
        return db;
    }

    [Fact]
    public async Task Upsert_is_idempotent_and_keeps_detail_when_a_rerun_lacks_it()
    {
        await using var db = await OpenDbAsync();
        Advisory Row(string? affected, bool exploited) => new()
        {
            AdvisoryId = "FG-IR-24-015", Title = "Out-of-bound Write in sslvpnd", Url = "https://fortiguard.fortinet.com/psirt/FG-IR-24-015",
            CveIdsJson = "[\"CVE-2024-21762\"]", AffectedJson = affected, Severity = "Critical", ExploitedInTheWild = exploited, RetrievedAt = Now
        };
        var json = PsirtStore.AffectedJson(new[] { new AffectedRow("FortiOS", "7.2.0 through 7.2.6", "7.2.7 or above") });

        Assert.Equal(1, await PsirtStore.UpsertAsync(db, "fortinet", new[] { Row(json, false) }, CancellationToken.None));
        Assert.Equal(1, await PsirtStore.UpsertAsync(db, "fortinet", new[] { Row(json, true), Row(json, true) }, CancellationToken.None));
        var stored = await db.Advisories.AsNoTracking().SingleAsync();
        Assert.Equal("fortinet", stored.Vendor);
        Assert.True(stored.ExploitedInTheWild);
        Assert.Equal(json, stored.AffectedJson);

        // a later run that could not fetch the page passes null detail: the stored rows survive
        await PsirtStore.UpsertAsync(db, "fortinet", new[] { Row(null, true) }, CancellationToken.None);
        stored = await db.Advisories.AsNoTracking().SingleAsync();
        Assert.Equal(json, stored.AffectedJson);
        Assert.Equal(1, await db.Advisories.CountAsync());

        // another vendor with the same id is a separate row; ReplaceAsync touches only its own vendor
        await PsirtStore.ReplaceAsync(db, "debian", new[] { new Advisory { AdvisoryId = "FG-IR-24-015", RetrievedAt = Now } }, CancellationToken.None);
        await PsirtStore.ReplaceAsync(db, "debian", new[] { new Advisory { AdvisoryId = "CVE-2024-5535:openssl", RetrievedAt = Now } }, CancellationToken.None);
        Assert.Equal(2, await db.Advisories.CountAsync());
        Assert.Equal("CVE-2024-5535:openssl", (await db.Advisories.SingleAsync(a => a.Vendor == "debian")).AdvisoryId);
    }

    // ---- live (VV_LIVE_TESTS=1) -------------------------------------------------------------------------------------

    [LiveFact]
    public async Task Live_fortinet_rss_and_one_advisory_page()
    {
        using var http = Live();
        var items = FortinetPsirtFeed.ParseRss(await http.GetStringAsync(FortinetPsirtFeed.RssUrl));
        Assert.NotEmpty(items);
        var page = FortinetPsirtFeed.ParsePage(await http.GetStringAsync(items[0].Link));
        Assert.NotEmpty(page.CveIds);
        Assert.NotNull(page.Severity);
    }

    [LiveFact]
    public async Task Live_msrc_updates_list()
    {
        using var http = Live();
        using var doc = await PsirtStore.GetJsonAsync(http, MsrcFeed.UpdatesUrl, CancellationToken.None);
        var docs = MsrcFeed.ParseUpdates(doc.RootElement);
        Assert.NotEmpty(docs);
        Assert.Contains(docs, d => d.InitialReleaseDate > DateTime.UtcNow.AddMonths(-3));
    }

    [LiveFact]
    public async Task Live_ubuntu_first_page()
    {
        using var http = Live();
        using var doc = await PsirtStore.GetJsonAsync(http, new UbuntuSecurityFeed { PageSize = 5 }.PageUrl(0), CancellationToken.None);
        var rows = UbuntuSecurityFeed.Parse(doc.RootElement, DateTime.UtcNow);
        Assert.NotEmpty(rows);
        Assert.Contains(rows, r => PsirtStore.ReadAffected(r.AffectedJson).Count > 0);
    }

    [LiveFact]
    public async Task Live_debian_tracker_head_only()
    {
        using var http = Live();
        using var req = new HttpRequestMessage(HttpMethod.Head, DebianSecurityFeed.Url);
        using var resp = await http.SendAsync(req);
        resp.EnsureSuccessStatusCode();
        Assert.True(resp.Content.Headers.ContentLength > 10_000_000, "Debian tracker JSON should be tens of MB");
    }

    [LiveFact]
    public async Task Live_redhat_recent_cves()
    {
        using var http = Live();
        using var doc = await PsirtStore.GetJsonAsync(http, $"{RedHatCsafFeed.Url}?after={DateTime.UtcNow.AddDays(-30):yyyy-MM-dd}&per_page=50&page=1", CancellationToken.None);
        var rows = RedHatCsafFeed.Parse(doc.RootElement, DateTime.UtcNow);
        Assert.NotEmpty(rows);
    }

    [LiveFact]
    public async Task Live_broadcom_vmware_list()
    {
        using var http = Live();
        using var req = new HttpRequestMessage(HttpMethod.Post, BroadcomVmwareFeed.ListUrl)
        {
            Content = new StringContent("""{"pageNumber":0,"pageSize":5,"searchVal":"","segment":"VC","sortInfo":{"column":"","order":""}}""", Encoding.UTF8, "application/json")
        };
        req.Headers.Accept.ParseAdd("application/json");
        using var resp = await http.SendAsync(req);
        resp.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var rows = BroadcomVmwareFeed.Parse(doc.RootElement, DateTime.UtcNow, out _);
        Assert.NotEmpty(rows);
        Assert.Contains(rows, r => PsirtStore.ReadCveIds(r.CveIdsJson).Count > 0);
    }
}
