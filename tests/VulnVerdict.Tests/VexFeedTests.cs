using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;
using VulnVerdict.Core.Feeds;
using VulnVerdict.Core.Feeds.Vex;

namespace VulnVerdict.Tests;

/// <summary>
/// The CSAF VEX feed against a fake provider: what it fetches, what it keeps, and that nothing unfinished or failed is
/// ever stepped over.
/// </summary>
public class VexFeedTests : IAsyncLifetime
{
    private const string Base = "https://vex.example.test/vex/";
    private static readonly DateTime T0 = new(2026, 9, 1, 8, 0, 0, DateTimeKind.Utc);

    private SqliteConnection _conn = null!;
    private VvDbContext _db = null!;
    private Guid _asset;
    /// <summary>The fake provider's index: path to change time. Documents are served from <see cref="_docs"/>.</summary>
    private readonly Dictionary<string, DateTime> _index = new();
    private readonly Dictionary<string, Func<HttpResponseMessage>> _docs = new();
    private string? _deletions;
    private FakeHandler _http = null!;

    public async Task InitializeAsync()
    {
        _conn = new SqliteConnection("DataSource=:memory:");
        await _conn.OpenAsync();
        _db = new VvDbContext(new DbContextOptionsBuilder<VvDbContext>().UseSqlite(_conn).Options);
        await _db.Database.EnsureCreatedAsync();
        _db.Settings.Add(new AppSetting { Key = VexProviders.SettingKey, Value = """[{"id":"redhat","name":"Red Hat","url":"https://vex.example.test/vex/","vendors":["Red Hat"]}]""" });
        var asset = new Asset { Id = Guid.NewGuid(), DisplayName = "web-01", FirstSeen = T0, LastSeen = DateTime.UtcNow };
        _db.Assets.Add(asset);
        _asset = asset.Id;
        await _db.SaveChangesAsync();

        _http = new FakeHandler()
            .On(r => r.RequestUri!.AbsoluteUri == Base + "changes.csv", (_, _) => Text(string.Join("\n", _index.Select(e => $"\"{e.Key}\",\"{e.Value:yyyy-MM-ddTHH:mm:ss}+00:00\""))))
            .On(r => r.RequestUri!.AbsoluteUri == Base + "deletions.csv", (_, _) => _deletions is null ? new HttpResponseMessage(HttpStatusCode.NotFound) : Text(_deletions))
            .On(r => r.RequestUri!.AbsoluteUri.StartsWith(Base) && _docs.ContainsKey(r.RequestUri.AbsoluteUri[Base.Length..]), (r, _) => _docs[r.RequestUri!.AbsoluteUri[Base.Length..]]());
    }

    public async Task DisposeAsync() { await _db.DisposeAsync(); await _conn.DisposeAsync(); }

    private static HttpResponseMessage Text(string body) => new(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "text/csv") };

    private static string PathOf(string cve) => cve[4..8] + "/" + cve.ToLowerInvariant() + ".json";

    /// <summary>A small Red Hat style document: openssl and curl as components of RHEL 9, each with the given status.</summary>
    private static string Doc(string cve, string openssl = "known_affected", string curl = "known_affected", string revision = "1")
    {
        object Component(string name) => new Dictionary<string, object> { ["category"] = "product_version", ["name"] = name, ["product"] = new Dictionary<string, object> { ["name"] = name, ["product_id"] = name, ["product_identification_helper"] = new Dictionary<string, object> { ["purl"] = "pkg:rpm/redhat/" + name + "?arch=src" } } };
        object Relation(string name) => new Dictionary<string, object> { ["category"] = "default_component_of", ["full_product_name"] = new Dictionary<string, object> { ["name"] = name + " as a component of Red Hat Enterprise Linux 9", ["product_id"] = "rhel9:" + name }, ["product_reference"] = name, ["relates_to_product_reference"] = "rhel9" };
        var status = new Dictionary<string, List<string>>();
        (status.TryGetValue(openssl, out var a) ? a : status[openssl] = new()).Add("rhel9:openssl");
        (status.TryGetValue(curl, out var b) ? b : status[curl] = new()).Add("rhel9:curl");
        return JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["document"] = new Dictionary<string, object> { ["category"] = "csaf_vex", ["csaf_version"] = "2.0", ["tracking"] = new Dictionary<string, object> { ["id"] = cve, ["version"] = revision, ["current_release_date"] = "2026-09-01T08:00:00+00:00" } },
            ["product_tree"] = new Dictionary<string, object>
            {
                ["branches"] = new object[] { new Dictionary<string, object> { ["category"] = "vendor", ["name"] = "Red Hat", ["branches"] = new object[]
                {
                    new Dictionary<string, object> { ["category"] = "product_name", ["name"] = "Red Hat Enterprise Linux 9", ["product"] = new Dictionary<string, object> { ["name"] = "Red Hat Enterprise Linux 9", ["product_id"] = "rhel9", ["product_identification_helper"] = new Dictionary<string, object> { ["cpe"] = "cpe:/o:redhat:enterprise_linux:9" } } },
                    Component("openssl"), Component("curl")
                } } },
                ["relationships"] = new[] { Relation("openssl"), Relation("curl") }
            },
            ["vulnerabilities"] = new object[] { new Dictionary<string, object> { ["cve"] = cve, ["product_status"] = status } }
        });
    }

    /// <summary>Publish a document on the fake provider: listed in the index and served.</summary>
    private void Publish(string cve, DateTime changed, string? body = null)
    {
        _index[PathOf(cve)] = changed;
        var json = body ?? Doc(cve);
        _docs[PathOf(cve)] = () => FakeHandler.Json(json);
    }

    private async Task<Guid> InstallAsync(string package, string vendor = "Red Hat Enterprise Linux", string? ecosystem = "Red Hat:enterprise_linux:9::baseos")
    {
        var sw = new SoftwareInstance
        {
            Id = Guid.NewGuid(), AssetId = _asset, Vendor = vendor, Product = package, Version = "1.0-1.el9", VendorNorm = Normalizer.Norm(vendor), ProductNorm = Normalizer.Norm(package),
            Ecosystem = ecosystem, Purl = ecosystem is null ? null : "pkg:rpm/redhat/" + package + "@1.0-1.el9", MappingStatus = ecosystem is null ? MappingStatus.Exact : MappingStatus.Package, ConnectorId = "test", FirstSeen = T0, LastSeen = DateTime.UtcNow
        };
        _db.Software.Add(sw);
        await _db.SaveChangesAsync();
        _db.ChangeTracker.Clear();
        return sw.Id;
    }

    /// <summary>A verdict for this CVE against this software: what makes the CVE's document wanted.</summary>
    private async Task VerdictAsync(string cve, Guid software)
    {
        if (!await _db.Cves.AnyAsync(c => c.Id == cve)) _db.Cves.Add(new Cve { Id = cve, State = "PUBLISHED", RetrievedAt = T0 });
        _db.Verdicts.Add(new Verdict { Id = Guid.NewGuid(), CveId = cve, SoftwareInstanceId = software, AssetId = _asset, Tier = VerdictTier.FixThisWeek, CreatedAt = T0, UpdatedAt = T0, LastEvaluatedAt = T0 });
        await _db.SaveChangesAsync();
        _db.ChangeTracker.Clear();
    }

    private Task<FeedResult> RunAsync(CsafVexFeed? feed = null, string? cursor = null) =>
        (feed ?? new CsafVexFeed()).RunAsync(new FeedContext { Db = _db, Http = new HttpClient(_http), Log = NullLogger.Instance, DataDir = Path.GetTempPath(), Cursor = cursor }, CancellationToken.None);

    private int Fetches(string cve) => _http.Calls.Count(c => c.Url.AbsoluteUri == Base + PathOf(cve));
    private static string Cve(int n) => $"CVE-2099-{n:D4}";

    // ---- what is fetched and kept ------------------------------------------------------------------------------------

    [Fact]
    public async Task Only_documents_for_cves_with_a_verdict_are_fetched_and_only_statements_about_installed_products_kept()
    {
        var openssl = await InstallAsync("openssl");
        await VerdictAsync(Cve(1), openssl);
        await VerdictAsync(Cve(2), openssl);
        for (var i = 1; i <= 4; i++) Publish(Cve(i), T0.AddHours(i));   // 3 and 4 concern nothing installed here

        var r = await RunAsync();

        Assert.Equal(2, r.Records);
        Assert.False(r.MoreSoon);
        Assert.Equal((1, 1, 0, 0), (Fetches(Cve(1)), Fetches(Cve(2)), Fetches(Cve(3)), Fetches(Cve(4))));
        var statements = await _db.VexStatements.AsNoTracking().ToListAsync();
        Assert.Equal(new[] { Cve(1), Cve(2) }, statements.Select(s => s.CveId).OrderBy(c => c));
        Assert.All(statements, s => Assert.Equal(("openssl", "Red Hat Enterprise Linux 9", VexStatus.KnownAffected), (s.Product, s.Platform, s.Status)));   // curl is not installed: not kept
        var docs = await _db.VexDocuments.AsNoTracking().OrderBy(d => d.Path).ToListAsync();
        Assert.Equal(new[] { PathOf(Cve(1)), PathOf(Cve(2)) }, docs.Select(d => d.Path));
        Assert.All(docs, d => { Assert.Equal("openssl", d.Scope); Assert.Equal(1, d.Statements); Assert.Equal(0, d.Attempts); Assert.NotNull(d.ChangedAt); });
        Assert.Equal("redhat:2026-09-01T10:00:00Z", r.Cursor);   // the newest change among the documents wanted here

        // nothing changed: the index is read again, no document is
        var again = await RunAsync(cursor: r.Cursor);
        Assert.Equal(0, again.Records);
        Assert.Equal((1, 1), (Fetches(Cve(1)), Fetches(Cve(2))));
    }

    [Fact]
    public async Task A_provider_is_not_called_when_none_of_its_products_are_installed()
    {
        await InstallAsync("FortiClient", "Fortinet", ecosystem: null);
        Publish(Cve(1), T0);
        var r = await RunAsync(cursor: "kept");
        Assert.Empty(_http.Calls);
        Assert.Equal("kept", r.Cursor);
        Assert.Contains("not called", r.Note);
    }

    // ---- resuming ----------------------------------------------------------------------------------------------------

    [Fact]
    public async Task A_capped_run_asks_to_run_again_and_carries_on_where_it_stopped()
    {
        var openssl = await InstallAsync("openssl");
        for (var i = 1; i <= 5; i++) { await VerdictAsync(Cve(i), openssl); Publish(Cve(i), T0.AddHours(i)); }
        var feed = new CsafVexFeed { MaxDocumentsPerRun = 2 };

        var r1 = await RunAsync(feed);
        Assert.True(r1.MoreSoon);
        Assert.Equal(2, await _db.VexDocuments.CountAsync(d => d.ChangedAt != null));
        // newest first, so the cursor is held at the oldest document still to do
        Assert.Equal("redhat:held 2026-09-01T09:00:00Z", r1.Cursor);

        var r2 = await RunAsync(feed, r1.Cursor);
        Assert.True(r2.MoreSoon);
        var r3 = await RunAsync(feed, r2.Cursor);
        Assert.False(r3.MoreSoon);
        Assert.Equal("redhat:2026-09-01T13:00:00Z", r3.Cursor);
        Assert.Equal(5, await _db.VexStatements.CountAsync());
        Assert.All(Enumerable.Range(1, 5), i => Assert.Equal(1, Fetches(Cve(i))));   // each document exactly once across the three runs
    }

    [Fact]
    public async Task A_failed_document_keeps_its_place_and_is_retried_while_the_rest_are_stored()
    {
        var openssl = await InstallAsync("openssl");
        for (var i = 1; i <= 3; i++) { await VerdictAsync(Cve(i), openssl); Publish(Cve(i), T0.AddHours(i)); }
        var down = true;
        var good = _docs[PathOf(Cve(2))];
        _docs[PathOf(Cve(2))] = () => down ? new HttpResponseMessage(HttpStatusCode.BadGateway) : good();

        var r1 = await RunAsync();
        Assert.Equal(2, r1.Records);
        Assert.False(r1.MoreSoon);                                    // nothing untried is left; the failure waits for the next scheduled run
        Assert.Equal("redhat:held 2026-09-01T10:00:00Z", r1.Cursor);  // held at the failed document, not moved to the newest
        Assert.Contains("1 failed and will be retried", r1.Note);
        var failed = await _db.VexDocuments.AsNoTracking().SingleAsync(d => d.Path == PathOf(Cve(2)));
        Assert.Equal((1, (DateTime?)null), (failed.Attempts, failed.ChangedAt));
        Assert.NotNull(failed.LastError);

        down = false;
        var r2 = await RunAsync(cursor: r1.Cursor);
        Assert.Equal(1, r2.Records);
        Assert.Equal("redhat:2026-09-01T11:00:00Z", r2.Cursor);
        var retried = await _db.VexDocuments.AsNoTracking().SingleAsync(d => d.Path == PathOf(Cve(2)));
        Assert.Equal((0, (string?)null), (retried.Attempts, retried.LastError));
        Assert.Equal(3, await _db.VexStatements.CountAsync());
        Assert.Equal((1, 2, 1), (Fetches(Cve(1)), Fetches(Cve(2)), Fetches(Cve(3))));
    }

    [Fact]
    public async Task A_new_revision_replaces_the_statements_and_a_broken_one_leaves_them_alone()
    {
        var openssl = await InstallAsync("openssl");
        await VerdictAsync(Cve(1), openssl);
        Publish(Cve(1), T0, Doc(Cve(1), openssl: "known_not_affected"));
        await RunAsync();
        Assert.Equal(VexStatus.KnownNotAffected, (await _db.VexStatements.AsNoTracking().SingleAsync()).Status);

        // the next revision is an error page saying 200: not a CSAF document, so the stored statement stays and the document stays due
        Publish(Cve(1), T0.AddDays(1), "{\"error\":\"temporarily unavailable\"}");
        var broken = await RunAsync();
        Assert.Contains("failed", broken.Note);
        Assert.Equal(VexStatus.KnownNotAffected, (await _db.VexStatements.AsNoTracking().SingleAsync()).Status);
        Assert.Equal(T0, (await _db.VexDocuments.AsNoTracking().SingleAsync()).ChangedAt);

        // the vendor withdraws not-affected in revision 2
        Publish(Cve(1), T0.AddDays(1), Doc(Cve(1), openssl: "known_affected", revision: "2"));
        await RunAsync();
        var now = await _db.VexStatements.AsNoTracking().SingleAsync();
        Assert.Equal((VexStatus.KnownAffected, "2"), (now.Status, now.Revision));
        Assert.Equal(T0.AddDays(1), (await _db.VexDocuments.AsNoTracking().SingleAsync()).ChangedAt);
    }

    [Fact]
    public async Task A_product_installed_later_brings_its_statements_in_from_documents_already_read()
    {
        var openssl = await InstallAsync("openssl");
        await VerdictAsync(Cve(1), openssl);
        Publish(Cve(1), T0);
        await RunAsync();
        Assert.Equal("openssl", (await _db.VexStatements.AsNoTracking().SingleAsync()).Product);

        var curl = await InstallAsync("curl");
        await VerdictAsync(Cve(1), curl);
        var r = await RunAsync();
        Assert.Equal(2, Fetches(Cve(1)));
        Assert.Equal(new[] { "curl", "openssl" }, (await _db.VexStatements.AsNoTracking().Select(s => s.Product).ToListAsync()).OrderBy(p => p));
        Assert.Equal("curl|openssl", (await _db.VexDocuments.AsNoTracking().SingleAsync()).Scope);
        Assert.Equal(2, r.Records);
    }

    // ---- withdrawn documents and the floor ---------------------------------------------------------------------------

    [Fact]
    public async Task A_withdrawn_document_takes_its_statements_with_it_but_a_truncated_index_removes_nothing()
    {
        var openssl = await InstallAsync("openssl");
        for (var i = 1; i <= 12; i++) { await VerdictAsync(Cve(i), openssl); Publish(Cve(i), T0.AddHours(i)); }
        await RunAsync();
        Assert.Equal(12, await _db.VexStatements.CountAsync());

        // Red Hat lists removals in deletions.csv; a deletion newer than the last change takes the document out
        _deletions = $"\"{PathOf(Cve(12))}\",\"2026-09-03T00:00:00+00:00\"\n\"{PathOf(Cve(11))}\",\"2026-08-01T00:00:00+00:00\"";
        var r = await RunAsync();
        Assert.Contains("1 withdrawn", r.Note);
        Assert.Equal(11, await _db.VexStatements.CountAsync());
        Assert.False(await _db.VexStatements.AnyAsync(s => s.CveId == Cve(12)));
        Assert.True(await _db.VexStatements.AnyAsync(s => s.CveId == Cve(11)));   // deleted before it was last changed: republished since

        // an index that has lost most of what is stored is a bad download: the only provider fails, so the feed fails, and nothing is removed
        foreach (var path in _index.Keys.Skip(3).ToList()) _index.Remove(path);
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => RunAsync());
        Assert.Contains("not removing them", ex.Message);
        Assert.Equal(11, await _db.VexStatements.CountAsync());
        Assert.Equal(11, await _db.VexDocuments.CountAsync());
    }

    [Fact]
    public async Task A_provider_that_is_down_is_given_up_on_for_the_run_instead_of_being_asked_for_every_document()
    {
        var openssl = await InstallAsync("openssl");
        for (var i = 1; i <= 9; i++) { await VerdictAsync(Cve(i), openssl); _index[PathOf(Cve(i))] = T0.AddHours(i); }   // listed, but every fetch is a 404

        var r = await RunAsync();
        Assert.Equal(5, _http.Calls.Count(c => c.Url.AbsolutePath.Contains("/cve-")));
        Assert.False(r.MoreSoon);
        Assert.StartsWith("redhat:held ", r.Cursor);
        Assert.Equal(0, await _db.VexStatements.CountAsync());
    }

    // ---- indexes -----------------------------------------------------------------------------------------------------

    [Fact]
    public void Changes_csv_rows_are_read_whatever_their_order_and_junk_is_skipped()
    {
        var rows = CsafVexFeed.ParseChanges("\"2026/cve-2026-0002.json\",\"2026-10-02T17:42:43+00:00\"\n\"cve-2017-1000404.json\",\"2023-02-15T04:34:59Z\"\nnot,a,row\n\"../etc/passwd.json\",\"2026-01-01T00:00:00Z\"\n\"2026/notes.txt\",\"2026-01-01T00:00:00Z\"\n").ToList();
        Assert.Equal(new[] { ("2026/cve-2026-0002.json", new DateTime(2026, 10, 2, 17, 42, 43, DateTimeKind.Utc)), ("cve-2017-1000404.json", new DateTime(2023, 2, 15, 4, 34, 59, DateTimeKind.Utc)) }, rows);
        Assert.Equal("CVE-2026-0002", CsafVexFeed.CveInPath("2026/cve-2026-0002.json"));
        Assert.Equal("CVE-2026-69896", CsafVexFeed.CveInPath("2026/msrc_cve-2026-69896.json"));
        Assert.Null(CsafVexFeed.CveInPath("2099/ex-sa-2099-01.json"));
    }

    [Fact]
    public async Task Provider_metadata_leads_to_the_vex_directory_and_a_rolie_feed_lists_documents_by_url()
    {
        using var meta = JsonDocument.Parse(Fixtures.Read("vex", "provider-metadata.json"));
        var (directories, feeds) = CsafVexFeed.Distributions(meta.RootElement);
        Assert.Equal(new[] { "https://csaf.example.test/csaf/advisories/", "https://csaf.example.test/csaf/vex/" }, directories);
        Assert.Equal(new[] { "https://csaf.example.test/csaf/feed-tlp-white.json" }, feeds);

        var http = new FakeHandler()
            .On(HttpMethod.Get, "provider-metadata.json", Fixtures.Read("vex", "provider-metadata.json"))
            .On(r => r.RequestUri!.AbsoluteUri == "https://csaf.example.test/csaf/vex/changes.csv", (_, _) => Text("\"2099/cve-2099-0001.json\",\"2026-09-01T08:00:00Z\""));
        var index = await CsafVexFeed.ReadIndexAsync(new HttpClient(http), new VexProvider("ex", "Example", "https://csaf.example.test/.well-known/csaf/provider-metadata.json", new[] { "Example" }), CancellationToken.None);
        Assert.Equal("https://csaf.example.test/csaf/vex/2099/cve-2099-0001.json", Assert.Single(index).Value.Url);

        using var rolie = JsonDocument.Parse(Fixtures.Read("vex", "rolie_feed.json"));
        var entries = CsafVexFeed.ParseRolie(rolie.RootElement);
        Assert.Equal(2, entries.Count);   // the entry served over plain http is not followed
        Assert.Equal(("https://csaf.example.test/csaf/white/2099/ex-sa-2099-01.json", new DateTime(2026, 9, 15, 10, 0, 0, DateTimeKind.Utc)), (entries[0].Url, entries[0].Changed));
    }

    [Fact]
    public async Task Documents_not_named_by_cve_are_read_in_full_for_a_vendor_that_is_installed()
    {
        // an advisory provider behind a ROLIE feed: the file name says nothing, so every statement is kept
        _db.Settings.RemoveRange(_db.Settings);
        _db.Settings.Add(new AppSetting { Key = VexProviders.SettingKey, Value = """[{"id":"example","name":"Example Networks","url":"https://csaf.example.test/csaf/feed-tlp-white.json","vendors":["Example Networks"]}]""" });
        _db.Watchlist.Add(new WatchlistEntry { Id = Guid.NewGuid(), Vendor = "Example Networks", Product = "ExampleOS", VendorNorm = "examplenetworks", ProductNorm = "exampleos", Version = "7.2.5", CreatedAt = T0, UpdatedAt = T0 });
        await _db.SaveChangesAsync();
        _http.On(HttpMethod.Get, "feed-tlp-white.json", Fixtures.Read("vex", "rolie_feed.json"))
             .On(HttpMethod.Get, "ex-sa-2099-01.json", Fixtures.Read("vex", "vendor_advisory.json"));   // the second entry is a 404

        var r = await RunAsync();
        Assert.Equal(4, r.Records);
        Assert.Contains("1 failed and will be retried", r.Note);
        var doc = await _db.VexDocuments.AsNoTracking().SingleAsync(d => d.ChangedAt != null);
        Assert.Equal(("*", "EX-SA-2099-01", (string?)null), (doc.Scope, doc.DocumentId, doc.CveId));
        Assert.Equal(4, await _db.VexStatements.CountAsync(s => s.Provider == "example"));
    }

    // ---- live (VV_LIVE_TESTS=1) ----------------------------------------------------------------------------------------

    [LiveFact]
    public async Task Live_redhat_vex_index_and_one_document()
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(120) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("VulnVerdict/0.2 (tests)");
        var redhat = VexProviders.Defaults.Single(p => p.Id == "redhat");
        var index = await CsafVexFeed.ReadIndexAsync(http, redhat, CancellationToken.None);
        Assert.True(index.Count > 10_000, "Red Hat lists one VEX document per CVE");
        var entry = index.Values.First(e => e.Path.EndsWith("cve-2024-6387.json"));
        using var doc = JsonDocument.Parse(await http.GetStringAsync(entry.Url));
        var parsed = CsafVexParser.Parse(doc.RootElement, redhat.Id, redhat.Name, entry.Url, DateTime.UtcNow, n => n == "openssh");
        Assert.Equal("CVE-2024-6387", parsed.DocumentId);
        Assert.Contains(parsed.Statements, s => s.Status == VexStatus.Fixed && s.Version is not null && s.PlatformCpe is not null);
        Assert.Contains(parsed.Statements, s => s.Status == VexStatus.KnownNotAffected);
    }
}
