using System.IO.Compression;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Feeds;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

/// <summary>The CVE List feed's baseline reload and delta cursor, against fake GitHub releases and in-memory SQLite.</summary>
public class CveListFeedTests : IDisposable
{
    private readonly SqliteConnection _conn;
    private readonly VvDbContext _db;
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "vv-cvelist-test-" + Guid.NewGuid().ToString("N"));
    private readonly FakeHandler _http = new();
    private readonly ListLogger _log = new();

    public CveListFeedTests()
    {
        _conn = new SqliteConnection("Data Source=:memory:");
        _conn.Open();
        _db = new VvDbContext(new DbContextOptionsBuilder<VvDbContext>().UseSqlite(_conn).Options);
        _db.Database.EnsureCreated();
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        _db.Dispose(); _conn.Dispose();
        try { Directory.Delete(_dir, true); } catch { }
    }

    private sealed class ListLogger : ILogger
    {
        public List<string> Lines { get; } = new();
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) => Lines.Add(formatter(state, exception));
    }

    // ------------------------------------------------------------------ fakes

    private static string Record(string id, string title) => JsonSerializer.Serialize(new
    {
        dataType = "CVE_RECORD",
        cveMetadata = new { cveId = id, state = "PUBLISHED", assignerShortName = "fortinet", datePublished = "2024-02-09T09:31:34.588Z" },
        containers = new { cna = new { title, affected = new[] { new { vendor = "Fortinet", product = "FortiOS" } } } }
    });

    private static byte[] Zip(params (string Name, string Text)[] files) => ZipBytes(files.Select(f => (f.Name, Encoding.UTF8.GetBytes(f.Text))).ToArray());

    private static byte[] ZipBytes(params (string Name, byte[] Bytes)[] files)
    {
        using var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, true))
            foreach (var (name, bytes) in files)
            {
                using var s = zip.CreateEntry(name).Open();
                s.Write(bytes);
            }
        return ms.ToArray();
    }

    /// <summary>The midnight snapshot's shape: a zip holding a zip of records.</summary>
    private static byte[] Baseline(params (string Id, string Title)[] cves) =>
        ZipBytes(("cves.zip", Zip(cves.Select(c => ("cves/2024/" + c.Id + ".json", Record(c.Id, c.Title))).ToArray())));

    /// <summary>Releases newest first; each asset maps a name to its bytes, or null for a download that fails.</summary>
    private void Releases(params (string Tag, (string Name, byte[]? Bytes)[] Assets)[] releases)
    {
        var arr = new JsonArray();
        foreach (var (tag, assets) in releases)
        {
            var list = new JsonArray();
            foreach (var (name, bytes) in assets)
            {
                list.Add(new JsonObject { ["name"] = name, ["browser_download_url"] = "https://assets.test/" + name, ["size"] = bytes?.Length ?? 0 });
                _http.On(r => r.RequestUri!.AbsoluteUri == "https://assets.test/" + name,
                    (_, _) => bytes is null ? new HttpResponseMessage(HttpStatusCode.InternalServerError) : new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) });
            }
            arr.Add(new JsonObject { ["tag_name"] = tag, ["assets"] = list });
        }
        _http.On(HttpMethod.Get, "releases?per_page=100&page=1", arr.ToJsonString());
        _http.On(HttpMethod.Get, "releases?per_page=100&page=", "[]");
    }

    private FeedContext Ctx(string? cursor) => new() { Db = _db, Http = new HttpClient(_http), Log = _log, DataDir = _dir, Cursor = cursor };

    private async Task<Guid> SeedVerdictAsync(string cveId, string title)
    {
        _db.Cves.Add(new Cve { Id = cveId, State = "PUBLISHED", Title = title, RetrievedAt = DateTime.UtcNow, SourceRef = "cve_2026-08-01_0100Z",
            Affected = { new CveAffected { Vendor = "Fortinet", Product = "FortiOS", VendorNorm = "fortinet", ProductNorm = "fortios" } } });
        var v = new Verdict { Id = Guid.NewGuid(), CveId = cveId, Subject = "Fortinet FortiOS 7.2.5 on FW-EDGE-01", Tier = VerdictTier.FixToday, State = VerdictState.AcceptedRisk, Sentence = "x",
            CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow, LastEvaluatedAt = DateTime.UtcNow };
        _db.Verdicts.Add(v);
        _db.VerdictHistory.Add(new VerdictHistory { VerdictId = v.Id, At = DateTime.UtcNow, Kind = "state", From = "Open", To = "AcceptedRisk" });
        await _db.SaveChangesAsync();
        _db.ChangeTracker.Clear();
        return v.Id;
    }

    // ------------------------------------------------------------------ baseline reload

    [Fact]
    public async Task Reload_upserts_and_keeps_existing_verdicts()
    {
        var kept = await SeedVerdictAsync("CVE-2024-0001", "old title");
        var gone = await SeedVerdictAsync("CVE-2024-0002", "withdrawn upstream");
        Releases(
            ("cve_2026-10-02_0100Z", new[] { ("2026-10-02_all_CVEs_at_midnight.zip.zip", Baseline(("CVE-2024-0001", "new title"), ("CVE-2024-0003", "brand new"))),
                                             ("2026-10-02_delta_CVEs_at_0100Z.zip", (byte[]?)Zip()) }),
            ("cve_2026-10-02_0000Z", new[] { ("2026-10-02_delta_CVEs_at_0000Z.zip", (byte[]?)Zip()) }));

        // an old parser version in the cursor forces the full reload
        var result = await new CveListFeed().RunAsync(Ctx("tag=cve_2026-10-02_0000Z;parser=1"), CancellationToken.None);

        Assert.Equal("tag=cve_2026-10-02_0100Z;parser=" + CveListFeed.ParserVersion, result.Cursor);
        Assert.Equal("new title", (await _db.Cves.FindAsync("CVE-2024-0001"))!.Title);
        Assert.NotNull(await _db.Cves.FindAsync("CVE-2024-0003"));
        Assert.Equal(1, await _db.CveAffected.CountAsync(a => a.CveId == "CVE-2024-0001"));
        Assert.Equal(VerdictState.AcceptedRisk, (await _db.Verdicts.FindAsync(kept))!.State);
        Assert.Equal(2, await _db.VerdictHistory.CountAsync());
        // absent from the completed baseline: marked rejected, not deleted, so its verdict is not cascaded away
        Assert.Equal("REJECTED", (await _db.Cves.FindAsync("CVE-2024-0002"))!.State);
        Assert.NotNull(await _db.Verdicts.FindAsync(gone));
    }

    [Fact]
    public async Task Failed_reload_leaves_existing_data_intact()
    {
        var kept = await SeedVerdictAsync("CVE-2024-0001", "old title");
        Releases(
            ("cve_2026-10-02_0100Z", new[] { ("2026-10-02_all_CVEs_at_midnight.zip.zip", Baseline(("CVE-2024-0001", "new title"), ("CVE-2024-0003", "brand new"))),
                                             ("2026-10-02_delta_CVEs_at_0100Z.zip", (byte[]?)null) }));

        await Assert.ThrowsAsync<HttpRequestException>(() => new CveListFeed().RunAsync(Ctx(null), CancellationToken.None));

        _db.ChangeTracker.Clear();
        Assert.Equal("old title", (await _db.Cves.FindAsync("CVE-2024-0001"))!.Title);
        Assert.Null(await _db.Cves.FindAsync("CVE-2024-0003"));
        Assert.Equal(1, await _db.CveAffected.CountAsync());
        Assert.NotNull(await _db.Verdicts.FindAsync(kept));
    }

    // ------------------------------------------------------------------ deltas

    [Fact]
    public async Task Missing_delta_asset_does_not_advance_the_cursor()
    {
        Releases(
            ("cve_2026-10-02_0300Z", new[] { ("2026-10-02_delta_CVEs_at_0300Z.zip", (byte[]?)Zip(("deltaCves/CVE-2024-0009.json", Record("CVE-2024-0009", "later")))) }),
            ("cve_2026-10-02_0200Z", Array.Empty<(string, byte[]?)>()),
            ("cve_2026-10-02_0100Z", new[] { ("2026-10-02_delta_CVEs_at_0100Z.zip", (byte[]?)Zip(("deltaCves/CVE-2024-0005.json", Record("CVE-2024-0005", "applied")))) }),
            ("cve_2026-10-02_0000Z", Array.Empty<(string, byte[]?)>()));

        var result = await new CveListFeed().RunAsync(Ctx("tag=cve_2026-10-02_0000Z;parser=" + CveListFeed.ParserVersion), CancellationToken.None);

        Assert.Equal("tag=cve_2026-10-02_0100Z;parser=" + CveListFeed.ParserVersion, result.Cursor);
        Assert.NotNull(await _db.Cves.FindAsync("CVE-2024-0005"));
        Assert.Null(await _db.Cves.FindAsync("CVE-2024-0009"));
        Assert.Contains("waiting for cve_2026-10-02_0200Z", result.Note);
    }

    [Fact]
    public async Task Unreadable_records_are_counted_in_the_status_and_logged_by_id()
    {
        Releases(("cve_2026-10-02_0100Z", new[] { ("2026-10-02_delta_CVEs_at_0100Z.zip", (byte[]?)Zip(
            ("deltaCves/CVE-2024-0005.json", Record("CVE-2024-0005", "fine")),
            ("deltaCves/CVE-2024-0006.json", "{ not json"))) }),
            ("cve_2026-10-02_0000Z", Array.Empty<(string, byte[]?)>()));

        var result = await new CveListFeed().RunAsync(Ctx("tag=cve_2026-10-02_0000Z;parser=" + CveListFeed.ParserVersion), CancellationToken.None);

        Assert.Equal(1, result.Records);
        Assert.Contains("1 unreadable", result.Note);
        Assert.Contains(_log.Lines, l => l.Contains("CVE-2024-0006"));
    }

    // ------------------------------------------------------------------ bundles

    [Fact]
    public async Task Bundle_with_a_cve_repeated_across_batches_applies_to_a_fresh_database()
    {
        using var key = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var manifest = await TestBundleWriter.WriteAsync(_db, _dir, key, CancellationToken.None, version: "202610020800");

        // 2,001 records then the first again: the repeat lands in the second batch of 2,000
        var lines = Enumerable.Range(1, 2001).Select(i => JsonSerializer.Serialize(BundleCve.From(new Cve { Id = "CVE-2024-" + i.ToString("D5"), State = "PUBLISHED", RetrievedAt = DateTime.UtcNow }), BundleJson.Options)).ToList();
        lines.Add(lines[0]);
        var path = Path.Combine(_dir, BundleFiles.Cves);
        await File.WriteAllLinesAsync(path, lines);
        manifest.Files.RemoveAll(f => f.Name == BundleFiles.Cves);
        manifest.Files.Add(new BundleFile(BundleFiles.Cves, await BundleHash.FileSha256Async(path, CancellationToken.None), new FileInfo(path).Length));

        var result = await BundleApplier.ApplyAsync(_db, manifest, _dir, "test", CancellationToken.None);

        Assert.Equal(2001, result.Cves);
        Assert.Equal(2001, await _db.Cves.CountAsync());
    }
}
