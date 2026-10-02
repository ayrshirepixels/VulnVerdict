using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

/// <summary>Merging assets across sources, mapping software to CNA names, exposure evidence, coverage.</summary>
public class InventoryServiceTests : IDisposable
{
    private readonly SqliteConnection _conn;
    private readonly TestFactory _factory;

    private sealed class TestFactory : IDbContextFactory<VvDbContext>
    {
        private readonly DbContextOptions<SqliteVvDbContext> _o;
        public TestFactory(SqliteConnection c) => _o = new DbContextOptionsBuilder<SqliteVvDbContext>().UseSqlite(c).Options;
        public VvDbContext CreateDbContext() => new SqliteVvDbContext(_o);
        public Task<VvDbContext> CreateDbContextAsync(CancellationToken ct = default) => Task.FromResult(CreateDbContext());
    }

    public InventoryServiceTests()
    {
        _conn = new SqliteConnection("Data Source=:memory:");
        _conn.Open();
        _factory = new TestFactory(_conn);
        using var db = _factory.CreateDbContext();
        db.Database.EnsureCreated();
        db.CnaProducts.AddRange(
            new CnaProduct { VendorNorm = "microsoft", ProductNorm = "windowsserver2022", Vendor = "Microsoft", Product = "Windows Server 2022", CveCount = 100, LastSeen = DateTime.UtcNow },
            new CnaProduct { VendorNorm = "fortinet", ProductNorm = "fortios", Vendor = "Fortinet", Product = "FortiOS", CveCount = 50, LastSeen = DateTime.UtcNow },
            new CnaProduct { VendorNorm = "google", ProductNorm = "chrome", Vendor = "Google", Product = "Chrome", CveCount = 900, LastSeen = DateTime.UtcNow });
        db.Aliases.Add(new ProductAlias { AliasNorm = "fortigate", VendorNorm = "fortinet", ProductNorm = "fortios" });
        db.SaveChanges();
    }

    public void Dispose() => _conn.Dispose();

    private InventoryService Svc() => new(_factory, NullLogger<InventoryService>.Instance);
    private static Connector Conn(string adapter, string name) => new() { Id = Guid.NewGuid(), AdapterId = adapter, DisplayName = name, Enabled = true };

    [Fact]
    public async Task Assets_from_two_sources_merge_by_mac_and_hostname()
    {
        var svc = Svc();
        var ems = Conn("forticlient-ems", "EMS");
        var r1 = new CollectResult();
        r1.Assets.Add(new AssetRecord("ems-1", "DC-01", AssetKind.Server, new[] { "dc-01.corp.local" }, new[] { "10.0.0.5" }, new[] { "00-11-22-33-44-55" }, "Microsoft", "Windows Server 2022", "10.0.20348.2000", "10.0.20348.2000"));
        r1.Software.Add(new SoftwareRecord("ems-1", "Google", "Google Chrome", "128.0.6613.84"));
        await svc.ApplyAsync(ems, r1, CancellationToken.None);

        var winrm = Conn("winrm", "WinRM");
        var r2 = new CollectResult();
        r2.Assets.Add(new AssetRecord("dc-01", "DC-01", AssetKind.Server, new[] { "DC-01" }, new[] { "10.0.0.5" }, new[] { "00:11:22:33:44:55" }, "Microsoft", "Windows Server 2022", "10.0.20348.2000", "10.0.20348.2000"));
        r2.Software.Add(new SoftwareRecord("dc-01", "Microsoft", "Windows Server 2022", "10.0.20348.2000", SoftwareKind.OperatingSystem));
        r2.Software.Add(new SoftwareRecord("dc-01", "Microsoft", "Windows SMBv1", "", SoftwareKind.RoleOrFeature, Enabled: false));
        await svc.ApplyAsync(winrm, r2, CancellationToken.None);

        await using var db = _factory.CreateDbContext();
        var assets = await db.Assets.Include(a => a.Sources).ToListAsync();
        Assert.Single(assets);
        Assert.Equal(2, assets[0].Sources.Count);
        Assert.False(assets[0].Unknown);
        var software = await db.Software.ToListAsync();
        Assert.Equal(3, software.Count);
        Assert.Equal(MappingStatus.Exact, software.First(s => s.Product == "Windows Server 2022").MappingStatus);
        // "Google Chrome" is mapped through the version-stripped / fuzzy path or stays unmapped; it must not be Exact
        var chrome = software.First(s => s.Product == "Google Chrome");
        Assert.NotEqual(MappingStatus.Exact, chrome.MappingStatus);
        Assert.False(software.First(s => s.Product == "Windows SMBv1").Enabled);
    }

    [Fact]
    public async Task Alias_table_maps_display_names_and_accepting_a_mapping_is_remembered()
    {
        var svc = Svc();
        var c = Conn("snmp", "SNMP");
        var r = new CollectResult();
        r.Assets.Add(new AssetRecord("10.0.0.1", "fw-edge-01", AssetKind.Firewall, new[] { "fw-edge-01" }, new[] { "10.0.0.1" }, Array.Empty<string>()));
        r.Software.Add(new SoftwareRecord("10.0.0.1", "Fortinet", "FortiGate", "7.2.5", SoftwareKind.Firmware));
        r.Software.Add(new SoftwareRecord("10.0.0.1", "Acme", "Widget Manager", "1.0", SoftwareKind.Firmware));
        await svc.ApplyAsync(c, r, CancellationToken.None);

        await using (var db = _factory.CreateDbContext())
        {
            var fw = await db.Software.FirstAsync(s => s.Product == "FortiGate");
            Assert.Equal(MappingStatus.Alias, fw.MappingStatus);
            Assert.Equal("fortios", fw.MappedProductNorm);
            var unmapped = await db.Software.FirstAsync(s => s.Product == "Widget Manager");
            Assert.Equal(MappingStatus.Unmapped, unmapped.MappingStatus);
            var asset = await db.Assets.FirstAsync();
            Assert.Equal(Criticality.Critical, asset.Criticality); // firewalls default to critical
        }

        await svc.AcceptMappingAsync("acme", "widgetmanager", "google", "chrome", "tester");
        await using (var db = _factory.CreateDbContext())
        {
            Assert.Equal(MappingStatus.Alias, (await db.Software.FirstAsync(s => s.Product == "Widget Manager")).MappingStatus);
            Assert.True(await db.Aliases.AnyAsync(a => a.AliasNorm == "acmewidgetmanager"));
        }
    }

    [Fact]
    public async Task Exposure_evidence_raises_exposure_unless_pinned_and_discovery_hosts_are_unknown()
    {
        var svc = Svc();
        var disc = Conn("discovery-sweep", "Sweep");
        var r = new CollectResult();
        r.Assets.Add(new AssetRecord("10.0.0.9", "10.0.0.9", AssetKind.Other, Array.Empty<string>(), new[] { "10.0.0.9" }, Array.Empty<string>()));
        await svc.ApplyAsync(disc, r, CancellationToken.None);

        var fg = Conn("fortigate", "FortiGate");
        var r2 = new CollectResult();
        r2.Exposures.Add(new ExposureRecord(Exposure.Internet, "VIP web-in 203.0.113.10:443 policy 12", IpAddress: "10.0.0.9"));
        await svc.ApplyAsync(fg, r2, CancellationToken.None);

        await using (var db = _factory.CreateDbContext())
        {
            var a = await db.Assets.FirstAsync();
            Assert.True(a.Unknown);
            Assert.Equal(Exposure.Internet, a.Exposure);
            Assert.Contains("policy 12", a.ExposureEvidence);
            a.ExposurePinned = true; a.Exposure = Exposure.Isolated;
            await db.SaveChangesAsync();
        }
        await svc.ApplyAsync(fg, r2, CancellationToken.None);
        await using (var db = _factory.CreateDbContext())
            Assert.Equal(Exposure.Isolated, (await db.Assets.FirstAsync()).Exposure);

        var cov = await svc.CoverageAsync();
        Assert.Equal(1, cov.Unknown);
    }

    [Fact]
    public async Task Full_snapshot_removes_software_no_longer_reported()
    {
        var svc = Svc();
        var c = Conn("winrm", "WinRM");
        var r = new CollectResult();
        r.Assets.Add(new AssetRecord("srv", "SRV", AssetKind.Server, new[] { "srv" }, new[] { "10.0.0.3" }, Array.Empty<string>()));
        r.Software.Add(new SoftwareRecord("srv", "Google", "Chrome", "127.0.0.1"));
        r.Software.Add(new SoftwareRecord("srv", "Google", "Chrome", "128.0.0.1"));
        await svc.ApplyAsync(c, r, CancellationToken.None);
        var r2 = new CollectResult();
        r2.Assets.Add(r.Assets[0]);
        r2.Software.Add(new SoftwareRecord("srv", "Google", "Chrome", "129.0.0.1"));
        await svc.ApplyAsync(c, r2, CancellationToken.None);
        await using var db = _factory.CreateDbContext();
        var sw = await db.Software.ToListAsync();
        Assert.Single(sw);
        Assert.Equal("129.0.0.1", sw[0].Version);
        Assert.Equal(MappingStatus.Exact, sw[0].MappingStatus);
    }
}
