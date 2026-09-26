using Microsoft.EntityFrameworkCore;

namespace VulnVerdict.Core.Data;

public class VvDbContext : DbContext
{
    public VvDbContext(DbContextOptions<VvDbContext> options) : base(options) { }
    protected VvDbContext(DbContextOptions options) : base(options) { }

    public DbSet<Cve> Cves => Set<Cve>();
    public DbSet<CveAffected> CveAffected => Set<CveAffected>();
    public DbSet<CnaProduct> CnaProducts => Set<CnaProduct>();
    public DbSet<KevEntry> Kev => Set<KevEntry>();
    public DbSet<EpssScore> Epss => Set<EpssScore>();
    public DbSet<ExploitSignal> ExploitSignals => Set<ExploitSignal>();
    public DbSet<FeedStatus> FeedStatuses => Set<FeedStatus>();
    public DbSet<WatchlistEntry> Watchlist => Set<WatchlistEntry>();
    public DbSet<Verdict> Verdicts => Set<Verdict>();
    public DbSet<VerdictHistory> VerdictHistory => Set<VerdictHistory>();
    public DbSet<SuppressionRule> Suppressions => Set<SuppressionRule>();
    public DbSet<Ticket> Tickets => Set<Ticket>();
    public DbSet<DigestRun> DigestRuns => Set<DigestRun>();
    public DbSet<AppSetting> Settings => Set<AppSetting>();
    public DbSet<AppUser> Users => Set<AppUser>();
    public DbSet<AuditEntry> Audit => Set<AuditEntry>();
    public DbSet<ProductAlias> Aliases => Set<ProductAlias>();
    public DbSet<Narrative> Narratives => Set<Narrative>();

    // inventory
    public DbSet<Asset> Assets => Set<Asset>();
    public DbSet<AssetSource> AssetSources => Set<AssetSource>();
    public DbSet<SoftwareInstance> Software => Set<SoftwareInstance>();
    public DbSet<ExternalFinding> Findings => Set<ExternalFinding>();
    public DbSet<Connector> Connectors => Set<Connector>();
    public DbSet<CompensatingControl> Controls => Set<CompensatingControl>();
    public DbSet<PackageVulnCache> PackageVulns => Set<PackageVulnCache>();
    public DbSet<WebhookDelivery> WebhookDeliveries => Set<WebhookDelivery>();
    public DbSet<BundleState> Bundles => Set<BundleState>();
    public DbSet<Advisory> Advisories => Set<Advisory>();
    public DbSet<OfficeRelease> OfficeReleases => Set<OfficeRelease>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<Cve>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => x.LastModified);
            e.HasIndex(x => x.Published);
            e.HasMany(x => x.Affected).WithOne(x => x.Cve).HasForeignKey(x => x.CveId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<CveAffected>(e =>
        {
            e.HasIndex(x => new { x.VendorNorm, x.ProductNorm });
            e.HasIndex(x => x.ProductNorm);
            e.HasIndex(x => x.CveId);
        });
        b.Entity<CnaProduct>(e => e.HasKey(x => new { x.VendorNorm, x.ProductNorm }));
        b.Entity<KevEntry>(e => e.HasKey(x => x.CveId));
        b.Entity<EpssScore>(e => e.HasKey(x => x.CveId));
        b.Entity<ExploitSignal>(e =>
        {
            e.HasIndex(x => x.CveId);
            e.HasIndex(x => new { x.CveId, x.Source, x.Url }).IsUnique();
        });
        b.Entity<FeedStatus>(e => e.HasKey(x => x.Name));
        b.Entity<WatchlistEntry>(e => e.HasIndex(x => new { x.VendorNorm, x.ProductNorm }));
        b.Entity<Verdict>(e =>
        {
            e.HasIndex(x => new { x.CveId, x.WatchlistEntryId }).IsUnique();
            e.HasIndex(x => new { x.CveId, x.SoftwareInstanceId }).IsUnique();
            e.HasIndex(x => x.AssetId);
            e.HasIndex(x => x.Tier);
            e.HasIndex(x => x.State);
            e.HasOne(x => x.Cve).WithMany().HasForeignKey(x => x.CveId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(x => x.WatchlistEntry).WithMany().HasForeignKey(x => x.WatchlistEntryId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(x => x.SoftwareInstance).WithMany().HasForeignKey(x => x.SoftwareInstanceId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(x => x.Asset).WithMany().HasForeignKey(x => x.AssetId).OnDelete(DeleteBehavior.Cascade);
            e.HasMany(x => x.History).WithOne().HasForeignKey(x => x.VerdictId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<VerdictHistory>(e => e.HasIndex(x => new { x.VerdictId, x.At }));
        b.Entity<Ticket>(e => e.HasIndex(x => x.CorrelationKey));
        b.Entity<DigestRun>(e => e.HasIndex(x => x.GeneratedAt));
        b.Entity<AppSetting>(e => e.HasKey(x => x.Key));
        b.Entity<AppUser>(e => e.HasIndex(x => x.Username).IsUnique());
        b.Entity<AuditEntry>(e => e.HasIndex(x => x.At));
        b.Entity<ProductAlias>(e => e.HasIndex(x => x.AliasNorm));
        b.Entity<Narrative>(e => e.HasKey(x => x.Key));

        b.Entity<Asset>(e =>
        {
            e.HasIndex(x => x.DisplayName);
            e.HasIndex(x => x.LastSeen);
            e.HasMany(x => x.Sources).WithOne().HasForeignKey(x => x.AssetId).OnDelete(DeleteBehavior.Cascade);
            e.HasMany(x => x.Software).WithOne(x => x.Asset).HasForeignKey(x => x.AssetId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<AssetSource>(e => e.HasIndex(x => new { x.ConnectorId, x.ExternalId }).IsUnique());
        b.Entity<SoftwareInstance>(e =>
        {
            e.HasIndex(x => new { x.AssetId, x.ConnectorId });
            e.HasIndex(x => new { x.MappedVendorNorm, x.MappedProductNorm });
            e.HasIndex(x => x.MappingStatus);
            // removed software stays in the table for its verdicts' history; everything except the inventory upsert and the evaluator's close step ignores it
            e.HasQueryFilter(x => x.RemovedAt == null);
        });
        b.Entity<ExternalFinding>(e => e.HasIndex(x => x.AssetId));
        b.Entity<Connector>(e => e.HasIndex(x => x.AdapterId));
        b.Entity<CompensatingControl>(e => { e.HasIndex(x => x.AssetId); e.HasIndex(x => x.WatchlistEntryId); });
        b.Entity<PackageVulnCache>(e => e.HasKey(x => x.Key));
        b.Entity<WebhookDelivery>(e => e.HasIndex(x => x.At));
        b.Entity<BundleState>(e => e.HasKey(x => x.Id));
        b.Entity<Advisory>(e => { e.HasIndex(x => new { x.Vendor, x.AdvisoryId }).IsUnique(); e.HasIndex(x => x.Updated); });
        b.Entity<OfficeRelease>(e => e.HasIndex(x => new { x.Build, x.Released }));
    }
}

/// <summary>Provider-specific contexts so each provider keeps its own migrations folder.</summary>
public sealed class SqliteVvDbContext : VvDbContext
{
    public SqliteVvDbContext(DbContextOptions<SqliteVvDbContext> options) : base(options) { }
}

public sealed class PostgresVvDbContext : VvDbContext
{
    public PostgresVvDbContext(DbContextOptions<PostgresVvDbContext> options) : base(options) { }
}
