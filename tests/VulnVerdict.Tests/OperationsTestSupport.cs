using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

/// <summary>A SQLite database file in its own data directory, for the backup, metrics and SLA tests.</summary>
internal sealed class OpsTestHost : IDisposable
{
    public string DataDir { get; }
    public string ConnectionString { get; }
    public Factory Db { get; }
    public SettingsService Settings { get; }
    public IDataProtectionProvider Protection { get; } = new MarkingProvider();

    public OpsTestHost()
    {
        DataDir = Path.Combine(Path.GetTempPath(), "vv-ops-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(DataDir);
        ConnectionString = "Data Source=" + Path.Combine(DataDir, "vv.db") + ";Pooling=false";
        Db = new Factory(new DbContextOptionsBuilder<VvDbContext>().UseSqlite(ConnectionString).Options);
        using (var db = Db.CreateDbContext()) db.Database.EnsureCreated();
        Settings = new SettingsService(Db, Protection);
    }

    public void Dispose()
    {
        try { Directory.Delete(DataDir, true); } catch { }
    }

    public sealed class Factory : IDbContextFactory<VvDbContext>
    {
        private readonly DbContextOptions<VvDbContext> _options;
        public Factory(DbContextOptions<VvDbContext> options) => _options = options;
        public VvDbContext CreateDbContext() => new(_options);
        public Task<VvDbContext> CreateDbContextAsync(CancellationToken ct = default) => Task.FromResult(CreateDbContext());
    }

    /// <summary>Changes what it protects, so a test can tell stored-encrypted from stored-plain.</summary>
    private sealed class MarkingProvider : IDataProtectionProvider, IDataProtector
    {
        public IDataProtector CreateProtector(string purpose) => this;
        public byte[] Protect(byte[] plaintext) => new byte[] { 0xEE }.Concat(plaintext).ToArray();
        public byte[] Unprotect(byte[] protectedData) => protectedData[0] == 0xEE ? protectedData.Skip(1).ToArray() : throw new System.Security.Cryptography.CryptographicException("not protected");
    }
}
