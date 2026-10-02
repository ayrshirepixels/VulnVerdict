using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

/// <summary>Contexts over one open SQLite connection, for services that take a factory.</summary>
internal sealed class SharedDbFactory : IDbContextFactory<VvDbContext>
{
    private readonly DbContextOptions<VvDbContext> _options;
    public SharedDbFactory(System.Data.Common.DbConnection connection) => _options = new DbContextOptionsBuilder<VvDbContext>().UseSqlite(connection).Options;
    public VvDbContext CreateDbContext() => new(_options);
    public Task<VvDbContext> CreateDbContextAsync(CancellationToken ct = default) => Task.FromResult(CreateDbContext());
}

/// <summary>A reversible stand-in for data protection whose output is visibly not the input, so a test can tell a stored secret was encrypted.</summary>
internal sealed class MarkingProtectionProvider : IDataProtectionProvider, IDataProtector
{
    private static readonly byte[] Mark = "ENC:"u8.ToArray();
    public IDataProtector CreateProtector(string purpose) => this;
    public byte[] Protect(byte[] plaintext) => Mark.Concat(plaintext.Reverse()).ToArray();
    public byte[] Unprotect(byte[] protectedData)
    {
        if (!protectedData.AsSpan().StartsWith(Mark)) throw new System.Security.Cryptography.CryptographicException("not protected by this provider");
        return protectedData.Skip(Mark.Length).Reverse().ToArray();
    }
}

internal static class TestSettings
{
    /// <summary>A settings service over the same in-memory database as <paramref name="db"/>.</summary>
    public static SettingsService For(VvDbContext db) => new(new SharedDbFactory(db.Database.GetDbConnection()), new MarkingProtectionProvider());
}
