using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Services;

public enum ApiScope { None, Read, ReadWrite }

/// <summary>
/// API bearer tokens: a read-only token and a read-write token. Only a SHA-256 hash is stored, so a token is shown
/// once when generated and cannot be read back; a lost token is replaced, not recovered.
/// </summary>
public sealed class ApiTokenService
{
    public const string ReadHashKey = "api:token:read";
    public const string WriteHashKey = "api:token:write";
    /// <summary>Set when a token from an earlier release (stored reversibly) was converted; Settings suggests replacing it.</summary>
    public const string LegacyNoticeKey = "api:token:legacy";
    private const string LegacySettingKey = "ApiToken";
    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly IDataProtector _protector;

    public ApiTokenService(IDbContextFactory<VvDbContext> factory, IDataProtectionProvider dp)
    {
        _factory = factory;
        _protector = dp.CreateProtector("VulnVerdict.Secrets.v1");
    }

    public static string Hash(string token) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))).ToLowerInvariant();

    /// <summary>Constant-time comparison of a presented token with a stored hash.</summary>
    public static bool Matches(string? presented, string? storedHash)
    {
        if (string.IsNullOrEmpty(presented) || string.IsNullOrEmpty(storedHash) || storedHash.Length != 64) return false;
        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Hash(presented)), Encoding.ASCII.GetBytes(storedHash));
    }

    /// <summary>The scope an Authorization header grants: the read-write token also reads.</summary>
    public async Task<ApiScope> AuthoriseAsync(string? authorizationHeader, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(authorizationHeader) || !authorizationHeader.StartsWith("Bearer ", StringComparison.Ordinal)) return ApiScope.None;
        var token = authorizationHeader["Bearer ".Length..].Trim();
        var (read, write) = await HashesAsync(ct);
        // both compared every time, so the answer takes the same time whichever matched
        var isWrite = Matches(token, write);
        var isRead = Matches(token, read);
        return isWrite ? ApiScope.ReadWrite : isRead ? ApiScope.Read : ApiScope.None;
    }

    public async Task<(bool Read, bool Write, bool Legacy)> StatusAsync(CancellationToken ct = default)
    {
        var (read, write) = await HashesAsync(ct);
        await using var db = await _factory.CreateDbContextAsync(ct);
        var legacy = await db.Settings.AnyAsync(s => s.Key == LegacyNoticeKey && s.Value == "1", ct);
        return (!string.IsNullOrEmpty(read), !string.IsNullOrEmpty(write), legacy && !string.IsNullOrEmpty(write));
    }

    /// <summary>Create (or replace) a token. The plain value is returned once and never stored.</summary>
    public async Task<string> GenerateAsync(ApiScope scope, string actor, CancellationToken ct = default)
    {
        if (scope == ApiScope.None) throw new ArgumentOutOfRangeException(nameof(scope));
        var token = "vv_" + (scope == ApiScope.ReadWrite ? "rw_" : "ro_") + Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();
        await SetAsync(scope == ApiScope.ReadWrite ? WriteHashKey : ReadHashKey, Hash(token), actor, "api.token.generate", scope, ct);
        return token;
    }

    public Task RevokeAsync(ApiScope scope, string actor, CancellationToken ct = default) =>
        SetAsync(scope == ApiScope.ReadWrite ? WriteHashKey : ReadHashKey, null, actor, "api.token.revoke", scope, ct);

    /// <summary>
    /// Start-up: a token saved by an earlier release (encrypted, reversible, and it could write) becomes the read-write
    /// token's hash so integrations keep working, and the reversible copy is removed.
    /// </summary>
    public async Task MigrateLegacyAsync(CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var row = await db.Settings.FirstOrDefaultAsync(s => s.Key == LegacySettingKey, ct);
        if (row is null) return;
        var plain = row.Value;
        if (row.Encrypted && !string.IsNullOrEmpty(plain))
        {
            try { plain = _protector.Unprotect(plain); } catch { plain = null; }
        }
        db.Settings.Remove(row);
        if (!string.IsNullOrEmpty(plain) && !await db.Settings.AnyAsync(s => s.Key == WriteHashKey && s.Value != null && s.Value != "", ct))
        {
            var now = DateTime.UtcNow;
            Upsert(db, WriteHashKey, Hash(plain), now);
            Upsert(db, LegacyNoticeKey, "1", now);
            db.Audit.Add(new AuditEntry { At = now, Actor = "system", Action = "api.token.migrate", Target = "api", After = "existing token kept with read-write scope, stored as a hash" });
        }
        await db.SaveChangesAsync(ct);
    }

    private async Task<(string? Read, string? Write)> HashesAsync(CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var rows = await db.Settings.AsNoTracking().Where(s => s.Key == ReadHashKey || s.Key == WriteHashKey).ToDictionaryAsync(s => s.Key, s => s.Value, ct);
        return (rows.GetValueOrDefault(ReadHashKey), rows.GetValueOrDefault(WriteHashKey));
    }

    private async Task SetAsync(string key, string? hash, string actor, string action, ApiScope scope, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var now = DateTime.UtcNow;
        Upsert(db, key, hash, now);
        if (key == WriteHashKey) Upsert(db, LegacyNoticeKey, null, now);
        db.Audit.Add(new AuditEntry { At = now, Actor = actor, Action = action, Target = "api", After = scope == ApiScope.ReadWrite ? "read-write token" : "read-only token" });
        await db.SaveChangesAsync(ct);
    }

    private static void Upsert(VvDbContext db, string key, string? value, DateTime now)
    {
        var row = db.Settings.Local.FirstOrDefault(s => s.Key == key) ?? db.Settings.FirstOrDefault(s => s.Key == key);
        if (row is null) db.Settings.Add(new AppSetting { Key = key, Value = value, UpdatedAt = now });
        else { row.Value = value; row.UpdatedAt = now; }
    }
}
