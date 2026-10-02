using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Services;

/// <summary>
/// Console accounts: the local administrator created at first run, local users, and OIDC users recorded at sign-in.
/// Every change to an account's access rotates its security stamp, which ends sessions issued before the change.
/// </summary>
public sealed class UserService
{
    /// <summary>Written in the same save as the first administrator, so two first-run posts cannot both succeed.</summary>
    public const string SetupGuardKey = "state:setup:done";
    public const string SetupTokenFile = "setup-token";
    private static readonly PasswordHasher<AppUser> Hasher = new();
    private readonly IDbContextFactory<VvDbContext> _factory;

    public UserService(IDbContextFactory<VvDbContext> factory) => _factory = factory;

    public static string NewStamp() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

    public async Task<bool> HasUsersAsync(CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        return await db.Users.AnyAsync(ct);
    }

    public async Task<List<AppUser>> ListUsersAsync(CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        return await db.Users.AsNoTracking().OrderBy(u => u.Username).ToListAsync(ct);
    }

    public async Task<AppUser?> FindAsync(Guid id, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        return await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == id, ct);
    }

    /// <summary>True while the account exists and its stamp still matches the one the session was issued with.</summary>
    public async Task<bool> IsSessionValidAsync(string? userId, string? stamp, CancellationToken ct = default)
    {
        if (!Guid.TryParse(userId, out var id) || string.IsNullOrEmpty(stamp)) return false;
        var user = await FindAsync(id, ct);
        return user is not null && user.SecurityStamp.Length > 0 && FixedTimeEquals(user.SecurityStamp, stamp);
    }

    public async Task<AppUser> CreateLocalUserAsync(string username, string password, UserRole role, string? email, string actor, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        username = username.Trim();
        if (await db.Users.AnyAsync(u => u.Username == username, ct)) throw new InvalidOperationException("That username already exists");
        var user = NewLocalUser(username, password, role, email);
        db.Users.Add(user);
        db.Audit.Add(new AuditEntry { At = DateTime.UtcNow, Actor = actor, Action = "user.create", Target = username, After = role.ToString() });
        await db.SaveChangesAsync(ct);
        return user;
    }

    /// <summary>
    /// First run: create the administrator, only with the setup token and only while no account exists. The guard row
    /// shares the user's save, so of two concurrent posts the second fails on the guard's key instead of adding a second administrator.
    /// </summary>
    public async Task<AppUser?> CreateFirstAdministratorAsync(string dataDir, string? setupToken, string username, string password, string? email, CancellationToken ct = default)
    {
        if (!SetupTokenMatches(dataDir, setupToken)) return null;
        await using var db = await _factory.CreateDbContextAsync(ct);
        if (await db.Users.AnyAsync(ct) || await db.Settings.AnyAsync(s => s.Key == SetupGuardKey, ct)) return null;
        username = username.Trim();
        var user = NewLocalUser(username, password, UserRole.Administrator, email);
        db.Users.Add(user);
        db.Settings.Add(new AppSetting { Key = SetupGuardKey, Value = user.Id.ToString(), UpdatedAt = DateTime.UtcNow });
        db.Audit.Add(new AuditEntry { At = DateTime.UtcNow, Actor = "setup", Action = "user.create", Target = username, After = UserRole.Administrator.ToString() });
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException) { return null; }
        try { File.Delete(Path.Combine(dataDir, SetupTokenFile)); } catch { }
        return user;
    }

    /// <summary>
    /// At start-up with no accounts: make sure a setup token exists (reused across restarts until the administrator is
    /// created) and clear a guard row left by an account table emptied by hand. Returns the token, or null once set up.
    /// </summary>
    public async Task<string?> EnsureSetupTokenAsync(string dataDir, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        if (await db.Users.AnyAsync(ct))
        {
            try { File.Delete(Path.Combine(dataDir, SetupTokenFile)); } catch { }
            return null;
        }
        await db.Settings.Where(s => s.Key == SetupGuardKey).ExecuteDeleteAsync(ct);
        var path = Path.Combine(dataDir, SetupTokenFile);
        var existing = ReadSetupToken(dataDir);
        if (existing is not null) return existing;
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        await File.WriteAllTextAsync(path, token + "\n", ct);
        if (!OperatingSystem.IsWindows())
        {
            try { File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); } catch { }
        }
        return token;
    }

    public static string? ReadSetupToken(string dataDir)
    {
        try
        {
            var t = File.ReadAllText(Path.Combine(dataDir, SetupTokenFile)).Trim();
            return t.Length >= 16 ? t : null;
        }
        catch { return null; }
    }

    public static bool SetupTokenMatches(string dataDir, string? presented)
    {
        var expected = ReadSetupToken(dataDir);
        return expected is not null && !string.IsNullOrWhiteSpace(presented) && FixedTimeEquals(expected, presented.Trim().ToLowerInvariant());
    }

    public async Task UpdateUserAsync(Guid id, UserRole role, string? newPassword, string actor, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == id, ct) ?? throw new KeyNotFoundException();
        if (user.Role == UserRole.Administrator && role != UserRole.Administrator && await db.Users.CountAsync(u => u.Role == UserRole.Administrator, ct) == 1)
            throw new InvalidOperationException("Cannot demote the last administrator");
        var before = user.Role;
        user.Role = role;
        if (!string.IsNullOrEmpty(newPassword)) user.PasswordHash = Hasher.HashPassword(user, newPassword);
        if (before != role || !string.IsNullOrEmpty(newPassword)) user.SecurityStamp = NewStamp();
        db.Audit.Add(new AuditEntry { At = DateTime.UtcNow, Actor = actor, Action = "user.update", Target = user.Username, Before = before.ToString(), After = role + (string.IsNullOrEmpty(newPassword) ? "" : ", password reset") });
        await db.SaveChangesAsync(ct);
    }

    public async Task DeleteUserAsync(Guid id, string actor, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == id, ct);
        if (user is null) return;
        if (user.Role == UserRole.Administrator && await db.Users.CountAsync(u => u.Role == UserRole.Administrator, ct) == 1)
            throw new InvalidOperationException("Cannot delete the last administrator");
        // the row goes, so its sessions fail the existence check; the stamp is not needed
        db.Users.Remove(user);
        db.Audit.Add(new AuditEntry { At = DateTime.UtcNow, Actor = actor, Action = "user.delete", Target = user.Username });
        await db.SaveChangesAsync(ct);
    }

    public async Task<AppUser?> ValidateLocalAsync(string username, string password, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var user = await db.Users.FirstOrDefaultAsync(u => u.Username == username.Trim() && u.Provider == "local", ct);
        if (user?.PasswordHash is null) return null;
        var result = Hasher.VerifyHashedPassword(user, user.PasswordHash, password);
        if (result == PasswordVerificationResult.Failed) return null;
        if (result == PasswordVerificationResult.SuccessRehashNeeded) user.PasswordHash = Hasher.HashPassword(user, password);
        if (user.SecurityStamp.Length == 0) user.SecurityStamp = NewStamp();
        user.LastLoginAt = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);
        return user;
    }

    /// <summary>Record an OIDC sign-in with the role its groups map to. A role change rotates the stamp, ending older sessions.</summary>
    public async Task<AppUser> RecordOidcSignInAsync(string name, string? email, UserRole role, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var user = await db.Users.FirstOrDefaultAsync(u => u.Username == name && u.Provider == "oidc", ct);
        if (user is null)
        {
            user = new AppUser { Id = Guid.NewGuid(), Username = name, Email = email, Provider = "oidc", Role = role, CreatedAt = DateTime.UtcNow, SecurityStamp = NewStamp() };
            db.Users.Add(user);
            db.Audit.Add(new AuditEntry { At = DateTime.UtcNow, Actor = name, Action = "user.oidc-first-login", Target = name, After = role.ToString() });
        }
        else
        {
            if (user.Role != role || user.SecurityStamp.Length == 0) user.SecurityStamp = NewStamp();
            user.Role = role; user.Email = email ?? user.Email;
        }
        user.LastLoginAt = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);
        return user;
    }

    private static AppUser NewLocalUser(string username, string password, UserRole role, string? email)
    {
        var user = new AppUser { Id = Guid.NewGuid(), Username = username, Email = email, Role = role, Provider = "local", CreatedAt = DateTime.UtcNow, SecurityStamp = NewStamp() };
        user.PasswordHash = Hasher.HashPassword(user, password);
        return user;
    }

    private static bool FixedTimeEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
}
