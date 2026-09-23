using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Web;

/// <summary>Section 10.3: local administrator created at install, OIDC for everything else, roles from groups.</summary>
public sealed class AuthService
{
    public const string OidcScheme = "oidc";
    private static readonly PasswordHasher<AppUser> Hasher = new();
    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly IOptionsMonitorCache<OpenIdConnectOptions> _oidcCache;

    public AuthService(IDbContextFactory<VvDbContext> factory, IOptionsMonitorCache<OpenIdConnectOptions> oidcCache)
    {
        _factory = factory; _oidcCache = oidcCache;
    }

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

    public async Task<AppUser> CreateLocalUserAsync(string username, string password, UserRole role, string? email, string actor, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        username = username.Trim();
        if (await db.Users.AnyAsync(u => u.Username == username, ct)) throw new InvalidOperationException("That username already exists");
        var user = new AppUser { Id = Guid.NewGuid(), Username = username, Email = email, Role = role, Provider = "local", CreatedAt = DateTime.UtcNow };
        user.PasswordHash = Hasher.HashPassword(user, password);
        db.Users.Add(user);
        db.Audit.Add(new AuditEntry { At = DateTime.UtcNow, Actor = actor, Action = "user.create", Target = username, After = role.ToString() });
        await db.SaveChangesAsync(ct);
        return user;
    }

    public async Task UpdateUserAsync(Guid id, UserRole role, string? newPassword, string actor, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == id, ct) ?? throw new KeyNotFoundException();
        var before = user.Role.ToString();
        user.Role = role;
        if (!string.IsNullOrEmpty(newPassword)) user.PasswordHash = Hasher.HashPassword(user, newPassword);
        db.Audit.Add(new AuditEntry { At = DateTime.UtcNow, Actor = actor, Action = "user.update", Target = user.Username, Before = before, After = role + (string.IsNullOrEmpty(newPassword) ? "" : ", password reset") });
        await db.SaveChangesAsync(ct);
    }

    public async Task DeleteUserAsync(Guid id, string actor, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == id, ct);
        if (user is null) return;
        if (user.Role == UserRole.Administrator && await db.Users.CountAsync(u => u.Role == UserRole.Administrator, ct) == 1)
            throw new InvalidOperationException("Cannot delete the last administrator");
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
        user.LastLoginAt = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);
        return user;
    }

    public static ClaimsPrincipal BuildPrincipal(AppUser user)
    {
        var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme, ClaimTypes.Name, ClaimTypes.Role);
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
        identity.AddClaim(new Claim(ClaimTypes.Name, user.Username));
        identity.AddClaim(new Claim(ClaimTypes.Role, user.Role.ToString()));
        if (!string.IsNullOrEmpty(user.Email)) identity.AddClaim(new Claim(ClaimTypes.Email, user.Email));
        identity.AddClaim(new Claim("provider", user.Provider));
        return new ClaimsPrincipal(identity);
    }

    public static string SafeReturnUrl(string? returnUrl) =>
        !string.IsNullOrEmpty(returnUrl) && returnUrl.StartsWith('/') && !returnUrl.StartsWith("//") ? returnUrl : "/";

    /// <summary>Force the OIDC options to be re-read from settings on next use.</summary>
    public void ReloadOidc() => _oidcCache.TryRemove(OidcScheme);

    /// <summary>Map the identity provider's groups to a role and record the user. Default role is Viewer.</summary>
    public static async Task OnOidcTokenValidatedAsync(TokenValidatedContext ctx)
    {
        var sp = ctx.HttpContext.RequestServices;
        var settings = await sp.GetRequiredService<SettingsService>().LoadAsync();
        var factory = sp.GetRequiredService<IDbContextFactory<VvDbContext>>();
        var p = ctx.Principal!;
        var name = p.FindFirst("preferred_username")?.Value ?? p.FindFirst(ClaimTypes.Email)?.Value ?? p.FindFirst("email")?.Value ?? p.Identity?.Name ?? p.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "oidc-user";
        var email = p.FindFirst(ClaimTypes.Email)?.Value ?? p.FindFirst("email")?.Value;
        var groups = p.FindAll(settings.OidcGroupClaim).Select(c => c.Value).Concat(p.FindAll("roles").Select(c => c.Value)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var role = !string.IsNullOrWhiteSpace(settings.OidcAdminGroup) && groups.Contains(settings.OidcAdminGroup) ? UserRole.Administrator
                 : !string.IsNullOrWhiteSpace(settings.OidcOperatorGroup) && groups.Contains(settings.OidcOperatorGroup) ? UserRole.Operator
                 : UserRole.Viewer;

        await using var db = await factory.CreateDbContextAsync();
        var user = await db.Users.FirstOrDefaultAsync(u => u.Username == name && u.Provider == "oidc");
        if (user is null)
        {
            user = new AppUser { Id = Guid.NewGuid(), Username = name, Email = email, Provider = "oidc", Role = role, CreatedAt = DateTime.UtcNow };
            db.Users.Add(user);
            db.Audit.Add(new AuditEntry { At = DateTime.UtcNow, Actor = name, Action = "user.oidc-first-login", Target = name, After = role.ToString() });
        }
        else { user.Role = role; user.Email = email ?? user.Email; }
        user.LastLoginAt = DateTime.UtcNow;
        await db.SaveChangesAsync();
        ctx.Principal = BuildPrincipal(user);
    }
}

public static class Ui
{
    public static string TierClass(VerdictTier t) => t switch
    {
        VerdictTier.FixToday => "tier tier-today",
        VerdictTier.FixThisWeek => "tier tier-week",
        VerdictTier.NextPatchCycle => "tier tier-cycle",
        VerdictTier.IgnoreTracked => "tier tier-ignore",
        _ => "tier tier-na"
    };

    public static string StateClass(VerdictState s) => s switch
    {
        VerdictState.Open => "state state-open",
        VerdictState.Closed => "state state-closed",
        _ => "state state-other"
    };

    public static string Ago(DateTime? utc)
    {
        if (utc is null) return "never";
        var d = DateTime.UtcNow - utc.Value;
        if (d.TotalSeconds < 90) return "just now";
        if (d.TotalMinutes < 90) return (int)d.TotalMinutes + " min ago";
        if (d.TotalHours < 36) return (int)d.TotalHours + " h ago";
        return (int)d.TotalDays + " days ago";
    }

    public static string Local(DateTime? utc, TimeZoneInfo tz, string format = "d MMM yyyy HH:mm") =>
        utc is null ? "-" : TimeZoneInfo.ConvertTimeFromUtc(DateTime.SpecifyKind(utc.Value, DateTimeKind.Utc), tz).ToString(format);

    public static string Actor(System.Security.Claims.ClaimsPrincipal? user) => user?.Identity?.Name ?? "unknown";
    public static bool CanOperate(System.Security.Claims.ClaimsPrincipal? user) => user is not null && (user.IsInRole("Administrator") || user.IsInRole("Operator"));
    public static bool IsAdmin(System.Security.Claims.ClaimsPrincipal? user) => user is not null && user.IsInRole("Administrator");
}
