using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Options;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Web;

/// <summary>Local administrator created at install, OIDC for everything else, roles from groups. Accounts live in <see cref="UserService"/>.</summary>
public sealed class AuthService
{
    public const string OidcScheme = "oidc";
    public const string StampClaim = "vv:stamp";
    private readonly IOptionsMonitorCache<OpenIdConnectOptions> _oidcCache;

    public AuthService(IOptionsMonitorCache<OpenIdConnectOptions> oidcCache) => _oidcCache = oidcCache;

    public static ClaimsPrincipal BuildPrincipal(AppUser user)
    {
        var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme, ClaimTypes.Name, ClaimTypes.Role);
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
        identity.AddClaim(new Claim(ClaimTypes.Name, user.Username));
        identity.AddClaim(new Claim(ClaimTypes.Role, user.Role.ToString()));
        if (!string.IsNullOrEmpty(user.Email)) identity.AddClaim(new Claim(ClaimTypes.Email, user.Email));
        identity.AddClaim(new Claim("provider", user.Provider));
        identity.AddClaim(new Claim(StampClaim, user.SecurityStamp));
        return new ClaimsPrincipal(identity);
    }

    public static string SafeReturnUrl(string? returnUrl) =>
        !string.IsNullOrEmpty(returnUrl) && returnUrl.StartsWith('/') && !returnUrl.StartsWith("//") ? returnUrl : "/";

    /// <summary>The identity provider's origin while single sign-on is on, for the form-action content security policy.</summary>
    public string? OidcOrigin { get; private set; }

    /// <summary>Force the OIDC options to be re-read from settings on next use.</summary>
    public void ReloadOidc(AppSettings s)
    {
        _oidcCache.TryRemove(OidcScheme);
        OidcOrigin = s.OidcEnabled && Uri.TryCreate(s.OidcAuthority, UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps ? u.GetLeftPart(UriPartial.Authority) : null;
    }

    /// <summary>
    /// Every cookie-authenticated request: the account must still exist with the stamp the cookie was issued with.
    /// Deleting a user, changing their role or resetting their password ends their sessions; so does a cookie from
    /// before stamps existed (one sign-in again after the upgrade).
    /// </summary>
    public static async Task ValidatePrincipalAsync(CookieValidatePrincipalContext ctx)
    {
        var users = ctx.HttpContext.RequestServices.GetRequiredService<UserService>();
        var p = ctx.Principal;
        if (p is not null && await users.IsSessionValidAsync(p.FindFirst(ClaimTypes.NameIdentifier)?.Value, p.FindFirst(StampClaim)?.Value, ctx.HttpContext.RequestAborted)) return;
        ctx.RejectPrincipal();
        await ctx.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }

    /// <summary>Map the identity provider's groups to a role and record the user. Default role is Viewer.</summary>
    public static async Task OnOidcTokenValidatedAsync(TokenValidatedContext ctx)
    {
        var sp = ctx.HttpContext.RequestServices;
        var settings = await sp.GetRequiredService<SettingsService>().LoadAsync();
        var p = ctx.Principal!;
        var name = p.FindFirst("preferred_username")?.Value ?? p.FindFirst(ClaimTypes.Email)?.Value ?? p.FindFirst("email")?.Value ?? p.Identity?.Name ?? p.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "oidc-user";
        var email = p.FindFirst(ClaimTypes.Email)?.Value ?? p.FindFirst("email")?.Value;
        var groups = p.FindAll(settings.OidcGroupClaim).Select(c => c.Value).Concat(p.FindAll("roles").Select(c => c.Value)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var role = !string.IsNullOrWhiteSpace(settings.OidcAdminGroup) && groups.Contains(settings.OidcAdminGroup) ? UserRole.Administrator
                 : !string.IsNullOrWhiteSpace(settings.OidcOperatorGroup) && groups.Contains(settings.OidcOperatorGroup) ? UserRole.Operator
                 : UserRole.Viewer;
        var user = await sp.GetRequiredService<UserService>().RecordOidcSignInAsync(name, email, role);
        ctx.Principal = BuildPrincipal(user);
    }
}

/// <summary>
/// Open Blazor circuits re-check the account every few minutes with the same rule as the cookie, so a deleted or
/// demoted user's open tab loses access without a page load.
/// </summary>
public sealed class RevalidatingAuthStateProvider : Microsoft.AspNetCore.Components.Server.RevalidatingServerAuthenticationStateProvider
{
    private readonly UserService _users;

    public RevalidatingAuthStateProvider(ILoggerFactory loggerFactory, UserService users) : base(loggerFactory) => _users = users;

    protected override TimeSpan RevalidationInterval => TimeSpan.FromMinutes(5);

    protected override async Task<bool> ValidateAuthenticationStateAsync(AuthenticationState state, CancellationToken ct)
    {
        var p = state.User;
        if (p.Identity?.IsAuthenticated != true) return true;
        return await _users.IsSessionValidAsync(p.FindFirst(ClaimTypes.NameIdentifier)?.Value, p.FindFirst(AuthService.StampClaim)?.Value, ct);
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
    // event handlers check the role themselves: a hidden button is not access control
    public static async Task<bool> CanOperateAsync(Task<AuthenticationState> state) => CanOperate((await state).User);
    public static async Task<bool> IsAdminAsync(Task<AuthenticationState> state) => IsAdmin((await state).User);

    /// <summary>Only http and https links from CVE records are rendered as links.</summary>
    public static bool IsWebLink(string? url) => Uri.TryCreate(url, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttps || u.Scheme == Uri.UriSchemeHttp);
}
