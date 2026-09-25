using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using VulnVerdict.Core;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Digest;
using VulnVerdict.Core.Services;
using VulnVerdict.Web;
using VulnVerdict.Web.Components;

var builder = WebApplication.CreateBuilder(args);
var cfg = builder.Configuration;

// ---- configuration (appsettings.json, overridable by environment variables such as Database__Provider)
var dataDir = cfg["Worker:DataDir"] ?? "data";
Directory.CreateDirectory(dataDir);
var provider = cfg["Database:Provider"] ?? "sqlite";
var connectionString = string.IsNullOrWhiteSpace(cfg["Database:ConnectionString"]) ? "Data Source=" + Path.Combine(dataDir, "vulnverdict.db") : cfg["Database:ConnectionString"]!;
var role = (cfg["Role"] ?? "all").ToLowerInvariant();
var workerOptions = new WorkerOptions
{
    DataDir = dataDir,
    CveMinYear = cfg.GetValue<int?>("Worker:CveMinYear") ?? 0,
    LoopSeconds = cfg.GetValue<int?>("Worker:LoopSeconds") ?? 60
};

// ---- services
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(dataDir, "keys")))
    .SetApplicationName("VulnVerdict");
builder.Services.AddVulnVerdictCore(provider, connectionString, workerOptions, role);
builder.Services.AddSingleton<AuthService>();
builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddHttpContextAccessor();
builder.Services.AddAuthorization(o => o.FallbackPolicy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(o =>
    {
        o.LoginPath = "/login";
        o.LogoutPath = "/auth/logout";
        o.AccessDeniedPath = "/denied";
        o.ExpireTimeSpan = TimeSpan.FromHours(12);
        o.SlidingExpiration = true;
        o.Cookie.Name = "vv.auth";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = SameSiteMode.Lax;
        o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    })
    .AddOpenIdConnect(AuthService.OidcScheme, o =>
    {
        o.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        o.ResponseType = OpenIdConnectResponseType.Code;
        o.CallbackPath = "/signin-oidc";
        o.SignedOutCallbackPath = "/signout-callback-oidc";
        o.GetClaimsFromUserInfoEndpoint = true;
        o.SaveTokens = false;
        o.Scope.Add("email");
        o.Scope.Add("profile");
        o.TokenValidationParameters.NameClaimType = "name";
        o.Events = new OpenIdConnectEvents { OnTokenValidated = AuthService.OnOidcTokenValidatedAsync };
    });
// OIDC endpoint details live in the settings table; they are read lazily on first use and refreshed when settings change
builder.Services.AddOptions<OpenIdConnectOptions>(AuthService.OidcScheme).Configure<SettingsService>((o, settings) =>
{
    var s = settings.LoadAsync().GetAwaiter().GetResult();
    var enabled = s.OidcEnabled && !string.IsNullOrWhiteSpace(s.OidcAuthority) && !string.IsNullOrWhiteSpace(s.OidcClientId);
    o.Authority = enabled ? s.OidcAuthority : "https://oidc.disabled.invalid";
    o.ClientId = enabled ? s.OidcClientId : "disabled";
    o.ClientSecret = enabled ? s.OidcClientSecret : null;
    o.ClientSecret = string.IsNullOrEmpty(o.ClientSecret) ? null : o.ClientSecret;
});

builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.AddPolicy("login", ctx => RateLimitPartition.GetFixedWindowLimiter(ctx.Connection.RemoteIpAddress?.ToString() ?? "anon",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 10, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
    o.AddPolicy("api", ctx => RateLimitPartition.GetFixedWindowLimiter(ctx.Connection.RemoteIpAddress?.ToString() ?? "anon",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 120, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
});

var app = builder.Build();

await CoreServices.InitialiseDatabaseAsync(app.Services);

// ---- pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);

// section 10.4: security headers on every response
app.Use(async (ctx, next) =>
{
    var h = ctx.Response.Headers;
    h["X-Content-Type-Options"] = "nosniff";
    h["X-Frame-Options"] = "SAMEORIGIN"; // the console frames its own digest HTML
    h["Referrer-Policy"] = "same-origin";
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
    h["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' ws: wss:; frame-src 'self'; frame-ancestors 'self'; form-action 'self' https:; base-uri 'self'";
    await next();
});

app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapStaticAssets().AllowAnonymous();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();

// ---- authentication endpoints (static forms, antiforgery-protected)
app.MapPost("/auth/setup", async ([FromForm] string username, [FromForm] string password, [FromForm] string? email, HttpContext http, AuthService auth) =>
{
    if (await auth.HasUsersAsync()) return Results.Redirect("/login");
    if (string.IsNullOrWhiteSpace(username) || password.Length < 12) return Results.Redirect("/setup?error=Password+must+be+at+least+12+characters");
    var user = await auth.CreateLocalUserAsync(username, password, UserRole.Administrator, email, "setup");
    await http.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, AuthService.BuildPrincipal(user), new AuthenticationProperties { IsPersistent = true });
    return Results.Redirect("/settings?first=1");
}).AllowAnonymous().RequireRateLimiting("login");

app.MapPost("/auth/login", async ([FromForm] string username, [FromForm] string password, [FromForm] string? returnUrl, HttpContext http, AuthService auth) =>
{
    var user = await auth.ValidateLocalAsync(username, password);
    if (user is null)
    {
        await Task.Delay(Random.Shared.Next(200, 600));
        return Results.Redirect("/login?error=1" + (string.IsNullOrEmpty(returnUrl) ? "" : "&returnUrl=" + Uri.EscapeDataString(returnUrl)));
    }
    await http.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, AuthService.BuildPrincipal(user), new AuthenticationProperties { IsPersistent = true });
    return Results.LocalRedirect(AuthService.SafeReturnUrl(returnUrl));
}).AllowAnonymous().RequireRateLimiting("login");

app.MapGet("/auth/oidc", async (string? returnUrl, HttpContext http, SettingsService settings) =>
{
    var s = await settings.LoadAsync();
    if (!s.OidcEnabled) return Results.Redirect("/login");
    return Results.Challenge(new AuthenticationProperties { RedirectUri = AuthService.SafeReturnUrl(returnUrl) }, new[] { AuthService.OidcScheme });
}).AllowAnonymous();

app.MapPost("/auth/logout", async (HttpContext http) =>
{
    await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/login");
}).AllowAnonymous();

// ---- section 11.4: read API with a static token (Authorization: Bearer <token>)
var api = app.MapGroup("/api").RequireRateLimiting("api").AllowAnonymous().AddEndpointFilter(async (ctx, next) =>
{
    var settings = ctx.HttpContext.RequestServices.GetRequiredService<SettingsService>();
    var s = await settings.LoadAsync();
    var header = ctx.HttpContext.Request.Headers.Authorization.ToString();
    if (string.IsNullOrEmpty(s.ApiToken) || header != "Bearer " + s.ApiToken)
        return Results.Json(new { error = "unauthorized", hint = "send Authorization: Bearer <API token from Settings>" }, statusCode: StatusCodes.Status401Unauthorized);
    return await next(ctx);
});
api.MapGet("/verdicts", async (VvDbContext db, string? tier, string? state) =>
{
    var q = db.Verdicts.AsNoTracking().Include(v => v.WatchlistEntry).AsQueryable();
    if (Enum.TryParse<VerdictTier>(tier, true, out var t)) q = q.Where(v => v.Tier == t);
    if (Enum.TryParse<VerdictState>(state, true, out var st)) q = q.Where(v => v.State == st);
    return Results.Ok(await q.OrderByDescending(v => v.Tier).ThenBy(v => v.SlaDue).Take(2000).Select(v => new
    {
        v.Id, v.CveId, Product = v.WatchlistEntry!.Vendor + " " + v.WatchlistEntry.Product, v.WatchlistEntry.Version, Asset = v.WatchlistEntry.AssetName,
        Verdict = v.Tier.ToString(), v.RuleNumber, Confidence = v.Confidence.ToString(), State = v.State.ToString(), v.SlaDue, v.Sentence, v.FixedIn,
        Exploitation = v.Exploitation.ToString(), v.Automatable, AttackVector = v.AttackVector.ToString(), Exposure = v.EffectiveExposure.ToString(), Criticality = v.Criticality.ToString(),
        v.InKev, v.Epss, v.CreatedAt, v.UpdatedAt
    }).ToListAsync());
});
api.MapGet("/verdicts/{id:guid}", async (Guid id, VvDbContext db) =>
{
    var v = await db.Verdicts.AsNoTracking().Include(x => x.WatchlistEntry).Include(x => x.History).FirstOrDefaultAsync(x => x.Id == id);
    return v is null ? Results.NotFound() : Results.Ok(new { v.Id, v.CveId, Verdict = v.Tier.ToString(), v.RuleNumber, v.Sentence, Evidence = System.Text.Json.JsonDocument.Parse(v.EvidenceJson).RootElement, v.History });
});
api.MapGet("/assets", async (VvDbContext db) => Results.Ok(await db.Assets.AsNoTracking().Include(a => a.Sources).Where(a => !a.Archived).OrderBy(a => a.DisplayName).Take(5000).Select(a => new
{
    a.Id, a.DisplayName, Kind = a.Kind.ToString(), Hostnames = a.HostnamesJson, IpAddresses = a.IpAddressesJson, a.OsProduct, a.OsVersion,
    Exposure = a.Exposure.ToString(), a.ExposureEvidence, Criticality = a.Criticality.ToString(), a.Unknown, a.FirstSeen, a.LastSeen,
    Sources = a.Sources.Select(s => s.AdapterId).Distinct().ToList()
}).ToListAsync()));
api.MapGet("/watchlist", async (VvDbContext db) => Results.Ok(await db.Watchlist.AsNoTracking().OrderBy(w => w.Vendor).ThenBy(w => w.Product).ToListAsync()));
api.MapPost("/watchlist", async (HttpContext http, WatchlistService watchlist) =>
{
    using var reader = new StreamReader(http.Request.Body);
    var n = await watchlist.ImportJsonAsync(await reader.ReadToEndAsync(), "api");
    return Results.Ok(new { imported = n });
});
api.MapPost("/sbom", async (HttpContext http, string asset, VulnVerdict.Core.Adapters.Sbom.SbomImportService sbom, SettingsService settings) =>
{
    if (string.IsNullOrWhiteSpace(asset)) return Results.BadRequest(new { error = "asset query parameter is required (the application or site name)" });
    using var reader = new StreamReader(http.Request.Body);
    var summary = await sbom.ImportAsync(asset.Trim(), await reader.ReadToEndAsync(), "api");
    await settings.SetStateAsync(SettingsService.Keys.EvaluateRequested, "1");
    return Results.Ok(new { asset, summary.Software, summary.Unmapped });
});
api.MapGet("/digest", async (DigestService digest) =>
{
    var d = await digest.BuildAsync();
    return Results.Ok(new { d.Headline, d.FixToday, d.FixThisWeek, d.CheckThese, d.Changed, d.Overdue, d.NextPatchCycleCount, d.DismissedSinceMonday, d.DismissedTotal, d.CoverageLine, d.FeedWarning, d.GeneratedAt });
});

// ---- digest HTML for the console iframe (cookie-authenticated)
app.MapGet("/digests/{id:guid}/html", async (Guid id, VvDbContext db) =>
{
    var run = await db.DigestRuns.AsNoTracking().FirstOrDefaultAsync(r => r.Id == id);
    return run is null ? Results.NotFound() : Results.Content(run.Html, "text/html");
});
app.MapGet("/digests/preview/html", async (DigestService digest) => Results.Content((await digest.BuildAsync()).Html, "text/html"));
app.MapGet("/reports/weekly.html", async (ReportService reports, int? weeks) => Results.Content((await reports.BuildAsync(weeks is > 0 ? DateTime.UtcNow.AddDays(-7 * weeks.Value) : null)).Html, "text/html"));
app.MapGet("/reports/weekly.csv", async (ReportService reports, int? weeks) =>
    Results.File(System.Text.Encoding.UTF8.GetBytes((await reports.BuildAsync(weeks is > 0 ? DateTime.UtcNow.AddDays(-7 * weeks.Value) : null)).Csv), "text/csv", "vulnverdict-weekly-" + DateTime.UtcNow.ToString("yyyy-MM-dd") + ".csv"));

// Healthy means the console can reach its database, so a stack whose web container is up but cut off
// from Postgres shows as unhealthy to Docker, the appliance test and anyone probing it.
app.MapGet("/healthz", async (IDbContextFactory<VvDbContext> factory, CancellationToken ct) =>
{
    try
    {
        await using var db = await factory.CreateDbContextAsync(ct);
        return await db.Database.CanConnectAsync(ct) ? Results.Ok("ok") : Results.Json("database unreachable", statusCode: StatusCodes.Status503ServiceUnavailable);
    }
    catch (Exception ex) { return Results.Json("database unreachable: " + ex.GetType().Name, statusCode: StatusCodes.Status503ServiceUnavailable); }
}).AllowAnonymous();

app.Run();
