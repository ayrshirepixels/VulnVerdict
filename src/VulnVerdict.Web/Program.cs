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

// backup-decrypt and backup-verify (deploy/restore.sh) run and exit without starting the console
if (await BackupCli.TryRunAsync(args)) return;

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
builder.Services.AddSingleton<UserService>();
builder.Services.AddSingleton<TwoFactorService>();
builder.Services.AddSingleton<ApiTokenService>();
builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<Microsoft.AspNetCore.Components.Authorization.AuthenticationStateProvider, RevalidatingAuthStateProvider>();
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
        // the account is re-checked on every request, so a deleted, demoted or reset user's cookie stops working
        o.Events = new CookieAuthenticationEvents { OnValidatePrincipal = AuthService.ValidatePrincipalAsync };
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
if (await ConsoleCommands.RunAsync(args, app.Services)) return; // break-glass: reset-2fa <username>, see docs/security.md
await app.Services.GetRequiredService<ApiTokenService>().MigrateLegacyAsync();
app.Services.GetRequiredService<AuthService>().ReloadOidc(await app.Services.GetRequiredService<SettingsService>().LoadAsync());
if (role is "all" or "web")
{
    // First run: the setup page needs a one-time token that only someone with the container log or data folder has,
    // so whoever reaches the console first over the network cannot claim the administrator account.
    var setupToken = await app.Services.GetRequiredService<UserService>().EnsureSetupTokenAsync(dataDir);
    if (setupToken is not null)
        app.Logger.LogWarning("""

            ================================================================
             VulnVerdict first run. Setup token: {Token}
             Enter it on the setup page to create the administrator account.
             Also saved in {Path} until the account exists.
            ================================================================
            """, setupToken, Path.Combine(Path.GetFullPath(dataDir), UserService.SetupTokenFile));
}

// ---- pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);

// security headers on every response
app.Use(async (ctx, next) =>
{
    var h = ctx.Response.Headers;
    h["X-Content-Type-Options"] = "nosniff";
    h["X-Frame-Options"] = "SAMEORIGIN"; // the console frames its own digest HTML
    h["Referrer-Policy"] = "same-origin";
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
    // connect-src: Blazor's circuit is a same-origin WebSocket; 'self' covers it in current browsers and the explicit
    // ws(s)://host covers older Safari. form-action: the console's own forms, plus the identity provider when SSO is on.
    var host = ctx.Request.Host.Value ?? "";
    var socket = host.Length > 0 && host.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '-' or ':' or '[' or ']') ? " wss://" + host + " ws://" + host : "";
    var oidc = ctx.RequestServices.GetRequiredService<AuthService>().OidcOrigin;
    h["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'" + socket + "; frame-src 'self'; frame-ancestors 'self'; form-action 'self'" + (oidc is null ? "" : " " + oidc) + "; base-uri 'self'";
    await next();
});

app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapStaticAssets().AllowAnonymous();
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();

// ---- authentication endpoints (static forms, antiforgery-protected)
app.MapPost("/auth/setup", async ([FromForm] string username, [FromForm] string password, [FromForm] string? email, [FromForm] string? token, HttpContext http, UserService users) =>
{
    if (await users.HasUsersAsync()) return Results.Redirect("/login");
    if (string.IsNullOrWhiteSpace(username) || password.Length < 12) return Results.Redirect("/setup?error=Password+must+be+at+least+12+characters");
    if (!UserService.SetupTokenMatches(dataDir, token))
    {
        await Task.Delay(Random.Shared.Next(200, 600));
        return Results.Redirect("/setup?error=" + Uri.EscapeDataString("That setup token is not right. It is printed in the console log (docker compose logs web)."));
    }
    var user = await users.CreateFirstAdministratorAsync(dataDir, token, username, password, email);
    if (user is null) return Results.Redirect("/login");
    await http.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, AuthService.BuildPrincipal(user), new AuthenticationProperties { IsPersistent = true });
    return Results.Redirect("/account?first=1"); // offers two-factor for the new administrator, then carries on to settings
}).AllowAnonymous().RequireRateLimiting("login");

app.MapPost("/auth/login", async ([FromForm] string username, [FromForm] string password, [FromForm] string? returnUrl, HttpContext http, UserService users) =>
{
    var user = await users.ValidateLocalAsync(username, password);
    if (user is null)
    {
        await Task.Delay(Random.Shared.Next(200, 600));
        return Results.Redirect("/login?error=1" + (string.IsNullOrEmpty(returnUrl) ? "" : "&returnUrl=" + Uri.EscapeDataString(returnUrl)));
    }
    // signed in here only when the account needs no second step; otherwise on to the code, or to enrolment
    return await TwoFactorEndpoints.ContinueSignInAsync(http, user, returnUrl);
}).AllowAnonymous().RequireRateLimiting("login");
app.MapTwoFactor();

app.MapGet("/auth/oidc", async (string? returnUrl, HttpContext http, SettingsService settings) =>
{
    var s = await settings.LoadAsync();
    if (!s.OidcEnabled) return Results.Redirect("/login");
    return Results.Challenge(new AuthenticationProperties { RedirectUri = AuthService.SafeReturnUrl(returnUrl) }, new[] { AuthService.OidcScheme });
}).AllowAnonymous();

// The antiforgery middleware only enforces its check on endpoints that bind form fields; these bind none, so they check it themselves.
static async ValueTask<object?> RequireAntiforgery(EndpointFilterInvocationContext ctx, EndpointFilterDelegate next) =>
    await ctx.HttpContext.RequestServices.GetRequiredService<Microsoft.AspNetCore.Antiforgery.IAntiforgery>().IsRequestValidAsync(ctx.HttpContext)
        ? await next(ctx)
        : Results.BadRequest("The form has expired. Reload the page and try again.");

app.MapPost("/auth/logout", async (HttpContext http) =>
{
    await http.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/login");
}).AllowAnonymous().AddEndpointFilter(RequireAntiforgery);

// ---- API with bearer tokens (Authorization: Bearer <token>): the read-only token reads, the read-write token also imports
var api = app.MapGroup("/api").RequireRateLimiting("api").AllowAnonymous().AddEndpointFilter(async (ctx, next) =>
{
    var http = ctx.HttpContext;
    var scope = await http.RequestServices.GetRequiredService<ApiTokenService>().AuthoriseAsync(http.Request.Headers.Authorization.ToString(), http.RequestAborted);
    if (scope == ApiScope.None)
        return Results.Json(new { error = "unauthorized", hint = "send Authorization: Bearer <API token from Settings>" }, statusCode: StatusCodes.Status401Unauthorized);
    if (HttpMethods.IsGet(http.Request.Method) || HttpMethods.IsHead(http.Request.Method)) return await next(ctx);
    if (scope != ApiScope.ReadWrite)
        return Results.Json(new { error = "forbidden", hint = "this call changes data and needs the read-write API token" }, statusCode: StatusCodes.Status403Forbidden);
    // every write through the API is in the audit log
    await using (var db = await http.RequestServices.GetRequiredService<IDbContextFactory<VvDbContext>>().CreateDbContextAsync(http.RequestAborted))
    {
        var target = http.Request.Method + " " + http.Request.Path + http.Request.QueryString;
        db.Audit.Add(new AuditEntry { At = DateTime.UtcNow, Actor = "api", Action = "api.write", Target = target.Length > 256 ? target[..256] : target, After = http.Connection.RemoteIpAddress?.ToString() });
        await db.SaveChangesAsync(http.RequestAborted);
    }
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
app.MapDigestActions();   // the digest email's Done and Snooze links: anonymous, token-signed (DigestActionEndpoints.cs)
app.MapGet("/digests/preview/html", async (DigestService digest) => Results.Content((await digest.BuildAsync()).Html, "text/html"));
app.MapGet("/reports/weekly.html", async (ReportService reports, int? weeks) => Results.Content((await reports.BuildAsync(weeks is > 0 ? DateTime.UtcNow.AddDays(-7 * weeks.Value) : null)).Html, "text/html"));
// Connector diagnostics for a bug report: one collection run, nothing applied to the inventory, identifying values replaced.
// Administrators only (it runs the connector with its stored credentials), audited, and a POST with an antiforgery
// token because it contacts the source: a link or image on another page cannot start it.
app.MapPost("/connectors/{id:guid}/diagnostics", async (Guid id, HttpContext http, IDbContextFactory<VvDbContext> factory, ConnectorService connectors, ConnectorDiagnostics diagnostics, CancellationToken ct) =>
{
    await using var db = await factory.CreateDbContextAsync(ct);
    var c = await db.Connectors.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct);
    var adapter = c is null ? null : connectors.Adapters.FirstOrDefault(a => a.Metadata.Id.Equals(c.AdapterId, StringComparison.OrdinalIgnoreCase));
    if (c is null || adapter is null) return Results.NotFound();
    db.Audit.Add(new AuditEntry { At = DateTime.UtcNow, Actor = http.User.Identity?.Name ?? "?", Action = "connector.diagnostics", Target = c.DisplayName });
    await db.SaveChangesAsync(ct);
    var bytes = await diagnostics.RunAsync(adapter, connectors.Decrypt(c), ct);
    http.Response.Headers.CacheControl = "no-store";
    return Results.File(bytes, "application/json", "vulnverdict-diagnostics-" + adapter.Metadata.Id + "-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmm") + ".json");
}).RequireAuthorization(p => p.RequireRole("Administrator")).AddEndpointFilter(RequireAntiforgery);

app.MapGet("/reports/weekly.csv", async (ReportService reports, int? weeks) =>
    Results.File(System.Text.Encoding.UTF8.GetBytes((await reports.BuildAsync(weeks is > 0 ? DateTime.UtcNow.AddDays(-7 * weeks.Value) : null)).Csv), "text/csv", "vulnverdict-weekly-" + DateTime.UtcNow.ToString("yyyy-MM-dd") + ".csv"));

app.MapOperationsEndpoints();

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
