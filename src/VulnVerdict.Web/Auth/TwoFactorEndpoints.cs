using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Web;

/// <summary>
/// The second step of a local sign-in and the forms on the My account page. Between password and code the browser
/// holds only <see cref="PendingCookie"/>: a five-minute token for that one purpose, which the cookie
/// authentication never reads, so nothing is signed in until the code is accepted.
/// </summary>
public static class TwoFactorEndpoints
{
    public const string PendingCookie = "vv.2fa";
    /// <summary>Carries freshly made recovery codes from the endpoint to the page that shows them, once.</summary>
    public const string CodesCookie = "vv.2fa.codes";

    /// <summary>The password was right. Sign in, or hand over to the code step or to forced enrolment.</summary>
    public static async Task<IResult> ContinueSignInAsync(HttpContext http, AppUser user, string? returnUrl)
    {
        var twoFactor = http.RequestServices.GetRequiredService<TwoFactorService>();
        var step = TwoFactorService.NextStep(user, await twoFactor.IsRequiredAsync(http.RequestAborted));
        if (step == SignInStep.SignedIn)
        {
            await SignInAsync(http, user);
            return Results.LocalRedirect(AuthService.SafeReturnUrl(returnUrl));
        }
        var needsCode = step == SignInStep.NeedsCode;
        SetCookie(http, PendingCookie, twoFactor.IssuePending(user, needsCode ? TwoFactorService.PurposeVerify : TwoFactorService.PurposeEnrol));
        return Results.Redirect((needsCode ? "/login/code" : "/login/enrol") + ReturnQuery('?', returnUrl));
    }

    public static IEndpointRouteBuilder MapTwoFactor(this IEndpointRouteBuilder app)
    {
        // ---- sign-in, second step: no session yet, only the pending token
        app.MapPost("/auth/login/code", async ([FromForm] string? code, [FromForm] string? returnUrl, HttpContext http, TwoFactorService twoFactor, UserService users) =>
        {
            var user = await twoFactor.PendingUserAsync(http.Request.Cookies[PendingCookie], TwoFactorService.PurposeVerify);
            if (user is null) return Expired(http);
            var result = await twoFactor.VerifyAsync(user.Id, code);
            if (result == SecondFactorResult.Locked)
            {
                http.Response.Cookies.Delete(PendingCookie);
                return Results.Redirect("/login?error=locked");
            }
            if (result == SecondFactorResult.Wrong)
            {
                await Task.Delay(Random.Shared.Next(200, 600));
                return Results.Redirect("/login/code?error=1" + ReturnQuery('&', returnUrl));
            }
            http.Response.Cookies.Delete(PendingCookie);
            await SignInAsync(http, user);
            // a recovery code is spent: say so, and how many are left
            return result == SecondFactorResult.OkRecoveryCode
                ? Results.Redirect("/account?notice=recovery" + ReturnQuery('&', returnUrl))
                : Results.LocalRedirect(AuthService.SafeReturnUrl(returnUrl));
        }).AllowAnonymous().RequireRateLimiting("login");

        // ---- sign-in when the policy requires two-factor and the account has none: enrol before any session exists
        app.MapPost("/auth/login/enrol", async ([FromForm] string? code, [FromForm] string? returnUrl, HttpContext http, TwoFactorService twoFactor, UserService users) =>
        {
            var user = await twoFactor.PendingUserAsync(http.Request.Cookies[PendingCookie], TwoFactorService.PurposeEnrol);
            if (user is null) return Expired(http);
            var codes = await twoFactor.ConfirmEnrolmentAsync(user.Id, code, user.Username);
            if (codes is null) return Results.Redirect("/login/enrol?error=1" + ReturnQuery('&', returnUrl));
            http.Response.Cookies.Delete(PendingCookie);
            return await ShowCodesAsync(http, twoFactor, users, user.Id, codes, returnUrl);
        }).AllowAnonymous().RequireRateLimiting("login");

        // ---- My account (signed in)
        app.MapPost("/auth/2fa/enable", async ([FromForm] string? code, [FromForm] string? returnUrl, HttpContext http, TwoFactorService twoFactor, UserService users) =>
        {
            if (UserId(http) is not { } id) return Results.Redirect("/login");
            var codes = await twoFactor.ConfirmEnrolmentAsync(id, code, Ui.Actor(http.User));
            if (codes is null) return Results.Redirect("/account?enrol=1&error=code" + ReturnQuery('&', returnUrl));
            return await ShowCodesAsync(http, twoFactor, users, id, codes, returnUrl);
        }).RequireRateLimiting("login");

        app.MapPost("/auth/2fa/recovery-codes", async ([FromForm] string? code, HttpContext http, TwoFactorService twoFactor, UserService users) =>
        {
            if (UserId(http) is not { } id) return Results.Redirect("/login");
            var codes = await twoFactor.RegenerateRecoveryCodesAsync(id, code);
            if (codes is null) return Results.Redirect("/account?error=code");
            return await ShowCodesAsync(http, twoFactor, users, id, codes, null);
        }).RequireRateLimiting("login");

        app.MapPost("/auth/2fa/disable", async ([FromForm] string? password, [FromForm] string? code, HttpContext http, TwoFactorService twoFactor, UserService users) =>
        {
            if (UserId(http) is not { } id) return Results.Redirect("/login");
            if (await twoFactor.IsRequiredAsync()) return Results.Redirect("/account?error=required");
            if (!await twoFactor.DisableAsync(id, password, code))
            {
                await Task.Delay(Random.Shared.Next(200, 600));
                return Results.Redirect("/account?error=disable");
            }
            // the stamp moved: this browser carries on with a fresh cookie, every other session of the account ends
            if (await users.FindAsync(id) is { } user) await SignInAsync(http, user);
            return Results.Redirect("/account?notice=off");
        }).RequireRateLimiting("login");

        return app;
    }

    public static Task SignInAsync(HttpContext http, AppUser user) =>
        http.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, AuthService.BuildPrincipal(user), new AuthenticationProperties { IsPersistent = true });

    /// <summary>Two-factor has just been switched on (or the codes replaced): refresh this browser's session and show the codes once.</summary>
    private static async Task<IResult> ShowCodesAsync(HttpContext http, TwoFactorService twoFactor, UserService users, Guid id, IReadOnlyList<string> codes, string? returnUrl)
    {
        var user = await users.FindAsync(id);
        if (user is null) return Results.Redirect("/login");
        await SignInAsync(http, user);
        SetCookie(http, CodesCookie, twoFactor.IssuePending(user, TwoFactorService.PurposeCodes, string.Join(',', codes)));
        return Results.Redirect("/account" + ReturnQuery('?', returnUrl));
    }

    private static IResult Expired(HttpContext http)
    {
        http.Response.Cookies.Delete(PendingCookie);
        return Results.Redirect("/login?error=expired");
    }

    private static Guid? UserId(HttpContext http) => Guid.TryParse(http.User.FindFirst(ClaimTypes.NameIdentifier)?.Value, out var id) ? id : null;

    private static void SetCookie(HttpContext http, string name, string value) =>
        http.Response.Cookies.Append(name, value, new CookieOptions
        {
            HttpOnly = true, SameSite = SameSiteMode.Strict, Secure = http.Request.IsHttps, IsEssential = true,
            MaxAge = TwoFactorService.PendingLifetime,
        });

    private static string ReturnQuery(char separator, string? returnUrl) =>
        string.IsNullOrEmpty(returnUrl) || AuthService.SafeReturnUrl(returnUrl) == "/" ? "" : separator + "returnUrl=" + Uri.EscapeDataString(returnUrl);
}
