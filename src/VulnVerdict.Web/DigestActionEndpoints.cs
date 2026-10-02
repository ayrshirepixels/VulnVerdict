using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.RateLimiting;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Digest;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Web;

/// <summary>
/// The pages behind the digest email's Done and Snooze links. Nobody is signed in: the signed token in the link is
/// the authority (see docs/digest.md). The GET shows what the link would do and changes nothing, because mail
/// scanners and link previewers follow links; the change happens on the POST from the page's Confirm button, which
/// carries an antiforgery token. Both are rate limited per address.
/// </summary>
public static class DigestActionEndpoints
{
    public static IEndpointRouteBuilder MapDigestActions(this IEndpointRouteBuilder app)
    {
        var limit = new PerAddressLimit();

        app.MapGet(DigestActionTokens.Path, async (string? t, HttpContext http, DigestActionService actions, IAntiforgery antiforgery, SettingsService settings, CancellationToken ct) =>
        {
            var result = await actions.PreviewAsync(t, ct);
            var form = result.Status == DigestActionStatus.Ready ? antiforgery.GetAndStoreTokens(http) : null;
            return Page(http, result, t, form, (await settings.LoadAsync(ct)).ResolveTimeZone());
        }).AllowAnonymous().RequireRateLimiting(limit);

        app.MapPost(DigestActionTokens.Path, async (HttpContext http, DigestActionService actions, IAntiforgery antiforgery, SettingsService settings, CancellationToken ct) =>
        {
            if (!http.Request.HasFormContentType || !await antiforgery.IsRequestValidAsync(http))
                return Html(http, "The page has expired", "<p>Go back to the email and open the link again.</p>", StatusCodes.Status400BadRequest);
            var t = (await http.Request.ReadFormAsync(ct))["t"].ToString();
            var result = await actions.ConfirmAsync(t, http.Connection.RemoteIpAddress?.ToString(), ct);
            return Page(http, result, t, null, (await settings.LoadAsync(ct)).ResolveTimeZone());
        }).AllowAnonymous().RequireRateLimiting(limit);

        return app;
    }

    private static IResult Page(HttpContext http, DigestActionResult r, string? token, AntiforgeryTokenSet? form, TimeZoneInfo tz)
    {
        static string E(string? s) => WebUtility.HtmlEncode(s ?? "");
        var console = r.VerdictId is { } id ? "<a class=\"btn btn-secondary\" href=\"/verdicts/" + id + "\">Open it in the console</a>" : "<a class=\"btn btn-secondary\" href=\"/\">Open the console</a>";
        var summary = r.CveId is null ? "" : "<p>" + E(r.Sentence) + "</p><p class=\"muted\">" + E(r.CveId) + " &middot; " + E(r.Tier.Plain())
            + (r.SlaDue is { } due ? " &middot; due " + E(Ui.Local(due, tz, "d MMM yyyy")) : "") + "</p>";
        var snooze = "Snooze for " + DigestActionService.SnoozeDays + " days";
        switch (r.Status)
        {
            case DigestActionStatus.Ready:
                return Html(http, r.Action == DigestActionKind.Done ? "Mark as done?" : snooze + "?", summary
                    + "<form method=\"post\" action=\"" + DigestActionTokens.Path + "\">"
                    + "<input type=\"hidden\" name=\"" + E(form!.FormFieldName) + "\" value=\"" + E(form.RequestToken) + "\" />"
                    + "<input type=\"hidden\" name=\"t\" value=\"" + E(token) + "\" />"
                    + "<div class=\"btn-row\"><button type=\"submit\" class=\"btn\">Confirm</button>" + console + "</div></form>"
                    + "<p class=\"muted\" style=\"margin:14px 0 0\">Nothing changes until you press Confirm. It is recorded as " + (r.Action == DigestActionKind.Done ? "done" : "snoozed") + " via digest link (" + E(r.DigestLabel) + ").</p>");
            case DigestActionStatus.Performed:
                return Html(http, r.Action == DigestActionKind.Done ? "Marked as done" : "Snoozed until " + Ui.Local(r.SnoozedUntil, tz, "d MMM yyyy"), summary
                    + "<div class=\"alert alert-ok\">" + (r.Action == DigestActionKind.Done ? "Done. It will not appear in the next digest unless it gets worse." : "Snoozed. It comes back when the snooze ends, or sooner if it is promoted.") + "</div>"
                    + "<div class=\"btn-row\">" + console + "</div>");
            case DigestActionStatus.Changed:
                return Html(http, "This has changed since the email", summary + "<div class=\"alert alert-warn\">Its state or verdict is not what it was when the digest was sent, so the link did nothing.</div><div class=\"btn-row\">" + console + "</div>");
            case DigestActionStatus.Expired:
                return Html(http, "This link has expired", summary + "<div class=\"alert alert-warn\">Digest links work for " + DigestActionTokens.Lifetime.Days + " days.</div><div class=\"btn-row\">" + console + "</div>");
            case DigestActionStatus.Disabled:
                return Html(http, "Digest links are switched off", "<p>An administrator has turned off the links in the digest email.</p><div class=\"btn-row\">" + console + "</div>");
            default:
                return Html(http, "This link is not valid", "<p>It was not issued by this console, or what it refers to no longer exists.</p><div class=\"btn-row\">" + console + "</div>", StatusCodes.Status400BadRequest);
        }
    }

    /// <summary>A small standalone page in the console's own style. <paramref name="body"/> is HTML: encode anything that came from data.</summary>
    private static IResult Html(HttpContext http, string title, string body, int status = StatusCodes.Status200OK)
    {
        // the address carries the token: keep the page out of caches and search indexes
        http.Response.Headers.CacheControl = "no-store";
        http.Response.Headers["X-Robots-Tag"] = "noindex";
        var html = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\" /><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />"
            + "<title>" + WebUtility.HtmlEncode(title) + " - VulnVerdict</title><link rel=\"stylesheet\" href=\"/fonts.css\" /><link rel=\"stylesheet\" href=\"/app.css\" />"
            + "<link rel=\"icon\" type=\"image/svg+xml\" href=\"/favicon.svg\" /></head><body><div class=\"auth-wrap\"><div class=\"auth-card\">"
            + "<div class=\"brand\"><img src=\"/logo.svg\" alt=\"\" /><span class=\"word\"><em>VULN</em>VERDICT</span></div>"
            + "<h2 style=\"margin:14px 0 10px\">" + WebUtility.HtmlEncode(title) + "</h2>" + body + "</div></div></body></html>";
        return Results.Content(html, "text/html; charset=utf-8", statusCode: status);
    }

    /// <summary>60 requests a minute per address: plenty for a team working through a digest behind one proxy, and a ceiling on anything automated.</summary>
    private sealed class PerAddressLimit : IRateLimiterPolicy<string>
    {
        public Func<OnRejectedContext, CancellationToken, ValueTask>? OnRejected => null;

        public RateLimitPartition<string> GetPartition(HttpContext http) =>
            RateLimitPartition.GetFixedWindowLimiter("digest-action:" + (http.Connection.RemoteIpAddress?.ToString() ?? "anon"),
                _ => new FixedWindowRateLimiterOptions { PermitLimit = 60, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 });
    }
}
