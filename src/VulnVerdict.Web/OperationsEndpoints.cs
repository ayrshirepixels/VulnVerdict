using VulnVerdict.Core.Digest;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Web;

/// <summary>The Prometheus endpoint and the SLA report downloads.</summary>
public static class OperationsEndpoints
{
    public static void MapOperationsEndpoints(this WebApplication app)
    {
        // Not behind the console's sign-in (a scraper has no cookie) and never open either: off until an administrator
        // turns it on, then only for the metrics bearer token or an address in the allow-list. While it is off the
        // answer is 404, so the endpoint does not advertise itself.
        app.MapGet("/metrics", async (HttpContext http, MetricsAuth auth, MetricsService metrics, CancellationToken ct) =>
        {
            switch (await auth.AuthoriseAsync(http.Request.Headers.Authorization.ToString(), http.Connection.RemoteIpAddress, ct))
            {
                case MetricsAccess.Disabled: return Results.NotFound();
                case MetricsAccess.Denied:
                    http.Response.Headers.WWWAuthenticate = "Bearer";
                    return Results.Text("unauthorized: send Authorization: Bearer <metrics token from Settings>\n", "text/plain", statusCode: StatusCodes.Status401Unauthorized);
            }
            http.Response.Headers.CacheControl = "no-store";
            return Results.Text(await metrics.RenderAsync(null, ct), MetricsService.ContentType);
        }).AllowAnonymous().RequireRateLimiting("api");

        // signed-in users, like the weekly report beside them
        app.MapGet("/reports/sla.html", async (SlaReportService sla, SettingsService settings, int? weeks, CancellationToken ct) =>
        {
            var report = await sla.BuildAsync(weeks is > 0 ? weeks.Value : 12, null, ct);
            return Results.Content(SlaReportRenderer.OwnerHtml(report, (await settings.LoadAsync(ct)).ResolveTimeZone()), "text/html");
        });
        app.MapGet("/reports/sla.csv", async (SlaReportService sla, int? weeks, CancellationToken ct) =>
            Results.File(System.Text.Encoding.UTF8.GetBytes(SlaReportRenderer.Csv(await sla.BuildAsync(weeks is > 0 ? weeks.Value : 26, null, ct))), "text/csv", "vulnverdict-sla-" + DateTime.UtcNow.ToString("yyyy-MM-dd") + ".csv"));
    }
}
