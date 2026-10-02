using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Digest;
using VulnVerdict.Core.Services;
using VulnVerdict.Web;

namespace VulnVerdict.Tests;

/// <summary>
/// The digest link pages over real HTTP on a loopback port: nobody signed in, a GET that only looks, a POST that
/// needs the page's antiforgery token.
/// </summary>
public class DigestActionEndpointTests : IAsyncLifetime
{
    private readonly NotificationFixture _fx = new();
    private WebApplication _app = default!;
    private HttpClient _client = default!;
    private Verdict _verdict = default!;
    private string _done = "";

    public async Task InitializeAsync()
    {
        await _fx.ConfigureAsync(_ => { });
        _verdict = _fx.AddVerdict();
        var tokens = new DigestActionTokens(_fx.Protection);
        var run = new DigestRun { Id = Guid.NewGuid(), Kind = DigestKind.Daily, GeneratedAt = DateTime.UtcNow, SentAt = DateTime.UtcNow, Subject = "test" };
        await using (var db = await _fx.Factory.CreateDbContextAsync()) { db.DigestRuns.Add(run); await db.SaveChangesAsync(); }
        _done = tokens.Create(run.Id, _verdict, DigestActionKind.Done, DateTime.UtcNow);

        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        builder.Logging.ClearProviders();
        builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();
        builder.Services.AddAntiforgery();
        builder.Services.AddRateLimiter(_ => { });
        builder.Services.AddSingleton(_fx.Settings);
        builder.Services.AddSingleton(new DigestActionService(_fx.Factory, _fx.Settings, _fx.Workflow(_fx.Outbox()), tokens));
        _app = builder.Build();
        _app.UseRateLimiter();
        _app.UseAntiforgery();
        _app.MapDigestActions();
        await _app.StartAsync();

        var address = _app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.First();
        _client = new HttpClient(new HttpClientHandler { CookieContainer = new CookieContainer(), AllowAutoRedirect = false }) { BaseAddress = new Uri(address) };
    }

    public async Task DisposeAsync()
    {
        _client.Dispose();
        await _app.StopAsync();
        await _app.DisposeAsync();
        _fx.Dispose();
    }

    private string Link(string token) => DigestActionTokens.Path + "?t=" + token;

    private (int History, int Audit, VerdictState State) Snapshot()
    {
        using var db = _fx.Factory.CreateDbContext();
        return (db.VerdictHistory.Count(), db.Audit.Count(), db.Verdicts.AsNoTracking().First(v => v.Id == _verdict.Id).State);
    }

    private static FormUrlEncodedContent Form(string page, string token)
    {
        var field = Regex.Match(page, "<input type=\"hidden\" name=\"(__RequestVerificationToken)\" value=\"([^\"]+)\"");
        Assert.True(field.Success, "the confirmation page carries an antiforgery field");
        return new FormUrlEncodedContent(new Dictionary<string, string> { [field.Groups[1].Value] = WebUtility.HtmlDecode(field.Groups[2].Value), ["t"] = token });
    }

    [Fact]
    public async Task Get_shows_a_confirmation_and_changes_nothing()
    {
        var before = Snapshot();
        for (var i = 0; i < 3; i++)
        {
            using var resp = await _client.GetAsync(Link(_done));
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            Assert.Contains("no-store", resp.Headers.CacheControl!.ToString());
            var page = await resp.Content.ReadAsStringAsync();
            Assert.Contains("Mark as done?", page);
            Assert.Contains(">Confirm</button>", page);
            Assert.Contains("CVE-2024-1234", page);
            Assert.Contains("Nothing changes until you press Confirm.", page);
        }
        // a HEAD from a link checker gets no further than a GET does
        using (var head = await _client.SendAsync(new HttpRequestMessage(HttpMethod.Head, Link(_done)))) { }
        Assert.Equal(before, Snapshot());
    }

    [Fact]
    public async Task Post_needs_the_antiforgery_token_from_the_page()
    {
        var before = Snapshot();
        var page = await _client.GetStringAsync(Link(_done));

        // a form posted from somewhere else: the token in the link alone is not enough
        using (var forged = await _client.PostAsync(DigestActionTokens.Path, new FormUrlEncodedContent(new Dictionary<string, string> { ["t"] = _done })))
        {
            Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);
            Assert.Contains("The page has expired", await forged.Content.ReadAsStringAsync());
        }
        using (var bare = new HttpClient { BaseAddress = _client.BaseAddress })
        using (var noCookie = await bare.PostAsync(DigestActionTokens.Path, Form(page, _done)))
            Assert.Equal(HttpStatusCode.BadRequest, noCookie.StatusCode);
        Assert.Equal(before, Snapshot());

        using var resp = await _client.PostAsync(DigestActionTokens.Path, Form(page, _done));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains("Marked as done", await resp.Content.ReadAsStringAsync());
        var v = _fx.Reload(_verdict.Id);
        Assert.Equal(VerdictState.Closed, v.State);
        Assert.StartsWith("digest link (digest ", Assert.Single(v.History).Actor);
        await using (var db = await _fx.Factory.CreateDbContextAsync())
            Assert.Contains("confirmed from 127.0.0.1", (await db.Audit.AsNoTracking().SingleAsync(a => a.Action == "digest.link")).After);

        // the same link again, by GET or by POST: the verdict is no longer what the email described
        var after = Snapshot();
        Assert.Contains("This has changed since the email", await _client.GetStringAsync(Link(_done)));
        using (var again = await _client.PostAsync(DigestActionTokens.Path, Form(page, _done)))
            Assert.Contains("This has changed since the email", await again.Content.ReadAsStringAsync());
        Assert.Equal(after, Snapshot());
    }

    [Fact]
    public async Task A_bad_token_is_refused_and_requests_are_rate_limited()
    {
        using (var bad = await _client.GetAsync(Link(_done[..^6] + "AAAAAA")))
        {
            Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
            Assert.Contains("This link is not valid", await bad.Content.ReadAsStringAsync());
        }
        using (var none = await _client.GetAsync(DigestActionTokens.Path)) Assert.Equal(HttpStatusCode.BadRequest, none.StatusCode);

        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 70; i++)
        {
            using var resp = await _client.GetAsync(Link("guess" + i));
            statuses.Add(resp.StatusCode);
        }
        Assert.Contains(statuses, s => (int)s is 429 or 503);
        Assert.Equal(VerdictState.Open, _fx.Reload(_verdict.Id).State);
    }
}
