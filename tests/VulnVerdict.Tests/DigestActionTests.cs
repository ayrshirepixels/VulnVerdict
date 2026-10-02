using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Digest;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

/// <summary>
/// The digest email's Done and Snooze links: what the token is bound to, that opening a link changes nothing, and
/// that a confirmed action is recorded. Also that a re-open is always reported under "Changed".
/// </summary>
public class DigestActionTests : IDisposable
{
    private readonly NotificationFixture _fx = new();
    private readonly DigestActionTokens _tokens;
    private readonly DigestActionService _actions;
    private readonly VerdictWorkflow _workflow;
    private readonly Verdict _verdict;

    public DigestActionTests()
    {
        _fx.Http.On(HttpMethod.Post, "/v3/mail/send", "");
        _fx.ConfigureMailAsync().GetAwaiter().GetResult();
        _tokens = new DigestActionTokens(_fx.Protection);
        _workflow = _fx.Workflow(_fx.Outbox());
        _actions = new DigestActionService(_fx.Factory, _fx.Settings, _workflow, _tokens);
        _verdict = _fx.AddVerdict();
    }

    public void Dispose() => _fx.Dispose();

    /// <summary>Send a digest and pull the tokens for the test verdict out of the email, as a recipient's mail client would see them.</summary>
    private async Task<(DigestRun Run, string Done, string Snooze)> SendAsync()
    {
        var run = await _fx.Digest(_tokens).SendDigestAsync(DigestKind.Daily);
        Assert.NotNull(run.SentAt);
        var links = Regex.Matches(SentHtml(), "href=\"https://vv\\.example\\.com/digest/action\\?t=([A-Za-z0-9_-]+)\"").Select(m => m.Groups[1].Value).ToList();
        var mine = links.Where(t => _tokens.Read(t)!.VerdictId == _verdict.Id).ToList();
        Assert.Equal(2, mine.Count);
        return (run, mine.Single(t => _tokens.Read(t)!.Action == DigestActionKind.Done), mine.Single(t => _tokens.Read(t)!.Action == DigestActionKind.Snooze));
    }

    /// <summary>The last email as it left: the SendGrid request's text and HTML parts.</summary>
    private FakeHandler.Call LastMail() => _fx.Http.Calls.Last(c => c.Path == "/v3/mail/send");
    private string SentText() => LastMail().Json!["content"]![0]!["value"]!.GetValue<string>();
    private string SentHtml() => LastMail().Json!["content"]![1]!["value"]!.GetValue<string>();

    private (int History, int Audit, int Outbox, string Verdict) Snapshot()
    {
        using var db = _fx.Factory.CreateDbContext();
        var v = db.Verdicts.AsNoTracking().First(x => x.Id == _verdict.Id);
        return (db.VerdictHistory.Count(), db.Audit.Count(), db.Outbox.Count(), v.State + "|" + v.Tier + "|" + v.StateReason + "|" + v.StateOwner + "|" + v.StateChangedAt?.Ticks + "|" + v.SnoozedUntil?.Ticks + "|" + v.UpdatedAt.Ticks);
    }

    // ------------------------------------------------------------------ tokens

    [Fact]
    public void Token_round_trips_what_it_was_issued_for()
    {
        var digest = Guid.NewGuid();
        var now = new DateTime(2026, 10, 2, 7, 30, 0, DateTimeKind.Utc);
        var token = _tokens.Create(digest, _verdict, DigestActionKind.Snooze, now);

        Assert.Matches("^[A-Za-z0-9_-]+$", token);   // safe in a link as it stands
        var read = _tokens.Read(token);
        Assert.NotNull(read);
        Assert.Equal(digest, read.DigestId);
        Assert.Equal(_verdict.Id, read.VerdictId);
        Assert.Equal(DigestActionKind.Snooze, read.Action);
        Assert.Equal(DigestActionTokens.StateVersion(_verdict), read.StateVersion);
        Assert.Equal(now.AddDays(7), read.ExpiresUtc);
    }

    [Fact]
    public void A_tampered_or_foreign_token_is_refused()
    {
        var token = _tokens.Create(Guid.NewGuid(), _verdict, DigestActionKind.Done, DateTime.UtcNow);
        Assert.NotNull(_tokens.Read(token));

        // any single character changed, anywhere
        for (var i = 0; i < token.Length - 2; i += 7)
        {
            var changed = token[..i] + (token[i] == 'A' ? 'B' : 'A') + token[(i + 1)..];
            Assert.Null(_tokens.Read(changed));
        }
        Assert.Null(_tokens.Read(token[..^4]));
        Assert.Null(_tokens.Read(""));
        Assert.Null(_tokens.Read(null));
        Assert.Null(_tokens.Read("not a token"));
        Assert.Null(_tokens.Read(new string('A', 5000)));

        // signed by the same console for another purpose (a settings secret, say): not a digest link
        var other = _fx.Protection.CreateProtector("VulnVerdict.Secrets.v1");
        Assert.Null(_tokens.Read(System.Buffers.Text.Base64Url.EncodeToString(other.Protect(new byte[50]))));
        // signed by another console's keys
        Assert.Null(new DigestActionTokens(new EphemeralDataProtectionProvider()).Read(token));
    }

    [Fact]
    public void State_version_follows_state_and_tier_only()
    {
        var before = DigestActionTokens.StateVersion(_verdict);
        var v = _fx.Reload(_verdict.Id);
        v.UpdatedAt = v.LastEvaluatedAt = DateTime.UtcNow.AddHours(1); v.FirstDigestAt = DateTime.UtcNow; v.Sentence = "reworded";
        Assert.Equal(before, DigestActionTokens.StateVersion(v));   // a re-evaluation that changes nothing leaves links working

        v.Tier = VerdictTier.FixThisWeek;
        Assert.NotEqual(before, DigestActionTokens.StateVersion(v));
        v.Tier = _verdict.Tier; v.TierChangedAt = DateTime.UtcNow;
        Assert.NotEqual(before, DigestActionTokens.StateVersion(v));
        v.TierChangedAt = _verdict.TierChangedAt; v.StateChangedAt = DateTime.UtcNow;
        Assert.NotEqual(before, DigestActionTokens.StateVersion(v));
    }

    // ------------------------------------------------------------------ the email

    [Fact]
    public async Task Sent_digest_carries_links_for_fix_today_and_fix_this_week_only()
    {
        var week = _fx.AddVerdict(cve: "CVE-2024-2000", tier: VerdictTier.FixThisWeek);
        var cycle = _fx.AddVerdict(cve: "CVE-2024-3000", tier: VerdictTier.NextPatchCycle);
        var unsure = _fx.AddVerdict(cve: "CVE-2024-4000", change: v => v.Confidence = MatchConfidence.Possible);

        var (run, done, _) = await SendAsync();

        var tokens = Regex.Matches(SentHtml(), "/digest/action\\?t=([A-Za-z0-9_-]+)").Select(m => _tokens.Read(m.Groups[1].Value)!).ToList();
        Assert.Equal(4, tokens.Count);
        Assert.All(tokens, t => Assert.Equal(run.Id, t.DigestId));   // one email to every recipient: bound to the digest, not a person
        Assert.Equal(new[] { _verdict.Id, week.Id }.Order(), tokens.Select(t => t.VerdictId).Distinct().Order());
        Assert.DoesNotContain(tokens, t => t.VerdictId == cycle.Id || t.VerdictId == unsure.Id);
        Assert.Contains(">Snooze 7 days</a>", SentHtml());
        Assert.Contains("    Done: https://vv.example.com/digest/action?t=" + done, SentText());
        Assert.Contains("    Snooze 7 days: https://vv.example.com/digest/action?t=", SentText());

        // one message to both recipients, so both hold the same links
        Assert.Contains("it@example.com", LastMail().Body);
        Assert.Contains("desk@example.com", LastMail().Body);

        // the copy the console keeps (and shows to any signed-in user) has the ordinary links, not the tokens
        Assert.DoesNotContain("/digest/action", run.Html);
        Assert.DoesNotContain("/digest/action", run.Text);
        Assert.Contains("?action=done", run.Html);
        await using var db = await _fx.Factory.CreateDbContextAsync();
        var stored = await db.DigestRuns.AsNoTracking().SingleAsync(r => r.Id == run.Id);
        Assert.DoesNotContain("/digest/action", stored.Html + stored.Text);
    }

    [Fact]
    public async Task No_links_in_a_preview_or_when_switched_off_or_without_a_console_address()
    {
        var digest = _fx.Digest(_tokens);
        var preview = await digest.BuildAsync();
        Assert.DoesNotContain("/digest/action", preview.Html);
        Assert.Contains("?action=done", preview.Html);   // Done opens the console, as before

        await _fx.ConfigureAsync(s => s.DigestActionLinks = false);
        await digest.SendDigestAsync(DigestKind.Daily);
        Assert.DoesNotContain("/digest/action", SentHtml());
        Assert.DoesNotContain("/digest/action", SentText());
        Assert.Contains("?action=done", SentHtml());

        await _fx.ConfigureAsync(s => { s.DigestActionLinks = true; });
        await digest.SendDigestAsync(DigestKind.Daily);
        Assert.Contains("/digest/action", SentHtml());
        var s2 = await _fx.Settings.LoadAsync(); s2.BaseUrl = ""; await _fx.Settings.SaveAsync(s2, "test");
        await digest.SendDigestAsync(DigestKind.Daily);
        Assert.DoesNotContain("/digest/action", SentHtml());
    }

    // ------------------------------------------------------------------ opening a link

    [Fact]
    public async Task Opening_a_link_never_changes_anything()
    {
        var (_, done, snooze) = await SendAsync();
        var before = Snapshot();

        // a mail scanner, a link previewer and the recipient all fetch the address; some of them several times
        for (var i = 0; i < 5; i++)
        {
            var d = await _actions.PreviewAsync(done);
            Assert.Equal(DigestActionStatus.Ready, d.Status);
            Assert.Equal(DigestActionKind.Done, d.Action);
            Assert.Equal(_verdict.Id, d.VerdictId);
            Assert.Equal("CVE-2024-1234", d.CveId);
            Assert.Equal(DigestActionKind.Snooze, (await _actions.PreviewAsync(snooze)).Action);
            Assert.Equal(DigestActionStatus.Invalid, (await _actions.PreviewAsync(done + "x")).Status);
        }

        Assert.Equal(before, Snapshot());
        Assert.Equal(VerdictState.Open, _fx.Reload(_verdict.Id).State);
    }

    [Fact]
    public async Task Confirming_done_closes_the_verdict_and_records_who_and_how()
    {
        var (run, done, snooze) = await SendAsync();
        var name = "digest " + run.Id.ToString("N")[..8];

        var result = await _actions.ConfirmAsync(done, "10.1.2.3");

        Assert.Equal(DigestActionStatus.Performed, result.Status);
        var v = _fx.Reload(_verdict.Id);
        Assert.Equal(VerdictState.Closed, v.State);
        Assert.Equal("marked done via digest link (" + name + ")", v.StateReason);
        var h = Assert.Single(v.History);
        Assert.Equal("digest link (" + name + ")", h.Actor);
        Assert.Equal("Closed", h.To);
        Assert.Equal("marked done via digest link (" + name + ")", h.Reason);

        await using (var db = await _fx.Factory.CreateDbContextAsync())
        {
            var audit = await db.Audit.AsNoTracking().Where(a => a.Actor == "digest link (" + name + ")").OrderBy(a => a.Id).ToListAsync();
            Assert.Equal(new[] { "verdict.closed", "digest.link" }, audit.Select(a => a.Action));
            Assert.Contains("via digest link (" + name, audit[1].After);
            Assert.Contains("confirmed from 10.1.2.3", audit[1].After);
        }

        // the link has been used: it, and the Snooze link from the same email, now find the verdict changed
        var before = Snapshot();
        Assert.Equal(DigestActionStatus.Changed, (await _actions.ConfirmAsync(done, "10.1.2.3")).Status);
        Assert.Equal(DigestActionStatus.Changed, (await _actions.ConfirmAsync(snooze, "10.1.2.3")).Status);
        Assert.Equal(DigestActionStatus.Changed, (await _actions.PreviewAsync(done)).Status);
        Assert.Equal(before, Snapshot());
    }

    [Fact]
    public async Task Confirming_snooze_snoozes_for_seven_days()
    {
        var (_, _, snooze) = await SendAsync();

        var result = await _actions.ConfirmAsync(snooze, null);

        Assert.Equal(DigestActionStatus.Performed, result.Status);
        var v = _fx.Reload(_verdict.Id);
        Assert.Equal(VerdictState.Snoozed, v.State);
        Assert.InRange(v.SnoozedUntil!.Value - DateTime.UtcNow, TimeSpan.FromDays(6.99), TimeSpan.FromDays(7));
        Assert.StartsWith("snoozed 7 days via digest link (digest ", v.StateReason);
        Assert.StartsWith("digest link (digest ", Assert.Single(v.History).Actor);
    }

    [Fact]
    public async Task An_expired_link_does_nothing()
    {
        var (run, _, _) = await SendAsync();
        var stale = _tokens.Create(run.Id, _fx.Reload(_verdict.Id), DigestActionKind.Done, DateTime.UtcNow.AddDays(-7).AddMinutes(-1));
        var fresh = _tokens.Create(run.Id, _fx.Reload(_verdict.Id), DigestActionKind.Done, DateTime.UtcNow.AddDays(-7).AddMinutes(5));
        var before = Snapshot();

        Assert.Equal(DigestActionStatus.Expired, (await _actions.PreviewAsync(stale)).Status);
        Assert.Equal(DigestActionStatus.Expired, (await _actions.ConfirmAsync(stale, null)).Status);
        Assert.Equal(before, Snapshot());

        Assert.Equal(DigestActionStatus.Ready, (await _actions.PreviewAsync(fresh)).Status);   // five minutes left
    }

    [Fact]
    public async Task A_link_for_a_verdict_that_has_changed_since_the_email_does_nothing()
    {
        var (_, done, snooze) = await SendAsync();

        // promoted or demoted by an evaluation after the digest went out
        await using (var db = await _fx.Factory.CreateDbContextAsync())
        {
            var v = await db.Verdicts.FirstAsync(x => x.Id == _verdict.Id);
            v.Tier = VerdictTier.FixThisWeek; v.PreviousTier = VerdictTier.FixToday; v.TierChangedAt = DateTime.UtcNow; v.TierChangeReason = "exploit evidence withdrawn";
            await db.SaveChangesAsync();
        }
        var before = Snapshot();
        Assert.Equal(DigestActionStatus.Changed, (await _actions.PreviewAsync(done)).Status);
        Assert.Equal(DigestActionStatus.Changed, (await _actions.ConfirmAsync(done, null)).Status);
        Assert.Equal(DigestActionStatus.Changed, (await _actions.ConfirmAsync(snooze, null)).Status);
        Assert.Equal(before, Snapshot());
        Assert.Equal(VerdictState.Open, _fx.Reload(_verdict.Id).State);
    }

    [Fact]
    public async Task A_link_for_a_verdict_closed_and_re_opened_since_the_email_does_nothing()
    {
        var (_, done, _) = await SendAsync();
        await _workflow.CloseAsync(_verdict.Id, "alice", "patched");
        await _workflow.ReopenAsync(_verdict.Id, "alice");

        // open again at the same tier, but not the decision the email was about
        Assert.Equal(VerdictState.Open, _fx.Reload(_verdict.Id).State);
        Assert.Equal(DigestActionStatus.Changed, (await _actions.ConfirmAsync(done, null)).Status);
        Assert.Equal(VerdictState.Open, _fx.Reload(_verdict.Id).State);
    }

    [Fact]
    public async Task Links_stop_working_when_switched_off_and_for_a_digest_that_was_never_sent()
    {
        var (_, done, _) = await SendAsync();

        // a token for a digest id that never went out (built, not sent)
        var unsent = _tokens.Create(Guid.NewGuid(), _fx.Reload(_verdict.Id), DigestActionKind.Done, DateTime.UtcNow);
        Assert.Equal(DigestActionStatus.Invalid, (await _actions.ConfirmAsync(unsent, null)).Status);

        await _fx.ConfigureAsync(s => s.DigestActionLinks = false);
        Assert.Equal(DigestActionStatus.Disabled, (await _actions.PreviewAsync(done)).Status);
        Assert.Equal(DigestActionStatus.Disabled, (await _actions.ConfirmAsync(done, null)).Status);
        Assert.Equal(VerdictState.Open, _fx.Reload(_verdict.Id).State);

        await _fx.ConfigureAsync(s => s.DigestActionLinks = true);
        Assert.Equal(DigestActionStatus.Performed, (await _actions.ConfirmAsync(done, null)).Status);
    }

    // ------------------------------------------------------------------ re-opens under "Changed"

    [Fact]
    public async Task A_re_open_without_a_tier_change_is_reported_under_changed()
    {
        // marked done by a person, then re-opened by the evaluator at the same tier: a state line, no tier line
        await _workflow.CloseAsync(_verdict.Id, "alice", "patched");
        await using (var db = await _fx.Factory.CreateDbContextAsync())
        {
            var v = await db.Verdicts.FirstAsync(x => x.Id == _verdict.Id);
            await db.VerdictHistory.Where(h => h.VerdictId == v.Id).ExecuteUpdateAsync(u => u.SetProperty(h => h.Digested, true));   // the close was in yesterday's digest
            var now = DateTime.UtcNow;
            db.VerdictHistory.Add(new VerdictHistory { VerdictId = v.Id, At = now, Actor = "system", Kind = "state", From = "Closed", To = "Open", Reason = "re-opened: now in CISA KEV" });
            v.State = VerdictState.Open; v.StateReason = null; v.StateOwner = null; v.StateChangedAt = now; v.TierChangeReason = "re-opened: now in CISA KEV";
            await db.SaveChangesAsync();
        }

        var digest = await _fx.Digest().BuildAsync();

        Assert.Contains(digest.FixToday, i => i.VerdictId == _verdict.Id);
        var changed = Assert.Single(digest.Changed);
        Assert.Equal(_verdict.Id, changed.VerdictId);
        Assert.Equal("re-opened: now in CISA KEV", changed.Reason);
        Assert.Contains("Changed since last digest", digest.Html);
        Assert.Contains("(re-opened: now in CISA KEV)", digest.Html);
        Assert.Contains("(re-opened: now in CISA KEV)", digest.Text);
    }

    [Fact]
    public async Task Every_kind_of_re_open_is_reported_once_with_its_reason()
    {
        // re-opened by hand in the console
        await _workflow.CloseAsync(_verdict.Id, "alice", "patched");
        await _workflow.ReopenAsync(_verdict.Id, "alice");
        // a snooze that ran out
        var snoozed = _fx.AddVerdict(cve: "CVE-2024-2000", tier: VerdictTier.FixThisWeek);
        // re-opened with a promotion: a tier line and a state line for the same verdict
        var promoted = _fx.AddVerdict(cve: "CVE-2024-3000");
        // re-opened, but no longer worth anyone's time: not reported
        var quiet = _fx.AddVerdict(cve: "CVE-2024-4000", tier: VerdictTier.IgnoreTracked);
        await using (var db = await _fx.Factory.CreateDbContextAsync())
        {
            var now = DateTime.UtcNow;
            db.VerdictHistory.Add(new VerdictHistory { VerdictId = snoozed.Id, At = now, Actor = "system", Kind = "state", From = "Snoozed", To = "Open", Reason = "snooze expired" });
            db.VerdictHistory.Add(new VerdictHistory { VerdictId = promoted.Id, At = now, Actor = "system", Kind = "state", From = "Closed", To = "Open", Reason = "re-opened: promoted to Fix today" });
            db.VerdictHistory.Add(new VerdictHistory { VerdictId = promoted.Id, At = now, Actor = "system", Kind = "tier", From = "FixThisWeek", To = "FixToday", Reason = "public exploit published (re-opened)" });
            db.VerdictHistory.Add(new VerdictHistory { VerdictId = quiet.Id, At = now, Actor = "system", Kind = "state", From = "Closed", To = "Open", Reason = "re-opened: matches again" });
            await db.SaveChangesAsync();
        }

        var changed = (await _fx.Digest().BuildAsync()).Changed.ToDictionary(c => c.VerdictId, c => c.Reason);

        Assert.Equal(3, changed.Count);
        Assert.Equal("re-opened manually", changed[_verdict.Id]);
        Assert.Equal("re-opened: snooze expired", changed[snoozed.Id]);
        Assert.Equal("promoted from Fix this week to Fix today: public exploit published (re-opened)", changed[promoted.Id]);
    }
}
