using System.Net;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Core.Digest;

public sealed record DigestItem(Guid VerdictId, string CveId, string Sentence, VerdictTier Tier, MatchConfidence Confidence, DateTime? SlaDue, string? Reason);

/// <summary>Section 11.1: the digest email is the product. This is its content, rendered to HTML and text.</summary>
public sealed class DigestContent
{
    public string Headline { get; init; } = "";
    public string Subject { get; init; } = "";
    public List<DigestItem> FixToday { get; init; } = new();
    public List<DigestItem> FixThisWeek { get; init; } = new();
    public List<DigestItem> CheckThese { get; init; } = new();
    public List<DigestItem> Changed { get; init; } = new();
    public List<DigestItem> Overdue { get; init; } = new();
    public int NextPatchCycleCount { get; init; }
    public int DismissedSinceMonday { get; init; }
    public int DismissedTotal { get; init; }
    public string CoverageLine { get; init; } = "";
    public string? FeedWarning { get; init; }
    public DateTime GeneratedAt { get; init; }
    public string Html { get; init; } = "";
    public string Text { get; init; } = "";
    public List<long> HistoryIdsIncluded { get; init; } = new();
}

public sealed class DigestService
{
    public const string EpssAttribution = "Exploit probability scores are EPSS, provided by FIRST (https://www.first.org/epss). Exploitation status uses the CISA Known Exploited Vulnerabilities catalogue. CVE data from the CVE Program (CVE is a registered trademark of The MITRE Corporation).";

    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly SettingsService _settings;
    private readonly EmailService _email;
    private readonly ILogger<DigestService> _log;

    public DigestService(IDbContextFactory<VvDbContext> factory, SettingsService settings, EmailService email, ILogger<DigestService> log)
    {
        _factory = factory; _settings = settings; _email = email; _log = log;
    }

    // ------------------------------------------------------------------ build

    public async Task<DigestContent> BuildAsync(CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var s = await _settings.LoadAsync(ct);
        var now = DateTime.UtcNow;
        var tz = s.ResolveTimeZone();
        var localNow = TimeZoneInfo.ConvertTimeFromUtc(now, tz);
        var monday = localNow.Date.AddDays(-(((int)localNow.DayOfWeek + 6) % 7));
        var mondayUtc = TimeZoneInfo.ConvertTimeToUtc(DateTime.SpecifyKind(monday, DateTimeKind.Unspecified), tz);

        var open = await db.Verdicts.AsNoTracking().Include(v => v.WatchlistEntry)
            .Where(v => v.State == VerdictState.Open && v.Tier >= VerdictTier.NextPatchCycle).ToListAsync(ct);

        DigestItem Item(Verdict v, string? reason = null) => new(v.Id, v.CveId, v.Sentence, v.Tier, v.Confidence, v.SlaDue, reason);

        var fixToday = open.Where(v => v.Tier == VerdictTier.FixToday && v.Confidence != MatchConfidence.Possible).OrderBy(v => v.SlaDue).Select(v => Item(v)).ToList();
        var fixWeek = open.Where(v => v.Tier == VerdictTier.FixThisWeek && v.Confidence != MatchConfidence.Possible).OrderBy(v => v.SlaDue).Select(v => Item(v)).ToList();
        var check = open.Where(v => v.Tier >= VerdictTier.FixThisWeek && v.Confidence == MatchConfidence.Possible).OrderByDescending(v => v.Tier).Select(v => Item(v)).ToList();
        var overdue = open.Where(v => v.IsOverdue(now)).OrderBy(v => v.SlaDue).Select(v => Item(v, "due " + v.SlaDue!.Value.ToString("d MMM"))).ToList();
        var nextCycle = open.Count(v => v.Tier == VerdictTier.NextPatchCycle);

        var dismissedSinceMonday = await db.Verdicts.CountAsync(v => v.CreatedAt >= mondayUtc && (v.Tier <= VerdictTier.IgnoreTracked || v.State == VerdictState.Suppressed), ct);
        var dismissedTotal = await db.Verdicts.CountAsync(v => v.Tier <= VerdictTier.IgnoreTracked || v.State == VerdictState.Suppressed, ct);

        // changed since last digest: undigested tier changes that touch an actionable tier, and closures
        var history = await db.VerdictHistory.AsNoTracking().Where(h => !h.Digested).OrderByDescending(h => h.At).Take(200).ToListAsync(ct);
        var histVerdictIds = history.Select(h => h.VerdictId).Distinct().ToList();
        var histVerdicts = await db.Verdicts.AsNoTracking().Where(v => histVerdictIds.Contains(v.Id)).ToDictionaryAsync(v => v.Id, ct);
        var changed = new List<DigestItem>();
        var includedIds = new List<long>();
        foreach (var h in history)
        {
            if (!histVerdicts.TryGetValue(h.VerdictId, out var v)) continue;
            includedIds.Add(h.Id);
            if (h.Kind == "tier")
            {
                var from = Enum.TryParse<VerdictTier>(h.From, out var f) ? f : VerdictTier.NotAffected;
                var to = Enum.TryParse<VerdictTier>(h.To, out var t) ? t : VerdictTier.NotAffected;
                if (from < VerdictTier.NextPatchCycle && to < VerdictTier.NextPatchCycle) continue;
                var dir = to > from ? "promoted" : "demoted";
                changed.Add(Item(v, dir + " from " + from.Plain() + " to " + to.Plain() + ": " + h.Reason));
            }
            else if (h.Kind == "state" && h.To == "Closed")
                changed.Add(Item(v, "closed: " + h.Reason));
        }
        changed = changed.DistinctBy(c => c.VerdictId).Take(25).ToList();

        // coverage line and feed health
        var feeds = await db.FeedStatuses.AsNoTracking().ToListAsync(ct);
        var entries = await db.Watchlist.CountAsync(w => w.Enabled, ct);
        var feedsAsOf = feeds.Where(f => f.LastSuccess.HasValue).Select(f => f.LastSuccess!.Value).DefaultIfEmpty().Min();
        var stale = feeds.Where(f => f.LastSuccess is null || now - f.LastSuccess.Value > TimeSpan.FromHours(24)).Select(f => f.DisplayName).ToList();
        var coverage = "Watching " + entries + " product" + (entries == 1 ? "" : "s") + " on the watchlist. Feeds current as of " + (feedsAsOf == default ? "never" : TimeZoneInfo.ConvertTimeFromUtc(feedsAsOf, tz).ToString("d MMM HH:mm")) + ".";
        var warning = stale.Count > 0 ? "Feeds not updated in the last 24 hours: " + string.Join(", ", stale) + "." : null;

        var headline = fixToday.Count + " to fix today, " + fixWeek.Count + " this week. " + dismissedSinceMonday + " CVE" + (dismissedSinceMonday == 1 ? "" : "s") + " since Monday you did not need to read.";
        var subject = "VulnVerdict" + (string.IsNullOrWhiteSpace(s.OrganisationName) ? "" : " for " + s.OrganisationName) + ": " + headline;

        var content = new DigestContent
        {
            Headline = headline, Subject = subject, FixToday = fixToday, FixThisWeek = fixWeek, CheckThese = check, Changed = changed, Overdue = overdue,
            NextPatchCycleCount = nextCycle, DismissedSinceMonday = dismissedSinceMonday, DismissedTotal = dismissedTotal,
            CoverageLine = coverage, FeedWarning = warning, GeneratedAt = now, HistoryIdsIncluded = includedIds
        };
        var html = RenderHtml(content, s.BaseUrl, localNow);
        var text = RenderText(content, s.BaseUrl, localNow);
        return new DigestContent
        {
            Headline = content.Headline, Subject = content.Subject, FixToday = fixToday, FixThisWeek = fixWeek, CheckThese = check, Changed = changed, Overdue = overdue,
            NextPatchCycleCount = nextCycle, DismissedSinceMonday = dismissedSinceMonday, DismissedTotal = dismissedTotal,
            CoverageLine = coverage, FeedWarning = warning, GeneratedAt = now, HistoryIdsIncluded = includedIds, Html = html, Text = text
        };
    }

    // ------------------------------------------------------------------ send

    /// <summary>Build and send the daily digest. Stores the run whether or not the send succeeds.</summary>
    public async Task<DigestRun> SendDigestAsync(DigestKind kind, string? overrideRecipients = null, CancellationToken ct = default)
    {
        var s = await _settings.LoadAsync(ct);
        var content = await BuildAsync(ct);
        var recipients = (overrideRecipients is null ? s.Recipients : overrideRecipients.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)).ToList();
        var run = new DigestRun
        {
            Id = Guid.NewGuid(), Kind = kind, GeneratedAt = content.GeneratedAt, Recipients = string.Join(", ", recipients), Subject = content.Subject,
            FixToday = content.FixToday.Count, FixThisWeek = content.FixThisWeek.Count, NextPatchCycle = content.NextPatchCycleCount, Dismissed = content.DismissedSinceMonday,
            Html = content.Html, Text = content.Text
        };
        try
        {
            if (recipients.Count == 0) throw new InvalidOperationException("No digest recipients configured");
            await _email.SendAsync(recipients, content.Subject, content.Html, content.Text, ct);
            run.SentAt = DateTime.UtcNow;
        }
        catch (Exception ex)
        {
            run.Error = ex.Message.Length > 2000 ? ex.Message[..2000] : ex.Message;
            _log.LogWarning(ex, "Digest not sent");
        }

        await using var db = await _factory.CreateDbContextAsync(ct);
        db.DigestRuns.Add(run);
        if (run.SentAt is not null)
        {
            var ids = content.HistoryIdsIncluded;
            if (ids.Count > 0) await db.VerdictHistory.Where(h => ids.Contains(h.Id)).ExecuteUpdateAsync(u => u.SetProperty(h => h.Digested, true), ct);
            var now = DateTime.UtcNow;
            var mentioned = content.FixToday.Concat(content.FixThisWeek).Concat(content.CheckThese).Select(i => i.VerdictId).ToList();
            if (mentioned.Count > 0) await db.Verdicts.Where(v => mentioned.Contains(v.Id) && v.FirstDigestAt == null).ExecuteUpdateAsync(u => u.SetProperty(v => v.FirstDigestAt, now), ct);
            if (kind == DigestKind.Daily) await _settings.SetStateAsync(SettingsService.Keys.LastDailyDigest, now.ToString("O"), ct);
        }
        await db.SaveChangesAsync(ct);
        return run;
    }

    /// <summary>Section 6.4: Fix today is always emailed immediately as well. One email per batch of new items.</summary>
    public async Task<int> SendImmediateAsync(CancellationToken ct = default)
    {
        var s = await _settings.LoadAsync(ct);
        if (!s.SmtpConfigured || !s.Recipients.Any()) return 0;
        await using var db = await _factory.CreateDbContextAsync(ct);
        var pending = await db.Verdicts.Where(v => v.State == VerdictState.Open && v.Tier == VerdictTier.FixToday && v.Confidence != MatchConfidence.Possible && v.ImmediateEmailSentAt == null).ToListAsync(ct);
        if (pending.Count == 0) return 0;
        var tz = s.ResolveTimeZone();
        var items = pending.Select(v => new DigestItem(v.Id, v.CveId, v.Sentence, v.Tier, v.Confidence, v.SlaDue, v.TierChangeReason)).ToList();
        var subject = "VulnVerdict: " + pending.Count + " to fix today";
        var sb = new StringBuilder();
        sb.Append("<div style=\"font-family:Segoe UI,Helvetica,Arial,sans-serif;font-size:15px;color:#1c1c1c;max-width:720px\">");
        sb.Append("<p style=\"font-size:17px;font-weight:600\">" + pending.Count + " new item" + (pending.Count == 1 ? "" : "s") + " to fix today</p>");
        AppendItems(sb, items, s.BaseUrl, "#b3261e");
        sb.Append("<p style=\"color:#666;font-size:12px\">" + WebUtility.HtmlEncode(EpssAttribution) + "</p></div>");
        var text = new StringBuilder("FIX TODAY\n\n");
        foreach (var i in items) text.AppendLine("- " + i.Sentence + "\n  " + Link(s.BaseUrl, i.VerdictId) + "\n");
        try
        {
            await _email.SendAsync(s.Recipients, subject, sb.ToString(), text.ToString(), ct);
        }
        catch (Exception ex) { _log.LogWarning(ex, "Immediate Fix-today email not sent"); return 0; }
        var now = DateTime.UtcNow;
        foreach (var v in pending) v.ImmediateEmailSentAt = now;
        await db.SaveChangesAsync(ct);
        return pending.Count;
    }

    /// <summary>Section 11.3: one email per Fix today / Fix this week verdict to the helpdesk intake address with a stable correlation key.</summary>
    public async Task<int> SendTicketsAsync(CancellationToken ct = default)
    {
        var s = await _settings.LoadAsync(ct);
        if (!s.TicketsEnabled || !s.SmtpConfigured || string.IsNullOrWhiteSpace(s.HelpdeskIntakeAddress)) return 0;
        await using var db = await _factory.CreateDbContextAsync(ct);
        var pending = await db.Verdicts.Include(v => v.WatchlistEntry)
            .Where(v => v.State == VerdictState.Open && v.Tier >= VerdictTier.FixThisWeek && v.Confidence != MatchConfidence.Possible && v.TicketSentAt == null)
            .Take(50).ToListAsync(ct);
        int sent = 0;
        foreach (var v in pending)
        {
            var key = "VV:" + v.CveId + ":" + v.WatchlistEntryId.ToString("N")[..8];
            var subject = "[" + key + "] " + v.Tier.Plain() + ": " + v.CveId + " on " + (v.WatchlistEntry?.DisplayName ?? "watchlist item");
            var html = "<div style=\"font-family:Segoe UI,Helvetica,Arial,sans-serif;font-size:15px\"><p>" + WebUtility.HtmlEncode(v.Sentence) + "</p>"
                       + "<p>Verdict: <b>" + v.Tier.Plain() + "</b>" + (v.SlaDue.HasValue ? ", due " + v.SlaDue.Value.ToString("d MMM yyyy") : "") + "</p>"
                       + "<p><a href=\"" + Link(s.BaseUrl, v.Id) + "\">Details and evidence</a></p>"
                       + "<p style=\"color:#666;font-size:12px\">Correlation key " + key + ". Raised automatically by VulnVerdict.</p></div>";
            var text = v.Sentence + "\n\nVerdict: " + v.Tier.Plain() + (v.SlaDue.HasValue ? ", due " + v.SlaDue.Value.ToString("d MMM yyyy") : "") + "\n" + Link(s.BaseUrl, v.Id) + "\n\nCorrelation key " + key;
            try
            {
                await _email.SendAsync(new[] { s.HelpdeskIntakeAddress }, subject, html, text, ct, new[] { ("X-VulnVerdict-Key", key) });
            }
            catch (Exception ex) { _log.LogWarning(ex, "Ticket email not sent for {Cve}", v.CveId); break; }
            v.TicketSentAt = DateTime.UtcNow;
            db.Tickets.Add(new Ticket { Id = Guid.NewGuid(), VerdictId = v.Id, Channel = "email", CorrelationKey = key, ExternalRef = s.HelpdeskIntakeAddress, SentAt = DateTime.UtcNow, LastStatus = "sent" });
            sent++;
        }
        await db.SaveChangesAsync(ct);
        return sent;
    }

    // ------------------------------------------------------------------ rendering

    public static string Link(string baseUrl, Guid verdictId) => (string.IsNullOrWhiteSpace(baseUrl) ? "" : baseUrl.TrimEnd('/')) + "/verdicts/" + verdictId;

    private static void AppendItems(StringBuilder sb, List<DigestItem> items, string baseUrl, string colour)
    {
        sb.Append("<ul style=\"padding-left:18px;margin:6px 0 16px\">");
        foreach (var i in items)
        {
            sb.Append("<li style=\"margin:0 0 10px\"><span style=\"display:inline-block;width:8px;height:8px;border-radius:50%;background:" + colour + ";margin-right:8px\"></span>");
            sb.Append(WebUtility.HtmlEncode(i.Sentence));
            if (i.Reason is not null) sb.Append(" <i style=\"color:#555\">(" + WebUtility.HtmlEncode(i.Reason) + ")</i>");
            sb.Append(" <a href=\"" + Link(baseUrl, i.VerdictId) + "\" style=\"color:#1a4fbf\">Details</a> &middot; <a href=\"" + Link(baseUrl, i.VerdictId) + "?action=done\" style=\"color:#1a4fbf\">Done</a></li>");
        }
        sb.Append("</ul>");
    }

    public static string RenderHtml(DigestContent c, string baseUrl, DateTime localNow)
    {
        var sb = new StringBuilder();
        sb.Append("<!doctype html><html><body style=\"margin:0;padding:16px;background:#f6f6f4\"><div style=\"font-family:Segoe UI,Helvetica,Arial,sans-serif;font-size:15px;color:#1c1c1c;max-width:720px;margin:0 auto;background:#fff;padding:24px;border-radius:8px\">");
        sb.Append("<div style=\"font-weight:700;font-size:14px;letter-spacing:.04em;color:#444;margin-bottom:4px\">VULNVERDICT</div>");
        sb.Append("<div style=\"color:#666;font-size:12px;margin-bottom:16px\">" + localNow.ToString("dddd d MMMM yyyy, HH:mm") + "</div>");
        sb.Append("<p style=\"font-size:20px;font-weight:600;margin:0 0 20px\">" + WebUtility.HtmlEncode(c.Headline) + "</p>");

        void Section(string title, List<DigestItem> items, string colour, string emptyText)
        {
            sb.Append("<h3 style=\"font-size:15px;margin:18px 0 4px;color:" + colour + "\">" + title + "</h3>");
            if (items.Count == 0) sb.Append("<p style=\"color:#666;margin:4px 0 12px\">" + emptyText + "</p>");
            else AppendItems(sb, items, baseUrl, colour);
        }
        Section("Fix today", c.FixToday, "#b3261e", "Nothing.");
        Section("Fix this week", c.FixThisWeek, "#b26a00", "Nothing.");
        if (c.CheckThese.Count > 0) Section("Check these", c.CheckThese, "#5b5b5b", "");
        if (c.Changed.Count > 0) Section("Changed since last digest", c.Changed, "#1a4fbf", "");
        if (c.Overdue.Count > 0) Section("Overdue", c.Overdue, "#b3261e", "");
        sb.Append("<h3 style=\"font-size:15px;margin:18px 0 4px;color:#444\">Next patch cycle</h3><p style=\"margin:4px 0 12px\">" + c.NextPatchCycleCount + " item" + (c.NextPatchCycleCount == 1 ? "" : "s") + ". <a href=\"" + (string.IsNullOrWhiteSpace(baseUrl) ? "" : baseUrl.TrimEnd('/')) + "/verdicts?tier=NextPatchCycle\" style=\"color:#1a4fbf\">View list</a></p>");
        sb.Append("<hr style=\"border:0;border-top:1px solid #e5e5e5;margin:20px 0\">");
        sb.Append("<p style=\"color:#444;font-size:13px\">" + WebUtility.HtmlEncode(c.CoverageLine) + " " + c.DismissedTotal + " CVEs dismissed in total as not affected or not worth your time.</p>");
        if (c.FeedWarning is not null) sb.Append("<p style=\"color:#b3261e;font-size:13px\">" + WebUtility.HtmlEncode(c.FeedWarning) + "</p>");
        sb.Append("<p style=\"color:#5c6470;font-size:12px;margin-top:14px\"><b style=\"color:#1E222A\"><span style=\"color:#FF9F0A\">VULN</span>VERDICT</b> &middot; Cut the noise. Know your risk.</p>");
        sb.Append("<p style=\"color:#888;font-size:11px\">" + WebUtility.HtmlEncode(EpssAttribution) + "</p>");
        sb.Append("</div></body></html>");
        return sb.ToString();
    }

    public static string RenderText(DigestContent c, string baseUrl, DateTime localNow)
    {
        var sb = new StringBuilder();
        sb.AppendLine("VULNVERDICT - " + localNow.ToString("dddd d MMMM yyyy, HH:mm"));
        sb.AppendLine();
        sb.AppendLine(c.Headline);
        sb.AppendLine();
        void Section(string title, List<DigestItem> items, string emptyText)
        {
            sb.AppendLine(title.ToUpperInvariant());
            if (items.Count == 0) sb.AppendLine("  " + emptyText);
            foreach (var i in items)
            {
                sb.AppendLine("  - " + i.Sentence + (i.Reason is null ? "" : " (" + i.Reason + ")"));
                sb.AppendLine("    " + Link(baseUrl, i.VerdictId));
            }
            sb.AppendLine();
        }
        Section("Fix today", c.FixToday, "Nothing.");
        Section("Fix this week", c.FixThisWeek, "Nothing.");
        if (c.CheckThese.Count > 0) Section("Check these", c.CheckThese, "");
        if (c.Changed.Count > 0) Section("Changed since last digest", c.Changed, "");
        if (c.Overdue.Count > 0) Section("Overdue", c.Overdue, "");
        sb.AppendLine("NEXT PATCH CYCLE: " + c.NextPatchCycleCount + " items. " + (string.IsNullOrWhiteSpace(baseUrl) ? "" : baseUrl.TrimEnd('/')) + "/verdicts?tier=NextPatchCycle");
        sb.AppendLine();
        sb.AppendLine(c.CoverageLine + " " + c.DismissedTotal + " CVEs dismissed in total.");
        if (c.FeedWarning is not null) sb.AppendLine(c.FeedWarning);
        sb.AppendLine();
        sb.AppendLine(EpssAttribution);
        return sb.ToString();
    }
}
