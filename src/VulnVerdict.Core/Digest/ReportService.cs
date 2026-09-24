using System.Net;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Core.Digest;

/// <summary>Section 11.2 item 8: weekly management summary (new, affecting us, actioned, overdue, dismissed) as HTML and CSV.</summary>
public sealed class ReportService
{
    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly SettingsService _settings;
    private readonly EmailService _email;
    private readonly ILogger<ReportService> _log;

    public ReportService(IDbContextFactory<VvDbContext> factory, SettingsService settings, EmailService email, ILogger<ReportService> log)
    {
        _factory = factory; _settings = settings; _email = email; _log = log;
    }

    public sealed record Row(string CveId, string Subject, string Verdict, string State, string? Owner, DateTime? SlaDue, DateTime CreatedAt, DateTime? ClosedAt, string Sentence, Guid Id);

    public sealed class WeeklyReport
    {
        public DateTime From { get; init; }
        public DateTime To { get; init; }
        public string Organisation { get; init; } = "";
        public int NewCves { get; init; }
        public int NewMatched { get; init; }
        public int NewActionable { get; init; }
        public int Actioned { get; init; }
        public int OpenActionable { get; init; }
        public int Overdue { get; init; }
        public int Dismissed { get; init; }
        public int Assets { get; init; }
        public int Products { get; init; }
        public List<Row> ActionedRows { get; init; } = new();
        public List<Row> OverdueRows { get; init; } = new();
        public List<Row> OpenRows { get; init; } = new();
        public List<Row> NewActionableRows { get; init; } = new();
        public string Html { get; init; } = "";
        public string Csv { get; init; } = "";
    }

    public async Task<WeeklyReport> BuildAsync(DateTime? toUtc = null, CancellationToken ct = default)
    {
        var s = await _settings.LoadAsync(ct);
        var tz = s.ResolveTimeZone();
        var to = toUtc ?? DateTime.UtcNow;
        var from = to.AddDays(-7);
        await using var db = await _factory.CreateDbContextAsync(ct);

        var newCves = await db.Cves.CountAsync(c => c.Published >= from && c.Published < to, ct);
        var created = await db.Verdicts.AsNoTracking().Where(v => v.CreatedAt >= from && v.CreatedAt < to).ToListAsync(ct);
        var open = await db.Verdicts.AsNoTracking().Where(v => v.State == VerdictState.Open && v.Tier >= VerdictTier.NextPatchCycle).ToListAsync(ct);
        var closedHist = await db.VerdictHistory.AsNoTracking().Where(h => h.Kind == "state" && h.To == "Closed" && h.At >= from && h.At < to).ToListAsync(ct);
        var closedIds = closedHist.Select(h => h.VerdictId).Distinct().ToList();
        var closed = await db.Verdicts.AsNoTracking().Where(v => closedIds.Contains(v.Id)).ToListAsync(ct);
        var assets = await db.Assets.CountAsync(a => !a.Archived, ct);
        var products = await db.Watchlist.CountAsync(w => w.Enabled, ct);

        Row R(Verdict v) => new(v.CveId, v.Subject.Length > 0 ? v.Subject : (v.WatchlistEntryId?.ToString() ?? ""), v.Tier.Plain(), v.State.Plain(), v.StateOwner, v.SlaDue, v.CreatedAt, closedHist.FirstOrDefault(h => h.VerdictId == v.Id)?.At, v.Sentence, v.Id);

        var report = new WeeklyReport
        {
            From = from, To = to, Organisation = s.OrganisationName,
            NewCves = newCves,
            NewMatched = created.Count,
            NewActionable = created.Count(v => v.Tier >= VerdictTier.NextPatchCycle),
            Actioned = closed.Count,
            OpenActionable = open.Count,
            Overdue = open.Count(v => v.IsOverdue(to)),
            Dismissed = created.Count(v => v.Tier <= VerdictTier.IgnoreTracked),
            Assets = assets, Products = products,
            ActionedRows = closed.OrderByDescending(v => v.Tier).Select(R).ToList(),
            OverdueRows = open.Where(v => v.IsOverdue(to)).OrderBy(v => v.SlaDue).Select(R).ToList(),
            OpenRows = open.Where(v => v.Tier >= VerdictTier.FixThisWeek).OrderByDescending(v => v.Tier).ThenBy(v => v.SlaDue).Select(R).ToList(),
            NewActionableRows = created.Where(v => v.Tier >= VerdictTier.FixThisWeek).OrderByDescending(v => v.Tier).Select(R).ToList()
        };
        var html = RenderHtml(report, tz);
        var csv = RenderCsv(report);
        return new WeeklyReport
        {
            From = report.From, To = report.To, Organisation = report.Organisation, NewCves = report.NewCves, NewMatched = report.NewMatched, NewActionable = report.NewActionable,
            Actioned = report.Actioned, OpenActionable = report.OpenActionable, Overdue = report.Overdue, Dismissed = report.Dismissed, Assets = report.Assets, Products = report.Products,
            ActionedRows = report.ActionedRows, OverdueRows = report.OverdueRows, OpenRows = report.OpenRows, NewActionableRows = report.NewActionableRows, Html = html, Csv = csv
        };
    }

    /// <summary>Email the weekly report on the configured day (once per week).</summary>
    public async Task<bool> SendIfDueAsync(CancellationToken ct = default)
    {
        var s = await _settings.LoadAsync(ct);
        if (!s.MailConfigured || string.IsNullOrWhiteSpace(s.ReportRecipients)) return false;
        var tz = s.ResolveTimeZone();
        var localNow = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, tz);
        if (!Enum.TryParse<DayOfWeek>(s.ReportDay, true, out var day)) day = DayOfWeek.Monday;
        if (localNow.DayOfWeek != day || localNow.Hour < 8) return false;
        var last = await _settings.GetStateAsync("state:report:last", ct);
        if (last is not null && DateTime.TryParse(last, null, System.Globalization.DateTimeStyles.RoundtripKind, out var d) && DateTime.UtcNow - d < TimeSpan.FromDays(6)) return false;
        var r = await BuildAsync(null, ct);
        var recipients = s.ReportRecipients.Split(new[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        try
        {
            await _email.SendAsync(recipients, "VulnVerdict weekly report" + (r.Organisation == "" ? "" : " for " + r.Organisation) + ": " + r.NewActionable + " new to act on, " + r.Actioned + " done, " + r.Overdue + " overdue", r.Html, RenderText(r), ct);
            await _settings.SetStateAsync("state:report:last", DateTime.UtcNow.ToString("O"), ct);
            return true;
        }
        catch (Exception ex) { _log.LogWarning(ex, "Weekly report not sent"); return false; }
    }

    public static string RenderHtml(WeeklyReport r, TimeZoneInfo tz)
    {
        string L(DateTime? d, string f = "d MMM") => d is null ? "-" : TimeZoneInfo.ConvertTimeFromUtc(d.Value, tz).ToString(f);
        var sb = new StringBuilder();
        sb.Append("<!doctype html><html><head><meta charset=\"utf-8\"><title>VulnVerdict weekly report</title><style>body{font-family:Inter,Segoe UI,Helvetica,Arial,sans-serif;color:#1E222A;margin:24px;font-size:14px}h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:22px 0 6px}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:6px 8px;border-top:1px solid #e1e5eb;vertical-align:top}th{font-size:11px;text-transform:uppercase;color:#5c6470}.stats{display:flex;gap:12px;flex-wrap:wrap;margin:14px 0}.stat{border:1px solid #e1e5eb;border-radius:8px;padding:8px 14px;min-width:120px}.stat b{display:block;font-size:22px}.muted{color:#5c6470}@media print{body{margin:0}}</style></head><body>");
        sb.Append("<div style=\"font-weight:700;letter-spacing:.04em;color:#5c6470;font-size:12px\"><span style=\"color:#FF9F0A\">VULN</span>VERDICT</div>");
        sb.Append("<h1>Weekly report" + (r.Organisation == "" ? "" : " for " + WebUtility.HtmlEncode(r.Organisation)) + "</h1><div class=\"muted\">" + L(r.From, "d MMM yyyy") + " to " + L(r.To, "d MMM yyyy") + ". Watching " + r.Assets + " assets and " + r.Products + " watchlist products.</div>");
        sb.Append("<div class=\"stats\">");
        foreach (var (label, val) in new[] { ("new CVEs published worldwide", r.NewCves), ("matched something we run", r.NewMatched), ("needed action", r.NewActionable), ("done this week", r.Actioned), ("open and needing action", r.OpenActionable), ("overdue", r.Overdue), ("dismissed as noise", r.Dismissed) })
            sb.Append("<div class=\"stat\"><b>" + val + "</b><span class=\"muted\">" + label + "</span></div>");
        sb.Append("</div>");
        sb.Append("<p>Are we affected by what was on the news? Of the " + r.NewCves.ToString("N0") + " vulnerabilities published this week, " + r.NewMatched + " concerned software we run and " + r.NewActionable + " needed action. " + r.Actioned + " item" + (r.Actioned == 1 ? " was" : "s were") + " fixed or closed. " + (r.Overdue == 0 ? "Nothing is overdue." : r.Overdue + " item" + (r.Overdue == 1 ? " is" : "s are") + " past the agreed fix window.") + "</p>");
        void Table(string title, List<Row> rows, bool showClosed)
        {
            sb.Append("<h2>" + title + " (" + rows.Count + ")</h2>");
            if (rows.Count == 0) { sb.Append("<p class=\"muted\">None.</p>"); return; }
            sb.Append("<table><thead><tr><th>Verdict</th><th>CVE</th><th>What</th><th>" + (showClosed ? "Closed" : "Due") + "</th><th>Owner</th></tr></thead><tbody>");
            foreach (var x in rows.Take(60))
                sb.Append("<tr><td>" + x.Verdict + "</td><td>" + x.CveId + "</td><td>" + WebUtility.HtmlEncode(x.Sentence) + "</td><td>" + (showClosed ? L(x.ClosedAt) : L(x.SlaDue)) + "</td><td>" + WebUtility.HtmlEncode(x.Owner ?? "") + "</td></tr>");
            sb.Append("</tbody></table>");
        }
        Table("Overdue", r.OverdueRows, false);
        Table("Open: fix today and fix this week", r.OpenRows, false);
        Table("Done this week", r.ActionedRows, true);
        Table("New this week that needed action", r.NewActionableRows, false);
        sb.Append("<p class=\"muted\" style=\"font-size:11px;margin-top:24px\">" + WebUtility.HtmlEncode(DigestService.Disclaimer) + "</p><p class=\"muted\" style=\"font-size:11px\">" + WebUtility.HtmlEncode(DigestService.EpssAttribution) + "</p></body></html>");
        return sb.ToString();
    }

    public static string RenderText(WeeklyReport r)
    {
        var sb = new StringBuilder();
        sb.AppendLine("VULNVERDICT WEEKLY REPORT " + r.From.ToString("d MMM") + " to " + r.To.ToString("d MMM yyyy"));
        sb.AppendLine("New CVEs published: " + r.NewCves + "; matched something we run: " + r.NewMatched + "; needed action: " + r.NewActionable + "; done: " + r.Actioned + "; open: " + r.OpenActionable + "; overdue: " + r.Overdue + "; dismissed: " + r.Dismissed);
        foreach (var x in r.OverdueRows) sb.AppendLine("OVERDUE " + x.CveId + " " + x.Sentence);
        foreach (var x in r.OpenRows) sb.AppendLine("OPEN " + x.Verdict + " " + x.CveId + " " + x.Sentence);
        foreach (var x in r.ActionedRows) sb.AppendLine("DONE " + x.CveId + " " + x.Sentence);
        sb.AppendLine();
        sb.AppendLine(DigestService.Disclaimer);
        return sb.ToString();
    }

    public static string RenderCsv(WeeklyReport r)
    {
        static string Q(string? s) => "\"" + (s ?? "").Replace("\"", "\"\"") + "\"";
        var sb = new StringBuilder();
        sb.AppendLine("section,verdict,cve,subject,state,owner,due,created,closed,sentence");
        foreach (var (section, rows) in new[] { ("overdue", r.OverdueRows), ("open", r.OpenRows), ("done", r.ActionedRows), ("new", r.NewActionableRows) })
            foreach (var x in rows)
                sb.AppendLine(string.Join(",", section, Q(x.Verdict), x.CveId, Q(x.Subject), Q(x.State), Q(x.Owner), x.SlaDue?.ToString("yyyy-MM-dd") ?? "", x.CreatedAt.ToString("yyyy-MM-dd"), x.ClosedAt?.ToString("yyyy-MM-dd") ?? "", Q(x.Sentence)));
        return sb.ToString();
    }
}
