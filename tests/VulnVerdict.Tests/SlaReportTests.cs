using VulnVerdict.Core.Data;
using VulnVerdict.Core.Digest;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

/// <summary>SLA trends: percentiles, weeks in local time, replaying a verdict's history, and the report built from them.</summary>
public class SlaReportTests : IDisposable
{
    private readonly OpsTestHost _host = new();
    private static readonly TimeZoneInfo London = TimeZoneInfo.FindSystemTimeZoneById("Europe/London");
    private static readonly SlaDays Sla = new(2, 7, 30);

    public void Dispose() => _host.Dispose();

    private static DateTime Utc(string s) => DateTime.Parse(s, null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal);

    // ---- percentiles

    [Fact]
    public void Median_and_90th_percentile_interpolate()
    {
        Assert.Null(SlaMath.Median(Array.Empty<double>()));
        Assert.Equal(7, SlaMath.Median(new[] { 7.0 }));
        Assert.Equal(7, SlaMath.Percentile(new[] { 7.0 }, 0.9));
        Assert.Equal(2, SlaMath.Median(new[] { 3.0, 1, 2 }));
        Assert.Equal(2.5, SlaMath.Median(new[] { 4.0, 1, 3, 2 }));
        Assert.Equal(9.1, SlaMath.Percentile(Enumerable.Range(1, 10).Select(i => (double)i), 0.9)!.Value, 10);
        Assert.Equal(1.9, SlaMath.Percentile(new[] { 1.0, 2 }, 0.9)!.Value, 10);
        // one slow fix among quick ones moves the 90th percentile, not the median
        var days = new[] { 1.0, 1, 1, 1, 1, 1, 1, 1, 1, 30 };
        Assert.Equal(1, SlaMath.Median(days));
        Assert.Equal(3.9, SlaMath.Percentile(days, 0.9)!.Value, 10);
        Assert.Equal(1, SlaMath.Percentile(days, 0));
        Assert.Equal(30, SlaMath.Percentile(days, 1));
    }

    // ---- weeks

    [Fact]
    public void Weeks_run_monday_to_monday_in_local_time()
    {
        // Friday 2 October 2026, British Summer Time: Monday 00:00 local is Sunday 23:00 UTC
        var weeks = SlaMath.Weeks(Utc("2026-10-02 09:00:00Z"), London, 3);
        Assert.Equal(new[] { "2026-W38", "2026-W39", "2026-W40" }, weeks.Select(w => w.Label));
        Assert.Equal(new DateOnly(2026, 9, 28), weeks[2].Start);
        Assert.Equal(Utc("2026-09-27 23:00:00Z"), weeks[2].StartUtc);
        Assert.Equal(Utc("2026-10-04 23:00:00Z"), weeks[2].EndUtc);
        Assert.True(weeks[2].Partial);
        Assert.False(weeks[1].Partial);
        Assert.All(weeks.Zip(weeks.Skip(1)), p => Assert.Equal(p.First.EndUtc, p.Second.StartUtc));
        // 23:30 UTC on Sunday is already Monday in London
        Assert.True(weeks[2].Contains(Utc("2026-09-27 23:30:00Z")));
        Assert.False(weeks[1].Contains(Utc("2026-09-27 23:30:00Z")));
        // on Monday itself, and a second before it
        Assert.Equal(new DateOnly(2026, 9, 28), SlaMath.Weeks(Utc("2026-09-27 23:00:00Z"), London, 1)[0].Start);
        Assert.Equal(new DateOnly(2026, 9, 21), SlaMath.Weeks(Utc("2026-09-27 22:59:59Z"), London, 1)[0].Start);
    }

    [Fact]
    public void A_week_with_a_clock_change_is_an_hour_longer_or_shorter()
    {
        // clocks go back on Sunday 25 October 2026 and forward on Sunday 29 March 2026
        var autumn = SlaMath.Weeks(Utc("2026-10-28 12:00:00Z"), London, 2);
        Assert.Equal(169, (autumn[0].EndUtc - autumn[0].StartUtc).TotalHours);
        Assert.Equal(Utc("2026-10-18 23:00:00Z"), autumn[0].StartUtc);
        Assert.Equal(Utc("2026-10-26 00:00:00Z"), autumn[0].EndUtc);
        Assert.Equal(168, (autumn[1].EndUtc - autumn[1].StartUtc).TotalHours);

        var spring = SlaMath.Weeks(Utc("2026-04-01 12:00:00Z"), London, 2);
        Assert.Equal(167, (spring[0].EndUtc - spring[0].StartUtc).TotalHours);
        Assert.Equal(Utc("2026-03-23 00:00:00Z"), spring[0].StartUtc);
        Assert.Equal(Utc("2026-03-29 23:00:00Z"), spring[0].EndUtc);
        // an event in the hour that happens twice lands in one week only
        Assert.Single(autumn, w => w.Contains(Utc("2026-10-25 00:30:00Z")));
        Assert.Single(autumn, w => w.Contains(Utc("2026-10-25 01:30:00Z")));
    }

    [Fact]
    public void Weeks_cross_the_year_boundary_by_iso_week()
    {
        // 2026 has 53 ISO weeks: 28 December 2026 to 3 January 2027 is 2026-W53, then 2027-W01
        var weeks = SlaMath.Weeks(Utc("2027-01-06 12:00:00Z"), London, 3);
        Assert.Equal(new[] { "2026-W52", "2026-W53", "2027-W01" }, weeks.Select(w => w.Label));
        Assert.Equal(new[] { new DateOnly(2026, 12, 21), new DateOnly(2026, 12, 28), new DateOnly(2027, 1, 4) }, weeks.Select(w => w.Start));
        Assert.True(weeks[1].Contains(Utc("2026-12-31 23:59:59Z")));
        Assert.True(weeks[1].Contains(Utc("2027-01-01 00:00:00Z")));
        Assert.True(weeks[1].Contains(Utc("2027-01-03 23:59:59Z")));
        Assert.True(weeks[2].Contains(Utc("2027-01-04 00:00:00Z")));
        // 1 January 2021 was in 2020-W53
        Assert.Equal("2020-W53", SlaMath.Weeks(Utc("2021-01-01 12:00:00Z"), London, 1)[0].Label);
        // a zone a day ahead of UTC: Monday there begins on Sunday UTC
        var auckland = SlaMath.Weeks(Utc("2026-12-31 12:00:00Z"), TimeZoneInfo.FindSystemTimeZoneById("Pacific/Auckland"), 1)[0];
        Assert.Equal(new DateOnly(2026, 12, 28), auckland.Start);
        Assert.Equal(Utc("2026-12-27 11:00:00Z"), auckland.StartUtc);
    }

    // ---- replaying a verdict

    private static VerdictTimeline Timeline(string created, VerdictTier tier, VerdictState state, params HistoryPoint[] history) =>
        new(Guid.NewGuid(), Utc(created), tier, state, history);

    [Fact]
    public void A_verdict_closed_inside_its_window_counts_as_within_sla()
    {
        var t = Timeline("2026-09-01 08:00:00Z", VerdictTier.FixThisWeek, VerdictState.Closed,
            new HistoryPoint(Utc("2026-09-04 08:00:00Z"), "state", "Open", "Closed", "marked done"));
        var c = Assert.Single(t.Closures(Sla));
        Assert.Equal(VerdictTier.FixThisWeek, c.Tier);
        Assert.Equal(3, c.Days);
        Assert.Equal(Utc("2026-09-08 08:00:00Z"), c.DueUtc);
        Assert.True(c.WithinSla);

        var late = Timeline("2026-09-01 08:00:00Z", VerdictTier.FixToday, VerdictState.Closed,
            new HistoryPoint(Utc("2026-09-03 08:00:01Z"), "state", "Open", "Closed", "marked done"));
        Assert.False(Assert.Single(late.Closures(Sla)).WithinSla);
        // closed on the second it was due is in time
        var onTime = Timeline("2026-09-01 08:00:00Z", VerdictTier.FixToday, VerdictState.Closed,
            new HistoryPoint(Utc("2026-09-03 08:00:00Z"), "state", "Open", "Closed", "marked done"));
        Assert.True(Assert.Single(onTime.Closures(Sla)).WithinSla);
    }

    [Fact]
    public void A_patched_verdict_is_counted_in_the_tier_it_had_before_it_closed()
    {
        // the evaluator records the tier change to Not affected and the close at the same instant
        var at = Utc("2026-09-10 12:00:00Z");
        var t = Timeline("2026-09-01 12:00:00Z", VerdictTier.NotAffected, VerdictState.Closed,
            new HistoryPoint(at, "tier", "FixThisWeek", "NotAffected", "fixed version observed: 7.2.8"),
            new HistoryPoint(at, "state", "Open", "Closed", "patched, closed: fixed version observed 7.2.8"));
        var c = Assert.Single(t.Closures(Sla));
        Assert.Equal(VerdictTier.FixThisWeek, c.Tier);
        Assert.Equal(9, c.Days);
        Assert.False(c.WithinSla);
        // it was open and Fix this week on the 5th, and overdue from the 8th
        var on5 = t.At(Utc("2026-09-05 00:00:00Z"), Sla)!.Value;
        Assert.Equal((VerdictTier.FixThisWeek, VerdictState.Open), (on5.Tier, on5.State));
        Assert.Equal(Utc("2026-09-08 12:00:00Z"), on5.Due);
        Assert.Equal(VerdictState.Closed, t.At(Utc("2026-09-11 00:00:00Z"), Sla)!.Value.State);
        Assert.Null(t.At(Utc("2026-08-31 00:00:00Z"), Sla));
    }

    [Fact]
    public void A_promotion_restarts_the_fix_window_and_a_reopening_restarts_the_clock()
    {
        var t = Timeline("2026-09-01 00:00:00Z", VerdictTier.FixToday, VerdictState.Closed,
            new HistoryPoint(Utc("2026-09-10 00:00:00Z"), "tier", "NextPatchCycle", "FixToday", "now in CISA KEV"),
            new HistoryPoint(Utc("2026-09-11 12:00:00Z"), "state", "Open", "Closed", "marked done"),
            new HistoryPoint(Utc("2026-09-20 00:00:00Z"), "state", "Closed", "Open", "re-opened: affected again"),
            new HistoryPoint(Utc("2026-09-23 00:00:00Z"), "state", "Open", "Closed", "marked done"));
        var closures = t.Closures(Sla).ToList();
        Assert.Equal(2, closures.Count);
        // first: opened on the 1st, promoted on the 10th (due the 12th), closed on the 11th
        Assert.Equal(VerdictTier.FixToday, closures[0].Tier);
        Assert.Equal(10.5, closures[0].Days);
        Assert.Equal(Utc("2026-09-12 00:00:00Z"), closures[0].DueUtc);
        Assert.True(closures[0].WithinSla);
        // second: three days from the re-opening, against a two-day window
        Assert.Equal(3, closures[1].Days);
        Assert.False(closures[1].WithinSla);
        // opened once at creation and once at the re-opening; the promotion was between two actionable tiers
        Assert.Equal(new[] { Utc("2026-09-01 00:00:00Z"), Utc("2026-09-20 00:00:00Z") }, t.Openings().OrderBy(d => d));
        Assert.Equal(VerdictTier.NextPatchCycle, t.TierAt(Utc("2026-09-05 00:00:00Z")));
    }

    [Fact]
    public void Dismissed_verdicts_and_corrections_are_not_fixes()
    {
        var ignored = Timeline("2026-09-01 00:00:00Z", VerdictTier.IgnoreTracked, VerdictState.Closed,
            new HistoryPoint(Utc("2026-09-02 00:00:00Z"), "state", "Open", "Closed", "closed: no longer reported"));
        Assert.Empty(ignored.Closures(Sla));
        Assert.Empty(ignored.Openings());

        var mismatch = Timeline("2026-09-01 00:00:00Z", VerdictTier.FixThisWeek, VerdictState.Closed,
            new HistoryPoint(Utc("2026-09-02 00:00:00Z"), "state", "Open", "Closed", "closed: " + VerdictEvaluator.NoLongerMatches));
        Assert.Empty(mismatch.Closures(Sla));

        // promoted from Ignore to Fix this week: that is when it started needing action
        var promoted = Timeline("2026-09-01 00:00:00Z", VerdictTier.FixThisWeek, VerdictState.Open,
            new HistoryPoint(Utc("2026-09-15 00:00:00Z"), "tier", "IgnoreTracked", "FixThisWeek", "public exploit published"));
        Assert.Equal(new[] { Utc("2026-09-15 00:00:00Z") }, promoted.Openings());
    }

    // ---- the report

    private async Task<(Guid Entry, Guid Asset)> SeedAsync(DateTime now)
    {
        await _host.Settings.SaveAsync(new AppSettings { TimeZone = "Europe/London", OrganisationName = "Example Ltd" }, "test");
        await using var db = _host.Db.CreateDbContext();
        var entry = new WatchlistEntry { Id = Guid.NewGuid(), Vendor = "Fortinet", Product = "FortiOS", VendorNorm = "fortinet", ProductNorm = "fortios", Version = "7.2.5", AssetName = "FW-EDGE-01", CreatedAt = now.AddDays(-90), UpdatedAt = now };
        var other = new WatchlistEntry { Id = Guid.NewGuid(), Vendor = "Veeam", Product = "Backup & Replication", VendorNorm = "veeam", ProductNorm = "backup replication", CreatedAt = now.AddDays(-90), UpdatedAt = now };
        db.Watchlist.AddRange(entry, other);
        var seen = new Asset { Id = Guid.NewGuid(), DisplayName = "SRV-01", FirstSeen = now.AddDays(-60), LastSeen = now };
        var stale = new Asset { Id = Guid.NewGuid(), DisplayName = "SRV-02", FirstSeen = now.AddDays(-60), LastSeen = now.AddDays(-20) };
        var archived = new Asset { Id = Guid.NewGuid(), DisplayName = "SRV-OLD", FirstSeen = now.AddDays(-60), LastSeen = now, Archived = true };
        db.Assets.AddRange(seen, stale, archived);
        var rmm = new Connector { Id = Guid.NewGuid(), AdapterId = "ninjaone", DisplayName = "NinjaOne", CreatedAt = now.AddDays(-60) };
        var vc = new Connector { Id = Guid.NewGuid(), AdapterId = "vcenter", DisplayName = "vCenter", CreatedAt = now.AddDays(-60) };
        db.Connectors.AddRange(rmm, vc);
        db.AssetSources.AddRange(
            new AssetSource { AssetId = seen.Id, ConnectorId = rmm.Id.ToString("N"), AdapterId = "ninjaone", ExternalId = "1", FirstSeen = now.AddDays(-60), LastSeen = now.AddHours(-3) },
            new AssetSource { AssetId = stale.Id, ConnectorId = rmm.Id.ToString("N"), AdapterId = "ninjaone", ExternalId = "2", FirstSeen = now.AddDays(-60), LastSeen = now.AddDays(-20) },
            new AssetSource { AssetId = archived.Id, ConnectorId = rmm.Id.ToString("N"), AdapterId = "ninjaone", ExternalId = "3", FirstSeen = now.AddDays(-60), LastSeen = now },
            new AssetSource { AssetId = stale.Id, ConnectorId = vc.Id.ToString("N"), AdapterId = "vcenter", ExternalId = "vm-2", FirstSeen = now.AddDays(-60), LastSeen = now.AddDays(-8) });
        for (var i = 1; i <= 9; i++) db.Cves.Add(new Cve { Id = "CVE-2026-200" + i, State = "PUBLISHED", RetrievedAt = now });
        await db.SaveChangesAsync();
        return (entry.Id, other.Id);
    }

    private async Task<Guid> AddVerdictAsync(int n, Guid entry, VerdictTier tier, VerdictState state, DateTime created, DateTime? due, params HistoryPoint[] history)
    {
        await using var db = _host.Db.CreateDbContext();
        var v = new Verdict { Id = Guid.NewGuid(), CveId = "CVE-2026-200" + n, WatchlistEntryId = entry, Subject = "subject " + n, Tier = tier, State = state, CreatedAt = created, UpdatedAt = created, LastEvaluatedAt = created, SlaDue = due };
        db.Verdicts.Add(v);
        foreach (var h in history) db.VerdictHistory.Add(new VerdictHistory { VerdictId = v.Id, At = h.At, Kind = h.Kind, From = h.From, To = h.To, Reason = h.Reason });
        await db.SaveChangesAsync();
        return v.Id;
    }

    [Fact]
    public async Task The_report_buckets_closures_by_week_and_measures_them_against_the_fix_window()
    {
        var now = Utc("2026-10-02 09:00:00Z");   // Friday of 2026-W40
        var (fortios, veeam) = await SeedAsync(now);
        // W39 (21 to 27 September): three Fix this week closures taking 2, 4 and 12 days, and one Fix today taking 1
        await AddVerdictAsync(1, fortios, VerdictTier.FixThisWeek, VerdictState.Closed, Utc("2026-09-20 10:00:00Z"), null, new HistoryPoint(Utc("2026-09-22 10:00:00Z"), "state", "Open", "Closed", "marked done"));
        await AddVerdictAsync(2, fortios, VerdictTier.FixThisWeek, VerdictState.Closed, Utc("2026-09-19 10:00:00Z"), null, new HistoryPoint(Utc("2026-09-23 10:00:00Z"), "state", "Open", "Closed", "marked done"));
        await AddVerdictAsync(3, fortios, VerdictTier.FixThisWeek, VerdictState.Closed, Utc("2026-09-12 10:00:00Z"), null, new HistoryPoint(Utc("2026-09-24 10:00:00Z"), "state", "Open", "Closed", "marked done"));
        await AddVerdictAsync(4, fortios, VerdictTier.FixToday, VerdictState.Closed, Utc("2026-09-24 10:00:00Z"), null, new HistoryPoint(Utc("2026-09-25 10:00:00Z"), "state", "Open", "Closed", "marked done"));
        // closed at 23:30 UTC on Sunday 27 September: already Monday in London, so it belongs to W40
        await AddVerdictAsync(5, veeam, VerdictTier.NextPatchCycle, VerdictState.Closed, Utc("2026-09-17 23:30:00Z"), null, new HistoryPoint(Utc("2026-09-27 23:30:00Z"), "state", "Open", "Closed", "marked done"));
        // open now: one overdue, one not; one accepted risk expiring soon, one with no expiry
        await AddVerdictAsync(6, fortios, VerdictTier.FixToday, VerdictState.Open, Utc("2026-09-29 10:00:00Z"), Utc("2026-10-01 10:00:00Z"));
        await AddVerdictAsync(7, veeam, VerdictTier.NextPatchCycle, VerdictState.Open, Utc("2026-09-30 10:00:00Z"), Utc("2026-10-30 10:00:00Z"));
        var risk = await AddVerdictAsync(8, fortios, VerdictTier.FixThisWeek, VerdictState.AcceptedRisk, Utc("2026-08-01 10:00:00Z"), null);
        await AddVerdictAsync(9, veeam, VerdictTier.FixThisWeek, VerdictState.AcceptedRisk, Utc("2026-08-01 10:00:00Z"), null);
        await using (var db = _host.Db.CreateDbContext())
        {
            var v = db.Verdicts.Single(x => x.Id == risk);
            v.AcceptedRiskExpiry = Utc("2026-10-12 00:00:00Z"); v.StateOwner = "it.manager";
            await db.SaveChangesAsync();
        }

        var svc = new SlaReportService(_host.Db, _host.Settings);
        Assert.True(await svc.WriteSnapshotIfDueAsync(now));
        Assert.False(await svc.WriteSnapshotIfDueAsync(now.AddMinutes(30)));
        var r = await svc.BuildAsync(4, now);

        Assert.Equal(new[] { "2026-W37", "2026-W38", "2026-W39", "2026-W40" }, r.Weeks.Select(w => w.Week.Label));
        var w39 = r.Weeks[2];
        Assert.Equal(4, w39.Closed);
        var week = w39.Tiers[VerdictTier.FixThisWeek];
        Assert.Equal(3, week.Closed);
        Assert.Equal(4, week.MedianDays);
        Assert.Equal(10.4, week.P90Days!.Value, 10);
        Assert.Equal(2, week.WithinSla);
        Assert.Equal(new SlaTierWeek(1, 1, 1, 1), w39.Tiers[VerdictTier.FixToday]);
        Assert.Equal(new SlaTierWeek(0, null, null, 0), w39.Tiers[VerdictTier.NextPatchCycle]);
        Assert.Equal(75, w39.WithinSlaPercent);
        // opened in W39: verdicts 1 (Sunday 20th is W38), 4 only
        Assert.Equal(1, w39.Opened);

        var w40 = r.Weeks[3];
        Assert.True(w40.Week.Partial);
        Assert.Equal(1, w40.Closed);
        Assert.Equal(10, w40.Tiers[VerdictTier.NextPatchCycle].MedianDays);
        Assert.Equal(100, w40.WithinSlaPercent);
        Assert.Equal(2, w40.Opened);
        // today's snapshot: two open, one overdue
        Assert.Equal(2, w40.OpenAtEnd);
        Assert.Equal(1, w40.OverdueAtEnd);
        Assert.False(w40.Backfilled);
        // earlier weeks were rebuilt from history: at the end of W39 only verdict 5 was open (closed half an hour into W40)
        Assert.True(w39.Backfilled);
        Assert.Equal((1, 0), (w39.OpenAtEnd, w39.OverdueAtEnd));
        // at the end of W38 (Sunday 20 September): 1, 2, 3 and 5 open; only 3 (opened the 12th, due the 19th) overdue
        Assert.Equal(4, r.Weeks[1].OpenAtEnd);
        Assert.Equal(1, r.Weeks[1].OverdueAtEnd);
        Assert.Null(r.Weeks[1].WithinSlaPercent);

        Assert.Equal((2, 1), (r.OpenNow, r.OverdueNow));
        Assert.Equal((2, 1), (r.AcceptedRisk, r.AcceptedRiskWithoutExpiry));
        var expiry = Assert.Single(r.UpcomingExpiries);
        Assert.Equal(("CVE-2026-2008", "it.manager"), (expiry.CveId, expiry.Owner));

        // coverage: two live assets, one seen in the last 7 days; the archived one does not count
        Assert.Equal((2, 1), (r.Assets, r.AssetsSeen));
        Assert.Equal(50, r.CoveragePercent);
        Assert.Equal(new[] { new ConnectorCoverage("NinjaOne", 1, 50), new ConnectorCoverage("vCenter", 0, 0) }, r.Coverage);

        Assert.Equal(new[] { new ProductCount("Fortinet FortiOS", 1, 1), new ProductCount("Veeam Backup & Replication", 1, 0) }, r.TopProducts);
    }

    [Fact]
    public async Task The_csv_owner_view_and_weekly_report_carry_the_numbers()
    {
        var now = Utc("2026-10-02 09:00:00Z");
        var (fortios, _) = await SeedAsync(now);
        await AddVerdictAsync(1, fortios, VerdictTier.FixThisWeek, VerdictState.Closed, Utc("2026-09-20 10:00:00Z"), null, new HistoryPoint(Utc("2026-09-22 10:00:00Z"), "state", "Open", "Closed", "marked done"));
        await AddVerdictAsync(6, fortios, VerdictTier.FixToday, VerdictState.Open, Utc("2026-09-29 10:00:00Z"), Utc("2026-10-01 10:00:00Z"));
        var svc = new SlaReportService(_host.Db, _host.Settings);
        await svc.WriteSnapshotIfDueAsync(now);
        var r = await svc.BuildAsync(4, now);

        var csv = SlaReportRenderer.Csv(r).Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => l.TrimEnd('\r')).ToList();
        Assert.Equal("section,week,week_start,item,measure,value", csv[0]);
        Assert.All(csv, l => Assert.Equal(5, l.Count(c => c == ',')));
        Assert.Contains("time_to_fix,2026-W39,2026-09-21,\"Fix this week\",median_days,2", csv);
        Assert.Contains("time_to_fix,2026-W39,2026-09-21,\"Fix this week\",closed_within_sla,1", csv);
        Assert.Contains("flow,2026-W39,2026-09-21,\"all tiers\",closed_within_sla_percent,100", csv);
        Assert.Contains("backlog,2026-W40,2026-09-28,\"all tiers\",overdue_at_week_end,1", csv);
        Assert.Contains("coverage,,,\"NinjaOne\",percent_seen_7d,50", csv);
        Assert.Contains("top_products,,,\"Fortinet FortiOS\",open,1", csv);

        var html = SlaReportRenderer.OwnerHtml(r, London);
        Assert.Contains("Vulnerability SLA summary for Example Ltd", html);
        Assert.Contains("@media print", html);
        Assert.Contains("@page{size:A4", html);
        Assert.Equal(4, System.Text.RegularExpressions.Regex.Matches(html, "<figure class=\"vv-chart\">").Count);
        Assert.DoesNotContain("<script", html);
        // charts take their colours from the page: nothing but variables with fallbacks and currentColor on the marks and text
        var svg = SlaCharts.TimeToFix(r);
        Assert.Contains("stroke=\"var(--vv-s1,#2a78d6)\"", svg);
        Assert.Contains("fill=\"currentColor\"", svg);
        Assert.Contains("<title>Fix this week, 21 Sep: 2 days</title>", svg);
        Assert.DoesNotMatch("(fill|stroke)=\"#", svg);
        System.Xml.Linq.XDocument.Parse(svg.Replace("&middot;", "."));
        System.Xml.Linq.XDocument.Parse(SlaCharts.OpenedClosed(r));
        System.Xml.Linq.XDocument.Parse(SlaCharts.Overdue(r));
        System.Xml.Linq.XDocument.Parse(SlaCharts.WithinSla(r));

        // the emailed weekly report has the table (mail clients drop SVG)
        var weekly = await new ReportService(_host.Db, _host.Settings, null!, Microsoft.Extensions.Logging.Abstractions.NullLogger<ReportService>.Instance).BuildAsync(now);
        Assert.NotNull(weekly.Sla);
        Assert.Contains("Trends: the last eight weeks", weekly.Html);
        Assert.DoesNotContain("<svg", weekly.Html);
    }

    [Fact]
    public void Chart_axes_use_round_steps()
    {
        Assert.Equal(1, SlaCharts.NiceStep(4));
        Assert.Equal(2, SlaCharts.NiceStep(7));
        Assert.Equal(5, SlaCharts.NiceStep(18));
        Assert.Equal(50, SlaCharts.NiceStep(100));
        Assert.Equal(0.5, SlaCharts.NiceStep(1.7));
        // nothing to draw: a sentence, not an empty frame
        var empty = SlaCharts.Line("Median days to fix", new[] { "1 Sep" }, new[] { new SlaCharts.Series("Fix today", 0, new double?[] { null }) }, "", " days");
        Assert.DoesNotContain("<svg", empty);
    }
}
