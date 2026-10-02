using System.Globalization;
using System.Net;
using System.Text;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Core.Digest;

/// <summary>The fix windows in days, per tier (Settings, SLA).</summary>
public readonly record struct SlaDays(int FixToday, int FixThisWeek, int NextPatchCycle)
{
    public static SlaDays From(AppSettings s) => new(s.SlaFixTodayDays, s.SlaFixThisWeekDays, s.SlaNextPatchCycleDays);
    public int? For(VerdictTier tier) => tier switch
    {
        VerdictTier.FixToday => FixToday,
        VerdictTier.FixThisWeek => FixThisWeek,
        VerdictTier.NextPatchCycle => NextPatchCycle,
        _ => null
    };
}

/// <summary>The arithmetic behind the SLA trends: percentiles and local-time weeks.</summary>
public static class SlaMath
{
    public static readonly VerdictTier[] Tiers = { VerdictTier.FixToday, VerdictTier.FixThisWeek, VerdictTier.NextPatchCycle };

    /// <summary>
    /// Percentile with linear interpolation between the two nearest values (the method spreadsheets call PERCENTILE.INC):
    /// the median of 1, 2, 3, 4 is 2.5 and the 90th percentile of 1..10 is 9.1. Null for no values.
    /// </summary>
    public static double? Percentile(IEnumerable<double> values, double p)
    {
        var sorted = values.OrderBy(v => v).ToList();
        if (sorted.Count == 0) return null;
        var rank = Math.Clamp(p, 0, 1) * (sorted.Count - 1);
        var lo = (int)Math.Floor(rank);
        var hi = Math.Min(lo + 1, sorted.Count - 1);
        return sorted[lo] + (sorted[hi] - sorted[lo]) * (rank - lo);
    }

    public static double? Median(IEnumerable<double> values) => Percentile(values, 0.5);

    /// <summary>A week in the reader's time zone: Monday 00:00 local to the next Monday 00:00 local, as UTC instants.</summary>
    public sealed record Week(DateOnly Start, DateTime StartUtc, DateTime EndUtc, string Label, bool Partial)
    {
        public bool Contains(DateTime utc) => utc >= StartUtc && utc < EndUtc;
    }

    /// <summary>Midnight at the start of a local day, in UTC. A midnight the clocks skip is the first instant after it.</summary>
    public static DateTime LocalMidnightUtc(DateOnly day, TimeZoneInfo tz)
    {
        var local = day.ToDateTime(TimeOnly.MinValue, DateTimeKind.Unspecified);
        while (tz.IsInvalidTime(local)) local = local.AddMinutes(30);
        return TimeZoneInfo.ConvertTimeToUtc(local, tz);
    }

    public static DateOnly LocalDay(DateTime utc, TimeZoneInfo tz) => DateOnly.FromDateTime(TimeZoneInfo.ConvertTimeFromUtc(DateTime.SpecifyKind(utc, DateTimeKind.Utc), tz));

    /// <summary>
    /// The last <paramref name="count"/> weeks, oldest first, ending with the week that contains now (marked partial).
    /// Weeks are built from local dates, so a week with a clock change is 167 or 169 hours long and still starts on
    /// Monday; labels are ISO weeks, so the week of 28 December 2026 is 2026-W53 and the next is 2027-W01.
    /// </summary>
    public static List<Week> Weeks(DateTime nowUtc, TimeZoneInfo tz, int count)
    {
        var today = LocalDay(nowUtc, tz);
        var monday = today.AddDays(-(((int)today.DayOfWeek + 6) % 7));
        var weeks = new List<Week>();
        for (var i = count - 1; i >= 0; i--)
        {
            var start = monday.AddDays(-7 * i);
            var d = start.ToDateTime(TimeOnly.MinValue);
            var label = ISOWeek.GetYear(d).ToString(CultureInfo.InvariantCulture) + "-W" + ISOWeek.GetWeekOfYear(d).ToString("00", CultureInfo.InvariantCulture);
            weeks.Add(new Week(start, LocalMidnightUtc(start, tz), LocalMidnightUtc(start.AddDays(7), tz), label, i == 0));
        }
        return weeks;
    }
}

/// <summary>One recorded change to a verdict, as the trend calculations need it.</summary>
public sealed record HistoryPoint(DateTime At, string Kind, string? From, string? To, string? Reason = null);

/// <summary>A verdict closing: which tier it was in, when its clock started, when it closed and when it was due.</summary>
public sealed record Closure(Guid VerdictId, VerdictTier Tier, DateTime OpenedUtc, DateTime ClosedUtc, DateTime DueUtc)
{
    public double Days => (ClosedUtc - OpenedUtc).TotalDays;
    public bool WithinSla => ClosedUtc <= DueUtc;
}

/// <summary>
/// A verdict with its history, replayed to answer "what was it at that moment". The verdict row holds only the present;
/// tier and state changes are in the history, each with a from and a to, so the past can be rebuilt. The fix window
/// restarts whenever the tier changes or the verdict re-opens, as it does in the evaluator.
/// </summary>
public sealed class VerdictTimeline
{
    public Guid Id { get; }
    public DateTime CreatedAt { get; }
    public VerdictTier Tier { get; }
    public VerdictState State { get; }
    private readonly List<HistoryPoint> _tier, _state;

    public VerdictTimeline(Guid id, DateTime createdAt, VerdictTier tier, VerdictState state, IEnumerable<HistoryPoint> history)
    {
        Id = id; CreatedAt = createdAt; Tier = tier; State = state;
        var ordered = history.OrderBy(h => h.At).ToList();
        _tier = ordered.Where(h => h.Kind == "tier").ToList();
        _state = ordered.Where(h => h.Kind == "state").ToList();
    }

    private static VerdictTier ParseTier(string? s, VerdictTier fallback) => Enum.TryParse<VerdictTier>(s, out var t) ? t : fallback;
    private static VerdictState ParseState(string? s, VerdictState fallback) => Enum.TryParse<VerdictState>(s, out var t) ? t : fallback;
    private static bool IsReopen(HistoryPoint h) => h.From == "Closed" && h.To == "Open";

    /// <summary>The tier at <paramref name="t"/>; with <paramref name="before"/>, the tier just before anything recorded at exactly t.</summary>
    public VerdictTier TierAt(DateTime t, bool before = false)
    {
        var last = _tier.LastOrDefault(h => before ? h.At < t : h.At <= t);
        if (last is not null) return ParseTier(last.To, Tier);
        return _tier.Count > 0 ? ParseTier(_tier[0].From, Tier) : Tier;
    }

    public VerdictState StateAt(DateTime t, bool before = false)
    {
        var last = _state.LastOrDefault(h => before ? h.At < t : h.At <= t);
        if (last is not null) return ParseState(last.To, State);
        return _state.Count > 0 ? ParseState(_state[0].From, State) : State;
    }

    /// <summary>When the fix window in force at <paramref name="t"/> started: creation, the last tier change or the last re-opening.</summary>
    private DateTime ClockStart(DateTime t, bool before)
    {
        var start = CreatedAt;
        foreach (var h in _tier.Concat(_state.Where(IsReopen)))
            if ((before ? h.At < t : h.At <= t) && h.At > start) start = h.At;
        return start;
    }

    /// <summary>Tier, state and due date at a moment, or null if the verdict did not exist yet.</summary>
    public (VerdictTier Tier, VerdictState State, DateTime? Due)? At(DateTime t, SlaDays sla)
    {
        if (CreatedAt > t) return null;
        var tier = TierAt(t);
        return (tier, StateAt(t), sla.For(tier) is { } d ? ClockStart(t, false).AddDays(d) : null);
    }

    /// <summary>
    /// Every time the verdict closed while it needed action. Time to fix runs from when it was opened (or last
    /// re-opened) to the close. Closures because the CVE stopped matching are left out: nothing was fixed.
    /// </summary>
    public IEnumerable<Closure> Closures(SlaDays sla)
    {
        foreach (var h in _state)
        {
            if (h.To != "Closed" || h.From is "Suppressed" or "Closed") continue;
            if (h.Reason is { } r && r.StartsWith("closed: no longer matches", StringComparison.Ordinal)) continue;
            var tier = TierAt(h.At, before: true);
            if (sla.For(tier) is not { } days) continue;
            var opened = _state.LastOrDefault(x => IsReopen(x) && x.At < h.At)?.At ?? CreatedAt;
            yield return new Closure(Id, tier, opened, h.At, ClockStart(h.At, before: true).AddDays(days));
        }
    }

    /// <summary>Every time the verdict started needing action: created in an actionable tier, promoted into one, or re-opened.</summary>
    public IEnumerable<DateTime> Openings()
    {
        if (TierAt(CreatedAt) >= VerdictTier.NextPatchCycle && StateAt(CreatedAt) == VerdictState.Open) yield return CreatedAt;
        foreach (var h in _tier)
            if (h.At > CreatedAt && ParseTier(h.From, VerdictTier.NotAffected) < VerdictTier.NextPatchCycle && ParseTier(h.To, VerdictTier.NotAffected) >= VerdictTier.NextPatchCycle && StateAt(h.At) == VerdictState.Open)
                yield return h.At;
        foreach (var h in _state)
            if (IsReopen(h) && h.At > CreatedAt && TierAt(h.At) >= VerdictTier.NextPatchCycle) yield return h.At;
    }
}

public sealed record SlaTierWeek(int Closed, double? MedianDays, double? P90Days, int WithinSla);

public sealed class SlaWeek
{
    public SlaMath.Week Week { get; init; } = default!;
    public Dictionary<VerdictTier, SlaTierWeek> Tiers { get; init; } = new();
    public int Opened { get; init; }
    public int Closed { get; init; }
    public int ClosedWithinSla { get; init; }
    /// <summary>Open and overdue at the end of the week, from the daily snapshots. Null when no snapshot covers the week.</summary>
    public int? OpenAtEnd { get; init; }
    public int? OverdueAtEnd { get; init; }
    /// <summary>The snapshot was rebuilt from history, not counted on the day.</summary>
    public bool Backfilled { get; init; }
    public double? WithinSlaPercent => Closed == 0 ? null : 100.0 * ClosedWithinSla / Closed;
    public string ShortLabel => "W" + Week.Label[^2..];
}

public sealed record RiskExpiry(Guid VerdictId, string CveId, string Subject, string? Owner, DateTime Expiry);
public sealed record ConnectorCoverage(string Connector, int AssetsSeen, double Percent);
public sealed record ProductCount(string Product, int Open, int Overdue);

public sealed class SlaReport
{
    public DateTime GeneratedUtc { get; init; }
    public string Organisation { get; init; } = "";
    public string TimeZone { get; init; } = "";
    public SlaDays Sla { get; init; }
    public List<SlaWeek> Weeks { get; init; } = new();
    public int OpenNow { get; init; }
    public int OverdueNow { get; init; }
    public int AcceptedRisk { get; init; }
    public int AcceptedRiskWithoutExpiry { get; init; }
    public List<RiskExpiry> UpcomingExpiries { get; init; } = new();
    public int Assets { get; init; }
    public int AssetsSeen { get; init; }
    public List<ConnectorCoverage> Coverage { get; init; } = new();
    public List<ProductCount> TopProducts { get; init; } = new();
    public double? CoveragePercent => Assets == 0 ? null : 100.0 * AssetsSeen / Assets;
}

/// <summary>
/// SLA trends for the Reports page, the weekly report and the owner's one-page view: time to fix per tier by week,
/// how much closed inside its fix window, overdue over time, opened against closed, accepted risk, connector coverage
/// and the products with the most open verdicts. Closures and openings come from the verdict history; open and overdue
/// counts over time come from a daily snapshot the worker writes (and fills in from history the first time).
/// </summary>
public sealed class SlaReportService
{
    public const string LastSnapshotKey = "state:sla:lastSnapshot";
    /// <summary>How far back the first snapshot run reconstructs from history.</summary>
    public const int BackfillDays = 182;
    public const int CoverageDays = 7;
    public const int ExpiryHorizonDays = 30;

    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly SettingsService _settings;

    public SlaReportService(IDbContextFactory<VvDbContext> factory, SettingsService settings) { _factory = factory; _settings = settings; }

    public async Task<SlaReport> BuildAsync(int weeks = 12, DateTime? nowUtc = null, CancellationToken ct = default)
    {
        var s = await _settings.LoadAsync(ct);
        var tz = s.ResolveTimeZone();
        var now = nowUtc ?? DateTime.UtcNow;
        var sla = SlaDays.From(s);
        var buckets = SlaMath.Weeks(now, tz, Math.Clamp(weeks, 1, 104));
        var from = buckets[0].StartUtc;
        await using var db = await _factory.CreateDbContextAsync(ct);

        var timelines = await LoadTimelinesAsync(db, from, ct);
        var closures = timelines.SelectMany(t => t.Closures(sla)).Where(c => c.ClosedUtc >= from && c.ClosedUtc <= now).ToList();
        var openings = timelines.SelectMany(t => t.Openings()).Where(o => o >= from && o <= now).ToList();

        // open and overdue over time: the last snapshot day inside each week
        var snapshots = new List<SlaSnapshot>();
        var firstDay = buckets[0].Start;
        try { snapshots = await db.SlaSnapshots.AsNoTracking().Where(x => x.Day >= firstDay).ToListAsync(ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { }   // before the table's migration has run

        var rows = new List<SlaWeek>();
        foreach (var w in buckets)
        {
            var closed = closures.Where(c => w.Contains(c.ClosedUtc)).ToList();
            var lastDay = snapshots.Where(x => x.Day >= w.Start && x.Day < w.Start.AddDays(7)).Select(x => (DateOnly?)x.Day).Max();
            var snap = lastDay is null ? null : snapshots.Where(x => x.Day == lastDay).ToList();
            rows.Add(new SlaWeek
            {
                Week = w,
                Tiers = SlaMath.Tiers.ToDictionary(t => t, t =>
                {
                    var c = closed.Where(x => x.Tier == t).ToList();
                    return new SlaTierWeek(c.Count, SlaMath.Median(c.Select(x => x.Days)), SlaMath.Percentile(c.Select(x => x.Days), 0.9), c.Count(x => x.WithinSla));
                }),
                Opened = openings.Count(w.Contains),
                Closed = closed.Count,
                ClosedWithinSla = closed.Count(c => c.WithinSla),
                OpenAtEnd = snap?.Sum(x => x.Open),
                OverdueAtEnd = snap?.Sum(x => x.Overdue),
                Backfilled = snap?.Any(x => x.Backfilled) ?? false,
            });
        }

        var open = await db.Verdicts.AsNoTracking().Include(v => v.WatchlistEntry).Include(v => v.SoftwareInstance)
            .Where(v => v.State == VerdictState.Open && v.Tier >= VerdictTier.NextPatchCycle).ToListAsync(ct);
        var horizon = now.AddDays(ExpiryHorizonDays);
        var accepted = await db.Verdicts.AsNoTracking().Where(v => v.State == VerdictState.AcceptedRisk)
            .Select(v => new { v.Id, v.CveId, v.Subject, v.StateOwner, v.AcceptedRiskExpiry }).ToListAsync(ct);

        // coverage: assets a connector has seen in the last seven days, against every asset the console knows
        var seenSince = now.AddDays(-CoverageDays);
        var assetIds = await db.Assets.AsNoTracking().Where(a => !a.Archived).Select(a => a.Id).ToListAsync(ct);
        var known = assetIds.ToHashSet();
        var sources = await db.AssetSources.AsNoTracking().Where(x => x.LastSeen >= seenSince).Select(x => new { x.AssetId, x.ConnectorId }).ToListAsync(ct);
        sources = sources.Where(x => known.Contains(x.AssetId)).ToList();
        var connectors = await db.Connectors.AsNoTracking().Select(c => new { c.Id, c.DisplayName, c.Enabled }).ToListAsync(ct);
        var everSeen = (await db.AssetSources.AsNoTracking().Select(x => x.ConnectorId).Distinct().ToListAsync(ct)).ToHashSet();
        var coverage = connectors.Where(c => everSeen.Contains(c.Id.ToString("N")))
            .Select(c =>
            {
                var n = sources.Where(x => x.ConnectorId == c.Id.ToString("N")).Select(x => x.AssetId).Distinct().Count();
                return new ConnectorCoverage(c.DisplayName + (c.Enabled ? "" : " (disabled)"), n, known.Count == 0 ? 0 : 100.0 * n / known.Count);
            }).OrderByDescending(c => c.AssetsSeen).ThenBy(c => c.Connector).ToList();

        return new SlaReport
        {
            GeneratedUtc = now, Organisation = s.OrganisationName, TimeZone = tz.Id, Sla = sla, Weeks = rows,
            OpenNow = open.Count, OverdueNow = open.Count(v => v.IsOverdue(now)),
            AcceptedRisk = accepted.Count, AcceptedRiskWithoutExpiry = accepted.Count(a => a.AcceptedRiskExpiry is null),
            UpcomingExpiries = accepted.Where(a => a.AcceptedRiskExpiry is { } e && e <= horizon).OrderBy(a => a.AcceptedRiskExpiry)
                .Select(a => new RiskExpiry(a.Id, a.CveId, a.Subject, a.StateOwner, a.AcceptedRiskExpiry!.Value)).Take(25).ToList(),
            Assets = known.Count, AssetsSeen = sources.Select(x => x.AssetId).Distinct().Count(), Coverage = coverage,
            TopProducts = TopProducts(open, now, 10),
        };
    }

    /// <summary>Vendor and product only, never the asset: the name is also used as a metrics label.</summary>
    public static string ProductName(Verdict v)
    {
        var name = v.WatchlistEntry is { } w ? (w.Vendor + " " + w.Product).Trim()
            : v.SoftwareInstance is { } i ? (i.Vendor + " " + i.Product).Trim() : "";
        return name.Length == 0 ? "Unknown product" : name;
    }

    public static List<ProductCount> TopProducts(IEnumerable<Verdict> open, DateTime now, int take) =>
        open.GroupBy(ProductName, StringComparer.OrdinalIgnoreCase)
            .Select(g => new ProductCount(g.Key, g.Count(), g.Count(v => v.IsOverdue(now))))
            .OrderByDescending(p => p.Open).ThenByDescending(p => p.Overdue).ThenBy(p => p.Product, StringComparer.OrdinalIgnoreCase).Take(take).ToList();

    /// <summary>Closures in a period, for the metrics endpoint's mean time to fix.</summary>
    public async Task<List<Closure>> ClosuresAsync(DateTime fromUtc, DateTime toUtc, CancellationToken ct = default)
    {
        var sla = SlaDays.From(await _settings.LoadAsync(ct));
        await using var db = await _factory.CreateDbContextAsync(ct);
        return (await LoadTimelinesAsync(db, fromUtc, ct)).SelectMany(t => t.Closures(sla)).Where(c => c.ClosedUtc >= fromUtc && c.ClosedUtc <= toUtc).ToList();
    }

    /// <summary>Verdicts that were created or changed since <paramref name="from"/> and ever needed action, each with its whole history.</summary>
    private static async Task<List<VerdictTimeline>> LoadTimelinesAsync(VvDbContext db, DateTime from, CancellationToken ct)
    {
        var changed = await db.VerdictHistory.AsNoTracking().Where(h => h.At >= from).Select(h => h.VerdictId).Distinct().ToListAsync(ct);
        var created = await db.Verdicts.AsNoTracking().Where(v => v.CreatedAt >= from && v.Tier >= VerdictTier.NextPatchCycle).Select(v => v.Id).ToListAsync(ct);
        return await LoadTimelinesAsync(db, changed.Union(created).ToList(), ct);
    }

    private static async Task<List<VerdictTimeline>> LoadTimelinesAsync(VvDbContext db, List<Guid> ids, CancellationToken ct)
    {
        var result = new List<VerdictTimeline>();
        foreach (var chunk in ids.Chunk(2000))
        {
            var verdicts = await db.Verdicts.AsNoTracking().Where(v => chunk.Contains(v.Id)).Select(v => new { v.Id, v.CreatedAt, v.Tier, v.State }).ToListAsync(ct);
            var history = (await db.VerdictHistory.AsNoTracking().Where(h => chunk.Contains(h.VerdictId)).OrderBy(h => h.At).ThenBy(h => h.Id)
                .Select(h => new { h.VerdictId, h.At, h.Kind, h.From, h.To, h.Reason }).ToListAsync(ct)).ToLookup(h => h.VerdictId);
            result.AddRange(verdicts.Select(v => new VerdictTimeline(v.Id, v.CreatedAt, v.Tier, v.State, history[v.Id].Select(h => new HistoryPoint(h.At, h.Kind, h.From, h.To, h.Reason)))));
        }
        return result;
    }

    // ------------------------------------------------------------------ daily snapshot (worker)

    /// <summary>
    /// Worker step, at most hourly: record today's open, overdue, snoozed and accepted-risk counts per tier (the last
    /// write of the day stands). The first run also rebuilds the previous <see cref="BackfillDays"/> days from history.
    /// </summary>
    public async Task<bool> WriteSnapshotIfDueAsync(DateTime? nowUtc = null, CancellationToken ct = default)
    {
        var now = nowUtc ?? DateTime.UtcNow;
        var last = await _settings.GetStateAsync(LastSnapshotKey, ct);
        if (last is not null && DateTime.TryParse(last, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var d) && now - d.ToUniversalTime() < TimeSpan.FromHours(1) && now >= d.ToUniversalTime()) return false;
        var s = await _settings.LoadAsync(ct);
        var tz = s.ResolveTimeZone();
        var today = SlaMath.LocalDay(now, tz);
        await using var db = await _factory.CreateDbContextAsync(ct);
        if (!await db.SlaSnapshots.AnyAsync(ct)) await BackfillAsync(db, today, tz, SlaDays.From(s), now, ct);

        var live = await db.Verdicts.AsNoTracking().Where(v => v.Tier >= VerdictTier.NextPatchCycle && (v.State == VerdictState.Open || v.State == VerdictState.Snoozed || v.State == VerdictState.AcceptedRisk))
            .Select(v => new { v.Tier, v.State, v.SlaDue }).ToListAsync(ct);
        var existing = await db.SlaSnapshots.Where(x => x.Day == today).ToListAsync(ct);
        foreach (var tier in SlaMath.Tiers)
        {
            var row = existing.FirstOrDefault(x => x.Tier == tier);
            if (row is null) db.SlaSnapshots.Add(row = new SlaSnapshot { Day = today, Tier = tier });
            var mine = live.Where(v => v.Tier == tier).ToList();
            row.Open = mine.Count(v => v.State == VerdictState.Open);
            row.Overdue = mine.Count(v => v.State == VerdictState.Open && v.SlaDue is { } due && due < now);
            row.Snoozed = mine.Count(v => v.State == VerdictState.Snoozed);
            row.AcceptedRisk = mine.Count(v => v.State == VerdictState.AcceptedRisk);
            row.Backfilled = false; row.RecordedAt = now;
        }
        await db.SaveChangesAsync(ct);
        await _settings.SetStateAsync(LastSnapshotKey, now.ToString("O"), ct);
        return true;
    }

    /// <summary>
    /// Rebuild past days from the verdict history. Close, but not exact: verdicts deleted since (a watchlist entry
    /// removed) are gone, and the fix windows are today's settings. The rows are marked so the report can say so.
    /// </summary>
    private static async Task BackfillAsync(VvDbContext db, DateOnly today, TimeZoneInfo tz, SlaDays sla, DateTime now, CancellationToken ct)
    {
        var withTierHistory = await db.VerdictHistory.AsNoTracking().Where(h => h.Kind == "tier").Select(h => h.VerdictId).Distinct().ToListAsync(ct);
        var actionable = await db.Verdicts.AsNoTracking().Where(v => v.Tier >= VerdictTier.NextPatchCycle).Select(v => v.Id).ToListAsync(ct);
        var timelines = await LoadTimelinesAsync(db, withTierHistory.Union(actionable).ToList(), ct);
        if (timelines.Count == 0) return;
        var first = SlaMath.LocalDay(timelines.Min(t => t.CreatedAt), tz);
        var start = today.AddDays(-BackfillDays);
        if (first > start) start = first;
        for (var day = start; day < today; day = day.AddDays(1))
        {
            var end = SlaMath.LocalMidnightUtc(day.AddDays(1), tz);
            var at = timelines.Select(t => t.At(end, sla)).Where(x => x is not null).Select(x => x!.Value).ToList();
            foreach (var tier in SlaMath.Tiers)
            {
                var mine = at.Where(x => x.Tier == tier).ToList();
                db.SlaSnapshots.Add(new SlaSnapshot
                {
                    Day = day, Tier = tier, Backfilled = true, RecordedAt = now,
                    Open = mine.Count(x => x.State == VerdictState.Open),
                    Overdue = mine.Count(x => x.State == VerdictState.Open && x.Due is { } due && due < end),
                    Snoozed = mine.Count(x => x.State == VerdictState.Snoozed),
                    AcceptedRisk = mine.Count(x => x.State == VerdictState.AcceptedRisk),
                });
            }
        }
        await db.SaveChangesAsync(ct);
    }
}

/// <summary>The SLA trends as CSV, as a section of the weekly report, and as the owner's one-page print view.</summary>
public static class SlaReportRenderer
{
    private static string N(double? v, string format = "0.#") => v is null ? "" : v.Value.ToString(format, CultureInfo.InvariantCulture);
    private static string Q(string? s) => "\"" + (s ?? "").Replace("\"", "\"\"") + "\"";
    private static string H(string? s) => WebUtility.HtmlEncode(s ?? "");
    public static string Days(double? v) => v is null ? "-" : v.Value.ToString(v < 10 ? "0.#" : "0", CultureInfo.InvariantCulture) + " d";
    public static string Pct(double? v) => v is null ? "-" : v.Value.ToString("0", CultureInfo.InvariantCulture) + "%";

    /// <summary>Every number behind the charts, one measure per line: section, week, week start, item, measure, value.</summary>
    public static string Csv(SlaReport r)
    {
        var sb = new StringBuilder();
        sb.AppendLine("section,week,week_start,item,measure,value");
        void Line(string section, SlaWeek? w, string item, string measure, string value) =>
            sb.AppendLine(string.Join(",", section, w?.Week.Label ?? "", w?.Week.Start.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "", Q(item), measure, value));
        foreach (var w in r.Weeks)
        {
            foreach (var tier in SlaMath.Tiers)
            {
                var t = w.Tiers[tier];
                Line("time_to_fix", w, tier.Plain(), "closed", t.Closed.ToString(CultureInfo.InvariantCulture));
                Line("time_to_fix", w, tier.Plain(), "median_days", N(t.MedianDays, "0.##"));
                Line("time_to_fix", w, tier.Plain(), "p90_days", N(t.P90Days, "0.##"));
                Line("time_to_fix", w, tier.Plain(), "closed_within_sla", t.WithinSla.ToString(CultureInfo.InvariantCulture));
            }
            Line("flow", w, "all tiers", "opened", w.Opened.ToString(CultureInfo.InvariantCulture));
            Line("flow", w, "all tiers", "closed", w.Closed.ToString(CultureInfo.InvariantCulture));
            Line("flow", w, "all tiers", "closed_within_sla_percent", N(w.WithinSlaPercent, "0.#"));
            Line("backlog", w, "all tiers", "open_at_week_end", w.OpenAtEnd?.ToString(CultureInfo.InvariantCulture) ?? "");
            Line("backlog", w, "all tiers", "overdue_at_week_end", w.OverdueAtEnd?.ToString(CultureInfo.InvariantCulture) ?? "");
            Line("backlog", w, "all tiers", "rebuilt_from_history", w.OpenAtEnd is null ? "" : w.Backfilled ? "1" : "0");
        }
        Line("now", null, "all tiers", "open", r.OpenNow.ToString(CultureInfo.InvariantCulture));
        Line("now", null, "all tiers", "overdue", r.OverdueNow.ToString(CultureInfo.InvariantCulture));
        Line("accepted_risk", null, "all", "count", r.AcceptedRisk.ToString(CultureInfo.InvariantCulture));
        Line("accepted_risk", null, "all", "without_expiry", r.AcceptedRiskWithoutExpiry.ToString(CultureInfo.InvariantCulture));
        foreach (var e in r.UpcomingExpiries) Line("accepted_risk", null, e.CveId + " " + e.Subject, "expires", e.Expiry.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
        Line("coverage", null, "all connectors", "assets", r.Assets.ToString(CultureInfo.InvariantCulture));
        Line("coverage", null, "all connectors", "assets_seen_7d", r.AssetsSeen.ToString(CultureInfo.InvariantCulture));
        Line("coverage", null, "all connectors", "percent_seen_7d", N(r.CoveragePercent));
        foreach (var c in r.Coverage)
        {
            Line("coverage", null, c.Connector, "assets_seen_7d", c.AssetsSeen.ToString(CultureInfo.InvariantCulture));
            Line("coverage", null, c.Connector, "percent_seen_7d", N(c.Percent));
        }
        foreach (var p in r.TopProducts)
        {
            Line("top_products", null, p.Product, "open", p.Open.ToString(CultureInfo.InvariantCulture));
            Line("top_products", null, p.Product, "overdue", p.Overdue.ToString(CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }

    /// <summary>The week-by-week table, shared by the Reports page's print view and the weekly email (tables only: mail clients drop SVG).</summary>
    public static string WeekTableHtml(SlaReport r, int lastWeeks)
    {
        var sb = new StringBuilder();
        sb.Append("<table><thead><tr><th>Week</th><th>Opened</th><th>Closed</th><th>In fix window</th>");
        foreach (var t in SlaMath.Tiers) sb.Append("<th>" + t.Plain() + ": median / 90th</th>");
        sb.Append("<th>Open at end</th><th>Overdue at end</th></tr></thead><tbody>");
        foreach (var w in r.Weeks.TakeLast(lastWeeks))
        {
            sb.Append("<tr><td>" + w.Week.Start.ToString("d MMM", CultureInfo.InvariantCulture) + (w.Week.Partial ? " (so far)" : "") + "</td><td>" + w.Opened + "</td><td>" + w.Closed + "</td><td>" + Pct(w.WithinSlaPercent) + "</td>");
            foreach (var t in SlaMath.Tiers) sb.Append("<td>" + (w.Tiers[t].Closed == 0 ? "-" : Days(w.Tiers[t].MedianDays) + " / " + Days(w.Tiers[t].P90Days)) + "</td>");
            sb.Append("<td>" + (w.OpenAtEnd?.ToString(CultureInfo.InvariantCulture) ?? "-") + "</td><td>" + (w.OverdueAtEnd?.ToString(CultureInfo.InvariantCulture) ?? "-") + (w.Backfilled ? "*" : "") + "</td></tr>");
        }
        sb.Append("</tbody></table>");
        if (r.Weeks.TakeLast(lastWeeks).Any(w => w.Backfilled)) sb.Append("<p class=\"muted\" style=\"font-size:11px\">* rebuilt from the verdict history, not counted on the day.</p>");
        return sb.ToString();
    }

    /// <summary>The section added to the weekly report: the last eight weeks, accepted risk, coverage and the busiest products.</summary>
    public static string WeeklySectionHtml(SlaReport r)
    {
        var sb = new StringBuilder();
        sb.Append("<h2>Trends: the last eight weeks</h2>");
        sb.Append("<p class=\"muted\">Fix windows: " + r.Sla.FixToday + " days for Fix today, " + r.Sla.FixThisWeek + " for Fix this week, " + r.Sla.NextPatchCycle + " for Next patch cycle. Time to fix is from when a verdict opened to when it closed.</p>");
        sb.Append(WeekTableHtml(r, 8));
        sb.Append("<h2>Accepted risk and coverage</h2><p>" + Sentence(r) + "</p>");
        if (r.TopProducts.Count > 0)
        {
            sb.Append("<h2>Products with the most open verdicts</h2><table><thead><tr><th>Product</th><th>Open</th><th>Overdue</th></tr></thead><tbody>");
            foreach (var p in r.TopProducts.Take(5)) sb.Append("<tr><td>" + H(p.Product) + "</td><td>" + p.Open + "</td><td>" + p.Overdue + "</td></tr>");
            sb.Append("</tbody></table>");
        }
        return sb.ToString();
    }

    public static string WeeklySectionText(SlaReport r)
    {
        var sb = new StringBuilder();
        sb.AppendLine("TRENDS (week starting: opened, closed, closed in fix window, overdue at end)");
        foreach (var w in r.Weeks.TakeLast(8))
            sb.AppendLine("  " + w.Week.Start.ToString("d MMM", CultureInfo.InvariantCulture) + ": " + w.Opened + ", " + w.Closed + ", " + Pct(w.WithinSlaPercent) + ", " + (w.OverdueAtEnd?.ToString(CultureInfo.InvariantCulture) ?? "-"));
        sb.AppendLine(Sentence(r));
        return sb.ToString();
    }

    /// <summary>Accepted risk and coverage in one plain sentence each.</summary>
    public static string Sentence(SlaReport r)
    {
        var next = r.UpcomingExpiries.Count;
        var risk = r.AcceptedRisk == 0 ? "No risks are accepted."
            : r.AcceptedRisk + " risk" + (r.AcceptedRisk == 1 ? " is" : "s are") + " accepted; " + (next == 0 ? "none expires" : next + (next == 1 ? " expires" : " expire")) + " in the next " + SlaReportService.ExpiryHorizonDays + " days"
              + (r.AcceptedRiskWithoutExpiry > 0 ? " and " + r.AcceptedRiskWithoutExpiry + (r.AcceptedRiskWithoutExpiry == 1 ? " has" : " have") + " no expiry date." : ".");
        var coverage = r.Assets == 0 ? "No assets are in the inventory yet."
            : r.AssetsSeen + " of " + r.Assets + " assets (" + Pct(r.CoveragePercent) + ") were seen by a connector in the last " + SlaReportService.CoverageDays + " days.";
        return risk + " " + coverage;
    }

    /// <summary>
    /// One page for the owner or an auditor: the position today, four charts and the numbers behind them. Standalone
    /// HTML with its own print stylesheet (A4, light, no page furniture).
    /// </summary>
    public static string OwnerHtml(SlaReport r, TimeZoneInfo tz)
    {
        var last = r.Weeks.Where(w => !w.Week.Partial).TakeLast(4).ToList();
        var closed = last.Sum(w => w.Closed);
        var within = last.Sum(w => w.ClosedWithinSla);
        var sb = new StringBuilder();
        sb.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>VulnVerdict: vulnerability SLA summary</title><style>");
        sb.Append(SlaCharts.Css);
        sb.Append("""
            :root{color-scheme:light dark;--bg:#fff;--ink:#1E222A;--muted:#5c6470;--line:#e1e5eb}
            @media (prefers-color-scheme:dark){:root{--bg:#1a1a19;--ink:#f1f1ef;--muted:#b4b3ab;--line:#3a3a37}}
            body{font-family:Inter,"Segoe UI",Helvetica,Arial,sans-serif;background:var(--bg);color:var(--ink);margin:24px auto;max-width:980px;padding:0 20px;font-size:13px;line-height:1.4}
            h1{font-size:21px;margin:2px 0}h2{font-size:13px;margin:0 0 4px}.muted{color:var(--muted)}
            .brand{font-weight:700;letter-spacing:.04em;color:var(--muted);font-size:12px}.brand span{color:#FF9F0A}
            .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:12px 0}.stat{border:1px solid var(--line);border-radius:8px;padding:6px 12px}.stat b{display:block;font-size:20px}
            .grid{display:grid;grid-template-columns:1fr 1fr;gap:10px 20px}.grid>div{break-inside:avoid}
            table{border-collapse:collapse;width:100%;font-size:11.5px}th,td{text-align:left;padding:3px 6px;border-top:1px solid var(--line);vertical-align:top}th{font-size:10px;text-transform:uppercase;color:var(--muted)}
            .noprint{margin:0 0 12px}.sign{margin-top:14px;display:flex;gap:40px}.sign div{flex:1;border-top:1px solid var(--ink);padding-top:3px;font-size:11px}
            @page{size:A4;margin:11mm}
            @media print{:root{color-scheme:light;--bg:#fff;--ink:#000;--muted:#444;--line:#bbb}body{margin:0;max-width:none;padding:0;font-size:10.5px}.noprint{display:none}.vv-chart{--vv-surface:#fff}.stat b{font-size:16px}h1{font-size:17px}table{font-size:9.5px}}
            """);
        sb.Append("</style></head><body>");
        sb.Append("<p class=\"noprint muted\">Print this page (Ctrl+P or Cmd+P) for a one-page A4 summary. <a href=\"/reports\">Back to Reports</a> &middot; <a href=\"/reports/sla.csv\">Download the numbers (CSV)</a></p>");
        sb.Append("<div class=\"brand\"><span>VULN</span>VERDICT</div>");
        sb.Append("<h1>Vulnerability SLA summary" + (r.Organisation == "" ? "" : " for " + H(r.Organisation)) + "</h1>");
        sb.Append("<div class=\"muted\">As of " + TimeZoneInfo.ConvertTimeFromUtc(r.GeneratedUtc, tz).ToString("d MMMM yyyy HH:mm", CultureInfo.InvariantCulture) + " (" + H(r.TimeZone) + "). Fix windows: " + r.Sla.FixToday + " days for Fix today, " + r.Sla.FixThisWeek + " for Fix this week, " + r.Sla.NextPatchCycle + " for Next patch cycle.</div>");
        sb.Append("<div class=\"stats\">");
        foreach (var (label, value) in new[]
                 {
                     ("open, needing action", r.OpenNow.ToString(CultureInfo.InvariantCulture)), ("overdue", r.OverdueNow.ToString(CultureInfo.InvariantCulture)),
                     ("closed in the last 4 full weeks", closed.ToString(CultureInfo.InvariantCulture)), ("of those, inside the fix window", Pct(closed == 0 ? null : 100.0 * within / closed)),
                     ("risks accepted", r.AcceptedRisk.ToString(CultureInfo.InvariantCulture)), ("assets seen in 7 days", Pct(r.CoveragePercent))
                 })
            sb.Append("<div class=\"stat\"><b>" + value + "</b><span class=\"muted\">" + label + "</span></div>");
        sb.Append("</div><div class=\"grid\">");
        sb.Append("<div>" + SlaCharts.TimeToFix(r) + "</div><div>" + SlaCharts.WithinSla(r) + "</div><div>" + SlaCharts.OpenedClosed(r) + "</div><div>" + SlaCharts.Overdue(r) + "</div>");
        sb.Append("</div><h2 style=\"margin-top:10px\">The numbers, by week starting</h2>" + WeekTableHtml(r, 12));
        sb.Append("<div class=\"grid\" style=\"margin-top:10px\"><div><h2>Products with the most open verdicts</h2>");
        if (r.TopProducts.Count == 0) sb.Append("<p class=\"muted\">Nothing open.</p>");
        else
        {
            sb.Append("<table><thead><tr><th>Product</th><th>Open</th><th>Overdue</th></tr></thead><tbody>");
            foreach (var p in r.TopProducts.Take(6)) sb.Append("<tr><td>" + H(p.Product) + "</td><td>" + p.Open + "</td><td>" + p.Overdue + "</td></tr>");
            sb.Append("</tbody></table>");
        }
        sb.Append("</div><div><h2>Accepted risk and coverage</h2><p style=\"margin:0 0 4px\">" + H(Sentence(r)) + "</p>");
        if (r.Coverage.Count > 0)
        {
            sb.Append("<table><thead><tr><th>Connector</th><th>Assets seen in 7 days</th><th>Of all assets</th></tr></thead><tbody>");
            foreach (var c in r.Coverage.Take(6)) sb.Append("<tr><td>" + H(c.Connector) + "</td><td>" + c.AssetsSeen + "</td><td>" + Pct(c.Percent) + "</td></tr>");
            sb.Append("</tbody></table>");
        }
        sb.Append("</div></div>");
        sb.Append("<div class=\"sign\"><div>Reviewed by</div><div>Date</div></div>");
        sb.Append("<p class=\"muted\" style=\"font-size:9.5px;margin-top:10px\">Time to fix runs from when a verdict opened (or re-opened) to when it closed; median and 90th percentile in days. Open and overdue are counted at the end of each week. " + H(DigestService.Disclaimer) + "</p>");
        sb.Append("</body></html>");
        return sb.ToString();
    }
}
