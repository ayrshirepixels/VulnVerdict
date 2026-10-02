using System.Text.Json;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;

namespace VulnVerdict.Core.Feeds.Psirt;

/// <summary>
/// Ubuntu security tracker CVE API (https://ubuntu.com/security/cves.json). Pages newest-updated first
/// (sort_by=updated, order=descending) for critical, high and medium priority CVEs until a page reaches the cursor.
/// Each package status per release becomes one affected row: "released" carries the fixed version.
/// Cursor: ISO 8601 of the newest updated_at stored, plus a resume offset (and the date to stop at) when a run hit
/// MaxRecords before reaching the old cursor; later runs carry on from there until the backfill is complete.
/// </summary>
public sealed class UbuntuSecurityFeed : IFeed
{
    public string Name => PsirtFeedNames.Ubuntu;
    public string DisplayName => "Ubuntu security tracker";
    public int IntervalMinutes => 1440;
    public string Licence => "Ubuntu security data, public API. Referenced and linked only.";
    public const string Vendor = "ubuntu";
    public const string Url = "https://ubuntu.com/security/cves.json";
    private static readonly HashSet<string> SkipStatus = new(StringComparer.OrdinalIgnoreCase) { "not-affected", "DNE" };

    public int PageSize { get; init; } = 20; // the API rejects anything above 20
    public int MaxRecords { get; init; } = 2000;
    public string Priorities { get; init; } = "critical,high,medium";

    public string PageUrl(int offset)
    {
        var pri = string.Join("", Priorities.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(p => "&priority=" + p));
        return $"{Url}?limit={PageSize}&offset={offset}&order=descending&sort_by=updated{pri}";
    }

    public async Task<FeedResult> RunAsync(FeedContext ctx, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var (cursor, resume, until) = ParseCursor(ctx.Cursor);
        DateTime? newest = cursor;
        var total = 0;
        var offset = 0;
        var notes = new List<string>();

        // forward: newest-updated first until a page reaches the cursor
        var forwardDone = false;
        while (total < MaxRecords)
        {
            ct.ThrowIfCancellationRequested();
            ctx.Progress($"Ubuntu offset {offset}");
            List<Advisory> rows;
            try { rows = await PageAsync(ctx, offset, now, ct); }
            catch (Exception ex) when (ex is not OperationCanceledException && total > 0)
            {
                // nothing is lost: the old cursor and resume point stand, and the upserts are idempotent
                ctx.Log.LogWarning(ex, "Ubuntu page at offset {Offset} failed; will retry next run", offset);
                return new FeedResult(total, ctx.Cursor, $"stopped at offset {offset}: {ex.Message}");
            }
            if (rows.Count == 0) { forwardDone = true; break; }
            var fresh = cursor is null ? rows : rows.Where(r => r.Updated is null || r.Updated > cursor).ToList();
            total += await PsirtStore.UpsertAsync(ctx.Db, Vendor, fresh, ct);
            foreach (var r in fresh) if (r.Updated is { } u && (newest is null || u > newest)) newest = u;
            offset += rows.Count;
            if (fresh.Count < rows.Count || rows.Count < PageSize) { forwardDone = true; break; }
        }
        if (!forwardDone)
        {
            // capped before reaching the cursor: everything from here down to the old cursor (or to the end of the list on a
            // first run, or when an older backfill was pending) is still to fetch
            until = resume is null ? cursor : until;
            resume = offset;
            notes.Add($"capped at {MaxRecords} records; resuming at offset {offset} next run");
            return new FeedResult(total, FormatCursor(newest ?? now, resume, until), string.Join("; ", notes), MoreSoon: true);
        }

        // backfill: resume an earlier capped run. Offsets only shift down as CVEs are updated (they move to the top, where the
        // forward pass takes them), so resuming at a stored offset re-reads a few rows but never skips one.
        if (resume is { } start)
        {
            offset = start;
            var done = false;
            while (total < MaxRecords)
            {
                ct.ThrowIfCancellationRequested();
                ctx.Progress($"Ubuntu backfill offset {offset}");
                List<Advisory> rows;
                try { rows = await PageAsync(ctx, offset, now, ct); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    ctx.Log.LogWarning(ex, "Ubuntu backfill page at offset {Offset} failed; will retry next run", offset);
                    notes.Add($"backfill stopped at offset {offset}: {ex.Message}");
                    return new FeedResult(total, FormatCursor(newest ?? now, offset, until), string.Join("; ", notes), MoreSoon: total > 0);
                }
                if (rows.Count == 0) { done = true; break; }
                var due = until is null ? rows : rows.Where(r => r.Updated is null || r.Updated > until).ToList();
                total += await PsirtStore.UpsertAsync(ctx.Db, Vendor, due, ct);
                offset += rows.Count;
                if (due.Count < rows.Count || rows.Count < PageSize) { done = true; break; }
            }
            if (!done)
            {
                notes.Add($"backfill at offset {offset}, continuing shortly");
                return new FeedResult(total, FormatCursor(newest ?? now, offset, until), string.Join("; ", notes), MoreSoon: true);
            }
            notes.Add("backfill complete");
        }
        return new FeedResult(total, FormatCursor(newest ?? now, null, null), notes.Count > 0 ? string.Join("; ", notes) : null);
    }

    private async Task<List<Advisory>> PageAsync(FeedContext ctx, int offset, DateTime now, CancellationToken ct)
    {
        using var doc = await PsirtStore.GetJsonAsync(ctx.Http, PageUrl(offset), ct);
        return Parse(doc.RootElement, now);
    }

    /// <summary>
    /// "2026-09-25T02:43:53.0000000Z" (forward cursor only), "...;resume=2000" (backfill to the end of the list from offset 2000)
    /// or "...;resume=2000;until=2026-08-01T00:00:00.0000000Z" (backfill until rows are no newer than that date).
    /// </summary>
    public static (DateTime? Forward, int? Resume, DateTime? Until) ParseCursor(string? cursor)
    {
        if (string.IsNullOrWhiteSpace(cursor)) return (null, null, null);
        var parts = cursor.Split(';');
        string? Part(string key) => parts.Skip(1).FirstOrDefault(p => p.StartsWith(key + "=", StringComparison.Ordinal))?[(key.Length + 1)..];
        var resume = int.TryParse(Part("resume"), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var r) ? r : (int?)null;
        return (PsirtStore.ParseDate(parts[0]), resume, resume is null ? null : PsirtStore.ParseDate(Part("until")));
    }

    public static string FormatCursor(DateTime forward, int? resume, DateTime? until) =>
        forward.ToString("o") + (resume is { } r ? ";resume=" + r.ToString(System.Globalization.CultureInfo.InvariantCulture) + (until is { } u ? ";until=" + u.ToString("o") : "") : "");

    /// <summary>Parse one cves.json page.</summary>
    public static List<Advisory> Parse(JsonElement root, DateTime now)
    {
        var list = new List<Advisory>();
        foreach (var c in PsirtStore.Arr(root, "cves"))
        {
            var id = PsirtStore.Str(c, "id")?.Trim().ToUpperInvariant();
            if (string.IsNullOrEmpty(id) || !id.StartsWith("CVE-", StringComparison.Ordinal)) continue;
            var rows = new List<AffectedRow>();
            foreach (var p in PsirtStore.Arr(c, "packages"))
            {
                var pkg = PsirtStore.Str(p, "name")?.Trim();
                if (string.IsNullOrEmpty(pkg)) continue;
                foreach (var s in PsirtStore.Arr(p, "statuses"))
                {
                    var release = PsirtStore.Str(s, "release_codename")?.Trim();
                    var status = PsirtStore.Str(s, "status")?.Trim() ?? "";
                    if (string.IsNullOrEmpty(release) || release.Equals("upstream", StringComparison.OrdinalIgnoreCase) || SkipStatus.Contains(status)) continue;
                    var desc = PsirtStore.Str(s, "description")?.Trim() ?? "";
                    var product = pkg + " (" + release + ")";
                    rows.Add(status.Equals("released", StringComparison.OrdinalIgnoreCase)
                        ? new AffectedRow(product, "", desc)
                        : new AffectedRow(product, status, ""));
                    if (rows.Count >= 400) break;
                }
                if (rows.Count >= 400) break;
            }
            var description = PsirtStore.Str(c, "description")?.Trim();
            var title = description is null ? null : PsirtStore.Trunc(description.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault() ?? "", 500);
            list.Add(new Advisory
            {
                Vendor = Vendor,
                AdvisoryId = PsirtStore.Trunc(id, 64),
                Title = string.IsNullOrEmpty(title) ? null : title,
                Url = "https://ubuntu.com/security/" + id,
                Published = PsirtStore.ParseDate(PsirtStore.Str(c, "published")),
                Updated = PsirtStore.ParseDate(PsirtStore.Str(c, "updated_at")),
                CveIdsJson = PsirtStore.CveIdsJson(Normalizer.ExtractCveIds(id)),
                AffectedJson = PsirtStore.AffectedJson(rows),
                Severity = PsirtStore.TruncOrNull(PsirtStore.Str(c, "priority"), 32),
                ExploitedInTheWild = false,
                RetrievedAt = now
            });
        }
        return list;
    }
}
