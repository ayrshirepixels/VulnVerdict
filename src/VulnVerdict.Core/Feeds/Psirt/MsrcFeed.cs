using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;

namespace VulnVerdict.Core.Feeds.Psirt;

public sealed record MsrcUpdateDoc(string Id, DateTime? InitialReleaseDate, DateTime? CurrentReleaseDate);

/// <summary>
/// Microsoft MSRC CVRF API v3. The updates list gives one document per month with its CurrentReleaseDate; each
/// document is fetched as JSON and every Vulnerability becomes one Advisory (AdvisoryId = CVE). Threats of Type 1 carry the
/// exploit status ("Exploited:Yes"), Type 3 the severity; Remediations of Type 2 give the KB and FixedBuild per product.
/// Cursor: ISO 8601 of the newest CurrentReleaseDate processed. First run takes the last InitialMonths months only.
/// </summary>
public sealed partial class MsrcFeed : IFeed
{
    public string Name => PsirtFeedNames.Msrc;
    public string DisplayName => "Microsoft MSRC security updates (CVRF)";
    public int IntervalMinutes => 1440;
    public string Licence => "Microsoft Security Update Guide, public API. Referenced and linked only.";
    public const string Vendor = "microsoft";
    public const string UpdatesUrl = "https://api.msrc.microsoft.com/cvrf/v3.0/updates";
    public const string CvrfUrlBase = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/";

    public int InitialMonths { get; init; } = 3;
    public int MaxDocsPerRun { get; init; } = 12;

    [GeneratedRegex(@"^\d{4}-[A-Z][a-z]{2}$")] private static partial Regex MonthlyId();

    public async Task<FeedResult> RunAsync(FeedContext ctx, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        List<MsrcUpdateDoc> docs;
        using (var list = await PsirtStore.GetJsonAsync(ctx.Http, UpdatesUrl, ct))
            docs = ParseUpdates(list.RootElement);

        var (cursor, history, historyDone) = ParseCursor(ctx.Cursor);
        string? note;
        List<MsrcUpdateDoc> due;
        if (cursor is null)
        {
            var since = now.AddMonths(-InitialMonths);
            due = docs.Where(d => d.InitialReleaseDate >= since).ToList();
            note = $"first run: monthly documents from the last {InitialMonths} months only";
        }
        else
        {
            due = docs.Where(d => d.CurrentReleaseDate > cursor).ToList();
            note = null;
        }
        due = due.OrderBy(d => d.CurrentReleaseDate ?? DateTime.MinValue).Take(MaxDocsPerRun).ToList();

        var total = 0;
        DateTime? newCursor = cursor;
        var processed = 0;
        foreach (var doc in due)
        {
            ct.ThrowIfCancellationRequested();
            ctx.Progress($"MSRC {doc.Id}");
            try
            {
                using var json = await PsirtStore.GetJsonAsync(ctx.Http, CvrfUrlBase + doc.Id, ct);
                var rows = Parse(json.RootElement, now);
                total += await PsirtStore.UpsertAsync(ctx.Db, Vendor, rows, ct);
                processed++;
                if (doc.CurrentReleaseDate is { } cr && (newCursor is null || cr > newCursor)) newCursor = cr;
            }
            catch (Exception ex) when (ex is not OperationCanceledException && processed > 0)
            {
                // resumable: keep the cursor of the documents already stored and retry the rest next run
                ctx.Log.LogWarning(ex, "MSRC document {Id} failed; will retry next run", doc.Id);
                note = (note is null ? "" : note + "; ") + $"stopped at {doc.Id}: {ex.Message}";
                break;
            }
        }
        var forwardPending = due.Count > MaxDocsPerRun - 1 && docs.Count(d => cursor is null ? d.InitialReleaseDate >= now.AddMonths(-InitialMonths) : d.CurrentReleaseDate > cursor) > due.Count;
        if (forwardPending) note = (note is null ? "" : note + "; ") + "more documents pending, continuing shortly";

        // History: once the recent months are in, walk back through older monthly documents to HistoryFloor. Old Windows
        // CVE records often say "10.0.0 < publication" instead of a build, and these documents hold the fixed build.
        var historyProcessed = 0;
        if (HistoryBackfill && !historyDone && !forwardPending)
        {
            history ??= now.AddMonths(-InitialMonths);
            var older = docs.Where(d => d.InitialReleaseDate is { } ir && ir < history && ir >= HistoryFloor)
                .OrderByDescending(d => d.InitialReleaseDate).Take(Math.Max(1, MaxDocsPerRun - processed)).ToList();
            foreach (var doc in older)
            {
                ct.ThrowIfCancellationRequested();
                ctx.Progress($"MSRC history {doc.Id}");
                try
                {
                    using var json = await PsirtStore.GetJsonAsync(ctx.Http, CvrfUrlBase + doc.Id, ct);
                    total += await PsirtStore.UpsertAsync(ctx.Db, Vendor, Parse(json.RootElement, now), ct);
                    history = doc.InitialReleaseDate;
                    historyProcessed++;
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    ctx.Log.LogWarning(ex, "MSRC history document {Id} failed; will retry next run", doc.Id);
                    note = (note is null ? "" : note + "; ") + $"history stopped at {doc.Id}: {ex.Message}";
                    break;
                }
            }
            historyDone = !docs.Any(d => d.InitialReleaseDate is { } ir && ir < history && ir >= HistoryFloor);
            note = (note is null ? "" : note + "; ") + (historyDone ? "history complete back to " + HistoryFloor.ToString("MMM yyyy") : "history back to " + history!.Value.ToString("MMM yyyy") + ", continuing shortly");
        }
        var more = forwardPending || (HistoryBackfill && !historyDone && historyProcessed > 0);
        return new FeedResult(total, FormatCursor(newCursor ?? now, history, historyDone), note ?? $"{processed} monthly documents", more);
    }

    /// <summary>Walk back through monthly documents older than the first run's window (on by default).</summary>
    public bool HistoryBackfill { get; init; } = true;
    /// <summary>The oldest monthly document fetched: April 2016, the first month the CVRF API covers in full.</summary>
    public static readonly DateTime HistoryFloor = new(2016, 4, 1, 0, 0, 0, DateTimeKind.Utc);

    /// <summary>"2026-09-25T02:43:53Z" or "2026-09-25T02:43:53Z;history=2019-03-12" or "...;history=done".</summary>
    public static (DateTime? Forward, DateTime? History, bool HistoryDone) ParseCursor(string? cursor)
    {
        if (string.IsNullOrWhiteSpace(cursor)) return (null, null, false);
        var parts = cursor.Split(';');
        var forward = PsirtStore.ParseDate(parts[0]);
        var h = parts.Skip(1).FirstOrDefault(p => p.StartsWith("history=", StringComparison.Ordinal))?["history=".Length..];
        return h == "done" ? (forward, null, true) : (forward, PsirtStore.ParseDate(h), false);
    }

    public static string FormatCursor(DateTime forward, DateTime? history, bool historyDone) =>
        forward.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'") + (historyDone ? ";history=done" : history is { } h ? ";history=" + h.ToString("yyyy-MM-dd") : "");

    public static List<MsrcUpdateDoc> ParseUpdates(JsonElement root)
    {
        var list = new List<MsrcUpdateDoc>();
        foreach (var v in PsirtStore.Arr(root, "value"))
        {
            var id = PsirtStore.Str(v, "ID");
            if (id is null || !MonthlyId().IsMatch(id)) continue;
            // CBL-Mariner release notes share the yyyy-Mon id shape ("1999-Sep", "2000-Feb") but are not Windows security updates
            var title = PsirtStore.Str(v, "DocumentTitle") ?? "";
            if (title.Contains("Mariner", StringComparison.OrdinalIgnoreCase) || title.Contains("Azure Linux", StringComparison.OrdinalIgnoreCase)) continue;
            list.Add(new MsrcUpdateDoc(id, PsirtStore.ParseDate(PsirtStore.Str(v, "InitialReleaseDate")), PsirtStore.ParseDate(PsirtStore.Str(v, "CurrentReleaseDate"))));
        }
        return list;
    }

    private static readonly string[] SeverityOrder = { "Critical", "Important", "Moderate", "Low" };

    /// <summary>One Advisory per Vulnerability in a CVRF JSON document.</summary>
    public static List<Advisory> Parse(JsonElement root, DateTime now)
    {
        var products = new Dictionary<string, string>();
        if (root.TryGetProperty("ProductTree", out var tree))
            foreach (var p in PsirtStore.Arr(tree, "FullProductName"))
            {
                var id = PsirtStore.Str(p, "ProductID");
                var name = PsirtStore.Str(p, "Value");
                if (id is not null && name is not null) products[id] = name;
            }
        DateTime? docInitial = null, docCurrent = null;
        if (root.TryGetProperty("DocumentTracking", out var tracking))
        {
            docInitial = PsirtStore.ParseDate(PsirtStore.Str(tracking, "InitialReleaseDate"));
            docCurrent = PsirtStore.ParseDate(PsirtStore.Str(tracking, "CurrentReleaseDate"));
        }

        var list = new List<Advisory>();
        foreach (var v in PsirtStore.Arr(root, "Vulnerability"))
        {
            var cve = PsirtStore.Str(v, "CVE")?.Trim();
            if (string.IsNullOrEmpty(cve)) continue;
            var adv = new Advisory
            {
                Vendor = Vendor,
                AdvisoryId = PsirtStore.Trunc(cve.ToUpperInvariant(), 64),
                Title = PsirtStore.TruncOrNull(PsirtStore.Str(v, "Title"), 500),
                Url = "https://msrc.microsoft.com/update-guide/vulnerability/" + cve.ToUpperInvariant(),
                CveIdsJson = PsirtStore.CveIdsJson(Normalizer.ExtractCveIds(cve)),
                RetrievedAt = now
            };

            var exploited = false;
            string? severity = null;
            foreach (var t in PsirtStore.Arr(v, "Threats"))
            {
                var type = PsirtStore.Int(t, "Type");
                var text = PsirtStore.Str(t, "Description");
                if (text is null) continue;
                if (type == 1 && text.Contains("Exploited:Yes", StringComparison.OrdinalIgnoreCase)) exploited = true;
                if (type == 3)
                {
                    var rank = Array.FindIndex(SeverityOrder, s => s.Equals(text.Trim(), StringComparison.OrdinalIgnoreCase));
                    if (rank >= 0 && (severity is null || rank < Array.IndexOf(SeverityOrder, severity))) severity = SeverityOrder[rank];
                }
            }
            if (severity is null)
            {
                double best = 0;
                foreach (var s in PsirtStore.Arr(v, "CVSSScoreSets"))
                    if (s.TryGetProperty("BaseScore", out var b) && b.ValueKind == JsonValueKind.Number && b.GetDouble() > best) best = b.GetDouble();
                if (best > 0) severity = best >= 9 ? "Critical" : best >= 7 ? "Important" : best >= 4 ? "Moderate" : "Low";
            }
            adv.ExploitedInTheWild = exploited;
            adv.Severity = severity;

            var rows = new List<AffectedRow>();
            var fixedProducts = new HashSet<string>();
            foreach (var r in PsirtStore.Arr(v, "Remediations"))
            {
                if (PsirtStore.Int(r, "Type") != 2) continue;
                // Description is the KB number for Windows updates; for other products it is a link label ("Release Notes")
                var desc = PsirtStore.Str(r, "Description")?.Trim();
                var kb = desc is { Length: > 0 } && desc.All(char.IsDigit) ? "KB" + desc : null;
                var build = PsirtStore.Str(r, "FixedBuild")?.Trim();
                var fixedIn = build is { Length: > 0 }
                    ? build + (kb is null ? "" : " (" + kb + ")")
                    : kb ?? desc ?? "";
                foreach (var pid in PsirtStore.StrArr(r, "ProductID"))
                {
                    if (!products.TryGetValue(pid, out var name)) continue;
                    fixedProducts.Add(pid);
                    rows.Add(new AffectedRow(name, "", fixedIn));
                    if (rows.Count >= 300) break;
                }
                if (rows.Count >= 300) break;
            }
            foreach (var ps in PsirtStore.Arr(v, "ProductStatuses"))
            {
                if (PsirtStore.Int(ps, "Type") != 3) continue; // 3 = Known Affected
                foreach (var pid in PsirtStore.StrArr(ps, "ProductID"))
                {
                    if (fixedProducts.Contains(pid) || !products.TryGetValue(pid, out var name)) continue;
                    rows.Add(new AffectedRow(name, "affected", ""));
                    if (rows.Count >= 300) break;
                }
            }
            adv.AffectedJson = PsirtStore.AffectedJson(rows);

            DateTime? first = null, last = null;
            foreach (var h in PsirtStore.Arr(v, "RevisionHistory"))
            {
                var d = PsirtStore.ParseDate(PsirtStore.Str(h, "Date"));
                if (d is null) continue;
                if (first is null || d < first) first = d;
                if (last is null || d > last) last = d;
            }
            adv.Published = first ?? PsirtStore.ParseDate(PsirtStore.Str(v, "ReleaseDate")) ?? docInitial;
            adv.Updated = last ?? docCurrent ?? adv.Published;
            list.Add(adv);
        }
        return list;
    }
}
