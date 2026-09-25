using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Feeds.Psirt;

/// <summary>Vendor PSIRT feed names.</summary>
public static class PsirtFeedNames
{
    public const string Fortinet = "psirt-fortinet";
    public const string Msrc = "psirt-msrc";
    public const string Cisco = "psirt-cisco";
    public const string Ubuntu = "psirt-ubuntu";
    public const string Debian = "psirt-debian";
    public const string RedHat = "psirt-redhat";
    public const string Vmware = "psirt-vmware";
}

/// <summary>One row of <see cref="Advisory.AffectedJson"/>: the product and the affected and fixed versions exactly as the vendor states them.</summary>
public sealed record AffectedRow(string Product, string Affected, string FixedIn);

/// <summary>Shared storage and parsing helpers for the vendor PSIRT feeds.</summary>
public static partial class PsirtStore
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    /// <summary>Serialise affected rows as [{product, affected, fixedIn}].</summary>
    public static string AffectedJson(IEnumerable<AffectedRow> rows) => JsonSerializer.Serialize(rows.Distinct().ToList(), JsonOpts);

    public static List<AffectedRow> ReadAffected(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return new();
        try { return JsonSerializer.Deserialize<List<AffectedRow>>(json, JsonOpts) ?? new(); }
        catch (JsonException) { return new(); }
    }

    public static string CveIdsJson(IEnumerable<string> ids) =>
        JsonSerializer.Serialize(ids.Select(i => i.Trim().ToUpperInvariant()).Where(i => i.Length > 0).Distinct().OrderBy(i => i, StringComparer.Ordinal).ToList());

    public static List<string> ReadCveIds(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return new();
        try { return JsonSerializer.Deserialize<List<string>>(json) ?? new(); }
        catch (JsonException) { return new(); }
    }

    public static string Trunc(string? s, int max) => s is null ? "" : (s.Length <= max ? s : s[..max]);
    public static string? TruncOrNull(string? s, int max) => string.IsNullOrWhiteSpace(s) ? null : Trunc(s.Trim(), max);

    [GeneratedRegex(@"([+-]\d{2})(\d{2})$")] private static partial Regex OffsetNoColon();

    /// <summary>Parse a vendor date. Tries the exact formats first, then a general invariant parse. Result is UTC.</summary>
    public static DateTime? ParseDate(string? s, params string[] exactFormats)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        s = OffsetNoColon().Replace(s.Trim(), "$1:$2");
        const DateTimeStyles styles = DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal | DateTimeStyles.AllowWhiteSpaces;
        foreach (var f in exactFormats)
            if (DateTime.TryParseExact(s, f, CultureInfo.InvariantCulture, styles, out var d)) return Sane(d);
        if (DateTime.TryParse(s, CultureInfo.InvariantCulture, styles, out var g)) return Sane(g);
        return null;
    }

    private static DateTime? Sane(DateTime d) => d.Year < 1990 ? null : d;

    [GeneratedRegex(@"<(script|style)[^>]*>.*?</\1>", RegexOptions.IgnoreCase | RegexOptions.Singleline)] private static partial Regex ScriptStyle();
    [GeneratedRegex(@"<[^>]+>")] private static partial Regex Tag();
    [GeneratedRegex(@"\s+")] private static partial Regex Ws();

    /// <summary>HTML fragment to plain text: scripts and styles removed, tags stripped, entities decoded, whitespace collapsed.</summary>
    public static string HtmlText(string? html)
    {
        if (string.IsNullOrEmpty(html)) return "";
        var t = ScriptStyle().Replace(html, " ");
        t = Tag().Replace(t, " ");
        t = WebUtility.HtmlDecode(t);
        return Ws().Replace(t, " ").Trim();
    }

    [GeneratedRegex(@"exploited in the wild|being (?:actively )?exploited|actively exploited|active exploitation|attempted exploitation|in-the-wild exploitation|exploitation (?:has been|was|is being) (?:observed|detected|reported|seen)|aware of (?:an instance|instances|reports|a report|attempted|active|successful|limited|ongoing|in-the-wild|of)?[^.<]{0,80}?exploit|exploited:\s*yes", RegexOptions.IgnoreCase)]
    private static partial Regex ExploitationRx();
    [GeneratedRegex(@"\b(?:not|no|never|unaware|isn't|aren't|hasn't|haven't|without)\b", RegexOptions.IgnoreCase)] private static partial Regex NegationRx();

    /// <summary>
    /// True when the text states the issue is exploited in the wild ("exploited in the wild", "aware of an instance where this
    /// vulnerability was exploited", "Exploited:Yes"). A negation within the 40 characters before the phrase ("is not aware of
    /// any instance ...") cancels the match.
    /// </summary>
    public static bool ExploitationStated(string? text)
    {
        if (string.IsNullOrEmpty(text)) return false;
        // MSRC threat text "Publicly Disclosed:No;Exploited:Yes;..." is a flag, not prose: no negation scan
        if (text.Contains("Exploited:Yes", StringComparison.OrdinalIgnoreCase)) return true;
        foreach (Match m in ExploitationRx().Matches(text))
        {
            var start = Math.Max(0, m.Index - 40);
            var before = text.Substring(start, m.Index - start);
            if (NegationRx().IsMatch(before)) continue;
            return true;
        }
        return false;
    }

    /// <summary>
    /// Insert or update advisories by (Vendor, AdvisoryId) in one transaction. Idempotent. Null incoming Title, Url, dates,
    /// AffectedJson and Severity keep the stored value; an empty CVE list keeps a stored non-empty list.
    /// </summary>
    public static async Task<int> UpsertAsync(VvDbContext db, string vendor, IEnumerable<Advisory> rows, CancellationToken ct)
    {
        var unique = rows.Where(r => !string.IsNullOrEmpty(r.AdvisoryId)).GroupBy(r => r.AdvisoryId).Select(g => g.Last()).ToList();
        if (unique.Count == 0) return 0;
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        foreach (var chunk in unique.Chunk(500))
        {
            var ids = chunk.Select(r => r.AdvisoryId).ToList();
            var existing = await db.Advisories.Where(a => a.Vendor == vendor && ids.Contains(a.AdvisoryId)).ToDictionaryAsync(a => a.AdvisoryId, ct);
            foreach (var r in chunk)
            {
                r.Vendor = vendor;
                if (existing.TryGetValue(r.AdvisoryId, out var e)) Merge(r, e);
                else db.Advisories.Add(r);
            }
            await db.SaveChangesAsync(ct);
            db.ChangeTracker.Clear();
        }
        await tx.CommitAsync(ct);
        return unique.Count;
    }

    private static void Merge(Advisory from, Advisory to)
    {
        to.Title = from.Title ?? to.Title;
        to.Url = from.Url ?? to.Url;
        to.Published = from.Published ?? to.Published;
        to.Updated = from.Updated ?? to.Updated;
        if (from.CveIdsJson is not (null or "" or "[]") || string.IsNullOrEmpty(to.CveIdsJson)) to.CveIdsJson = from.CveIdsJson;
        to.AffectedJson = from.AffectedJson ?? to.AffectedJson;
        to.Severity = from.Severity ?? to.Severity;
        to.ExploitedInTheWild = from.ExploitedInTheWild;
        to.RetrievedAt = from.RetrievedAt;
    }

    /// <summary>Replace every advisory of one vendor in a single transaction (whole-set feeds such as Debian).</summary>
    public static async Task<int> ReplaceAsync(VvDbContext db, string vendor, IEnumerable<Advisory> rows, CancellationToken ct)
    {
        var unique = rows.Where(r => !string.IsNullOrEmpty(r.AdvisoryId)).DistinctBy(r => r.AdvisoryId).ToList();
        db.ChangeTracker.AutoDetectChangesEnabled = false;
        try
        {
            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await db.Advisories.Where(a => a.Vendor == vendor).ExecuteDeleteAsync(ct);
            foreach (var chunk in unique.Chunk(5000))
            {
                foreach (var r in chunk) r.Vendor = vendor;
                db.Advisories.AddRange(chunk);
                await db.SaveChangesAsync(ct);
                db.ChangeTracker.Clear();
            }
            await tx.CommitAsync(ct);
        }
        finally { db.ChangeTracker.AutoDetectChangesEnabled = true; }
        return unique.Count;
    }

    // ---- JSON helpers -------------------------------------------------------------------------------------------

    public static string? Str(JsonElement e, string name)
    {
        if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(name, out var v)) return null;
        return Val(v);
    }

    /// <summary>String value of an element; MSRC wraps strings as {"Value": "..."}.</summary>
    public static string? Val(JsonElement v) => v.ValueKind switch
    {
        JsonValueKind.String => v.GetString(),
        JsonValueKind.Number => v.GetRawText(),
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        JsonValueKind.Object when v.TryGetProperty("Value", out var inner) => Val(inner),
        _ => null
    };

    public static IEnumerable<JsonElement> Arr(JsonElement e, string name)
    {
        if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(name, out var v)) yield break;
        if (v.ValueKind == JsonValueKind.Array) foreach (var x in v.EnumerateArray()) yield return x;
        else if (v.ValueKind == JsonValueKind.Object) yield return v;
    }

    public static IEnumerable<string> StrArr(JsonElement e, string name) => Arr(e, name).Select(Val).Where(s => !string.IsNullOrWhiteSpace(s))!;

    public static int? Int(JsonElement e, string name)
    {
        if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(name, out var v)) return null;
        if (v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var i)) return i;
        if (v.ValueKind == JsonValueKind.String && int.TryParse(v.GetString(), out var j)) return j;
        return null;
    }

    /// <summary>Send a GET with an Accept header and return the parsed JSON document.</summary>
    public static async Task<JsonDocument> GetJsonAsync(HttpClient http, string url, CancellationToken ct, string accept = "application/json", string? bearer = null)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Accept.ParseAdd(accept);
        if (bearer is not null) req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", bearer);
        using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        resp.EnsureSuccessStatusCode();
        await using var stream = await resp.Content.ReadAsStreamAsync(ct);
        return await JsonDocument.ParseAsync(stream, cancellationToken: ct);
    }
}
