using System.Text.Json;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;

namespace VulnVerdict.Core.Feeds.Psirt;

/// <summary>
/// Streaming reader for the Debian security tracker JSON ({package: {CVE: {description, releases: {codename: {...}}}}}).
/// The file is ~75 MB; entries are handed out one CVE object at a time without loading the whole document.
/// </summary>
public static class DebianTrackerParser
{
    /// <summary>Invoke <paramref name="onEntry"/>(package, cve, entry) for every CVE object. Returns the number of entries.</summary>
    public static int Parse(Stream stream, Action<string, string, JsonElement> onEntry, int initialBufferSize = 1 << 20)
    {
        var buffer = new byte[Math.Max(initialBufferSize, 16)];
        var len = 0;
        var final = false;
        var state = new JsonReaderState(new JsonReaderOptions { AllowTrailingCommas = true, CommentHandling = JsonCommentHandling.Skip });
        string? package = null;
        var count = 0;
        while (true)
        {
            if (!final)
            {
                while (len < buffer.Length)
                {
                    var n = stream.Read(buffer, len, buffer.Length - len);
                    if (n == 0) { final = true; break; }
                    len += n;
                }
            }
            var reader = new Utf8JsonReader(buffer.AsSpan(0, len), final, state);
            var done = false;
            while (true)
            {
                var checkpoint = reader;
                if (!reader.Read())
                {
                    // in the final block a failed Read means the last token is behind us (only whitespace may remain)
                    if (final) done = true;
                    reader = checkpoint;
                    break;
                }
                if (reader.TokenType != JsonTokenType.PropertyName) continue;
                if (reader.CurrentDepth == 1) { package = reader.GetString(); continue; }
                if (reader.CurrentDepth != 2 || package is null) continue;
                var cve = reader.GetString()!;
                if (!reader.Read())
                {
                    if (final) throw new JsonException("Unexpected end of Debian security tracker JSON after " + cve);
                    reader = checkpoint; break;
                }
                if (reader.TokenType != JsonTokenType.StartObject)
                {
                    if (!reader.TrySkip()) { reader = checkpoint; break; }
                    continue;
                }
                var start = (int)reader.TokenStartIndex;
                if (!reader.TrySkip())
                {
                    if (final) throw new JsonException("Unexpected end of Debian security tracker JSON inside " + cve);
                    reader = checkpoint; break;
                }
                var end = (int)reader.BytesConsumed;
                using (var doc = JsonDocument.Parse(buffer.AsMemory(start, end - start)))
                    onEntry(package, cve, doc.RootElement);
                count++;
            }
            if (done) break;
            var consumed = (int)reader.BytesConsumed;
            state = reader.CurrentState;
            if (final && consumed >= len) break;
            if (consumed > 0)
            {
                Buffer.BlockCopy(buffer, consumed, buffer, 0, len - consumed);
                len -= consumed;
            }
            else if (final) throw new JsonException("Unexpected end of Debian security tracker JSON");
            else if (len == buffer.Length) Array.Resize(ref buffer, buffer.Length * 2);
        }
        return count;
    }
}

/// <summary>
/// Section 7: Debian security tracker (https://security-tracker.debian.org/tracker/data/json). One Advisory per CVE and
/// source package (AdvisoryId = "CVE:package") with a row per release: "open" releases are affected, "resolved" releases carry
/// fixed_version. Releases resolved with fixed_version "0" (never affected) are skipped, and CVEs with no remaining release
/// are not stored. The whole vendor set is replaced in one transaction. Cursor: the file's Last-Modified header, sent back as
/// If-Modified-Since so an unchanged file costs one request.
/// </summary>
public sealed class DebianSecurityFeed : IFeed
{
    public string Name => PsirtFeedNames.Debian;
    public string DisplayName => "Debian security tracker";
    public int IntervalMinutes => 1440;
    public string Licence => "Debian security tracker data (public). Referenced and linked only.";
    public const string Vendor = "debian";
    public const string Url = "https://security-tracker.debian.org/tracker/data/json";
    /// <summary>Tracker urgencies that are severities; "not yet assigned" and "end-of-life" are stored as no severity.</summary>
    private static readonly string[] UrgencyOrder = { "high", "medium", "low", "unimportant" };

    public async Task<FeedResult> RunAsync(FeedContext ctx, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        using var req = new HttpRequestMessage(HttpMethod.Get, Url);
        req.Headers.Accept.ParseAdd("application/json");
        if (DateTimeOffset.TryParse(ctx.Cursor, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var since))
            req.Headers.IfModifiedSince = since;
        using var resp = await ctx.Http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        if (resp.StatusCode == System.Net.HttpStatusCode.NotModified)
            return new FeedResult(0, ctx.Cursor, "not modified since " + ctx.Cursor);
        resp.EnsureSuccessStatusCode();
        var lastModified = resp.Content.Headers.LastModified ?? now;

        Directory.CreateDirectory(ctx.DataDir);
        var path = Path.Combine(ctx.DataDir, "debian-security-tracker.json");
        try
        {
            await using (var file = File.Create(path))
            await using (var body = await resp.Content.ReadAsStreamAsync(ct))
                await body.CopyToAsync(file, ct);
            ctx.Progress("Debian tracker downloaded");

            var rows = new List<Advisory>();
            var entries = 0;
            await using (var file = File.OpenRead(path))
            {
                entries = DebianTrackerParser.Parse(file, (pkg, cve, entry) =>
                {
                    var adv = ToAdvisory(pkg, cve, entry, now);
                    if (adv is not null) rows.Add(adv);
                });
            }
            if (rows.Count == 0) throw new InvalidOperationException($"Debian tracker parsed {entries} entries but produced no advisories; not replacing the stored set");
            ctx.Progress($"Debian {rows.Count} advisories");
            var count = await PsirtStore.ReplaceAsync(ctx.Db, Vendor, rows, ct);
            return new FeedResult(count, lastModified.ToString("R"), $"{entries} tracker entries, {count} stored");
        }
        finally
        {
            try { File.Delete(path); } catch (Exception ex) { ctx.Log.LogDebug(ex, "Could not delete {Path}", path); }
        }
    }

    /// <summary>One tracker entry to an Advisory, or null when no release is affected or fixed.</summary>
    public static Advisory? ToAdvisory(string package, string cve, JsonElement entry, DateTime now)
    {
        if (!cve.StartsWith("CVE-", StringComparison.OrdinalIgnoreCase)) return null;
        var rows = new List<AffectedRow>();
        string? severity = null;
        if (entry.TryGetProperty("releases", out var releases) && releases.ValueKind == JsonValueKind.Object)
        {
            foreach (var rel in releases.EnumerateObject())
            {
                var r = rel.Value;
                var status = PsirtStore.Str(r, "status") ?? "";
                var fixedVersion = PsirtStore.Str(r, "fixed_version");
                if (status.Equals("not-affected", StringComparison.OrdinalIgnoreCase)) continue;
                if (fixedVersion == "0") continue; // resolved with version 0 = never affected
                var product = package + " (" + rel.Name + ")";
                if (status.Equals("resolved", StringComparison.OrdinalIgnoreCase))
                {
                    if (string.IsNullOrEmpty(fixedVersion)) continue;
                    rows.Add(new AffectedRow(product, "", fixedVersion));
                }
                else
                {
                    var nodsa = PsirtStore.Str(r, "nodsa_reason") ?? PsirtStore.Str(r, "nodsa");
                    rows.Add(new AffectedRow(product, status + (string.IsNullOrEmpty(nodsa) ? "" : " (" + nodsa + ")"), ""));
                }
                var urgency = PsirtStore.Str(r, "urgency")?.Trim().ToLowerInvariant();
                if (urgency is not null)
                {
                    var rank = Array.IndexOf(UrgencyOrder, urgency);
                    if (rank >= 0 && (severity is null || rank < Array.IndexOf(UrgencyOrder, severity))) severity = UrgencyOrder[rank];
                }
            }
        }
        if (rows.Count == 0) return null;
        var id = cve.ToUpperInvariant();
        return new Advisory
        {
            Vendor = Vendor,
            AdvisoryId = PsirtStore.Trunc(id + ":" + package, 64),
            Title = PsirtStore.TruncOrNull(PsirtStore.Str(entry, "description"), 500),
            Url = "https://security-tracker.debian.org/tracker/" + id,
            CveIdsJson = PsirtStore.CveIdsJson(Normalizer.ExtractCveIds(id)),
            AffectedJson = PsirtStore.AffectedJson(rows),
            Severity = severity,
            ExploitedInTheWild = false,
            RetrievedAt = now
        };
    }
}
