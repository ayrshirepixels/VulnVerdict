using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Digest;

namespace VulnVerdict.Core.Services;

/// <summary>
/// Outbound notifications: webhooks for verdict created, promoted and closed, and the Teams and Slack messages built
/// by <see cref="ChatMessages"/>. Everything goes through the outbox table (<see cref="OutboxMessage"/>), never a queue
/// in memory, so an event queued by the web process is sent by the worker and nothing is lost on a restart.
///
/// Emitting: the evaluator and workflow call <see cref="EnqueueAsync"/> before their SaveChanges, which adds the rows
/// to the same save as the change. The worker loop calls <see cref="FlushPendingAsync"/> once per pass. A failed
/// delivery is retried with exponential backoff (<see cref="RetryDelay"/> doubling up to <see cref="MaxBackoff"/>);
/// after <see cref="MaxAttempts"/> it is marked failed and shows as a health notice.
///
/// A webhook is one POST to Settings.WebhookUrl with the verdict as JSON, the event name in X-VulnVerdict-Event, and
/// HMAC-SHA256 signatures of the body (see <see cref="Sign"/> and <see cref="SignWithTimestamp"/>). Every attempt is
/// written to WebhookDelivery. Nothing is queued while no destination is set.
/// </summary>
public sealed class WebhookService
{
    public const string EventCreated = "verdict.created";
    public const string EventPromoted = "verdict.promoted";
    public const string EventClosed = "verdict.closed";

    public const string KindWebhook = "webhook";
    public const string KindTeams = "teams";
    public const string KindSlack = "slack";

    public const string SignatureHeader = "X-VulnVerdict-Signature";
    /// <summary>The signature that also covers <see cref="TimestampHeader"/>, so a captured delivery cannot be replayed later.</summary>
    public const string TimestampedSignatureHeader = "X-VulnVerdict-Signature-V2";
    public const string TimestampHeader = "X-VulnVerdict-Timestamp";
    public const string EventHeader = "X-VulnVerdict-Event";
    /// <summary>The outbox id: the same on every retry of one event, so a receiver can drop duplicates.</summary>
    public const string DeliveryHeader = "X-VulnVerdict-Delivery";

    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web) { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };
    private static readonly TimeSpan KeepDelivered = TimeSpan.FromDays(7);
    private static readonly TimeSpan KeepFailed = TimeSpan.FromDays(30);
    private const int BatchSize = 500;

    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly SettingsService _settings;
    private readonly IHttpClientFactory _http;
    private readonly ILogger<WebhookService> _log;

    public WebhookService(IDbContextFactory<VvDbContext> factory, SettingsService settings, IHttpClientFactory http, ILogger<WebhookService> log)
    {
        _factory = factory; _settings = settings; _http = http; _log = log;
    }

    /// <summary>The wait after the first failed attempt; each further failure doubles it. 30 seconds in production; tests shorten it.</summary>
    public TimeSpan RetryDelay { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>The longest wait between attempts.</summary>
    public TimeSpan MaxBackoff { get; set; } = TimeSpan.FromHours(1);

    /// <summary>Attempts before a delivery is given up: with the defaults, about an hour of trying.</summary>
    public int MaxAttempts { get; set; } = 8;

    /// <summary>Per-request timeout for the receiver.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(20);

    /// <summary>How long a delivery in progress is left alone by other processes. One that dies mid-send is retried after this.</summary>
    public TimeSpan Lease { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>The wait after attempt number <paramref name="attempts"/> failed.</summary>
    public TimeSpan Backoff(int attempts)
    {
        var factor = Math.Pow(2, Math.Clamp(attempts - 1, 0, 30));
        var wait = TimeSpan.FromTicks((long)Math.Min(RetryDelay.Ticks * factor, MaxBackoff.Ticks));
        return wait < MaxBackoff ? wait : MaxBackoff;
    }

    /// <summary>Outbox rows not yet delivered or given up. For diagnostics and tests.</summary>
    public async Task<int> PendingCountAsync(CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        return await db.Outbox.CountAsync(o => o.DeliveredAt == null && o.FailedAt == null, ct);
    }

    // ------------------------------------------------------------------ enqueue

    /// <summary>
    /// Add the outbox rows for these verdict events to <paramref name="db"/>, to be written by the caller's own
    /// SaveChanges together with the change itself. Call it after the verdicts have their new values and before saving.
    /// One webhook row per event while a webhook URL is set; Teams and Slack rows for the events switched on in Settings.
    /// </summary>
    public async Task<List<OutboxMessage>> EnqueueAsync(VvDbContext db, IReadOnlyCollection<(string Event, Guid VerdictId)> events, CancellationToken ct = default)
    {
        var rows = new List<OutboxMessage>();
        if (events.Count == 0) return rows;
        var s = await _settings.LoadAsync(ct);
        var webhook = !string.IsNullOrWhiteSpace(s.WebhookUrl);
        if (!webhook && !ChatMessages.Configured(s)) return rows;
        var now = DateTime.UtcNow;
        foreach (var (evt, id) in events.Distinct())
        {
            var v = await db.Verdicts.FindAsync(new object[] { id }, ct);
            if (v is null) continue;
            if (webhook)
                rows.Add(new OutboxMessage { Kind = KindWebhook, Event = evt, VerdictId = v.Id, PayloadJson = BuildPayload(evt, v, s.BaseUrl, now), CreatedAt = now, NextAttemptAt = now });
            rows.AddRange(ChatMessages.ForVerdictEvent(s, evt, v, now));
        }
        db.Outbox.AddRange(rows);
        return rows;
    }

    // ------------------------------------------------------------------ deliver

    /// <summary>
    /// Deliver every due outbox row. Called by the worker loop once per pass. Returns one line for each delivery given
    /// up in this pass, for the administrator alert.
    /// </summary>
    public async Task<IReadOnlyList<string>> FlushPendingAsync(CancellationToken ct)
    {
        await using (var db = await _factory.CreateDbContextAsync(ct))
        {
            var now = DateTime.UtcNow;
            var delivered = now - KeepDelivered; var failed = now - KeepFailed;
            await db.Outbox.Where(o => (o.DeliveredAt != null && o.DeliveredAt < delivered) || (o.FailedAt != null && o.FailedAt < failed)).ExecuteDeleteAsync(ct);
        }
        return await DeliverAsync(null, ct);
    }

    /// <summary>
    /// Try these rows now instead of waiting for the worker (a helpdesk should hear about a closed verdict straight
    /// away, and the Test button wants an answer). Safe alongside the worker: a row is claimed before it is sent.
    /// </summary>
    public async Task DeliverNowAsync(IEnumerable<OutboxMessage> rows, CancellationToken ct = default)
    {
        var ids = rows.Select(r => r.Id).Where(id => id > 0).ToList();
        if (ids.Count == 0) return;
        try { await DeliverAsync(ids, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        // the change that queued these is already saved and the rows are safe in the outbox: the worker will send them
        catch (Exception ex) { _log.LogWarning(ex, "Immediate delivery failed; left for the worker"); }
    }

    private async Task<IReadOnlyList<string>> DeliverAsync(List<long>? only, CancellationToken ct)
    {
        var gaveUp = new List<string>();
        await using var db = await _factory.CreateDbContextAsync(ct);
        var now = DateTime.UtcNow;
        var due = db.Outbox.Where(o => o.DeliveredAt == null && o.FailedAt == null && o.NextAttemptAt <= now);
        if (only is not null) due = due.Where(o => only.Contains(o.Id));
        var rows = await due.OrderBy(o => o.Id).Take(BatchSize).ToListAsync(ct);
        if (rows.Count == 0) return gaveUp;
        var s = await _settings.LoadAsync(ct);

        foreach (var row in rows.Where(r => r.Kind == KindWebhook))
        {
            ct.ThrowIfCancellationRequested();
            // the destination was removed after the event was queued: nothing to send it to
            if (string.IsNullOrWhiteSpace(s.WebhookUrl)) { await DropAsync(db, new[] { row }, ct); continue; }
            if (!await ClaimAsync(db, row, ct)) continue;
            var (error, retryAfter) = await PostWebhookAsync(row, s, ct);
            Complete(row, error, retryAfter, gaveUp);
            await db.SaveChangesAsync(CancellationToken.None);
        }

        var chat = rows.Where(r => r.Kind != KindWebhook).ToList();
        if (chat.Count > 0)
        {
            var airGapped = await ChatMessages.AirGappedAsync(db, s, ct);
            foreach (var kind in chat.GroupBy(r => r.Kind))
            {
                var url = ChatMessages.UrlFor(s, kind.Key);
                if (airGapped || string.IsNullOrWhiteSpace(url))
                {
                    _log.LogInformation("{Count} {Kind} message(s) dropped: {Why}", kind.Count(), kind.Key, airGapped ? "the console is in air-gap mode" : "no webhook address is set");
                    await DropAsync(db, kind, ct);
                    continue;
                }
                foreach (var message in await ChatMessages.RenderAsync(db, s, kind.ToList(), ct))
                {
                    ct.ThrowIfCancellationRequested();
                    // nothing left to say: the verdict was closed or removed before the message went out
                    if (message.Card is null) { await DropAsync(db, message.Rows, ct); continue; }
                    var claimed = new List<OutboxMessage>();
                    foreach (var row in message.Rows) if (await ClaimAsync(db, row, ct)) claimed.Add(row);
                    if (claimed.Count == 0) continue;
                    var body = kind.Key == KindTeams ? ChatMessages.BuildTeams(message.Card) : ChatMessages.BuildSlack(message.Card);
                    var (error, retryAfter, _) = await SendAsync(url, body, null, true, ct);
                    if (error is null) _log.LogInformation("{Kind} message {Event} delivered", kind.Key, claimed[0].Event);
                    else _log.LogWarning("{Kind} message {Event} failed ({Error})", kind.Key, claimed[0].Event, error);
                    foreach (var row in claimed) Complete(row, error, retryAfter, gaveUp);
                    await db.SaveChangesAsync(CancellationToken.None);
                }
            }
        }
        return gaveUp.Distinct().ToList();
    }

    /// <summary>Delete rows that will never be sent. A plain DELETE, so it does not matter if another process got there first.</summary>
    private static Task DropAsync(VvDbContext db, IEnumerable<OutboxMessage> rows, CancellationToken ct)
    {
        var ids = rows.Select(r => r.Id).ToList();
        return db.Outbox.Where(o => ids.Contains(o.Id) && o.DeliveredAt == null).ExecuteDeleteAsync(ct);
    }

    /// <summary>
    /// Take a row for this process: one UPDATE that only succeeds if nobody else has started an attempt since it was
    /// read. Counts the attempt and pushes the next one past the lease, so a process that dies mid-send does not lose it.
    /// </summary>
    private async Task<bool> ClaimAsync(VvDbContext db, OutboxMessage row, CancellationToken ct)
    {
        var id = row.Id; var attempts = row.Attempts; var until = DateTime.UtcNow + Lease;
        var taken = await db.Outbox.Where(o => o.Id == id && o.Attempts == attempts && o.DeliveredAt == null && o.FailedAt == null)
            .ExecuteUpdateAsync(u => u.SetProperty(o => o.Attempts, attempts + 1).SetProperty(o => o.NextAttemptAt, until), ct);
        if (taken != 1) return false;
        row.Attempts = attempts + 1; row.NextAttemptAt = until;
        return true;
    }

    private void Complete(OutboxMessage row, string? error, TimeSpan? retryAfter, List<string> gaveUp)
    {
        var now = DateTime.UtcNow;
        if (error is null) { row.DeliveredAt = now; row.LastError = null; return; }
        row.LastError = Truncate(error, 500);
        if (row.Attempts >= MaxAttempts)
        {
            row.FailedAt = now;
            gaveUp.Add(Describe(row.Kind) + " (" + row.Event + ") given up after " + row.Attempts + " attempts: " + row.LastError);
            return;
        }
        var wait = Backoff(row.Attempts);
        // a receiver that says when to come back (HTTP 429) is taken at its word, within the cap
        if (retryAfter is { } asked && asked > wait) wait = asked < MaxBackoff ? asked : MaxBackoff;
        row.NextAttemptAt = now + wait;
    }

    private async Task<(string? Error, TimeSpan? RetryAfter)> PostWebhookAsync(OutboxMessage row, AppSettings s, CancellationToken ct)
    {
        var body = row.PayloadJson;
        var delivery = new WebhookDelivery { At = DateTime.UtcNow, Event = row.Event, VerdictId = row.VerdictId ?? Guid.Empty, Url = Truncate(s.WebhookUrl, 500) };
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        var headers = new List<(string, string)> { (EventHeader, row.Event), (DeliveryHeader, row.Id.ToString(CultureInfo.InvariantCulture)), (TimestampHeader, timestamp) };
        if (!string.IsNullOrEmpty(s.WebhookSecret))
        {
            headers.Add((SignatureHeader, Sign(s.WebhookSecret, body)));
            headers.Add((TimestampedSignatureHeader, SignWithTimestamp(s.WebhookSecret, timestamp, body)));
        }
        var (error, retryAfter, status) = await SendAsync(s.WebhookUrl, body, headers, false, ct);
        delivery.StatusCode = status; delivery.Error = error;
        try
        {
            await using var db = await _factory.CreateDbContextAsync(CancellationToken.None);
            db.WebhookDeliveries.Add(delivery);
            await db.SaveChangesAsync(CancellationToken.None);
        }
        catch (Exception ex) { _log.LogWarning(ex, "Webhook delivery could not be recorded"); }

        if (error is null) _log.LogInformation("Webhook {Event} delivered ({Status})", row.Event, status);
        else if (row.Attempts >= MaxAttempts) _log.LogWarning("Webhook {Event} failed on attempt {Attempt} ({Error}); giving up", row.Event, row.Attempts, error);
        else _log.LogWarning("Webhook {Event} failed on attempt {Attempt} ({Error}); retrying after {Delay} s", row.Event, row.Attempts, error, Backoff(row.Attempts).TotalSeconds);
        return (error, retryAfter);
    }

    /// <summary>One POST. The error text never contains the address: a Teams or Slack webhook URL is itself the credential.</summary>
    private async Task<(string? Error, TimeSpan? RetryAfter, int? Status)> SendAsync(string url, string body, List<(string Name, string Value)>? headers, bool httpsOnly, CancellationToken ct)
    {
        try
        {
            if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttps && (httpsOnly || uri.Scheme != Uri.UriSchemeHttp)))
                return (httpsOnly ? "The webhook address must start with https://" : "The webhook address is not a valid http(s) URL", null, null);
            var client = _http.CreateClient(Adapters.Tickets.TicketAdapterBase.HttpClientName);
            using var req = new HttpRequestMessage(HttpMethod.Post, uri) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            foreach (var (name, value) in headers ?? new()) req.Headers.TryAddWithoutValidation(name, value);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(Timeout);
            using var resp = await client.SendAsync(req, cts.Token);
            if (resp.IsSuccessStatusCode) return (null, null, (int)resp.StatusCode);
            var text = await resp.Content.ReadAsStringAsync(CancellationToken.None);
            var retryAfter = resp.Headers.RetryAfter is { } ra ? ra.Delta ?? (ra.Date is { } at ? at - DateTimeOffset.UtcNow : null) : null;
            // What the receiver replied goes to the log, not into the error that the health banner and the administrator
            // alert show: the address is whatever was typed in Settings, and its reply is not for every signed-in user.
            if (text.Length > 0) _log.LogWarning("Receiver replied HTTP {Status}: {Body}", (int)resp.StatusCode, Truncate(text.Trim(), 500));
            return ("HTTP " + (int)resp.StatusCode + " (" + resp.StatusCode + ")", retryAfter, (int)resp.StatusCode);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            return (Truncate(ex is OperationCanceledException ? "Timed out after " + Timeout.TotalSeconds + " s" : ex.Message, 500), null, null);
        }
    }

    // ------------------------------------------------------------------ health

    /// <summary>
    /// Destinations that are not getting their notifications: something given up in the last week, or failing three
    /// times running, with nothing delivered since. Shown as a banner by <see cref="HealthNotices"/>.
    /// </summary>
    public static async Task<List<HealthNotices.Notice>> FailureNoticesAsync(IDbContextFactory<VvDbContext> factory, CancellationToken ct = default)
    {
        var list = new List<HealthNotices.Notice>();
        await using var db = await factory.CreateDbContextAsync(ct);
        var since = DateTime.UtcNow.AddDays(-7);
        var troubled = await db.Outbox.AsNoTracking()
            .Where(o => (o.FailedAt != null && o.FailedAt >= since) || (o.DeliveredAt == null && o.FailedAt == null && o.Attempts >= 3 && o.LastError != null))
            .Select(o => new { o.Id, o.Kind, o.FailedAt, o.LastError }).ToListAsync(ct);
        foreach (var kind in troubled.GroupBy(o => o.Kind))
        {
            var kindName = kind.Key;
            var retrying = kind.Count(o => o.FailedAt == null);
            var gaveUp = kind.Count() - retrying;
            // nothing still failing and one got through after the last give-up: the destination works again
            var lastGiveUp = kind.Max(o => o.FailedAt);
            if (retrying == 0 && await db.Outbox.AnyAsync(o => o.Kind == kindName && o.DeliveredAt != null && o.DeliveredAt > lastGiveUp, ct)) continue;
            var counts = (gaveUp > 0 ? gaveUp + " given up" : "") + (gaveUp > 0 && retrying > 0 ? ", " : "") + (retrying > 0 ? retrying + " still being retried" : "");
            var error = (kind.OrderByDescending(o => o.Id).First().LastError ?? "unknown error").TrimEnd().TrimEnd('.');
            list.Add(new HealthNotices.Notice(true, Describe(kindName) + "s are not being delivered (" + counts + "): " + error + ". Check the address under Settings.", "/settings"));
        }
        return list;
    }

    private static string Describe(string kind) => kind switch { KindTeams => "Teams message", KindSlack => "Slack message", _ => "Webhook" };

    // ------------------------------------------------------------------ payload and signatures

    /// <summary>The JSON body: {event, sentAt, verdict:{id, cveId, subject, verdict, rule, confidence, state, slaDue, sentence, fixedIn, url}}.</summary>
    public static string BuildPayload(string eventName, Verdict v, string baseUrl, DateTime sentAtUtc) => JsonSerializer.Serialize(new
    {
        @event = eventName,
        sentAt = sentAtUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"),
        verdict = new
        {
            id = v.Id,
            cveId = v.CveId,
            subject = v.Subject,
            verdict = v.Tier.Plain(),
            rule = v.RuleNumber,
            confidence = v.Confidence.ToString(),
            state = v.State.ToString(),
            slaDue = v.SlaDue?.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            sentence = v.Sentence,
            fixedIn = v.FixedIn,
            url = DigestService.Link(baseUrl, v.Id)
        }
    }, JsonOpts);

    /// <summary>"sha256=&lt;lower-case hex HMAC-SHA256 of the UTF-8 body&gt;". Receivers recompute this over the raw request body.</summary>
    public static string Sign(string secret, string body) =>
        "sha256=" + Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(body))).ToLowerInvariant();

    /// <summary>
    /// "sha256=&lt;lower-case hex HMAC-SHA256 of timestamp + "." + body&gt;", where timestamp is the X-VulnVerdict-Timestamp
    /// header exactly as sent (Unix seconds). Receivers recompute it and refuse timestamps more than a few minutes old.
    /// </summary>
    public static string SignWithTimestamp(string secret, string timestamp, string body) => Sign(secret, timestamp + "." + body);

    private static string Truncate(string s, int max) => s.Length > max ? s[..max] : s;
}
