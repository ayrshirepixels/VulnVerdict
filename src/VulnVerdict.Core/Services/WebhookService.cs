using System.Collections.Concurrent;
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
/// Section 11.4: webhooks for verdict created, promoted and closed. One POST per event to Settings.WebhookUrl with the
/// verdict as JSON, an HMAC-SHA256 signature of the exact body in X-VulnVerdict-Signature ("sha256=&lt;hex&gt;") and the
/// event name in X-VulnVerdict-Event. Every attempt is written to WebhookDelivery. A failed delivery is retried once,
/// no sooner than <see cref="RetryDelay"/> later, by the next <see cref="FlushPendingAsync"/>.
///
/// Emitting: the evaluator and workflow call <see cref="Enqueue"/> (cheap, in-memory) after their SaveChanges; the
/// worker loop calls <see cref="FlushPendingAsync"/> once per pass, which loads the verdicts and posts. Code that already
/// holds the verdict and wants the post to happen now can call <see cref="NotifyAsync"/> directly.
/// Nothing happens while WebhookUrl is blank.
/// </summary>
public sealed class WebhookService
{
    public const string EventCreated = "verdict.created";
    public const string EventPromoted = "verdict.promoted";
    public const string EventClosed = "verdict.closed";

    public const string SignatureHeader = "X-VulnVerdict-Signature";
    public const string EventHeader = "X-VulnVerdict-Event";

    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web) { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };

    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly SettingsService _settings;
    private readonly IHttpClientFactory _http;
    private readonly ILogger<WebhookService> _log;
    private readonly ConcurrentQueue<Pending> _queue = new();

    private sealed record Pending(string Event, Guid VerdictId, int Attempt, DateTime NotBefore);

    public WebhookService(IDbContextFactory<VvDbContext> factory, SettingsService settings, IHttpClientFactory http, ILogger<WebhookService> log)
    {
        _factory = factory; _settings = settings; _http = http; _log = log;
    }

    /// <summary>How long a failed delivery waits before its single retry. 30 seconds in production; tests shorten it.</summary>
    public TimeSpan RetryDelay { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Per-request timeout for the receiver.</summary>
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(20);

    /// <summary>Queued events (including retries) not yet delivered. For diagnostics and tests.</summary>
    public int PendingCount => _queue.Count;

    /// <summary>Queue an event for the next flush. Safe to call from any thread; does not touch the database.</summary>
    public void Enqueue(string eventName, Guid verdictId) => _queue.Enqueue(new Pending(eventName, verdictId, 0, DateTime.UtcNow));

    /// <summary>
    /// Deliver every due queued event: load the verdict, post, record. Called by the worker loop once per pass.
    /// Items whose retry time has not come yet go back on the queue. Drops everything when no webhook URL is set.
    /// </summary>
    public async Task FlushPendingAsync(CancellationToken ct)
    {
        if (_queue.IsEmpty) return;
        var s = await _settings.LoadAsync(ct);
        if (string.IsNullOrWhiteSpace(s.WebhookUrl))
        {
            while (_queue.TryDequeue(out _)) { }
            return;
        }
        var now = DateTime.UtcNow;
        var later = new List<Pending>();
        var due = new List<Pending>();
        while (_queue.TryDequeue(out var p)) (p.NotBefore <= now ? due : later).Add(p);
        foreach (var p in later) _queue.Enqueue(p);
        if (due.Count == 0) return;

        await using var db = await _factory.CreateDbContextAsync(ct);
        var ids = due.Select(p => p.VerdictId).Distinct().ToList();
        var verdicts = await db.Verdicts.AsNoTracking().Where(v => ids.Contains(v.Id)).ToDictionaryAsync(v => v.Id, ct);
        foreach (var p in due)
        {
            ct.ThrowIfCancellationRequested();
            if (!verdicts.TryGetValue(p.VerdictId, out var v)) { _log.LogDebug("Webhook {Event} skipped: verdict {Id} no longer exists", p.Event, p.VerdictId); continue; }
            await DeliverAsync(p.Event, v, p.Attempt, s, ct);
        }
    }

    /// <summary>Post one event for a verdict now. On failure the single retry is queued for the next flush after <see cref="RetryDelay"/>.</summary>
    public async Task NotifyAsync(string eventName, Verdict verdict, CancellationToken ct)
    {
        var s = await _settings.LoadAsync(ct);
        if (string.IsNullOrWhiteSpace(s.WebhookUrl)) return;
        await DeliverAsync(eventName, verdict, 0, s, ct);
    }

    private async Task<bool> DeliverAsync(string eventName, Verdict verdict, int attempt, AppSettings s, CancellationToken ct)
    {
        var body = BuildPayload(eventName, verdict, s.BaseUrl, DateTime.UtcNow);
        var delivery = new WebhookDelivery { At = DateTime.UtcNow, Event = eventName, VerdictId = verdict.Id, Url = Truncate(s.WebhookUrl, 500) };
        var ok = false;
        try
        {
            var client = _http.CreateClient(Adapters.Tickets.TicketAdapterBase.HttpClientName);
            using var req = new HttpRequestMessage(HttpMethod.Post, s.WebhookUrl) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            req.Headers.TryAddWithoutValidation(EventHeader, eventName);
            if (!string.IsNullOrEmpty(s.WebhookSecret)) req.Headers.TryAddWithoutValidation(SignatureHeader, Sign(s.WebhookSecret, body));
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(Timeout);
            using var resp = await client.SendAsync(req, cts.Token);
            delivery.StatusCode = (int)resp.StatusCode;
            ok = resp.IsSuccessStatusCode;
            if (!ok)
            {
                var text = await resp.Content.ReadAsStringAsync(CancellationToken.None);
                delivery.Error = Truncate("HTTP " + (int)resp.StatusCode + (text.Length > 0 ? ": " + text.Trim() : ""), 500);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            delivery.Error = Truncate(ex is OperationCanceledException ? "Timed out after " + Timeout.TotalSeconds + " s" : ex.Message, 500);
        }

        try
        {
            await using var db = await _factory.CreateDbContextAsync(CancellationToken.None);
            db.WebhookDeliveries.Add(delivery);
            await db.SaveChangesAsync(CancellationToken.None);
        }
        catch (Exception ex) { _log.LogWarning(ex, "Webhook delivery could not be recorded"); }

        if (ok)
        {
            _log.LogInformation("Webhook {Event} for {Cve} delivered ({Status})", eventName, verdict.CveId, delivery.StatusCode);
            return true;
        }
        if (attempt == 0)
        {
            _queue.Enqueue(new Pending(eventName, verdict.Id, 1, DateTime.UtcNow + RetryDelay));
            _log.LogWarning("Webhook {Event} for {Cve} failed ({Error}); retrying once after {Delay} s", eventName, verdict.CveId, delivery.Error, RetryDelay.TotalSeconds);
        }
        else _log.LogWarning("Webhook {Event} for {Cve} failed on retry ({Error}); giving up", eventName, verdict.CveId, delivery.Error);
        return false;
    }

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

    private static string Truncate(string s, int max) => s.Length > max ? s[..max] : s;
}
