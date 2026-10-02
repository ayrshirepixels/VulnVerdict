using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Digest;

namespace VulnVerdict.Core.Services;

public sealed record ChatFact(string Name, string Value);

/// <summary>What one chat message says, before it is shaped for Teams or Slack.</summary>
public sealed class ChatCard
{
    public string Title { get; set; } = "";
    public string? Text { get; set; }
    /// <summary>Colours the title in Teams: red for Fix today, amber for Fix this week.</summary>
    public VerdictTier? Tier { get; set; }
    public List<ChatFact> Facts { get; set; } = new();
    public string? LinkText { get; set; }
    public string? LinkUrl { get; set; }
}

/// <summary>A chat message ready to send, and the outbox rows it settles. No card means there is nothing left to say.</summary>
public sealed record ChatDelivery(List<OutboxMessage> Rows, ChatCard? Card);

/// <summary>
/// Teams and Slack messages. Outbound only: an on-prem console cannot be called back by either service, so a message
/// carries a link to the console and no buttons that post. Both are someone else's cloud, so a message names the
/// product, version and CVE and never an asset or an address, unless "include asset names" is switched on.
///
/// A verdict event is queued as a reference to the verdict (<see cref="ForVerdictEvent"/>); the card is built when it
/// is sent (<see cref="RenderAsync"/>), one per CVE however many assets it touches, from the verdicts as they are then.
/// </summary>
public static class ChatMessages
{
    public const string EventFixToday = "chat.fixtoday";
    public const string EventChanged = "chat.changed";
    public const string EventDigest = "chat.digest";
    public const string EventFeedHealth = "chat.feedhealth";
    public const string EventTest = "chat.test";

    private const int MaxNames = 5;

    private sealed record VerdictRef(Guid VerdictId, string CveId, string? Reason);

    public static bool Configured(AppSettings s) => !string.IsNullOrWhiteSpace(s.TeamsWebhookUrl) || !string.IsNullOrWhiteSpace(s.SlackWebhookUrl);

    public static string UrlFor(AppSettings s, string kind) => (kind == WebhookService.KindTeams ? s.TeamsWebhookUrl : kind == WebhookService.KindSlack ? s.SlackWebhookUrl : "").Trim();

    private static IEnumerable<string> Kinds(AppSettings s)
    {
        if (!string.IsNullOrWhiteSpace(s.TeamsWebhookUrl)) yield return WebhookService.KindTeams;
        if (!string.IsNullOrWhiteSpace(s.SlackWebhookUrl)) yield return WebhookService.KindSlack;
    }

    /// <summary>
    /// Fed by bundles carried in by hand, with no central service: the site has chosen to have no route out, so nothing
    /// is sent to Teams or Slack. Same test as the worker uses to keep the public feeds switched off.
    /// </summary>
    public static async Task<bool> AirGappedAsync(VvDbContext db, AppSettings s, CancellationToken ct = default)
    {
        if (!string.IsNullOrWhiteSpace(s.BundleUrl)) return false;
        var last = await BundleApplier.CurrentAsync(db, ct);
        return last is not null && last.Source.StartsWith("upload", StringComparison.OrdinalIgnoreCase) && DateTime.UtcNow - last.AppliedAt < BundleService.UploadedBundleWindow;
    }

    // ------------------------------------------------------------------ queueing

    /// <summary>
    /// The chat rows for one verdict event, by what is switched on in Settings: a new or newly promoted Fix today, and
    /// promotions and re-opens at Fix this week or above. "Check these" verdicts are never announced.
    /// </summary>
    public static IEnumerable<OutboxMessage> ForVerdictEvent(AppSettings s, string verdictEvent, Verdict v, DateTime now)
    {
        if (v.State != VerdictState.Open || v.Confidence == MatchConfidence.Possible) yield break;
        var changed = verdictEvent == WebhookService.EventPromoted;
        var evt = (changed || verdictEvent == WebhookService.EventCreated) && v.Tier == VerdictTier.FixToday && s.ChatNotifyFixToday ? EventFixToday
            : changed && v.Tier >= VerdictTier.FixThisWeek && s.ChatNotifyChanges ? EventChanged
            : null;
        if (evt is null) yield break;
        var payload = JsonSerializer.Serialize(new VerdictRef(v.Id, v.CveId, changed ? v.TierChangeReason : null));
        foreach (var kind in Kinds(s))
            yield return new OutboxMessage { Kind = kind, Event = evt, VerdictId = v.Id, PayloadJson = payload, CreatedAt = now, NextAttemptAt = now };
    }

    /// <summary>The daily digest as one short message: the headline and the counts, with a link to the console.</summary>
    public static IEnumerable<OutboxMessage> ForDigest(AppSettings s, DigestContent c, DateTime now)
    {
        if (!s.ChatNotifyDigest) return Array.Empty<OutboxMessage>();
        var card = new ChatCard
        {
            Title = "VulnVerdict daily digest" + (string.IsNullOrWhiteSpace(s.OrganisationName) ? "" : " for " + s.OrganisationName.Trim()),
            Text = c.Headline,
            Tier = c.FixToday.Count > 0 ? VerdictTier.FixToday : c.FixThisWeek.Count > 0 ? VerdictTier.FixThisWeek : null,
        };
        card.Facts.Add(new("Fix today", c.FixToday.Count.ToString(CultureInfo.InvariantCulture)));
        card.Facts.Add(new("Fix this week", c.FixThisWeek.Count.ToString(CultureInfo.InvariantCulture)));
        if (c.CheckThese.Count > 0) card.Facts.Add(new("Check these", c.CheckThese.Count.ToString(CultureInfo.InvariantCulture)));
        if (c.Overdue.Count > 0) card.Facts.Add(new("Overdue", c.Overdue.Count.ToString(CultureInfo.InvariantCulture)));
        card.Facts.Add(new("Next patch cycle", c.NextPatchCycleCount.ToString(CultureInfo.InvariantCulture)));
        WithLink(card, s.BaseUrl, "/", "Open VulnVerdict");
        return ForCard(s, EventDigest, card, now);
    }

    /// <summary>One row per configured destination carrying a finished card.</summary>
    public static IEnumerable<OutboxMessage> ForCard(AppSettings s, string evt, ChatCard card, DateTime now, string? onlyKind = null)
    {
        var payload = JsonSerializer.Serialize(card);
        return Kinds(s).Where(k => onlyKind is null || k == onlyKind)
            .Select(kind => new OutboxMessage { Kind = kind, Event = evt, PayloadJson = payload, CreatedAt = now, NextAttemptAt = now }).ToList();
    }

    public static void WithLink(ChatCard card, string baseUrl, string path, string text)
    {
        if (string.IsNullOrWhiteSpace(baseUrl)) return;
        card.LinkUrl = baseUrl.Trim().TrimEnd('/') + path; card.LinkText = text;
    }

    // ------------------------------------------------------------------ rendering

    /// <summary>
    /// Turn due rows for one destination into messages. Verdict events are grouped by CVE, so a CVE on two hundred
    /// endpoints is one message with a count, and are built from the verdicts as they stand now: one that was closed
    /// in the meantime is not announced.
    /// </summary>
    public static async Task<List<ChatDelivery>> RenderAsync(VvDbContext db, AppSettings s, List<OutboxMessage> rows, CancellationToken ct = default)
    {
        var result = new List<ChatDelivery>();
        var events = new List<(OutboxMessage Row, VerdictRef Ref)>();
        foreach (var row in rows)
        {
            if (row.Event is EventFixToday or EventChanged)
            {
                VerdictRef? r = null;
                try { r = JsonSerializer.Deserialize<VerdictRef>(row.PayloadJson); } catch (JsonException) { }
                if (r is null) result.Add(new ChatDelivery(new() { row }, null)); else events.Add((row, r));
            }
            else
            {
                ChatCard? card = null;
                try { card = JsonSerializer.Deserialize<ChatCard>(row.PayloadJson); } catch (JsonException) { }
                result.Add(new ChatDelivery(new() { row }, card));
            }
        }
        if (events.Count == 0) return result;

        var ids = events.Select(e => e.Ref.VerdictId).Distinct().ToList();
        var verdicts = await db.Verdicts.AsNoTracking().Include(v => v.WatchlistEntry).Include(v => v.SoftwareInstance).Include(v => v.Asset)
            .Where(v => ids.Contains(v.Id)).ToDictionaryAsync(v => v.Id, ct);
        foreach (var group in events.GroupBy(e => (e.Row.Event, e.Ref.CveId)))
        {
            var floor = group.Key.Event == EventFixToday ? VerdictTier.FixToday : VerdictTier.FixThisWeek;
            var current = group.Select(e => verdicts.GetValueOrDefault(e.Ref.VerdictId)).Where(v => v is not null && v.State == VerdictState.Open && v.Tier >= floor)
                .Select(v => v!).DistinctBy(v => v.Id).OrderByDescending(v => v.Tier).ThenBy(v => v.SlaDue).ToList();
            var groupRows = group.Select(e => e.Row).ToList();
            if (current.Count == 0) { result.Add(new ChatDelivery(groupRows, null)); continue; }
            var reason = group.Select(e => e.Ref.Reason).FirstOrDefault(r => !string.IsNullOrWhiteSpace(r));
            result.Add(new ChatDelivery(groupRows, await VerdictCardAsync(db, s, group.Key.Event, current, reason, ct)));
        }
        return result;
    }

    private static async Task<ChatCard> VerdictCardAsync(VvDbContext db, AppSettings s, string evt, List<Verdict> verdicts, string? reason, CancellationToken ct)
    {
        var lead = verdicts[0];
        // everything open for this CVE, not only the verdicts that changed just now: "how many machines" is the question
        var affected = await db.Verdicts.AsNoTracking().Where(v => v.CveId == lead.CveId && v.State == VerdictState.Open && v.Tier >= VerdictTier.NextPatchCycle)
            .Select(v => new { v.Id, v.AssetId, v.WatchlistEntryId, Asset = v.Asset != null ? v.Asset.DisplayName : null, Entry = v.WatchlistEntry != null ? v.WatchlistEntry.AssetName : null })
            .ToListAsync(ct);
        var count = Math.Max(1, affected.Select(a => a.AssetId ?? a.WatchlistEntryId ?? a.Id).Distinct().Count());
        var names = affected.Select(a => a.Asset ?? a.Entry).Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n!.Trim())
            .Concat(verdicts.Select(AssetNameOf).Where(n => n is not null).Select(n => n!))
            .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList();

        var products = verdicts.Select(ProductOf).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var reopened = reason is not null && reason.Contains("re-opened", StringComparison.OrdinalIgnoreCase);
        var card = new ChatCard
        {
            Title = (evt == EventFixToday ? lead.Tier.Plain() : (reopened ? "Re-opened as " : "Promoted to ") + lead.Tier.Plain()) + ": " + lead.CveId,
            Text = ExplanationOf(lead, names),
            Tier = lead.Tier,
        };
        card.Facts.Add(new("Product", products[0] + (products.Count > 1 ? " and " + (products.Count - 1) + " other" + (products.Count == 2 ? "" : "s") : "")));
        card.Facts.Add(new("Verdict", lead.Tier.Plain()));
        if (lead.SlaDue is { } due) card.Facts.Add(new("Fix by", TimeZoneInfo.ConvertTimeFromUtc(DateTime.SpecifyKind(due, DateTimeKind.Utc), s.ResolveTimeZone()).ToString("d MMM yyyy", CultureInfo.InvariantCulture)));
        card.Facts.Add(new("Affected assets", count.ToString(CultureInfo.InvariantCulture)));
        if (s.ChatIncludeAssetNames && names.Count > 0)
            card.Facts.Add(new("Assets", string.Join(", ", names.Take(MaxNames)) + (names.Count > MaxNames ? " and " + (names.Count - MaxNames) + " more" : "")));
        if (!string.IsNullOrWhiteSpace(reason) && (s.ChatIncludeAssetNames || !Mentions(reason!, names))) card.Facts.Add(new("Why now", reason!));
        WithLink(card, s.BaseUrl, "/verdicts/" + lead.Id, "Open in VulnVerdict");
        return card;
    }

    private static string? AssetNameOf(Verdict v)
    {
        var name = v.Asset?.DisplayName ?? v.WatchlistEntry?.AssetName;
        return string.IsNullOrWhiteSpace(name) ? null : name.Trim();
    }

    /// <summary>Product and version without the asset: from the watchlist entry or the software row, not by cutting the subject text.</summary>
    public static string ProductOf(Verdict v)
    {
        if (v.WatchlistEntry is { } e) return ((e.Vendor + " " + e.Product).Trim() + (string.IsNullOrWhiteSpace(e.Version) ? "" : " " + e.Version)).Trim();
        if (v.SoftwareInstance is { } sw) return sw.Display;
        var subject = v.Subject;
        if (AssetNameOf(v) is { } name && subject.EndsWith(" on " + name, StringComparison.Ordinal)) return subject[..^(name.Length + 4)].Trim();
        return MspReportService.StripAssetName(subject);
    }

    /// <summary>
    /// The verdict's sentence without its "product version on asset:" opening, so what is left is how it is exploited,
    /// where it is reachable and what fixes it. A compensating control is described in its owner's words, which can
    /// name a host, so that part is replaced; and if an asset name still appears, the whole explanation is dropped.
    /// </summary>
    public static string ExplanationOf(Verdict v, IReadOnlyCollection<string> assetNames)
    {
        const string fallback = "Open the verdict for the details.";
        var text = v.Sentence;
        if (v.Subject.Length > 0 && text.StartsWith(v.Subject + ": ", StringComparison.Ordinal)) text = text[(v.Subject.Length + 2)..];
        else { var colon = text.IndexOf(": ", StringComparison.Ordinal); text = colon >= 0 ? text[(colon + 2)..] : ""; }
        var lowered = text.IndexOf(" Lowered one step because ", StringComparison.Ordinal);
        if (lowered >= 0)
        {
            var check = text.IndexOf(" Check this:", lowered, StringComparison.Ordinal);
            text = text[..lowered] + " Lowered one step by a compensating control." + (check >= 0 ? text[check..] : "");
        }
        text = text.Trim();
        if (text.Length == 0 || Mentions(text, assetNames)) return fallback;
        return char.ToUpperInvariant(text[0]) + text[1..];
    }

    private static bool Mentions(string text, IReadOnlyCollection<string> assetNames) => assetNames.Any(n => n.Length >= 3 && text.Contains(n, StringComparison.OrdinalIgnoreCase));

    // ------------------------------------------------------------------ wire formats

    /// <summary>
    /// The body for a Teams "Workflows" webhook (Power Automate, "when a Teams webhook request is received"): a message
    /// with one Adaptive Card attachment. The retired Office 365 connector format is not produced.
    /// </summary>
    public static string BuildTeams(ChatCard c)
    {
        var body = new JsonArray
        {
            new JsonObject
            {
                ["type"] = "TextBlock", ["text"] = c.Title, ["weight"] = "Bolder", ["size"] = "Medium", ["wrap"] = true,
                ["color"] = c.Tier switch { VerdictTier.FixToday => "Attention", VerdictTier.FixThisWeek => "Warning", _ => "Default" }
            }
        };
        if (!string.IsNullOrWhiteSpace(c.Text)) body.Add(new JsonObject { ["type"] = "TextBlock", ["text"] = c.Text, ["wrap"] = true });
        if (c.Facts.Count > 0)
        {
            var facts = new JsonArray();
            foreach (var f in c.Facts) facts.Add(new JsonObject { ["title"] = f.Name, ["value"] = f.Value });
            body.Add(new JsonObject { ["type"] = "FactSet", ["facts"] = facts });
        }
        var card = new JsonObject
        {
            ["$schema"] = "http://adaptivecards.io/schemas/adaptive-card.json", ["type"] = "AdaptiveCard", ["version"] = "1.4", ["body"] = body
        };
        // a link, not an action that posts back: Teams cannot reach an on-prem console
        if (!string.IsNullOrWhiteSpace(c.LinkUrl))
            card["actions"] = new JsonArray { new JsonObject { ["type"] = "Action.OpenUrl", ["title"] = c.LinkText ?? "Open", ["url"] = c.LinkUrl } };
        return new JsonObject
        {
            ["type"] = "message",
            ["attachments"] = new JsonArray { new JsonObject { ["contentType"] = "application/vnd.microsoft.card.adaptive", ["contentUrl"] = null, ["content"] = card } }
        }.ToJsonString();
    }

    /// <summary>The body for a Slack incoming webhook: Block Kit blocks, with a plain "text" for notifications and old clients.</summary>
    public static string BuildSlack(ChatCard c)
    {
        var blocks = new JsonArray
        {
            new JsonObject { ["type"] = "header", ["text"] = new JsonObject { ["type"] = "plain_text", ["text"] = Limit(c.Title, 150), ["emoji"] = false } }
        };
        if (!string.IsNullOrWhiteSpace(c.Text)) blocks.Add(Section(Limit(Escape(c.Text), 3000)));
        if (c.Facts.Count > 0)
        {
            var fields = new JsonArray();
            foreach (var f in c.Facts.Take(10)) fields.Add(new JsonObject { ["type"] = "mrkdwn", ["text"] = Limit("*" + Escape(f.Name) + "*\n" + Escape(f.Value), 2000) });
            blocks.Add(new JsonObject { ["type"] = "section", ["fields"] = fields });
        }
        // a plain link rather than a button: Slack reports button clicks to the app, and there is no app to answer
        if (!string.IsNullOrWhiteSpace(c.LinkUrl)) blocks.Add(Section("<" + Escape(c.LinkUrl) + "|" + Escape(c.LinkText ?? "Open") + ">"));
        return new JsonObject { ["text"] = c.Title + (string.IsNullOrWhiteSpace(c.Text) ? "" : " - " + c.Text), ["blocks"] = blocks }.ToJsonString();

        static JsonObject Section(string mrkdwn) => new() { ["type"] = "section", ["text"] = new JsonObject { ["type"] = "mrkdwn", ["text"] = mrkdwn } };
    }

    /// <summary>Slack's three control characters; everything else is literal.</summary>
    private static string Escape(string s) => s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");

    private static string Limit(string s, int max) => s.Length > max ? s[..(max - 3)] + "..." : s;
}

/// <summary>The chat notifications that do not start from a verdict (feed health, the Test button), and the air-gap check for the Settings page.</summary>
public sealed class ChatNotificationService
{
    public const string LastFeedHealthKey = "state:chat:lastFeedHealth";

    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly SettingsService _settings;
    private readonly WebhookService _outbox;

    public ChatNotificationService(IDbContextFactory<VvDbContext> factory, SettingsService settings, WebhookService outbox)
    {
        _factory = factory; _settings = settings; _outbox = outbox;
    }

    public async Task<bool> IsAirGappedAsync(CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        return await ChatMessages.AirGappedAsync(db, await _settings.LoadAsync(ct), ct);
    }

    /// <summary>Feeds overdue by their own schedule, at most one message a day. Returns true if a message was queued.</summary>
    public async Task<bool> QueueFeedHealthAsync(IReadOnlyCollection<string> overdueFeeds, CancellationToken ct = default)
    {
        if (overdueFeeds.Count == 0) return false;
        var s = await _settings.LoadAsync(ct);
        if (!s.ChatNotifyFeedHealth || !ChatMessages.Configured(s)) return false;
        var last = await _settings.GetStateAsync(LastFeedHealthKey, ct);
        if (last is not null && DateTime.TryParse(last, null, DateTimeStyles.RoundtripKind, out var d) && DateTime.UtcNow - d < TimeSpan.FromHours(24)) return false;
        var card = new ChatCard
        {
            Title = overdueFeeds.Count == 1 ? "A feed is overdue" : overdueFeeds.Count + " feeds are overdue",
            Text = "Not updated on schedule: " + string.Join(", ", overdueFeeds) + ". Verdicts may be out of date until " + (overdueFeeds.Count == 1 ? "it recovers." : "they recover."),
            Tier = VerdictTier.FixThisWeek,
        };
        ChatMessages.WithLink(card, s.BaseUrl, "/sources", "Open Sources");
        await using var db = await _factory.CreateDbContextAsync(ct);
        db.Outbox.AddRange(ChatMessages.ForCard(s, ChatMessages.EventFeedHealth, card, DateTime.UtcNow));
        await db.SaveChangesAsync(ct);
        await _settings.SetStateAsync(LastFeedHealthKey, DateTime.UtcNow.ToString("O"), ct);
        return true;
    }

    /// <summary>The Test button: one message to one destination, now, with no retries. Returns null when it was accepted, otherwise why not.</summary>
    public async Task<string?> SendTestAsync(string kind, CancellationToken ct = default)
    {
        var s = await _settings.LoadAsync(ct);
        if (string.IsNullOrWhiteSpace(ChatMessages.UrlFor(s, kind))) return "Enter the webhook address first.";
        var card = new ChatCard { Title = "VulnVerdict test message", Text = "Messages from VulnVerdict" + (string.IsNullOrWhiteSpace(s.OrganisationName) ? "" : " for " + s.OrganisationName.Trim()) + " reach this channel." };
        ChatMessages.WithLink(card, s.BaseUrl, "/", "Open VulnVerdict");
        var row = ChatMessages.ForCard(s, ChatMessages.EventTest, card, DateTime.UtcNow, kind).Single();
        await using (var db = await _factory.CreateDbContextAsync(ct))
        {
            if (await ChatMessages.AirGappedAsync(db, s, ct)) return "The console is in air-gap mode, so nothing is sent to Teams or Slack.";
            db.Outbox.Add(row);
            await db.SaveChangesAsync(ct);
        }
        await _outbox.DeliverNowAsync(new[] { row }, ct);
        await using (var db = await _factory.CreateDbContextAsync(ct))
        {
            var sent = await db.Outbox.FirstOrDefaultAsync(o => o.Id == row.Id, ct);
            if (sent?.DeliveredAt is not null) return null;
            // a test is not worth retrying for an hour
            if (sent is not null) { db.Outbox.Remove(sent); await db.SaveChangesAsync(ct); }
            return sent?.LastError ?? "The message was not sent.";
        }
    }
}
