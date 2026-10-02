using System.Buffers.Binary;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Core.Digest;

public enum DigestActionKind { Done = 1, Snooze = 2 }

/// <summary>The Done and Snooze addresses for one digest item.</summary>
public sealed record DigestActionLinks(string Done, string Snooze);

/// <summary>What a digest link token says once its signature has been checked.</summary>
public sealed record DigestActionToken(Guid DigestId, Guid VerdictId, DigestActionKind Action, ulong StateVersion, DateTime ExpiresUtc);

/// <summary>
/// Signs and reads the tokens behind the digest email's Done and Snooze links. A token is an ASP.NET Data Protection
/// payload under its own purpose, so nothing else the console signs can be passed off as one. It names the digest it
/// was sent in, the verdict, the one action it allows, the verdict's state and tier as they were when the digest was
/// built, and when it stops working. The digest is one email to every recipient, so the token is bound to the digest,
/// not to a person.
/// </summary>
public sealed class DigestActionTokens
{
    public const string Purpose = "VulnVerdict.DigestAction.v1";
    public const string Path = "/digest/action";
    public static readonly TimeSpan Lifetime = TimeSpan.FromDays(7);

    private const byte Version = 1;
    private const int Length = 1 + 16 + 16 + 1 + 8 + 8;

    private readonly IDataProtector _protector;

    public DigestActionTokens(IDataProtectionProvider dp) => _protector = dp.CreateProtector(Purpose);

    /// <summary>
    /// The verdict's workflow state and tier, and when each last changed. A token carries this as it was when the
    /// digest was built; any later change (done, snoozed, re-opened, promoted, demoted) gives a different value.
    /// </summary>
    public static ulong StateVersion(Verdict v)
    {
        var text = (int)v.State + "|" + (int)v.Tier + "|" + (v.StateChangedAt?.Ticks ?? 0) + "|" + (v.TierChangedAt?.Ticks ?? 0);
        return BinaryPrimitives.ReadUInt64BigEndian(SHA256.HashData(Encoding.ASCII.GetBytes(text)));
    }

    public string Create(Guid digestId, Verdict v, DigestActionKind action, DateTime nowUtc)
    {
        var raw = new byte[Length];
        raw[0] = Version;
        digestId.TryWriteBytes(raw.AsSpan(1, 16));
        v.Id.TryWriteBytes(raw.AsSpan(17, 16));
        raw[33] = (byte)action;
        BinaryPrimitives.WriteUInt64BigEndian(raw.AsSpan(34, 8), StateVersion(v));
        BinaryPrimitives.WriteInt64BigEndian(raw.AsSpan(42, 8), new DateTimeOffset(DateTime.SpecifyKind(nowUtc, DateTimeKind.Utc) + Lifetime).ToUnixTimeSeconds());
        return Base64Url.EncodeToString(_protector.Protect(raw));
    }

    public DigestActionLinks Links(string baseUrl, Guid digestId, Verdict v, DateTime nowUtc)
    {
        var address = baseUrl.Trim().TrimEnd('/') + Path + "?t=";
        return new DigestActionLinks(address + Create(digestId, v, DigestActionKind.Done, nowUtc), address + Create(digestId, v, DigestActionKind.Snooze, nowUtc));
    }

    /// <summary>Null unless the token was issued by this console and is intact. Expiry is the caller's to check: an expired token still says which verdict it was for.</summary>
    public DigestActionToken? Read(string? token)
    {
        if (string.IsNullOrWhiteSpace(token) || token.Length > 1024) return null;
        try
        {
            var raw = _protector.Unprotect(Base64Url.DecodeFromChars(token.Trim()));
            if (raw.Length != Length || raw[0] != Version) return null;
            var action = (DigestActionKind)raw[33];
            if (action is not (DigestActionKind.Done or DigestActionKind.Snooze)) return null;
            return new DigestActionToken(new Guid(raw.AsSpan(1, 16)), new Guid(raw.AsSpan(17, 16)), action, BinaryPrimitives.ReadUInt64BigEndian(raw.AsSpan(34, 8)),
                DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadInt64BigEndian(raw.AsSpan(42, 8))).UtcDateTime);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException) { return null; }
    }
}

public enum DigestActionStatus
{
    /// <summary>The link is good and the verdict is as it was: show the confirmation.</summary>
    Ready,
    /// <summary>The action was carried out (only ever from a confirmation).</summary>
    Performed,
    /// <summary>Not a token this console issued, or for a digest or verdict that no longer exists.</summary>
    Invalid,
    Expired,
    /// <summary>The verdict's state or tier changed after the digest was built.</summary>
    Changed,
    /// <summary>Digest links are switched off in Settings.</summary>
    Disabled
}

/// <summary>What the confirmation page shows.</summary>
public sealed record DigestActionResult(DigestActionStatus Status, DigestActionKind Action = DigestActionKind.Done, Guid? VerdictId = null, string? CveId = null,
    string? Sentence = null, VerdictTier Tier = VerdictTier.NotAffected, DateTime? SlaDue = null, string? DigestLabel = null, DateTime? SnoozedUntil = null);

/// <summary>
/// The digest email's Done and Snooze links. Opening a link only looks (<see cref="PreviewAsync"/>): mail scanners
/// and link previewers follow links, so nothing may change on a GET. The change happens in <see cref="ConfirmAsync"/>,
/// behind the confirmation page's button. Either way the token is the authority: nobody is signed in.
/// </summary>
public sealed class DigestActionService
{
    public const int SnoozeDays = 7;

    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly SettingsService _settings;
    private readonly VerdictWorkflow _workflow;
    private readonly DigestActionTokens _tokens;

    public DigestActionService(IDbContextFactory<VvDbContext> factory, SettingsService settings, VerdictWorkflow workflow, DigestActionTokens tokens)
    {
        _factory = factory; _settings = settings; _workflow = workflow; _tokens = tokens;
    }

    /// <summary>"digest 3f2a91c4": how a digest is named in history and the audit log.</summary>
    public static string DigestName(Guid digestId) => "digest " + digestId.ToString("N")[..8];

    /// <summary>Check a link and describe what it would do. Reads only.</summary>
    public async Task<DigestActionResult> PreviewAsync(string? token, CancellationToken ct = default) => (await CheckAsync(token, ct)).Result;

    /// <summary>
    /// Carry out the link's action, if it is still good. Recorded in the verdict's history and the audit log as done
    /// by "digest link (digest N)", with the address it came from.
    /// </summary>
    public async Task<DigestActionResult> ConfirmAsync(string? token, string? remoteAddress, CancellationToken ct = default)
    {
        var (result, parsed) = await CheckAsync(token, ct);
        if (result.Status != DigestActionStatus.Ready || parsed is null) return result;
        var name = DigestName(parsed.DigestId);
        var actor = "digest link (" + name + ")";
        DateTime? until = null;
        if (parsed.Action == DigestActionKind.Done)
            await _workflow.CloseAsync(parsed.VerdictId, actor, "marked done via digest link (" + name + ")", ct);
        else
        {
            until = DateTime.UtcNow.AddDays(SnoozeDays);
            await _workflow.SnoozeAsync(parsed.VerdictId, actor, until.Value, "snoozed " + SnoozeDays + " days via digest link (" + name + ")", ct);
        }
        await using (var db = await _factory.CreateDbContextAsync(ct))
        {
            // nobody was signed in, so the address the confirmation came from is kept next to the workflow's own entry
            db.Audit.Add(new AuditEntry
            {
                At = DateTime.UtcNow, Actor = actor, Action = "digest.link", Target = result.CveId + " / " + parsed.VerdictId,
                After = (parsed.Action == DigestActionKind.Done ? "done" : "snoozed " + SnoozeDays + " days") + " via digest link (" + result.DigestLabel + "), confirmed from " + (string.IsNullOrWhiteSpace(remoteAddress) ? "an unknown address" : remoteAddress)
            });
            await db.SaveChangesAsync(ct);
        }
        return result with { Status = DigestActionStatus.Performed, SnoozedUntil = until };
    }

    private async Task<(DigestActionResult Result, DigestActionToken? Token)> CheckAsync(string? token, CancellationToken ct)
    {
        var s = await _settings.LoadAsync(ct);
        if (!s.DigestActionLinks) return (new DigestActionResult(DigestActionStatus.Disabled), null);
        var parsed = _tokens.Read(token);
        if (parsed is null) return (new DigestActionResult(DigestActionStatus.Invalid), null);

        await using var db = await _factory.CreateDbContextAsync(ct);
        var v = await db.Verdicts.AsNoTracking().FirstOrDefaultAsync(x => x.Id == parsed.VerdictId, ct);
        var run = await db.DigestRuns.AsNoTracking().Where(r => r.Id == parsed.DigestId).Select(r => new { r.GeneratedAt, r.SentAt }).FirstOrDefaultAsync(ct);
        // a digest that was never sent put its links in nobody's inbox
        if (v is null || run?.SentAt is null) return (new DigestActionResult(DigestActionStatus.Invalid), null);

        var label = DigestName(parsed.DigestId) + ", " + TimeZoneInfo.ConvertTimeFromUtc(DateTime.SpecifyKind(run.GeneratedAt, DateTimeKind.Utc), s.ResolveTimeZone()).ToString("d MMM yyyy");
        var result = new DigestActionResult(DigestActionStatus.Ready, parsed.Action, v.Id, v.CveId, v.Sentence, v.Tier, v.SlaDue, label);
        if (DateTime.UtcNow >= parsed.ExpiresUtc) return (result with { Status = DigestActionStatus.Expired }, null);
        if (v.State != VerdictState.Open || DigestActionTokens.StateVersion(v) != parsed.StateVersion) return (result with { Status = DigestActionStatus.Changed }, null);
        return (result, parsed);
    }
}
