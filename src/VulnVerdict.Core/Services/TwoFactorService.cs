using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Services;

/// <summary>What a local sign-in still needs once the password is right.</summary>
public enum SignInStep { SignedIn, NeedsCode, MustEnrol }

public enum SecondFactorResult { Wrong, Ok, OkRecoveryCode, Locked }

/// <summary>A secret waiting to be confirmed: the key to type by hand and the address behind the QR code.</summary>
public sealed record TwoFactorEnrolment(string ManualKey, string Uri);

/// <summary>The half-way state between password and code: who, with which stamp, for what, until when.</summary>
public sealed record PendingSignIn(Guid UserId, string Stamp, string Purpose, DateTime Expires, string Payload);

/// <summary>
/// Two-factor sign-in for local accounts: an authenticator app (TOTP) and ten single-use recovery codes. Single
/// sign-on users are not covered here; their identity provider does it. Every change rotates the account's security
/// stamp, which ends its other sessions, and is written to the audit log.
/// </summary>
public sealed class TwoFactorService
{
    public const string Issuer = "VulnVerdict";
    public const int MaxFailures = 5;
    public const int RecoveryCodeCount = 10;
    public static readonly TimeSpan LockoutPeriod = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan PendingLifetime = TimeSpan.FromMinutes(5);
    /// <summary>Purposes of the half-way token. One cannot stand in for another.</summary>
    public const string PurposeVerify = "verify", PurposeEnrol = "enrol", PurposeCodes = "codes";
    private const string RecoveryAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly IDataProtector _secrets;
    private readonly IDataProtector _pending;

    public TwoFactorService(IDbContextFactory<VvDbContext> factory, IDataProtectionProvider dp)
    {
        _factory = factory;
        // their own purposes: a stored secret cannot be replayed as a sign-in token, and neither is a session cookie
        _secrets = dp.CreateProtector("VulnVerdict.TwoFactor.Secret.v1");
        _pending = dp.CreateProtector("VulnVerdict.TwoFactor.Pending.v1");
    }

    /// <summary>The clock; replaceable so tests can move between time steps.</summary>
    public Func<DateTime> UtcNow { get; set; } = () => DateTime.UtcNow;

    /// <summary>Single sign-on users skip all of this. A local user with two-factor needs the code; one without it must enrol when the policy says so.</summary>
    public static SignInStep NextStep(AppUser user, bool requireTwoFactor) =>
        user.Provider != "local" ? SignInStep.SignedIn
        : user.TwoFactorEnabled ? SignInStep.NeedsCode
        : requireTwoFactor ? SignInStep.MustEnrol
        : SignInStep.SignedIn;

    // ------------------------------------------------------------------ policy

    /// <summary>"Require two-factor for local accounts". A row of its own, so saving the settings page from a stale tab cannot switch it back.</summary>
    public const string RequiredKey = "policy:twofactor:required";

    public async Task<bool> IsRequiredAsync(CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        return await db.Settings.AnyAsync(s => s.Key == RequiredKey && s.Value == "true", ct);
    }

    /// <summary>
    /// Switch the policy. Turning it on signs out local accounts that have no two-factor yet, so the next thing they
    /// see is the enrolment step. Returns how many accounts that was.
    /// </summary>
    public async Task<int> SetRequiredAsync(bool required, string actor, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var row = await db.Settings.FirstOrDefaultAsync(s => s.Key == RequiredKey, ct);
        var before = row?.Value == "true";
        if (before == required) return 0;
        var now = UtcNow();
        if (row is null) db.Settings.Add(new AppSetting { Key = RequiredKey, Value = required ? "true" : "false", UpdatedAt = now });
        else { row.Value = required ? "true" : "false"; row.UpdatedAt = now; }
        var without = required ? await db.Users.Where(u => u.Provider == "local" && u.TotpEnabledAt == null).ToListAsync(ct) : new();
        foreach (var u in without) u.SecurityStamp = UserService.NewStamp();
        db.Audit.Add(new AuditEntry { At = now, Actor = actor, Action = "policy.2fa.required", Target = "local accounts", Before = before ? "required" : "optional", After = required ? "required" : "optional" });
        await db.SaveChangesAsync(ct);
        return without.Count;
    }

    // ------------------------------------------------------------------ enrolment

    /// <summary>
    /// Start (or continue) enrolment: the secret is created once and kept, encrypted, until a code confirms it, so
    /// reloading the page shows the same QR code. Null for single sign-on users and accounts that already have two-factor.
    /// </summary>
    public async Task<TwoFactorEnrolment?> BeginEnrolmentAsync(Guid userId, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null || user.Provider != "local" || user.TwoFactorEnabled) return null;
        var secret = Unprotect(user.TotpSecret);
        if (secret is null)
        {
            secret = Totp.NewSecret();
            user.TotpSecret = _secrets.Protect(Convert.ToBase64String(secret));
            await db.SaveChangesAsync(ct);
        }
        return new TwoFactorEnrolment(Totp.ToBase32(secret), Totp.Uri(Issuer, user.Username, secret));
    }

    /// <summary>Turn two-factor on once a code from the app proves the secret arrived. Returns the recovery codes, shown once; null when the code is wrong.</summary>
    public async Task<IReadOnlyList<string>?> ConfirmEnrolmentAsync(Guid userId, string? code, string actor, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null || user.Provider != "local" || user.TwoFactorEnabled) return null;
        var now = UtcNow();
        var secret = Unprotect(user.TotpSecret);
        var entered = Compact(code);
        if (secret is null || !LooksLikeTotp(entered) || Totp.MatchingStep(secret, entered, now) is not { } step) return null;
        var codes = NewRecoveryCodes();
        user.TotpEnabledAt = now; user.TotpLastStep = step;
        user.RecoveryCodeHashes = JsonSerializer.Serialize(codes.Select(c => HashRecoveryCode(user.Id, c)));
        user.FailedSecondFactorCount = 0; user.SecondFactorLockedUntil = null;
        user.SecurityStamp = UserService.NewStamp();
        db.Audit.Add(new AuditEntry { At = now, Actor = actor, Action = "user.2fa.enable", Target = user.Username, After = "authenticator app, " + codes.Count + " recovery codes" });
        await db.SaveChangesAsync(ct);
        return codes;
    }

    // ------------------------------------------------------------------ sign-in

    /// <summary>
    /// Check a code from the app, or a recovery code. A time step is accepted once: the step is claimed in the
    /// database, so the same code posted twice, even at the same moment, signs in once. Five wrong codes in a row
    /// lock the second step for fifteen minutes.
    /// </summary>
    public async Task<SecondFactorResult> VerifyAsync(Guid userId, string? code, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var user = await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null || !user.TwoFactorEnabled) return SecondFactorResult.Wrong;
        var now = UtcNow();
        if (user.SecondFactorLockedUntil is { } until && until > now) return SecondFactorResult.Locked;

        var entered = Compact(code);
        if (LooksLikeTotp(entered))
        {
            var secret = Unprotect(user.TotpSecret);
            if (secret is not null && Totp.MatchingStep(secret, entered, now) is { } step && step > user.TotpLastStep)
            {
                var claimed = await db.Users.Where(u => u.Id == userId && u.TotpLastStep < step).ExecuteUpdateAsync(u => u
                    .SetProperty(x => x.TotpLastStep, step).SetProperty(x => x.FailedSecondFactorCount, 0)
                    .SetProperty(x => x.SecondFactorLockedUntil, (DateTime?)null).SetProperty(x => x.LastLoginAt, now), ct);
                if (claimed == 1) return SecondFactorResult.Ok;
            }
        }
        else if (entered.Length > 0)
        {
            var hashes = RecoveryHashes(user);
            var hash = HashRecoveryCode(user.Id, entered);
            var index = -1;
            for (var i = 0; i < hashes.Count; i++)
                if (UserService.FixedTimeEquals(hashes[i], hash) && index < 0) index = i;
            if (index >= 0)
            {
                hashes.RemoveAt(index);
                var left = JsonSerializer.Serialize(hashes);
                // only if the list is still the one read above: a recovery code posted twice at once is used once
                var claimed = await db.Users.Where(u => u.Id == userId && u.RecoveryCodeHashes == user.RecoveryCodeHashes).ExecuteUpdateAsync(u => u
                    .SetProperty(x => x.RecoveryCodeHashes, left).SetProperty(x => x.FailedSecondFactorCount, 0)
                    .SetProperty(x => x.SecondFactorLockedUntil, (DateTime?)null).SetProperty(x => x.LastLoginAt, now), ct);
                if (claimed == 1)
                {
                    db.Audit.Add(new AuditEntry { At = now, Actor = user.Username, Action = "user.2fa.recovery-used", Target = user.Username, After = hashes.Count + " recovery codes left" });
                    await db.SaveChangesAsync(ct);
                    return SecondFactorResult.OkRecoveryCode;
                }
            }
        }

        await db.Users.Where(u => u.Id == userId).ExecuteUpdateAsync(u => u.SetProperty(x => x.FailedSecondFactorCount, x => x.FailedSecondFactorCount + 1), ct);
        var failures = await db.Users.Where(u => u.Id == userId).Select(u => u.FailedSecondFactorCount).FirstOrDefaultAsync(ct);
        if (failures < MaxFailures) return SecondFactorResult.Wrong;
        var lockedUntil = now + LockoutPeriod;
        await db.Users.Where(u => u.Id == userId).ExecuteUpdateAsync(u => u.SetProperty(x => x.FailedSecondFactorCount, 0).SetProperty(x => x.SecondFactorLockedUntil, (DateTime?)lockedUntil), ct);
        db.Audit.Add(new AuditEntry { At = now, Actor = user.Username, Action = "user.2fa.lockout", Target = user.Username, After = MaxFailures + " wrong codes in a row; locked until " + lockedUntil.ToString("u") });
        await db.SaveChangesAsync(ct);
        return SecondFactorResult.Locked;
    }

    // ------------------------------------------------------------------ changes

    /// <summary>Turning your own two-factor off takes the password and a current code (or a recovery code).</summary>
    public async Task<bool> DisableAsync(Guid userId, string? password, string? code, CancellationToken ct = default)
    {
        var user = await FindAsync(userId, ct);
        if (user is null || !user.TwoFactorEnabled || !UserService.PasswordMatches(user, password)) return false;
        if (await VerifyAsync(userId, code, ct) is not (SecondFactorResult.Ok or SecondFactorResult.OkRecoveryCode)) return false;
        await ClearAsync(userId, user.Username, "user.2fa.disable", "turned off by the user, with password and code", ct);
        return true;
    }

    /// <summary>An administrator resets someone's two-factor (a lost phone). Their sessions end; they enrol again if the policy requires it.</summary>
    public async Task<bool> ResetAsync(Guid userId, string actor, CancellationToken ct = default)
    {
        var user = await FindAsync(userId, ct);
        if (user is null) return false;
        await ClearAsync(userId, actor, "user.2fa.reset", user.TwoFactorEnabled ? "two-factor removed; sessions ended" : "two-factor was not on; lockouts cleared, sessions ended", ct);
        return true;
    }

    /// <summary>The break-glass command: reset by username from the console host, also clearing any lockout.</summary>
    public async Task<bool> ResetByUsernameAsync(string username, string actor, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var name = username.Trim();
        var id = await db.Users.Where(u => u.Username == name && u.Provider == "local").Select(u => (Guid?)u.Id).FirstOrDefaultAsync(ct);
        return id is not null && await ResetAsync(id.Value, actor, ct);
    }

    /// <summary>Replace the recovery codes; a current code proves it is still the owner asking. Null when the code is wrong.</summary>
    public async Task<IReadOnlyList<string>?> RegenerateRecoveryCodesAsync(Guid userId, string? code, CancellationToken ct = default)
    {
        if (await VerifyAsync(userId, code, ct) is not (SecondFactorResult.Ok or SecondFactorResult.OkRecoveryCode)) return null;
        await using var db = await _factory.CreateDbContextAsync(ct);
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null) return null;
        var codes = NewRecoveryCodes();
        user.RecoveryCodeHashes = JsonSerializer.Serialize(codes.Select(c => HashRecoveryCode(user.Id, c)));
        db.Audit.Add(new AuditEntry { At = UtcNow(), Actor = user.Username, Action = "user.2fa.recovery-regenerate", Target = user.Username, After = codes.Count + " new recovery codes; the old ones no longer work" });
        await db.SaveChangesAsync(ct);
        return codes;
    }

    public static int RecoveryCodesLeft(AppUser user) => RecoveryHashes(user).Count;

    private async Task ClearAsync(Guid userId, string actor, string action, string after, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == userId, ct);
        if (user is null) return;
        user.TotpSecret = null; user.TotpEnabledAt = null; user.TotpLastStep = 0; user.RecoveryCodeHashes = null;
        user.FailedSecondFactorCount = 0; user.SecondFactorLockedUntil = null;
        user.FailedPasswordCount = 0; user.PasswordLockedUntil = null;
        user.SecurityStamp = UserService.NewStamp();
        db.Audit.Add(new AuditEntry { At = UtcNow(), Actor = actor, Action = action, Target = user.Username, After = after });
        await db.SaveChangesAsync(ct);
    }

    // ------------------------------------------------------------------ the half-way token

    /// <summary>
    /// A short-lived token for the step between password and code (or forced enrolment). It names the user, the
    /// security stamp at the time and one purpose, and is encrypted under its own Data Protection purpose: it is
    /// not a session cookie and nothing accepts it as one.
    /// </summary>
    public string IssuePending(AppUser user, string purpose, string payload = "") =>
        _pending.Protect(string.Join('\n', purpose, user.Id.ToString("N"), user.SecurityStamp, (UtcNow() + PendingLifetime).Ticks.ToString(), payload));

    public PendingSignIn? ReadPending(string? token, string purpose)
    {
        if (string.IsNullOrEmpty(token)) return null;
        string plain;
        try { plain = _pending.Unprotect(token); } catch { return null; }
        var parts = plain.Split('\n', 5);
        if (parts.Length != 5 || parts[0] != purpose || !Guid.TryParseExact(parts[1], "N", out var id) || !long.TryParse(parts[3], out var ticks)) return null;
        var expires = new DateTime(ticks, DateTimeKind.Utc);
        return expires > UtcNow() ? new PendingSignIn(id, parts[2], parts[0], expires, parts[4]) : null;
    }

    /// <summary>The account a half-way token belongs to, while the token is in date and the account's stamp has not moved since it was issued.</summary>
    public async Task<AppUser?> PendingUserAsync(string? token, string purpose, CancellationToken ct = default)
    {
        if (ReadPending(token, purpose) is not { } pending) return null;
        var user = await FindAsync(pending.UserId, ct);
        return user is not null && user.SecurityStamp.Length > 0 && UserService.FixedTimeEquals(user.SecurityStamp, pending.Stamp) ? user : null;
    }

    // ------------------------------------------------------------------ helpers

    private async Task<AppUser?> FindAsync(Guid id, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        return await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == id, ct);
    }

    private byte[]? Unprotect(string? stored)
    {
        if (string.IsNullOrEmpty(stored)) return null;
        try { return Convert.FromBase64String(_secrets.Unprotect(stored)); } catch { return null; }
    }

    private static List<string> RecoveryHashes(AppUser user)
    {
        if (string.IsNullOrEmpty(user.RecoveryCodeHashes)) return new();
        try { return JsonSerializer.Deserialize<List<string>>(user.RecoveryCodeHashes) ?? new(); } catch { return new(); }
    }

    /// <summary>Sixteen characters from an alphabet without look-alikes (80 bits), written in groups of four.</summary>
    public static List<string> NewRecoveryCodes() =>
        Enumerable.Range(0, RecoveryCodeCount).Select(_ => string.Join("-", RandomNumberGenerator.GetString(RecoveryAlphabet, 16).Chunk(4).Select(c => new string(c)))).ToList();

    /// <summary>Recovery codes are random and long, so a salted SHA-256 is enough; the plain code is never stored.</summary>
    public static string HashRecoveryCode(Guid userId, string code) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(userId.ToString("N") + ":" + Compact(code)))).ToLowerInvariant();

    /// <summary>What was typed, without spaces and dashes, upper case: "123 456" and "abcd-efgh" both work.</summary>
    public static string Compact(string? code) => new string((code ?? "").Where(char.IsAsciiLetterOrDigit).ToArray()).ToUpperInvariant();

    private static bool LooksLikeTotp(string compact) => compact.Length == Totp.Digits && compact.All(char.IsAsciiDigit);
}
