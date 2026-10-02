using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

/// <summary>Local two-factor: the TOTP arithmetic, enrolment, replay, recovery codes, lockouts, stamps, the policy, the half-way token.</summary>
public class TwoFactorTests : IDisposable
{
    private readonly string _dir;
    private readonly TestDbFactory _factory;
    private DateTime _now = new(2026, 10, 2, 9, 0, 10, DateTimeKind.Utc);
    private const string Password = "correct horse battery";

    public TwoFactorTests()
    {
        // a file, not :memory:, so concurrent posts use their own connections as they do in the console
        _dir = Path.Combine(Path.GetTempPath(), "vv-2fa-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _factory = new TestDbFactory(new DbContextOptionsBuilder<VvDbContext>().UseSqlite("Data Source=" + Path.Combine(_dir, "vv.db") + ";Pooling=false").Options);
        using var db = _factory.CreateDbContext();
        db.Database.EnsureCreated();
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    private UserService Users() => new(_factory) { UtcNow = () => _now };
    private TwoFactorService TwoFactor() => new(_factory, new PurposeProtectionProvider()) { UtcNow = () => _now };

    private async Task<AppUser> Reload(Guid id) => (await Users().FindAsync(id))!;

    /// <summary>A local user with two-factor on. Returns the user, the secret and the recovery codes.</summary>
    private async Task<(AppUser User, byte[] Secret, IReadOnlyList<string> Codes)> EnrolledAsync(string name = "admin", UserRole role = UserRole.Administrator)
    {
        var user = await Users().CreateLocalUserAsync(name, Password, role, null, "test");
        var tf = TwoFactor();
        var enrolment = (await tf.BeginEnrolmentAsync(user.Id))!;
        var secret = Totp.FromBase32(enrolment.ManualKey);
        var codes = await tf.ConfirmEnrolmentAsync(user.Id, Totp.Code(secret, Totp.StepAt(_now)), "test");
        Assert.NotNull(codes);
        // the next code is from the next step: the confirming one is spent
        _now = _now.AddSeconds(Totp.StepSeconds);
        return (await Reload(user.Id), secret, codes!);
    }

    private string CodeNow(byte[] secret, int stepOffset = 0) => Totp.Code(secret, Totp.StepAt(_now) + stepOffset);

    // ---- RFC 6238

    [Theory]
    [InlineData(59L, "94287082")]
    [InlineData(1111111109L, "07081804")]
    [InlineData(1111111111L, "14050471")]
    [InlineData(1234567890L, "89005924")]
    [InlineData(2000000000L, "69279037")]
    [InlineData(20000000000L, "65353130")]
    public void Codes_match_the_rfc_6238_sha1_test_vectors(long unixSeconds, string expected)
    {
        var secret = Encoding.ASCII.GetBytes("12345678901234567890");
        var step = Totp.StepAt(DateTime.UnixEpoch.AddSeconds(unixSeconds));
        Assert.Equal(expected, Totp.Code(secret, step, digits: 8));
        // six digits, as authenticator apps show it, is the tail of the same number
        Assert.Equal(expected[2..], Totp.Code(secret, step));
    }

    [Fact]
    public void The_secret_is_160_bits_and_survives_base32()
    {
        var secret = Totp.NewSecret();
        Assert.Equal(20, secret.Length);
        Assert.Equal(secret, Totp.FromBase32(Totp.ToBase32(secret)));
        Assert.Equal("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", Totp.ToBase32(Encoding.ASCII.GetBytes("12345678901234567890")));
        Assert.Equal(secret, Totp.FromBase32(Totp.Grouped(Totp.ToBase32(secret)).ToLowerInvariant()));
        var uri = Totp.Uri("VulnVerdict", "admin@corp", secret);
        Assert.StartsWith("otpauth://totp/VulnVerdict%3Aadmin%40corp?secret=" + Totp.ToBase32(secret), uri);
        Assert.Contains("&issuer=VulnVerdict&algorithm=SHA1&digits=6&period=30", uri);
    }

    [Theory]
    [InlineData(-2, false)]
    [InlineData(-1, true)]
    [InlineData(0, true)]
    [InlineData(1, true)]
    [InlineData(2, false)]
    public void A_code_is_accepted_one_step_either_side_and_no_further(int offset, bool accepted)
    {
        var secret = Totp.NewSecret();
        var step = Totp.StepAt(_now);
        var match = Totp.MatchingStep(secret, Totp.Code(secret, step + offset), _now);
        Assert.Equal(accepted ? step + offset : null, match);
    }

    // ---- enrolment

    [Fact]
    public async Task Enrolment_needs_a_code_before_it_counts_and_stores_nothing_readable()
    {
        var user = await Users().CreateLocalUserAsync("admin", Password, UserRole.Administrator, null, "test");
        var tf = TwoFactor();
        var enrolment = (await tf.BeginEnrolmentAsync(user.Id))!;
        Assert.Equal(32, enrolment.ManualKey.Length); // 160 bits in base32
        Assert.Equal(enrolment.ManualKey, (await tf.BeginEnrolmentAsync(user.Id))!.ManualKey); // the same QR code on reload
        var secret = Totp.FromBase32(enrolment.ManualKey);

        Assert.Null(await tf.ConfirmEnrolmentAsync(user.Id, "000000", "admin"));
        Assert.False((await Reload(user.Id)).TwoFactorEnabled);
        Assert.Equal(SignInStep.SignedIn, TwoFactorService.NextStep(await Reload(user.Id), requireTwoFactor: false)); // a pending secret is not two-factor

        var codes = await tf.ConfirmEnrolmentAsync(user.Id, CodeNow(secret), "admin");
        Assert.NotNull(codes);
        Assert.Equal(TwoFactorService.RecoveryCodeCount, codes!.Distinct().Count());

        var saved = await Reload(user.Id);
        Assert.True(saved.TwoFactorEnabled);
        Assert.DoesNotContain(enrolment.ManualKey, saved.TotpSecret);
        Assert.DoesNotContain(Convert.ToBase64String(secret), saved.TotpSecret);
        Assert.All(codes, c => Assert.DoesNotContain(TwoFactorService.Compact(c), saved.RecoveryCodeHashes, StringComparison.OrdinalIgnoreCase));
        Assert.Null(await tf.BeginEnrolmentAsync(user.Id)); // the secret is not handed out again once it is on
        await using var db = _factory.CreateDbContext();
        Assert.Single(await db.Audit.Where(a => a.Action == "user.2fa.enable" && a.Target == "admin").ToListAsync());
    }

    [Fact]
    public async Task Single_sign_on_users_are_not_enrolled_here()
    {
        var oidc = await Users().RecordOidcSignInAsync("jo@corp.example", null, UserRole.Operator);
        Assert.Null(await TwoFactor().BeginEnrolmentAsync(oidc.Id));
    }

    // ---- sign-in

    [Fact]
    public async Task A_code_works_once_and_an_older_step_is_refused_after_a_newer_one()
    {
        var (user, secret, _) = await EnrolledAsync();
        var tf = TwoFactor();
        var earlier = CodeNow(secret, -1);
        var current = CodeNow(secret);

        Assert.Equal(SecondFactorResult.Ok, await tf.VerifyAsync(user.Id, current));
        Assert.Equal(SecondFactorResult.Wrong, await tf.VerifyAsync(user.Id, current)); // replay
        Assert.Equal(SecondFactorResult.Wrong, await tf.VerifyAsync(user.Id, earlier)); // still in the window, but behind the accepted step
        Assert.Equal(Totp.StepAt(_now), (await Reload(user.Id)).TotpLastStep);

        _now = _now.AddSeconds(Totp.StepSeconds);
        Assert.Equal(SecondFactorResult.Ok, await tf.VerifyAsync(user.Id, "  " + CodeNow(secret)[..3] + " " + CodeNow(secret)[3..])); // typed with a space
    }

    [Fact]
    public async Task The_same_code_posted_at_once_signs_in_once()
    {
        var (user, secret, _) = await EnrolledAsync();
        var code = CodeNow(secret);
        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => Task.Run(() => TwoFactor().VerifyAsync(user.Id, code))));
        Assert.Single(results, r => r == SecondFactorResult.Ok);
    }

    [Fact]
    public async Task A_recovery_code_signs_in_once_and_is_audited()
    {
        var (user, _, codes) = await EnrolledAsync();
        var tf = TwoFactor();
        Assert.Equal(TwoFactorService.RecoveryCodeCount, TwoFactorService.RecoveryCodesLeft(user));

        Assert.Equal(SecondFactorResult.OkRecoveryCode, await tf.VerifyAsync(user.Id, codes[3].ToLowerInvariant().Replace("-", " ")));
        Assert.Equal(SecondFactorResult.Wrong, await tf.VerifyAsync(user.Id, codes[3]));
        Assert.Equal(TwoFactorService.RecoveryCodeCount - 1, TwoFactorService.RecoveryCodesLeft(await Reload(user.Id)));
        Assert.Equal(SecondFactorResult.OkRecoveryCode, await tf.VerifyAsync(user.Id, codes[0]));

        await using var db = _factory.CreateDbContext();
        var used = await db.Audit.Where(a => a.Action == "user.2fa.recovery-used").OrderBy(a => a.Id).ToListAsync();
        Assert.Equal(2, used.Count);
        Assert.Equal("9 recovery codes left", used[0].After);
    }

    [Fact]
    public async Task New_recovery_codes_need_a_code_and_retire_the_old_ones()
    {
        var (user, secret, codes) = await EnrolledAsync();
        var tf = TwoFactor();
        Assert.Null(await tf.RegenerateRecoveryCodesAsync(user.Id, "000000"));
        var fresh = await tf.RegenerateRecoveryCodesAsync(user.Id, CodeNow(secret));
        Assert.NotNull(fresh);
        Assert.Equal(SecondFactorResult.Wrong, await tf.VerifyAsync(user.Id, codes[0]));
        Assert.Equal(SecondFactorResult.OkRecoveryCode, await tf.VerifyAsync(user.Id, fresh![0]));
    }

    [Fact]
    public async Task Five_wrong_codes_lock_the_second_step_for_fifteen_minutes()
    {
        var (user, secret, codes) = await EnrolledAsync();
        var tf = TwoFactor();
        for (var i = 0; i < TwoFactorService.MaxFailures - 1; i++) Assert.Equal(SecondFactorResult.Wrong, await tf.VerifyAsync(user.Id, "000000"));
        Assert.Equal(SecondFactorResult.Locked, await tf.VerifyAsync(user.Id, "not-a-recovery-code"));

        // locked means locked: neither the right code nor a recovery code gets through
        Assert.Equal(SecondFactorResult.Locked, await tf.VerifyAsync(user.Id, CodeNow(secret)));
        Assert.Equal(SecondFactorResult.Locked, await tf.VerifyAsync(user.Id, codes[0]));
        Assert.Equal(TwoFactorService.RecoveryCodeCount, TwoFactorService.RecoveryCodesLeft(await Reload(user.Id)));

        _now += TwoFactorService.LockoutPeriod + TimeSpan.FromSeconds(1);
        Assert.Equal(SecondFactorResult.Ok, await tf.VerifyAsync(user.Id, CodeNow(secret)));
        Assert.Equal(0, (await Reload(user.Id)).FailedSecondFactorCount);
        await using var db = _factory.CreateDbContext();
        Assert.Single(await db.Audit.Where(a => a.Action == "user.2fa.lockout").ToListAsync());
    }

    [Fact]
    public async Task A_right_code_clears_the_count_of_wrong_ones()
    {
        var (user, secret, _) = await EnrolledAsync();
        var tf = TwoFactor();
        for (var i = 0; i < TwoFactorService.MaxFailures - 1; i++) await tf.VerifyAsync(user.Id, "000000");
        Assert.Equal(SecondFactorResult.Ok, await tf.VerifyAsync(user.Id, CodeNow(secret)));
        Assert.Equal(SecondFactorResult.Wrong, await tf.VerifyAsync(user.Id, "000000"));
    }

    [Fact]
    public async Task Wrong_passwords_lock_the_account_whatever_address_they_come_from()
    {
        var users = Users();
        var user = await users.CreateLocalUserAsync("admin", Password, UserRole.Administrator, null, "test");
        for (var i = 0; i < UserService.MaxPasswordFailures; i++) Assert.Null(await users.ValidateLocalAsync("admin", "wrong " + i));
        Assert.Null(await users.ValidateLocalAsync("admin", Password)); // locked: the right password waits too
        Assert.NotNull((await Reload(user.Id)).PasswordLockedUntil);

        _now += UserService.LockoutPeriod + TimeSpan.FromSeconds(1);
        Assert.NotNull(await users.ValidateLocalAsync("admin", Password));
        Assert.Null((await Reload(user.Id)).PasswordLockedUntil);
        await using var db = _factory.CreateDbContext();
        Assert.Single(await db.Audit.Where(a => a.Action == "user.lockout").ToListAsync());
    }

    [Fact]
    public async Task A_right_password_resets_the_count_and_a_password_reset_lifts_the_lock()
    {
        var users = Users();
        var user = await users.CreateLocalUserAsync("admin", Password, UserRole.Administrator, null, "test");
        for (var i = 0; i < UserService.MaxPasswordFailures - 1; i++) await users.ValidateLocalAsync("admin", "wrong");
        Assert.NotNull(await users.ValidateLocalAsync("admin", Password));
        Assert.Equal(0, (await Reload(user.Id)).FailedPasswordCount);

        for (var i = 0; i < UserService.MaxPasswordFailures; i++) await users.ValidateLocalAsync("admin", "wrong");
        Assert.Null(await users.ValidateLocalAsync("admin", Password));
        await users.UpdateUserAsync(user.Id, UserRole.Administrator, "a brand new password", "other-admin");
        Assert.NotNull(await users.ValidateLocalAsync("admin", "a brand new password"));
    }

    [Fact]
    public async Task The_password_alone_does_not_count_as_a_login_when_two_factor_is_on()
    {
        var (user, secret, _) = await EnrolledAsync();
        Assert.Null(user.LastLoginAt);
        Assert.NotNull(await Users().ValidateLocalAsync("admin", Password));
        Assert.Null((await Reload(user.Id)).LastLoginAt);
        await TwoFactor().VerifyAsync(user.Id, CodeNow(secret));
        Assert.Equal(_now, (await Reload(user.Id)).LastLoginAt);
    }

    // ---- stamps

    [Fact]
    public async Task Enabling_disabling_and_resetting_each_rotate_the_stamp_and_end_sessions()
    {
        var users = Users();
        var created = await users.CreateLocalUserAsync("admin", Password, UserRole.Administrator, null, "test");
        var tf = TwoFactor();
        var secret = Totp.FromBase32((await tf.BeginEnrolmentAsync(created.Id))!.ManualKey);
        Assert.True(await users.IsSessionValidAsync(created.Id.ToString(), created.SecurityStamp)); // starting enrolment changes nothing

        await tf.ConfirmEnrolmentAsync(created.Id, CodeNow(secret), "admin");
        var enabled = await Reload(created.Id);
        Assert.False(await users.IsSessionValidAsync(created.Id.ToString(), created.SecurityStamp));

        _now = _now.AddSeconds(Totp.StepSeconds);
        Assert.False(await tf.DisableAsync(created.Id, "wrong password", CodeNow(secret)));
        Assert.False(await tf.DisableAsync(created.Id, Password, "000000"));
        Assert.True(await users.IsSessionValidAsync(created.Id.ToString(), enabled.SecurityStamp));
        Assert.True(await tf.DisableAsync(created.Id, Password, CodeNow(secret)));
        var disabled = await Reload(created.Id);
        Assert.False(disabled.TwoFactorEnabled);
        Assert.Null(disabled.TotpSecret);
        Assert.Null(disabled.RecoveryCodeHashes);
        Assert.False(await users.IsSessionValidAsync(created.Id.ToString(), enabled.SecurityStamp));

        var (second, _, _) = await EnrolledAsync("op", UserRole.Operator);
        Assert.True(await tf.ResetAsync(second.Id, "admin"));
        var reset = await Reload(second.Id);
        Assert.False(reset.TwoFactorEnabled);
        Assert.False(await users.IsSessionValidAsync(second.Id.ToString(), second.SecurityStamp));
        Assert.True(await users.IsSessionValidAsync(second.Id.ToString(), reset.SecurityStamp));

        await using var db = _factory.CreateDbContext();
        Assert.Equal("admin", (await db.Audit.SingleAsync(a => a.Action == "user.2fa.disable")).Target);
        var audit = await db.Audit.SingleAsync(a => a.Action == "user.2fa.reset");
        Assert.Equal(("admin", "op"), (audit.Actor, audit.Target));
    }

    [Fact]
    public async Task The_console_command_resets_two_factor_and_lockouts_by_username()
    {
        var (user, _, _) = await EnrolledAsync();
        var tf = TwoFactor();
        for (var i = 0; i < TwoFactorService.MaxFailures; i++) await tf.VerifyAsync(user.Id, "000000");
        Assert.False(await tf.ResetByUsernameAsync("nobody", "console"));
        Assert.True(await tf.ResetByUsernameAsync(" admin ", "console"));
        var after = await Reload(user.Id);
        Assert.False(after.TwoFactorEnabled);
        Assert.Null(after.SecondFactorLockedUntil);
        Assert.NotEqual(user.SecurityStamp, after.SecurityStamp);
        Assert.NotNull(await Users().ValidateLocalAsync("admin", Password));
        await using var db = _factory.CreateDbContext();
        Assert.Equal("console", (await db.Audit.SingleAsync(a => a.Action == "user.2fa.reset")).Actor);
    }

    // ---- policy

    [Theory]
    [InlineData("local", true, false, SignInStep.NeedsCode)]
    [InlineData("local", true, true, SignInStep.NeedsCode)]
    [InlineData("local", false, false, SignInStep.SignedIn)]
    [InlineData("local", false, true, SignInStep.MustEnrol)]
    [InlineData("oidc", false, true, SignInStep.SignedIn)]
    [InlineData("oidc", false, false, SignInStep.SignedIn)]
    public void What_a_sign_in_still_needs_after_the_password(string provider, bool enrolled, bool required, SignInStep expected)
    {
        var user = new AppUser { Provider = provider, TotpSecret = enrolled ? "x" : null, TotpEnabledAt = enrolled ? _now : null };
        Assert.Equal(expected, TwoFactorService.NextStep(user, required));
    }

    [Fact]
    public async Task Requiring_two_factor_is_off_by_default_and_signs_out_local_accounts_without_it()
    {
        var tf = TwoFactor();
        Assert.False(await tf.IsRequiredAsync());
        var (with, _, _) = await EnrolledAsync();
        var without = await Users().CreateLocalUserAsync("op", Password, UserRole.Operator, null, "test");
        var oidc = await Users().RecordOidcSignInAsync("jo@corp.example", null, UserRole.Viewer);

        Assert.Equal(1, await tf.SetRequiredAsync(true, "admin"));
        Assert.True(await tf.IsRequiredAsync());
        Assert.Equal(0, await tf.SetRequiredAsync(true, "admin")); // no change, nothing to do
        Assert.Equal(with.SecurityStamp, (await Reload(with.Id)).SecurityStamp);
        Assert.Equal(oidc.SecurityStamp, (await Reload(oidc.Id)).SecurityStamp);
        Assert.NotEqual(without.SecurityStamp, (await Reload(without.Id)).SecurityStamp);
        Assert.Equal(SignInStep.MustEnrol, TwoFactorService.NextStep(await Reload(without.Id), await tf.IsRequiredAsync()));

        await tf.SetRequiredAsync(false, "admin");
        Assert.False(await tf.IsRequiredAsync());
        await using var db = _factory.CreateDbContext();
        Assert.Equal(new[] { "required", "optional" }, await db.Audit.Where(a => a.Action == "policy.2fa.required").OrderBy(a => a.Id).Select(a => a.After).ToListAsync());
    }

    // ---- the half-way token

    [Fact]
    public async Task The_half_way_token_is_for_one_purpose_one_user_and_five_minutes()
    {
        var (user, _, _) = await EnrolledAsync();
        var tf = TwoFactor();
        var token = tf.IssuePending(user, TwoFactorService.PurposeVerify);

        Assert.Equal(user.Id, (await tf.PendingUserAsync(token, TwoFactorService.PurposeVerify))!.Id);
        Assert.Null(await tf.PendingUserAsync(token, TwoFactorService.PurposeEnrol)); // a code-step token cannot enrol
        Assert.Null(await tf.PendingUserAsync(token + "x", TwoFactorService.PurposeVerify));
        Assert.Null(await tf.PendingUserAsync(null, TwoFactorService.PurposeVerify));

        _now += TwoFactorService.PendingLifetime - TimeSpan.FromSeconds(1);
        Assert.NotNull(await tf.PendingUserAsync(token, TwoFactorService.PurposeVerify));
        _now += TimeSpan.FromSeconds(2);
        Assert.Null(await tf.PendingUserAsync(token, TwoFactorService.PurposeVerify));
    }

    [Fact]
    public async Task The_half_way_token_dies_with_the_security_stamp()
    {
        var (user, _, _) = await EnrolledAsync();
        var tf = TwoFactor();
        var token = tf.IssuePending(user, TwoFactorService.PurposeVerify);
        await Users().UpdateUserAsync(user.Id, user.Role, "a brand new password", "other-admin");
        Assert.Null(await tf.PendingUserAsync(token, TwoFactorService.PurposeVerify));
    }

    [Fact]
    public async Task The_half_way_token_is_not_a_session()
    {
        var (user, _, _) = await EnrolledAsync();
        var tf = TwoFactor();
        var token = tf.IssuePending(user, TwoFactorService.PurposeVerify);

        // a session is the user id with the security stamp; the token is neither, and does not show the stamp
        Assert.DoesNotContain(user.SecurityStamp, token);
        Assert.False(await Users().IsSessionValidAsync(user.Id.ToString(), token));
        Assert.False(await Users().IsSessionValidAsync(token, user.SecurityStamp));
        // it is sealed under its own purpose: whatever protects session cookies, settings or the TOTP secret cannot open it
        var provider = new PurposeProtectionProvider();
        foreach (var purpose in new[] { "Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware", "VulnVerdict.Secrets.v1", "VulnVerdict.TwoFactor.Secret.v1" })
            Assert.Throws<CryptographicException>(() => provider.CreateProtector(purpose).Unprotect(token));
        // and holding it is not being signed in: the second step still has to be passed
        Assert.Equal(SecondFactorResult.Wrong, await tf.VerifyAsync(user.Id, "000000"));
        Assert.Null((await Reload(user.Id)).LastLoginAt);
    }

    private sealed class TestDbFactory : IDbContextFactory<VvDbContext>
    {
        private readonly DbContextOptions<VvDbContext> _options;
        public TestDbFactory(DbContextOptions<VvDbContext> options) => _options = options;
        public VvDbContext CreateDbContext() => new(_options);
        public Task<VvDbContext> CreateDbContextAsync(CancellationToken ct = default) => Task.FromResult(CreateDbContext());
    }

    /// <summary>Stands in for Data Protection: what one purpose seals, only that purpose opens, and the sealed form is not the plain text.</summary>
    private sealed class PurposeProtectionProvider : IDataProtectionProvider
    {
        public IDataProtector CreateProtector(string purpose) => new Protector(purpose);

        private sealed class Protector : IDataProtector
        {
            private readonly byte[] _key;
            public Protector(string purpose) => _key = SHA256.HashData(Encoding.UTF8.GetBytes(purpose));
            public IDataProtector CreateProtector(string purpose) => new Protector(Convert.ToHexString(_key) + "/" + purpose);

            public byte[] Protect(byte[] plaintext)
            {
                var masked = Mask(plaintext);
                return HMACSHA256.HashData(_key, masked).Concat(masked).ToArray();
            }

            public byte[] Unprotect(byte[] protectedData)
            {
                if (protectedData.Length < 32) throw new CryptographicException("not protected");
                var masked = protectedData[32..];
                if (!CryptographicOperations.FixedTimeEquals(HMACSHA256.HashData(_key, masked), protectedData.AsSpan(0, 32))) throw new CryptographicException("wrong purpose or tampered");
                return Mask(masked);
            }

            private byte[] Mask(byte[] data) => data.Select((b, i) => (byte)(b ^ _key[i % _key.Length])).ToArray();
        }
    }
}
