using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

/// <summary>Connector secret reuse, security stamps, the last administrator, first-run setup, API tokens, secret settings.</summary>
public class AccessControlTests : IDisposable
{
    private readonly string _dir;
    private readonly TestDbFactory _factory;

    public AccessControlTests()
    {
        // a file, not :memory:, so concurrent saves use their own connections as they do in the console
        _dir = Path.Combine(Path.GetTempPath(), "vv-access-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
        _factory = new TestDbFactory(new DbContextOptionsBuilder<VvDbContext>().UseSqlite("Data Source=" + Path.Combine(_dir, "vv.db") + ";Pooling=false").Options);
        using var db = _factory.CreateDbContext();
        db.Database.EnsureCreated();
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, true); } catch { }
    }

    // ---- connector secrets

    private static readonly AdapterMetadata Meta = new("test", "Test", "Vendor", "", Array.Empty<AssetKind>(), new[]
    {
        new CredentialField("host", "Host"),
        new CredentialField("username", "Username"),
        new CredentialField("password", "Password", CredentialTypes.Password),
        new CredentialField("verifyTls", "Verify TLS", CredentialTypes.Bool, Default: "true"),
        new CredentialField("timeoutSeconds", "Timeout", CredentialTypes.Number, Required: false),
    }, "read-only");

    private static Dictionary<string, string> Stored() => new() { ["host"] = "fw.corp.local", ["username"] = "reader", ["password"] = "s3cret", ["verifyTls"] = "true", ["timeoutSeconds"] = "30" };

    [Fact]
    public void Blank_password_reuses_the_saved_one_when_the_address_is_unchanged()
    {
        var form = Stored(); form["password"] = ""; form["timeoutSeconds"] = "60";
        Assert.Empty(ConnectorService.ReuseStoredSecrets(Meta, form, Stored()));
        Assert.Equal("s3cret", form["password"]);
    }

    [Theory]
    [InlineData("host", "attacker.example.com")]
    [InlineData("username", "someone-else")]
    [InlineData("verifyTls", "false")]
    public void Blank_password_is_not_reused_when_the_connection_details_change(string key, string value)
    {
        var form = Stored(); form["password"] = ""; form[key] = value;
        var reenter = ConnectorService.ReuseStoredSecrets(Meta, form, Stored());
        Assert.Equal(new[] { "Password" }, reenter);
        Assert.Equal("", form["password"]);
    }

    [Fact]
    public void A_field_the_form_does_not_know_cannot_carry_the_saved_password_elsewhere()
    {
        var form = Stored(); form["password"] = ""; form["baseUrl"] = "https://attacker.example.com";
        Assert.NotEmpty(ConnectorService.ReuseStoredSecrets(Meta, form, Stored()));
        Assert.Equal("", form["password"]);
    }

    [Fact]
    public void A_typed_password_is_used_whatever_the_address()
    {
        var form = Stored(); form["password"] = "new"; form["host"] = "other.corp.local";
        Assert.Empty(ConnectorService.ReuseStoredSecrets(Meta, form, Stored()));
        Assert.Equal("new", form["password"]);
    }

    // ---- accounts and sessions

    private UserService Users() => new(_factory);

    [Fact]
    public async Task Role_change_and_password_reset_rotate_the_stamp_and_end_sessions()
    {
        var users = Users();
        await users.CreateLocalUserAsync("admin", "correct horse battery", UserRole.Administrator, null, "test");
        var op = await users.CreateLocalUserAsync("op", "correct horse battery", UserRole.Operator, null, "test");
        var stamp = op.SecurityStamp;
        Assert.True(await users.IsSessionValidAsync(op.Id.ToString(), stamp));

        await users.UpdateUserAsync(op.Id, UserRole.Viewer, null, "test");
        Assert.False(await users.IsSessionValidAsync(op.Id.ToString(), stamp));
        var afterDemotion = (await users.FindAsync(op.Id))!.SecurityStamp;
        Assert.True(await users.IsSessionValidAsync(op.Id.ToString(), afterDemotion));

        await users.UpdateUserAsync(op.Id, UserRole.Viewer, "another long password", "test");
        Assert.False(await users.IsSessionValidAsync(op.Id.ToString(), afterDemotion));

        var current = (await users.FindAsync(op.Id))!.SecurityStamp;
        await users.DeleteUserAsync(op.Id, "test");
        Assert.False(await users.IsSessionValidAsync(op.Id.ToString(), current));
    }

    [Fact]
    public async Task A_session_without_a_stamp_is_not_valid()
    {
        var users = Users();
        var u = await users.CreateLocalUserAsync("admin", "correct horse battery", UserRole.Administrator, null, "test");
        Assert.False(await users.IsSessionValidAsync(u.Id.ToString(), null));
        Assert.False(await users.IsSessionValidAsync(u.Id.ToString(), ""));
        Assert.False(await users.IsSessionValidAsync("not-a-guid", u.SecurityStamp));
    }

    [Fact]
    public async Task The_last_administrator_cannot_be_demoted()
    {
        var users = Users();
        var admin = await users.CreateLocalUserAsync("admin", "correct horse battery", UserRole.Administrator, null, "test");
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => users.UpdateUserAsync(admin.Id, UserRole.Operator, null, "test"));
        Assert.Contains("last administrator", ex.Message);

        var second = await users.CreateLocalUserAsync("admin2", "correct horse battery", UserRole.Administrator, null, "test");
        await users.UpdateUserAsync(admin.Id, UserRole.Operator, null, "test");
        await Assert.ThrowsAsync<InvalidOperationException>(() => users.UpdateUserAsync(second.Id, UserRole.Viewer, null, "test"));
    }

    // ---- first run

    [Fact]
    public async Task First_administrator_needs_the_setup_token_and_is_created_once()
    {
        var users = Users();
        var token = await users.EnsureSetupTokenAsync(_dir);
        Assert.NotNull(token);
        Assert.Equal(token, await users.EnsureSetupTokenAsync(_dir)); // kept across restarts

        Assert.Null(await users.CreateFirstAdministratorAsync(_dir, "wrong", "admin", "correct horse battery", null));
        Assert.Null(await users.CreateFirstAdministratorAsync(_dir, null, "admin", "correct horse battery", null));
        Assert.False(await users.HasUsersAsync());

        var admin = await users.CreateFirstAdministratorAsync(_dir, token, "admin", "correct horse battery", null);
        Assert.NotNull(admin);
        Assert.Equal(UserRole.Administrator, admin!.Role);
        Assert.False(File.Exists(Path.Combine(_dir, UserService.SetupTokenFile)));
        Assert.Null(await users.CreateFirstAdministratorAsync(_dir, token, "second", "correct horse battery", null));
        Assert.Null(await users.EnsureSetupTokenAsync(_dir));
    }

    [Fact]
    public async Task Concurrent_first_run_posts_create_one_administrator()
    {
        var token = await Users().EnsureSetupTokenAsync(_dir);
        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(i =>
            Task.Run(() => Users().CreateFirstAdministratorAsync(_dir, token, "admin" + i, "correct horse battery", null))));
        Assert.Single(results, r => r is not null);
        await using var db = _factory.CreateDbContext();
        Assert.Equal(1, await db.Users.CountAsync());
    }

    [Fact]
    public async Task The_setup_guard_alone_blocks_a_second_administrator()
    {
        var token = await Users().EnsureSetupTokenAsync(_dir);
        await using (var db = _factory.CreateDbContext())
        {
            // as if another request's save had just committed its guard row
            db.Settings.Add(new AppSetting { Key = UserService.SetupGuardKey, Value = "x", UpdatedAt = DateTime.UtcNow });
            await db.SaveChangesAsync();
        }
        Assert.Null(await Users().CreateFirstAdministratorAsync(_dir, token, "admin", "correct horse battery", null));
    }

    // ---- API tokens

    private ApiTokenService Tokens() => new(_factory, new MarkingProtectionProvider());

    [Fact]
    public async Task Api_tokens_are_stored_as_hashes_and_scoped()
    {
        var tokens = Tokens();
        var read = await tokens.GenerateAsync(ApiScope.Read, "test");
        var write = await tokens.GenerateAsync(ApiScope.ReadWrite, "test");

        await using (var db = _factory.CreateDbContext())
            Assert.DoesNotContain(await db.Settings.Select(s => s.Value).ToListAsync(), v => v != null && (v.Contains(read) || v.Contains(write)));

        Assert.Equal(ApiScope.Read, await tokens.AuthoriseAsync("Bearer " + read));
        Assert.Equal(ApiScope.ReadWrite, await tokens.AuthoriseAsync("Bearer " + write));
        Assert.Equal(ApiScope.None, await tokens.AuthoriseAsync("Bearer " + read + "x"));
        Assert.Equal(ApiScope.None, await tokens.AuthoriseAsync(read));
        Assert.Equal(ApiScope.None, await tokens.AuthoriseAsync(""));

        await tokens.RevokeAsync(ApiScope.Read, "test");
        Assert.Equal(ApiScope.None, await tokens.AuthoriseAsync("Bearer " + read));
        var replaced = await tokens.GenerateAsync(ApiScope.ReadWrite, "test");
        Assert.Equal(ApiScope.None, await tokens.AuthoriseAsync("Bearer " + write));
        Assert.Equal(ApiScope.ReadWrite, await tokens.AuthoriseAsync("Bearer " + replaced));
    }

    [Fact]
    public void Token_comparison_rejects_near_misses()
    {
        var hash = ApiTokenService.Hash("vv_rw_abc");
        Assert.True(ApiTokenService.Matches("vv_rw_abc", hash));
        Assert.False(ApiTokenService.Matches("vv_rw_abd", hash));
        Assert.False(ApiTokenService.Matches("vv_rw_abc", ""));
        Assert.False(ApiTokenService.Matches("", hash));
    }

    [Fact]
    public async Task A_token_from_an_earlier_release_keeps_working_read_write_and_its_reversible_copy_goes()
    {
        var protector = new MarkingProtectionProvider().CreateProtector("VulnVerdict.Secrets.v1");
        await using (var db = _factory.CreateDbContext())
        {
            db.Settings.Add(new AppSetting { Key = "ApiToken", Value = protector.Protect("legacy-token-value"), Encrypted = true, UpdatedAt = DateTime.UtcNow });
            await db.SaveChangesAsync();
        }
        var tokens = Tokens();
        await tokens.MigrateLegacyAsync();
        await tokens.MigrateLegacyAsync(); // idempotent

        Assert.Equal(ApiScope.ReadWrite, await tokens.AuthoriseAsync("Bearer legacy-token-value"));
        Assert.True((await tokens.StatusAsync()).Legacy);
        await using (var db = _factory.CreateDbContext())
            Assert.False(await db.Settings.AnyAsync(s => s.Key == "ApiToken"));

        await tokens.GenerateAsync(ApiScope.ReadWrite, "test");
        Assert.False((await tokens.StatusAsync()).Legacy);
        Assert.Equal(ApiScope.None, await tokens.AuthoriseAsync("Bearer legacy-token-value"));
    }

    // ---- secret settings

    [Fact]
    public async Task A_plaintext_licence_key_is_encrypted_when_read_and_never_audited_in_clear()
    {
        await using (var db = _factory.CreateDbContext())
        {
            db.Settings.Add(new AppSetting { Key = nameof(AppSettings.LicenceKey), Value = "LICENCE-KEY-TEXT", Encrypted = false, UpdatedAt = DateTime.UtcNow });
            await db.SaveChangesAsync();
        }
        var settings = new SettingsService(_factory, new MarkingProtectionProvider());
        var s = await settings.LoadAsync();
        Assert.Equal("LICENCE-KEY-TEXT", s.LicenceKey);
        await using (var db = _factory.CreateDbContext())
        {
            var row = await db.Settings.SingleAsync(r => r.Key == nameof(AppSettings.LicenceKey));
            Assert.True(row.Encrypted);
            Assert.NotEqual("LICENCE-KEY-TEXT", row.Value);
        }
        Assert.Equal("LICENCE-KEY-TEXT", (await settings.LoadAsync()).LicenceKey);

        s.LicenceKey = "NEW-LICENCE-KEY";
        await settings.SaveAsync(s, "test");
        await using (var db = _factory.CreateDbContext())
            Assert.DoesNotContain(await db.Audit.Select(a => a.After).ToListAsync(), a => a != null && a.Contains("LICENCE-KEY"));
    }

    private sealed class TestDbFactory : IDbContextFactory<VvDbContext>
    {
        private readonly DbContextOptions<VvDbContext> _options;
        public TestDbFactory(DbContextOptions<VvDbContext> options) => _options = options;
        public VvDbContext CreateDbContext() => new(_options);
        public Task<VvDbContext> CreateDbContextAsync(CancellationToken ct = default) => Task.FromResult(CreateDbContext());
    }

    /// <summary>Changes what it protects, so a test can tell stored-encrypted from stored-plain.</summary>
    private sealed class MarkingProtectionProvider : IDataProtectionProvider, IDataProtector
    {
        public IDataProtector CreateProtector(string purpose) => this;
        public byte[] Protect(byte[] plaintext) => new byte[] { 0xEE }.Concat(plaintext).ToArray();
        public byte[] Unprotect(byte[] protectedData) => protectedData.Length > 0 && protectedData[0] == 0xEE ? protectedData[1..] : throw new System.Security.Cryptography.CryptographicException("not protected");
    }
}
