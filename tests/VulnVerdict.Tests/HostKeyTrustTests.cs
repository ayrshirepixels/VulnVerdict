using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Adapters.Linux;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

/// <summary>The trust prompt for SSH host keys: new against changed, what Trust all may touch, how the pins are written, the audit trail, and the saved password.</summary>
public class HostKeyTrustTests : IDisposable
{
    private const string FpA = "AAAAaaaaAAAAaaaaAAAAaaaaAAAAaaaaAAAAaaaaAAA";
    private const string FpB = "BBBBbbbbBBBBbbbbBBBBbbbbBBBBbbbbBBBBbbbbBBB";
    private const string FpC = "CCCCccccCCCCccccCCCCccccCCCCccccCCCCccccCCC";

    private readonly SqliteConnection _conn;
    private readonly TestFactory _factory;

    public HostKeyTrustTests()
    {
        _conn = new SqliteConnection("Data Source=:memory:");
        _conn.Open();
        _factory = new TestFactory(_conn);
        using var db = _factory.CreateDbContext();
        db.Database.EnsureCreated();
    }

    public void Dispose() => _conn.Dispose();

    /// <summary>The multi-host form (Linux, Windows over OpenSSH): one pinned key per line.</summary>
    private static readonly AdapterMetadata Many = new("fake-ssh", "Fake SSH", "Test", "", Array.Empty<AssetKind>(), new[]
    {
        new CredentialField("hosts", "Hosts", CredentialTypes.TextArea),
        new CredentialField("username", "Username"),
        new CredentialField("password", "Password", CredentialTypes.Password),
        new CredentialField("acceptAny", "Accept any host key", CredentialTypes.Bool, Required: false, Default: "false"),
        new CredentialField("knownHostKeys", "Known host keys", CredentialTypes.TextArea, Required: false),
    }, "read-only");

    /// <summary>The appliance form (firewalls over SSH): one host, one fingerprint.</summary>
    private static readonly AdapterMetadata Single = new("fake-fw", "Fake firewall", "Test", "", Array.Empty<AssetKind>(), new[]
    {
        new CredentialField("host", "Host"),
        new CredentialField("username", "Username"),
        new CredentialField("password", "Password", CredentialTypes.Password),
        new CredentialField("hostKey", "Host key fingerprint", Required: false),
    }, "read-only");

    private static Dictionary<string, string> ManyStored(string known = "") => new() { ["hosts"] = "10.0.0.5\n10.0.0.6:2222\nweb01", ["username"] = "reader", ["password"] = "s3cret", ["acceptAny"] = "false", ["knownHostKeys"] = known };
    private static Dictionary<string, string> SingleStored(string pin = "") => new() { ["host"] = "fw.corp.local", ["username"] = "reader", ["password"] = "s3cret", ["hostKey"] = pin };

    private static PresentedHostKey Key(string host, string fp, HostKeyStatus status = HostKeyStatus.New, string? pinned = null) => new(host, "ssh-ed25519", fp, status, pinned);

    // ---- classification

    [Fact]
    public void A_key_is_new_changed_or_pinned_against_what_is_pinned()
    {
        Assert.Equal(HostKeyStatus.New, SshHostKeys.Classify(FpA, null));
        Assert.Equal(HostKeyStatus.New, SshHostKeys.Classify(FpA, "  "));
        Assert.Equal(HostKeyStatus.Pinned, SshHostKeys.Classify(FpA, "SHA256:" + FpA + "="));
        Assert.Equal(HostKeyStatus.Changed, SshHostKeys.Classify(FpA, "SHA256:" + FpB));
    }

    [Fact]
    public async Task Every_connection_under_a_listener_reports_its_key_with_the_right_status()
    {
        var log = SshHostKeys.Listen();
        await Task.WhenAll(
            Task.Run(() => SshHostKeys.Observe("10.0.0.5", "ssh-ed25519", "SHA256:" + FpA, null, accepted: false)),
            Task.Run(() => SshHostKeys.Observe("10.0.0.6:2222", "ssh-rsa", FpB, "SHA256:" + FpC, accepted: false)),
            Task.Run(() => SshHostKeys.Observe("web01", "ecdsa-sha2-nistp256", FpC, FpC, accepted: true)),
            Task.Run(() => SshHostKeys.Observe("lab01", "ssh-ed25519", FpA, null, accepted: true))); // Accept any host key was on

        var seen = log.Snapshot().OrderBy(k => k.Host).ToList();
        Assert.Equal(new[] { "10.0.0.5", "10.0.0.6:2222", "lab01", "web01" }, seen.Select(k => k.Host));
        Assert.Equal(new[] { HostKeyStatus.New, HostKeyStatus.Changed, HostKeyStatus.New, HostKeyStatus.Pinned }, seen.Select(k => k.Status));
        Assert.Equal(FpA, seen[0].Fingerprint); // stored without the prefix
        Assert.Equal("10.0.0.5 ssh-ed25519 SHA256:" + FpA, seen[0].Describe());
        Assert.Equal(FpC, seen[1].PinnedFingerprint);
        // a run flags what it refused and what changed; a host knowingly accepted without a pin is not nagged about
        Assert.Equal(new[] { "10.0.0.5", "10.0.0.6:2222" }, log.NeedReview().Select(k => k.Host).OrderBy(h => h));
    }

    [Fact]
    public async Task A_listener_hears_only_what_happens_beneath_it()
    {
        // nobody is listening yet: the report goes nowhere, and a listener started afterwards does not find it
        await Task.Run(() => SshHostKeys.Observe("10.0.0.5", "ssh-ed25519", FpA, null, accepted: false));
        var log = SshHostKeys.Listen();
        Assert.Empty(log.Snapshot());
    }

    // ---- writing the pins

    [Fact]
    public void A_new_host_is_appended_and_the_rest_of_the_list_is_left_alone()
    {
        Assert.Equal("10.0.0.5 SHA256:" + FpA, SshHostKeys.AppendKnownHost("", "10.0.0.5", FpA));
        Assert.Equal("10.0.0.5 SHA256:" + FpA, SshHostKeys.AppendKnownHost(null, "10.0.0.5", "SHA256:" + FpA));
        var known = "# core switches\r\nweb01 SHA256:" + FpB + "\r\n\r\n";
        Assert.Equal("# core switches\nweb01 SHA256:" + FpB + "\n10.0.0.6:2222 SHA256:" + FpA, SshHostKeys.AppendKnownHost(known, "10.0.0.6:2222", FpA));
    }

    [Fact]
    public void A_replaced_key_is_rewritten_on_its_own_line()
    {
        var known = "# core\nweb01 SHA256:" + FpB + "\n10.0.0.5 SHA256:" + FpA + "\nWEB01 SHA256:" + FpA;
        var replaced = SshHostKeys.ReplaceKnownHost(known, "web01", FpC);
        Assert.Equal("# core\n10.0.0.5 SHA256:" + FpA + "\nWEB01 SHA256:" + FpC, replaced); // the line in force is rewritten, its stale duplicate goes
        Assert.Equal(FpC, SshHostKeys.PinnedFor(replaced, "web01"));
        Assert.Equal(FpA, SshHostKeys.PinnedFor(replaced, "10.0.0.5"));

        // pinned by host, presented as host:port: the host's line is the one that changes
        Assert.Equal("10.0.0.6 SHA256:" + FpC, SshHostKeys.ReplaceKnownHost("10.0.0.6 SHA256:" + FpA, "10.0.0.6:2222", FpC));
        // nothing to replace: it is added
        Assert.Equal("web01 SHA256:" + FpB + "\ndb01 SHA256:" + FpC, SshHostKeys.ReplaceKnownHost("web01 SHA256:" + FpB, "db01", FpC));
    }

    // ---- trust

    [Fact]
    public void Trust_all_pins_the_new_hosts_and_never_a_changed_one()
    {
        var creds = ManyStored("web01 SHA256:" + FpB);
        var presented = new[] { Key("10.0.0.5", FpA), Key("10.0.0.6:2222", FpA), Key("web01", FpC, HostKeyStatus.Changed, FpB) };

        var applied = ConnectorService.ApplyTrust(Many, creds, presented);

        Assert.Equal(new[] { "10.0.0.5", "10.0.0.6:2222" }, applied.Select(k => k.Host));
        Assert.Equal("web01 SHA256:" + FpB + "\n10.0.0.5 SHA256:" + FpA + "\n10.0.0.6:2222 SHA256:" + FpA, creds["knownHostKeys"]);
    }

    [Fact]
    public void A_changed_key_cannot_be_slipped_in_as_new()
    {
        // the page says "new", but the credential already pins something else for that host: it is still a change
        var creds = ManyStored("web01 SHA256:" + FpB);
        Assert.Empty(ConnectorService.ApplyTrust(Many, creds, new[] { Key("web01", FpC, HostKeyStatus.New) }));
        Assert.Equal("web01 SHA256:" + FpB, creds["knownHostKeys"]);
    }

    [Fact]
    public void A_changed_key_is_replaced_only_for_the_host_that_was_confirmed()
    {
        var creds = ManyStored("web01 SHA256:" + FpB + "\n10.0.0.5 SHA256:" + FpB);
        var presented = new[] { Key("web01", FpC, HostKeyStatus.Changed, FpB), Key("10.0.0.5", FpA, HostKeyStatus.Changed, FpB) };

        var applied = ConnectorService.ApplyTrust(Many, creds, presented, new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "WEB01" });

        var one = Assert.Single(applied);
        Assert.Equal(("web01", HostKeyStatus.Changed, FpB), (one.Host, one.Status, one.PinnedFingerprint));
        Assert.Equal("web01 SHA256:" + FpC + "\n10.0.0.5 SHA256:" + FpB, creds["knownHostKeys"]);
    }

    [Fact]
    public void Trusting_a_key_that_is_already_pinned_changes_nothing()
    {
        var creds = ManyStored("10.0.0.5 SHA256:" + FpA);
        Assert.Empty(ConnectorService.ApplyTrust(Many, creds, new[] { Key("10.0.0.5", FpA) }));
        Assert.Equal("10.0.0.5 SHA256:" + FpA, creds["knownHostKeys"]);
    }

    [Fact]
    public void The_single_fingerprint_form_pins_its_own_host_only()
    {
        var creds = SingleStored();
        Assert.Empty(ConnectorService.ApplyTrust(Single, creds, new[] { Key("other.corp.local", FpA) })); // the form moved on since the test
        Assert.Equal("", creds["hostKey"]);

        Assert.Single(ConnectorService.ApplyTrust(Single, creds, new[] { Key("fw.corp.local", FpA) }));
        Assert.Equal("SHA256:" + FpA, creds["hostKey"]);
        Assert.Equal(FpA, ConnectorService.PinnedFingerprint(Single, creds, "fw.corp.local"));

        Assert.Empty(ConnectorService.ApplyTrust(Single, creds, new[] { Key("fw.corp.local", FpB) })); // changed: not without the confirmation
        Assert.Single(ConnectorService.ApplyTrust(Single, creds, new[] { Key("fw.corp.local", FpB) }, new HashSet<string> { "fw.corp.local" }));
        Assert.Equal("SHA256:" + FpB, creds["hostKey"]);
    }

    [Fact]
    public void A_source_without_ssh_has_nothing_to_pin()
    {
        var meta = new AdapterMetadata("api", "API", "Test", "", Array.Empty<AssetKind>(), new[] { new CredentialField("host", "Host") }, "read-only");
        var creds = new Dictionary<string, string> { ["host"] = "fw.corp.local" };
        Assert.Empty(ConnectorService.ApplyTrust(meta, creds, new[] { Key("fw.corp.local", FpA) }));
        Assert.Single(creds);
    }

    // ---- the saved password

    [Fact]
    public void Pinning_a_host_key_does_not_ask_for_the_password_again()
    {
        var form = ManyStored(); form["password"] = "";
        ConnectorService.ApplyTrust(Many, form, new[] { Key("10.0.0.5", FpA) });
        Assert.Empty(ConnectorService.ReuseStoredSecrets(Many, form, ManyStored()));
        Assert.Equal("s3cret", form["password"]);

        var fw = SingleStored(); fw["password"] = "";
        ConnectorService.ApplyTrust(Single, fw, new[] { Key("fw.corp.local", FpA) });
        Assert.Empty(ConnectorService.ReuseStoredSecrets(Single, fw, SingleStored()));
        Assert.Equal("s3cret", fw["password"]);
    }

    [Theory]
    [InlineData("hosts", "10.0.0.5\nattacker.example.com")]
    [InlineData("hosts", "10.0.0.5:2222\n10.0.0.6:2222\nweb01")]
    [InlineData("username", "someone-else")]
    public void Changing_the_host_or_port_still_does_even_with_host_keys_pinned(string key, string value)
    {
        var form = ManyStored(); form["password"] = ""; form[key] = value;
        ConnectorService.ApplyTrust(Many, form, new[] { Key("10.0.0.5", FpA) });
        Assert.Equal(new[] { "Password" }, ConnectorService.ReuseStoredSecrets(Many, form, ManyStored()));
        Assert.Equal("", form["password"]);
    }

    [Fact]
    public void Changing_the_appliance_address_still_asks_for_the_password()
    {
        var form = SingleStored("SHA256:" + FpA); form["password"] = ""; form["host"] = "fw.corp.local:2222";
        Assert.Equal(new[] { "Password" }, ConnectorService.ReuseStoredSecrets(Single, form, SingleStored("SHA256:" + FpA)));
    }

    // ---- through the service: test result, audit, scheduled runs

    private ConnectorService Service(FakeSshAdapter adapter) => new(_factory, new IInventoryAdapter[] { adapter }, Array.Empty<ITicketAdapter>(),
        new InventoryService(_factory, NullLogger<InventoryService>.Instance), new PassThroughProtection(), NullLogger<ConnectorService>.Instance);

    [Fact]
    public async Task The_test_result_carries_the_presented_keys()
    {
        var adapter = new FakeSshAdapter(Many) { Presents = { ["10.0.0.5"] = FpA, ["web01"] = FpC } };
        var svc = Service(adapter);
        var result = await svc.TestAsync(Many.Id, ManyStored("web01 SHA256:" + FpB), null);

        Assert.False(result.Ok);
        var keys = result.HostKeys.OrderBy(k => k.Host).ToList();
        Assert.Equal(new[] { ("10.0.0.5", HostKeyStatus.New), ("web01", HostKeyStatus.Changed) }, keys.Select(k => (k.Host, k.Status)));
        Assert.Equal(FpB, keys[1].PinnedFingerprint);
        Assert.Equal("ssh-ed25519", keys[0].KeyType);
    }

    [Fact]
    public async Task Trusting_saves_the_pin_keeps_the_password_and_writes_the_fingerprints_to_the_audit_log()
    {
        var adapter = new FakeSshAdapter(Many) { Presents = { ["10.0.0.5"] = FpA, ["10.0.0.6:2222"] = FpA, ["web01"] = FpC } };
        var svc = Service(adapter);
        var c = await svc.SaveAsync(null, Many.Id, "Linux fleet", ManyStored("web01 SHA256:" + FpB), true, 240, "admin");
        var test = await svc.TestAsync(Many.Id, ManyStored("web01 SHA256:" + FpB), c.Id);

        // "Trust all N new hosts": whatever the caller passes, the changed one stays as it was
        var applied = await svc.TrustHostKeysAsync(c.Id, test.HostKeys.ToList(), null, "admin");
        Assert.Equal(2, applied.Count);
        var stored = svc.Decrypt((await svc.GetAsync(c.Id))!);
        Assert.Equal("s3cret", stored["password"]);
        Assert.Equal("web01 SHA256:" + FpB + "\n10.0.0.5 SHA256:" + FpA + "\n10.0.0.6:2222 SHA256:" + FpA, stored["knownHostKeys"]);

        // "Replace pinned key", for the one host that was confirmed
        var replaced = await svc.TrustHostKeysAsync(c.Id, test.HostKeys.ToList(), new HashSet<string> { "web01" }, "admin");
        Assert.Equal("web01", Assert.Single(replaced).Host);
        Assert.Equal(FpC, SshHostKeys.PinnedFor(svc.Decrypt((await svc.GetAsync(c.Id))!)["knownHostKeys"], "web01"));

        await using var db = _factory.CreateDbContext();
        var trust = await db.Audit.SingleAsync(a => a.Action == "connector.hostkey.trust");
        Assert.Equal(("admin", "Linux fleet"), (trust.Actor, trust.Target));
        Assert.Equal("10.0.0.5 ssh-ed25519 SHA256:" + FpA + "; 10.0.0.6:2222 ssh-ed25519 SHA256:" + FpA, trust.After);
        var replace = await db.Audit.SingleAsync(a => a.Action == "connector.hostkey.replace");
        Assert.Equal("web01 SHA256:" + FpB, replace.Before);
        Assert.Equal("web01 ssh-ed25519 SHA256:" + FpC, replace.After);
        Assert.DoesNotContain(await db.Audit.Select(a => a.After).ToListAsync(), a => a != null && a.Contains("s3cret"));
    }

    [Fact]
    public async Task Pins_typed_into_the_form_are_audited_on_save_and_a_blank_password_is_kept()
    {
        var svc = Service(new FakeSshAdapter(Many));
        var c = await svc.SaveAsync(null, Many.Id, "Linux fleet", ManyStored(), true, 240, "admin");
        var form = ManyStored("10.0.0.5 SHA256:" + FpA); form["password"] = "";

        await svc.SaveAsync(c.Id, Many.Id, "Linux fleet", form, true, 240, "admin");

        Assert.Equal("s3cret", svc.Decrypt((await svc.GetAsync(c.Id))!)["password"]);
        await using var db = _factory.CreateDbContext();
        var pins = await db.Audit.SingleAsync(a => a.Action == "connector.hostkeys");
        Assert.Null(pins.Before);
        Assert.Equal("10.0.0.5 SHA256:" + FpA, pins.After);
    }

    [Fact]
    public async Task A_run_that_meets_unpinned_or_changed_hosts_leaves_them_for_review_until_they_are_trusted()
    {
        var adapter = new FakeSshAdapter(Many) { Presents = { ["10.0.0.5"] = FpA, ["10.0.0.6:2222"] = FpA, ["web01"] = FpC } };
        var svc = Service(adapter);
        var c = await svc.SaveAsync(null, Many.Id, "Linux fleet", ManyStored("web01 SHA256:" + FpB + "\n10.0.0.6:2222 SHA256:" + FpA), true, 240, "admin");

        await svc.RunAsync(c.Id);
        var pending = ConnectorService.PendingHostKeys((await svc.GetAsync(c.Id))!).OrderBy(k => k.Host).ToList();
        Assert.Equal(new[] { ("10.0.0.5", HostKeyStatus.New), ("web01", HostKeyStatus.Changed) }, pending.Select(k => (k.Host, k.Status)));

        // the warning on every page links to the prompt
        var notices = await new HealthNotices(new SettingsService(_factory, new PassThroughProtection()), _factory, svc).HostKeysAsync();
        Assert.Equal(2, notices.Count);
        Assert.All(notices, n => Assert.Equal("/connectors?review=" + c.Id, n.Link));
        Assert.Contains(notices, n => n.Error && n.Text.Contains("different SSH host key"));

        await svc.TrustHostKeysAsync(c.Id, pending, null, "admin");
        Assert.Equal("web01", Assert.Single(ConnectorService.PendingHostKeys((await svc.GetAsync(c.Id))!)).Host);

        await svc.TrustHostKeysAsync(c.Id, pending, new HashSet<string> { "web01" }, "admin");
        await svc.RunAsync(c.Id);
        Assert.Null((await svc.GetAsync(c.Id))!.PendingHostKeysJson);
        Assert.Empty(await new HealthNotices(new SettingsService(_factory, new PassThroughProtection()), _factory, svc).HostKeysAsync());
    }

    /// <summary>Behaves like the SSH adapters as far as host keys go: each host presents a key, and an unpinned or changed one is refused.</summary>
    private sealed class FakeSshAdapter : IInventoryAdapter
    {
        public FakeSshAdapter(AdapterMetadata metadata) => Metadata = metadata;
        public AdapterMetadata Metadata { get; }
        public Dictionary<string, string> Presents { get; } = new();

        private int Connect(IReadOnlyDictionary<string, string> credentials)
        {
            var refused = 0;
            foreach (var host in credentials["hosts"].Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (!Presents.TryGetValue(host, out var fp)) continue;
                var pinned = SshHostKeys.PinnedFor(credentials.GetValueOrDefault("knownHostKeys"), host);
                var trusted = SshHostKeys.Check(fp, pinned, acceptAny: false) == HostKeyCheck.Trusted;
                SshHostKeys.Observe(host, "ssh-ed25519", "SHA256:" + fp, pinned, trusted);
                if (!trusted) refused++;
            }
            return refused;
        }

        public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
        {
            await Task.Yield();
            var refused = Connect(credentials);
            return new TestResult(refused == 0, refused + " refused");
        }

        public async Task<CollectResult> CollectAsync(IReadOnlyDictionary<string, string> credentials, DateTime? since, IProgress<string>? progress, CancellationToken ct)
        {
            await Task.Yield();
            var result = new CollectResult();
            if (Connect(credentials) > 0) result.Warnings.Add("some hosts were refused");
            return result;
        }
    }

    private sealed class TestFactory : IDbContextFactory<VvDbContext>
    {
        private readonly DbContextOptions<SqliteVvDbContext> _o;
        public TestFactory(SqliteConnection c) => _o = new DbContextOptionsBuilder<SqliteVvDbContext>().UseSqlite(c).Options;
        public VvDbContext CreateDbContext() => new SqliteVvDbContext(_o);
        public Task<VvDbContext> CreateDbContextAsync(CancellationToken ct = default) => Task.FromResult(CreateDbContext());
    }

    private sealed class PassThroughProtection : IDataProtectionProvider, IDataProtector
    {
        public IDataProtector CreateProtector(string purpose) => this;
        public byte[] Protect(byte[] plaintext) => plaintext;
        public byte[] Unprotect(byte[] protectedData) => protectedData;
    }
}
