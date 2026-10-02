using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;
using VulnVerdict.Core.Services;
using Xunit;

namespace VulnVerdict.Tests;

/// <summary>
/// "What changed and why": the evaluator records the inputs before and after a change, and the timeline turns the
/// difference into plain sentences with the evidence that caused it and the rule that matched each side.
/// </summary>
public class VerdictChangesTests : IDisposable
{
    private const string Cve = "CVE-2099-1001";
    private readonly SqliteConnection _conn;
    private readonly TestDbFactory _factory;
    private readonly VerdictEvaluator _evaluator;
    private readonly VerdictWorkflow _workflow;

    public VerdictChangesTests()
    {
        _conn = new SqliteConnection("DataSource=:memory:");
        _conn.Open();
        _factory = new TestDbFactory(new DbContextOptionsBuilder<VvDbContext>().UseSqlite(_conn).Options);
        using (var db = _factory.CreateDbContext()) db.Database.EnsureCreated();
        var settings = new SettingsService(_factory, new PassthroughProtectionProvider());
        var webhooks = new WebhookService(_factory, settings, new FakeHttpClientFactory(new FakeHandler()), NullLogger<WebhookService>.Instance);
        _evaluator = new VerdictEvaluator(_factory, settings, new ServiceCollection().BuildServiceProvider(), webhooks, NullLogger<VerdictEvaluator>.Instance);
        _workflow = new VerdictWorkflow(_factory, settings, webhooks, new WatchlistService(_factory, _evaluator));
    }

    public void Dispose() => _conn.Dispose();

    /// <summary>FortiOS 7.2.0 up to 7.2.8 affected, network-reachable and automatable, on a watchlist entry; then the first evaluation.</summary>
    private async Task<Guid> SeedAsync(Exposure exposure, Criticality criticality, string version = "7.2.5")
    {
        Guid entry;
        await using (var db = await _factory.CreateDbContextAsync())
        {
            db.Cves.Add(new Cve { Id = Cve, State = "PUBLISHED", RetrievedAt = DateTime.UtcNow, Description = "test record", CvssV31Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", CvssV31Score = 9.8 });
            db.CveAffected.Add(new CveAffected
            {
                CveId = Cve, Vendor = "Fortinet", Product = "FortiOS", VendorNorm = Normalizer.Norm("Fortinet"), ProductNorm = Normalizer.Norm("FortiOS"),
                DefaultStatus = "unaffected", VersionsJson = "[{\"version\":\"7.2.0\",\"status\":\"affected\",\"lessThan\":\"7.2.8\",\"versionType\":\"semver\"}]",
            });
            var e = new WatchlistEntry
            {
                Id = Guid.NewGuid(), Vendor = "Fortinet", Product = "FortiOS", VendorNorm = Normalizer.Norm("Fortinet"), ProductNorm = Normalizer.Norm("FortiOS"),
                Version = version, AssetName = "FW-EDGE-01", Exposure = exposure, Criticality = criticality, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow,
            };
            db.Watchlist.Add(e);
            entry = e.Id;
            await db.SaveChangesAsync();
        }
        await _evaluator.EvaluateAllAsync();
        return entry;
    }

    private async Task<Verdict> VerdictAsync()
    {
        await using var db = await _factory.CreateDbContextAsync();
        return await db.Verdicts.AsNoTracking().Include(v => v.History).SingleAsync();
    }

    private async Task<List<TimelineEntry>> TimelineAsync(string? exposureEvidence = null, Exposure? currentExposure = null) =>
        VerdictChanges.Timeline((await VerdictAsync()).History, exposureEvidence, currentExposure);

    private async Task AddKevAsync()
    {
        await using var db = await _factory.CreateDbContextAsync();
        db.Kev.Add(new KevEntry { CveId = Cve, DateAdded = new DateTime(2026, 10, 1), RetrievedAt = DateTime.UtcNow });
        await db.SaveChangesAsync();
    }

    // ------------------------------------------------------------------ through the evaluator

    [Fact]
    public async Task A_new_verdict_has_no_inputs_line_and_an_unchanged_one_gains_none()
    {
        await SeedAsync(Exposure.Internet, Criticality.Standard);
        await _evaluator.EvaluateAllAsync();
        Assert.Empty((await VerdictAsync()).History);
        Assert.Empty(await TimelineAsync());
    }

    [Fact]
    public async Task KEV_promotion_names_the_KEV_entry_and_the_rule_before_and_after()
    {
        await SeedAsync(Exposure.Internal, Criticality.Critical);
        Assert.Equal(VerdictTier.NextPatchCycle, (await VerdictAsync()).Tier);
        await AddKevAsync();
        await _evaluator.EvaluateAllAsync();

        var t = Assert.Single(await TimelineAsync());
        Assert.Equal("promoted from Next patch cycle to Fix today because CVE added to CISA KEV (evidence: KEV entry dated 2026-10-01)", t.Text);
        Assert.Equal("rule 14: no known exploit, automatable, internal, on a critical asset (Next patch cycle)", t.RuleBefore);
        Assert.Equal("rule 3: exploited in the wild, automatable, on an internal asset that is not low-value (Fix today)", t.RuleAfter);

        // the inputs line stays out of the digest's way, and the tier line the digest reads is unchanged
        var v = await VerdictAsync();
        var inputs = Assert.Single(v.History, h => h.Kind == VerdictChanges.Kind);
        Assert.True(inputs.Digested);
        Assert.True(inputs.Reason!.Length <= 1000);
        Assert.Contains(v.History, h => h.Kind == "tier" && h.Reason == "now in CISA KEV" && !h.Digested);
    }

    [Fact]
    public async Task EPSS_crossing_the_threshold_is_explained_with_both_scores_and_drift_below_it_records_nothing()
    {
        await SeedAsync(Exposure.Internet, Criticality.Standard);
        await using (var db = await _factory.CreateDbContextAsync())
        {
            db.Epss.Add(new EpssScore { CveId = Cve, Score = 0.04, Percentile = 0.5, ScoreDate = DateTime.UtcNow.Date, RetrievedAt = DateTime.UtcNow });
            await db.SaveChangesAsync();
        }
        await _evaluator.EvaluateAllAsync();
        Assert.Empty((await VerdictAsync()).History);   // 0.04 changes no input

        await using (var db = await _factory.CreateDbContextAsync()) await db.Epss.ExecuteUpdateAsync(u => u.SetProperty(e => e.Score, 0.31));
        await _evaluator.EvaluateAllAsync();

        var t = Assert.Single(await TimelineAsync());
        Assert.Equal("promoted from Fix this week to Fix today because EPSS rose from 0.04 to 0.31, crossing the 0.10 threshold", t.Text);
        Assert.StartsWith("rule 12: ", t.RuleBefore);
        Assert.StartsWith("rule 6: ", t.RuleAfter);

        await using (var db = await _factory.CreateDbContextAsync()) await db.Epss.ExecuteUpdateAsync(u => u.SetProperty(e => e.Score, 0.08));
        await _evaluator.EvaluateAllAsync();
        Assert.Equal("demoted from Fix today to Fix this week because EPSS fell from 0.31 to 0.08, back under the 0.10 threshold", (await TimelineAsync())[0].Text);
    }

    [Fact]
    public async Task A_widened_range_reopens_with_the_old_and_new_range()
    {
        var entry = await SeedAsync(Exposure.Internet, Criticality.Standard);
        // upgraded to the fixed version: closed as patched
        await using (var db = await _factory.CreateDbContextAsync()) await db.Watchlist.Where(w => w.Id == entry).ExecuteUpdateAsync(u => u.SetProperty(w => w.Version, "7.2.8"));
        await _evaluator.EvaluateAllAsync();
        Assert.Equal("demoted from Fix this week to Not affected and closed because installed version changed from 7.2.5 to 7.2.8: no affected range covers 7.2.8 (affected: 7.2.0 < 7.2.8)",
            (await TimelineAsync())[0].Text);

        // the CNA widens the range: 7.2.8 is affected after all
        await using (var db = await _factory.CreateDbContextAsync())
            await db.CveAffected.ExecuteUpdateAsync(u => u.SetProperty(a => a.VersionsJson, "[{\"version\":\"7.2.0\",\"status\":\"affected\",\"lessThanOrEqual\":\"7.2.9\",\"versionType\":\"semver\"}]"));
        await _evaluator.EvaluateAllAsync();

        var timeline = await TimelineAsync();
        Assert.Equal(2, timeline.Count);
        Assert.Equal("re-opened and promoted from Not affected to Fix this week because installed version 7.2.8 is inside the widened affected range 7.2.0–7.2.9 (was 7.2.0 up to, not including, 7.2.8)",
            timeline[0].Text);
        Assert.StartsWith("rule 1: ", timeline[0].RuleBefore);
        Assert.StartsWith("rule 12: ", timeline[0].RuleAfter);
    }

    [Fact]
    public async Task An_exposure_change_carries_the_evidence_for_the_exposure_it_ends_at()
    {
        var entry = await SeedAsync(Exposure.Internal, Criticality.Standard);
        Assert.Equal(VerdictTier.IgnoreTracked, (await VerdictAsync()).Tier);
        await using (var db = await _factory.CreateDbContextAsync()) await db.Watchlist.Where(w => w.Id == entry).ExecuteUpdateAsync(u => u.SetProperty(w => w.Exposure, Exposure.Internet));
        await _evaluator.EvaluateAllAsync();

        var t = Assert.Single(await TimelineAsync("FortiGate VIP 'web-dmz'", Exposure.Internet));
        Assert.Equal("promoted from Ignore (tracked) to Fix this week because exposure changed from Internal network only to Internet-facing (FortiGate VIP 'web-dmz')", t.Text);
        Assert.StartsWith("rule 15: ", t.RuleBefore);
        Assert.StartsWith("rule 12: ", t.RuleAfter);
        // evidence for some other exposure does not belong to this change
        Assert.EndsWith("to Internet-facing", Assert.Single(await TimelineAsync("isolated VLAN 40", Exposure.Isolated)).Text);
    }

    [Fact]
    public async Task A_rule_change_that_keeps_the_tier_is_still_recorded_and_explained()
    {
        var entry = await SeedAsync(Exposure.Internal, Criticality.Critical);
        await AddKevAsync();
        await _evaluator.EvaluateAllAsync();   // rule 3, Fix today
        await using (var db = await _factory.CreateDbContextAsync()) await db.Watchlist.Where(w => w.Id == entry).ExecuteUpdateAsync(u => u.SetProperty(w => w.Exposure, Exposure.Internet));
        await _evaluator.EvaluateAllAsync();   // rule 2, still Fix today

        var v = await VerdictAsync();
        Assert.Equal(2, v.RuleNumber);
        Assert.Single(v.History, h => h.Kind == "tier");
        var t = (await TimelineAsync())[0];
        Assert.Equal("still Fix today, for a different reason: exposure changed from Internal network only to Internet-facing", t.Text);
        Assert.Equal("rule 3: exploited in the wild, automatable, on an internal asset that is not low-value (Fix today)", t.RuleBefore);
        Assert.Equal("rule 2: exploited in the wild and reachable from the internet (Fix today)", t.RuleAfter);
    }

    [Fact]
    public async Task What_people_did_reads_as_who_did_what_and_a_human_done_reopened_by_KEV_says_why()
    {
        await SeedAsync(Exposure.Internet, Criticality.Critical);
        var id = (await VerdictAsync()).Id;
        await _workflow.SnoozeAsync(id, "olga", new DateTime(2099, 3, 30), "change window");
        await _workflow.ReopenAsync(id, "olga");
        await _workflow.DoneAsync(id, "olga", "7.2.8", updateWatchlist: false, note: null);
        await AddKevAsync();
        await _evaluator.EvaluateAllAsync();

        var texts = (await TimelineAsync()).Select(t => t.Text).ToList();
        Assert.Equal(new[]
        {
            "re-opened and promoted from Fix this week to Fix today because CVE added to CISA KEV (evidence: KEV entry dated 2026-10-01)",
            "marked done by olga: now running 7.2.8",
            "re-opened by olga",
            "snoozed by olga: change window (until " + new DateTime(2099, 3, 30).ToString("d MMM yyyy") + ")",
        }, texts);
    }

    // ------------------------------------------------------------------ the diff on its own

    private static readonly VerdictSnapshot Base = new()
    {
        Tier = VerdictTier.NextPatchCycle, Rule = 10, Exploitation = Exploitation.PoC, Automatable = false, AttackVector = AttackVector.Network,
        DeclaredExposure = Exposure.Internal, EffectiveExposure = Exposure.Internal, Criticality = Criticality.Standard, Epss = 0.03,
        VersionCheck = "7.2.3 is inside the affected range 7.0.0 <= 7.2.6", ExploitEvidence = "Public exploit: Exploit-DB - FortiOS RCE",
    };

    [Fact]
    public void Each_input_that_moved_gets_its_own_phrase()
    {
        var after = Base with { Criticality = Criticality.Critical, Automatable = true, AttackVector = AttackVector.Adjacent, Control = "WAF in front (Cloudflare)" };
        Assert.Equal(new[]
        {
            "criticality changed from Standard to Critical",
            "attack path re-assessed: was reachable over any network, now same broadcast domain or VPN segment",
            "now judged automatable at scale",
            "compensating control recorded: WAF in front (Cloudflare)",
        }, VerdictChanges.Explain(Base, after));
        Assert.Empty(VerdictChanges.Explain(Base, Base with { Epss = 0.09 }));
    }

    [Fact]
    public void Exploitation_changes_name_their_evidence()
    {
        var none = Base with { Exploitation = Exploitation.None, ExploitEvidence = null };
        Assert.Equal(new[] { "public exploit code published (evidence: Public exploit: Exploit-DB - FortiOS RCE)" }, VerdictChanges.Explain(none, Base));
        Assert.Equal(new[] { "EPSS is now 0.31, crossing the 0.10 threshold" }, VerdictChanges.Explain(none with { Epss = null }, none with { Exploitation = Exploitation.PoC, Epss = 0.31 }));
        Assert.Equal(new[] { "now reported as exploited in the wild (evidence: Vendor advisory FG-IR-24-015; the vendor states it is exploited in the wild)" },
            VerdictChanges.Explain(Base, Base with { Exploitation = Exploitation.Active, ExploitEvidence = "Vendor advisory FG-IR-24-015; the vendor states it is exploited in the wild" }));
        Assert.Equal(new[] { "CVE no longer listed in CISA KEV" },
            VerdictChanges.Explain(Base with { Exploitation = Exploitation.Active, InKev = true, KevSince = "2026-10-01" }, Base));
        Assert.Equal(new[] { "exploit evidence withdrawn: was public exploit code exists, now no known exploit" }, VerdictChanges.Explain(Base, none));
    }

    [Fact]
    public void Version_changes_say_whether_the_version_or_the_range_moved()
    {
        var clear = Base with
        {
            Tier = VerdictTier.NotAffected, Rule = 1, DeclaredExposure = Exposure.NotInstalled, EffectiveExposure = Exposure.NotInstalled,
            VersionCheck = "no affected range covers 7.2.3 (affected: 7.0.0 < 7.2.3)",
        };
        Assert.Equal(new[] { "installed version 7.2.3 is inside the widened affected range 7.0.0–7.2.6 (was 7.0.0 up to, not including, 7.2.3)" },
            VerdictChanges.Explain(clear, Base with { Version = "7.2.3" }));
        // rolled back: the range is the same one, the version is not
        Assert.Equal(new[] { "installed version changed from 7.2.8 to 7.2.3, which is inside the affected range 7.0.0–7.2.6" },
            VerdictChanges.Explain(clear with { VersionCheck = "no affected range covers 7.2.8 (affected: 7.0.0 <= 7.2.6)" }, Base with { Version = "7.2.3" }));
        Assert.Equal(new[] { "the role, feature or service is now disabled, so it is treated as not installed" },
            VerdictChanges.Explain(Base, Base with { Tier = VerdictTier.NotAffected, Rule = 1, DeclaredExposure = Exposure.NotInstalled, EffectiveExposure = Exposure.NotInstalled, Version = "7.2.3" }));
    }

    [Fact]
    public void Ranges_read_in_plain_words()
    {
        Assert.Equal("7.0.0–7.2.6", VerdictChanges.PlainRange("7.0.0 <= 7.2.6"));
        Assert.Equal("anything before 7.2.7", VerdictChanges.PlainRange("any < 7.2.7"));
        Assert.Equal("7.0.0 up to, not including, 7.0.12, 7.2.0 and later", VerdictChanges.PlainRange("7.0.0 < 7.0.12, 7.2.0 <= any"));
        Assert.Equal("7.2.x (unparsed)", VerdictChanges.PlainRange("7.2.x (unparsed)"));
    }

    [Fact]
    public void Both_snapshots_always_fit_a_history_reason()
    {
        var wordy = Base with { Version = "7.2.3", VersionCheck = new string('v', 150), ExploitEvidence = new string('e', 100), Control = new string('c', 80), KevSince = "2026-10-01", InKev = true };
        var packed = VerdictChanges.Pack(wordy with { VersionCheck = new string('"', 150) }, wordy);
        Assert.True(packed.Length <= 1000, packed.Length.ToString());
        var (before, after) = VerdictChanges.Unpack(packed)!.Value;
        Assert.Equal(wordy.Rule, after.Rule);
        Assert.Equal(wordy.Epss, before.Epss);
        Assert.Equal("7.2.3", after.Version);
        Assert.Null(VerdictChanges.Unpack("now in CISA KEV"));
        Assert.Null(VerdictChanges.Unpack(null));
    }

    [Fact]
    public void History_from_before_inputs_were_recorded_still_reads()
    {
        var at = new DateTime(2026, 9, 1, 7, 12, 0, DateTimeKind.Utc);
        var timeline = VerdictChanges.Timeline(new[]
        {
            new VerdictHistory { Id = 1, At = at, Actor = "system", Kind = "tier", From = "FixThisWeek", To = "FixToday", Reason = "now in CISA KEV" },
            new VerdictHistory { Id = 2, At = at, Actor = "system", Kind = "state", From = "Snoozed", To = "Open", Reason = "re-opened: promoted to Fix today (now in CISA KEV)" },
            new VerdictHistory { Id = 3, At = at.AddDays(1), Actor = "system", Kind = "state", From = "AcceptedRisk", To = "Open", Reason = "accepted risk expired" },
        });
        Assert.Equal(new[] { "re-opened: accepted risk expired", "promoted from Fix this week to Fix today, which lifted the snooze: now in CISA KEV" }, timeline.Select(t => t.Text));
        Assert.All(timeline, t => Assert.Null(t.RuleBefore));
    }

    private sealed class TestDbFactory : IDbContextFactory<VvDbContext>
    {
        private readonly DbContextOptions<VvDbContext> _options;
        public TestDbFactory(DbContextOptions<VvDbContext> options) => _options = options;
        public VvDbContext CreateDbContext() => new(_options);
        public Task<VvDbContext> CreateDbContextAsync(CancellationToken ct = default) => Task.FromResult(CreateDbContext());
    }

    private sealed class PassthroughProtectionProvider : IDataProtectionProvider, IDataProtector
    {
        public IDataProtector CreateProtector(string purpose) => this;
        public byte[] Protect(byte[] plaintext) => plaintext;
        public byte[] Unprotect(byte[] protectedData) => protectedData;
    }
}
