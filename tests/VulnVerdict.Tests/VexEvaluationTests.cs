using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

/// <summary>
/// What each kind of vendor VEX statement does to a verdict. A missed vulnerability is the dangerous mistake, so the
/// not-affected cases are the ones pinned down hardest: applied only on an exact match, never for an exploited CVE,
/// never by closing the verdict, and undone when the vendor withdraws the statement.
/// </summary>
public class VexEvaluationTests : IDisposable
{
    private const string Cve = EvaluatorHarness.Cve;
    private readonly EvaluatorHarness _h = new();
    public void Dispose() => _h.Dispose();

    private static VexStatement St(VexStatus status, string? version = null, string product = "FortiOS", string? platform = null, string? justification = null, string? detail = null, string revision = "1") => new()
    {
        Provider = "fortinet", DocumentId = "FG-VEX-2099-01", CveId = Cve, Status = status, Vendor = "Fortinet", VendorNorm = "fortinet", Product = product, ProductNorm = Normalizer.Norm(product),
        Version = version, Platform = platform, PlatformNorm = platform is null ? null : Normalizer.Norm(platform), Justification = justification, Detail = detail,
        Url = "https://vex.fortinet.example/csaf/fg-vex-2099-01.json", DocumentDate = new DateTime(2026, 9, 20, 0, 0, 0, DateTimeKind.Utc), Revision = revision, RetrievedAt = DateTime.UtcNow
    };

    /// <summary>FortiOS on the watchlist with one CVE affecting 7.2.0 up to 7.2.8, evaluated once before any vendor statement exists.</summary>
    private async Task<Verdict> BaselineAsync(string? version = "7.2.5", string? versionsJson = null, bool kev = false)
    {
        await _h.SeedAsync(db =>
        {
            if (versionsJson is null) EvaluatorHarness.AddFortiOs(db); else EvaluatorHarness.AddCve(db, Cve, "Fortinet", "FortiOS", versionsJson);
            EvaluatorHarness.AddWatchlist(db, version: version);
            if (kev) db.Kev.Add(new KevEntry { CveId = Cve, DateAdded = DateTime.UtcNow.AddDays(-2), RetrievedAt = DateTime.UtcNow });
        });
        await _h.Evaluator().EvaluateAllAsync();
        return Assert.Single(await _h.VerdictsAsync());
    }

    private async Task<Verdict> WithStatementsAsync(params VexStatement[] statements)
    {
        await using (var db = await _h.Factory.CreateDbContextAsync())
        {
            await db.VexStatements.ExecuteDeleteAsync();
            db.VexStatements.AddRange(statements);
            await db.SaveChangesAsync();
        }
        await _h.Evaluator().EvaluateAllAsync();
        return Assert.Single(await _h.VerdictsAsync());
    }

    private static List<EvidenceClaim> Evidence(Verdict v) => System.Text.Json.JsonSerializer.Deserialize<List<EvidenceClaim>>(v.EvidenceJson)!;

    // ---- fixed -------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Fixed_adds_the_vendors_fixed_version_when_the_cve_record_names_none()
    {
        var before = await BaselineAsync(versionsJson: "[{\"version\":\"7.2.5\",\"status\":\"affected\"}]");   // the record names the affected version and no fix
        Assert.False(VersionCompare.IsParseable(before.FixedIn));   // "a release later than 7.2.5"

        var v = await WithStatementsAsync(St(VexStatus.Fixed, "7.2.6", detail: "vendor_fix: https://vex.fortinet.example/FG-IR-99-001"));
        Assert.Equal("7.2.6", v.FixedIn);
        Assert.Contains("Fixed in 7.2.6.", v.Sentence);
        Assert.Equal(before.Tier, v.Tier);
        Assert.Contains(Evidence(v), e => e.Claim == "Vendor VEX: Fortinet lists FortiOS 7.2.6 as fixed (vendor_fix: https://vex.fortinet.example/FG-IR-99-001)" && e.Source == "https://vex.fortinet.example/csaf/fg-vex-2099-01.json");
    }

    // ---- known affected ----------------------------------------------------------------------------------------------

    [Fact]
    public async Task Known_affected_raises_a_check_this_match_to_exact_or_likely()
    {
        var before = await BaselineAsync(version: null);   // no installed version recorded: "possible (check this)"
        Assert.Equal(MatchConfidence.Possible, before.Confidence);
        Assert.Contains("Check this", before.Sentence);

        var exact = await WithStatementsAsync(St(VexStatus.KnownAffected));
        Assert.Equal(MatchConfidence.Exact, exact.Confidence);
        Assert.DoesNotContain("Check this", exact.Sentence);
        Assert.True(exact.Tier >= before.Tier);
        Assert.Contains(Evidence(exact), e => e.Claim == "Vendor VEX: Fortinet states FortiOS is affected");

        // the vendor names the product as part of something this entry does not record: the product is confirmed, not the rest
        var likely = await WithStatementsAsync(St(VexStatus.KnownAffected, platform: "FortiGate 7000F"));
        Assert.Equal(MatchConfidence.Likely, likely.Confidence);
    }

    [Fact]
    public async Task Known_affected_for_the_exact_installed_version_outweighs_a_range_that_excludes_it()
    {
        var before = await BaselineAsync(version: "7.2.9");
        Assert.Equal(VerdictTier.NotAffected, before.Tier);

        // the product as a whole, or its branch: evidence and a prompt to check, the tier stays
        var vague = await WithStatementsAsync(St(VexStatus.KnownAffected));
        Assert.Equal(VerdictTier.NotAffected, vague.Tier);
        Assert.Contains(Evidence(vague), e => e.Claim.Contains("is affected: check, the version check puts the installed version outside the affected range"));

        var named = await WithStatementsAsync(St(VexStatus.KnownAffected, "7.2.9"));
        Assert.True(named.Tier > VerdictTier.NotAffected);
        Assert.Equal(MatchConfidence.Exact, named.Confidence);
    }

    // ---- known not affected ------------------------------------------------------------------------------------------

    [Fact]
    public async Task Not_affected_on_an_exact_match_makes_the_verdict_not_affected_and_keeps_it_listed_with_the_statement()
    {
        var before = await BaselineAsync();
        Assert.True(before.Tier >= VerdictTier.NextPatchCycle);

        var v = await WithStatementsAsync(St(VexStatus.KnownNotAffected, "7.2.5", justification: "vulnerable_code_not_present"));

        Assert.Equal(VerdictTier.NotAffected, v.Tier);
        Assert.Equal(VerdictState.Open, v.State);        // listed like any other not-affected verdict: not closed, not hidden
        Assert.Null(v.StateOwner);
        Assert.Equal(MatchConfidence.Exact, v.Confidence);
        Assert.Equal("Fortinet FortiOS 7.2.5 on FW-EDGE-01: not affected, the vendor states this product is not affected (the vulnerable code is not present).", v.Sentence);
        var claim = Assert.Single(Evidence(v), e => e.Claim.StartsWith(VexAssessor.AppliedPrefix));
        Assert.Contains("Fortinet states FortiOS 7.2.5 is not affected (the vulnerable code is not present), in a statement dated 2026-09-20", claim.Claim);
        Assert.Equal("https://vex.fortinet.example/csaf/fg-vex-2099-01.json", claim.Source);
        Assert.Equal("Document FG-VEX-2099-01, revision 1, revised 2026-09-20", claim.Excerpt);
        var change = Assert.Single(v.History, h => h.Kind == "tier");
        Assert.Equal((before.Tier.ToString(), nameof(VerdictTier.NotAffected), VexAssessor.NotAffectedReason), (change.From, change.To, change.Reason));
        Assert.DoesNotContain(v.History, h => h.Kind == "state");
    }

    [Theory]
    [InlineData("FortiOS", "7.2", null)]                       // the branch, or 7.2.0 exactly
    [InlineData("FortiOS", null, "FortiGate 7000F")]           // as a component of something this entry does not record
    [InlineData("FortiOS-6K7K", null, null)]                   // a related product
    public async Task Not_affected_on_a_weaker_match_is_evidence_only_and_the_tier_does_not_move(string product, string? version, string? platform)
    {
        var before = await BaselineAsync();
        var v = await WithStatementsAsync(St(VexStatus.KnownNotAffected, version, product, platform, "vulnerable_code_not_present"));

        Assert.Equal(before.Tier, v.Tier);
        Assert.Equal(before.SlaDue, v.SlaDue);
        Assert.Empty(v.History);
        Assert.DoesNotContain("not affected", v.Sentence);
        Assert.Contains(Evidence(v), e => e.Claim.StartsWith("Vendor VEX: Fortinet says not affected for " + product) && e.Claim.Contains(": check. Not applied"));
        Assert.DoesNotContain(Evidence(v), e => e.Claim.StartsWith(VexAssessor.AppliedPrefix));
    }

    [Fact]
    public async Task Not_affected_for_another_version_is_not_even_evidence()
    {
        var before = await BaselineAsync();
        var v = await WithStatementsAsync(St(VexStatus.KnownNotAffected, "7.4.1"));
        Assert.Equal(before.Tier, v.Tier);
        Assert.DoesNotContain(Evidence(v), e => e.Claim.Contains("Vendor VEX"));
    }

    [Fact]
    public async Task Not_affected_never_lowers_a_cve_in_kev_it_is_flagged_for_a_person()
    {
        var before = await BaselineAsync(kev: true);
        Assert.Equal(VerdictTier.FixToday, before.Tier);

        var v = await WithStatementsAsync(St(VexStatus.KnownNotAffected, "7.2.5", justification: "vulnerable_code_not_present"));

        Assert.Equal(VerdictTier.FixToday, v.Tier);
        Assert.Equal(VerdictState.Open, v.State);
        Assert.Equal(before.Confidence, v.Confidence);   // still emailed as Fix today: the flag does not turn it into a "check this"
        Assert.Empty(v.History);
        Assert.EndsWith("Check this: the vendor states this product is not affected (the vulnerable code is not present); it is exploited in the wild, so confirm before closing.", v.Sentence);
        Assert.Contains(Evidence(v), e => e.Claim.Contains("this CVE is exploited in the wild, so the verdict is not lowered automatically") && e.Source.StartsWith("https://vex.fortinet.example/"));
        Assert.DoesNotContain(Evidence(v), e => e.Claim.StartsWith(VexAssessor.AppliedPrefix));
    }

    [Fact]
    public async Task Not_affected_applied_before_a_cve_reaches_kev_is_taken_back_when_it_does()
    {
        await BaselineAsync();
        var lowered = await WithStatementsAsync(St(VexStatus.KnownNotAffected, "7.2.5"));
        Assert.Equal(VerdictTier.NotAffected, lowered.Tier);

        await _h.SeedAsync(db => db.Kev.Add(new KevEntry { CveId = Cve, DateAdded = DateTime.UtcNow, RetrievedAt = DateTime.UtcNow }));
        await _h.Evaluator().EvaluateAllAsync();
        var v = Assert.Single(await _h.VerdictsAsync());
        Assert.Equal(VerdictTier.FixToday, v.Tier);
        Assert.Null(v.ImmediateEmailSentAt);
        // the statement still stands; what changed is the exploitation, and that is the reason recorded
        Assert.Equal("now in CISA KEV", v.History.Where(h => h.Kind == "tier").OrderBy(h => h.Id).Last().Reason);
        Assert.Contains(Evidence(v), e => e.Claim.Contains("so the verdict is not lowered automatically"));
    }

    [Fact]
    public async Task A_verdict_already_settled_by_the_installed_version_still_closes_as_patched()
    {
        await BaselineAsync();
        // the vendor says the product is not affected at 7.2.8, and the watchlist is then updated to 7.2.8, outside the affected range
        await using (var db = await _h.Factory.CreateDbContextAsync())
        {
            db.VexStatements.Add(St(VexStatus.KnownNotAffected, "7.2.8", justification: "vulnerable_code_not_present"));
            await db.Watchlist.ExecuteUpdateAsync(u => u.SetProperty(w => w.Version, "7.2.8"));
            await db.SaveChangesAsync();
        }
        await _h.Evaluator().EvaluateAllAsync();

        var v = Assert.Single(await _h.VerdictsAsync());
        Assert.Equal((VerdictTier.NotAffected, VerdictState.Closed, "system"), (v.Tier, v.State, v.StateOwner));
        Assert.EndsWith("not affected, the installed version is outside the affected range.", v.Sentence);
        Assert.Contains(Evidence(v), e => e.Claim.StartsWith("Vendor VEX: Fortinet also states FortiOS 7.2.8 is not affected"));
        Assert.DoesNotContain(Evidence(v), e => e.Claim.StartsWith(VexAssessor.AppliedPrefix));
    }

    // ---- under investigation -----------------------------------------------------------------------------------------

    [Fact]
    public async Task Under_investigation_is_an_evidence_line_and_nothing_else()
    {
        var before = await BaselineAsync();
        var v = await WithStatementsAsync(St(VexStatus.UnderInvestigation));
        Assert.Equal((before.Tier, before.Confidence, before.Sentence), (v.Tier, v.Confidence, v.Sentence));
        Assert.Empty(v.History);
        Assert.Contains(Evidence(v), e => e.Claim == "Vendor VEX: Fortinet is still investigating whether FortiOS is affected");
    }

    // ---- withdrawn ---------------------------------------------------------------------------------------------------

    [Fact]
    public async Task A_revision_that_withdraws_not_affected_brings_the_verdict_back_with_a_fresh_fix_window()
    {
        var before = await BaselineAsync();
        var lowered = await WithStatementsAsync(St(VexStatus.KnownNotAffected, "7.2.5"));
        Assert.Equal(VerdictTier.NotAffected, lowered.Tier);
        Assert.Null(lowered.SlaDue);

        // revision 2 of the vendor's document lists the same version as affected
        var v = await WithStatementsAsync(St(VexStatus.KnownAffected, "7.2.5", revision: "2"));

        Assert.Equal(before.Tier, v.Tier);
        Assert.Equal(VerdictState.Open, v.State);
        Assert.NotNull(v.SlaDue);
        Assert.Null(v.TicketSentAt);
        var back = v.History.Where(h => h.Kind == "tier").OrderBy(h => h.Id).Last();
        Assert.Equal((nameof(VerdictTier.NotAffected), before.Tier.ToString(), VexAssessor.WithdrawnReason), (back.From, back.To, back.Reason));
        Assert.DoesNotContain("not affected", v.Sentence);
    }

    [Fact]
    public async Task A_verdict_someone_closed_on_the_vendors_word_reopens_when_the_vendor_withdraws_it()
    {
        var before = await BaselineAsync();
        await WithStatementsAsync(St(VexStatus.KnownNotAffected, "7.2.5"));
        await using (var db = await _h.Factory.CreateDbContextAsync())
            await db.Verdicts.ExecuteUpdateAsync(u => u.SetProperty(x => x.State, VerdictState.Closed).SetProperty(x => x.StateOwner, "alice").SetProperty(x => x.StateReason, "vendor says not affected"));

        // while the statement stands, the closure stands
        await _h.Evaluator().EvaluateAllAsync();
        Assert.Equal(VerdictState.Closed, Assert.Single(await _h.VerdictsAsync()).State);

        // the statement goes (the document was withdrawn): nothing says not affected any more
        var v = await WithStatementsAsync();
        Assert.Equal(VerdictState.Open, v.State);
        Assert.Equal(before.Tier, v.Tier);
        Assert.Null(v.StateOwner);
        Assert.Contains(v.History, h => h.Kind == "state" && h.From == "Closed" && h.To == "Open" && h.Reason == "re-opened: " + VexAssessor.WithdrawnReason);
    }

    // ---- packages ----------------------------------------------------------------------------------------------------

    [Fact]
    public async Task A_red_hat_package_gets_its_streams_fix_from_the_vendor_document_and_ignores_other_streams()
    {
        Guid software = Guid.NewGuid();
        await _h.SeedAsync(db =>
        {
            var asset = new Asset { Id = Guid.NewGuid(), DisplayName = "web-01", Exposure = Exposure.Internet, FirstSeen = DateTime.UtcNow, LastSeen = DateTime.UtcNow };
            db.Assets.Add(asset);
            db.Software.Add(new SoftwareInstance
            {
                Id = software, AssetId = asset.Id, Vendor = "Red Hat Enterprise Linux", Product = "openssl", Version = "1:3.0.7-25.el9", VendorNorm = "redhatenterpriselinux", ProductNorm = "openssl",
                Purl = "pkg:rpm/redhat/openssl@3.0.7-25.el9?arch=x86_64&epoch=1", Ecosystem = "Red Hat:enterprise_linux:9::appstream", MappingStatus = MappingStatus.Package, ConnectorId = "test", FirstSeen = DateTime.UtcNow, LastSeen = DateTime.UtcNow,
            });
            db.Cves.Add(new Cve { Id = Cve, State = "PUBLISHED", RetrievedAt = DateTime.UtcNow, CvssV31Vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" });
            using var doc = System.Text.Json.JsonDocument.Parse(Fixtures.Read("vex", "redhat_cve-2099-1001.json"));
            db.VexStatements.AddRange(VulnVerdict.Core.Feeds.Vex.CsafVexParser.Parse(doc.RootElement, "redhat", "Red Hat", null, DateTime.UtcNow).Statements);
        });
        await _h.Evaluator(s => s.AddSingleton<VulnVerdict.Core.Adapters.IPackageVulnSource>(new OsvSaysAffected())).EvaluateAllAsync();

        var v = Assert.Single(await _h.VerdictsAsync());
        Assert.True(v.Tier > VerdictTier.NotAffected);   // the RHEL 8 not-affected statement says nothing about a RHEL 9 host
        Assert.Equal("3.0.7-28.el9_4", v.FixedIn);
        Assert.Contains(Evidence(v), e => e.Claim.StartsWith("Vendor VEX: Red Hat lists openssl 3.0.7-28.el9_4 as a component of Red Hat Enterprise Linux AppStream (v. 9) as fixed"));
        Assert.DoesNotContain(Evidence(v), e => e.Claim.Contains("Red Hat Enterprise Linux 8"));
    }

    private sealed class OsvSaysAffected : VulnVerdict.Core.Adapters.IPackageVulnSource
    {
        public Task<IReadOnlyList<VulnVerdict.Core.Adapters.PackageVuln>> LookupAsync(IEnumerable<VulnVerdict.Core.Adapters.PackageQuery> queries, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<VulnVerdict.Core.Adapters.PackageVuln>>(queries.Select(q => new VulnVerdict.Core.Adapters.PackageVuln(q.Key, Cve, null, "OSV RHSA-test")).ToList());
    }
}
