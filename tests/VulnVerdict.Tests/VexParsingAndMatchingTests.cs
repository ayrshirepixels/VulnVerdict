using System.Text.Json;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;
using VulnVerdict.Core.Feeds.Vex;

namespace VulnVerdict.Tests;

/// <summary>CSAF VEX documents into statements, and statements against what is installed.</summary>
public class VexParsingAndMatchingTests
{
    private static readonly DateTime Now = new(2026, 10, 2, 12, 0, 0, DateTimeKind.Utc);

    private static CsafDocument Parse(string fixture, Func<string, bool>? keep = null)
    {
        using var doc = JsonDocument.Parse(Fixtures.Read("vex", fixture));
        return CsafVexParser.Parse(doc.RootElement, "redhat", "Red Hat", "https://vex.example.test/fetched.json", Now, keep);
    }

    private static Subject Package(string name, string version, string ecosystem, string vendor = "Red Hat Enterprise Linux") =>
        new(vendor, name, version, "web-01", Exposure.Internal, Criticality.Standard, SoftwareInstanceId: Guid.NewGuid(), AssetId: Guid.NewGuid(),
            Purl: "pkg:rpm/redhat/" + name + "@" + version, Ecosystem: ecosystem);

    private static Subject Product(string vendor, string product, string? version, MatchConfidence confidence = MatchConfidence.Exact) =>
        new(vendor, product, version, "FW-EDGE-01", Exposure.Internet, Criticality.Critical, WatchlistEntryId: Guid.NewGuid(), ProductConfidence: confidence);

    // ---- product tree ------------------------------------------------------------------------------------------------

    [Fact]
    public void Red_hat_document_maps_components_of_a_product_stream_and_collapses_architectures()
    {
        var doc = Parse("redhat_cve-2099-1001.json");
        Assert.Equal("CVE-2099-1001", doc.DocumentId);
        Assert.Equal("3", doc.Revision);
        Assert.Equal(new DateTime(2026, 9, 1, 11, 7, 0, DateTimeKind.Utc), doc.Date);
        Assert.Equal("https://security.access.redhat.com/data/csaf/v2/vex/2099/cve-2099-1001.json", doc.Url);
        Assert.Equal(8, doc.StatementsInDocument);   // five fixed ids, one each of the others
        Assert.Equal(6, doc.Statements.Count);       // src, x86_64 and aarch64 of the same package are one statement
        Assert.All(doc.Statements, s => { Assert.Equal("CVE-2099-1001", s.CveId); Assert.Equal("Red Hat", s.Vendor); Assert.Equal("redhat", s.Provider); });

        var fix = doc.Statements.Single(s => s.Status == VexStatus.Fixed && s.Product == "openssl" && s.PlatformCpe == "cpe:/a:redhat:enterprise_linux:9::appstream");
        Assert.Equal("3.0.7-28.el9_4", fix.Version);
        Assert.Equal("Red Hat Enterprise Linux AppStream (v. 9)", fix.Platform);
        Assert.Equal("vendor_fix: https://access.redhat.com/errata/RHSA-2099:4312", fix.Detail);
        Assert.Null(fix.Justification);

        var eus = doc.Statements.Single(s => s.Status == VexStatus.Fixed && s.PlatformCpe == "cpe:/a:redhat:rhel_eus:9.2::appstream");
        Assert.Equal("3.0.7-18.el9_2", eus.Version);

        var notAffected = doc.Statements.Single(s => s.Status == VexStatus.KnownNotAffected);
        Assert.Equal(("openssl", (string?)null, "Red Hat Enterprise Linux 8", "vulnerable_code_not_present"), (notAffected.Product, notAffected.Version, notAffected.Platform, notAffected.Justification));
        Assert.Equal("cpe:/o:redhat:enterprise_linux:8", notAffected.PlatformCpe);

        var affected = doc.Statements.Single(s => s.Status == VexStatus.KnownAffected);
        Assert.Equal(("compat-openssl11", "Red Hat Enterprise Linux 9", "no_fix_planned: Out of support scope"), (affected.Product, affected.Platform, affected.Detail));

        var investigating = doc.Statements.Single(s => s.Status == VexStatus.UnderInvestigation);
        Assert.Equal("Red Hat Enterprise Linux 10", investigating.Platform);
    }

    [Fact]
    public void Only_statements_about_wanted_products_are_kept()
    {
        Assert.Empty(Parse("redhat_cve-2099-1001.json", n => CsafVexFeed.Relevant(new[] { "curl" }, n)).Statements);
        // a related name is kept as well (either contains the other); the evaluator shows it as evidence only
        Assert.Equal(6, Parse("redhat_cve-2099-1001.json", n => CsafVexFeed.Relevant(new[] { "openssl" }, n)).Statements.Count);
        var kept = Parse("redhat_cve-2099-1001.json", n => CsafVexFeed.Relevant(new[] { "openssllibs" }, n)).Statements;
        Assert.Equal(5, kept.Count);
        Assert.DoesNotContain(kept, s => s.Product == "compat-openssl11");
    }

    [Fact]
    public void Vendor_advisory_maps_name_and_version_branches_ranges_groups_and_cpe()
    {
        var doc = Parse("vendor_advisory.json");
        Assert.Equal("EX-SA-2099-01", doc.DocumentId);
        Assert.Equal("https://vex.example.test/fetched.json", doc.Url);   // no self reference: where it was fetched from
        Assert.Equal(4, doc.Statements.Count);                            // first_fixed and recommended name the same fix once; the entry with no CVE is skipped
        Assert.All(doc.Statements, s => Assert.Equal("Example Networks", s.Vendor));

        var exact = doc.Statements.Single(s => s.Status == VexStatus.KnownAffected && s.Version is not null);
        Assert.Equal(("ExampleOS", "exampleos", "7.2.5", "cpe:2.3:o:example:exampleos:7.2.5:*:*:*:*:*:*:*"), (exact.Product, exact.ProductNorm, exact.Version, exact.Cpe));
        Assert.Equal("vendor_fix: Upgrade to ExampleOS 7.2.8 or later.", exact.Detail);

        var range = doc.Statements.Single(s => s.VersionRange is not null);
        Assert.Equal((VexStatus.KnownAffected, "vers:generic/>=7.0.0|<7.2.8", (string?)null), (range.Status, range.VersionRange, range.Version));

        Assert.Equal("7.2.8", doc.Statements.Single(s => s.Status == VexStatus.Fixed).Version);

        var notAffected = doc.Statements.Single(s => s.Status == VexStatus.KnownNotAffected);
        Assert.Equal(("Example Manager", "component_not_present", "Example Manager does not include the management interface code."), (notAffected.Product, notAffected.Justification, notAffected.Detail));
        Assert.Null(notAffected.Platform);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"document\":{\"csaf_version\":\"2.0\",\"tracking\":{\"id\":\"X\"}}}")]
    [InlineData("{\"document\":{\"title\":\"an error page\"},\"vulnerabilities\":[]}")]
    public void Something_that_is_not_a_csaf_document_with_vulnerabilities_is_an_error_not_an_empty_result(string json)
    {
        using var doc = JsonDocument.Parse(json);
        Assert.Throws<FormatException>(() => CsafVexParser.Parse(doc.RootElement, "redhat", "Red Hat", null, Now));
    }

    [Fact]
    public void Purl_and_cpe_helpers()
    {
        Assert.Equal(("openssh", "8.7p1-38.el9_4.1"), CsafVexParser.ParsePurl("pkg:rpm/redhat/openssh@8.7p1-38.el9_4.1?arch=x86_64"));
        Assert.Equal(("openssh", (string?)null), CsafVexParser.ParsePurl("pkg:rpm/redhat/openssh?arch=src"));
        Assert.Equal(("openssh", (string?)null), CsafVexParser.ParsePurl("pkg:rpm/suse/openssh@?upstream=openssh.src.rpm"));   // SUSE writes an empty version
        Assert.Equal(("ose-cli", (string?)null), CsafVexParser.ParsePurl("pkg:oci/ose-cli@sha256:035b69cc?arch=arm64&repository_url=registry.redhat.io/openshift4/ose-cli"));
        Assert.Null(CsafVexParser.ParsePurl("not a purl"));
        Assert.Equal(new CpeName("redhat", "enterprise_linux", "9"), CsafVexParser.ParseCpe("cpe:/a:redhat:enterprise_linux:9::appstream"));
        Assert.Equal(new CpeName("fortinet", "fortios", null), CsafVexParser.ParseCpe("cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"));
        Assert.Null(CsafVexParser.ParseCpe("cpe:/o"));
    }

    // ---- matching: packages on a product stream ----------------------------------------------------------------------

    [Fact]
    public void A_package_matches_its_own_stream_exactly_another_stream_not_at_all_and_a_rebuild_as_the_product_only()
    {
        var st = Parse("redhat_cve-2099-1001.json").Statements;
        var fix9 = st.Single(s => s.Status == VexStatus.Fixed && s.Product == "openssl" && s.PlatformCpe!.Contains("enterprise_linux:9"));
        var fixEus = st.Single(s => s.PlatformCpe == "cpe:/a:redhat:rhel_eus:9.2::appstream");
        var notAffected8 = st.Single(s => s.Status == VexStatus.KnownNotAffected);
        var investigating10 = st.Single(s => s.Status == VexStatus.UnderInvestigation);
        var libs = st.Single(s => s.Product == "openssl-libs");

        var rhel9 = Package("openssl", "1:3.0.7-25.el9", "Red Hat:enterprise_linux:9::appstream");
        Assert.Equal(VexMatchLevel.Exact, VexAssessor.Match(rhel9, fix9).Level);
        Assert.Equal(VexMatchLevel.Product, VexAssessor.Match(rhel9, fixEus).Level);     // an extended-support stream, not the one installed
        Assert.Equal(VexMatchLevel.None, VexAssessor.Match(rhel9, notAffected8).Level);   // RHEL 8 says nothing about RHEL 9
        Assert.Equal(VexMatchLevel.None, VexAssessor.Match(rhel9, investigating10).Level);
        Assert.Equal(VexMatchLevel.Weak, VexAssessor.Match(rhel9, libs).Level);

        var rhel8 = Package("openssl", "1:1.1.1k-12.el8_9", "Red Hat:enterprise_linux:8::baseos");
        Assert.Equal(VexMatchLevel.Exact, VexAssessor.Match(rhel8, notAffected8).Level);
        var alma8 = Package("openssl", "1:1.1.1k-12.el8_9", "AlmaLinux:8", "AlmaLinux");
        Assert.Equal(VexMatchLevel.Product, VexAssessor.Match(alma8, notAffected8).Level);
        var ubuntu = Package("openssl", "3.0.2-0ubuntu1.18", "Ubuntu:22.04:LTS", "Ubuntu");
        Assert.Equal(VexMatchLevel.Weak, VexAssessor.Match(ubuntu, notAffected8).Level);
    }

    [Fact]
    public void Red_hat_statements_give_a_rhel9_package_the_fix_for_its_own_stream_and_leave_it_affected()
    {
        var a = VexAssessor.Assess(Package("openssl", "1:3.0.7-25.el9", "Red Hat:enterprise_linux:9::appstream"), Parse("redhat_cve-2099-1001.json").Statements, VersionMatch.Affected, exploited: false)!;
        Assert.Equal("3.0.7-28.el9_4", a.FixedIn);   // not the older 9.2 EUS build
        Assert.Null(a.Overall);
        Assert.Null(a.NotAffectedText);
        Assert.Contains(a.Evidence, e => e.Claim.StartsWith("Vendor VEX: Red Hat lists openssl 3.0.7-28.el9_4 as a component of Red Hat Enterprise Linux AppStream (v. 9) as fixed") && e.Source.EndsWith("cve-2099-1001.json"));
        Assert.DoesNotContain(a.Evidence, e => e.Claim.Contains("not affected for openssl"));
    }

    [Fact]
    public void Red_hat_not_affected_applies_on_rhel8_and_is_only_evidence_on_a_rebuild()
    {
        var statements = Parse("redhat_cve-2099-1001.json").Statements;
        var on8 = VexAssessor.Assess(Package("openssl", "1:1.1.1k-12.el8_9", "Red Hat:enterprise_linux:8::baseos"), statements, VersionMatch.Affected, exploited: false)!;
        Assert.Equal(VersionMatch.NotAffected, on8.Overall);
        Assert.Equal("the vendor states this product is not affected (the vulnerable code is not present)", on8.NotAffectedText);
        var applied = Assert.Single(on8.Evidence, e => e.Claim.StartsWith(VexAssessor.AppliedPrefix));
        Assert.Contains("in a statement dated 2026-09-01", applied.Claim);
        Assert.Equal("Document CVE-2099-1001, revision 3, revised 2026-09-01", applied.Excerpt);

        var onAlma = VexAssessor.Assess(Package("openssl", "1:1.1.1k-12.el8_9", "AlmaLinux:8", "AlmaLinux"), statements, VersionMatch.Affected, exploited: false)!;
        Assert.Null(onAlma.Overall);
        Assert.Contains(onAlma.Evidence, e => e.Claim.StartsWith("Vendor VEX: Red Hat says not affected for openssl as a component of Red Hat Enterprise Linux 8: check"));
    }

    // ---- matching: products by vendor, name and version ---------------------------------------------------------------

    private static VexStatement St(VexStatus status, string? version = null, string product = "FortiOS", string vendor = "Fortinet", string? range = null, string? platform = null, string? cpe = null) => new()
    {
        Provider = "test", DocumentId = "DOC-1", CveId = "CVE-2099-1001", Status = status, Vendor = vendor, VendorNorm = Normalizer.Norm(vendor), Product = product, ProductNorm = Normalizer.Norm(product),
        Version = version, VersionRange = range, Platform = platform, PlatformNorm = platform is null ? null : Normalizer.Norm(platform), Cpe = cpe, RetrievedAt = Now
    };

    [Fact]
    public void Product_statements_match_by_vendor_name_and_version()
    {
        var installed = Product("Fortinet", "FortiOS", "7.2.5");
        Assert.Equal(new VexMatch(St(VexStatus.KnownNotAffected, "7.2.5"), VexMatchLevel.Exact, true), VexAssessor.Match(installed, St(VexStatus.KnownNotAffected, "7.2.5")), MatchComparer.Instance);
        Assert.Equal(VexMatchLevel.Exact, VexAssessor.Match(installed, St(VexStatus.KnownNotAffected)).Level);                   // the product as a whole
        Assert.Equal(VexMatchLevel.Exact, VexAssessor.Match(installed, St(VexStatus.KnownNotAffected, product: "Fortinet FortiOS")).Level);
        Assert.Equal(VexMatchLevel.Exact, VexAssessor.Match(installed, St(VexStatus.KnownNotAffected, product: "FortiOS firmware", cpe: "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*")).Level);
        Assert.Equal(VexMatchLevel.None, VexAssessor.Match(installed, St(VexStatus.KnownNotAffected, "7.4.1")).Level);           // about another version
        Assert.Equal(VexMatchLevel.Product, VexAssessor.Match(installed, St(VexStatus.KnownNotAffected, "7.2")).Level);          // the branch, or 7.2.0 exactly: not confirmed
        Assert.Equal(VexMatchLevel.Product, VexAssessor.Match(installed, St(VexStatus.KnownNotAffected, platform: "FortiGate 7000F")).Level);
        Assert.Equal(VexMatchLevel.Weak, VexAssessor.Match(installed, St(VexStatus.KnownNotAffected, product: "FortiOS-6K7K")).Level);
        Assert.Equal(VexMatchLevel.Weak, VexAssessor.Match(installed, St(VexStatus.KnownNotAffected, vendor: "Somebody Else")).Level);
        Assert.Equal(VexMatchLevel.None, VexAssessor.Match(installed, St(VexStatus.KnownNotAffected, product: "FortiProxy")).Level);
        // a fixed statement names the fixed version, not the installed one
        Assert.Equal(VexMatchLevel.Exact, VexAssessor.Match(installed, St(VexStatus.Fixed, "7.2.8")).Level);
        // no installed version, or a product mapped by a fuzzy name: never exact
        Assert.Equal(VexMatchLevel.Product, VexAssessor.Match(Product("Fortinet", "FortiOS", null), St(VexStatus.KnownNotAffected, "7.2.5")).Level);
        Assert.Equal(VexMatchLevel.Product, VexAssessor.Match(Product("Fortinet", "FortiOS", "7.2.5", MatchConfidence.Likely), St(VexStatus.KnownNotAffected, "7.2.5")).Level);
    }

    private sealed class MatchComparer : IEqualityComparer<VexMatch>
    {
        public static readonly MatchComparer Instance = new();
        public bool Equals(VexMatch? a, VexMatch? b) => a!.Level == b!.Level && a.VersionExplicit == b.VersionExplicit;
        public int GetHashCode(VexMatch m) => (int)m.Level;
    }

    [Theory]
    [InlineData("7.2.5", "vers:generic/>=7.0.0|<7.2.8", true)]
    [InlineData("7.2.8", "vers:generic/>=7.0.0|<7.2.8", false)]
    [InlineData("6.4.9", "vers:generic/>=7.0.0|<7.2.8", false)]
    [InlineData("7.2.4", "<= 7.2.4", true)]
    [InlineData("7.2.5", "<= 7.2.4", false)]
    [InlineData("7.4.2", ">=7.0, <7.2.8, >=7.4.0, <7.4.3", true)]
    [InlineData("7.3.0", ">=7.0, <7.2.8, >=7.4.0, <7.4.3", false)]
    [InlineData("7.6.0", ">= 7.4", true)]
    [InlineData("7.2.5", "vers:generic/7.2.4|7.2.5", true)]
    [InlineData("7.2.5", "vers:generic/*", true)]
    [InlineData("7.2.5", "all versions prior to 7.2.8", null)]
    public void Version_ranges(string installed, string range, bool? expected) => Assert.Equal(expected, VexAssessor.InRange(installed, range));

    [Fact]
    public void A_range_decides_whether_the_statement_is_about_the_installed_version()
    {
        var statements = Parse("vendor_advisory.json").Statements;
        var range = statements.Single(s => s.VersionRange is not null);
        Assert.Equal(VexMatchLevel.Exact, VexAssessor.Match(Product("Example Networks", "ExampleOS", "7.1.0"), range).Level);
        Assert.Equal(VexMatchLevel.None, VexAssessor.Match(Product("Example Networks", "ExampleOS", "7.2.9"), range).Level);
        // the CPE identifies the product even when the watchlist spells the vendor its own way
        var named = statements.Single(s => s.Version == "7.2.5");
        Assert.Equal(new VexMatch(named, VexMatchLevel.Exact, true), VexAssessor.Match(Product("Example", "ExampleOS", "7.2.5"), named));
    }

    // ---- assessment --------------------------------------------------------------------------------------------------

    [Fact]
    public void Not_affected_is_not_applied_when_the_vendor_data_also_says_affected_or_names_a_later_fix()
    {
        var installed = Product("Fortinet", "FortiOS", "7.2.5");
        var both = VexAssessor.Assess(installed, new[] { St(VexStatus.KnownNotAffected), St(VexStatus.KnownAffected, "7.2.5") }, VersionMatch.Affected, false)!;
        Assert.Null(both.Overall);
        Assert.Null(both.NotAffectedText);
        Assert.Contains(both.Evidence, e => e.Claim.Contains("not applied, check"));
        Assert.DoesNotContain(both.Evidence, e => e.Claim.StartsWith(VexAssessor.AppliedPrefix));

        var laterFix = VexAssessor.Assess(installed, new[] { St(VexStatus.KnownNotAffected), St(VexStatus.Fixed, "7.2.8") }, VersionMatch.Affected, false)!;
        Assert.Null(laterFix.Overall);
        Assert.Equal("7.2.8", laterFix.FixedIn);

        // a fix at or below the installed version contradicts nothing
        var olderFix = VexAssessor.Assess(installed, new[] { St(VexStatus.KnownNotAffected), St(VexStatus.Fixed, "7.2.3") }, VersionMatch.Affected, false)!;
        Assert.Equal(VersionMatch.NotAffected, olderFix.Overall);
        Assert.Null(olderFix.FixedIn);
    }

    [Fact]
    public void Tier_reasons_are_read_back_from_the_evidence()
    {
        var applied = new List<EvidenceClaim> { new(VexAssessor.AppliedPrefix + "Fortinet states FortiOS is not affected", "https://vendor.example/vex.json", Now) };
        var none = new List<EvidenceClaim> { new("Version check: inside the affected range", "CVE List V5", Now) };
        var storedApplied = JsonSerializer.Serialize(applied);
        Assert.Equal(VexAssessor.NotAffectedReason, VexAssessor.TierReason(null, applied, VerdictTier.NotAffected));
        Assert.Null(VexAssessor.TierReason(null, none, VerdictTier.NotAffected));
        Assert.Equal(VexAssessor.WithdrawnReason, VexAssessor.TierReason(storedApplied, none, VerdictTier.FixThisWeek));
        Assert.Null(VexAssessor.TierReason(storedApplied, applied, VerdictTier.FixThisWeek));
        Assert.Null(VexAssessor.TierReason(JsonSerializer.Serialize(none), none, VerdictTier.FixThisWeek));
    }

    // ---- providers ---------------------------------------------------------------------------------------------------

    [Fact]
    public void Provider_list_defaults_when_blank_and_rejects_what_it_cannot_use()
    {
        Assert.Same(VexProviders.Defaults, VexProviders.Parse(""));
        Assert.Equal(new[] { "redhat", "suse" }, VexProviders.Defaults.Where(p => p.Enabled).Select(p => p.Id));
        Assert.Equal(VexProviders.Defaults.Select(p => p.Id), VexProviders.Parse(VexProviders.DefaultsJson).Select(p => p.Id));

        var custom = VexProviders.Parse("""[{"id":"acme","name":"Acme","url":"https://acme.example/csaf/vex/","vendors":["Acme Corp"]}]""");
        Assert.True(Assert.Single(custom).Enabled);
        Assert.Throws<FormatException>(() => VexProviders.Parse("[{"));
        Assert.Throws<FormatException>(() => VexProviders.Parse("""[{"id":"acme","name":"Acme","url":"http://acme.example/vex/","vendors":["Acme"]}]"""));
        Assert.Throws<FormatException>(() => VexProviders.Parse("""[{"id":"acme","name":"Acme","url":"https://acme.example/vex/","vendors":[]}]"""));
    }

    [Fact]
    public void A_provider_speaks_for_its_vendors_products_and_package_ecosystems()
    {
        var redhat = VexProviders.Defaults.Single(p => p.Id == "redhat");
        Assert.True(redhat.SpeaksFor("Red Hat Enterprise Linux", "Red Hat:enterprise_linux:9::baseos"));
        Assert.True(redhat.SpeaksFor("Rocky Linux", "Rocky Linux:9"));
        Assert.True(redhat.SpeaksFor("redhat"));
        Assert.False(redhat.SpeaksFor("Fortinet"));
        Assert.False(redhat.SpeaksFor("", "Ubuntu:22.04:LTS"));
    }
}
