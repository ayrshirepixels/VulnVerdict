using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;

namespace VulnVerdict.Tests;

public class VersionTests
{
    [Theory]
    [InlineData("7.2.5", "7.2.8", -1)]
    [InlineData("7.2.8", "7.2.8", 0)]
    [InlineData("7.2", "7.2.0", 0)]
    [InlineData("7.10.1", "7.9.9", 1)]
    [InlineData("10.0.20348.2322", "10.0.20348.2000", 1)]
    [InlineData("v2.1.0", "2.1.0", 0)]
    [InlineData("2.1.0-beta", "2.1.0", -1)]
    [InlineData("2.1.0-rc1", "2.1.0-beta2", 1)]
    [InlineData("16.0.1", "16.0.1 (build 1234)", 0)]
    [InlineData("1.2.3", "1.2.3.1", -1)]
    // hotfix, maintenance-release and patch tags come after the bare version, unlike pre-release tags
    [InlineData("11.1.5", "11.1.5-h1", -1)]        // PAN-OS (CVE-2024-0012 fixed in 11.1.5-h1)
    [InlineData("11.1.5-h1", "11.1.5-h10", -1)]
    [InlineData("11.1.5-h1", "11.1.5", 1)]
    [InlineData("21.0", "21.0 MR1 (21.0.1)", -1)]  // Sophos
    [InlineData("21.0 GA", "21.0 MR1", -1)]
    [InlineData("5.21", "5.21-patch1", -1)]        // Zyxel
    [InlineData("5.21 Patch 1", "5.21-patch1", 0)]
    [InlineData("8.9p1", "8.9", 1)]                // OpenSSH
    [InlineData("7.1.1-7058", "7.1.2-7019", -1)]   // SonicOS
    public void Compares_dotted_versions(string a, string b, int expectedSign)
    {
        var c = VersionCompare.Compare(a, b);
        Assert.NotNull(c);
        Assert.Equal(expectedSign, Math.Sign(c!.Value));
    }

    [Fact]
    public void Unparseable_versions_return_null()
    {
        Assert.Null(VersionCompare.Compare("n/a", "1.0"));
        Assert.Null(VersionCompare.Compare("1.0", "unspecified"));
    }

    private static List<AffectedVersion> V(params (string? version, string? status, string? lessThan, string? lessThanOrEqual)[] rows) =>
        rows.Select(r => new AffectedVersion { Version = r.version, Status = r.status, LessThan = r.lessThan, LessThanOrEqual = r.lessThanOrEqual }).ToList();

    [Fact]
    public void Fixed_in_is_the_next_unaffected_release_above_the_installed_one()
    {
        // CVE-2024-23897 as Jenkins files it: affected by default, with these releases unaffected.
        var versions = V(("0", "unaffected", "1.606", null), ("2.442", "unaffected", "*", null), ("2.426.3", "unaffected", "2.426.*", null), ("2.440.1", "unaffected", "2.440.*", null));

        var onLts = VersionMatcher.Evaluate("2.440", versions, "affected");
        Assert.Equal(VersionMatch.Affected, onLts.Match);
        Assert.Equal("2.440.1", onLts.FixedIn);   // was "0", the start of the "old releases never affected" range

        var onWeekly = VersionMatcher.Evaluate("2.441", versions, "affected");
        Assert.Equal(VersionMatch.Affected, onWeekly.Match);
        Assert.Equal("2.442", onWeekly.FixedIn);

        Assert.Equal(VersionMatch.NotAffected, VersionMatcher.Evaluate("2.440.1", versions, "affected").Match);
        Assert.Equal(VersionMatch.NotAffected, VersionMatcher.Evaluate("2.442", versions, "affected").Match);
    }

    [Fact]
    public void Structured_range_matches_exactly()
    {
        var versions = V(("7.2.0", "affected", "7.2.8", null), ("7.4.0", "affected", "7.4.4", null));
        var r = VersionMatcher.Evaluate("7.2.5", versions, "unaffected");
        Assert.Equal(VersionMatch.Affected, r.Match);
        Assert.Equal(MatchConfidence.Exact, r.Confidence);
        Assert.Equal("7.2.8", r.FixedIn);

        var fixedVersion = VersionMatcher.Evaluate("7.2.8", versions, "unaffected");
        Assert.Equal(VersionMatch.NotAffected, fixedVersion.Match);
        Assert.Equal(MatchConfidence.Exact, fixedVersion.Confidence);

        var other = VersionMatcher.Evaluate("7.6.1", versions, "unaffected");
        Assert.Equal(VersionMatch.NotAffected, other.Match);
    }

    [Fact]
    public void Fixed_in_comes_from_the_installed_branch()
    {
        // Fortinet style: several branches, inclusive upper bounds, newest branch listed first
        var versions = V(("7.4.0", "affected", null, "7.4.2"), ("7.2.0", "affected", null, "7.2.6"), ("7.0.0", "affected", null, "7.0.13"));
        var r = VersionMatcher.Evaluate("7.2.5", versions, "unaffected");
        Assert.Equal(VersionMatch.Affected, r.Match);
        Assert.Equal("a release later than 7.2.6", r.FixedIn);

        var exclusive = V(("7.4.0", "affected", "7.4.3", null), ("7.2.0", "affected", "7.2.7", null));
        Assert.Equal("7.2.7", VersionMatcher.Evaluate("7.2.5", exclusive, "unaffected").FixedIn);
    }

    [Fact]
    public void Less_than_or_equal_is_inclusive()
    {
        var versions = V(("0", "affected", null, "2.4.1"));
        Assert.Equal(VersionMatch.Affected, VersionMatcher.Evaluate("2.4.1", versions, null).Match);
        Assert.Equal(VersionMatch.NotAffected, VersionMatcher.Evaluate("2.4.2", versions, null).Match);
    }

    [Fact]
    public void Unaffected_entries_take_precedence()
    {
        var versions = V(("0", "affected", "*", null), ("3.0.5", "unaffected", null, null));
        var r = VersionMatcher.Evaluate("3.0.5", versions, "affected");
        Assert.Equal(VersionMatch.NotAffected, r.Match);
        Assert.Equal("3.0.5", r.FixedIn);
        Assert.Equal(VersionMatch.Affected, VersionMatcher.Evaluate("3.0.4", versions, "affected").Match);
    }

    [Fact]
    public void Default_status_affected_with_only_unaffected_rows()
    {
        var versions = V(("9.1.0", "unaffected", "*", null));
        var r = VersionMatcher.Evaluate("8.5.2", versions, "affected");
        Assert.Equal(VersionMatch.Affected, r.Match);
        Assert.Equal(MatchConfidence.Likely, r.Confidence);
        Assert.Equal(VersionMatch.NotAffected, VersionMatcher.Evaluate("9.2.0", versions, "affected").Match);
    }

    [Theory]
    [InlineData("7.2.0 - 7.2.7", "7.2.3", VersionMatch.Affected)]
    [InlineData("7.2.0 - 7.2.7", "7.2.8", VersionMatch.NotAffected)]
    [InlineData("< 7.2.8", "7.2.7", VersionMatch.Affected)]
    [InlineData("< 7.2.8", "7.2.8", VersionMatch.NotAffected)]
    [InlineData("7.2.7 and earlier", "7.2.7", VersionMatch.Affected)]
    [InlineData("prior to 2.0", "1.9", VersionMatch.Affected)]
    // SonicWall: CVE-2024-40766, CVE-2024-53704
    [InlineData("7.1.1-7058 and older versions", "7.1.1-7058", VersionMatch.Affected)]
    [InlineData("7.1.1-7058 and older versions", "7.1.1-7040", VersionMatch.Affected)]
    [InlineData("7.1.1-7058 and older versions", "7.1.2-7019", VersionMatch.NotAffected)]
    [InlineData("6.5.4.14-109n and older versions", "6.5.4.4-44v", VersionMatch.Affected)]
    // Zyxel: CVE-2024-11667, CVE-2025-9133, CVE-2022-30525, CVE-2025-1732
    [InlineData("versions V5.00 through V5.38", "5.38", VersionMatch.Affected)]
    [InlineData("versions V5.00 through V5.38", "5.39", VersionMatch.NotAffected)]
    [InlineData("versions from V4.32 through V5.40", "4.60", VersionMatch.Affected)]
    [InlineData("5.00 through 5.21 Patch 1", "5.21 Patch 1", VersionMatch.Affected)]
    [InlineData("5.00 through 5.21 Patch 1", "5.21", VersionMatch.Affected)]
    [InlineData("5.00 through 5.21 Patch 1", "5.21 Patch 2", VersionMatch.NotAffected)]
    [InlineData("<= V1.31", "1.31", VersionMatch.Affected)]
    public void Lenient_text_ranges_are_likely_matches(string text, string installed, VersionMatch expected)
    {
        var r = VersionMatcher.Evaluate(installed, V((text, "affected", null, null)), null);
        Assert.Equal(expected, r.Match);
        if (expected == VersionMatch.Affected) Assert.Equal(MatchConfidence.Likely, r.Confidence);
    }

    [Fact]
    public void Pan_os_hotfix_ranges_catch_the_unpatched_release()
    {
        // CVE-2024-0012: 11.1.0 < 11.1.5-h1 is affected; 11.1.5 without the hotfix must be caught
        var versions = V(("11.1.0", "affected", "11.1.5-h1", null));
        Assert.Equal(VersionMatch.Affected, VersionMatcher.Evaluate("11.1.5", versions, "unaffected").Match);
        Assert.Equal(VersionMatch.NotAffected, VersionMatcher.Evaluate("11.1.5-h1", versions, "unaffected").Match);
        Assert.Equal(VersionMatch.NotAffected, VersionMatcher.Evaluate("11.1.6", versions, "unaffected").Match);
    }

    [Fact]
    public void Unparsed_versions_are_possible_not_exact()
    {
        var r = VersionMatcher.Evaluate("1.0", V(("n/a", "affected", null, null)), null);
        Assert.Equal(VersionMatch.Unknown, r.Match);
        Assert.Equal(MatchConfidence.Possible, r.Confidence);

        var noVersion = VersionMatcher.Evaluate(null, V(("7.2.0", "affected", "7.2.8", null)), null);
        Assert.Equal(VersionMatch.Unknown, noVersion.Match);
        Assert.Equal(MatchConfidence.Possible, noVersion.Confidence);
    }

    [Fact]
    public void Single_version_rows_match_only_that_version()
    {
        var versions = V(("2.3.1", "affected", null, null), ("2.3.2", "affected", null, null));
        Assert.Equal(VersionMatch.Affected, VersionMatcher.Evaluate("2.3.2", versions, "unaffected").Match);
        Assert.Equal(VersionMatch.NotAffected, VersionMatcher.Evaluate("2.3.3", versions, "unaffected").Match);
    }

    [Fact]
    public void Normaliser_strips_noise()
    {
        Assert.Equal("fortios", Normalizer.Norm("FortiOS"));
        Assert.Equal("windowsserver2022", Normalizer.Norm("Windows Server 2022"));
        Assert.Equal("microsoft", Normalizer.Norm("Microsoft Corporation"));
        Assert.Equal("progresssoftware", Normalizer.Norm("Progress Software Corporation"));
        Assert.Equal(new[] { "CVE-2024-21762", "CVE-2023-27997" }, Normalizer.ExtractCveIds("cve-2024-21762;OSVDB-1;CVE-2023-27997").ToArray());
    }

    // A letter glued to a number is a later build (OpenSSL, IOS XE); a spelled-out or separated tag is a pre-release
    [Theory]
    [InlineData("1.1.1s", "1.1.1", 1)]
    [InlineData("1.1.1", "1.1.1a", -1)]
    [InlineData("1.1.1a", "1.1.1s", -1)]
    [InlineData("1.1.1s", "1.1.1t", -1)]
    [InlineData("1.1.1t", "1.1.1za", -1)]
    [InlineData("1.0.2zf", "1.0.2z", 1)]
    [InlineData("9.3a", "9.3", 1)]
    [InlineData("1.1.1s", "1.1.1.0", 1)]
    [InlineData("1.1.1a", "1.1.1-beta", 1)]
    [InlineData("1.2.0-a", "1.2.0", -1)]
    [InlineData("1.0.0beta", "1.0.0", -1)]
    [InlineData("2.0rc1", "2.0", -1)]
    [InlineData("1.0a1", "1.0", -1)]               // Python alpha
    [InlineData("1.2.0-pre", "1.2.0", -1)]
    public void Glued_letters_are_later_builds(string a, string b, int expectedSign)
    {
        Assert.Equal(expectedSign, Math.Sign(VersionCompare.Compare(a, b)!.Value));
    }

    [Fact]
    public void Openssl_lettered_release_inside_its_range()
    {
        var versions = V(("1.1.1", "affected", "1.1.1t", null));
        var r = VersionMatcher.Evaluate("1.1.1s", versions, "unaffected");
        Assert.Equal(VersionMatch.Affected, r.Match);
        Assert.Equal(VersionMatch.NotAffected, VersionMatcher.Evaluate("1.1.1t", versions, "unaffected").Match);
    }

    [Theory]
    [InlineData("7.2.5 and later")]
    [InlineData("7.2.5 onwards")]
    [InlineData("7.2.5+")]
    [InlineData(">= 7.2.5")]
    [InlineData("n/a")]
    [InlineData("*not stated*")]
    public void Unaffected_text_does_not_override_affected_ranges(string unaffected)
    {
        var versions = V(("7.0.0", "affected", "7.2.5", null), (unaffected, "unaffected", null, null));
        Assert.Equal(VersionMatch.Affected, VersionMatcher.Evaluate("7.2.3", versions, null).Match);
    }

    [Theory]
    [InlineData("7.2.5 and later")]
    [InlineData("7.2.5 onwards")]
    [InlineData("7.2.5+")]
    [InlineData(">= 7.2.5")]
    [InlineData("from 7.2.5")]
    public void Lower_bounded_unaffected_text_clears_later_releases(string unaffected)
    {
        var versions = V(("0", "affected", "*", null), (unaffected, "unaffected", null, null));
        Assert.Equal(VersionMatch.NotAffected, VersionMatcher.Evaluate("7.2.6", versions, "affected").Match);
        Assert.Equal(VersionMatch.NotAffected, VersionMatcher.Evaluate("7.2.5", versions, "affected").Match);
        Assert.Equal(VersionMatch.Affected, VersionMatcher.Evaluate("7.2.4", versions, "affected").Match);
    }

    [Fact]
    public void Greater_than_excludes_its_bound()
    {
        var versions = V(("> 7.2.5", "affected", null, null));
        Assert.Equal(VersionMatch.NotAffected, VersionMatcher.Evaluate("7.2.5", versions, null).Match);
        Assert.Equal(VersionMatch.Affected, VersionMatcher.Evaluate("7.2.6", versions, null).Match);
    }

    // Free-text ranges, however written, are read the same way: start and end as written, inclusive unless a
    // comparator says otherwise
    [Theory]
    [InlineData("1.1.0-5.0.0")]
    [InlineData("1.1.0 - 5.0.0")]
    [InlineData("1.1.0- 5.0.0")]
    [InlineData("1.1.0 -5.0.0")]
    [InlineData("1.1.0 – 5.0.0")]
    [InlineData("1.1.0—5.0.0")]
    [InlineData("1.1.0 to 5.0.0")]
    [InlineData("from 1.1.0 through 5.0.0")]
    [InlineData("between 1.1.0 and 5.0.0")]
    [InlineData(">=1.1.0 <=5.0.0")]
    [InlineData("1.1.0 <= x <= 5.0.0")]
    [InlineData("v1.1.0 - v5.0.0")]
    [InlineData("Product 1.1.0 - Product 5.0.0")]
    public void Inclusive_text_ranges(string text)
    {
        var versions = V((text, "affected", null, null));
        Assert.Equal(VersionMatch.NotAffected, VersionMatcher.Evaluate("1.0.9", versions, null).Match);
        Assert.Equal(VersionMatch.Affected, VersionMatcher.Evaluate("1.1.0", versions, null).Match);
        var mid = VersionMatcher.Evaluate("3.2.1", versions, null);
        Assert.Equal(VersionMatch.Affected, mid.Match);
        Assert.Equal(MatchConfidence.Likely, mid.Confidence);
        Assert.Equal(VersionMatch.Affected, VersionMatcher.Evaluate("5.0.0", versions, null).Match);
        var above = VersionMatcher.Evaluate("5.0.1", versions, null);
        Assert.Equal(VersionMatch.NotAffected, above.Match);
        Assert.Equal(MatchConfidence.Likely, above.Confidence);   // cleared by a text range, so not "exact"
    }

    [Theory]
    [InlineData(">= 1.1.0, < 5.0.0", "1.1.0", VersionMatch.Affected)]
    [InlineData(">= 1.1.0, < 5.0.0", "5.0.0", VersionMatch.NotAffected)]
    [InlineData("> 1.1.0 and < 5.0.0", "1.1.0", VersionMatch.NotAffected)]
    [InlineData("> 1.1.0 and < 5.0.0", "1.1.1", VersionMatch.Affected)]
    [InlineData("1.1.0 <= x < 5.0.0", "1.1.0", VersionMatch.Affected)]
    [InlineData("1.1.0 <= x < 5.0.0", "4.9.9", VersionMatch.Affected)]
    [InlineData("1.1.0 <= x < 5.0.0", "5.0.0", VersionMatch.NotAffected)]
    [InlineData("1.1.0 < x <= 5.0.0", "1.1.0", VersionMatch.NotAffected)]
    [InlineData("FortiOS 7.0.0 - 7.0.12", "7.0.12", VersionMatch.Affected)]
    [InlineData("FortiOS 7.0.0 - 7.0.12", "7.0.13", VersionMatch.NotAffected)]
    [InlineData("1.1.1s-1.1.1v", "1.1.1t", VersionMatch.Affected)]
    public void Comparator_ranges_keep_each_bound_as_written(string text, string installed, VersionMatch expected)
    {
        Assert.Equal(expected, VersionMatcher.Evaluate(installed, V((text, "affected", null, null)), null).Match);
    }

    [Fact]
    public void Hyphen_range_without_spaces_is_not_one_exact_version()
    {
        var versions = V(("5.0.0-5.0.5", "affected", null, null));
        var r = VersionMatcher.Evaluate("5.0.3", versions, null);
        Assert.Equal(VersionMatch.Affected, r.Match);
        Assert.Equal(MatchConfidence.Likely, r.Confidence);
    }

    [Theory]
    [InlineData("5.0.0 - 1.1.0")]
    [InlineData("5.0.0-1.1.0")]
    [InlineData("from 5.0.0 to 1.1.0")]
    public void Backwards_range_is_unparsed_not_empty(string text)
    {
        var r = VersionMatcher.Evaluate("3.0.0", V((text, "affected", null, null)), null);
        Assert.Equal(VersionMatch.Unknown, r.Match);
        Assert.Equal(MatchConfidence.Possible, r.Confidence);
    }

    // build suffixes and pre-releases stay single versions
    [Theory]
    [InlineData("7.1.1-7058", "7.1.1-7058", VersionMatch.Affected)]
    [InlineData("7.1.1-7058", "7.1.1", VersionMatch.NotAffected)]
    [InlineData("1.2.3-rc.1", "1.2.3-rc.1", VersionMatch.Affected)]
    [InlineData("1.2.3-rc.1", "1.2.3", VersionMatch.NotAffected)]
    [InlineData("1.0.0-beta-2.0.0", "1.5.0", VersionMatch.NotAffected)]
    [InlineData("1.0.0-beta-2.0.0", "1.0.0-beta-2.0.0", VersionMatch.Affected)]
    public void Single_versions_with_hyphens_are_not_ranges(string text, string installed, VersionMatch expected)
    {
        Assert.Equal(expected, VersionMatcher.Evaluate(installed, V((text, "affected", null, null)), null).Match);
    }

    [Fact]
    public void Changes_hold_until_the_next_change()
    {
        var versions = new List<AffectedVersion>
        {
            new()
            {
                Version = "1.0", Status = "affected", LessThan = "3.0",
                // listed out of order on purpose
                Changes = new() { new() { At = "2.0", Status = "affected" }, new() { At = "1.5", Status = "unaffected" } }
            }
        };
        Assert.Equal(VersionMatch.Affected, VersionMatcher.Evaluate("1.2", versions, "unaffected").Match);
        Assert.Equal(VersionMatch.NotAffected, VersionMatcher.Evaluate("1.7", versions, "unaffected").Match);
        Assert.Equal(VersionMatch.Affected, VersionMatcher.Evaluate("2.5", versions, "unaffected").Match);
        Assert.Equal(VersionMatch.NotAffected, VersionMatcher.Evaluate("3.0", versions, "unaffected").Match);

        // an unaffected base with a later "affected" change must not clear the affected stretch
        var reopened = new List<AffectedVersion>
        {
            new() { Version = "1.0", Status = "unaffected", LessThan = "3.0", Changes = new() { new() { At = "2.0", Status = "affected" } } }
        };
        Assert.Equal(VersionMatch.Affected, VersionMatcher.Evaluate("2.5", reopened, "unaffected").Match);
        Assert.Equal(VersionMatch.NotAffected, VersionMatcher.Evaluate("1.5", reopened, "unaffected").Match);
    }

    [Fact]
    public void Git_commits_are_never_evidence_of_not_affected()
    {
        var versions = new List<AffectedVersion>
        {
            new() { Version = "1da177e4c3f4", Status = "affected", LessThan = "8b1d0e0c2b1a", VersionType = "git" },
            new() { Version = "8b1d0e0c2b1a", Status = "unaffected", VersionType = "git" }
        };
        var r = VersionMatcher.Evaluate("6.1.0", versions, null);
        Assert.Equal(VersionMatch.Unknown, r.Match);
        Assert.Equal(MatchConfidence.Possible, r.Confidence);
        Assert.Null(r.FixedIn);

        // alongside semver rows, the semver rows decide
        versions.Add(new AffectedVersion { Version = "6.1", Status = "affected", LessThan = "6.1.80", VersionType = "semver" });
        Assert.Equal(VersionMatch.Affected, VersionMatcher.Evaluate("6.1.50", versions, null).Match);
    }

    [Theory]
    [InlineData("7.2.x", "7.2.9", VersionMatch.Affected)]
    [InlineData("7.2.*", "7.3.0", VersionMatch.NotAffected)]
    public void Branch_wildcard_versions_cover_the_line(string text, string installed, VersionMatch expected)
    {
        Assert.Equal(expected, VersionMatcher.Evaluate(installed, V((text, "affected", null, null)), null).Match);
    }

    [Theory]
    [InlineData("1.2.3,1.2.4")]
    [InlineData("1.x.3")]
    [InlineData("1.2.3; 1.2.4")]
    public void Lists_and_wildcard_segments_are_never_exact(string text)
    {
        var r = VersionMatcher.Evaluate("1.2.4", V((text, "affected", null, null)), null);
        Assert.Equal(VersionMatch.Unknown, r.Match);
        Assert.Equal(MatchConfidence.Possible, r.Confidence);
    }

    [Fact]
    public void Empty_or_unreadable_records_do_not_clear_a_release()
    {
        var r = VersionMatcher.Evaluate("1.0", VersionMatcher.ParseVersions("{not json"), null);
        Assert.Equal(VersionMatch.Unknown, r.Match);
        Assert.Equal(MatchConfidence.Possible, r.Confidence);
        Assert.Equal(VersionMatch.NotAffected, VersionMatcher.Evaluate("1.0", new(), "unaffected").Match);
    }

    [Fact]
    public void A_specific_affected_range_beats_a_blanket_unaffected_entry()
    {
        var versions = V(("*", "unaffected", null, null), ("7.0.0", "affected", "7.2.5", null));
        Assert.Equal(VersionMatch.Affected, VersionMatcher.Evaluate("7.2.3", versions, null).Match);
        var outside = VersionMatcher.Evaluate("7.4.0", versions, null);
        Assert.Equal(VersionMatch.NotAffected, outside.Match);
        Assert.NotEqual(MatchConfidence.Exact, outside.Confidence);
    }
}
