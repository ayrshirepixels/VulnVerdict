using System.Text.Json;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;
using VulnVerdict.Core.Feeds;

namespace VulnVerdict.Tests;

public class CveParseTests
{
    private const string Sample = """
    {
      "dataType": "CVE_RECORD",
      "dataVersion": "5.1",
      "cveMetadata": { "cveId": "CVE-2024-21762", "assignerOrgId": "x", "state": "PUBLISHED", "assignerShortName": "fortinet",
                       "datePublished": "2024-02-09T09:31:34.588Z", "dateUpdated": "2024-08-01T22:27:36.315Z" },
      "containers": {
        "cna": {
          "title": "FortiOS SSL VPN out-of-bound write",
          "affected": [
            { "vendor": "Fortinet", "product": "FortiOS", "versions": [
                { "version": "7.4.0", "status": "affected", "lessThanOrEqual": "7.4.2", "versionType": "semver" },
                { "version": "7.2.0", "status": "affected", "lessThanOrEqual": "7.2.6", "versionType": "semver" },
                { "version": "7.0.0", "status": "affected", "lessThanOrEqual": "7.0.13", "versionType": "semver" } ],
              "defaultStatus": "unaffected" },
            { "vendor": "Fortinet", "product": "FortiProxy", "versions": [
                { "version": "7.4.0", "status": "affected", "lessThanOrEqual": "7.4.2" } ] }
          ],
          "descriptions": [ { "lang": "en", "value": "A out-of-bounds write in Fortinet FortiOS ... may allow attacker to execute unauthorized code or commands via specifically crafted requests" } ],
          "metrics": [ { "cvssV3_1": { "version": "3.1", "baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseSeverity": "CRITICAL" } } ],
          "references": [ { "url": "https://fortiguard.com/psirt/FG-IR-24-015" } ]
        },
        "adp": [
          { "providerMetadata": { "shortName": "CISA-ADP" },
            "metrics": [ { "other": { "type": "ssvc", "content": { "timestamp": "2024-06-04T17:24:14.109Z", "id": "CVE-2024-21762", "version": "2.0.3",
                            "options": [ { "Exploitation": "active" }, { "Automatable": "yes" }, { "Technical Impact": "total" } ], "role": "CISA Coordinator" } } } ],
            "affected": [ { "vendor": "fortinet", "product": "fortios", "cpes": [ "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*" ], "defaultStatus": "unknown",
                            "versions": [ { "version": "7.4.0", "status": "affected", "lessThanOrEqual": "7.4.2", "versionType": "semver" } ] } ]
          }
        ]
      }
    }
    """;

    private static string Record(string cnaAffected, string? adpAffected) => """
    { "dataType": "CVE_RECORD", "dataVersion": "5.1",
      "cveMetadata": { "cveId": "CVE-2024-46538", "state": "PUBLISHED", "assignerShortName": "mitre", "datePublished": "2024-10-25T00:00:00.000Z" },
      "containers": { "cna": { "affected":
    """ + cnaAffected + """
    , "descriptions": [ { "lang": "en", "value": "A cross-site scripting (XSS) vulnerability in pfsense v2.5.2 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the $pconfig variable at interfaces_groups_edit.php." } ] }
    """ + (adpAffected is null ? "" : """
    , "adp": [ { "providerMetadata": { "shortName": "CISA-ADP" }, "affected":
    """ + adpAffected + " } ]") + " } }";

    [Fact]
    public void Placeholder_cna_product_falls_back_to_the_cisa_affected_list()
    {
        // A third of the CVE list is filed this way: vendor and product "n/a" in the CNA container, the real names
        // only in CISA's ADP container. CVE-2024-46538 (pfSense) as published.
        using var doc = JsonDocument.Parse(Record(
            """[ { "vendor": "n/a", "product": "n/a", "versions": [ { "version": "n/a", "status": "affected" } ] } ]""",
            """[ { "vendor": "pfsense", "product": "pfsense", "cpes": [ "cpe:2.3:a:pfsense:pfsense:2.5.2:*:*:*:*:*:*:*" ], "defaultStatus": "unknown", "versions": [ { "version": "2.5.2", "status": "affected" } ] } ]"""));
        var cve = CveListFeed.Parse(doc.RootElement, DateTime.UtcNow, "test")!;
        var row = Assert.Single(cve.Affected);
        Assert.Equal("pfsense", row.VendorNorm);
        Assert.Equal("pfsense", row.ProductNorm);
        Assert.Contains("2.5.2", row.VersionsJson);
    }

    [Fact]
    public void Placeholder_product_with_no_cisa_data_yields_no_affected_rows()
    {
        using var doc = JsonDocument.Parse(Record("""[ { "vendor": "N/A", "product": "N/A", "versions": [ { "version": "n/a", "status": "affected" } ] } ]""", null));
        var cve = CveListFeed.Parse(doc.RootElement, DateTime.UtcNow, "test")!;
        Assert.Empty(cve.Affected);
    }

    [Fact]
    public void Placeholder_vendor_with_a_real_product_is_kept_without_a_vendor()
    {
        using var doc = JsonDocument.Parse(Record("""[ { "vendor": "n/a", "product": "BIG-IP", "versions": [ { "version": "16.1.0", "status": "affected", "lessThan": "16.1.4" } ] } ]""", null));
        var cve = CveListFeed.Parse(doc.RootElement, DateTime.UtcNow, "test")!;
        var row = Assert.Single(cve.Affected);
        Assert.Equal("", row.Vendor);
        Assert.Equal("", row.VendorNorm);
        Assert.Equal("bigip", row.ProductNorm);
    }

    [Theory]
    [InlineData("n/a", true)] [InlineData("N/A", true)] [InlineData("-", true)] [InlineData("unknown", true)] [InlineData("", true)] [InlineData(null, true)]
    [InlineData("pfSense", false)] [InlineData("Nagios", false)] [InlineData("nano", false)]
    public void Placeholder_detection(string? name, bool placeholder) => Assert.Equal(placeholder, CveListFeed.IsPlaceholder(name));

    [Fact]
    public void A_cursor_from_an_older_parser_forces_a_full_reload()
    {
        Assert.False(CveListFeed.CursorIsCurrent(null));
        Assert.False(CveListFeed.CursorIsCurrent("tag=cve_2026-09-24_0900Z"));                 // written before parser versions existed
        Assert.False(CveListFeed.CursorIsCurrent("tag=cve_2026-09-24_0900Z;parser=1"));
        Assert.True(CveListFeed.CursorIsCurrent("tag=cve_2026-09-24_0900Z;parser=" + CveListFeed.ParserVersion));
    }

    [Fact]
    public void Parses_cna_and_adp_containers()
    {
        using var doc = JsonDocument.Parse(Sample);
        var cve = CveListFeed.Parse(doc.RootElement, DateTime.UtcNow, "test")!;
        Assert.Equal("CVE-2024-21762", cve.Id);
        Assert.Equal("PUBLISHED", cve.State);
        Assert.Equal("fortinet", cve.Assigner);
        Assert.Equal("FortiOS SSL VPN out-of-bound write", cve.Title);
        Assert.Equal("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cve.CvssV31Vector);
        Assert.Equal(9.8, cve.CvssV31Score);
        Assert.Equal("active", cve.SsvcExploitation);
        Assert.Equal("yes", cve.SsvcAutomatable);
        Assert.Equal(new DateTime(2024, 2, 9, 9, 31, 34, 588, DateTimeKind.Utc), cve.Published);
        Assert.Contains("fortiguard.com", cve.ReferencesJson);

        // CNA affected rows are used, ADP rows are not duplicated
        Assert.Equal(2, cve.Affected.Count);
        var fortios = cve.Affected.First(a => a.ProductNorm == "fortios");
        Assert.Equal("fortinet", fortios.VendorNorm);
        Assert.Equal("unaffected", fortios.DefaultStatus);
        var versions = VersionMatcher.ParseVersions(fortios.VersionsJson);
        Assert.Equal(3, versions.Count);

        var affected = VersionMatcher.Evaluate("7.2.5", versions, fortios.DefaultStatus);
        Assert.Equal(VersionMatch.Affected, affected.Match);
        Assert.Equal(MatchConfidence.Exact, affected.Confidence);
        Assert.Equal(VersionMatch.NotAffected, VersionMatcher.Evaluate("7.2.7", versions, fortios.DefaultStatus).Match);
        Assert.Equal(VersionMatch.NotAffected, VersionMatcher.Evaluate("7.6.0", versions, fortios.DefaultStatus).Match);
    }

    [Fact]
    public void Sentence_reads_as_documented()
    {
        var entry = new Subject("Fortinet", "FortiOS", "7.2.5", "FW-EDGE-01", Exposure.Internet, Criticality.Critical);
        var cvss = CvssVector.Parse("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
        var inputs = new DecisionInputs(Exploitation.Active, true, AttackVector.Network, Exposure.Internet, Criticality.Critical);
        var s = SentenceBuilder.Build(entry, inputs, cvss, VerdictTier.FixToday, "7.2.8", MatchConfidence.Exact, false);
        Assert.Equal("Fortinet FortiOS 7.2.5 on FW-EDGE-01: exploited in the wild, works over the network with no login, reachable from the internet. Fixed in 7.2.8.", s);

        var local = new DecisionInputs(Exploitation.PoC, false, AttackVector.Physical, Exposure.Internet, Criticality.Standard);
        var s2 = SentenceBuilder.Build(entry, local, CvssVector.Parse("CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"), VerdictTier.NextPatchCycle, null, MatchConfidence.Exact, false);
        Assert.Contains("needs hands on the hardware", s2);
        Assert.Contains("does not help this attacker", s2);
    }
}
