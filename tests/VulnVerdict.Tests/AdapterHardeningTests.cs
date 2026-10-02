using VulnVerdict.Core.Adapters.External;
using VulnVerdict.Core.Adapters.Sbom;
using VulnVerdict.Core.Adapters.Tickets;

namespace VulnVerdict.Tests;

/// <summary>Small guards: bounded SBOM reads, ServiceNow encoded-query values, the Shodan key kept out of warnings.</summary>
public class AdapterHardeningTests
{
    [Fact]
    public async Task Sbom_read_is_bounded_by_the_bytes_actually_received()
    {
        Assert.Equal("{\"a\":1}", await SbomUrlAdapter.ReadBoundedAsync(new MemoryStream("{\"a\":1}"u8.ToArray()), 16, CancellationToken.None));
        await Assert.ThrowsAsync<InvalidOperationException>(() => SbomUrlAdapter.ReadBoundedAsync(new MemoryStream(new byte[200_000]), 100_000, CancellationToken.None));
    }

    [Fact]
    public void ServiceNow_query_values_with_a_condition_separator_are_refused()
    {
        Assert.Equal("VV-CVE-2026-1234-abc", ServiceNowAdapter.QueryValue("VV-CVE-2026-1234-abc"));
        Assert.Throws<ArgumentException>(() => ServiceNowAdapter.QueryValue("x^ORactive=false"));
        Assert.Throws<ArgumentException>(() => ServiceNowAdapter.QueryValue("x\ny"));
        Assert.Throws<ArgumentException>(() => ServiceNowAdapter.QueryValue(""));
    }

    [Fact]
    public void Shodan_key_is_scrubbed_from_warning_text()
    {
        var text = ExternalCrossCheckAdapter.ScrubKey("GET https://api.shodan.io/shodan/host/1.2.3.4?key=ab%2Bc failed (ab+c)", "ab+c");
        Assert.DoesNotContain("ab", text);
    }
}
