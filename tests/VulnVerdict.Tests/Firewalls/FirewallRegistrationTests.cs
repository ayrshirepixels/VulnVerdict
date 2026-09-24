using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Adapters.Firewalls;
using VulnVerdict.Core.Engine;

namespace VulnVerdict.Tests.Firewalls;

/// <summary>Every firewall adapter is registered once, has a complete credential form, and its names line up with the alias table.</summary>
public class FirewallRegistrationTests
{
    private static List<IInventoryAdapter> Adapters()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IHttpClientFactory>(new FakeHttpClientFactory(new FakeHandler()));
        AdapterRegistry.Register(services);
        using var sp = services.BuildServiceProvider();
        return sp.GetServices<IInventoryAdapter>().ToList();
    }

    [Fact]
    public void All_firewall_families_are_registered_with_unique_ids()
    {
        var adapters = Adapters();
        var ids = adapters.Select(a => a.Metadata.Id).ToList();
        Assert.Equal(ids.Count, ids.Distinct().Count());
        foreach (var id in new[] { "fortigate", "panos", "sonicwall", "meraki-mx", "sophos-firewall", "watchguard-firebox", "checkpoint-spark", "zyxel-firewall", "unifi-gateway", "pfsense", "opnsense" })
            Assert.Contains(id, ids);
    }

    [Fact]
    public void Firewall_forms_are_complete_and_secrets_are_password_fields()
    {
        foreach (var m in Adapters().Where(a => a.GetType().Namespace == typeof(PanOsAdapter).Namespace).Select(a => a.Metadata))
        {
            Assert.False(string.IsNullOrWhiteSpace(m.MinimumPermission), m.Id);
            Assert.StartsWith("https://", m.DocsUrl ?? "", StringComparison.Ordinal);
            Assert.Contains("Read-only", m.Description);
            if (m.Id != "meraki-mx") Assert.Contains(m.Form, f => f.Key == "host" && f.Required); // Meraki is reached through the cloud dashboard
            Assert.All(m.Form, f => Assert.False(string.IsNullOrWhiteSpace(f.Label)));
            // OPNsense's key is the public half of a key/secret pair; everywhere else an API key is the whole credential
            foreach (var f in m.Form.Where(f => f.Key is "password" or "apiSecret" or "community" or "snmpAuthPassword" or "snmpPrivPassword" or "passphrase" || (f.Key == "apiKey" && m.Id != "opnsense")))
                Assert.True(f.Type == CredentialTypes.Password, m.Id + "." + f.Key + " should be a password field");
        }
    }

    [Fact]
    public void Firewall_seed_aliases_point_at_the_names_the_adapters_report()
    {
        var byAlias = CoreServices.SeedAliases.GroupBy(a => Normalizer.Norm(a.Alias)).ToList();
        Assert.All(byAlias, g => Assert.Single(g)); // no alias is seeded twice
        (string Vendor, string Product) Target(string alias) { var a = CoreServices.SeedAliases.Single(x => x.Alias == alias); return (Normalizer.Norm(a.Vendor), Normalizer.Norm(a.Product)); }
        Assert.Equal((Normalizer.Norm(CnaNames.Sophos), Normalizer.Norm(CnaNames.SophosFirewall)), Target("Sophos XGS"));
        Assert.Equal((Normalizer.Norm(CnaNames.WatchGuard), Normalizer.Norm(CnaNames.Fireware)), Target("WatchGuard Firebox"));
        Assert.Equal((Normalizer.Norm(CnaNames.Cisco), Normalizer.Norm(CnaNames.MerakiMx)), Target("Meraki MX"));
        Assert.Equal((Normalizer.Norm(CnaNames.CheckPoint), Normalizer.Norm(CnaNames.SparkFirewalls)), Target("Quantum Spark"));
        Assert.Equal((Normalizer.Norm(CnaNames.Zyxel), Normalizer.Norm(CnaNames.ZyxelUsgFlexSeries)), Target("Zyxel USG FLEX"));
        Assert.Equal((Normalizer.Norm(CnaNames.Ubiquiti), Normalizer.Norm(CnaNames.UniFiOs)), Target("UniFi OS"));
        // "Check Point" and the CNA's "checkpoint", "Ubiquiti" and "Ubiquiti Inc" normalise the same, so exact matching works
        Assert.Equal(Normalizer.Norm("checkpoint"), Normalizer.Norm(CnaNames.CheckPoint));
        Assert.Equal(Normalizer.Norm("Ubiquiti"), Normalizer.Norm(CnaNames.Ubiquiti));
    }
}
