using Microsoft.Extensions.DependencyInjection;
using VulnVerdict.Core.Adapters.Tickets;
using VulnVerdict.Core.Feeds;
using VulnVerdict.Core.Feeds.Psirt;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Core.Adapters;

/// <summary>
/// The one place adapters are registered. Inventory adapters implement IInventoryAdapter (section 9.2 order),
/// ticket adapters ITicketAdapter (11.3), package sources IPackageVulnSource, vendor PSIRT feeds IFeed (7).
/// Order here is the order shown in the console.
/// </summary>
public static class AdapterRegistry
{
    public static void Register(IServiceCollection services)
    {
        // inventory sources, section 9.2 order
        services.AddSingleton<IInventoryAdapter, Fortinet.FortiClientEmsAdapter>();
        services.AddSingleton<IInventoryAdapter, Windows.WinRmAdapter>();
        services.AddSingleton<IInventoryAdapter, Fortinet.FortiGateAdapter>();
        // other firewall families, same exposure model as the FortiGate
        services.AddSingleton<IInventoryAdapter, Firewalls.PanOsAdapter>();
        services.AddSingleton<IInventoryAdapter, Firewalls.SonicWallAdapter>();
        services.AddSingleton<IInventoryAdapter, Firewalls.MerakiMxAdapter>();
        services.AddSingleton<IInventoryAdapter, Firewalls.SophosFirewallAdapter>();
        services.AddSingleton<IInventoryAdapter, Firewalls.WatchGuardFireboxAdapter>();
        services.AddSingleton<IInventoryAdapter, Firewalls.UniFiGatewayAdapter>();
        services.AddSingleton<IInventoryAdapter, Firewalls.PfSenseAdapter>();
        services.AddSingleton<IInventoryAdapter, Firewalls.OpnSenseAdapter>();
        services.AddSingleton<IInventoryAdapter, VMware.VCenterAdapter>();
        services.AddSingleton<IInventoryAdapter, Linux.SshLinuxAdapter>();
        services.AddSingleton<IInventoryAdapter, Sbom.SbomUrlAdapter>();
        services.AddSingleton<IInventoryAdapter, Snmp.SnmpAdapter>();
        services.AddSingleton<IInventoryAdapter, Discovery.DiscoverySweepAdapter>();
        services.AddSingleton<IInventoryAdapter, External.ExternalCrossCheckAdapter>();
        services.AddSingleton<Sbom.SbomImportService>();
        services.AddSingleton<IPackageVulnSource>(sp => new Packages.OsvPackageVulnSource(sp.GetRequiredService<IHttpClientFactory>(), sp.GetRequiredService<Microsoft.Extensions.Logging.ILogger<Packages.OsvPackageVulnSource>>()));

        // vendor PSIRT advisories, section 7
        services.AddSingleton<IFeed, FortinetPsirtFeed>();
        services.AddSingleton<IFeed, MsrcFeed>();
        services.AddSingleton<IFeed, CiscoOpenVulnFeed>();
        services.AddSingleton<IFeed, BroadcomVmwareFeed>();
        services.AddSingleton<IFeed, UbuntuSecurityFeed>();
        services.AddSingleton<IFeed, DebianSecurityFeed>();
        services.AddSingleton<IFeed, RedHatCsafFeed>();

        // ticket channels, section 11.3
        services.AddSingleton<ITicketAdapter, JiraCloudAdapter>();
        services.AddSingleton<ITicketAdapter, ServiceNowAdapter>();
        services.AddSingleton<ITicketAdapter, FreshserviceAdapter>();
        services.AddSingleton<ITicketAdapter, ZendeskAdapter>();
        services.AddSingleton<ITicketAdapter, AzureDevOpsAdapter>();
        services.AddSingleton<ITicketAdapter, HaloPsaAdapter>();
        services.AddSingleton<ITicketAdapter, AutotaskAdapter>();

        // webhooks, section 11.4
        services.AddSingleton<WebhookService>();
    }
}
