using Microsoft.Extensions.DependencyInjection;
using VulnVerdict.Core.Adapters.Tickets;
using VulnVerdict.Core.Feeds;
using VulnVerdict.Core.Feeds.Psirt;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Core.Adapters;

/// <summary>
/// The one place adapters are registered. Inventory adapters implement IInventoryAdapter,
/// ticket adapters ITicketAdapter, package sources IPackageVulnSource, vendor PSIRT feeds IFeed.
/// Order here is the order shown in the console.
/// </summary>
public static class AdapterRegistry
{
    public static void Register(IServiceCollection services)
    {
        // inventory sources
        services.AddSingleton<IInventoryAdapter, Fortinet.FortiClientEmsAdapter>();
        services.AddSingleton<IInventoryAdapter, Windows.WinRmAdapter>();
        // endpoint management, MDM and RMM: installed software for the laptops and servers they manage
        services.AddSingleton<IInventoryAdapter, Endpoints.IntuneAdapter>();
        services.AddSingleton<IInventoryAdapter, Endpoints.DefenderEndpointAdapter>();
        services.AddSingleton<IInventoryAdapter>(sp => new Endpoints.ConfigMgrAdapter(sp.GetService<Microsoft.Extensions.Logging.ILogger<Endpoints.ConfigMgrAdapter>>()));
        services.AddSingleton<IInventoryAdapter, Endpoints.JamfProAdapter>();
        services.AddSingleton<IInventoryAdapter, Endpoints.KandjiAdapter>();
        services.AddSingleton<IInventoryAdapter, Endpoints.NinjaOneAdapter>();
        services.AddSingleton<IInventoryAdapter, Endpoints.DattoRmmAdapter>();
        services.AddSingleton<IInventoryAdapter, Endpoints.NCentralAdapter>();
        services.AddSingleton<IInventoryAdapter, Endpoints.LansweeperAdapter>();
        services.AddSingleton<IInventoryAdapter, Endpoints.PdqConnectAdapter>();
        services.AddSingleton<IInventoryAdapter, Fortinet.FortiGateAdapter>();
        // other firewall families, same exposure model as the FortiGate
        services.AddSingleton<IInventoryAdapter, Firewalls.PanOsAdapter>();
        services.AddSingleton<IInventoryAdapter, Firewalls.SonicWallAdapter>();
        services.AddSingleton<IInventoryAdapter, Firewalls.MerakiMxAdapter>();
        services.AddSingleton<IInventoryAdapter, Firewalls.SophosFirewallAdapter>();
        services.AddSingleton<IInventoryAdapter, Firewalls.WatchGuardFireboxAdapter>();
        services.AddSingleton<IInventoryAdapter, Firewalls.CheckPointSparkAdapter>();
        services.AddSingleton<IInventoryAdapter, Firewalls.ZyxelFirewallAdapter>();
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

        // vendor PSIRT advisories
        services.AddSingleton<IFeed, FortinetPsirtFeed>();
        services.AddSingleton<IFeed, MsrcFeed>();
        services.AddSingleton<IFeed, CiscoOpenVulnFeed>();
        services.AddSingleton<IFeed, BroadcomVmwareFeed>();
        services.AddSingleton<IFeed, UbuntuSecurityFeed>();
        services.AddSingleton<IFeed, DebianSecurityFeed>();
        services.AddSingleton<IFeed, RedHatCsafFeed>();

        // ticket channels
        services.AddSingleton<ITicketAdapter, JiraCloudAdapter>();
        services.AddSingleton<ITicketAdapter, ServiceNowAdapter>();
        services.AddSingleton<ITicketAdapter, FreshserviceAdapter>();
        services.AddSingleton<ITicketAdapter, ZendeskAdapter>();
        services.AddSingleton<ITicketAdapter, AzureDevOpsAdapter>();
        services.AddSingleton<ITicketAdapter, HaloPsaAdapter>();
        services.AddSingleton<ITicketAdapter, AutotaskAdapter>();

        // webhooks
        services.AddSingleton<WebhookService>();
    }
}
