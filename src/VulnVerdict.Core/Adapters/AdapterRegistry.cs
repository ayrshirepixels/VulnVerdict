using Microsoft.Extensions.DependencyInjection;
using VulnVerdict.Core.Adapters.Tickets;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Core.Adapters;

/// <summary>
/// The one place adapters are registered. Inventory adapters implement IInventoryAdapter, ticket adapters
/// ITicketAdapter, package sources IPackageVulnSource. Order here is the order shown in the console.
/// </summary>
public static class AdapterRegistry
{
    public static void Register(IServiceCollection services)
    {
        // inventory sources, section 9.2 steps 7 to 10
        services.AddSingleton<IInventoryAdapter, Fortinet.FortiClientEmsAdapter>();
        services.AddSingleton<IInventoryAdapter, Windows.WinRmAdapter>();
        services.AddSingleton<IInventoryAdapter, Fortinet.FortiGateAdapter>();
        services.AddSingleton<IInventoryAdapter, Sbom.SbomUrlAdapter>();
        services.AddSingleton<IInventoryAdapter, Snmp.SnmpAdapter>();
        services.AddSingleton<IInventoryAdapter, Discovery.DiscoverySweepAdapter>();
        services.AddSingleton<IInventoryAdapter, External.ExternalCrossCheckAdapter>();
        services.AddSingleton<Sbom.SbomImportService>();

        // ticket channels (section 11.3)
        services.AddSingleton<ITicketAdapter, JiraCloudAdapter>();
        services.AddSingleton<ITicketAdapter, ServiceNowAdapter>();
        services.AddSingleton<ITicketAdapter, FreshserviceAdapter>();
        services.AddSingleton<ITicketAdapter, ZendeskAdapter>();
        services.AddSingleton<ITicketAdapter, AzureDevOpsAdapter>();
        services.AddSingleton<ITicketAdapter, HaloPsaAdapter>();
        services.AddSingleton<ITicketAdapter, AutotaskAdapter>();

        // webhooks (section 11.4)
        services.AddSingleton<WebhookService>();
    }
}
