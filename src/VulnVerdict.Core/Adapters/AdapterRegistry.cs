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
