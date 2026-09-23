using Microsoft.Extensions.DependencyInjection;

namespace VulnVerdict.Core.Adapters;

/// <summary>
/// The one place adapters are registered. Inventory adapters implement IInventoryAdapter, ticket adapters
/// ITicketAdapter, package sources IPackageVulnSource. Order here is the order shown in the console.
/// </summary>
public static class AdapterRegistry
{
    public static void Register(IServiceCollection services)
    {
        // inventory adapters (section 9.2 order) are registered by the phase 3 packages below
        // ticket adapters (section 11.3) and package sources (section 9.2 step 6/7) likewise
    }
}
