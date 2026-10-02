using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Digest;

namespace VulnVerdict.Core.Services;

/// <summary>The worker's housekeeping for operations: the nightly backup and the daily SLA snapshot. One failing does not stop the other.</summary>
public static class OperationsJobs
{
    public static async Task RunAsync(IServiceProvider sp, ILogger log, CancellationToken ct)
    {
        using var scope = sp.CreateScope();
        try { await BackupService.RunIfDueAsync(scope.ServiceProvider, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { log.LogError(ex, "Backup step failed"); }
        try { await scope.ServiceProvider.GetRequiredService<SlaReportService>().WriteSnapshotIfDueAsync(null, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { log.LogWarning(ex, "SLA snapshot not written"); }
    }
}
