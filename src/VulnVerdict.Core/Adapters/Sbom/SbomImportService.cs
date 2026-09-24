using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Core.Adapters.Sbom;

/// <summary>
/// Section 9.2 step 7: SBOM upload from CI (file or API). Each upload is applied as a full snapshot through one
/// upload-fed connector per asset name ("SBOM: name"), so a library CVE lands on the named site and libraries
/// missing from the next upload are removed. The connector row is stored disabled because nothing polls it;
/// the worker skips disabled connectors and the console shows where the software came from.
/// </summary>
public sealed class SbomImportService
{
    public const string AdapterId = "sbom";
    public const string DisplayNamePrefix = "SBOM: ";

    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly InventoryService _inventory;
    private readonly ILogger<SbomImportService> _log;

    public SbomImportService(IDbContextFactory<VvDbContext> factory, InventoryService inventory, ILogger<SbomImportService> log)
    {
        _factory = factory; _inventory = inventory; _log = log;
    }

    /// <summary>Parse and apply an SBOM for the named asset (a hostname or site name so it merges with the IIS or server inventory).</summary>
    public async Task<ApplySummary> ImportAsync(string assetName, string sbomJson, string actor, CancellationToken ct = default)
    {
        assetName = (assetName ?? "").Trim();
        if (assetName == "") throw new ArgumentException("An asset name (the site or server the SBOM describes) is required.");
        if (assetName.Length > 200) assetName = assetName[..200];

        var parsed = SbomParser.Parse(sbomJson, assetName);
        var result = BuildResult(assetName, parsed);

        await using var db = await _factory.CreateDbContextAsync(ct);
        var displayName = DisplayNamePrefix + assetName;
        var connector = await db.Connectors.FirstOrDefaultAsync(c => c.AdapterId == AdapterId && c.DisplayName == displayName, ct);
        var now = DateTime.UtcNow;
        if (connector is null)
        {
            connector = new Connector { Id = Guid.NewGuid(), AdapterId = AdapterId, DisplayName = displayName, CredentialsJson = "", Enabled = false, IntervalMinutes = 1440, CreatedAt = now };
            db.Connectors.Add(connector);
            await db.SaveChangesAsync(ct);
        }
        connector.Running = true; connector.LastAttempt = now; connector.Progress = "Importing " + parsed.Format;
        await db.SaveChangesAsync(ct);

        try
        {
            var summary = await _inventory.ApplyAsync(connector, result, ct);
            connector.LastSuccess = DateTime.UtcNow; connector.ConsecutiveFailures = 0;
            connector.LastError = result.Warnings.Count > 0 ? "Warnings: " + string.Join("; ", result.Warnings.Take(5)) : null;
            connector.AssetsLastRun = summary.Assets; connector.SoftwareLastRun = summary.Software;
            connector.Progress = parsed.Format + ": " + summary.Software + " components" + (summary.Unmapped > 0 ? ", " + summary.Unmapped + " need mapping" : "");
            db.Audit.Add(new AuditEntry
            {
                At = DateTime.UtcNow, Actor = actor, Action = "sbom.import", Target = assetName,
                After = parsed.Format + ", " + (parsed.ApplicationName ?? "(unnamed application)") + (string.IsNullOrEmpty(parsed.ApplicationVersion) ? "" : " " + parsed.ApplicationVersion) + ", " + result.Software.Count + " software records"
            });
            _log.LogInformation("SBOM import for {Asset}: {Format}, {Count} software records", assetName, parsed.Format, result.Software.Count);
            return summary;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            connector.ConsecutiveFailures++;
            connector.LastError = ex.Message.Length > 2000 ? ex.Message[..2000] : ex.Message;
            throw;
        }
        finally
        {
            connector.Running = false;
            await db.SaveChangesAsync(CancellationToken.None);
        }
    }

    /// <summary>One asset record keyed and named by the asset name (so it merges with an existing asset of that hostname) plus the parsed software, as a full snapshot.</summary>
    public static CollectResult BuildResult(string assetName, SbomParseResult parsed)
    {
        var result = new CollectResult { FullSnapshot = true };
        result.Assets.Add(new AssetRecord(assetName, assetName, AssetKind.Other, new[] { assetName }, Array.Empty<string>(), Array.Empty<string>()));
        result.Software.AddRange(parsed.Software);
        result.Warnings.AddRange(parsed.Warnings);
        if (parsed.Software.Count == 0) result.Warnings.Add("The SBOM lists no components.");
        return result;
    }
}
