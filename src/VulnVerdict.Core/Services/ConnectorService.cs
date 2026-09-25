using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Services;

/// <summary>
/// Sections 9.1 and 11.3: connectors are adapter instances (inventory sources or ticket channels) with a hostname
/// and a credential. Credentials live encrypted in the database, never in configuration files or logs. Three
/// consecutive failures raise the administrator alert; inventory adapters never write to the source system.
/// </summary>
public sealed class ConnectorService
{
    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly IEnumerable<IInventoryAdapter> _adapters;
    private readonly IEnumerable<ITicketAdapter> _ticketAdapters;
    private readonly InventoryService _inventory;
    private readonly IDataProtector _protector;
    private readonly ILogger<ConnectorService> _log;

    public ConnectorService(IDbContextFactory<VvDbContext> factory, IEnumerable<IInventoryAdapter> adapters, IEnumerable<ITicketAdapter> ticketAdapters, InventoryService inventory, IDataProtectionProvider dp, ILogger<ConnectorService> log)
    {
        _factory = factory; _adapters = adapters; _ticketAdapters = ticketAdapters; _inventory = inventory; _log = log;
        _protector = dp.CreateProtector("VulnVerdict.Connectors.v1");
    }

    public IReadOnlyList<IInventoryAdapter> Adapters => _adapters.ToList();
    public IReadOnlyList<ITicketAdapter> TicketAdapters => _ticketAdapters.ToList();
    public IInventoryAdapter? Adapter(string id) => _adapters.FirstOrDefault(a => a.Metadata.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    public ITicketAdapter? TicketAdapter(string id) => _ticketAdapters.FirstOrDefault(a => a.Metadata.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
    public AdapterMetadata? Metadata(string id) => Adapter(id)?.Metadata ?? TicketAdapter(id)?.Metadata;
    public bool IsTicketAdapter(string id) => TicketAdapter(id) is not null;

    public async Task<List<Connector>> ListAsync(CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        return await db.Connectors.AsNoTracking().OrderBy(c => c.DisplayName).ToListAsync(ct);
    }

    public async Task<Connector?> GetAsync(Guid id, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        return await db.Connectors.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id, ct);
    }

    public Dictionary<string, string> Decrypt(Connector c)
    {
        if (string.IsNullOrEmpty(c.CredentialsJson)) return new();
        try { return JsonSerializer.Deserialize<Dictionary<string, string>>(_protector.Unprotect(c.CredentialsJson)) ?? new(); }
        catch { return new(); }
    }

    public async Task<Connector> SaveAsync(Guid? id, string adapterId, string displayName, Dictionary<string, string> credentials, bool enabled, int intervalMinutes, string actor, CancellationToken ct = default)
    {
        var meta = Metadata(adapterId) ?? throw new ArgumentException("Unknown adapter " + adapterId);
        await using var db = await _factory.CreateDbContextAsync(ct);
        var c = id is null ? null : await db.Connectors.FirstOrDefaultAsync(x => x.Id == id, ct);
        var now = DateTime.UtcNow;
        if (c is null) { c = new Connector { Id = Guid.NewGuid(), AdapterId = meta.Id, CreatedAt = now }; db.Connectors.Add(c); }
        // blank password fields keep the stored value
        var current = Decrypt(c);
        foreach (var f in meta.Form)
            if (f.Type == CredentialTypes.Password && credentials.TryGetValue(f.Key, out var v) && v == "" && current.TryGetValue(f.Key, out var old)) credentials[f.Key] = old;
        var missing = meta.Form.Where(f => f.Required && string.IsNullOrWhiteSpace(credentials.GetValueOrDefault(f.Key))).Select(f => f.Label).ToList();
        if (missing.Count > 0) throw new ArgumentException("Required: " + string.Join(", ", missing));
        c.DisplayName = string.IsNullOrWhiteSpace(displayName) ? meta.DisplayName : displayName.Trim();
        c.CredentialsJson = _protector.Protect(JsonSerializer.Serialize(credentials));
        c.Enabled = enabled; c.IntervalMinutes = Math.Max(15, intervalMinutes);
        db.Audit.Add(new AuditEntry { At = now, Actor = actor, Action = id is null ? "connector.add" : "connector.update", Target = c.DisplayName, After = meta.Id + (enabled ? "" : " (disabled)") });
        await db.SaveChangesAsync(ct);
        return c;
    }

    public async Task DeleteAsync(Guid id, string actor, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var c = await db.Connectors.FirstOrDefaultAsync(x => x.Id == id, ct);
        if (c is null) return;
        var cid = c.Id.ToString("N");
        db.Connectors.Remove(c);
        db.AssetSources.RemoveRange(db.AssetSources.Where(s => s.ConnectorId == cid));
        // software is marked removed, not deleted: its verdicts close as "no longer reported" and keep their history
        await db.Software.Where(s => s.ConnectorId == cid).ExecuteUpdateAsync(u => u.SetProperty(s => s.RemovedAt, DateTime.UtcNow), ct);
        db.Findings.RemoveRange(db.Findings.Where(f => f.ConnectorId == cid));
        db.Audit.Add(new AuditEntry { At = DateTime.UtcNow, Actor = actor, Action = "connector.delete", Target = c.DisplayName });
        await db.SaveChangesAsync(ct);
        // assets with no remaining source become unknown, not deleted, so history is kept
        var orphans = await db.Assets.Include(a => a.Sources).Where(a => !a.Sources.Any()).ToListAsync(ct);
        foreach (var a in orphans) a.Unknown = true;
        await db.SaveChangesAsync(ct);
    }

    public async Task<TestResult> TestAsync(string adapterId, Dictionary<string, string> credentials, Guid? existingId, CancellationToken ct = default)
    {
        var meta = Metadata(adapterId) ?? throw new ArgumentException("Unknown adapter " + adapterId);
        if (existingId is not null)
        {
            await using var db = await _factory.CreateDbContextAsync(ct);
            var c = await db.Connectors.AsNoTracking().FirstOrDefaultAsync(x => x.Id == existingId, ct);
            if (c is not null)
            {
                var current = Decrypt(c);
                foreach (var f in meta.Form)
                    if (f.Type == CredentialTypes.Password && credentials.GetValueOrDefault(f.Key) == "" && current.TryGetValue(f.Key, out var old)) credentials[f.Key] = old;
            }
        }
        try
        {
            var inv = Adapter(adapterId);
            if (inv is not null) return await inv.TestAsync(credentials, ct);
            return await TicketAdapter(adapterId)!.TestAsync(credentials, ct);
        }
        catch (Exception ex) { return new TestResult(false, ex.Message); }
    }

    public async Task RequestRunAsync(Guid id, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        await db.Connectors.Where(c => c.Id == id).ExecuteUpdateAsync(u => u.SetProperty(c => c.RunRequested, true), ct);
    }

    /// <summary>Run one inventory connector end to end. Used by the worker on schedule and by "Run now".</summary>
    public async Task<ApplySummary?> RunAsync(Guid id, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var c = await db.Connectors.FirstOrDefaultAsync(x => x.Id == id, ct);
        if (c is null) return null;
        var adapter = Adapter(c.AdapterId);
        if (adapter is null)
        {
            c.RunRequested = false;
            if (!IsTicketAdapter(c.AdapterId)) c.LastError = "Adapter " + c.AdapterId + " is not installed";
            await db.SaveChangesAsync(ct);
            return null;
        }
        c.Running = true; c.RunRequested = false; c.LastAttempt = DateTime.UtcNow; c.Progress = "Starting";
        await db.SaveChangesAsync(ct);
        try
        {
            var creds = Decrypt(c);
            var progress = new Progress<string>(msg => { _ = ReportAsync(c.Id, msg); });
            var result = await adapter.CollectAsync(creds, c.LastSuccess, progress, ct);
            var summary = await _inventory.ApplyAsync(c, result, ct);
            c.LastSuccess = DateTime.UtcNow; c.LastError = result.Warnings.Count > 0 ? "Warnings: " + string.Join("; ", result.Warnings.Take(5)) : null;
            c.ConsecutiveFailures = 0; c.AssetsLastRun = summary.Assets; c.SoftwareLastRun = summary.Software;
            c.Progress = summary.Assets + " assets, " + summary.Software + " software" + (summary.Unmapped > 0 ? ", " + summary.Unmapped + " need mapping" : "");
            return summary;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            c.ConsecutiveFailures++;
            c.LastError = ex.Message.Length > 2000 ? ex.Message[..2000] : ex.Message;
            c.Progress = null;
            _log.LogError(ex, "Connector {Name} failed ({N} in a row)", c.DisplayName, c.ConsecutiveFailures);
            return null;
        }
        finally
        {
            c.Running = false;
            await db.SaveChangesAsync(CancellationToken.None);
        }
    }

    /// <summary>Raise a ticket through a ticket-adapter connector. Returns the external reference and URL.</summary>
    public async Task<(string ExternalRef, string? Url)> CreateTicketAsync(Guid connectorId, TicketRequest request, CancellationToken ct = default)
    {
        var c = await GetAsync(connectorId, ct) ?? throw new InvalidOperationException("Ticket connector not found");
        var adapter = TicketAdapter(c.AdapterId) ?? throw new InvalidOperationException("Ticket adapter " + c.AdapterId + " is not installed");
        var result = await adapter.CreateAsync(Decrypt(c), request, ct);
        await using var db = await _factory.CreateDbContextAsync(ct);
        await db.Connectors.Where(x => x.Id == connectorId).ExecuteUpdateAsync(u => u.SetProperty(x => x.LastSuccess, DateTime.UtcNow).SetProperty(x => x.LastError, (string?)null).SetProperty(x => x.ConsecutiveFailures, 0), ct);
        return result;
    }

    private async Task ReportAsync(Guid id, string msg)
    {
        try
        {
            await using var db = await _factory.CreateDbContextAsync();
            await db.Connectors.Where(c => c.Id == id).ExecuteUpdateAsync(u => u.SetProperty(c => c.Progress, msg.Length > 256 ? msg[..256] : msg));
        }
        catch { }
    }
}
