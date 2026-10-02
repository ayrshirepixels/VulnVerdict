using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Adapters.Linux;
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
        else if (!c.AdapterId.Equals(meta.Id, StringComparison.OrdinalIgnoreCase)) throw new ArgumentException("That connector uses a different source.");
        // blank password fields keep the stored value, but only while the connector still points where it did
        var stored = Decrypt(c);
        var reenter = ReuseStoredSecrets(meta, credentials, stored);
        if (reenter.Count > 0) throw new ArgumentException(ReenterMessage(reenter));
        var missing = meta.Form.Where(f => f.Required && string.IsNullOrWhiteSpace(credentials.GetValueOrDefault(f.Key))).Select(f => f.Label).ToList();
        if (missing.Count > 0) throw new ArgumentException("Required: " + string.Join(", ", missing));
        c.DisplayName = string.IsNullOrWhiteSpace(displayName) ? meta.DisplayName : displayName.Trim();
        c.CredentialsJson = _protector.Protect(JsonSerializer.Serialize(credentials));
        c.Enabled = enabled; c.IntervalMinutes = Math.Max(15, intervalMinutes);
        db.Audit.Add(new AuditEntry { At = now, Actor = actor, Action = id is null ? "connector.add" : "connector.update", Target = c.DisplayName, After = meta.Id + (enabled ? "" : " (disabled)") });
        // which hosts the saved credential may be sent to is worth its own line, fingerprints included
        if (HostKeyChanges(stored, credentials) is { } pins)
            db.Audit.Add(new AuditEntry { At = now, Actor = actor, Action = "connector.hostkeys", Target = c.DisplayName, Before = pins.Before, After = pins.After });
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
            if (c is not null && !c.AdapterId.Equals(meta.Id, StringComparison.OrdinalIgnoreCase)) return new TestResult(false, "That connector uses a different source.");
            if (c is not null)
            {
                var reenter = ReuseStoredSecrets(meta, credentials, Decrypt(c));
                if (reenter.Count > 0) return new TestResult(false, ReenterMessage(reenter));
            }
        }
        // every SSH connection the test makes reports the key it was shown, for the trust prompt
        var seen = SshHostKeys.Listen();
        try
        {
            var inv = Adapter(adapterId);
            var result = inv is not null ? await inv.TestAsync(credentials, ct) : await TicketAdapter(adapterId)!.TestAsync(credentials, ct);
            return result with { HostKeys = seen.Snapshot() };
        }
        catch (Exception ex) { return new TestResult(false, ex.Message) { HostKeys = seen.Snapshot() }; }
    }

    /// <summary>
    /// Fill blank secret fields from the stored credential, only if every field that says where the credential goes
    /// (address, tenant, account, TLS checking: every text field and the verify switch) is unchanged. Otherwise a
    /// changed address with a blank password would send the stored secret to wherever the form now points.
    /// Returns the labels of secrets that must be typed again.
    /// </summary>
    public static List<string> ReuseStoredSecrets(AdapterMetadata meta, Dictionary<string, string> credentials, Dictionary<string, string> stored)
    {
        var blank = meta.Form.Where(f => CredentialTypes.IsSecret(f.Type) && credentials.GetValueOrDefault(f.Key) == "" && !string.IsNullOrEmpty(stored.GetValueOrDefault(f.Key))).ToList();
        if (blank.Count == 0) return new();
        var moved = meta.Form.Any(f => IdentifiesEndpoint(f) && Norm(f, credentials.GetValueOrDefault(f.Key)) != Norm(f, stored.GetValueOrDefault(f.Key)))
            // a key the form does not know about could be read by the adapter as well
            || credentials.Where(kv => meta.Form.All(f => f.Key != kv.Key)).Any(kv => Norm(kv.Value) != Norm(stored.GetValueOrDefault(kv.Key)));
        if (moved) return blank.Select(f => f.Label).ToList();
        foreach (var f in blank) credentials[f.Key] = stored[f.Key];
        return new();
    }

    // Pinned host keys are not where the credential goes: pinning a host's key (the trust prompt, or pasting a line)
    // must not ask for the password again. The host and port fields still do, and so do the switches that decide which
    // server is believed: TLS verification, and accepting any SSH host key (on, the password goes to whatever answers).
    private static bool IdentifiesEndpoint(CredentialField f) =>
        !IsHostKeyField(f.Key) && (f.Type is CredentialTypes.Text or CredentialTypes.TextArea
            || (f.Type == CredentialTypes.Bool && (f.Key.Equals("verifyTls", StringComparison.OrdinalIgnoreCase) || f.Key.Equals("acceptAny", StringComparison.OrdinalIgnoreCase))));

    private static string Norm(string? v) => (v ?? "").Trim();
    // a switch never saved reads as its default, so ticking it on and off again is not a change
    private static string Norm(CredentialField f, string? v) =>
        f.Type == CredentialTypes.Bool ? (string.IsNullOrWhiteSpace(v) ? (f.Default ?? "false") : v.Trim()).ToLowerInvariant() : Norm(v);

    private static string ReenterMessage(List<string> labels) =>
        "The connection details changed, so the saved " + string.Join(", ", labels) + " is not reused. Type " + (labels.Count == 1 ? "it" : "them") + " again.";

    // ------------------------------------------------------------------ SSH host keys

    /// <summary>The multi-host forms (Linux, Windows over OpenSSH) pin one key per line; the appliance forms pin a single fingerprint.</summary>
    public const string KnownHostKeysField = "knownHostKeys";
    public const string HostKeyField = "hostKey";

    public static bool IsHostKeyField(string key) => key is KnownHostKeysField or HostKeyField;

    /// <summary>What the credential currently pins for a host, or null.</summary>
    public static string? PinnedFingerprint(AdapterMetadata meta, IReadOnlyDictionary<string, string> credentials, string host)
    {
        if (meta.Form.Any(f => f.Key == KnownHostKeysField)) return SshHostKeys.PinnedFor(credentials.GetValueOrDefault(KnownHostKeysField), host);
        if (meta.Form.Any(f => f.Key == HostKeyField) && SameHost(credentials.GetValueOrDefault("host"), host))
            return credentials.GetValueOrDefault(HostKeyField) is { } pin && pin.Trim().Length > 0 ? SshLinuxAdapter.NormaliseFingerprint(pin) : null;
        return null;
    }

    /// <summary>
    /// Pin presented keys in a credential. Each key is compared again with what the credential pins now, not with
    /// what the test saw: a host with no pin is added; a host pinned to a different key is only replaced when it is
    /// named in <paramref name="replaceHosts"/>, so trusting everything new can never swap a key that changed.
    /// Returns what was applied, with the fingerprint each one replaced (if any).
    /// </summary>
    public static List<PresentedHostKey> ApplyTrust(AdapterMetadata meta, Dictionary<string, string> credentials, IEnumerable<PresentedHostKey> keys, IReadOnlySet<string>? replaceHosts = null)
    {
        var applied = new List<PresentedHostKey>();
        var many = meta.Form.Any(f => f.Key == KnownHostKeysField);
        if (!many && !meta.Form.Any(f => f.Key == HostKeyField)) return applied;
        foreach (var k in keys)
        {
            // the single-fingerprint forms have one host; a key from some other host is not theirs to pin
            if (string.IsNullOrWhiteSpace(k.Fingerprint) || (!many && !SameHost(credentials.GetValueOrDefault("host"), k.Host))) continue;
            var pinned = PinnedFingerprint(meta, credentials, k.Host);
            var status = SshHostKeys.Classify(k.Fingerprint, pinned);
            if (status == HostKeyStatus.Pinned) continue;
            if (status == HostKeyStatus.Changed && replaceHosts?.Contains(k.Host) != true) continue;
            if (!many) credentials[HostKeyField] = k.Display();
            else credentials[KnownHostKeysField] = status == HostKeyStatus.Changed
                ? SshHostKeys.ReplaceKnownHost(credentials.GetValueOrDefault(KnownHostKeysField), k.Host, k.Fingerprint)
                : SshHostKeys.AppendKnownHost(credentials.GetValueOrDefault(KnownHostKeysField), k.Host, k.Fingerprint);
            applied.Add(k with { Status = status, PinnedFingerprint = pinned });
        }
        return applied;
    }

    /// <summary>
    /// The trust prompt for a saved connector: pin the keys in the stored credential and write them to the audit log.
    /// Administrators only; the page checks the role before calling. Nothing else in the credential changes, so the
    /// saved password stays. Returns what was pinned.
    /// </summary>
    public async Task<List<PresentedHostKey>> TrustHostKeysAsync(Guid id, IReadOnlyCollection<PresentedHostKey> keys, IReadOnlySet<string>? replaceHosts, string actor, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var c = await db.Connectors.FirstOrDefaultAsync(x => x.Id == id, ct);
        var meta = c is null ? null : Metadata(c.AdapterId);
        if (c is null || meta is null) return new();
        var credentials = Decrypt(c);
        var applied = ApplyTrust(meta, credentials, keys, replaceHosts);
        if (applied.Count == 0) return applied;
        c.CredentialsJson = _protector.Protect(JsonSerializer.Serialize(credentials));
        // what is pinned now no longer needs review
        var left = PendingHostKeys(c).Where(p => !applied.Any(a => a.Host.Equals(p.Host, StringComparison.OrdinalIgnoreCase))).ToList();
        c.PendingHostKeysJson = left.Count == 0 ? null : JsonSerializer.Serialize(left);
        var now = DateTime.UtcNow;
        var added = applied.Where(a => a.Status == HostKeyStatus.New).ToList();
        if (added.Count > 0)
            db.Audit.Add(new AuditEntry { At = now, Actor = actor, Action = "connector.hostkey.trust", Target = c.DisplayName, After = string.Join("; ", added.Select(a => a.Describe())) });
        foreach (var r in applied.Where(a => a.Status == HostKeyStatus.Changed))
            db.Audit.Add(new AuditEntry { At = now, Actor = actor, Action = "connector.hostkey.replace", Target = c.DisplayName, Before = r.Host + " " + SshLinuxAdapter.FormatFingerprint(r.PinnedFingerprint ?? ""), After = r.Describe() });
        await db.SaveChangesAsync(ct);
        return applied;
    }

    /// <summary>Host keys the connector's last run could not accept, for the review prompt.</summary>
    public static List<PresentedHostKey> PendingHostKeys(Connector c)
    {
        if (string.IsNullOrEmpty(c.PendingHostKeysJson)) return new();
        try { return JsonSerializer.Deserialize<List<PresentedHostKey>>(c.PendingHostKeysJson) ?? new(); } catch { return new(); }
    }

    /// <summary>Before and after of the pinned host keys when a save changed them; null when it did not.</summary>
    private static (string? Before, string After)? HostKeyChanges(Dictionary<string, string> stored, Dictionary<string, string> saved)
    {
        static string Pins(Dictionary<string, string> c) => string.Join("; ",
            SshLinuxAdapter.KnownHostKeys(c.GetValueOrDefault(KnownHostKeysField) ?? "").OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase).Select(kv => SshHostKeys.KnownHostsLine(kv.Key, kv.Value))
                .Concat(c.GetValueOrDefault(HostKeyField) is { } one && one.Trim().Length > 0 ? new[] { SshLinuxAdapter.FormatFingerprint(one) } : Array.Empty<string>()));
        var before = Pins(stored); var after = Pins(saved);
        return before == after ? null : (before.Length == 0 ? null : before, after.Length == 0 ? "no host keys pinned" : after);
    }

    private static bool SameHost(string? formHost, string presentedHost)
    {
        var typed = VulnVerdict.Core.Adapters.Firewalls.FwCreds.Host(formHost ?? "");
        return typed.Length > 0 && (typed.Equals(presentedHost, StringComparison.OrdinalIgnoreCase) || SshTarget.Parse(typed).Host.Equals(SshTarget.Parse(presentedHost).Host, StringComparison.OrdinalIgnoreCase));
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
        // unpinned and changed SSH host keys met on the way are kept for the review prompt on the Connectors page
        var seen = SshHostKeys.Listen();
        void NoteHostKeys() => c.PendingHostKeysJson = seen.NeedReview() is { Count: > 0 } review ? JsonSerializer.Serialize(review) : null;
        try
        {
            var creds = Decrypt(c);
            var progress = new Progress<string>(msg => { _ = ReportAsync(c.Id, msg); });
            var result = await adapter.CollectAsync(creds, c.LastSuccess, progress, ct);
            NoteHostKeys();
            var summary = await _inventory.ApplyAsync(c, result, ct);
            c.LastSuccess = DateTime.UtcNow; c.LastError = result.Warnings.Count > 0 ? "Warnings: " + string.Join("; ", result.Warnings.Take(5)) : null;
            c.ConsecutiveFailures = 0; c.AssetsLastRun = summary.Assets; c.SoftwareLastRun = summary.Software;
            c.Progress = summary.Assets + " assets, " + summary.Software + " software" + (summary.Unmapped > 0 ? ", " + summary.Unmapped + " need mapping" : "");
            return summary;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            NoteHostKeys();
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
