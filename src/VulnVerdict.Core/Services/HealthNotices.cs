using System.Globalization;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Services;

/// <summary>
/// Problems the console must show on screen because email cannot be relied on to report them: mail that is failing
/// (the administrator alert would go out over the same broken mail) and client secrets that expire soon.
/// </summary>
public sealed class HealthNotices
{
    public sealed record Notice(bool Error, string Text, string Link);

    /// <summary>The optional credential field on connector forms that records when the connector's secret expires.</summary>
    public const string SecretExpiresKey = "secretExpires";
    public const int WarnDays = 30;

    private readonly SettingsService _settings;
    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly ConnectorService _connectors;

    public HealthNotices(SettingsService settings, IDbContextFactory<VvDbContext> factory, ConnectorService connectors)
    {
        _settings = settings; _factory = factory; _connectors = connectors;
    }

    public async Task<List<Notice>> GetAsync(CancellationToken ct = default)
    {
        var list = new List<Notice>();
        if (await MailFailureAsync(ct) is { } mail) list.Add(mail);
        list.AddRange(await SecretsAsync(DateTime.UtcNow, ct));
        list.AddRange(await WebhookService.FailureNoticesAsync(_factory, ct));
        list.AddRange(await HostKeysAsync(ct));
        if (DeployFilesNotice(Environment.GetEnvironmentVariable("Role"), Environment.GetEnvironmentVariable("VV_DEPLOY_FILES")) is { } files) list.Add(files);
        return list;
    }

    /// <summary>The generation of deploy/docker-compose.yml this console expects; the file passes it as VV_DEPLOY_FILES.</summary>
    public const int DeployFilesVersion = 2;
    public const string UpdatingDocs = "https://github.com/ayrshirepixels/VulnVerdict/blob/main/docs/install.md#updating-from-11x";

    /// <summary>
    /// A Compose or appliance install (Role web or worker) still running under an older docker-compose.yml: update.sh
    /// before 1.2 changed images but never the file, so the backup folder, VV_KEY_SECRET and restore.sh are not wired up
    /// there, and nothing else would say so. The all-in-one image has no Compose file and is never flagged.
    /// </summary>
    public static Notice? DeployFilesNotice(string? role, string? deployFiles)
    {
        if (role is null || !(role.Equals("web", StringComparison.OrdinalIgnoreCase) || role.Equals("worker", StringComparison.OrdinalIgnoreCase))) return null;
        if (int.TryParse(deployFiles, out var v) && v >= DeployFilesVersion) return null;
        return new Notice(false, "This install's docker-compose.yml and scripts are from an older release, so the backup folder (VV_BACKUP_DIR), "
            + "VV_KEY_SECRET and restore.sh are not set up. Take the new ones from this release's vulnverdict-compose.tar.gz, as the install guide shows under Updating.", UpdatingDocs);
    }

    /// <summary>
    /// Connectors whose last run met SSH hosts it would not talk to: a key nobody has pinned, or one that differs
    /// from the pinned key. The link opens the review prompt on the Connectors page.
    /// </summary>
    public async Task<List<Notice>> HostKeysAsync(CancellationToken ct = default)
    {
        var list = new List<Notice>();
        await using var db = await _factory.CreateDbContextAsync(ct);
        foreach (var c in await db.Connectors.AsNoTracking().Where(c => c.Enabled && c.PendingHostKeysJson != null).ToListAsync(ct))
        {
            var keys = ConnectorService.PendingHostKeys(c);
            var changed = keys.Count(k => k.Status == Adapters.Linux.HostKeyStatus.Changed);
            var unpinned = keys.Count - changed;
            if (keys.Count == 0) continue;
            var link = "/connectors?review=" + c.Id;
            if (changed > 0)
                list.Add(new Notice(true, "Connector " + c.DisplayName + ": " + Hosts(changed) + " presented a different SSH host key from the pinned one. Check the server before replacing the key.", link));
            if (unpinned > 0)
                list.Add(new Notice(false, "Connector " + c.DisplayName + ": " + Hosts(unpinned) + (unpinned == 1 ? " has" : " have") + " no pinned SSH host key and " + (unpinned == 1 ? "was" : "were") + " not collected.", link));
        }
        return list;

        static string Hosts(int n) => n + " host" + (n == 1 ? "" : "s");
    }

    /// <summary>Mail failed more recently than it last worked.</summary>
    public async Task<Notice?> MailFailureAsync(CancellationToken ct = default)
    {
        var errorAt = ParseStamp(await _settings.GetStateAsync(SettingsService.Keys.MailLastErrorAt, ct));
        if (errorAt is null) return null;
        var okAt = ParseStamp(await _settings.GetStateAsync(SettingsService.Keys.MailLastSuccess, ct));
        if (okAt is not null && okAt >= errorAt) return null;
        var error = await _settings.GetStateAsync(SettingsService.Keys.MailLastError, ct) ?? "unknown error";
        return new Notice(true, "Mail is not being sent (failing since " + errorAt.Value.ToString("d MMM HH:mm", CultureInfo.InvariantCulture) + " UTC): " + error.TrimEnd().TrimEnd('.') + "."
            + " Digests and alerts will not arrive until this is fixed.", "/settings");
    }

    /// <summary>Secrets whose recorded expiry date is within <see cref="WarnDays"/> days, or past.</summary>
    public async Task<List<Notice>> SecretsAsync(DateTime utcNow, CancellationToken ct = default)
    {
        var dates = new List<(string What, string? Date, string Link)>();
        var s = await _settings.LoadAsync(ct);
        if (s.MailTransport.Equals("m365", StringComparison.OrdinalIgnoreCase)) dates.Add(("Microsoft 365 mail", s.M365SecretExpires, "/settings"));
        await using var db = await _factory.CreateDbContextAsync(ct);
        foreach (var c in await db.Connectors.AsNoTracking().Where(c => c.Enabled).ToListAsync(ct))
        {
            Dictionary<string, string> creds;
            try { creds = _connectors.Decrypt(c); } catch { continue; }
            if (creds.TryGetValue(SecretExpiresKey, out var d) && !string.IsNullOrWhiteSpace(d)) dates.Add(("Connector " + c.DisplayName, d, "/connectors"));
        }
        return Due(dates, utcNow).ToList();
    }

    public static IEnumerable<Notice> Due(IEnumerable<(string What, string? Date, string Link)> secrets, DateTime utcNow)
    {
        var today = utcNow.Date;
        foreach (var (what, date, link) in secrets)
        {
            if (ParseDate(date) is not { } expires) continue;
            var days = (expires - today).Days;
            if (days > WarnDays) continue;
            yield return days < 0
                ? new Notice(true, what + ": the client secret expired on " + expires.ToString("d MMM yyyy", CultureInfo.InvariantCulture) + ". Create a new one and enter it with its new expiry date.", link)
                : new Notice(false, what + ": the client secret expires " + (days == 0 ? "today" : "in " + days + " day" + (days == 1 ? "" : "s")) + " (" + expires.ToString("d MMM yyyy", CultureInfo.InvariantCulture) + "). Create a new one before then.", link);
        }
    }

    public static DateTime? ParseDate(string? s) =>
        DateTime.TryParseExact((s ?? "").Trim(), new[] { "yyyy-MM-dd", "d/M/yyyy", "dd/MM/yyyy" }, CultureInfo.InvariantCulture, DateTimeStyles.None, out var d) ? d.Date : null;

    private static DateTime? ParseStamp(string? s) =>
        DateTime.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var d) ? d.ToUniversalTime() : null;
}
