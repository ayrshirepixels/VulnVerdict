using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Services;

/// <summary>Section 11.2 item 9. Opinionated defaults; the customer changes only what they must.</summary>
public sealed class AppSettings
{
    // digest
    public string DigestTime { get; set; } = "07:30";
    public string TimeZone { get; set; } = "Europe/London";
    public bool DigestWeekdaysOnly { get; set; } = true;
    public string DigestRecipients { get; set; } = "";
    public string OrganisationName { get; set; } = "";
    public string BaseUrl { get; set; } = "";

    // email transport: smtp | sendgrid | brevo
    public string MailTransport { get; set; } = "smtp";
    public string MailApiKey { get; set; } = "";
    public string SmtpHost { get; set; } = "";
    public int SmtpPort { get; set; } = 587;
    public string SmtpUsername { get; set; } = "";
    public string SmtpPassword { get; set; } = "";
    public string SmtpSecurity { get; set; } = "auto"; // auto | starttls | ssl | none
    public string SmtpFrom { get; set; } = "";

    // tickets and alerts
    public string HelpdeskIntakeAddress { get; set; } = "";
    public bool TicketsEnabled { get; set; } = true;
    public string AdminAlertAddress { get; set; } = "";

    // SLA defaults (days)
    public int SlaFixTodayDays { get; set; } = 2;
    public int SlaFixThisWeekDays { get; set; } = 7;
    public int SlaNextPatchCycleDays { get; set; } = 30;

    // OIDC
    public bool OidcEnabled { get; set; }
    public string OidcDisplayName { get; set; } = "Single sign-on";
    public string OidcAuthority { get; set; } = "";
    public string OidcClientId { get; set; } = "";
    public string OidcClientSecret { get; set; } = "";
    public string OidcAdminGroup { get; set; } = "";
    public string OidcOperatorGroup { get; set; } = "";
    public string OidcGroupClaim { get; set; } = "groups";

    // api
    public string ApiToken { get; set; } = "";

    // tickets (section 11.3): "email" or the id of a ticket-adapter connector
    public string TicketChannel { get; set; } = "email";

    // webhooks (section 11.4): verdict created, promoted, closed
    public string WebhookUrl { get; set; } = "";
    public string WebhookSecret { get; set; } = "";

    // weekly management report (section 11.2 item 8)
    public string ReportRecipients { get; set; } = "";
    public string ReportDay { get; set; } = "Monday";

    // central service, licence, MSP (section 10.2, phase 5)
    public string BundleUrl { get; set; } = "";
    public string LicenceKey { get; set; } = "";
    public bool TelemetryOptIn { get; set; }
    public bool MspReportOptIn { get; set; }
    public string MspPortalUrl { get; set; } = "";
    public string MspTenantToken { get; set; } = "";

    // AI explanations (section 12): none | anthropic | openai | openai-compatible (Ollama, vLLM, LM Studio)
    public string LlmProvider { get; set; } = "none";
    public string LlmApiKey { get; set; } = "";
    public string LlmModel { get; set; } = "";
    public string LlmBaseUrl { get; set; } = "";
    public bool LlmConfigured => LlmProvider is not ("none" or "") && !string.IsNullOrWhiteSpace(LlmModel)
        && (LlmProvider.Equals("openai-compatible", StringComparison.OrdinalIgnoreCase) || !string.IsNullOrWhiteSpace(LlmApiKey));

    public IEnumerable<string> Recipients => DigestRecipients.Split(new[] { ',', ';', '\n', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    public bool MailConfigured => !string.IsNullOrWhiteSpace(SmtpFrom) && (MailTransport.Equals("smtp", StringComparison.OrdinalIgnoreCase)
        ? !string.IsNullOrWhiteSpace(SmtpHost)
        : !string.IsNullOrWhiteSpace(MailApiKey));
    public bool SmtpConfigured => MailConfigured;

    public TimeZoneInfo ResolveTimeZone()
    {
        try { return TimeZoneInfo.FindSystemTimeZoneById(TimeZone); }
        catch { return TimeZoneInfo.Utc; }
    }
}

public sealed class SettingsService
{
    private static readonly HashSet<string> Secret = new(StringComparer.OrdinalIgnoreCase) { nameof(AppSettings.SmtpPassword), nameof(AppSettings.MailApiKey), nameof(AppSettings.OidcClientSecret), nameof(AppSettings.ApiToken), nameof(AppSettings.LlmApiKey), nameof(AppSettings.WebhookSecret), nameof(AppSettings.MspTenantToken) };
    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly IDataProtector _protector;

    public SettingsService(IDbContextFactory<VvDbContext> factory, IDataProtectionProvider dp)
    {
        _factory = factory;
        _protector = dp.CreateProtector("VulnVerdict.Secrets.v1");
    }

    public async Task<AppSettings> LoadAsync(CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var rows = await db.Settings.AsNoTracking().ToDictionaryAsync(s => s.Key, ct);
        var s = new AppSettings();
        foreach (var p in typeof(AppSettings).GetProperties().Where(p => p.CanWrite))
        {
            if (!rows.TryGetValue(p.Name, out var row) || row.Value is null) continue;
            var value = row.Value;
            if (row.Encrypted)
            {
                try { value = _protector.Unprotect(value); } catch { value = ""; }
            }
            try
            {
                object typed = p.PropertyType == typeof(int) ? int.Parse(value)
                    : p.PropertyType == typeof(bool) ? bool.Parse(value)
                    : value;
                p.SetValue(s, typed);
            }
            catch { }
        }
        return s;
    }

    public async Task SaveAsync(AppSettings s, string actor, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var rows = await db.Settings.ToDictionaryAsync(r => r.Key, ct);
        var now = DateTime.UtcNow;
        var changed = new List<string>();
        foreach (var p in typeof(AppSettings).GetProperties().Where(p => p.CanWrite))
        {
            var raw = p.GetValue(s)?.ToString() ?? "";
            var enc = Secret.Contains(p.Name);
            var stored = enc ? (raw == "" ? "" : _protector.Protect(raw)) : raw;
            if (rows.TryGetValue(p.Name, out var row))
            {
                var before = row.Encrypted ? (row.Value == "" ? "" : SafeUnprotect(row.Value)) : row.Value;
                if (before == raw) continue;
                row.Value = stored; row.Encrypted = enc; row.UpdatedAt = now;
            }
            else db.Settings.Add(new AppSetting { Key = p.Name, Value = stored, Encrypted = enc, UpdatedAt = now });
            changed.Add(enc ? p.Name + " (secret)" : p.Name + "=" + raw);
        }
        if (changed.Count > 0)
            db.Audit.Add(new AuditEntry { At = now, Actor = actor, Action = "settings.update", Target = "settings", After = string.Join("; ", changed) });
        await db.SaveChangesAsync(ct);
    }

    private string? SafeUnprotect(string? v)
    {
        if (string.IsNullOrEmpty(v)) return v;
        try { return _protector.Unprotect(v); } catch { return null; }
    }

    // simple key/value used by the worker for state (heartbeat, last digest, last alert)
    public async Task<string?> GetStateAsync(string key, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        return (await db.Settings.AsNoTracking().FirstOrDefaultAsync(s => s.Key == key, ct))?.Value;
    }

    public async Task SetStateAsync(string key, string? value, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var row = await db.Settings.FirstOrDefaultAsync(s => s.Key == key, ct);
        if (row is null) db.Settings.Add(new AppSetting { Key = key, Value = value, UpdatedAt = DateTime.UtcNow });
        else { row.Value = value; row.UpdatedAt = DateTime.UtcNow; }
        await db.SaveChangesAsync(ct);
    }

    public static class Keys
    {
        public const string WorkerHeartbeat = "state:worker:heartbeat";
        public const string LastDailyDigest = "state:digest:lastDaily";
        public const string LastAdminAlert = "state:alert:last";
        public const string LastWorkerStaleAlert = "state:alert:workerStale";
        public const string EvaluateRequested = "state:evaluate:requested";
        public const string LastEvaluation = "state:evaluate:last";
    }
}
