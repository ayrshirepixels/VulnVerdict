using System.Globalization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Services;

/// <summary>Opinionated defaults; the customer changes only what they must.</summary>
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
    /// <summary>Microsoft 365 through Microsoft Graph: an Entra app registration allowed to send as the From mailbox.</summary>
    public string M365TenantId { get; set; } = "";
    public string M365ClientId { get; set; } = "";
    public string M365ClientSecret { get; set; } = "";
    /// <summary>Optional yyyy-MM-dd: the console warns 30 days before the client secret expires.</summary>
    public string M365SecretExpires { get; set; } = "";
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

    // api tokens are stored as hashes by ApiTokenService, never here

    // tickets: "email" or the id of a ticket-adapter connector
    public string TicketChannel { get; set; } = "email";

    // webhooks: verdict created, promoted, closed
    public string WebhookUrl { get; set; } = "";
    public string WebhookSecret { get; set; } = "";

    // Teams and Slack: outbound only. The webhook addresses carry their own credential, so they are stored as secrets.
    public string TeamsWebhookUrl { get; set; } = "";
    public string SlackWebhookUrl { get; set; } = "";
    public bool ChatNotifyFixToday { get; set; } = true;
    public bool ChatNotifyDigest { get; set; } = true;
    public bool ChatNotifyChanges { get; set; } = true;
    public bool ChatNotifyFeedHealth { get; set; } = true;
    /// <summary>Off by default: Teams and Slack are someone else's cloud, so messages carry product and CVE only.</summary>
    public bool ChatIncludeAssetNames { get; set; }

    /// <summary>Done and Snooze links in the digest email that work without signing in (see docs/digest.md).</summary>
    public bool DigestActionLinks { get; set; } = true;

    // weekly management report
    public string ReportRecipients { get; set; } = "";
    public string ReportDay { get; set; } = "Monday";

    // central service, licence, MSP
    public string BundleUrl { get; set; } = "";
    public string LicenceKey { get; set; } = "";
    public bool TelemetryOptIn { get; set; }
    public bool MspReportOptIn { get; set; }
    public string MspPortalUrl { get; set; } = "";
    public string MspTenantToken { get; set; } = "";

    // vendor VEX statements: a JSON list of CSAF providers, blank for the built-in list (Feeds/Vex/VexProviders.cs)
    public string VexProviders { get; set; } = "";
    /// <summary>A product is flagged "End of life in N days" this many days before its vendor support ends.</summary>
    public int EolWarnDays { get; set; } = 180;

    // Cisco PSIRT openVuln API (optional, free registration)
    public string CiscoClientId { get; set; } = "";
    public string CiscoClientSecret { get; set; } = "";

    // AI explanations: none | anthropic | openai | openai-compatible (Ollama, vLLM, LM Studio)
    public string LlmProvider { get; set; } = "none";
    public string LlmApiKey { get; set; } = "";
    public string LlmModel { get; set; } = "";
    public string LlmBaseUrl { get; set; } = "";
    public bool LlmConfigured => LlmProvider is not ("none" or "") && !string.IsNullOrWhiteSpace(LlmModel)
        && (LlmProvider.Equals("openai-compatible", StringComparison.OrdinalIgnoreCase) || !string.IsNullOrWhiteSpace(LlmApiKey));

    public IEnumerable<string> Recipients => DigestRecipients.Split(new[] { ',', ';', '\n', ' ' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    public bool MailConfigured => !string.IsNullOrWhiteSpace(SmtpFrom) && MailTransport.ToLowerInvariant() switch
    {
        "smtp" => !string.IsNullOrWhiteSpace(SmtpHost),
        "m365" => !string.IsNullOrWhiteSpace(M365TenantId) && !string.IsNullOrWhiteSpace(M365ClientId) && !string.IsNullOrWhiteSpace(M365ClientSecret),
        _ => !string.IsNullOrWhiteSpace(MailApiKey),
    };
    public bool SmtpConfigured => MailConfigured;

    public TimeZoneInfo ResolveTimeZone()
    {
        try { return TimeZoneInfo.FindSystemTimeZoneById(TimeZone); }
        catch { return TimeZoneInfo.Utc; }
    }
}

public sealed class SettingsService
{
    private static readonly HashSet<string> Secret = new(StringComparer.OrdinalIgnoreCase) { nameof(AppSettings.SmtpPassword), nameof(AppSettings.MailApiKey), nameof(AppSettings.M365ClientSecret), nameof(AppSettings.OidcClientSecret), nameof(AppSettings.LlmApiKey), nameof(AppSettings.WebhookSecret), nameof(AppSettings.MspTenantToken), nameof(AppSettings.LicenceKey), nameof(AppSettings.CiscoClientId), nameof(AppSettings.CiscoClientSecret) };
    /// <summary>
    /// State rows an earlier release read credentials from in plain text, and the secret setting each now lives in.
    /// Moved (encrypted, old row deleted) the first time settings are read.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string> LegacyPlaintext = new Dictionary<string, string>
    {
        ["psirt:cisco:clientId"] = nameof(AppSettings.CiscoClientId),
        ["psirt:cisco:clientSecret"] = nameof(AppSettings.CiscoClientSecret),
    };
    /// <summary>Settings stored encrypted and never sent back to the browser.</summary>
    public static IReadOnlySet<string> SecretNames => Secret;
    static SettingsService() { Secret.Add(nameof(AppSettings.TeamsWebhookUrl)); Secret.Add(nameof(AppSettings.SlackWebhookUrl)); }

    /// <summary>
    /// For each secret, the settings that say where it is sent. A secret left blank on the form is filled from the stored
    /// value only while these are unchanged; otherwise pointing one of them elsewhere and pressing Test would send the
    /// stored secret to the new address. Secrets sent only to a fixed vendor address (SendGrid, Brevo, Cisco) have none.
    /// The mail transport is left out so switching transport does not ask for a password the new one will not use.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, string[]> SecretDestinations = new Dictionary<string, string[]>
    {
        [nameof(AppSettings.SmtpPassword)] = new[] { nameof(AppSettings.SmtpHost), nameof(AppSettings.SmtpPort), nameof(AppSettings.SmtpUsername), nameof(AppSettings.SmtpSecurity) },
        [nameof(AppSettings.M365ClientSecret)] = new[] { nameof(AppSettings.M365TenantId), nameof(AppSettings.M365ClientId) },
        [nameof(AppSettings.OidcClientSecret)] = new[] { nameof(AppSettings.OidcAuthority), nameof(AppSettings.OidcClientId) },
        [nameof(AppSettings.LlmApiKey)] = new[] { nameof(AppSettings.LlmProvider), nameof(AppSettings.LlmBaseUrl) },
        [nameof(AppSettings.MspTenantToken)] = new[] { nameof(AppSettings.MspPortalUrl) },
        [nameof(AppSettings.WebhookSecret)] = new[] { nameof(AppSettings.WebhookUrl) },
        [nameof(AppSettings.LicenceKey)] = new[] { nameof(AppSettings.BundleUrl) },
    };

    /// <summary>
    /// Fills the secrets left blank on <paramref name="form"/> from <paramref name="stored"/>, except those in
    /// <paramref name="clear"/> and those whose destination changed (<see cref="SecretDestinations"/>). Returns the
    /// names of the secrets that must be typed again; when it is not empty the form must not be saved.
    /// </summary>
    public static List<string> ReuseStoredSecrets(AppSettings form, AppSettings stored, IReadOnlyCollection<string> clear)
    {
        static string Value(AppSettings s, string name) => Convert.ToString(typeof(AppSettings).GetProperty(name)!.GetValue(s), CultureInfo.InvariantCulture)?.Trim() ?? "";
        var retype = new List<string>();
        foreach (var name in Secret)
        {
            var p = typeof(AppSettings).GetProperty(name)!;
            if (!string.IsNullOrEmpty((string?)p.GetValue(form)) || clear.Contains(name) || string.IsNullOrEmpty((string?)p.GetValue(stored))) continue;
            if (SecretDestinations.TryGetValue(name, out var where) && where.Any(w => !string.Equals(Value(form, w), Value(stored, w), StringComparison.OrdinalIgnoreCase)))
                retype.Add(name);
            else
                p.SetValue(form, p.GetValue(stored));
        }
        return retype;
    }
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
        var plaintextSecrets = new List<string>();
        foreach (var p in typeof(AppSettings).GetProperties().Where(p => p.CanWrite))
        {
            if (!rows.TryGetValue(p.Name, out var row) || row.Value is null) continue;
            var value = row.Value;
            if (row.Encrypted)
            {
                try { value = _protector.Unprotect(value); } catch { value = ""; }
            }
            else if (Secret.Contains(p.Name) && value != "") plaintextSecrets.Add(p.Name);
            try
            {
                object typed = p.PropertyType == typeof(int) ? int.Parse(value)
                    : p.PropertyType == typeof(bool) ? bool.Parse(value)
                    : value;
                p.SetValue(s, typed);
            }
            catch { }
        }
        // a setting that became secret in a later release (the licence key) is encrypted the first time it is read
        if (plaintextSecrets.Count > 0) await EncryptPlaintextAsync(plaintextSecrets, ct);
        // credentials that used to sit in plain state rows (the Cisco API pair): used from the old row this once, then moved
        var legacy = false;
        foreach (var (key, name) in LegacyPlaintext)
        {
            if (!rows.TryGetValue(key, out var old)) continue;
            legacy = true;
            var value = old.Encrypted ? SafeUnprotect(old.Value) : old.Value;
            var p = typeof(AppSettings).GetProperty(name)!;
            if (!string.IsNullOrWhiteSpace(value) && string.IsNullOrEmpty((string?)p.GetValue(s))) p.SetValue(s, value.Trim());
        }
        if (legacy) await MoveLegacyAsync(ct);
        return s;
    }

    private async Task MoveLegacyAsync(CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        var now = DateTime.UtcNow;
        foreach (var (key, name) in LegacyPlaintext)
        {
            var old = await db.Settings.FirstOrDefaultAsync(r => r.Key == key, ct);
            if (old is null) continue;
            var value = (old.Encrypted ? SafeUnprotect(old.Value) : old.Value)?.Trim();
            if (!string.IsNullOrEmpty(value))
            {
                // a value already saved under the new name wins: it is the newer one
                var row = await db.Settings.FirstOrDefaultAsync(r => r.Key == name, ct);
                if (row is null) db.Settings.Add(new AppSetting { Key = name, Value = _protector.Protect(value), Encrypted = true, UpdatedAt = now });
                else if (string.IsNullOrEmpty(row.Value)) { row.Value = _protector.Protect(value); row.Encrypted = true; row.UpdatedAt = now; }
            }
            db.Settings.Remove(old);
        }
        // the web and the worker may both get here first; whichever loses finds the rows already moved
        try { await db.SaveChangesAsync(ct); } catch (DbUpdateException) { }
    }

    private async Task EncryptPlaintextAsync(List<string> keys, CancellationToken ct)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        foreach (var row in await db.Settings.Where(r => keys.Contains(r.Key) && !r.Encrypted).ToListAsync(ct))
        {
            if (string.IsNullOrEmpty(row.Value)) continue;
            row.Value = _protector.Protect(row.Value); row.Encrypted = true;
        }
        await db.SaveChangesAsync(ct);
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
                if (before == raw && row.Encrypted == enc) continue;
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
        /// <summary>Mail health: when mail last went out, and the last failure (shown as a banner until mail works again).</summary>
        public const string MailLastSuccess = "state:mail:lastSuccess";
        public const string MailLastError = "state:mail:lastError";
        public const string MailLastErrorAt = "state:mail:lastErrorAt";
    }
}
