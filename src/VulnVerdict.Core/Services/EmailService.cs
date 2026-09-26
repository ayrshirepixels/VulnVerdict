using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using VulnVerdict.Core.Adapters.Endpoints;
using System.Net.Http.Json;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Logging;
using MimeKit;

namespace VulnVerdict.Core.Services;

public sealed class EmailNotConfiguredException : Exception
{
    public EmailNotConfiguredException(string what) : base(what + " Set it in Settings under Mail.") { }
}

/// <summary>
/// Outbound mail. Four transports, chosen in Settings: SMTP (MailKit), Microsoft 365 through Microsoft Graph, and the
/// SendGrid and Brevo v3 APIs. Every message has an HTML body and a text alternative; custom headers carry ticket
/// correlation keys. Microsoft 365 matters because Exchange Online is retiring password sign-in for SMTP: Graph needs
/// only an app registration allowed to send as one mailbox, and outbound HTTPS.
/// </summary>
public sealed class EmailService
{
    public const string SendGridUrl = "https://api.sendgrid.com/v3/mail/send";
    public const string BrevoUrl = "https://api.brevo.com/v3/smtp/email";
    public const string GraphLogin = "https://login.microsoftonline.com/";
    public const string GraphSendMail = "https://graph.microsoft.com/v1.0/users/{0}/sendMail";

    /// <summary>Graph tokens per app registration (tenant, client and a hash of the secret), reused until shortly before they expire.</summary>
    private static readonly ConcurrentDictionary<string, OAuthTokens.Token> GraphTokens = new();

    private readonly SettingsService _settings;
    private readonly IHttpClientFactory _http;
    private readonly ILogger<EmailService> _log;

    public EmailService(SettingsService settings, IHttpClientFactory http, ILogger<EmailService> log)
    {
        _settings = settings; _http = http; _log = log;
    }

    public async Task SendAsync(IEnumerable<string> to, string subject, string html, string text, CancellationToken ct = default, IEnumerable<(string Name, string Value)>? headers = null)
    {
        try
        {
            await SendCoreAsync(to, subject, html, text, headers, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // kept for the on-screen banner: the administrator alert would go out over this same broken mail
            await RecordAsync(SettingsService.Keys.MailLastError, ex.Message.Length > 500 ? ex.Message[..500] : ex.Message);
            await RecordAsync(SettingsService.Keys.MailLastErrorAt, DateTime.UtcNow.ToString("O"));
            throw;
        }
        await RecordAsync(SettingsService.Keys.MailLastSuccess, DateTime.UtcNow.ToString("O"));
    }

    private async Task RecordAsync(string key, string value)
    {
        try { await _settings.SetStateAsync(key, value, CancellationToken.None); }
        catch (Exception ex) { _log.LogWarning(ex, "Could not record mail health"); }
    }

    private async Task SendCoreAsync(IEnumerable<string> to, string subject, string html, string text, IEnumerable<(string Name, string Value)>? headers, CancellationToken ct)
    {
        var s = await _settings.LoadAsync(ct);
        if (!s.MailConfigured) throw new EmailNotConfiguredException(s.MailTransport.ToLowerInvariant() switch
        {
            "smtp" => "SMTP host and from address are required.",
            "m365" => "Tenant ID, application (client) ID, client secret and the from mailbox are required for Microsoft 365.",
            _ => "API key and from address are required for " + s.MailTransport + ".",
        });
        var recipients = to.Where(t => !string.IsNullOrWhiteSpace(t)).Distinct().ToList();
        if (recipients.Count == 0) throw new InvalidOperationException("No recipients");
        var hdrs = headers?.ToList() ?? new();

        switch (s.MailTransport.ToLowerInvariant())
        {
            case "sendgrid": await SendGridAsync(s, recipients, subject, html, text, hdrs, ct); break;
            case "brevo": await BrevoAsync(s, recipients, subject, html, text, hdrs, ct); break;
            case "m365": await GraphAsync(s, recipients, subject, html, text, hdrs, ct); break;
            default: await SmtpAsync(s, recipients, subject, html, text, hdrs, ct); break;
        }
        _log.LogInformation("Sent mail '{Subject}' to {Count} recipient(s) via {Transport}", subject, recipients.Count, s.MailTransport);
    }

    /// <summary>The same message for SMTP and for Graph: HTML with a text alternative, plus any correlation headers.</summary>
    public static MimeMessage BuildMime(string from, List<string> recipients, string subject, string html, string text, List<(string Name, string Value)> headers)
    {
        var msg = new MimeMessage();
        msg.From.Add(MailboxAddress.Parse(from));
        foreach (var r in recipients) msg.To.Add(MailboxAddress.Parse(r));
        msg.Subject = subject;
        foreach (var (n, v) in headers) msg.Headers.Add(n, v);
        msg.Body = new BodyBuilder { HtmlBody = html, TextBody = text }.ToMessageBody();
        return msg;
    }

    private static async Task SmtpAsync(AppSettings s, List<string> recipients, string subject, string html, string text, List<(string Name, string Value)> headers, CancellationToken ct)
    {
        var msg = BuildMime(s.SmtpFrom, recipients, subject, html, text, headers);

        using var client = new SmtpClient();
        var security = s.SmtpSecurity.ToLowerInvariant() switch
        {
            "ssl" => SecureSocketOptions.SslOnConnect,
            "starttls" => SecureSocketOptions.StartTls,
            "none" => SecureSocketOptions.None,
            _ => SecureSocketOptions.Auto
        };
        await client.ConnectAsync(s.SmtpHost, s.SmtpPort, security, ct);
        if (!string.IsNullOrEmpty(s.SmtpUsername)) await client.AuthenticateAsync(s.SmtpUsername, s.SmtpPassword, ct);
        await client.SendAsync(msg, ct);
        await client.DisconnectAsync(true, ct);
    }

    private async Task SendGridAsync(AppSettings s, List<string> recipients, string subject, string html, string text, List<(string Name, string Value)> headers, CancellationToken ct)
    {
        var client = _http.CreateClient("mail");
        using var req = new HttpRequestMessage(HttpMethod.Post, SendGridUrl);
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", s.MailApiKey);
        req.Content = JsonContent.Create(new
        {
            personalizations = new[] { new { to = recipients.Select(r => new { email = r }).ToArray() } },
            from = new { email = s.SmtpFrom, name = "VulnVerdict" },
            subject,
            content = new[] { new { type = "text/plain", value = text }, new { type = "text/html", value = html } },
            headers = headers.ToDictionary(h => h.Name, h => h.Value)
        });
        using var resp = await client.SendAsync(req, ct);
        if (!resp.IsSuccessStatusCode)
            throw new InvalidOperationException("SendGrid returned " + (int)resp.StatusCode + ": " + Trim(await resp.Content.ReadAsStringAsync(ct)));
    }

    private async Task BrevoAsync(AppSettings s, List<string> recipients, string subject, string html, string text, List<(string Name, string Value)> headers, CancellationToken ct)
    {
        var client = _http.CreateClient("mail");
        using var req = new HttpRequestMessage(HttpMethod.Post, BrevoUrl);
        req.Headers.Add("api-key", s.MailApiKey);
        req.Content = JsonContent.Create(new
        {
            sender = new { email = s.SmtpFrom, name = "VulnVerdict" },
            to = recipients.Select(r => new { email = r }).ToArray(),
            subject,
            htmlContent = html,
            textContent = text,
            headers = headers.ToDictionary(h => h.Name, h => h.Value)
        });
        using var resp = await client.SendAsync(req, ct);
        if (!resp.IsSuccessStatusCode)
            throw new InvalidOperationException("Brevo returned " + (int)resp.StatusCode + ": " + Trim(await resp.Content.ReadAsStringAsync(ct)));
    }

    /// <summary>
    /// Microsoft Graph sendMail with the whole MIME message (base64, text/plain), so the text alternative and the
    /// correlation headers arrive exactly as over SMTP. Sent from the From mailbox, not saved to its Sent Items.
    /// </summary>
    private async Task GraphAsync(AppSettings s, List<string> recipients, string subject, string html, string text, List<(string Name, string Value)> headers, CancellationToken ct)
    {
        var client = _http.CreateClient("mail");
        var msg = BuildMime(s.SmtpFrom, recipients, subject, html, text, headers);
        using var ms = new MemoryStream();
        await msg.WriteToAsync(ms, ct);
        var mime = Convert.ToBase64String(ms.ToArray());
        var url = string.Format(GraphSendMail, Uri.EscapeDataString(s.SmtpFrom.Trim()));
        for (var attempt = 0; ; attempt++)
        {
            var token = await GraphTokenAsync(client, s, attempt > 0, ct);
            using var req = new HttpRequestMessage(HttpMethod.Post, url) { Content = new StringContent(mime, Encoding.ASCII, "text/plain") };
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var resp = await client.SendAsync(req, ct);
            if (resp.IsSuccessStatusCode) return;
            if (resp.StatusCode == HttpStatusCode.Unauthorized && attempt == 0) continue;   // a revoked or expired token: one fresh try
            var body = await resp.Content.ReadAsStringAsync(ct);
            throw new InvalidOperationException("Microsoft 365 returned " + (int)resp.StatusCode + ": " + GraphHint(resp.StatusCode, body, s.SmtpFrom) + " (" + Trim(body) + ")");
        }
    }

    private static async Task<string> GraphTokenAsync(HttpClient client, AppSettings s, bool refresh, CancellationToken ct)
    {
        var key = s.M365TenantId.Trim() + "|" + s.M365ClientId.Trim() + "|" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s.M365ClientSecret)));
        if (!refresh && GraphTokens.TryGetValue(key, out var cached) && cached.ExpiresAt > DateTime.UtcNow) return cached.AccessToken;
        try
        {
            var token = await OAuthTokens.RequestAsync(client, GraphLogin + Uri.EscapeDataString(s.M365TenantId.Trim()) + "/oauth2/v2.0/token",
                OAuthTokens.Form(("grant_type", "client_credentials"), ("client_id", s.M365ClientId.Trim()), ("client_secret", s.M365ClientSecret), ("scope", "https://graph.microsoft.com/.default")),
                ct, what: "Microsoft 365 sign-in");
            GraphTokens[key] = token;
            return token.AccessToken;
        }
        catch (EndpointApiException ex)
        {
            throw new InvalidOperationException(ex.Message + ". Check the tenant ID, the application (client) ID and that the client secret has not expired.");
        }
    }

    /// <summary>The usual setup mistakes, in words.</summary>
    public static string GraphHint(HttpStatusCode status, string body, string from) => status switch
    {
        HttpStatusCode.Forbidden => "the app registration may not send as " + from + ": it needs the Mail.Send application permission with admin consent, or an Exchange role assignment that covers this mailbox",
        HttpStatusCode.NotFound => from + " is not a mailbox in this tenant; use a user or shared mailbox address",
        HttpStatusCode.BadRequest when body.Contains("ErrorInvalidUser", StringComparison.OrdinalIgnoreCase) => from + " is not a mailbox in this tenant; use a user or shared mailbox address",
        HttpStatusCode.Unauthorized => "Microsoft 365 did not accept the token for this app registration",
        _ => "sending failed",
    };

    private static string Trim(string s) => s.Length > 300 ? s[..300] : s;
}
