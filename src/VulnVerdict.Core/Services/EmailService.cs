using System.Net.Http.Headers;
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
/// Outbound mail. Three transports: SMTP (MailKit), SendGrid v3 API and Brevo v3 API, chosen in Settings.
/// Every message has an HTML body and a text alternative; custom headers carry ticket correlation keys.
/// </summary>
public sealed class EmailService
{
    public const string SendGridUrl = "https://api.sendgrid.com/v3/mail/send";
    public const string BrevoUrl = "https://api.brevo.com/v3/smtp/email";

    private readonly SettingsService _settings;
    private readonly IHttpClientFactory _http;
    private readonly ILogger<EmailService> _log;

    public EmailService(SettingsService settings, IHttpClientFactory http, ILogger<EmailService> log)
    {
        _settings = settings; _http = http; _log = log;
    }

    public async Task SendAsync(IEnumerable<string> to, string subject, string html, string text, CancellationToken ct = default, IEnumerable<(string Name, string Value)>? headers = null)
    {
        var s = await _settings.LoadAsync(ct);
        if (!s.MailConfigured) throw new EmailNotConfiguredException(s.MailTransport == "smtp" ? "SMTP host and from address are required." : "API key and from address are required for " + s.MailTransport + ".");
        var recipients = to.Where(t => !string.IsNullOrWhiteSpace(t)).Distinct().ToList();
        if (recipients.Count == 0) throw new InvalidOperationException("No recipients");
        var hdrs = headers?.ToList() ?? new();

        switch (s.MailTransport.ToLowerInvariant())
        {
            case "sendgrid": await SendGridAsync(s, recipients, subject, html, text, hdrs, ct); break;
            case "brevo": await BrevoAsync(s, recipients, subject, html, text, hdrs, ct); break;
            default: await SmtpAsync(s, recipients, subject, html, text, hdrs, ct); break;
        }
        _log.LogInformation("Sent mail '{Subject}' to {Count} recipient(s) via {Transport}", subject, recipients.Count, s.MailTransport);
    }

    private static async Task SmtpAsync(AppSettings s, List<string> recipients, string subject, string html, string text, List<(string Name, string Value)> headers, CancellationToken ct)
    {
        var msg = new MimeMessage();
        msg.From.Add(MailboxAddress.Parse(s.SmtpFrom));
        foreach (var r in recipients) msg.To.Add(MailboxAddress.Parse(r));
        msg.Subject = subject;
        foreach (var (n, v) in headers) msg.Headers.Add(n, v);
        msg.Body = new BodyBuilder { HtmlBody = html, TextBody = text }.ToMessageBody();

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

    private static string Trim(string s) => s.Length > 300 ? s[..300] : s;
}
