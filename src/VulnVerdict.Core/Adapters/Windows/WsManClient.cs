using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;

namespace VulnVerdict.Core.Adapters.Windows;

/// <summary>What one remote PowerShell run produced.</summary>
public sealed record ShellResult(string Stdout, string Stderr, int ExitCode);

/// <summary>A way to run a PowerShell script on one Windows host and get its output back (WinRM or SSH).</summary>
public interface IWindowsShell : IDisposable
{
    /// <summary>Human-readable target, for warnings. Never contains credentials.</summary>
    string Target { get; }
    Task<ShellResult> RunPowerShellAsync(string script, CancellationToken ct);
}

public sealed class WsManOptions
{
    public required string Host { get; init; }
    /// <summary>Null means 5986 for HTTPS and 5985 for HTTP.</summary>
    public int? Port { get; init; }
    public bool UseTls { get; init; } = true;
    public bool VerifyTls { get; init; } = true;
    public required string Username { get; init; }
    public required string Password { get; init; }
    /// <summary>False (default) uses Negotiate/NTLM through the HttpClientHandler credential cache; true sends HTTP Basic, which is only allowed over TLS.</summary>
    public bool BasicAuth { get; init; }
    /// <summary>Overall budget for one script run, including shell set-up and tear-down.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(120);
    public int EffectivePort => Port ?? (UseTls ? 5986 : 5985);
}

/// <summary>A WS-Management fault returned by the remote WinRM service.</summary>
public sealed class WsManFaultException : Exception
{
    public string? Code { get; }
    public string? Subcode { get; }
    /// <summary>wsman:TimedOut (WSManFault 2150858793): the operation is still running and the client should call Receive again.</summary>
    public bool IsTimeout => Code == "2150858793" || (Subcode is not null && Subcode.EndsWith("TimedOut", StringComparison.Ordinal));

    public WsManFaultException(string message, string? code, string? subcode) : base(message) { Code = code; Subcode = subcode; }
}

/// <summary>Builds the SOAP envelopes for the WinRM shell (winrs) protocol. Pure functions, so they can be unit tested.</summary>
public static class WsManEnvelopes
{
    public static readonly XNamespace S = "http://www.w3.org/2003/05/soap-envelope";
    public static readonly XNamespace A = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
    public static readonly XNamespace W = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd";
    public static readonly XNamespace P = "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd";
    public static readonly XNamespace Rsp = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell";
    public static readonly XNamespace F = "http://schemas.microsoft.com/wbem/wsman/1/wsmanfault";

    public const string ShellResourceUri = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";
    public const string AnonymousAddress = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous";
    public const string ActionCreate = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create";
    public const string ActionDelete = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete";
    public const string ActionCommand = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command";
    public const string ActionReceive = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive";
    public const string ActionSignal = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal";
    public const string SignalTerminate = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate";
    public const string CommandStateDone = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done";
    public const int MaxEnvelopeSize = 153600;
    public const string OperationTimeout = "PT60S";

    /// <summary>WS-Transfer Create of a winrs shell with stdin/stdout/stderr streams, no profile, UTF-8 code page.</summary>
    public static string CreateShell(string endpoint)
    {
        var header = Header(endpoint, ActionCreate, null, new Dictionary<string, string> { ["WINRS_NOPROFILE"] = "TRUE", ["WINRS_CODEPAGE"] = "65001" });
        var body = new XElement(S + "Body",
            new XElement(Rsp + "Shell",
                new XElement(Rsp + "InputStreams", "stdin"),
                new XElement(Rsp + "OutputStreams", "stdout stderr")));
        return Wrap(header, body);
    }

    /// <summary>Start a command in the shell. WINRS_SKIP_CMD_SHELL runs it directly (no cmd.exe, so no 8191-character limit).</summary>
    public static string Command(string endpoint, string shellId, string command, IEnumerable<string> arguments)
    {
        var header = Header(endpoint, ActionCommand, shellId, new Dictionary<string, string> { ["WINRS_CONSOLEMODE_STDIN"] = "TRUE", ["WINRS_SKIP_CMD_SHELL"] = "TRUE" });
        var line = new XElement(Rsp + "CommandLine", new XElement(Rsp + "Command", command));
        foreach (var a in arguments) line.Add(new XElement(Rsp + "Arguments", a));
        return Wrap(header, new XElement(S + "Body", line));
    }

    public static string Receive(string endpoint, string shellId, string commandId)
    {
        var header = Header(endpoint, ActionReceive, shellId, null);
        var body = new XElement(S + "Body",
            new XElement(Rsp + "Receive",
                new XElement(Rsp + "DesiredStream", new XAttribute("CommandId", commandId), "stdout stderr")));
        return Wrap(header, body);
    }

    public static string Signal(string endpoint, string shellId, string commandId, string signal = SignalTerminate)
    {
        var header = Header(endpoint, ActionSignal, shellId, null);
        var body = new XElement(S + "Body",
            new XElement(Rsp + "Signal", new XAttribute("CommandId", commandId), new XElement(Rsp + "Code", signal)));
        return Wrap(header, body);
    }

    public static string DeleteShell(string endpoint, string shellId) => Wrap(Header(endpoint, ActionDelete, shellId, null), new XElement(S + "Body"));

    private static XElement Header(string endpoint, string action, string? shellId, IDictionary<string, string>? options)
    {
        var h = new XElement(S + "Header",
            new XElement(A + "To", endpoint),
            new XElement(W + "ResourceURI", new XAttribute(S + "mustUnderstand", "true"), ShellResourceUri),
            new XElement(A + "ReplyTo", new XElement(A + "Address", new XAttribute(S + "mustUnderstand", "true"), AnonymousAddress)),
            new XElement(A + "Action", new XAttribute(S + "mustUnderstand", "true"), action),
            new XElement(W + "MaxEnvelopeSize", new XAttribute(S + "mustUnderstand", "true"), MaxEnvelopeSize),
            new XElement(A + "MessageID", "uuid:" + Guid.NewGuid().ToString("D").ToUpperInvariant()),
            new XElement(W + "Locale", new XAttribute(XNamespace.Xml + "lang", "en-US"), new XAttribute(S + "mustUnderstand", "false")),
            new XElement(P + "DataLocale", new XAttribute(XNamespace.Xml + "lang", "en-US"), new XAttribute(S + "mustUnderstand", "false")),
            new XElement(W + "OperationTimeout", OperationTimeout));
        if (shellId is not null)
            h.Add(new XElement(W + "SelectorSet", new XElement(W + "Selector", new XAttribute("Name", "ShellId"), shellId)));
        if (options is { Count: > 0 })
            h.Add(new XElement(W + "OptionSet", options.Select(o => new XElement(W + "Option", new XAttribute("Name", o.Key), o.Value))));
        return h;
    }

    private static string Wrap(XElement header, XElement body)
    {
        var env = new XElement(S + "Envelope",
            new XAttribute(XNamespace.Xmlns + "s", S),
            new XAttribute(XNamespace.Xmlns + "a", A),
            new XAttribute(XNamespace.Xmlns + "w", W),
            new XAttribute(XNamespace.Xmlns + "p", P),
            new XAttribute(XNamespace.Xmlns + "rsp", Rsp),
            header, body);
        return env.ToString(SaveOptions.DisableFormatting);
    }
}

/// <summary>
/// A minimal WS-Management client for the WinRM shell service over HTTP(S), enough to run one PowerShell command and
/// collect its output: Create shell, Command, Receive until Done, Signal terminate, Delete shell. Authentication is
/// Negotiate/NTLM through the handler's credential cache (works in managed code on Linux too) or Basic over TLS.
/// Credentials are never logged; the endpoint and shell ids are.
/// </summary>
public sealed class WsManClient : IWindowsShell
{
    private readonly WsManOptions _o;
    private readonly HttpClient _http;
    private readonly ILogger? _log;

    public string Endpoint { get; }
    public string Target => _o.Host + ":" + _o.EffectivePort + (_o.UseTls ? " (winrm-https)" : " (winrm-http)");

    public WsManClient(WsManOptions options, ILogger? log = null)
    {
        if (options.BasicAuth && !options.UseTls)
            throw new ArgumentException("Basic authentication is only allowed over HTTPS: over plain HTTP the password would travel in clear text. Use winrm-https, or negotiate.");
        _o = options; _log = log;
        var handler = new HttpClientHandler { UseDefaultCredentials = false, PreAuthenticate = true, AllowAutoRedirect = false, UseCookies = false };
        if (!options.VerifyTls) handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        if (!options.BasicAuth) handler.Credentials = ToNetworkCredential(options.Username, options.Password);
        // per request; the OperationTimeout (60 s) makes the server answer before this fires
        _http = new HttpClient(handler, disposeHandler: true) { Timeout = TimeSpan.FromSeconds(90) };
        _http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("VulnVerdict", "0.2"));
        if (options.BasicAuth)
            _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(options.Username + ":" + options.Password)));
        var host = options.Host.Contains(':') && !options.Host.StartsWith('[') ? "[" + options.Host + "]" : options.Host;
        Endpoint = (options.UseTls ? "https" : "http") + "://" + host + ":" + options.EffectivePort + "/wsman";
    }

    /// <summary>"DOMAIN\user" and ".\user" become domain + user; "user@domain" (UPN) is passed through as the user name.</summary>
    public static NetworkCredential ToNetworkCredential(string username, string password)
    {
        var slash = username.IndexOf('\\');
        return slash > 0 ? new NetworkCredential(username[(slash + 1)..], password, username[..slash]) : new NetworkCredential(username, password);
    }

    public async Task<ShellResult> RunPowerShellAsync(string script, CancellationToken ct)
    {
        var args = new[] { "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-EncodedCommand", WindowsCollectorScript.Encode(script) };
        var lineLength = "powershell.exe".Length + args.Sum(a => a.Length + 1);
        if (lineLength > 32000)
            throw new InvalidOperationException("The PowerShell script is too long to run as one -EncodedCommand line (" + lineLength + " characters; the limit is 32767).");

        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(_o.Timeout);
        var tk = budget.Token;
        try
        {
            var shellId = await CreateShellAsync(tk);
            try
            {
                var commandId = await StartCommandAsync(shellId, "powershell.exe", args, tk);
                try { return await ReceiveUntilDoneAsync(shellId, commandId, tk); }
                finally { await CleanupAsync(WsManEnvelopes.Signal(Endpoint, shellId, commandId), "signal"); }
            }
            finally { await CleanupAsync(WsManEnvelopes.DeleteShell(Endpoint, shellId), "delete shell"); }
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException("No result from " + Target + " within " + _o.Timeout.TotalSeconds + " s.");
        }
    }

    public async Task<string> CreateShellAsync(CancellationToken ct)
    {
        var doc = await SendAsync(WsManEnvelopes.CreateShell(Endpoint), ct);
        var id = doc.Descendants(WsManEnvelopes.Rsp + "ShellId").FirstOrDefault()?.Value
              ?? doc.Descendants(WsManEnvelopes.W + "Selector").FirstOrDefault(s => s.Attribute("Name")?.Value == "ShellId")?.Value
              ?? throw new InvalidOperationException("WinRM did not return a ShellId for the Create request.");
        _log?.LogDebug("WinRM shell {ShellId} created on {Endpoint}", id, Endpoint);
        return id;
    }

    public async Task<string> StartCommandAsync(string shellId, string command, IEnumerable<string> arguments, CancellationToken ct)
    {
        var doc = await SendAsync(WsManEnvelopes.Command(Endpoint, shellId, command, arguments), ct);
        return doc.Descendants(WsManEnvelopes.Rsp + "CommandId").FirstOrDefault()?.Value
            ?? throw new InvalidOperationException("WinRM did not return a CommandId for the Command request.");
    }

    /// <summary>Receive loop: append each base64 stream chunk until CommandState is Done. A wsman:TimedOut fault just means "nothing yet", so keep going.</summary>
    public async Task<ShellResult> ReceiveUntilDoneAsync(string shellId, string commandId, CancellationToken ct)
    {
        var stdout = new MemoryStream(); var stderr = new MemoryStream();
        var exit = 0;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            XDocument doc;
            try { doc = await SendAsync(WsManEnvelopes.Receive(Endpoint, shellId, commandId), ct); }
            catch (WsManFaultException f) when (f.IsTimeout) { continue; }
            foreach (var stream in doc.Descendants(WsManEnvelopes.Rsp + "Stream"))
            {
                var text = stream.Value.Trim();
                if (text.Length == 0) continue;
                var bytes = Convert.FromBase64String(text);
                (stream.Attribute("Name")?.Value == "stderr" ? stderr : stdout).Write(bytes, 0, bytes.Length);
            }
            var state = doc.Descendants(WsManEnvelopes.Rsp + "CommandState").FirstOrDefault(s => s.Attribute("CommandId")?.Value == commandId)
                     ?? doc.Descendants(WsManEnvelopes.Rsp + "CommandState").FirstOrDefault();
            if (state?.Attribute("State")?.Value == WsManEnvelopes.CommandStateDone)
            {
                if (int.TryParse(state.Element(WsManEnvelopes.Rsp + "ExitCode")?.Value, out var e)) exit = e;
                break;
            }
        }
        return new ShellResult(DecodeUtf8(stdout), CleanStderr(DecodeUtf8(stderr)), exit);
    }

    private async Task CleanupAsync(string envelope, string what)
    {
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await SendAsync(envelope, cts.Token);
        }
        catch (Exception ex) { _log?.LogDebug(ex, "WinRM {What} on {Endpoint} failed (ignored)", what, Endpoint); }
    }

    private async Task<XDocument> SendAsync(string envelope, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, Endpoint) { Content = new StringContent(envelope, Encoding.UTF8) };
        req.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/soap+xml;charset=UTF-8");
        using var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseContentRead, ct);
        var body = await resp.Content.ReadAsStringAsync(ct);

        if (resp.StatusCode == HttpStatusCode.Unauthorized)
            throw new UnauthorizedAccessException("WinRM at " + Endpoint + " rejected the credentials (HTTP 401). Check the username and password and that " + (_o.BasicAuth ? "Basic" : "Negotiate")
                + " authentication is enabled on the listener (winrm get winrm/config/service/auth), and that the account is in Remote Management Users.");

        XDocument? doc = null;
        if (body.TrimStart().StartsWith('<'))
        {
            try { doc = XDocument.Parse(body); } catch (System.Xml.XmlException) { doc = null; }
        }
        var fault = doc?.Descendants(WsManEnvelopes.S + "Fault").FirstOrDefault();
        if (fault is not null) throw ParseFault(fault);
        if (!resp.IsSuccessStatusCode || doc is null)
            throw new HttpRequestException("WinRM at " + Endpoint + " answered HTTP " + (int)resp.StatusCode + " " + resp.ReasonPhrase + (doc is null ? " with a non-SOAP body (is this a WinRM listener?)" : "."));
        return doc;
    }

    private static WsManFaultException ParseFault(XElement fault)
    {
        var subcode = fault.Descendants(WsManEnvelopes.S + "Subcode").Descendants(WsManEnvelopes.S + "Value").FirstOrDefault()?.Value;
        var reason = fault.Descendants(WsManEnvelopes.S + "Reason").Descendants(WsManEnvelopes.S + "Text").FirstOrDefault()?.Value?.Trim();
        var wsmf = fault.Descendants(WsManEnvelopes.F + "WSManFault").FirstOrDefault();
        var code = wsmf?.Attribute("Code")?.Value;
        var message = wsmf?.Descendants(WsManEnvelopes.F + "Message").Select(m => m.Value.Trim()).FirstOrDefault(m => m.Length > 0) ?? reason ?? "WS-Management fault";
        if (message.Contains("nencrypted", StringComparison.Ordinal))
            message += " (Negotiate over plain HTTP needs message encryption that this client does not implement: use winrm-https, or set AllowUnencrypted on the listener for lab use only.)";
        return new WsManFaultException(message + (code is not null ? " [WSManFault " + code + "]" : "") + (subcode is not null ? " [" + subcode + "]" : ""), code, subcode);
    }

    private static string DecodeUtf8(MemoryStream ms)
    {
        var bytes = ms.ToArray();
        var s = Encoding.UTF8.GetString(bytes);
        return s.Length > 0 && s[0] == '﻿' ? s[1..] : s;
    }

    /// <summary>Windows PowerShell 5.1 writes stderr as CLIXML when not attached to a console; turn it back into text.</summary>
    public static string CleanStderr(string stderr)
    {
        if (!stderr.StartsWith("#< CLIXML", StringComparison.Ordinal)) return stderr;
        var sb = new StringBuilder();
        foreach (Match m in Regex.Matches(stderr, "<S S=\"Error\">(.*?)</S>", RegexOptions.Singleline))
            sb.Append(m.Groups[1].Value.Replace("_x000D__x000A_", "\n").Replace("_x000A_", "\n").Replace("&lt;", "<").Replace("&gt;", ">").Replace("&quot;", "\"").Replace("&amp;", "&"));
        return sb.ToString().Trim();
    }

    public void Dispose() => _http.Dispose();
}
