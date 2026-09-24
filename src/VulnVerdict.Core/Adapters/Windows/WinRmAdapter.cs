using System.Text.Json;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Windows;

/// <summary>One host line from the connector form: what was typed, the host part and an optional port.</summary>
public sealed record HostTarget(string AsTyped, string Host, int? Port);

/// <summary>Connector settings other than the host list, parsed once per run.</summary>
public sealed record WinRmSettings(string Username, string Password, string Transport, string Authentication, bool VerifyTls, TimeSpan Timeout)
{
    public bool IsSsh => Transport == "ssh";
    public bool UseTls => Transport == "winrm-https";
    public bool BasicAuth => Authentication == "basic";

    public static WinRmSettings From(IReadOnlyDictionary<string, string> c)
    {
        var transport = (c.GetValueOrDefault("transport") ?? "").Trim().ToLowerInvariant();
        if (transport is "" or "https" or "winrm") transport = "winrm-https";
        else if (transport is "http") transport = "winrm-http";
        if (transport is not ("winrm-https" or "winrm-http" or "ssh")) throw new ArgumentException("Transport must be winrm-https, winrm-http or ssh (got '" + transport + "').");
        var auth = (c.GetValueOrDefault("authentication") ?? "").Trim().ToLowerInvariant();
        if (auth is "" or "ntlm" or "kerberos") auth = "negotiate";
        if (auth is not ("basic" or "negotiate")) throw new ArgumentException("Authentication must be basic or negotiate (got '" + auth + "').");
        var verify = ParseBool(c.GetValueOrDefault("verifyTls"), true);
        var timeout = int.TryParse(c.GetValueOrDefault("timeoutSeconds"), out var t) && t > 0 ? t : 120;
        return new WinRmSettings((c.GetValueOrDefault("username") ?? "").Trim(), c.GetValueOrDefault("password") ?? "", transport, auth, verify, TimeSpan.FromSeconds(timeout));
    }

    private static bool ParseBool(string? s, bool dflt) => string.IsNullOrWhiteSpace(s) ? dflt : s.Trim().ToLowerInvariant() is "true" or "1" or "yes" or "on";
}

/// <summary>
/// Section 9.2 step 3 and 5: Windows servers (and Hyper-V hosts) over WinRM, or OpenSSH where that is what the estate
/// has. One PowerShell collector per host; roles, features and listeners decide reachability, which is why this adds
/// value even where an endpoint agent already lists software. Read-only, never writes to the host, never logs credentials.
/// </summary>
public sealed class WinRmAdapter : IInventoryAdapter
{
    private readonly ILogger<WinRmAdapter> _log;

    public WinRmAdapter(ILogger<WinRmAdapter> log)
    {
        _log = log;
        ShellFactory = DefaultShell;
    }

    /// <summary>How a host is reached. Replaceable so tests can feed a canned collector document without a network.</summary>
    public Func<HostTarget, WinRmSettings, IWindowsShell> ShellFactory { get; set; }

    public AdapterMetadata Metadata { get; } = new(
        Id: "winrm",
        DisplayName: "Windows servers (WinRM)",
        Vendor: "Microsoft",
        Description: "Runs one read-only PowerShell collector on each Windows host over WinRM (or OpenSSH): OS build and hotfixes, installed software from both Uninstall hives, roles and features (SMBv1, WebDAV, Print Spooler, RDP, IIS), listening ports with owning processes, IIS sites and bindings, SQL Server instances and patch level, .NET runtimes, SDKs and Framework. On a Hyper-V host the VM list becomes the coverage reconciliation set.",
        Kinds: new[] { AssetKind.Server, AssetKind.Hypervisor, AssetKind.VirtualMachine, AssetKind.Endpoint },
        Form: new[]
        {
            new CredentialField("hosts", "Hosts", CredentialTypes.TextArea, "One hostname or IP address per line, optionally with :port. Default ports: 5986 for winrm-https, 5985 for winrm-http, 22 for ssh."),
            new CredentialField("username", "Username", CredentialTypes.Text, "DOMAIN\\svc-vulnverdict, user@domain.local, or .\\localuser for a local account."),
            new CredentialField("password", "Password", CredentialTypes.Password),
            new CredentialField("transport", "Transport", CredentialTypes.Text, "winrm-https (default) | winrm-http | ssh. winrm-http only works when the listener has AllowUnencrypted set; keep it for lab use.", Required: false, Default: "winrm-https"),
            new CredentialField("authentication", "Authentication", CredentialTypes.Text, "negotiate (default; NTLM or Kerberos) | basic (only over winrm-https; needs Basic enabled on the listener and a local account).", Required: false, Default: "negotiate"),
            new CredentialField("verifyTls", "Verify TLS certificate", CredentialTypes.Bool, "Turn off only for self-signed WinRM listeners; the connection is still encrypted but not authenticated.", Required: false, Default: "true"),
            new CredentialField("timeoutSeconds", "Timeout per host (seconds)", CredentialTypes.Number, "The collector normally finishes in 5 to 30 seconds; Get-WindowsFeature on a busy server can take longer.", Required: false, Default: "120"),
        },
        MinimumPermission: "Local Administrators is NOT needed: a member of the 'Remote Management Users' group plus read access to the registry Uninstall keys and WMI (Get-HotFix needs local admin on some builds; if it fails the collector continues without hotfixes). Get-WindowsFeature, Get-SmbServerConfiguration and Hyper-V's Get-VM may also need more than the default rights; each is optional. The account needs no write permission anywhere.",
        DocsUrl: "https://learn.microsoft.com/powershell/module/microsoft.powershell.core/enable-psremoting",
        DefaultIntervalMinutes: 240);

    // ------------------------------------------------------------------ hosts

    /// <summary>Parse the hosts textarea: one entry per line (commas and semicolons also separate), optional :port, IPv6 in brackets.</summary>
    public static List<HostTarget> ParseHosts(string? text)
    {
        var list = new List<HostTarget>();
        if (string.IsNullOrWhiteSpace(text)) return list;
        foreach (var raw in text.Split(new[] { '\n', '\r', ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#')) continue;
            string host = line; int? port = null;
            if (line.StartsWith('['))
            {
                var close = line.IndexOf(']');
                if (close > 0)
                {
                    host = line[1..close];
                    if (close + 1 < line.Length && line[close + 1] == ':' && int.TryParse(line[(close + 2)..], out var p6)) port = p6;
                }
            }
            else
            {
                var colon = line.LastIndexOf(':');
                if (colon > 0 && line.IndexOf(':') == colon && int.TryParse(line[(colon + 1)..], out var p)) { host = line[..colon]; port = p; }
            }
            if (port is < 1 or > 65535) port = null;
            list.Add(new HostTarget(line, host, port));
        }
        return list;
    }

    private IWindowsShell DefaultShell(HostTarget target, WinRmSettings s)
    {
        if (s.IsSsh) return new WindowsSshShell(target.Host, target.Port ?? 22, s.Username, s.Password, s.Timeout, _log);
        return new WsManClient(new WsManOptions
        {
            Host = target.Host, Port = target.Port, UseTls = s.UseTls, VerifyTls = s.VerifyTls,
            Username = s.Username, Password = s.Password, BasicAuth = s.BasicAuth, Timeout = s.Timeout,
        }, _log);
    }

    // ------------------------------------------------------------------ contract

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            var settings = WinRmSettings.From(credentials);
            var hosts = ParseHosts(credentials.GetValueOrDefault("hosts"));
            if (hosts.Count == 0) return new TestResult(false, "Enter at least one host.");
            if (settings.Username.Length == 0) return new TestResult(false, "Enter a username.");
            var target = hosts[0];
            using var shell = ShellFactory(target, settings);
            var r = await shell.RunPowerShellAsync("$ProgressPreference='SilentlyContinue'; [Console]::Out.Write($PSVersionTable.PSVersion.ToString())", ct);
            var version = r.Stdout.Trim();
            if (r.ExitCode != 0 || version.Length == 0)
                return new TestResult(false, "Connected to " + shell.Target + " but PowerShell did not answer (exit " + r.ExitCode + "). " + Trim(r.Stderr, 300));
            return new TestResult(true, "Connected to " + shell.Target + ": PowerShell " + version + (hosts.Count > 1 ? " (" + (hosts.Count - 1) + " more host(s) not tested)" : ""));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            return new TestResult(false, ex.Message);
        }
    }

    public async Task<CollectResult> CollectAsync(IReadOnlyDictionary<string, string> credentials, DateTime? since, IProgress<string>? progress, CancellationToken ct)
    {
        var result = new CollectResult { FullSnapshot = true };
        var settings = WinRmSettings.From(credentials);
        var hosts = ParseHosts(credentials.GetValueOrDefault("hosts"));
        if (hosts.Count == 0) { result.Warnings.Add("No hosts configured."); return result; }

        var n = 0;
        foreach (var target in hosts)
        {
            ct.ThrowIfCancellationRequested();
            n++;
            progress?.Report("Collecting " + target.AsTyped + " (" + n + "/" + hosts.Count + ")");
            try
            {
                using var shell = ShellFactory(target, settings);
                var r = await shell.RunPowerShellAsync(WindowsCollectorScript.Compact, ct);
                var json = ExtractJson(r.Stdout) ?? throw new InvalidOperationException("The collector printed no JSON (exit " + r.ExitCode + "). " + Trim(r.Stderr, 400));
                using var doc = JsonDocument.Parse(json);
                var asset = WindowsCollectorMapper.Map(target.AsTyped, doc.RootElement, result);
                if (r.Stderr.Length > 0) _log.LogDebug("Collector stderr from {Host}: {Stderr}", target.AsTyped, Trim(r.Stderr, 1000));
                _log.LogInformation("WinRM collected {Host}: {Os} {Build}", target.AsTyped, asset.OsProduct, asset.OsBuild);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                _log.LogWarning("WinRM collection of {Host} failed: {Message}", target.AsTyped, ex.Message);
                result.Warnings.Add(target.AsTyped + ": " + ex.Message);
            }
        }
        return result;
    }

    /// <summary>The collector prints one JSON object; anything before it (a stray banner) is skipped.</summary>
    public static string? ExtractJson(string stdout)
    {
        if (string.IsNullOrWhiteSpace(stdout)) return null;
        var start = stdout.IndexOf('{');
        var end = stdout.LastIndexOf('}');
        return start >= 0 && end > start ? stdout[start..(end + 1)] : null;
    }

    private static string Trim(string s, int max) => s.Length <= max ? s : s[..max] + "...";
}
