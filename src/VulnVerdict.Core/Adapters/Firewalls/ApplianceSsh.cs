using System.Text;
using System.Text.RegularExpressions;
using Renci.SshNet;
using Renci.SshNet.Common;
using VulnVerdict.Core.Adapters.Linux;

namespace VulnVerdict.Core.Adapters.Firewalls;

/// <summary>How commands reach the appliance: an exec channel per command (Unix shells), or one interactive shell
/// where each command is typed at the vendor CLI prompt (Zyxel ZLD, Check Point Gaia Embedded clish).</summary>
public enum SshMode { Exec, Shell }

/// <summary>
/// SSH for firewalls whose only practical read path is the CLI. Same host-key rules as the Linux adapter: a pinned
/// fingerprint must match, an unpinned key is accepted and reported so it can be pinned. Only the read-only
/// commands each adapter lists are ever sent.
/// </summary>
public static partial class ApplianceSsh
{
    public static CredentialField[] FormFields(string device, string accountHelp, int defaultPort = 22) => new[]
    {
        new CredentialField("host", device + " host", CredentialTypes.Text, "Management address, optionally host:port (SSH port " + defaultPort + " unless changed)."),
        new CredentialField("username", "Username", CredentialTypes.Text, accountHelp),
        new CredentialField("password", "Password", CredentialTypes.Password, "Leave empty when authenticating with a private key.", Required: false),
        new CredentialField("privateKey", "Private key (PEM)", CredentialTypes.TextArea, "OpenSSH or PEM private key, where the appliance supports key login. Leave empty for password login.", Required: false),
        new CredentialField("passphrase", "Key passphrase", CredentialTypes.Password, "Only when the private key is encrypted.", Required: false),
        new CredentialField("hostKey", "Host key fingerprint", CredentialTypes.Text, "SHA256:... as printed by Test connection. Once set, a changed key stops the connection instead of being accepted.", Required: false),
        new CredentialField("timeoutSeconds", "Timeout (seconds)", CredentialTypes.Number, "Per connection and per command.", Required: false, Default: "30"),
    };

    public static SshTarget Target(IReadOnlyDictionary<string, string> c, int defaultPort = 22)
    {
        var raw = FwCreds.Host(FwCreds.Get(c, "host"));
        if (raw.Length == 0) throw new InvalidOperationException("Host is required");
        var t = SshTarget.Parse(raw);
        return t.Port == 22 && defaultPort != 22 && !raw.Contains(':') ? t with { Port = defaultPort } : t;
    }

    public static SshConnectionOptions Options(IReadOnlyDictionary<string, string> c)
    {
        var user = FwCreds.Get(c, "username");
        if (user.Length == 0) throw new InvalidOperationException("Username is required");
        var pw = FwCreds.Secret(c, "password");
        var key = FwCreds.Get(c, "privateKey");
        if (pw.Length == 0 && key.Length == 0) throw new InvalidOperationException("Enter a password or a private key");
        var pin = FwCreds.Get(c, "hostKey");
        return new SshConnectionOptions(user, pw.Length > 0 ? pw : null, key.Length > 0 ? key : null,
            FwCreds.Secret(c, "passphrase") is { Length: > 0 } pp ? pp : null,
            TimeSpan.FromSeconds(Math.Clamp(FwCreds.Int(c, "timeoutSeconds", 30), 5, 300)),
            AcceptAnyHostKey: false, ExpectedFingerprint: pin.Length > 0 ? pin : null);
    }

    /// <summary>Warning text when the host key is not pinned yet (null when it is, or unknown).</summary>
    public static string? PinWarning(IReadOnlyDictionary<string, string> c, ISshSession s) =>
        FwCreds.Get(c, "hostKey").Length == 0 && s.HostKeyFingerprint is { Length: > 0 } fp
            ? "Host key " + SshLinuxAdapter.FormatFingerprint(fp) + " is not pinned; paste it into Host key fingerprint so a changed key is detected."
            : null;

    /// <summary>Opens a session. Exec mode runs each command on its own channel; shell mode types it at the CLI prompt.</summary>
    public static async Task<ISshSession> ConnectAsync(SshTarget t, SshConnectionOptions o, SshMode mode, CancellationToken ct)
    {
        var methods = new List<AuthenticationMethod>();
        if (!string.IsNullOrEmpty(o.PrivateKeyPem))
        {
            var stream = new MemoryStream(Encoding.UTF8.GetBytes(o.PrivateKeyPem.Trim() + "\n"));
            var keyFile = string.IsNullOrEmpty(o.Passphrase) ? new PrivateKeyFile(stream) : new PrivateKeyFile(stream, o.Passphrase);
            methods.Add(new PrivateKeyAuthenticationMethod(o.Username, keyFile));
        }
        if (!string.IsNullOrEmpty(o.Password))
        {
            methods.Add(new PasswordAuthenticationMethod(o.Username, o.Password));
            // several appliance CLIs only offer keyboard-interactive; answer every prompt with the password
            var kbd = new KeyboardInteractiveAuthenticationMethod(o.Username);
            kbd.AuthenticationPrompt += (_, e) => { foreach (var p in e.Prompts) p.Response = o.Password; };
            methods.Add(kbd);
        }
        var info = new ConnectionInfo(t.Host, t.Port, o.Username, methods.ToArray()) { Timeout = o.Timeout };
        var client = new SshClient(info);
        string? presented = null; string? rejected = null;
        client.HostKeyReceived += (_, e) =>
        {
            presented = e.FingerPrintSHA256;
            if (o.AcceptAnyHostKey || o.ExpectedFingerprint is null) { e.CanTrust = true; return; }
            if (SshLinuxAdapter.FingerprintEquals(o.ExpectedFingerprint, presented)) e.CanTrust = true;
            else { rejected = presented; e.CanTrust = false; }
        };
        try
        {
            await client.ConnectAsync(ct);
        }
        catch (SshConnectionException ex) when (rejected is not null)
        {
            client.Dispose();
            throw new InvalidOperationException("Host key for " + t.AsTyped + " has changed: expected " + SshLinuxAdapter.FormatFingerprint(o.ExpectedFingerprint!) + ", received " + SshLinuxAdapter.FormatFingerprint(rejected) + ". Verify the appliance before updating the pinned key.", ex);
        }
        catch
        {
            client.Dispose();
            throw;
        }
        if (mode == SshMode.Exec) return new ExecSession(client, presented, o.Timeout);
        try { return await ShellSession.OpenAsync(client, presented, o.Timeout, ct); }
        catch { client.Dispose(); throw; }
    }

    private sealed class ExecSession : ISshSession
    {
        private readonly SshClient _client; private readonly TimeSpan _timeout;
        public ExecSession(SshClient client, string? fp, TimeSpan timeout) { _client = client; HostKeyFingerprint = fp; _timeout = timeout; }
        public string? HostKeyFingerprint { get; }

        public async Task<SshCommandResult> RunAsync(string command, CancellationToken ct)
        {
            using var cmd = _client.CreateCommand(command);
            cmd.CommandTimeout = _timeout;
            await cmd.ExecuteAsync(ct);
            return new SshCommandResult(cmd.ExitStatus ?? -1, cmd.Result ?? "", cmd.Error ?? "");
        }

        public void Dispose()
        {
            try { if (_client.IsConnected) _client.Disconnect(); } catch { /* best effort */ }
            _client.Dispose();
        }
    }

    [GeneratedRegex(@"\x1B\[[0-9;?]*[A-Za-z]|\x1B[()][A-Za-z0-9]|\r")] private static partial Regex AnsiRx();
    [GeneratedRegex(@"(?:^|\n)[^\n]{0,80}[>#$%]\s*$")] private static partial Regex PromptRx();
    [GeneratedRegex(@"-{1,3}\s*[Mm]ore\s*-{1,3}|\(more\)|Press any key", RegexOptions.IgnoreCase)] private static partial Regex MoreRx();

    /// <summary>Removes terminal escape sequences and carriage returns from CLI output.</summary>
    public static string CleanTerminal(string s) => AnsiRx().Replace(s, "");

    /// <summary>Strips the echoed command line and the trailing prompt from what a CLI printed for one command.</summary>
    public static string StripEchoAndPrompt(string raw, string command)
    {
        var lines = CleanTerminal(raw).Split('\n').ToList();
        var echo = lines.FindIndex(l => l.TrimEnd().EndsWith(command, StringComparison.Ordinal));
        if (echo >= 0 && echo < 3) lines.RemoveRange(0, echo + 1);
        if (lines.Count > 0 && PromptRx().IsMatch("\n" + lines[^1])) lines.RemoveAt(lines.Count - 1);
        return string.Join("\n", lines.Select(l => MoreRx().Replace(l, "").TrimEnd())).Trim('\n');
    }

    private sealed class ShellSession : ISshSession
    {
        private readonly SshClient _client; private readonly ShellStream _stream; private readonly TimeSpan _timeout;
        private ShellSession(SshClient client, ShellStream stream, string? fp, TimeSpan timeout) { _client = client; _stream = stream; HostKeyFingerprint = fp; _timeout = timeout; }
        public string? HostKeyFingerprint { get; }

        public static async Task<ShellSession> OpenAsync(SshClient client, string? fp, TimeSpan timeout, CancellationToken ct)
        {
            var stream = client.CreateShellStream("vt100", 250, 60, 1600, 1200, 1 << 16);
            var s = new ShellSession(client, stream, fp, timeout);
            await s.ReadUntilPromptAsync(ct); // banner and first prompt
            return s;
        }

        public async Task<SshCommandResult> RunAsync(string command, CancellationToken ct)
        {
            _stream.WriteLine(command);
            _stream.Flush();
            var raw = await ReadUntilPromptAsync(ct);
            return new SshCommandResult(0, StripEchoAndPrompt(raw, command), "");
        }

        private async Task<string> ReadUntilPromptAsync(CancellationToken ct)
        {
            var sb = new StringBuilder();
            var deadline = DateTime.UtcNow + _timeout;
            var quietSince = DateTime.UtcNow;
            while (DateTime.UtcNow < deadline)
            {
                ct.ThrowIfCancellationRequested();
                var chunk = _stream.Read();
                if (chunk.Length > 0)
                {
                    sb.Append(chunk);
                    quietSince = DateTime.UtcNow;
                    var tail = CleanTerminal(sb.ToString());
                    if (MoreRx().IsMatch(tail[Math.Max(0, tail.Length - 40)..])) { _stream.Write(" "); _stream.Flush(); continue; }
                }
                else
                {
                    var text = CleanTerminal(sb.ToString());
                    // a prompt at the end of the buffer, and nothing more for a moment: the command has finished
                    if (text.Length > 0 && PromptRx().IsMatch(text) && DateTime.UtcNow - quietSince > TimeSpan.FromMilliseconds(300)) return sb.ToString();
                    await Task.Delay(50, ct);
                }
            }
            throw new TimeoutException("No CLI prompt within " + _timeout.TotalSeconds + " s.");
        }

        public void Dispose()
        {
            try { _stream.WriteLine("exit"); } catch { /* best effort */ }
            try { _stream.Dispose(); } catch { /* best effort */ }
            try { if (_client.IsConnected) _client.Disconnect(); } catch { /* best effort */ }
            _client.Dispose();
        }
    }
}
