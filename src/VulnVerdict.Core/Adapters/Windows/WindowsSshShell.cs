using System.Text;
using Microsoft.Extensions.Logging;
using Renci.SshNet;

namespace VulnVerdict.Core.Adapters.Windows;

/// <summary>
/// Runs the collector on a Windows host that has OpenSSH Server (Windows 2019+ optional feature) instead of WinRM.
/// Windows sshd hands the command to cmd.exe unless DefaultShell is changed, so the 8191-character command-line
/// limit applies: short scripts go as -EncodedCommand, longer ones are piped to "powershell.exe -Command -" on stdin.
/// </summary>
public sealed class WindowsSshShell : IWindowsShell
{
    private const int CmdLineLimit = 8000;
    private readonly string _host; private readonly int _port; private readonly string _user; private readonly string _password;
    private readonly TimeSpan _timeout; private readonly ILogger? _log;

    public WindowsSshShell(string host, int port, string username, string password, TimeSpan timeout, ILogger? log = null)
    {
        _host = host; _port = port; _user = username; _password = password; _timeout = timeout; _log = log;
    }

    public string Target => _host + ":" + _port + " (ssh)";

    public async Task<ShellResult> RunPowerShellAsync(string script, CancellationToken ct)
    {
        var info = new ConnectionInfo(_host, _port, _user, new PasswordAuthenticationMethod(_user, _password)) { Timeout = TimeSpan.FromSeconds(30), Encoding = Encoding.UTF8 };
        using var client = new SshClient(info);
        client.HostKeyReceived += (_, e) =>
        {
            // no host-key store yet: accept and record the fingerprint so an operator can compare it (this is not a credential)
            _log?.LogInformation("SSH host key for {Host}: {Alg} SHA256:{Fp}", _host, e.HostKeyName, e.FingerPrintSHA256);
            e.CanTrust = true;
        };
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(_timeout);
        try
        {
            await client.ConnectAsync(budget.Token);
            var encoded = WindowsCollectorScript.Encode(script);
            var prefix = "powershell.exe -NoProfile -NonInteractive -OutputFormat Text ";
            var viaStdin = prefix.Length + "-EncodedCommand ".Length + encoded.Length > CmdLineLimit;
            using var cmd = client.CreateCommand(viaStdin ? prefix + "-Command -" : prefix + "-EncodedCommand " + encoded);
            cmd.CommandTimeout = _timeout;
            if (viaStdin)
            {
                var stdin = cmd.CreateInputStream();
                var run = cmd.ExecuteAsync(budget.Token);
                var bytes = Encoding.UTF8.GetBytes(script + "\n");
                await stdin.WriteAsync(bytes, budget.Token);
                await stdin.FlushAsync(budget.Token);
                stdin.Close();
                await run;
            }
            else await cmd.ExecuteAsync(budget.Token);
            return new ShellResult(cmd.Result, WsManClient.CleanStderr(cmd.Error), cmd.ExitStatus ?? 0);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException("No result from " + Target + " within " + _timeout.TotalSeconds + " s.");
        }
        finally
        {
            if (client.IsConnected) { try { client.Disconnect(); } catch { } }
        }
    }

    public void Dispose() { }
}
