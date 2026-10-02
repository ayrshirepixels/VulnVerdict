using Renci.SshNet;
using Renci.SshNet.Common;

namespace VulnVerdict.Core.Adapters.Linux;

public enum HostKeyCheck { Trusted, NotPinned, Changed }

/// <summary>
/// The server offered a key nobody has pinned. Thrown before authentication, so no password or key signature has
/// been sent; the message carries the fingerprint and exactly where to paste it.
/// </summary>
public sealed class HostKeyNotPinnedException : InvalidOperationException
{
    public string Host { get; }
    public string Fingerprint { get; }

    public HostKeyNotPinnedException(string host, string fingerprint, string howToPin)
        : base("Host key for " + host + " is not pinned, so the connection was refused before any credentials were sent. Check that "
               + SshLinuxAdapter.FormatFingerprint(fingerprint) + " is the server's key, then " + howToPin + " (or turn on Accept any host key).")
    {
        Host = host; Fingerprint = SshLinuxAdapter.NormaliseFingerprint(fingerprint);
    }
}

/// <summary>
/// One host-key rule for every SSH adapter (Linux, Windows over OpenSSH, CLI firewalls): a pinned key must match,
/// an unpinned key is refused unless the connector explicitly accepts any key.
/// </summary>
public static class SshHostKeys
{
    public static HostKeyCheck Check(string? presented, string? expected, bool acceptAny)
    {
        if (acceptAny) return HostKeyCheck.Trusted;
        if (string.IsNullOrWhiteSpace(expected) || string.IsNullOrEmpty(presented)) return HostKeyCheck.NotPinned;
        return SshLinuxAdapter.FingerprintEquals(expected, presented) ? HostKeyCheck.Trusted : HostKeyCheck.Changed;
    }

    /// <summary>"add this line to Known host keys: host SHA256:..." for the multi-host forms.</summary>
    public static string KnownHostsLine(string host, string fingerprint) => host + " " + SshLinuxAdapter.FormatFingerprint(fingerprint);

    /// <summary>Hooks the check onto a client, and turns the library's generic key-exchange failure into a message saying what to do.</summary>
    public sealed class Guard
    {
        private readonly string _host; private readonly string? _expected; private readonly Func<string, string> _howToPin;
        public string? Presented { get; private set; }
        public HostKeyCheck Verdict { get; private set; } = HostKeyCheck.NotPinned;

        public Guard(SshClient client, string host, string? expected, bool acceptAny, Func<string, string> howToPin)
        {
            _host = host; _expected = expected; _howToPin = howToPin;
            client.HostKeyReceived += (_, e) =>
            {
                Presented = e.FingerPrintSHA256;
                Verdict = Check(Presented, expected, acceptAny);
                e.CanTrust = Verdict == HostKeyCheck.Trusted;
            };
        }

        /// <summary>The exception to throw for a failed connect, or null when the host key was not the reason.</summary>
        public Exception? Explain(Exception ex)
        {
            if (ex is not SshConnectionException || Presented is null || Verdict == HostKeyCheck.Trusted) return null;
            if (Verdict == HostKeyCheck.NotPinned) return new HostKeyNotPinnedException(_host, Presented, _howToPin(Presented));
            return new InvalidOperationException("Host key for " + _host + " has changed: expected " + SshLinuxAdapter.FormatFingerprint(_expected!) + ", received "
                + SshLinuxAdapter.FormatFingerprint(Presented) + ". Verify the server before updating the pinned key.", ex);
        }
    }
}
