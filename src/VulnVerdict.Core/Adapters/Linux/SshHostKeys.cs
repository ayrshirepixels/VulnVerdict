using Renci.SshNet;
using Renci.SshNet.Common;

namespace VulnVerdict.Core.Adapters.Linux;

public enum HostKeyCheck { Trusted, NotPinned, Changed }

/// <summary>How a presented key compares with what the connector has pinned for that host.</summary>
public enum HostKeyStatus { Pinned, New, Changed }

/// <summary>
/// A key a host presented during a test or a run, as data the console can act on: the host as typed in the form,
/// the key type, the SHA256 fingerprint (base64, no prefix), and for a changed key the fingerprint that was pinned.
/// Accepted says whether the connection went ahead (pinned, or Accept any host key).
/// </summary>
public sealed record PresentedHostKey(string Host, string KeyType, string Fingerprint, HostKeyStatus Status, string? PinnedFingerprint = null, bool Accepted = false)
{
    public string Display() => SshLinuxAdapter.FormatFingerprint(Fingerprint);
    public string Describe() => Host + " " + (KeyType.Length > 0 ? KeyType + " " : "") + Display();
}

/// <summary>Collects the keys presented while one test or run is in progress. Hosts are collected in parallel, so it locks.</summary>
public sealed class HostKeyLog
{
    private readonly List<PresentedHostKey> _seen = new();

    public void Add(PresentedHostKey key) { lock (_seen) _seen.Add(key); }

    /// <summary>One entry per host: what it presented last.</summary>
    public List<PresentedHostKey> Snapshot()
    {
        lock (_seen) return _seen.GroupBy(k => k.Host, StringComparer.OrdinalIgnoreCase).Select(g => g.Last()).ToList();
    }

    /// <summary>Keys an administrator has to look at: refused because nobody pinned them, or different from the pinned one.</summary>
    public List<PresentedHostKey> NeedReview() =>
        Snapshot().Where(k => k.Status == HostKeyStatus.Changed || (k.Status == HostKeyStatus.New && !k.Accepted)).ToList();
}

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

    /// <summary>New when nothing is pinned for the host, Changed when something else is. Accept any host key does not come into it.</summary>
    public static HostKeyStatus Classify(string presented, string? pinned) =>
        string.IsNullOrWhiteSpace(pinned) ? HostKeyStatus.New
        : SshLinuxAdapter.FingerprintEquals(pinned, presented) ? HostKeyStatus.Pinned
        : HostKeyStatus.Changed;

    /// <summary>The pin for a host in a Known host keys list: its line as typed (host:port), or the line for the host alone.</summary>
    public static string? PinnedFor(string? knownHostKeys, string host)
    {
        var known = SshLinuxAdapter.KnownHostKeys(knownHostKeys ?? "");
        return known.GetValueOrDefault(host) ?? known.GetValueOrDefault(SshTarget.Parse(host).Host);
    }

    /// <summary>Known host keys with one more line. Whatever is already there, comments included, is left as it is.</summary>
    public static string AppendKnownHost(string? knownHostKeys, string host, string fingerprint)
    {
        var text = (knownHostKeys ?? "").Replace("\r\n", "\n").TrimEnd('\n', ' ', '\t');
        return (text.Length == 0 ? "" : text + "\n") + KnownHostsLine(host, fingerprint);
    }

    /// <summary>Known host keys with the host's line rewritten in place; appended when the host has no line.</summary>
    public static string ReplaceKnownHost(string? knownHostKeys, string host, string fingerprint)
    {
        var known = SshLinuxAdapter.KnownHostKeys(knownHostKeys ?? "");
        // the same lookup order the adapters use: the line as typed, then the host without its port
        var key = known.ContainsKey(host) ? host : SshTarget.Parse(host).Host;
        if (!known.ContainsKey(key)) return AppendKnownHost(knownHostKeys, host, fingerprint);
        var lines = (knownHostKeys ?? "").Replace("\r\n", "\n").Split('\n').ToList();
        var replaced = false;
        for (var i = lines.Count - 1; i >= 0; i--)
        {
            var parts = lines[i].Trim().Split(new[] { ' ', '\t', ',' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2 || parts[0].StartsWith('#') || !parts[0].Equals(key, StringComparison.OrdinalIgnoreCase)) continue;
            // the last line for a host is the one in force; earlier duplicates go
            if (replaced) lines.RemoveAt(i);
            else { lines[i] = KnownHostsLine(parts[0], fingerprint); replaced = true; }
        }
        return string.Join("\n", lines).TrimEnd('\n', ' ', '\t');
    }

    private static readonly AsyncLocal<HostKeyLog?> Listening = new();

    /// <summary>
    /// Start collecting the keys presented by every SSH connection made further down this call (a connector test or
    /// run). The adapters need not know: the guard on each connection reports here.
    /// </summary>
    public static HostKeyLog Listen()
    {
        var log = new HostKeyLog();
        Listening.Value = log;
        return log;
    }

    /// <summary>Report a presented key to whoever is listening. The guard calls this; a test double for a session can too.</summary>
    public static void Observe(string host, string? keyType, string presented, string? pinned, bool accepted) =>
        Observe(Listening.Value, host, keyType, presented, pinned, accepted);

    private static void Observe(HostKeyLog? log, string host, string? keyType, string presented, string? pinned, bool accepted) =>
        log?.Add(new PresentedHostKey(host, keyType ?? "", SshLinuxAdapter.NormaliseFingerprint(presented), Classify(presented, pinned),
            string.IsNullOrWhiteSpace(pinned) ? null : SshLinuxAdapter.NormaliseFingerprint(pinned), accepted));

    /// <summary>Hooks the check onto a client, and turns the library's generic key-exchange failure into a message saying what to do.</summary>
    public sealed class Guard
    {
        private readonly string _host; private readonly string? _expected; private readonly Func<string, string> _howToPin;
        public string? Presented { get; private set; }
        public HostKeyCheck Verdict { get; private set; } = HostKeyCheck.NotPinned;

        public Guard(SshClient client, string host, string? expected, bool acceptAny, Func<string, string> howToPin)
        {
            _host = host; _expected = expected; _howToPin = howToPin;
            // the library raises the event on its own thread; the listener is picked up here, on the caller's
            var log = Listening.Value;
            client.HostKeyReceived += (_, e) =>
            {
                Presented = e.FingerPrintSHA256;
                Verdict = Check(Presented, expected, acceptAny);
                e.CanTrust = Verdict == HostKeyCheck.Trusted;
                Observe(log, host, e.HostKeyName, Presented, expected, e.CanTrust);
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
