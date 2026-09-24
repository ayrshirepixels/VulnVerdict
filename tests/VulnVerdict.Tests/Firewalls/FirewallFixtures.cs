using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using VulnVerdict.Core.Adapters.Linux;

namespace VulnVerdict.Tests.Firewalls;

/// <summary>
/// Fixture access for the firewall adapter tests. Every fixture is hand-written from the vendor's documented response
/// shapes with RFC 5737 / RFC 1918 addresses and made-up serials; none of it came from a real device.
/// </summary>
internal static class FirewallFixtures
{
    private static string Root([CallerFilePath] string path = "") => Path.Combine(Path.GetDirectoryName(path)!, "..", "Fixtures", "firewalls");

    public static string Read(string vendor, string name) => File.ReadAllText(Path.Combine(Root(), vendor, name));

    public static HttpResponseMessage Xml(string xml, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(xml, Encoding.UTF8, "application/xml") };

    public static string Query(HttpRequestMessage r) => Uri.UnescapeDataString(r.RequestUri?.Query ?? "");

    /// <summary>A fixture file holding several API responses keyed by path (the "_comment" key is skipped).</summary>
    public static Dictionary<string, string> Responses(string vendor, string file = "responses.json")
    {
        using var doc = System.Text.Json.JsonDocument.Parse(Read(vendor, file));
        return doc.RootElement.EnumerateObject().Where(p => p.Name != "_comment").ToDictionary(p => p.Name, p => p.Value.GetRawText(), StringComparer.OrdinalIgnoreCase);
    }
}

/// <summary>An SSH session that answers commands from rules (substring of the command to output), recording what was sent.</summary>
internal sealed class FakeCli : ISshSession
{
    private readonly List<(string Match, SshCommandResult Result)> _rules = new();
    public string? HostKeyFingerprint { get; init; } = "q2b1w4Zb2sM6pGkQy0Xf3VJt8nHc9LrE5uA7dKoTiYw";
    public List<string> Commands { get; } = new();
    public bool Disposed { get; private set; }

    public FakeCli On(string contains, string output, int exit = 0, string error = "") { _rules.Add((contains, new SshCommandResult(exit, output, error))); return this; }

    public Task<SshCommandResult> RunAsync(string command, CancellationToken ct)
    {
        Commands.Add(command);
        foreach (var (m, r) in _rules) if (command.Contains(m, StringComparison.Ordinal)) return Task.FromResult(r);
        return Task.FromResult(new SshCommandResult(127, "", "command not found"));
    }

    public void Dispose() => Disposed = true;
}
