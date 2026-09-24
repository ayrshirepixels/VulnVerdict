using System.Diagnostics;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Adapters.Windows;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Tests;

/// <summary>A fact that is skipped on anything but Windows (the collector needs powershell.exe).</summary>
public sealed class WindowsOnlyFactAttribute : FactAttribute
{
    public WindowsOnlyFactAttribute() { if (!OperatingSystem.IsWindows()) Skip = "Windows only: runs the collector with powershell.exe"; }
}

public class WinRmAdapterTests
{
    private const string FixtureName = "windows-collector-sample.json";

    // ------------------------------------------------------------------ (a) live collector run on this machine

    [WindowsOnlyFact]
    public void Collector_runs_on_windows_powershell_and_prints_one_json_object()
    {
        var (stdout, stderr, exit) = RunCollector(Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"));
        Assert.True(exit == 0, "powershell.exe exit " + exit + ": " + stderr);
        AssertCollectorDocument(stdout);
    }

    [WindowsOnlyFact]
    public void Collector_runs_on_powershell_7_when_installed()
    {
        var pwsh = FindOnPath("pwsh.exe");
        if (pwsh is null) return; // PowerShell 7 is optional on the build machine
        var (stdout, stderr, exit) = RunCollector(pwsh);
        Assert.True(exit == 0, "pwsh exit " + exit + ": " + stderr);
        AssertCollectorDocument(stdout);
    }

    private static void AssertCollectorDocument(string stdout)
    {
        var json = WinRmAdapter.ExtractJson(stdout);
        Assert.NotNull(json);
        using var doc = JsonDocument.Parse(json!);
        var root = doc.RootElement;
        Assert.Equal(WindowsCollectorScript.Version, root.GetProperty("collector").GetString());
        Assert.False(string.IsNullOrWhiteSpace(root.GetProperty("host").GetProperty("name").GetString()));
        Assert.Matches(@"^\d+\.\d+\.\d+(\.\d+)?$", root.GetProperty("host").GetProperty("osBuild").GetString());
        Assert.True(root.GetProperty("software").GetArrayLength() > 0, "no installed software found");
        Assert.Equal(JsonValueKind.Array, root.GetProperty("listeners").ValueKind);
        Assert.Equal(JsonValueKind.Array, root.GetProperty("warnings").ValueKind);

        // the same document must map without throwing, and the mapping must yield the OS record
        var result = new CollectResult();
        var asset = WindowsCollectorMapper.Map("localhost", root, result);
        Assert.Equal("Microsoft", asset.OsVendor);
        Assert.Contains(result.Software, s => s.Kind == SoftwareKind.OperatingSystem && s.Vendor == "Microsoft");
    }

    private static (string Stdout, string Stderr, int Exit) RunCollector(string exe)
    {
        var script = Path.Combine(Path.GetTempPath(), "vulnverdict-collector-" + Guid.NewGuid().ToString("N") + ".ps1");
        File.WriteAllText(script, WindowsCollectorScript.Compact);
        try
        {
            var psi = new ProcessStartInfo(exe) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
            foreach (var a in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script }) psi.ArgumentList.Add(a);
            using var p = Process.Start(psi)!;
            var stdout = p.StandardOutput.ReadToEndAsync();
            var stderr = p.StandardError.ReadToEndAsync();
            Assert.True(p.WaitForExit(180_000), "collector did not finish within 3 minutes");
            return (stdout.Result, stderr.Result, p.ExitCode);
        }
        finally { File.Delete(script); }
    }

    private static string? FindOnPath(string exe)
    {
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var candidate = Path.Combine(dir.Trim(), exe);
            if (File.Exists(candidate)) return candidate;
        }
        return null;
    }

    // ------------------------------------------------------------------ (b) fixture through the mapper

    private static JsonDocument LoadFixture()
    {
        var dir = AppContext.BaseDirectory;
        for (var i = 0; i < 8 && dir is not null; i++)
        {
            var candidate = Path.Combine(dir, "Fixtures", FixtureName);
            if (File.Exists(candidate)) return JsonDocument.Parse(File.ReadAllText(candidate));
            dir = Path.GetDirectoryName(dir);
        }
        throw new FileNotFoundException("Fixture " + FixtureName + " not found above " + AppContext.BaseDirectory);
    }

    private static readonly string[] CnaOsNames =
    {
        "Windows Server 2025", "Windows Server 2022", "Windows Server 2019", "Windows Server 2016", "Windows Server 2012 R2", "Windows Server 2012",
        "Windows Server 2025 (Server Core installation)", "Windows Server 2022 (Server Core installation)", "Windows Server 2019 (Server Core installation)", "Windows Server 2016 (Server Core installation)",
        "Windows Server 2022, 23H2 Edition (Server Core Installation)",
        "Windows 11 Version 25H2", "Windows 11 Version 24H2", "Windows 11 Version 23H2", "Windows 11 Version 22H2", "Windows 11 Version 21H2",
        "Windows 10 Version 22H2", "Windows 10 Version 21H2", "Windows 10 Version 1809",
    };

    [Fact]
    public void Fixture_maps_to_os_record_with_cna_name_and_role_records()
    {
        using var doc = LoadFixture();
        var result = new CollectResult();
        var asset = WindowsCollectorMapper.Map("vv-sample-01.example.local", doc.RootElement, result);

        Assert.Equal("vv-sample-01.example.local", asset.ExternalId);
        Assert.Equal("VV-SAMPLE-01", asset.DisplayName);
        Assert.Equal("Microsoft", asset.OsVendor);
        Assert.Contains(asset.OsProduct, CnaOsNames);
        Assert.Equal("10.0.26200.9457", asset.OsBuild);
        Assert.Equal(asset.OsBuild, asset.OsVersion);
        Assert.Contains("192.168.1.184", asset.IpAddresses);
        Assert.Contains("10:ff:e0:83:a1:d4", asset.MacAddresses);
        Assert.Equal(AssetKind.Endpoint, asset.Kind); // ProductType WinNT: a workstation, not a server

        var os = Assert.Single(result.Software, s => s.Kind == SoftwareKind.OperatingSystem);
        Assert.Equal("Microsoft", os.Vendor);
        Assert.Contains(os.Product, CnaOsNames);
        Assert.Equal("10.0.26200.9457", os.Version);
        Assert.NotNull(os.Listeners);
        Assert.Contains(os.Listeners!, l => l.Port == 445 && l.Protocol == "tcp");

        var roles = result.Software.Where(s => s.Kind == SoftwareKind.RoleOrFeature).ToList();
        Assert.NotEmpty(roles);
        Assert.All(roles, r => Assert.Equal("Microsoft", r.Vendor));
        var spooler = Assert.Single(roles, r => r.Product == "Print Spooler");
        Assert.True(spooler.Enabled);
        var rdp = Assert.Single(roles, r => r.Product == "Remote Desktop Services");
        Assert.False(rdp.Enabled); // fDenyTSConnections = 1 on the sample host
        var smb1 = Assert.Single(roles, r => r.Product == "Windows SMBv1");
        Assert.False(smb1.Enabled);

        Assert.Contains(result.Software, s => s.Kind == SoftwareKind.Application && s.Vendor.Length > 0 && s.Version.Length > 0);
        Assert.Contains(result.Software, s => s.Kind == SoftwareKind.Runtime && s.Product == ".NET 8.0" && s.Version == "8.0.30");
        Assert.Contains(result.Software, s => s.Kind == SoftwareKind.Runtime && s.Product == "ASP.NET Core 10.0");
        Assert.Contains(result.Software, s => s.Kind == SoftwareKind.Runtime && s.Product == "Microsoft .NET Framework 4.8.1");
        Assert.Contains(result.Software, s => s.Kind == SoftwareKind.Runtime && s.Product == "Microsoft .NET Framework 3.5");
        Assert.DoesNotContain(result.Software, s => s.Product.StartsWith("Microsoft .NET Framework 2.0") || s.Product.StartsWith("Microsoft .NET Framework 3.0"));

        // the collector's own warning (DISM needs elevation on a workstation) is surfaced, prefixed with the host
        Assert.Contains(result.Warnings, w => w.StartsWith("vv-sample-01.example.local: collector: features:"));
        // every software record is tied to the host and has a stable external id so re-runs update instead of duplicating
        Assert.All(result.Software, s => { Assert.Equal("vv-sample-01.example.local", s.AssetExternalId); Assert.False(string.IsNullOrEmpty(s.ExternalId)); });
        Assert.Equal(result.Software.Count, result.Software.Select(s => s.ExternalId).Distinct().Count());
    }

    [Fact]
    public async Task CollectAsync_uses_the_shell_per_host_and_turns_failures_into_warnings()
    {
        using var doc = LoadFixture();
        var fixtureJson = doc.RootElement.GetRawText();
        var scripts = new List<string>();
        var adapter = new WinRmAdapter(NullLogger<WinRmAdapter>.Instance)
        {
            ShellFactory = (target, settings) => new FakeShell(target.Host == "bad" ? null : fixtureJson, target, settings, scripts),
        };
        var creds = new Dictionary<string, string>
        {
            ["hosts"] = "srv1.example.local\nbad:5985\n192.168.1.184",
            ["username"] = "EXAMPLE\\svc-vulnverdict", ["password"] = "not-logged", ["transport"] = "winrm-http", ["authentication"] = "negotiate",
        };
        var progress = new List<string>();
        var result = await adapter.CollectAsync(creds, null, new Progress<string>(progress.Add), CancellationToken.None);

        Assert.True(result.Assets.Count == 2, "assets: " + result.Assets.Count + "; warnings: " + string.Join(" | ", result.Warnings));
        Assert.Contains(result.Assets, a => a.ExternalId == "srv1.example.local");
        Assert.Contains(result.Assets, a => a.ExternalId == "192.168.1.184");
        Assert.Contains(result.Warnings, w => w.StartsWith("bad:5985: "));
        Assert.True(result.FullSnapshot);
        Assert.Equal(2, scripts.Count); // the "bad" host failed before a script could run
        Assert.All(scripts, s => Assert.Equal(WindowsCollectorScript.Compact, s));

        var test = await adapter.TestAsync(creds, CancellationToken.None);
        Assert.True(test.Ok, test.Message);
        Assert.Contains("PowerShell 5.1", test.Message);
    }

    private sealed class FakeShell : IWindowsShell
    {
        private readonly string? _json;
        private readonly List<string> _scripts;
        public FakeShell(string? json, HostTarget target, WinRmSettings settings, List<string> scripts)
        {
            _json = json; _scripts = scripts;
            Target = target.Host + ":" + (target.Port?.ToString() ?? "default") + " " + settings.Transport;
        }
        public string Target { get; }
        public Task<ShellResult> RunPowerShellAsync(string script, CancellationToken ct)
        {
            if (_json is null) throw new HttpRequestException("connection refused");
            if (!script.Contains("ConvertTo-Json")) return Task.FromResult(new ShellResult("5.1.20348.2582", "", 0)); // the TestAsync probe
            _scripts.Add(script);
            return Task.FromResult(new ShellResult(_json + "\n", "", 0));
        }
        public void Dispose() { }
    }

    // ------------------------------------------------------------------ (c) WS-Management envelopes

    private static readonly XNamespace S = WsManEnvelopes.S, A = WsManEnvelopes.A, W = WsManEnvelopes.W, Rsp = WsManEnvelopes.Rsp;
    private const string Endpoint = "https://srv1.example.local:5986/wsman";

    [Fact]
    public void Create_shell_envelope_has_resource_uri_action_and_streams()
    {
        var doc = XDocument.Parse(WsManEnvelopes.CreateShell(Endpoint));
        var header = doc.Root!.Element(S + "Header")!;
        Assert.Equal(WsManEnvelopes.ShellResourceUri, header.Element(W + "ResourceURI")!.Value);
        Assert.Equal("http://schemas.xmlsoap.org/ws/2004/09/transfer/Create", header.Element(A + "Action")!.Value);
        Assert.Equal("true", header.Element(A + "Action")!.Attribute(S + "mustUnderstand")!.Value);
        Assert.Equal(Endpoint, header.Element(A + "To")!.Value);
        Assert.Equal("153600", header.Element(W + "MaxEnvelopeSize")!.Value);
        Assert.Equal("PT60S", header.Element(W + "OperationTimeout")!.Value);
        Assert.StartsWith("uuid:", header.Element(A + "MessageID")!.Value);
        var shell = doc.Root.Element(S + "Body")!.Element(Rsp + "Shell")!;
        Assert.Equal("stdin", shell.Element(Rsp + "InputStreams")!.Value);
        Assert.Equal("stdout stderr", shell.Element(Rsp + "OutputStreams")!.Value);
        Assert.Contains(header.Element(W + "OptionSet")!.Elements(W + "Option"), o => o.Attribute("Name")!.Value == "WINRS_CODEPAGE" && o.Value == "65001");
    }

    [Fact]
    public void Command_envelope_targets_the_shell_and_carries_the_encoded_command()
    {
        var doc = XDocument.Parse(WsManEnvelopes.Command(Endpoint, "SHELL-1", "powershell.exe", new[] { "-NoProfile", "-EncodedCommand", "QQBCAA==" }));
        var header = doc.Root!.Element(S + "Header")!;
        Assert.Equal(WsManEnvelopes.ShellResourceUri, header.Element(W + "ResourceURI")!.Value);
        Assert.Equal("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command", header.Element(A + "Action")!.Value);
        var selector = header.Element(W + "SelectorSet")!.Element(W + "Selector")!;
        Assert.Equal("ShellId", selector.Attribute("Name")!.Value);
        Assert.Equal("SHELL-1", selector.Value);
        Assert.Contains(header.Element(W + "OptionSet")!.Elements(W + "Option"), o => o.Attribute("Name")!.Value == "WINRS_SKIP_CMD_SHELL" && o.Value == "TRUE");
        var line = doc.Root.Element(S + "Body")!.Element(Rsp + "CommandLine")!;
        Assert.Equal("powershell.exe", line.Element(Rsp + "Command")!.Value);
        Assert.Equal(new[] { "-NoProfile", "-EncodedCommand", "QQBCAA==" }, line.Elements(Rsp + "Arguments").Select(a => a.Value).ToArray());
    }

    [Fact]
    public void Receive_signal_and_delete_envelopes_have_the_right_actions()
    {
        var receive = XDocument.Parse(WsManEnvelopes.Receive(Endpoint, "SHELL-1", "CMD-1"));
        Assert.Equal("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive", receive.Root!.Element(S + "Header")!.Element(A + "Action")!.Value);
        Assert.Equal(WsManEnvelopes.ShellResourceUri, receive.Root.Element(S + "Header")!.Element(W + "ResourceURI")!.Value);
        var stream = receive.Root.Element(S + "Body")!.Element(Rsp + "Receive")!.Element(Rsp + "DesiredStream")!;
        Assert.Equal("CMD-1", stream.Attribute("CommandId")!.Value);
        Assert.Equal("stdout stderr", stream.Value);

        var signal = XDocument.Parse(WsManEnvelopes.Signal(Endpoint, "SHELL-1", "CMD-1"));
        Assert.Equal("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal", signal.Root!.Element(S + "Header")!.Element(A + "Action")!.Value);
        Assert.Equal(WsManEnvelopes.SignalTerminate, signal.Root.Element(S + "Body")!.Element(Rsp + "Signal")!.Element(Rsp + "Code")!.Value);

        var delete = XDocument.Parse(WsManEnvelopes.DeleteShell(Endpoint, "SHELL-1"));
        Assert.Equal("http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete", delete.Root!.Element(S + "Header")!.Element(A + "Action")!.Value);
        Assert.Equal("SHELL-1", delete.Root.Element(S + "Header")!.Element(W + "SelectorSet")!.Element(W + "Selector")!.Value);
        Assert.Empty(delete.Root.Element(S + "Body")!.Elements());
    }

    [Fact]
    public void Encoded_collector_fits_on_one_command_line()
    {
        // WinRM runs the script as powershell.exe -EncodedCommand; CreateProcess allows 32767 characters
        Assert.True(WindowsCollectorScript.EncodedCommand.Length < 30000, "encoded collector is " + WindowsCollectorScript.EncodedCommand.Length + " characters");
        Assert.DoesNotContain("\n#", WindowsCollectorScript.Compact);
        Assert.Contains("ConvertTo-Json", WindowsCollectorScript.Compact);
    }

    [Fact]
    public void Basic_auth_over_plain_http_is_refused_and_credentials_split_on_backslash()
    {
        Assert.Throws<ArgumentException>(() => new WsManClient(new WsManOptions { Host = "h", UseTls = false, BasicAuth = true, Username = "u", Password = "p" }));
        using var client = new WsManClient(new WsManOptions { Host = "fd00::10", UseTls = true, Username = "EXAMPLE\\svc", Password = "p" });
        Assert.Equal("https://[fd00::10]:5986/wsman", client.Endpoint);
        var cred = WsManClient.ToNetworkCredential("EXAMPLE\\svc", "p");
        Assert.Equal("EXAMPLE", cred.Domain); Assert.Equal("svc", cred.UserName);
        var upn = WsManClient.ToNetworkCredential("svc@example.local", "p");
        Assert.Equal("", upn.Domain); Assert.Equal("svc@example.local", upn.UserName);
    }

    [Fact]
    public void Clixml_stderr_is_turned_back_into_text()
    {
        var raw = "#< CLIXML\r\n<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\"><S S=\"Error\">Access is denied_x000D__x000A_</S><S S=\"Error\">second &lt;line&gt;</S></Objs>";
        Assert.Equal("Access is denied\nsecond <line>", WsManClient.CleanStderr(raw));
        Assert.Equal("plain", WsManClient.CleanStderr("plain"));
    }

    // ------------------------------------------------------------------ naming rules

    [Theory]
    [InlineData("Microsoft Windows Server 2022 Standard", null, "10.0.20348.2322", "Server", "Windows Server 2022")]
    [InlineData("Microsoft Windows Server 2022 Datacenter", null, "10.0.20348.2322", "Server Core", "Windows Server 2022 (Server Core installation)")]
    [InlineData("Microsoft Windows Server 2019 Standard", "1809", "10.0.17763.5576", "Server", "Windows Server 2019")]
    [InlineData("Microsoft Windows Server 2016 Standard", null, "10.0.14393.6796", "Server", "Windows Server 2016")]
    [InlineData("Microsoft Windows Server 2025 Standard", "24H2", "10.0.26100.2894", "Server", "Windows Server 2025")]
    [InlineData("Microsoft Windows Server 2012 R2 Standard", null, "6.3.9600.21000", "Server", "Windows Server 2012 R2")]
    [InlineData("Windows Server Datacenter", null, "10.0.25398.709", "Server Core", "Windows Server 2022, 23H2 Edition (Server Core Installation)")]
    [InlineData("Microsoft Windows 11 Pro for Workstations", "25H2", "10.0.26200.9457", "Client", "Windows 11 Version 25H2")]
    [InlineData("Microsoft Windows 11 Enterprise", "24H2", "10.0.26100.3037", "Client", "Windows 11 Version 24H2")]
    [InlineData("Microsoft Windows 10 Pro", "22H2", "10.0.19045.4046", "Client", "Windows 10 Version 22H2")]
    [InlineData("Microsoft Windows 10 Enterprise", null, "10.0.19045.4046", "Client", "Windows 10 Version 22H2")]
    [InlineData("Windows 10 Pro", null, "10.0.22631.3155", "Client", "Windows 11 Version 23H2")] // registry ProductName still says 10 on Windows 11
    public void Os_captions_map_to_cna_product_names(string caption, string? displayVersion, string build, string installationType, string expected)
    {
        Assert.Equal(expected, WindowsCollectorMapper.OsProductName(caption, displayVersion, build, installationType));
    }

    [Theory]
    [InlineData("16.0.1000.6", "Microsoft SQL Server 2022 (GDR)")]
    [InlineData("15.0.4335.1", "Microsoft SQL Server 2019 (GDR)")]
    [InlineData("14.0.3465.1", "Microsoft SQL Server 2017 (GDR)")]
    [InlineData("13.0.6435.1", "Microsoft SQL Server 2016 (GDR)")]
    [InlineData("10.50.6000.34", "Microsoft SQL Server 2008 R2 (GDR)")]
    [InlineData(null, "Microsoft SQL Server")]
    public void Sql_versions_map_to_cna_product_names(string? version, string expected) => Assert.Equal(expected, WindowsCollectorMapper.SqlProductName(version));

    [Theory]
    [InlineData("7-Zip 26.02 (x64)", "26.02", "7-Zip", "x64")]
    [InlineData("Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.38.33130", "14.38.33130.0", "Microsoft Visual C++ 2015-2022 Redistributable", "x64")]
    [InlineData("Python 3.12.4 (64-bit)", "3.12.4150.0", "Python", "x64")]
    [InlineData("Java 8 Update 401", "8.0.4010.10", "Java 8 Update 401", null)]
    [InlineData("Visual Studio Community 2022", "17.9.6", "Visual Studio Community 2022", null)]
    [InlineData("Node.js", "20.11.1", "Node.js", null)]
    [InlineData("Google Chrome", "", "Google Chrome", null)]
    [InlineData("Notepad++ (64-bit x64)", "8.6.4", "Notepad++", "x64")]
    public void Trailing_versions_and_architecture_are_split_from_display_names(string display, string version, string product, string? arch)
    {
        var (p, a) = WindowsCollectorMapper.CleanProductName(display, version);
        Assert.Equal(product, p); Assert.Equal(arch, a);
    }

    [Theory]
    [InlineData(533320, null, "4.8.1")]
    [InlineData(528040, "4.8.04084", "4.8")]
    [InlineData(461808, null, "4.7.2")]
    [InlineData(null, "3.5.30729.4926", "3.5")]
    [InlineData(null, "2.0.50727.4927", null)]
    public void Framework_release_numbers_map_to_versions(int? release, string? version, string? expected) => Assert.Equal(expected, WindowsCollectorMapper.FrameworkVersion(release, version));

    [Fact]
    public void Iis_bindings_become_listeners()
    {
        var l = WindowsCollectorMapper.ParseIisBinding("https/*:443:www.example.com", "Default Web Site")!;
        Assert.Equal(443, l.Port); Assert.Equal("https", l.Protocol); Assert.Equal("*/www.example.com", l.Bind); Assert.Equal("w3wp (Default Web Site)", l.Process);
        var plain = WindowsCollectorMapper.ParseIisBinding("http/*:80:")!;
        Assert.Equal(80, plain.Port); Assert.Equal("*", plain.Bind);
        Assert.Null(WindowsCollectorMapper.ParseIisBinding("net.tcp/808:*"));
    }

    [Fact]
    public void Hosts_textarea_parses_ports_and_ipv6()
    {
        var hosts = WinRmAdapter.ParseHosts("srv1.example.local\r\nsrv2:5985\n[fd00::10]:5986\n192.168.1.20\n# comment\n\n");
        Assert.Equal(4, hosts.Count);
        Assert.Equal(new HostTarget("srv1.example.local", "srv1.example.local", null), hosts[0]);
        Assert.Equal(new HostTarget("srv2:5985", "srv2", 5985), hosts[1]);
        Assert.Equal(new HostTarget("[fd00::10]:5986", "fd00::10", 5986), hosts[2]);
        Assert.Equal(new HostTarget("192.168.1.20", "192.168.1.20", null), hosts[3]);
    }

    [Fact]
    public void Settings_defaults_and_validation()
    {
        var s = WinRmSettings.From(new Dictionary<string, string> { ["username"] = "u", ["password"] = "p" });
        Assert.Equal("winrm-https", s.Transport); Assert.Equal("negotiate", s.Authentication); Assert.True(s.VerifyTls); Assert.Equal(TimeSpan.FromSeconds(120), s.Timeout);
        var t = WinRmSettings.From(new Dictionary<string, string> { ["username"] = "u", ["password"] = "p", ["transport"] = "SSH", ["verifyTls"] = "false", ["timeoutSeconds"] = "30" });
        Assert.True(t.IsSsh); Assert.False(t.VerifyTls); Assert.Equal(TimeSpan.FromSeconds(30), t.Timeout);
        Assert.Throws<ArgumentException>(() => WinRmSettings.From(new Dictionary<string, string> { ["transport"] = "telnet" }));
        Assert.Equal("winrm", new WinRmAdapter(NullLogger<WinRmAdapter>.Instance).Metadata.Id);
    }
}
