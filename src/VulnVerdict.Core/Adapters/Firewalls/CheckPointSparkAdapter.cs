using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Adapters.Linux;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Firewalls;

/// <summary>
/// Check Point Quantum Spark (1500, 1600, 1800 and later Spark appliances on Gaia Embedded) over SSH, with the
/// documented Gaia Clish command `show diag`: current firmware image, serial number, MAC addresses and hardware
/// version. Gaia Embedded has no documented read-only REST API for locally managed appliances, and this adapter does
/// not read NAT or which services face the internet: exposure comes from the external cross-check or is set by hand.
///
/// Firmware is reported as "Spark Firewalls" (CVE-2026-50751) and as the combined product name Check Point used in
/// CVE-2024-24919. Check Point writes affected versions as text ("R80.20.X, R81.10.X"), which the version matcher
/// cannot compare, so Spark verdicts carry "version could not be compared" until a person confirms them.
///
/// Read-only: only `show diag` is typed at the Clish prompt.
/// </summary>
public sealed partial class CheckPointSparkAdapter : IInventoryAdapter
{
    public const string ShowDiag = "show diag";

    private readonly ILogger _log;

    public CheckPointSparkAdapter(ILogger<CheckPointSparkAdapter>? log = null) { _log = log ?? NullLogger<CheckPointSparkAdapter>.Instance; }

    /// <summary>Opens the SSH session at the Clish prompt; tests substitute a fake.</summary>
    public Func<SshTarget, SshConnectionOptions, CancellationToken, Task<ISshSession>> SessionFactory { get; set; } =
        (t, o, ct) => ApplianceSsh.ConnectAsync(t, o, SshMode.Shell, ct);

    public AdapterMetadata Metadata { get; } = new(
        Id: "checkpoint-spark",
        DisplayName: "Check Point Quantum Spark (SSH: firmware)",
        Vendor: "Check Point",
        Description: "Connects to a locally managed Quantum Spark appliance (Gaia Embedded) over SSH and reads the firmware image, serial number, MAC addresses and hardware version with 'show diag'. NAT and which services face the internet are not read; the external cross-check covers exposure. Read-only.",
        Kinds: new[] { AssetKind.Firewall },
        Form: ApplianceSsh.FormFields("Appliance",
            "An administrator allowed to log in over SSH to the Gaia Clish shell (SSH access is enabled under Device > System > Administrator Access). Use the Read-only role where your firmware allows SSH for it."),
        MinimumPermission: "an administrator that can log in to Gaia Clish over SSH (Read-only role where the firmware allows it); only 'show diag' is sent",
        DocsUrl: "https://sc1.checkpoint.com/documents/Appliances/Quantum_Spark_R82.00.X/CLI/EN/Content/Topics/show-diag.htm",
        DefaultIntervalMinutes: 720);

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            using var s = await SessionFactory(ApplianceSsh.Target(credentials), ApplianceSsh.Options(credentials), ct);
            var d = ParseDiag((await s.RunAsync(ShowDiag, ct)).Output);
            if (d.Version is null) return new TestResult(false, "Connected, but 'show diag' did not show a current image: is this a Quantum Spark appliance, and does the account land in Gaia Clish?");
            var msg = "Connected: Quantum Spark " + d.Version + (d.Build is null ? "" : " (build " + d.Build + ")") + ", serial " + (d.Serial ?? "?") + ".";
            if (ApplianceSsh.PinWarning(credentials, s) is { } pin) msg += " " + pin;
            return new TestResult(true, msg);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { return new TestResult(false, ex.Message); }
    }

    public async Task<CollectResult> CollectAsync(IReadOnlyDictionary<string, string> credentials, DateTime? since, IProgress<string>? progress, CancellationToken ct)
    {
        var r = new CollectResult { FullSnapshot = true };
        var target = ApplianceSsh.Target(credentials);
        using var s = await SessionFactory(target, ApplianceSsh.Options(credentials), ct);
        if (ApplianceSsh.PinWarning(credentials, s) is { } pin) r.Warnings.Add(pin);

        progress?.Report("Reading show diag");
        var d = ParseDiag((await s.RunAsync(ShowDiag, ct)).Output);
        if (d.Version is null) throw new FirewallApiException(ShowDiag, 0, "no current image in the output: is this a Quantum Spark appliance?");
        var id = d.Serial ?? target.Host;
        var ip = System.Net.IPAddress.TryParse(target.Host, out _) ? target.Host : null;
        r.Assets.Add(EdgeRecords.Firewall(id, target.Host, new[] { ip }, d.Macs, CnaNames.CheckPoint, CnaNames.SparkFirewalls, d.Version, d.Build, new[] { ip is null ? target.Host : null }));
        r.Software.AddRange(EdgeRecords.Firmware(id, CnaNames.CheckPoint, CnaNames.SparkFirewalls, d.Version, "spark-firmware", new[] { CnaNames.SparkLegacy }, edition: d.Hardware));
        _log.LogInformation("Check Point Spark {Host}: {Version}", target.Host, d.Version);
        return r;
    }

    public sealed record Diag(string? Version, string? Build, string? Serial, string? Hardware, List<string> Macs);

    [GeneratedRegex(@"R(\d+)_(\d+)_(\d+)_(\d+)", RegexOptions.IgnoreCase)] private static partial Regex ImageNameRx();
    [GeneratedRegex(@"R\d+(?:\.\d+)+", RegexOptions.IgnoreCase)] private static partial Regex DottedReleaseRx();

    /// <summary>
    /// `show diag`: "Current image name: R81_996002945_10_17" is release R81.10.17, build 996002945 (the image name puts
    /// the build between the major and minor numbers); a dotted "R81.10.17" in the name or version is taken as is.
    /// </summary>
    public static Diag ParseDiag(string text)
    {
        var kv = ZyxelFirewallAdapter.ParseKeyValues(text);
        string? V(string k) => kv.GetValueOrDefault(k) is { Length: > 0 } v && !v.Equals("N/A", StringComparison.OrdinalIgnoreCase) ? v : null;
        var name = V("Current image name");
        var ver = V("Current image version");
        string? version = null, build = null;
        if (name is not null && ImageNameRx().Match(name) is { Success: true } m)
        {
            version = "R" + m.Groups[1].Value + "." + m.Groups[3].Value + "." + m.Groups[4].Value;
            build = m.Groups[2].Value;
        }
        else if (DottedReleaseRx().Match(name + " " + ver) is { Success: true } dm) version = dm.Value.ToUpperInvariant();
        if (build is null && ver is not null && Regex.IsMatch(ver, @"^\d{6,}$")) build = ver;
        var macs = kv.Where(p => p.Key.EndsWith("MAC Address", StringComparison.OrdinalIgnoreCase)).Select(p => p.Value.ToLowerInvariant()).Where(v => Regex.IsMatch(v, "^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")).Distinct().ToList();
        return new Diag(version, build, V("Serial number"), V("HW version"), macs);
    }
}
