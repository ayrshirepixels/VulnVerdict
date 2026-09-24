using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Adapters.Linux;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Firewalls;

/// <summary>
/// Zyxel USG FLEX, ATP, VPN and USG20(W)-VPN firewalls (ZLD) and USG FLEX H (uOS) over the SSH command line, with the
/// show commands of the ZLD CLI Reference Guide: `show version` (model and firmware), `show serial-number`,
/// `show zone WAN` (the WAN interfaces) and `show ip virtual-server` (port forwards). The firmware is reported under
/// the series name the Zyxel CNA uses ("USG FLEX series firmware", "ATP series firmware", ...) and, where Zyxel has
/// also used a per-model name ("USG FLEX 100(W) firmware"), under that too.
///
/// Read-only: only show commands are typed at the CLI prompt; configuration mode is never entered.
/// </summary>
public sealed partial class ZyxelFirewallAdapter : IInventoryAdapter
{
    public const string ShowVersion = "show version";
    public const string ShowSerial = "show serial-number";
    public const string ShowWanZone = "show zone WAN";
    public const string ShowVirtualServers = "show ip virtual-server";

    private readonly ILogger _log;

    public ZyxelFirewallAdapter(ILogger<ZyxelFirewallAdapter>? log = null) { _log = log ?? NullLogger<ZyxelFirewallAdapter>.Instance; }

    /// <summary>Opens the SSH session at the CLI prompt; tests substitute a fake.</summary>
    public Func<SshTarget, SshConnectionOptions, CancellationToken, Task<ISshSession>> SessionFactory { get; set; } =
        (t, o, ct) => ApplianceSsh.ConnectAsync(t, o, SshMode.Shell, ct);

    public AdapterMetadata Metadata { get; } = new(
        Id: "zyxel-firewall",
        DisplayName: "Zyxel USG FLEX / ATP firewall (SSH: firmware, virtual servers)",
        Vendor: "Zyxel",
        Description: "Connects to a Zyxel USG FLEX, ATP, VPN or USG20(W)-VPN firewall (ZLD) or USG FLEX H (uOS) over SSH and reads the model, firmware and serial number, the WAN zone and the NAT virtual servers on it (port forwards) for exposure. Which admin and VPN services the WAN allows is not read. Read-only.",
        Kinds: new[] { AssetKind.Firewall },
        Form: ApplianceSsh.FormFields("Firewall",
            "A limited-admin user (can view settings but not change them), with SSH allowed from the console's address (System > SSH and its service control rules)."),
        MinimumPermission: "a limited-admin user with SSH access from the console's address; only show commands are sent",
        DocsUrl: "https://mysupport.zyxel.com/hc/en-us/articles/18990522317330-USG-FLEX-H-Series-Firewall-Overview-of-CLI-Commands-for-H-Series",
        DefaultIntervalMinutes: 240);

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            using var s = await SessionFactory(ApplianceSsh.Target(credentials), ApplianceSsh.Options(credentials), ct);
            var (model, raw) = ParseVersion((await s.RunAsync(ShowVersion, ct)).Output);
            if (model is null || FirmwareVersion(raw).Version is null) return new TestResult(false, "Connected, but 'show version' did not give a model and firmware version: is this a Zyxel ZLD or uOS firewall?");
            var msg = "Connected: " + model + ", firmware " + raw + " (" + ProductNames(model).Primary + ").";
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

        progress?.Report("Reading version");
        var (model, raw) = ParseVersion((await s.RunAsync(ShowVersion, ct)).Output);
        if (model is null) throw new FirewallApiException(ShowVersion, 0, "no model in the output: is this a Zyxel ZLD or uOS firewall?");
        var (version, build) = FirmwareVersion(raw);
        if (version is null) r.Warnings.Add("Firmware version '" + raw + "' could not be read.");
        var serial = SerialNumber((await s.RunAsync(ShowSerial, ct)).Output);

        progress?.Report("Reading virtual servers");
        var wan = ZoneMembers((await s.RunAsync(ShowWanZone, ct)).Output);
        if (wan.Count == 0) r.Warnings.Add("'show zone WAN' listed no interfaces; interfaces named wan* are treated as WAN.");
        var servers = ParseVirtualServers((await s.RunAsync(ShowVirtualServers, ct)).Output);

        var id = serial ?? target.Host;
        var (primary, alternates) = ProductNames(model);
        var ip = System.Net.IPAddress.TryParse(target.Host, out _) ? target.Host : null;
        r.Assets.Add(EdgeRecords.Firewall(id, target.Host, new[] { ip }, Array.Empty<string>(), CnaNames.Zyxel, primary, version, build, new[] { ip is null ? target.Host : null }));
        r.Software.AddRange(EdgeRecords.Firmware(id, CnaNames.Zyxel, primary, version ?? "", "zyxel-firmware", alternates, edition: model));
        r.Exposures.AddRange(VirtualServerExposures(servers, wan));
        _log.LogInformation("Zyxel {Host}: {Model} {Version}", target.Host, model, version);
        return r;
    }

    // ------------------------------------------------------------------ parsing

    // [ \t] rather than \s so an empty value ("original end port:") never runs on into the next line
    [GeneratedRegex(@"^[ \t]*([A-Za-z][A-Za-z0-9 ._()-]*?)[ \t]*:[ \t]*(.*?)[ \t]*\r?$", RegexOptions.Multiline)] private static partial Regex KeyValueRx();

    /// <summary>"key : value" lines; the first occurrence of a key wins.</summary>
    public static Dictionary<string, string> ParseKeyValues(string text)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match m in KeyValueRx().Matches(ApplianceSsh.CleanTerminal(text))) d.TryAdd(m.Groups[1].Value.Trim(), m.Groups[2].Value.Trim());
        return d;
    }

    [GeneratedRegex(@"^\s*1\s+(\S+(?:\s\S+)*?)\s{2,}(V?\d+\.\d+\([A-Z0-9]+\.\d+\)\S*)", RegexOptions.Multiline | RegexOptions.IgnoreCase)] private static partial Regex VersionTableRx();

    /// <summary>
    /// Model and firmware from `show version`: the "model : ... / firmware version : ..." form, or the image table form
    /// ("1  USG110  V4.11(AAPH.0)b3s1 ...", first image is the running one).
    /// </summary>
    public static (string? Model, string? Firmware) ParseVersion(string text)
    {
        var kv = ParseKeyValues(text);
        var model = kv.GetValueOrDefault("model") is { Length: > 0 } m ? m : null;
        var fw = kv.GetValueOrDefault("firmware version") is { Length: > 0 } f ? f : null;
        if (model is not null && fw is not null) return (model, fw);
        var t = VersionTableRx().Match(ApplianceSsh.CleanTerminal(text));
        return t.Success ? (model ?? t.Groups[1].Value.Trim(), fw ?? t.Groups[2].Value) : (model, fw);
    }

    [GeneratedRegex(@"V?(\d+\.\d+)\s*\(\s*([A-Z0-9]+)\.(\d+)\s*\)", RegexOptions.IgnoreCase)] private static partial Regex FirmwareRx();
    [GeneratedRegex(@"V?(\d+\.\d+)", RegexOptions.IgnoreCase)] private static partial Regex PlainRx();

    /// <summary>
    /// "V5.38(ABUH.0)" to ("5.38", "ABUH.0"); "5.21(ABUH.1)" to ("5.21 Patch 1", "ABUH.1"), the form Zyxel's advisories
    /// and CVE records use ("5.00 through 5.21 Patch 1"). The model code in brackets becomes the build.
    /// </summary>
    public static (string? Version, string? Build) FirmwareVersion(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return (null, null);
        var m = FirmwareRx().Match(raw);
        if (m.Success)
        {
            var patch = int.Parse(m.Groups[3].Value);
            return (m.Groups[1].Value + (patch > 0 ? " Patch " + patch : ""), m.Groups[2].Value.ToUpperInvariant() + "." + m.Groups[3].Value);
        }
        var p = PlainRx().Match(raw);
        return (p.Success ? p.Groups[1].Value : null, null);
    }

    /// <summary>Model ("USG FLEX 100W", "ATP200", "USG20W-VPN", "USG FLEX 200HP") to the Zyxel CNA series name and per-model aliases.</summary>
    public static (string Primary, string[] Alternates) ProductNames(string model)
    {
        var m = Regex.Replace(model.Trim(), @"\s+", " ").ToUpperInvariant();
        var flex = Regex.Match(m, @"USG\s?FLEX\s?(\d+)\s?(AX|HP|H|W)?");
        if (flex.Success)
        {
            var num = flex.Groups[1].Value; var suffix = flex.Groups[2].Value;
            if (suffix is "H" or "HP") return (CnaNames.ZyxelUsgFlexHuOs, Array.Empty<string>());
            if (num == "50") return (CnaNames.ZyxelUsgFlex50Series, new[] { "USG FLEX 50(W) firmware" });
            return (CnaNames.ZyxelUsgFlexSeries, new[] { "USG FLEX " + num + (num == "100" ? "(W)" : suffix == "AX" ? "AX" : "") + " firmware" });
        }
        if (Regex.IsMatch(m, @"^ATP\s?\d")) return (CnaNames.ZyxelAtpSeries, Array.Empty<string>());
        if (Regex.IsMatch(m, @"USG\s?20W?-VPN")) return (CnaNames.ZyxelUsg20VpnSeries, new[] { "USG 20(W)-VPN firmware" });
        if (Regex.IsMatch(m, @"^VPN\s?\d")) return (CnaNames.ZyxelVpnSeries, Array.Empty<string>());
        return (model.Trim() + " firmware", Array.Empty<string>());
    }

    [GeneratedRegex(@"serial\s*number\s*:\s*(\S+)", RegexOptions.IgnoreCase)] private static partial Regex SerialRx();
    public static string? SerialNumber(string text) => SerialRx().Match(text) is { Success: true } m ? m.Groups[1].Value : null;

    [GeneratedRegex(@"^\s*\d+\s+interface\s+(\S+)", RegexOptions.Multiline | RegexOptions.IgnoreCase)] private static partial Regex ZoneMemberRx();

    /// <summary>`show zone WAN`: "No. Type Member / 1 interface ge2" rows to the member interfaces.</summary>
    public static HashSet<string> ZoneMembers(string text) =>
        new(ZoneMemberRx().Matches(ApplianceSsh.CleanTerminal(text)).Select(m => m.Groups[1].Value), StringComparer.OrdinalIgnoreCase);

    public sealed record VirtualServer(string Name, bool Active, string? Interface, bool OneToOne, string? OriginalIp, string? MappedIp, string? Protocol, string? OriginalPort, string? MappedPort);

    [GeneratedRegex(@"^\s*virtual server\s*:\s*(.+?)\s*$", RegexOptions.Multiline | RegexOptions.IgnoreCase)] private static partial Regex ServerHeaderRx();

    /// <summary>`show ip virtual-server`: one "virtual server: NAME" block of "key: value" lines per rule.</summary>
    public static List<VirtualServer> ParseVirtualServers(string text)
    {
        var clean = ApplianceSsh.CleanTerminal(text);
        var heads = ServerHeaderRx().Matches(clean).ToList();
        var list = new List<VirtualServer>();
        for (var i = 0; i < heads.Count; i++)
        {
            var start = heads[i].Index + heads[i].Length;
            var end = i + 1 < heads.Count ? heads[i + 1].Index : clean.Length;
            var kv = ParseKeyValues(clean[start..end]);
            string? V(string k) => kv.GetValueOrDefault(k) is { Length: > 0 } v ? v : null;
            list.Add(new VirtualServer(heads[i].Groups[1].Value, (V("active") ?? "yes").Equals("yes", StringComparison.OrdinalIgnoreCase), V("interface"),
                (V("NAT 1-1") ?? "no").Equals("yes", StringComparison.OrdinalIgnoreCase), V("original IP"), V("mapped IP"), V("protocol type"),
                V("original start port") is { } op ? op + (V("original end port") is { } oe && oe != op ? "-" + oe : "") : null,
                V("mapped start port") is { } mp ? mp + (V("mapped end port") is { } me && me != mp ? "-" + me : "") : null));
        }
        return list;
    }

    /// <summary>An active virtual server on a WAN interface mapping to a single address is internet exposure for that address.</summary>
    public static List<ExposureRecord> VirtualServerExposures(IEnumerable<VirtualServer> servers, HashSet<string> wan)
    {
        bool IsWan(string? iface) => iface is not null && (wan.Count > 0 ? wan.Contains(iface) : Regex.IsMatch(iface, @"^(wan\d*|ppp\d*)$", RegexOptions.IgnoreCase));
        var result = new List<ExposureRecord>();
        foreach (var v in servers)
        {
            if (!v.Active || !IsWan(v.Interface)) continue;
            var target = EdgeRecords.SingleHost(v.MappedIp);
            if (target is null) continue;
            var ports = v.OriginalPort is null ? "" : " " + (v.Protocol ?? "any") + " " + v.OriginalPort + " -> " + (v.MappedPort ?? v.OriginalPort);
            result.Add(new ExposureRecord(Exposure.Internet, (v.OneToOne ? "1:1 NAT " : "virtual server ") + v.Name + " on " + v.Interface + " (" + (v.OriginalIp ?? "any") + ")" + ports + " to " + target, IpAddress: target));
        }
        return result;
    }
}
