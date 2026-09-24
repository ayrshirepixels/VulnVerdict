using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Adapters.Linux;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Firewalls;

/// <summary>
/// Netgate pfSense (CE and Plus) over SSH. pfSense has no official on-box REST API (the Nexus controller API needs
/// the multi-instance controller), so the adapter runs a handful of read-only commands: the version files, hostname,
/// ifconfig, and the configuration file (/conf/config.xml) for port forwards, 1:1 NAT and WAN rules that pass
/// traffic to the firewall itself.
///
/// Read-only: only cat, hostname and ifconfig are run; nothing is written and no configuration command is used.
/// </summary>
public sealed partial class PfSenseAdapter : IInventoryAdapter
{
    public const string VersionCommand = "cat /etc/version";
    public const string PatchCommand = "cat /etc/version.patch";
    public const string HostnameCommand = "hostname";
    public const string IfconfigCommand = "ifconfig -a";
    public const string ConfigCommand = "cat /conf/config.xml";

    private readonly ILogger _log;

    public PfSenseAdapter(ILogger<PfSenseAdapter>? log = null) { _log = log ?? NullLogger<PfSenseAdapter>.Instance; }

    /// <summary>Opens the SSH session; tests substitute a fake.</summary>
    public Func<SshTarget, SshConnectionOptions, CancellationToken, Task<ISshSession>> SessionFactory { get; set; } =
        (t, o, ct) => ApplianceSsh.ConnectAsync(t, o, SshMode.Exec, ct);

    public AdapterMetadata Metadata { get; } = new(
        Id: "pfsense",
        DisplayName: "pfSense firewall (SSH: version, NAT exposure)",
        Vendor: "Netgate",
        Description: "Connects to a pfSense CE or pfSense Plus firewall over SSH and reads the version, hostname, interface addresses and the configuration file for port forwards, 1:1 NAT and WAN rules to the firewall itself (web GUI, SSH, VPN). pfSense has no official on-box REST API. Most pfSense CVEs are published with vendor and product 'n/a', so expect few automatic matches and use Needs mapping or the watchlist. Read-only.",
        Kinds: new[] { AssetKind.Firewall },
        Form: ApplianceSsh.FormFields("pfSense",
            "An account with the 'User - System: Shell account access' privilege. Reading /conf/config.xml (for exposure) needs an account in the admins group; with a shell-only account the version is still read."),
        MinimumPermission: "an SSH account with shell access (version only), or an admins-group account to read the configuration file for exposure; commands are read-only (cat, hostname, ifconfig)",
        DocsUrl: "https://docs.netgate.com/pfsense/en/latest/usermanager/privileges.html",
        DefaultIntervalMinutes: 240);

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            using var s = await SessionFactory(ApplianceSsh.Target(credentials), ApplianceSsh.Options(credentials), ct);
            var (product, version) = ParseVersion((await s.RunAsync(VersionCommand, ct)).Output, (await s.RunAsync(PatchCommand, ct)).Output);
            if (version is null) return new TestResult(false, "Connected, but /etc/version could not be read: is this pfSense, and does the account have shell access?");
            var config = await s.RunAsync(ConfigCommand, ct);
            var msg = "Connected: " + product + " " + version + "." + (config.Ok && config.Output.Contains("<pfsense", StringComparison.Ordinal) ? " Configuration readable." : " The configuration file is not readable by this account: exposure will not be collected.");
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
        var (product, version) = ParseVersion((await s.RunAsync(VersionCommand, ct)).Output, (await s.RunAsync(PatchCommand, ct)).Output);
        if (version is null) throw new FirewallApiException(VersionCommand, 0, "/etc/version could not be read: is this pfSense, and does the account have shell access?");
        var hostname = (await s.RunAsync(HostnameCommand, ct)).Output.Trim().Split('\n')[0].Trim();
        var (ips, macs) = ParseIfconfig((await s.RunAsync(IfconfigCommand, ct)).Output);

        progress?.Report("Reading configuration");
        var cfg = await s.RunAsync(ConfigCommand, ct);
        XElement? config = null;
        if (cfg.Ok && cfg.Output.Contains("<pfsense", StringComparison.Ordinal))
        {
            try { config = XElement.Parse(cfg.Output); }
            catch (System.Xml.XmlException ex) { r.Warnings.Add("config.xml could not be parsed: " + ex.Message); }
        }
        else r.Warnings.Add("config.xml is not readable by this account (" + (cfg.Error.Trim() is { Length: > 0 } e ? e : "exit " + cfg.ExitStatus) + "); exposure not collected.");

        var id = hostname.Length > 0 ? hostname : target.Host;
        var device = new DeviceExposure();
        if (config is not null)
        {
            var sys = config.Element("system");
            var name = sys?.Element("hostname")?.Value.Trim();
            var domain = sys?.Element("domain")?.Value.Trim();
            if (!string.IsNullOrEmpty(name)) hostname = string.IsNullOrEmpty(domain) ? name : name + "." + domain;
            foreach (var svc in SelfServices(config)) device.Add(svc.Port, svc.Protocol, svc.Interface, svc.Label, !svc.Restricted, svc.Evidence);
            r.Exposures.AddRange(NatExposures(config));
        }
        var display = hostname.Length > 0 ? hostname.Split('.')[0] : target.Host;
        r.Assets.Add(EdgeRecords.Firewall(id, display, ips, macs, CnaNames.Netgate, product, version, hostnames: new[] { hostname, display }));
        r.Software.AddRange(EdgeRecords.Firmware(id, CnaNames.Netgate, product, version, "pfsense", listeners: device.Listeners, kind: SoftwareKind.OperatingSystem));
        if (device.Record(id) is { } self) r.Exposures.Add(self);
        _log.LogInformation("pfSense {Host}: {Product} {Version}, {Exposures} exposure records", id, product, version, r.Exposures.Count);
        return r;
    }

    // ------------------------------------------------------------------ parsing

    [GeneratedRegex(@"^\s*(\d+(?:\.\d+)+)", RegexOptions.Multiline)] private static partial Regex VersionRx();

    /// <summary>
    /// "/etc/version" ("2.7.2-RELEASE" or "24.11-RELEASE") and "/etc/version.patch" ("0", "1") to the product and version.
    /// CE numbers releases 2.x; Plus numbers them YY.MM (21.02 onwards).
    /// </summary>
    public static (string Product, string? Version) ParseVersion(string versionFile, string patchFile)
    {
        var m = VersionRx().Match(versionFile);
        if (!m.Success) return (CnaNames.PfSenseCe, null);
        var v = m.Groups[1].Value;
        var plus = int.TryParse(v.Split('.')[0], out var major) && major >= 21;
        if (int.TryParse(patchFile.Trim(), out var patch) && patch > 0) v += "-p" + patch;
        return (plus ? CnaNames.PfSensePlus : CnaNames.PfSenseCe, v);
    }

    [GeneratedRegex(@"^\s+inet\s+(\d+\.\d+\.\d+\.\d+)", RegexOptions.Multiline)] private static partial Regex InetRx();
    [GeneratedRegex(@"^\s+ether\s+([0-9a-f:]{17})", RegexOptions.Multiline | RegexOptions.IgnoreCase)] private static partial Regex EtherRx();

    public static (List<string> Ips, List<string> Macs) ParseIfconfig(string text) =>
        (InetRx().Matches(text).Select(m => m.Groups[1].Value).Where(EdgeRecords.IsUsableIp).Distinct().ToList(),
         EtherRx().Matches(text).Select(m => m.Groups[1].Value.ToLowerInvariant()).Distinct().ToList());

    /// <summary>A service on the firewall a WAN rule lets through. Restricted: the rule only admits named sources, so it is a listener, not internet exposure.</summary>
    public sealed record SelfService(int Port, string Protocol, string Interface, string Label, string Evidence, bool Restricted = false);

    /// <summary>Interfaces that face the internet: wan, plus any interface with a gateway set.</summary>
    public static HashSet<string> WanInterfaces(XElement config)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "wan" };
        foreach (var i in config.Element("interfaces")?.Elements() ?? Enumerable.Empty<XElement>())
            if (!string.IsNullOrWhiteSpace(i.Element("gateway")?.Value)) set.Add(i.Name.LocalName);
        return set;
    }

    private static string? Network(XElement? side) => side?.Element("network")?.Value.Trim() ?? side?.Element("address")?.Value.Trim() ?? (side?.Element("any") is not null ? "any" : null);

    /// <summary>Enabled pass rules on a WAN interface whose destination is the firewall itself ((self) or the WAN address).</summary>
    public static List<SelfService> SelfServices(XElement config)
    {
        var wan = WanInterfaces(config);
        var sys = config.Element("system");
        var guiPort = int.TryParse(sys?.Element("webgui")?.Element("port")?.Value, out var gp) ? gp : (sys?.Element("webgui")?.Element("protocol")?.Value == "http" ? 80 : 443);
        var sshPort = int.TryParse(sys?.Element("ssh")?.Element("port")?.Value, out var sp) ? sp : 22;
        var vpnPorts = (config.Element("openvpn")?.Elements("openvpn-server") ?? Enumerable.Empty<XElement>())
            .Where(o => o.Element("disable") is null).Select(o => int.TryParse(o.Element("local_port")?.Value, out var p) ? p : 0).Where(p => p > 0).ToHashSet();
        var list = new List<SelfService>();
        foreach (var rule in config.Element("filter")?.Elements("rule") ?? Enumerable.Empty<XElement>())
        {
            if (rule.Element("disabled") is not null || (rule.Element("type")?.Value ?? "pass") != "pass") continue;
            var iface = (rule.Element("interface")?.Value ?? "").Split(',').FirstOrDefault(wan.Contains);
            if (iface is null) continue;
            var dest = Network(rule.Element("destination"));
            if (dest is not ("(self)" or "wanip") && !(dest ?? "").Equals(iface + "ip", StringComparison.OrdinalIgnoreCase)) continue;
            var portText = rule.Element("destination")?.Element("port")?.Value.Trim() ?? "";
            var port = int.TryParse(portText.Split('-', ':')[0], out var p) ? p : 0;
            var proto = (rule.Element("protocol")?.Value ?? "any").ToLowerInvariant();
            var label = port == guiPort ? "web GUI" : port == sshPort ? "SSH" : vpnPorts.Contains(port) ? "OpenVPN" : port == 0 ? "any service" : "port " + port;
            var source = Network(rule.Element("source")) ?? "any";
            var restricted = source != "any";
            list.Add(new SelfService(port, proto == "udp" ? "udp" : "tcp", iface, label,
                label + " allowed from " + (restricted ? source : "the internet") + " on " + iface + " by rule '" + (rule.Element("descr")?.Value.Trim() ?? "?") + "' (" + proto + " " + (portText.Length > 0 ? portText : "any") + ")", restricted));
        }
        return list;
    }

    /// <summary>
    /// Enabled port forwards on a WAN interface to a single host, when a filter rule lets them through (an associated
    /// rule, "pass", or a WAN pass rule to the target); enabled 1:1 NAT on a WAN interface with a WAN pass rule to the inside host.
    /// </summary>
    public static List<ExposureRecord> NatExposures(XElement config)
    {
        var wan = WanInterfaces(config);
        var nat = config.Element("nat");
        var rules = config.Element("filter")?.Elements("rule").Where(r => r.Element("disabled") is null && (r.Element("type")?.Value ?? "pass") == "pass").ToList() ?? new();
        var result = new List<ExposureRecord>();
        foreach (var pf in nat?.Elements("rule") ?? Enumerable.Empty<XElement>())
        {
            if (pf.Element("disabled") is not null || pf.Element("nordr") is not null) continue;
            var iface = (pf.Element("interface")?.Value ?? "").Split(',').FirstOrDefault(wan.Contains);
            var target = EdgeRecords.SingleHost(pf.Element("target")?.Value);
            if (iface is null || target is null) continue;
            var assoc = pf.Element("associated-rule-id")?.Value.Trim() ?? "";
            var passed = assoc == "pass"
                || (assoc.Length > 0 && rules.Any(r => r.Element("associated-rule-id")?.Value.Trim() == assoc))
                || rules.Any(r => (r.Element("interface")?.Value ?? "").Split(',').Contains(iface) && Network(r.Element("destination")) == target);
            if (!passed) continue;
            var dest = pf.Element("destination");
            result.Add(new ExposureRecord(Exposure.Internet,
                "port forward '" + (pf.Element("descr")?.Value.Trim() ?? "?") + "' on " + iface + " " + (pf.Element("protocol")?.Value ?? "any") + " " + (Network(dest) ?? "any") + ":" + (dest?.Element("port")?.Value ?? "any") + " -> " + target + ":" + (pf.Element("local-port")?.Value ?? "?"),
                IpAddress: target));
        }
        foreach (var o in nat?.Elements("onetoone") ?? Enumerable.Empty<XElement>())
        {
            if (o.Element("disabled") is not null) continue;
            var iface = o.Element("interface")?.Value ?? "wan";
            var inside = EdgeRecords.SingleHost(o.Element("source")?.Element("address")?.Value);
            if (!wan.Contains(iface) || inside is null) continue;
            if (!rules.Any(r => (r.Element("interface")?.Value ?? "").Split(',').Contains(iface) && Network(r.Element("destination")) == inside)) continue;
            result.Add(new ExposureRecord(Exposure.Internet, "1:1 NAT '" + (o.Element("descr")?.Value.Trim() ?? "?") + "' on " + iface + " " + (o.Element("external")?.Value ?? "?") + " <-> " + inside, IpAddress: inside));
        }
        return result;
    }
}
