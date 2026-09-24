using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Firewalls;

/// <summary>
/// WatchGuard Firebox (T-series, M-series, FireboxV) over read-only SNMP. Fireware OS has no documented on-box read
/// API for configuration, so this adapter reads the Fireware version from the WatchGuard enterprise MIB
/// (wgSoftwareVersion, 1.3.6.1.4.1.3097.6.3.1; the first row is the running version) plus sysDescr, sysName and
/// sysObjectID. It does not see policies, NAT or which services listen on external interfaces: exposure for a
/// Firebox comes from the external cross-check or is set by hand.
///
/// Read-only: SNMP GET and GETNEXT only.
/// </summary>
public sealed class WatchGuardFireboxAdapter : IInventoryAdapter
{
    public const string SysDescr = "1.3.6.1.2.1.1.1.0";
    public const string SysObjectId = "1.3.6.1.2.1.1.2.0";
    public const string SysName = "1.3.6.1.2.1.1.5.0";
    public const string WgSoftwareVersion = "1.3.6.1.4.1.3097.6.3.1";

    private readonly ILogger _log;

    public WatchGuardFireboxAdapter(ILogger<WatchGuardFireboxAdapter>? log = null) { _log = log ?? NullLogger<WatchGuardFireboxAdapter>.Instance; }

    /// <summary>SNMP read (host, credentials, GET oids, GETNEXT columns). Tests replace it.</summary>
    public Func<string, IReadOnlyDictionary<string, string>, string[], string[], CancellationToken, Task<Dictionary<string, string>?>> Snmp { get; set; } =
        (host, c, gets, nexts, ct) => Adapters.Snmp.SnmpAdapter.QueryAsync(host, FwCreds.SnmpFields(c), gets, nexts, ct);

    public AdapterMetadata Metadata { get; } = new(
        Id: "watchguard-firebox",
        DisplayName: "WatchGuard Firebox (Fireware version over SNMP)",
        Vendor: "WatchGuard",
        Description: "Reads the Fireware OS version, model description and name of a Firebox over read-only SNMP (WatchGuard enterprise MIB). Fireware has no documented on-box read API for policies, so this connector does not see NAT or which services face the internet; the external cross-check covers that. Read-only.",
        Kinds: new[] { AssetKind.Firewall },
        Form: new[]
        {
            new CredentialField("host", "Firebox host", CredentialTypes.Text, "Address the console can reach on udp/161. Enable SNMP under System > SNMP (Fireware Web UI) and allow the console's address in the SNMP policy."),
        }.Concat(FwCreds.SnmpFormFields("Required: the Firebox's SNMP v2c community, or fill in the SNMPv3 fields.")).ToArray(),
        MinimumPermission: "a read-only SNMP v2c community or SNMPv3 user on the Firebox, with the console's address allowed by the SNMP policy",
        DocsUrl: "https://www.watchguard.com/help/docs/help-center/en-US/Content/en-US/Fireware/basicadmin/snmp_mibs_details_c.html",
        DefaultIntervalMinutes: 720);

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            var (host, values) = await ReadAsync(credentials, ct);
            if (values is null) return new TestResult(false, host + " did not answer SNMP (wrong community or user, SNMP disabled on the Firebox, or udp/161 not allowed from the console).");
            var (version, model) = Interpret(values);
            return new TestResult(true, host + ": " + (values.GetValueOrDefault(SysName) ?? "(no sysName)") + ", " + (model ?? "Firebox") + ", Fireware " + (version ?? "version not reported") + ".");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new TestResult(false, ex.Message);
        }
    }

    public async Task<CollectResult> CollectAsync(IReadOnlyDictionary<string, string> credentials, DateTime? since, IProgress<string>? progress, CancellationToken ct)
    {
        var r = new CollectResult { FullSnapshot = true };
        progress?.Report("Reading the Firebox over SNMP");
        var (host, values) = await ReadAsync(credentials, ct);
        if (values is null) throw new FirewallApiException("SNMP " + host, 0, "no answer on udp/161");
        var (version, model) = Interpret(values);
        if (version is null) r.Warnings.Add(host + ": neither wgSoftwareVersion nor sysDescr gave a Fireware version.");
        var name = values.GetValueOrDefault(SysName) is { Length: > 0 } n ? n : host;
        var ip = System.Net.IPAddress.TryParse(host, out _) ? host : null;
        r.Assets.Add(EdgeRecords.Firewall(host, name, new[] { ip }, Array.Empty<string>(), CnaNames.WatchGuard, CnaNames.Fireware, version, hostnames: new[] { name, ip is null ? host : null }));
        r.Software.AddRange(EdgeRecords.Firmware(host, CnaNames.WatchGuard, CnaNames.Fireware, version ?? "", "fireware", edition: model));
        _log.LogInformation("WatchGuard {Host}: Fireware {Version}", host, version);
        return r;
    }

    private async Task<(string Host, Dictionary<string, string>? Values)> ReadAsync(IReadOnlyDictionary<string, string> c, CancellationToken ct)
    {
        var host = FwCreds.HostOnly(FwCreds.Get(c, "host"));
        if (host.Length == 0) throw new InvalidOperationException("Firebox host is required");
        if (!FwCreds.HasSnmp(c)) throw new InvalidOperationException("Enter the SNMP community, or the SNMPv3 user and passwords");
        return (host, await Snmp(host, c, new[] { SysDescr, SysObjectId, SysName }, new[] { WgSoftwareVersion }, ct));
    }

    /// <summary>
    /// Fireware version from wgSoftwareVersion ("12.10.4.B698735" or "12.11.3 Build 718410" to "12.10.4" / "12.11.3"),
    /// falling back to a version in sysDescr; the model is sysDescr with any version text removed.
    /// </summary>
    public static (string? Version, string? Model) Interpret(IReadOnlyDictionary<string, string> v)
    {
        var descr = v.GetValueOrDefault(SysDescr);
        var version = EdgeVersions.Dotted(v.GetValueOrDefault(WgSoftwareVersion));
        if (version is null && descr is not null)
        {
            var mapped = Adapters.Snmp.SnmpDeviceMapper.Map(descr, v.GetValueOrDefault(SysObjectId));
            version = mapped.Vendor == "WatchGuard" && mapped.Version.Length > 0 ? mapped.Version : null;
        }
        var model = descr is null ? null : System.Text.RegularExpressions.Regex.Replace(descr, @"\s*(Fireware(\s+OS)?\s+)?v?\d+(\.\d+)+.*$", "").Trim();
        return (version, string.IsNullOrEmpty(model) ? null : model);
    }
}
