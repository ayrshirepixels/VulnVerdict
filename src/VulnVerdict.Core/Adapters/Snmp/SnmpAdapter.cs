using System.Net;
using Lextm.SharpSnmpLib;
using Lextm.SharpSnmpLib.Messaging;
using Lextm.SharpSnmpLib.Security;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Adapters.Discovery;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Snmp;

/// <summary>
/// Section 9.2 step 8: the management network over read-only SNMP. sysDescr, sysObjectID, sysName and a short
/// ifPhysAddress walk for non-Fortinet switches, printers, UPS, NAS and out-of-band management (iDRAC, iLO, IPMI).
/// Devices the mapper cannot name land in the needs-mapping queue on first sight and are tracked automatically after.
/// </summary>
public sealed class SnmpAdapter : IInventoryAdapter
{
    private const string SysDescr = "1.3.6.1.2.1.1.1.0";
    private const string SysObjectId = "1.3.6.1.2.1.1.2.0";
    private const string SysName = "1.3.6.1.2.1.1.5.0";
    private const string IfPhysAddress = "1.3.6.1.2.1.2.2.1.6";
    private const string SynologyVersion = "1.3.6.1.4.1.6574.1.5.3.0";
    private const int MaxTargets = 1024;
    private const int MaxMacRows = 32;
    private const int Concurrency = 16;

    private readonly ILogger<SnmpAdapter> _log;

    public SnmpAdapter(ILogger<SnmpAdapter> log) { _log = log; }

    public AdapterMetadata Metadata { get; } = new(
        Id: "snmp",
        DisplayName: "Management network devices (SNMP)",
        Vendor: "Any SNMP device",
        Description: "Reads sysDescr, sysObjectID and sysName (plus interface MAC addresses) from switches, printers, UPS, NAS and out-of-band controllers (iDRAC, iLO, IPMI) over SNMP v2c or v3. Vendor, product family and version are parsed from the description; anything the parser cannot name is mapped once through the needs-mapping queue and tracked automatically after that.",
        Kinds: new[] { AssetKind.Switch, AssetKind.Printer, AssetKind.Storage, AssetKind.OutOfBandManagement, AssetKind.NetworkDevice, AssetKind.AccessPoint, AssetKind.Server, AssetKind.Other },
        Form: new[]
        {
            new CredentialField("targets", "Targets", CredentialTypes.TextArea, "IP addresses, hostnames or CIDR ranges, one per line (for example 10.0.10.0/24 for the management VLAN)."),
            new CredentialField("version", "SNMP version", CredentialTypes.Text, "2c or 3", Required: false, Default: "2c"),
            new CredentialField("community", "Community (v2c)", CredentialTypes.Password, "Read-only community string.", Required: false),
            new CredentialField("username", "SNMPv3 user name", CredentialTypes.Text, null, Required: false),
            new CredentialField("authProtocol", "SNMPv3 authentication protocol", CredentialTypes.Text, "MD5, SHA or SHA256", Required: false, Default: "SHA"),
            new CredentialField("authPassword", "SNMPv3 authentication password", CredentialTypes.Password, null, Required: false),
            new CredentialField("privProtocol", "SNMPv3 privacy protocol", CredentialTypes.Text, "DES or AES; blank for authNoPriv", Required: false),
            new CredentialField("privPassword", "SNMPv3 privacy password", CredentialTypes.Password, null, Required: false),
            new CredentialField("timeoutMs", "Timeout (ms)", CredentialTypes.Number, null, Required: false, Default: "1500"),
        },
        MinimumPermission: "a read-only SNMP community (v2c) or a read-only SNMPv3 user",
        DefaultIntervalMinutes: 720);

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            var opts = Options.From(credentials);
            var warnings = new List<string>();
            var targets = AddressRanges.Expand(credentials.GetValueOrDefault("targets"), MaxTargets, warnings);
            if (targets.Count == 0) return new TestResult(false, warnings.Count > 0 ? string.Join("; ", warnings) : "No targets given.");
            var first = targets[0];
            var sys = await Task.Run(() => QuerySystem(first.Address, opts), ct);
            if (sys is null) return new TestResult(false, first.Text + " did not answer on udp/161 within " + opts.TimeoutMs + " ms (wrong community, SNMP disabled or filtered).");
            var device = SnmpDeviceMapper.Map(sys.Value.Descr, sys.Value.ObjectId);
            return new TestResult(true, first.Text + ": " + (sys.Value.Name ?? "(no sysName)") + ", " + (device.Vendor == "" ? "unknown vendor" : device.Vendor) + " " + device.Product + " " + device.Version + (device.Named ? "" : " (will need mapping)") + (targets.Count > 1 ? "; " + targets.Count + " targets in total" : ""));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { return new TestResult(false, ex.Message); }
    }

    public async Task<CollectResult> CollectAsync(IReadOnlyDictionary<string, string> credentials, DateTime? since, IProgress<string>? progress, CancellationToken ct)
    {
        var result = new CollectResult { FullSnapshot = true };
        var opts = Options.From(credentials);
        var targets = AddressRanges.Expand(credentials.GetValueOrDefault("targets"), MaxTargets, result.Warnings);
        if (targets.Count == 0) { result.Warnings.Add("No targets to query."); return result; }

        var answered = 0; var done = 0;
        var errors = new List<string>();
        var gate = new SemaphoreSlim(Concurrency);
        var tasks = targets.Select(async t =>
        {
            await gate.WaitAsync(ct);
            try
            {
                var dev = await Task.Run(() => QueryDevice(t, opts, errors), ct);
                if (dev is not null)
                {
                    lock (result)
                    {
                        answered++;
                        result.Assets.Add(dev.Value.Asset);
                        if (dev.Value.Software is not null) result.Software.Add(dev.Value.Software);
                    }
                }
            }
            finally
            {
                gate.Release();
                var n = Interlocked.Increment(ref done);
                if (n % 16 == 0 || n == targets.Count) progress?.Report("Queried " + n + " of " + targets.Count + " targets, " + answered + " answered");
            }
        }).ToList();
        await Task.WhenAll(tasks);

        result.Warnings.Add(answered + " of " + targets.Count + " targets answered SNMP.");
        lock (errors) result.Warnings.AddRange(errors.Distinct().Take(10));
        var unnamed = result.Software.Count(s => s.Vendor == "" || s.Product.EndsWith(" device"));
        if (unnamed > 0) result.Warnings.Add(unnamed + " device(s) could not be named from sysDescr and will appear in the needs-mapping queue.");
        _log.LogInformation("SNMP: {Answered} of {Targets} targets answered", answered, targets.Count);
        return result;
    }

    // ------------------------------------------------------------------ per device

    private (AssetRecord Asset, SoftwareRecord? Software)? QueryDevice(AddressRanges.Entry target, Options opts, List<string> errors)
    {
        (string? Descr, string? ObjectId, string? Name)? sys;
        try { sys = QuerySystem(target.Address, opts); }
        catch (Exception ex) { lock (errors) errors.Add(target.Text + ": " + ex.Message); return null; }
        if (sys is null) return null;

        var descr = sys.Value.Descr ?? "";
        var enterprise = SnmpDeviceMapper.EnterpriseNumber(sys.Value.ObjectId);
        if (enterprise == 6574)
        {
            // Synology keeps the DSM version in its private MIB, sysDescr is only the kernel line
            try { var v = Get(target.Address, opts, new[] { SynologyVersion }); if (v is not null && Text(v[0]) is { Length: > 0 } dsm) descr += " " + (dsm.StartsWith("DSM", StringComparison.OrdinalIgnoreCase) ? dsm : "DSM " + dsm); } catch { }
        }
        var device = SnmpDeviceMapper.Map(descr, sys.Value.ObjectId);

        var macs = new List<string>();
        try { macs = WalkMacs(target.Address, opts); } catch (Exception ex) { _log.LogDebug("ifPhysAddress walk failed for {Target}: {Error}", target.Text, ex.Message); }

        var hostnames = new List<string>();
        var name = sys.Value.Name?.Trim();
        if (!string.IsNullOrEmpty(name) && !IPAddress.TryParse(name, out _)) hostnames.Add(name);
        if (!IPAddress.TryParse(target.Text, out _) && !hostnames.Contains(target.Text, StringComparer.OrdinalIgnoreCase)) hostnames.Add(target.Text);

        var asset = new AssetRecord(target.Text, string.IsNullOrEmpty(name) ? target.Text : name!, device.Kind, hostnames.ToArray(), new[] { target.Address.ToString() }, macs.ToArray(),
            device.OsVendor, device.OsProduct, device.OsVersion, device.OsBuild);
        SoftwareRecord? software = device.Product == "" ? null : new SoftwareRecord(target.Text, device.Vendor, device.Product, device.Version, device.SoftwareKind);
        return (asset, software);
    }

    private static (string? Descr, string? ObjectId, string? Name)? QuerySystem(IPAddress ip, Options opts)
    {
        var vars = Get(ip, opts, new[] { SysDescr, SysObjectId, SysName });
        if (vars is null) return null;
        return (Text(vars[0]), vars[1].Data is ObjectIdentifier oid ? oid.ToString() : null, Text(vars[2]));
    }

    private static List<string> WalkMacs(IPAddress ip, Options opts)
    {
        var macs = new List<string>();
        var root = new ObjectIdentifier(IfPhysAddress);
        var current = root;
        for (var i = 0; i < MaxMacRows; i++)
        {
            var vars = GetNext(ip, opts, current);
            if (vars is null || vars.Count == 0) break;
            var v = vars[0];
            if (!v.Id.ToString().StartsWith(IfPhysAddress + ".") || v.Data is EndOfMibView) break;
            if (v.Data is OctetString os)
            {
                var raw = os.GetRaw();
                if (raw.Length == 6 && raw.Any(b => b != 0)) { var mac = string.Join(":", raw.Select(b => b.ToString("x2"))); if (!macs.Contains(mac)) macs.Add(mac); }
            }
            current = v.Id;
        }
        return macs;
    }

    // ------------------------------------------------------------------ SNMP plumbing

    /// <summary>GET the oids; null when the device does not answer within the timeout. Throws for authentication or protocol errors.</summary>
    private static IList<Variable>? Get(IPAddress ip, Options opts, string[] oids)
    {
        var ep = new IPEndPoint(ip, 161);
        var vars = oids.Select(o => new Variable(new ObjectIdentifier(o))).ToList();
        try
        {
            if (!opts.V3)
            {
                var reply = Messenger.Get(opts.Version, ep, new OctetString(opts.Community), vars, opts.TimeoutMs);
                return reply.Any(v => v.Data is NoSuchObject or NoSuchInstance or Null) && reply.All(v => v.Data is NoSuchObject or NoSuchInstance or Null) ? null : reply;
            }
            var (priv, report) = V3(ip, opts);
            var request = new GetRequestMessage(VersionCode.V3, Messenger.NextMessageId, Messenger.NextRequestId, new OctetString(opts.Username), OctetString.Empty, vars, priv, Messenger.MaxMessageSize, report);
            return Pdu(request.GetResponse(opts.TimeoutMs, ep)).Variables;
        }
        catch (Lextm.SharpSnmpLib.Messaging.TimeoutException) { return null; }
    }

    private static IList<Variable>? GetNext(IPAddress ip, Options opts, ObjectIdentifier oid)
    {
        var ep = new IPEndPoint(ip, 161);
        var vars = new List<Variable> { new(oid) };
        try
        {
            if (!opts.V3)
                return Pdu(new GetNextRequestMessage(Messenger.NextRequestId, opts.Version, new OctetString(opts.Community), vars).GetResponse(opts.TimeoutMs, ep)).Variables;
            var (priv, report) = V3(ip, opts);
            return Pdu(new GetNextRequestMessage(VersionCode.V3, Messenger.NextMessageId, Messenger.NextRequestId, new OctetString(opts.Username), OctetString.Empty, vars, priv, Messenger.MaxMessageSize, report).GetResponse(opts.TimeoutMs, ep)).Variables;
        }
        catch (Lextm.SharpSnmpLib.Messaging.TimeoutException) { return null; }
    }

    private static ISnmpPdu Pdu(ISnmpMessage reply)
    {
        if (reply is ReportMessage)
        {
            var reason = reply.Pdu().Variables.FirstOrDefault()?.Id.ToString() ?? "";
            throw new InvalidOperationException("SNMPv3 report " + reason + ": check the user name, authentication and privacy settings");
        }
        var pdu = reply.Pdu();
        var status = pdu.ErrorStatus.ToErrorCode();
        if (status != ErrorCode.NoError) throw new InvalidOperationException("SNMP error " + status);
        return pdu;
    }

    /// <summary>SNMPv3 engine discovery plus the auth/priv providers for this user.</summary>
    // MD5, SHA-1 and DES are weak, and they are still what many switches, printers and BMCs offer for SNMPv3;
    // the console only reads with them, and the form defaults to SHA and AES.
#pragma warning disable CS0618
    private static (IPrivacyProvider Privacy, ISnmpMessage Report) V3(IPAddress ip, Options opts)
    {
        var discovery = Messenger.GetNextDiscovery(SnmpType.GetRequestPdu);
        var report = discovery.GetResponse(opts.TimeoutMs, new IPEndPoint(ip, 161));
        IAuthenticationProvider auth = opts.AuthPassword == "" ? DefaultAuthenticationProvider.Instance : opts.AuthProtocol switch
        {
            "MD5" => new MD5AuthenticationProvider(new OctetString(opts.AuthPassword)),
            "SHA256" or "SHA-256" => new SHA256AuthenticationProvider(new OctetString(opts.AuthPassword)),
            "SHA384" or "SHA-384" => new SHA384AuthenticationProvider(new OctetString(opts.AuthPassword)),
            "SHA512" or "SHA-512" => new SHA512AuthenticationProvider(new OctetString(opts.AuthPassword)),
            _ => new SHA1AuthenticationProvider(new OctetString(opts.AuthPassword)),
        };
        IPrivacyProvider priv = opts.PrivPassword == "" || opts.AuthPassword == "" ? (opts.AuthPassword == "" ? DefaultPrivacyProvider.DefaultPair : new DefaultPrivacyProvider(auth)) : opts.PrivProtocol switch
        {
            "DES" => new DESPrivacyProvider(new OctetString(opts.PrivPassword), auth),
            "AES192" or "AES-192" => new AES192PrivacyProvider(new OctetString(opts.PrivPassword), auth),
            "AES256" or "AES-256" => new AES256PrivacyProvider(new OctetString(opts.PrivPassword), auth),
            _ => new AESPrivacyProvider(new OctetString(opts.PrivPassword), auth),
        };
        return (priv, report);
    }
#pragma warning restore CS0618

    private static string? Text(Variable v) => v.Data is OctetString os ? os.ToString().Replace("\0", "").Trim() : null;

    private sealed record Options(VersionCode Version, bool V3, string Community, string Username, string AuthProtocol, string AuthPassword, string PrivProtocol, string PrivPassword, int TimeoutMs)
    {
        public static Options From(IReadOnlyDictionary<string, string> c)
        {
            var version = (c.GetValueOrDefault("version") ?? "2c").Trim().ToLowerInvariant();
            var v3 = version is "3" or "v3";
            var code = version is "1" or "v1" ? VersionCode.V1 : v3 ? VersionCode.V3 : VersionCode.V2;
            var community = c.GetValueOrDefault("community") ?? "";
            var user = (c.GetValueOrDefault("username") ?? "").Trim();
            if (!v3 && community == "") throw new ArgumentException("A read-only community string is required for SNMP v2c.");
            if (v3 && user == "") throw new ArgumentException("An SNMPv3 user name is required for SNMP v3.");
            var timeout = int.TryParse(c.GetValueOrDefault("timeoutMs"), out var t) && t >= 200 ? Math.Min(t, 30000) : 1500;
            return new Options(code, v3, community, user, (c.GetValueOrDefault("authProtocol") ?? "SHA").Trim().ToUpperInvariant(), c.GetValueOrDefault("authPassword") ?? "",
                (c.GetValueOrDefault("privProtocol") ?? "").Trim().ToUpperInvariant(), c.GetValueOrDefault("privPassword") ?? "", timeout);
        }
    }
}
