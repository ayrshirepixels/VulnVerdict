using System.Text.Json;
using System.Text.RegularExpressions;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Windows;

/// <summary>
/// Turns one collector JSON document into asset and software records. Pure: no I/O, so the fixture tests cover it.
/// Product names follow the Microsoft CNA spelling so the inventory mapping step gets exact hits where possible.
/// </summary>
public static partial class WindowsCollectorMapper
{
    public const string Vendor = "Microsoft";

    /// <summary>Map a collector document for the host typed as <paramref name="externalId"/> into <paramref name="result"/>. Returns the host's asset record.</summary>
    public static AssetRecord Map(string externalId, JsonElement root, CollectResult result)
    {
        var host = Prop(root, "host");
        var name = Str(host, "name") ?? externalId;
        var domain = Str(host, "domain");
        var productType = Str(host, "productType");
        var isDc = Bool(host, "isDomainController") ?? false;
        var isHv = Bool(host, "isHyperVHost") ?? false;
        var osBuild = Str(host, "osBuild") ?? Str(host, "osVersion") ?? "";
        var osProduct = OsProductName(Str(host, "osCaption"), Str(host, "displayVersion"), osBuild, Str(host, "installationType"));

        var hostnames = new List<string> { name };
        if (!string.IsNullOrWhiteSpace(domain) && !name.Contains('.')) hostnames.Add(name + "." + domain);
        var kind = isHv ? AssetKind.Hypervisor : productType is "WinNT" ? AssetKind.Endpoint : AssetKind.Server;
        var asset = new AssetRecord(externalId, name, kind, hostnames.ToArray(), Strings(host, "ips"), Strings(host, "macs").Select(NormaliseMac).ToArray(),
            Vendor, osProduct, osBuild, osBuild, isDc || isHv ? Criticality.Critical : null);
        result.Assets.Add(asset);

        foreach (var w in Strings(root, "warnings")) result.Warnings.Add(externalId + ": collector: " + w);

        // ---- lookups used by several sections
        var features = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in Arr(root, "features")) { var n = Str(f, "name"); if (n is not null) features[n] = Bool(f, "installed") ?? false; }
        var services = new Dictionary<string, (string Status, string StartType)>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in Arr(root, "services")) { var n = Str(s, "name"); if (n is not null) services[n] = (Str(s, "status") ?? "", Str(s, "startType") ?? ""); }
        bool? Feature(params string[] names)
        {
            var known = names.Where(features.ContainsKey).ToList();
            if (known.Count > 0) return known.Any(n => features[n]);
            return features.Count > 0 ? false : null;
        }
        bool? Running(string service) => services.TryGetValue(service, out var s) ? s.Status.Equals("Running", StringComparison.OrdinalIgnoreCase) : null;

        var listeners = Arr(root, "listeners").Select(l => new TcpListener(Str(l, "address") ?? "", Int(l, "port") ?? 0, Str(l, "process") ?? "", Str(l, "service") ?? "")).Where(l => l.Port > 0).ToList();
        var claimed = new HashSet<TcpListener>();

        // ---- the operating system itself (generic listeners are attached at the end)
        var osRecord = new SoftwareRecord(externalId, Vendor, osProduct, osBuild, SoftwareKind.OperatingSystem, ExternalId: "os");

        // ---- installed software from the Uninstall hives
        foreach (var s in Arr(root, "software"))
        {
            var display = Str(s, "name"); if (string.IsNullOrWhiteSpace(display)) continue;
            var version = Str(s, "version") ?? "";
            var (product, arch) = CleanProductName(display, version);
            result.Software.Add(new SoftwareRecord(externalId, Str(s, "publisher") ?? "", product, version, SoftwareKind.Application,
                Architecture: arch ?? Str(s, "arch"), ExternalId: "app:" + (Str(s, "arch") ?? "") + ":" + (Str(s, "key") ?? display)));
        }

        // ---- roles and features that decide reachability
        var smb1 = Bool(root, "smb1Enabled") ?? Feature("FS-SMB1", "FS-SMB1-Server", "SMB1Protocol", "SMB1Protocol-Server");
        if (smb1 is not null) result.Software.Add(Role(externalId, "Windows SMBv1", smb1.Value, "feature:smb1"));
        var webdav = Feature("Web-DAV-Publishing", "IIS-WebDAV");
        if (webdav is not null) result.Software.Add(Role(externalId, "WebDAV Publishing", webdav.Value, "feature:webdav"));
        var spooler = Running("Spooler");
        if (spooler is not null) result.Software.Add(Role(externalId, "Print Spooler", spooler.Value, "feature:spooler"));
        var rdp = Bool(root, "rdpEnabled");
        if (rdp is not null)
        {
            var rdpListeners = Take(listeners, claimed, l => l.Port == 3389 || l.Service.Contains("TermService", StringComparison.OrdinalIgnoreCase));
            var nla = Bool(root, "rdpNlaRequired");
            result.Software.Add(Role(externalId, "Remote Desktop Services", rdp.Value && (Running("TermService") ?? true), "feature:rdp", rdpListeners,
                nla is null ? null : nla.Value ? "NLA required" : "NLA not required"));
        }
        var iis = Prop(root, "iis");
        var iisVersion = Str(iis, "version");
        var w3svc = Running("W3SVC");
        var iisFeature = Feature("Web-Server", "Web-WebServer", "IIS-WebServer");
        if (iisVersion is not null || w3svc is not null || iisFeature is not null)
        {
            var enabled = w3svc ?? iisFeature ?? (iisVersion is not null);
            result.Software.Add(Role(externalId, "Internet Information Services", enabled, "feature:iis"));
            if (iisVersion is not null)
            {
                var bindings = new List<Listener>();
                var ports = new HashSet<int>();
                foreach (var site in Arr(iis, "sites"))
                {
                    var siteName = Str(site, "name") ?? "";
                    foreach (var b in Strings(site, "bindings"))
                    {
                        var l = ParseIisBinding(b, siteName);
                        if (l is null) continue;
                        bindings.Add(l); ports.Add(l.Port);
                    }
                }
                // http.sys owns IIS ports under pid 4 ("System"); claim those so they are not repeated on the OS record
                Take(listeners, claimed, l => ports.Contains(l.Port) && (l.Process.Equals("System", StringComparison.OrdinalIgnoreCase) || l.Process.Equals("w3wp", StringComparison.OrdinalIgnoreCase) || l.Process.Equals("inetinfo", StringComparison.OrdinalIgnoreCase)));
                result.Software.Add(new SoftwareRecord(externalId, Vendor, "Internet Information Services", iisVersion, SoftwareKind.Service, Enabled: enabled, ExternalId: "service:iis", Listeners: bindings.Count > 0 ? bindings.ToArray() : null));
            }
        }
        var hyperv = Feature("Hyper-V", "Microsoft-Hyper-V", "Microsoft-Hyper-V-All");
        if (isHv || hyperv is not null) result.Software.Add(Role(externalId, "Hyper-V", isHv || (hyperv ?? false), "feature:hyperv"));
        if (isDc) result.Software.Add(Role(externalId, "Active Directory Domain Services", true, "feature:adds"));

        // ---- SQL Server instances
        var sqlInstances = Arr(root, "sql").ToList();
        foreach (var s in sqlInstances)
        {
            var instance = Str(s, "instance") ?? "MSSQLSERVER";
            var version = Str(s, "patchLevel") ?? Str(s, "version") ?? "";
            var serviceName = instance.Equals("MSSQLSERVER", StringComparison.OrdinalIgnoreCase) ? "MSSQLSERVER" : "MSSQL$" + instance;
            var own = Take(listeners, claimed, l => l.Service.Split(',').Any(x => x.Equals(serviceName, StringComparison.OrdinalIgnoreCase)));
            if (own.Length == 0 && sqlInstances.Count == 1) own = Take(listeners, claimed, l => l.Process.Equals("sqlservr", StringComparison.OrdinalIgnoreCase));
            result.Software.Add(new SoftwareRecord(externalId, Vendor, SqlProductName(Str(s, "version")), version, SoftwareKind.Service,
                Enabled: Running(serviceName) ?? true, Edition: Str(s, "edition"), Architecture: Str(s, "arch"), ExternalId: "sql:" + instance,
                Listeners: own.Length > 0 ? own.Select(l => l.ToListener()).ToArray() : null));
        }

        // ---- .NET
        var dotnet = Prop(root, "dotnet");
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in Arr(dotnet, "runtimes"))
        {
            var rn = Str(r, "name"); var rv = Str(r, "version");
            if (rn is null || rv is null) continue;
            var product = DotnetProductName(rn, rv);
            if (product is null || !seen.Add(product + "|" + rv)) continue;
            result.Software.Add(new SoftwareRecord(externalId, Vendor, product, rv, SoftwareKind.Runtime, ExternalId: "runtime:" + rn + ":" + rv));
        }
        foreach (var sdk in Strings(dotnet, "sdks"))
        {
            var product = DotnetProductName("Microsoft.NETCore.App", sdk);
            if (product is null || !seen.Add(product + "|sdk|" + sdk)) continue;
            result.Software.Add(new SoftwareRecord(externalId, Vendor, product, sdk, SoftwareKind.Runtime, Edition: "SDK", ExternalId: "sdk:" + sdk));
        }
        foreach (var f in Arr(dotnet, "frameworks"))
        {
            var friendly = FrameworkVersion(Int(f, "release"), Str(f, "version"));
            if (friendly is null || !seen.Add("fx|" + friendly)) continue;
            result.Software.Add(new SoftwareRecord(externalId, Vendor, "Microsoft .NET Framework " + friendly, friendly, SoftwareKind.Runtime, ExternalId: "netfx:" + friendly));
        }

        // ---- everything still listening belongs to the OS record
        var rest = listeners.Where(l => !claimed.Contains(l)).Take(200).Select(l => l.ToListener()).ToArray();
        result.Software.Add(osRecord with { Listeners = rest.Length > 0 ? rest : null });

        // ---- Hyper-V guests: the coverage reconciliation set
        foreach (var vm in Arr(Prop(root, "hyperv"), "vms"))
        {
            var vmName = Str(vm, "name"); if (string.IsNullOrWhiteSpace(vmName)) continue;
            result.Assets.Add(new AssetRecord(externalId + "/vm/" + vmName, vmName, AssetKind.VirtualMachine, new[] { vmName },
                Strings(vm, "ips").Where(ip => !ip.StartsWith("fe80", StringComparison.OrdinalIgnoreCase)).ToArray(),
                Strings(vm, "macs").Select(NormaliseMac).Where(m => m != "00:00:00:00:00:00").ToArray()));
        }
        return asset;
    }

    // ------------------------------------------------------------------ naming rules

    private static readonly Dictionary<int, string> ServerBuilds = new()
    {
        [26100] = "Windows Server 2025", [25398] = "Windows Server 2022, 23H2 Edition", [20348] = "Windows Server 2022", [17763] = "Windows Server 2019",
        [14393] = "Windows Server 2016", [9600] = "Windows Server 2012 R2", [9200] = "Windows Server 2012", [7601] = "Windows Server 2008 R2",
    };
    private static readonly Dictionary<int, string> ClientVersions = new()
    {
        [26200] = "25H2", [26100] = "24H2", [22631] = "23H2", [22621] = "22H2", [22000] = "21H2", [19045] = "22H2", [19044] = "21H2",
        [19043] = "21H1", [19042] = "20H2", [19041] = "2004", [18363] = "1909", [18362] = "1903", [17763] = "1809", [17134] = "1803",
    };

    /// <summary>
    /// The Microsoft CNA product name for an OS: "Windows Server 2022", "Windows Server 2019 (Server Core installation)",
    /// "Windows 11 Version 24H2", "Windows 10 Version 22H2". Caption first, build number as the fallback.
    /// </summary>
    public static string OsProductName(string? caption, string? displayVersion, string? osBuild, string? installationType)
    {
        caption ??= "";
        var build = BuildNumber(osBuild);
        var isServer = caption.Contains("Server", StringComparison.OrdinalIgnoreCase) || installationType is "Server" or "Server Core";
        if (isServer)
        {
            string name;
            var m = ServerYear().Match(caption);
            if (m.Success) name = "Windows Server " + m.Groups[1].Value + (m.Groups[2].Success ? " R2" : "");
            else if (build is not null && ServerBuilds.TryGetValue(build.Value, out var byBuild)) name = byBuild;
            else name = "Windows Server";
            if (installationType is "Server Core") name += name.Contains("23H2") ? " (Server Core Installation)" : " (Server Core installation)";
            return name;
        }
        var major = build >= 22000 || caption.Contains("Windows 11", StringComparison.OrdinalIgnoreCase) ? "Windows 11" : "Windows 10";
        var version = displayVersion;
        if (string.IsNullOrWhiteSpace(version) && build is not null && ClientVersions.TryGetValue(build.Value, out var v)) version = v;
        return string.IsNullOrWhiteSpace(version) ? major : major + " Version " + version.Trim();
    }

    private static int? BuildNumber(string? osBuild)
    {
        if (osBuild is null) return null;
        var parts = osBuild.Split('.');
        if (parts.Length >= 3 && int.TryParse(parts[2], out var b)) return b;
        if (parts.Length == 1 && int.TryParse(parts[0], out b)) return b;
        return null;
    }

    /// <summary>"Microsoft SQL Server 2022 (GDR)" from the Setup Version major (16=2022, 15=2019, 14=2017, 13=2016).</summary>
    public static string SqlProductName(string? version)
    {
        var parts = (version ?? "").Split('.');
        if (!int.TryParse(parts.ElementAtOrDefault(0), out var major)) return "Microsoft SQL Server";
        var year = major switch
        {
            17 => "2025", 16 => "2022", 15 => "2019", 14 => "2017", 13 => "2016", 12 => "2014", 11 => "2012",
            10 => parts.ElementAtOrDefault(1) is "50" or "5" ? "2008 R2" : "2008", 9 => "2005", _ => null
        };
        return year is null ? "Microsoft SQL Server" : "Microsoft SQL Server " + year + " (GDR)";
    }

    /// <summary>Microsoft.NETCore.App 8.0.4 -> ".NET 8.0"; 3.1.x -> ".NET Core 3.1"; Microsoft.AspNetCore.App -> "ASP.NET Core 8.0"; WindowsDesktop shares the .NET name.</summary>
    public static string? DotnetProductName(string runtimeName, string version)
    {
        var parts = version.Split('.');
        if (parts.Length < 2 || !int.TryParse(parts[0], out var major)) return null;
        var mm = parts[0] + "." + parts[1];
        if (runtimeName.Equals("Microsoft.AspNetCore.App", StringComparison.OrdinalIgnoreCase)) return "ASP.NET Core " + mm;
        if (runtimeName.Equals("Microsoft.NETCore.App", StringComparison.OrdinalIgnoreCase) || runtimeName.Equals("Microsoft.WindowsDesktop.App", StringComparison.OrdinalIgnoreCase))
            return (major >= 5 ? ".NET " : ".NET Core ") + mm;
        return null;
    }

    /// <summary>NDP v4 Full "Release" to the marketing version; older NDP keys use their Version value. 2.0 and 3.0 are parts of 3.5 and are skipped.</summary>
    public static string? FrameworkVersion(int? release, string? version)
    {
        if (release is not null)
        {
            var r = release.Value;
            return r >= 533320 ? "4.8.1" : r >= 528040 ? "4.8" : r >= 461808 ? "4.7.2" : r >= 461308 ? "4.7.1" : r >= 460798 ? "4.7"
                 : r >= 394802 ? "4.6.2" : r >= 394254 ? "4.6.1" : r >= 393295 ? "4.6" : r >= 379893 ? "4.5.2" : r >= 378675 ? "4.5.1" : r >= 378389 ? "4.5" : version;
        }
        if (version is null) return null;
        if (version.StartsWith("2.0") || version.StartsWith("3.0")) return null;
        var p = version.Split('.');
        return p.Length >= 2 ? p[0] + "." + p[1] : version;
    }

    /// <summary>
    /// "7-Zip 26.02 (x64)" with version 26.02 -> ("7-Zip", "x64"). The trailing number is only removed when the
    /// version is known separately and starts with the same component, so "Java 8 Update 401" keeps its name.
    /// </summary>
    public static (string Product, string? Architecture) CleanProductName(string displayName, string? version)
    {
        var name = displayName.Trim();
        string? arch = null;
        // the architecture and the version can come in either order ("Python 3.12.4 (64-bit)", "... Redistributable (x64) - 14.38.33130")
        for (var pass = 0; pass < 2; pass++)
        {
            var am = ArchSuffix().Match(name);
            if (am.Success && am.Index > 0)
            {
                arch ??= am.Groups[1].Value.ToLowerInvariant() switch { "x64" or "64-bit" or "amd64" or "x86_64" => "x64", "arm64" => "arm64", _ => "x86" };
                name = name[..am.Index].TrimEnd(' ', '-', ',');
            }
            if (!string.IsNullOrWhiteSpace(version))
            {
                var vm = TrailingVersion().Match(name);
                if (vm.Success && vm.Index > 0)
                {
                    var tail = vm.Groups[1].Value;
                    var firstTail = tail.Split('.')[0]; var firstVer = version.Trim().TrimStart('v', 'V').Split('.')[0];
                    if (firstTail == firstVer) name = name[..vm.Index].TrimEnd(' ', '-', ',', '(');
                }
            }
        }
        return (name.Length == 0 ? displayName.Trim() : name, arch);
    }

    private static string NormaliseMac(string mac)
    {
        var hex = new string(mac.Where(Uri.IsHexDigit).ToArray());
        if (hex.Length != 12) return mac.Replace('-', ':').ToLowerInvariant();
        return string.Join(":", Enumerable.Range(0, 6).Select(i => hex.Substring(i * 2, 2))).ToLowerInvariant();
    }

    /// <summary>"https/*:443:www.example.com" or "http/*:80:" -> Listener(443, "https", "*/www.example.com").</summary>
    public static Listener? ParseIisBinding(string binding, string? site = null)
    {
        var slash = binding.IndexOf('/');
        if (slash <= 0) return null;
        var protocol = binding[..slash].ToLowerInvariant();
        if (protocol is not ("http" or "https")) return null;
        var info = binding[(slash + 1)..];
        // ip:port:host, where ip may be an IPv6 literal in brackets
        var lastColon = info.LastIndexOf(':');
        if (lastColon < 0) return null;
        var hostHeader = info[(lastColon + 1)..];
        var ipPort = info[..lastColon];
        var portColon = ipPort.LastIndexOf(':');
        if (portColon < 0 || !int.TryParse(ipPort[(portColon + 1)..], out var port)) return null;
        var ip = ipPort[..portColon];
        var bind = ip + (hostHeader.Length > 0 ? "/" + hostHeader : "");
        return new Listener(port, protocol, bind, string.IsNullOrEmpty(site) ? "w3wp" : "w3wp (" + site + ")");
    }

    // ------------------------------------------------------------------ helpers

    private sealed record TcpListener(string Address, int Port, string Process, string Service)
    {
        public Listener ToListener() => new(Port, "tcp", Address, Service.Length > 0 ? Process + " (" + Service + ")" : Process);
    }

    private static TcpListener[] Take(List<TcpListener> all, HashSet<TcpListener> claimed, Func<TcpListener, bool> pick)
    {
        var picked = all.Where(l => !claimed.Contains(l) && pick(l)).ToArray();
        foreach (var p in picked) claimed.Add(p);
        return picked;
    }

    private static SoftwareRecord Role(string asset, string product, bool enabled, string externalId, TcpListener[]? listeners = null, string? edition = null)
        => new(asset, Vendor, product, "", SoftwareKind.RoleOrFeature, Enabled: enabled, Edition: edition, ExternalId: externalId,
               Listeners: listeners is { Length: > 0 } ? listeners.Select(l => l.ToListener()).ToArray() : null);

    private static JsonElement Prop(JsonElement e, string name) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) ? v : default;
    private static string? Str(JsonElement e, string name)
    {
        var v = Prop(e, name);
        return v.ValueKind switch
        {
            JsonValueKind.String => string.IsNullOrWhiteSpace(v.GetString()) ? null : v.GetString()!.Trim(),
            JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False => v.GetRawText(),
            _ => null
        };
    }
    private static bool? Bool(JsonElement e, string name)
    {
        var v = Prop(e, name);
        return v.ValueKind switch { JsonValueKind.True => true, JsonValueKind.False => false, JsonValueKind.Number => v.GetInt64() != 0, _ => null };
    }
    private static int? Int(JsonElement e, string name)
    {
        var v = Prop(e, name);
        if (v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var i)) return i;
        if (v.ValueKind == JsonValueKind.String && int.TryParse(v.GetString(), out i)) return i;
        return null;
    }
    private static IEnumerable<JsonElement> Arr(JsonElement e, string name)
    {
        var v = Prop(e, name);
        if (v.ValueKind == JsonValueKind.Array) foreach (var x in v.EnumerateArray()) yield return x;
        else if (v.ValueKind == JsonValueKind.Object) yield return v; // ConvertTo-Json on PowerShell 5.1 can unwrap a one-element array
    }
    private static string[] Strings(JsonElement e, string name)
    {
        var v = Prop(e, name);
        if (v.ValueKind == JsonValueKind.String) return string.IsNullOrWhiteSpace(v.GetString()) ? Array.Empty<string>() : new[] { v.GetString()!.Trim() };
        if (v.ValueKind != JsonValueKind.Array) return Array.Empty<string>();
        return v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(x.GetString())).Select(x => x.GetString()!.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    [GeneratedRegex(@"Server[,\s]+(\d{4})(\s+R2)?", RegexOptions.IgnoreCase)] private static partial Regex ServerYear();
    [GeneratedRegex(@"[\s\-]*[\(\[]?(x64|x86|64-bit|32-bit|amd64|arm64|x86_64)[\)\]]?\s*$", RegexOptions.IgnoreCase)] private static partial Regex ArchSuffix();
    [GeneratedRegex(@"[\s\-]+v?(\d+(?:\.\d+)*)\s*$", RegexOptions.IgnoreCase)] private static partial Regex TrailingVersion();
}
