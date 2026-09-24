using System.Text.Json;
using System.Text.RegularExpressions;

namespace VulnVerdict.Core.Adapters.Fortinet;

/// <summary>An HTTP call to a Fortinet API failed. The message never contains credentials.</summary>
public sealed class FortinetApiException : Exception
{
    public string Path { get; }
    public int Status { get; }
    public FortinetApiException(string path, int status, string detail) : base(path + ": HTTP " + status + (detail.Length > 0 ? " " + detail : ""))
    {
        Path = path; Status = status;
    }
}

/// <summary>Credential-form access shared by the Fortinet adapters.</summary>
internal static class FortinetCreds
{
    public static string Get(IReadOnlyDictionary<string, string> creds, string key) => creds.TryGetValue(key, out var v) && v is not null ? v.Trim() : "";

    public static bool Bool(IReadOnlyDictionary<string, string> creds, string key, bool dflt)
    {
        var v = Get(creds, key);
        if (v.Length == 0) return dflt;
        return v.Equals("true", StringComparison.OrdinalIgnoreCase) || v == "1" || v.Equals("yes", StringComparison.OrdinalIgnoreCase) || v.Equals("on", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>"https://ems.example.local/" or "ems.example.local:8443" to "ems.example.local[:port]".</summary>
    public static string Host(string raw)
    {
        var h = raw.Trim();
        if (h.Contains("://", StringComparison.Ordinal)) h = h[(h.IndexOf("://", StringComparison.Ordinal) + 3)..];
        var slash = h.IndexOf('/');
        if (slash >= 0) h = h[..slash];
        return h;
    }
}

/// <summary>Tolerant JSON accessors and string helpers for FortiOS and EMS responses.</summary>
public static partial class FortinetJson
{
    public static JsonElement Parse(string json) => JsonSerializer.Deserialize<JsonElement>(json);

    public static string? Str(JsonElement e, params string[] names)
    {
        if (e.ValueKind != JsonValueKind.Object) return null;
        foreach (var n in names)
        {
            if (!e.TryGetProperty(n, out var v)) continue;
            switch (v.ValueKind)
            {
                case JsonValueKind.String:
                    var s = v.GetString();
                    if (!string.IsNullOrWhiteSpace(s)) return s.Trim();
                    break;
                case JsonValueKind.Number: return v.GetRawText();
                case JsonValueKind.True: return "true";
                case JsonValueKind.False: return "false";
            }
        }
        return null;
    }

    public static int? Int(JsonElement e, params string[] names)
    {
        if (e.ValueKind != JsonValueKind.Object) return null;
        foreach (var n in names)
        {
            if (!e.TryGetProperty(n, out var v)) continue;
            if (v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out var i)) return i;
            if (v.ValueKind == JsonValueKind.String && int.TryParse(v.GetString(), out var j)) return j;
        }
        return null;
    }

    /// <summary>FortiOS "enable"/"disable" flags, also true/false.</summary>
    public static bool Enabled(JsonElement e, string name, bool dflt)
    {
        var s = Str(e, name);
        if (s is null) return dflt;
        return s.Equals("enable", StringComparison.OrdinalIgnoreCase) || s.Equals("true", StringComparison.OrdinalIgnoreCase) || s == "1" || s.Equals("up", StringComparison.OrdinalIgnoreCase);
    }

    public static IEnumerable<JsonElement> Array(JsonElement e, string name)
    {
        if (e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array)
            foreach (var item in v.EnumerateArray()) yield return item;
    }

    /// <summary>FortiOS member lists: [{"name":"wan1"}] or ["wan1"] or "wan1 wan2".</summary>
    public static List<string> Names(JsonElement e, string name)
    {
        var list = new List<string>();
        if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(name, out var v)) return list;
        if (v.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in v.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String) { var s = item.GetString(); if (!string.IsNullOrWhiteSpace(s)) list.Add(s.Trim()); }
                else if (item.ValueKind == JsonValueKind.Object) { var s = Str(item, "name", "q_origin_key", "range"); if (s is not null) list.Add(s); }
            }
        }
        else if (v.ValueKind == JsonValueKind.String) list.AddRange(SplitList(v.GetString()));
        return list;
    }

    public static string[] SplitList(string? s) => string.IsNullOrWhiteSpace(s)
        ? System.Array.Empty<string>()
        : s.Split(new[] { ',', ';', ' ', '\t', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    [GeneratedRegex(@"v(\d+(?:\.\d+)*)", RegexOptions.IgnoreCase)] private static partial Regex VersionRx();
    [GeneratedRegex(@"^\d+(?:\.\d+)*")] private static partial Regex LeadingVersionRx();

    /// <summary>"v7.2.5" / "S124EF-v7.4.11-build2878 (GA)" / "FP221E-v6.4-build0460" to "7.2.5" / "7.4.11" / "6.4".</summary>
    public static string? FirmwareVersion(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        var m = VersionRx().Match(s);
        if (m.Success) return m.Groups[1].Value;
        var l = LeadingVersionRx().Match(s.Trim());
        return l.Success ? l.Value : null;
    }

    /// <summary>Model prefix of a FortiSwitch/FortiAP image name: "S124EF-v7.4.11-build2878" to "S124EF".</summary>
    public static string? ImageModel(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        var i = s.IndexOf("-v", StringComparison.OrdinalIgnoreCase);
        return i > 0 ? s[..i] : null;
    }

    [GeneratedRegex(@"\s+v?\d+(?:\.\d+)+.*$", RegexOptions.IgnoreCase)] private static partial Regex TrailingVersionRx();
    [GeneratedRegex(@"\s*\((?:x64|x86|64-bit|32-bit|64 bit|32 bit|arm64)[^)]*\)\s*$", RegexOptions.IgnoreCase)] private static partial Regex ArchSuffixRx();

    /// <summary>"Google Chrome 128.0.6613.84" to "Google Chrome"; "7-Zip 23.01 (x64)" to "7-Zip"; "Adobe Acrobat (64-bit)" to "Adobe Acrobat".</summary>
    public static string StripVersion(string name)
    {
        var t = ArchSuffixRx().Replace(name.Trim(), "");
        t = TrailingVersionRx().Replace(t, "");
        t = ArchSuffixRx().Replace(t, "");
        return t.Trim().TrimEnd('-', ',').Trim();
    }

    /// <summary>First three numeric components: "7.2.4.0933" to "7.2.4".</summary>
    public static string ShortVersion(string? v, int parts = 3)
    {
        if (string.IsNullOrWhiteSpace(v)) return "";
        var m = LeadingVersionRx().Match(v.Trim().TrimStart('v', 'V'));
        if (!m.Success) return v.Trim();
        var comps = m.Value.Split('.');
        return string.Join(".", comps.Take(parts));
    }

    /// <summary>FortiOS "192.0.2.10 255.255.255.0" or "192.0.2.10/24" to the address; null for unset.</summary>
    public static string? FirstIp(string? s)
    {
        if (string.IsNullOrWhiteSpace(s)) return null;
        var ip = s.Split(new[] { ' ', '/' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        return ip is null || ip == "0.0.0.0" || ip == "::" ? null : ip;
    }

    /// <summary>The single host of a FortiOS address, or null when it covers more than one host.</summary>
    public static string? SingleHost(JsonElement addr)
    {
        var type = Str(addr, "type") ?? "ipmask";
        if (type.Equals("ipmask", StringComparison.OrdinalIgnoreCase))
        {
            var subnet = Str(addr, "subnet");
            if (subnet is null) return null;
            var parts = subnet.Split(new[] { ' ', '/' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) return parts.Length == 1 ? parts[0] : null;
            return parts[1] is "255.255.255.255" or "32" ? parts[0] : null;
        }
        if (type.Equals("iprange", StringComparison.OrdinalIgnoreCase))
        {
            var start = Str(addr, "start-ip"); var end = Str(addr, "end-ip");
            return start is not null && (end is null || end == start) ? start : null;
        }
        return null;
    }

    public static bool IsZeroMac(string? mac) => string.IsNullOrWhiteSpace(mac) || mac.Replace(":", "").Replace("-", "").Trim('0').Length == 0;
}

/// <summary>Operating-system strings as EMS reports them, normalised to the names the CNAs use.</summary>
public static partial class FortinetOsNames
{
    public sealed record Os(string? Vendor, string Product, string? Version, string? Build, string Family);

    private static readonly Dictionary<int, string> Windows11 = new() { [22000] = "21H2", [22621] = "22H2", [22631] = "23H2", [26100] = "24H2", [26200] = "25H2" };
    private static readonly Dictionary<int, string> Windows10 = new()
    {
        [10240] = "1507", [10586] = "1511", [14393] = "1607", [15063] = "1703", [16299] = "1709", [17134] = "1803", [17763] = "1809",
        [18362] = "1903", [18363] = "1909", [19041] = "2004", [19042] = "20H2", [19043] = "21H1", [19044] = "21H2", [19045] = "22H2"
    };
    private static readonly Dictionary<int, string> WindowsServer = new() { [9200] = "2012", [9600] = "2012 R2", [14393] = "2016", [17763] = "2019", [20348] = "2022", [26100] = "2025" };
    private static readonly (string Key, string Vendor, string Product)[] Linux =
    {
        ("ubuntu", "Canonical", "Ubuntu"), ("debian", "Debian", "Debian"), ("red hat", "Red Hat", "Red Hat Enterprise Linux"), ("rhel", "Red Hat", "Red Hat Enterprise Linux"),
        ("centos", "CentOS", "CentOS"), ("rocky", "Rocky Enterprise Software Foundation", "Rocky Linux"), ("almalinux", "AlmaLinux", "AlmaLinux"), ("alma linux", "AlmaLinux", "AlmaLinux"),
        ("fedora", "Fedora Project", "Fedora"), ("opensuse", "openSUSE", "openSUSE Leap"), ("suse", "SUSE", "SUSE Linux Enterprise Server"), ("oracle linux", "Oracle", "Oracle Linux"),
        ("amazon linux", "Amazon", "Amazon Linux"), ("linux mint", "Linux Mint", "Linux Mint"), ("linux", null!, "Linux")
    };

    [GeneratedRegex(@"build\s*(\d{4,6})(?:\.(\d+))?", RegexOptions.IgnoreCase)] private static partial Regex BuildRx();
    [GeneratedRegex(@"server\s+(\d{4})(\s*R2)?", RegexOptions.IgnoreCase)] private static partial Regex ServerYearRx();
    [GeneratedRegex(@"windows\s+(\d+(?:\.\d+)?)", RegexOptions.IgnoreCase)] private static partial Regex WindowsMajorRx();
    [GeneratedRegex(@"(\d+\.\d+(?:\.\d+)*)")] private static partial Regex DottedRx();

    /// <summary>Map an EMS os_version text (plus optional os_type) to vendor, CNA product name, version and build.</summary>
    public static Os Parse(string? text, string? osType = null)
    {
        var t = (text ?? "").Trim();
        var type = (osType ?? "").Trim().ToLowerInvariant();
        if (t.Contains("windows", StringComparison.OrdinalIgnoreCase) || type.StartsWith("win"))
            return Windows(t);
        if (t.Contains("mac", StringComparison.OrdinalIgnoreCase) || t.Contains("os x", StringComparison.OrdinalIgnoreCase) || type is "mac" or "macos" or "darwin" or "osx")
        {
            var v = DottedRx().Match(t);
            return new Os("Apple", "macOS", v.Success ? v.Value : null, null, "macos");
        }
        foreach (var (key, vendor, product) in Linux)
        {
            if (!t.Contains(key, StringComparison.OrdinalIgnoreCase)) continue;
            var v = DottedRx().Match(t);
            return new Os(vendor, product, v.Success ? v.Value : null, null, "linux");
        }
        if (type is "linux")
        {
            var v = DottedRx().Match(t);
            return new Os(null, t.Length > 0 ? t : "Linux", v.Success ? v.Value : null, null, "linux");
        }
        if (type is "ios" or "iphone" or "ipad") return new Os("Apple", "iOS", DottedRx().Match(t) is { Success: true } m ? m.Value : null, null, "ios");
        if (type is "android") return new Os("Google", "Android", DottedRx().Match(t) is { Success: true } m2 ? m2.Value : null, null, "android");
        return new Os(null, t.Length > 0 ? t : "Unknown", null, null, "other");
    }

    private static Os Windows(string t)
    {
        var bm = BuildRx().Match(t);
        int? build = bm.Success ? int.Parse(bm.Groups[1].Value) : null;
        var ubr = bm.Success && bm.Groups[2].Success ? bm.Groups[2].Value : null;
        var version = NtVersion(build, ubr);
        if (t.Contains("server", StringComparison.OrdinalIgnoreCase))
        {
            var ym = ServerYearRx().Match(t);
            string product;
            if (ym.Success) product = "Windows Server " + ym.Groups[1].Value + (ym.Groups[2].Success ? " R2" : "");
            else if (build is not null && WindowsServer.TryGetValue(build.Value, out var year)) product = "Windows Server " + year;
            else product = "Windows Server";
            return new Os("Microsoft", product, version, build?.ToString(), "windows-server");
        }
        var mm = WindowsMajorRx().Match(t);
        var name = mm.Success ? "Windows " + mm.Groups[1].Value : "Windows";
        if (build is >= 22000)
        {
            name = "Windows 11";
            if (Windows11.TryGetValue(build.Value, out var v11)) name += " Version " + v11;
        }
        else if (build is >= 10240)
        {
            name = "Windows 10";
            if (Windows10.TryGetValue(build.Value, out var v10)) name += " Version " + v10;
        }
        return new Os("Microsoft", name, version, build?.ToString(), "windows");
    }

    private static string? NtVersion(int? build, string? ubr)
    {
        if (build is null) return null;
        var b = build.Value;
        var prefix = b >= 10240 ? "10.0" : b >= 9600 ? "6.3" : b >= 9200 ? "6.2" : b >= 7600 ? "6.1" : "6.0";
        return prefix + "." + b + (ubr is not null ? "." + ubr : "");
    }
}
