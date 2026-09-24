using System.Text.RegularExpressions;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Discovery;

/// <summary>
/// Turns the few banners a discovery sweep is allowed to read (SSH identification line, HTTP Server header, Shodan
/// product strings) into software records with the CNA vendor and product name where the mapping is certain.
/// Anything else keeps its raw product name and an empty vendor so the needs-mapping queue shows it.
/// </summary>
public static class BannerParser
{
    private static readonly Dictionary<string, (string Vendor, string Product)> Servers = new(StringComparer.OrdinalIgnoreCase)
    {
        ["nginx"] = ("F5", "NGINX Open Source"),
        ["apache"] = ("Apache Software Foundation", "Apache HTTP Server"),
        ["apache httpd"] = ("Apache Software Foundation", "Apache HTTP Server"),
        ["apache-coyote"] = ("Apache Software Foundation", "Apache Tomcat"),
        ["apache tomcat"] = ("Apache Software Foundation", "Apache Tomcat"),
        ["microsoft-iis"] = ("Microsoft", "Internet Information Services"),
        ["microsoft iis httpd"] = ("Microsoft", "Internet Information Services"),
        ["microsoft-httpapi"] = ("Microsoft", "HTTP.sys"),
        ["lighttpd"] = ("lighttpd", "lighttpd"),
        ["openresty"] = ("OpenResty", "OpenResty"),
        ["caddy"] = ("Caddy", "Caddy"),
        ["kestrel"] = ("Microsoft", "ASP.NET Core"),
        ["jetty"] = ("Eclipse Foundation", "Jetty"),
        ["openssh"] = ("OpenBSD", "OpenSSH"),
        ["postfix smtpd"] = ("Postfix", "Postfix"),
        ["exim smtpd"] = ("Exim", "Exim"),
        ["haproxy"] = ("HAProxy Technologies", "HAProxy"),
    };

    /// <summary>"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2" to OpenBSD / OpenSSH / 9.2p1 as a Service listening on the port.</summary>
    public static SoftwareRecord? FromSsh(string assetExternalId, string? identLine, int port = 22)
    {
        var line = (identLine ?? "").Split('\n')[0].Trim();
        var m = Regex.Match(line, @"^SSH-\d\.\d-(\S+)");
        if (!m.Success) return null;
        var software = m.Groups[1].Value;
        var listeners = new[] { new Listener(port, "tcp") };
        var win = Regex.Match(software, @"^OpenSSH_for_Windows_([\w.]+)", RegexOptions.IgnoreCase);
        if (win.Success) return new SoftwareRecord(assetExternalId, "OpenBSD", "OpenSSH", win.Groups[1].Value, SoftwareKind.Service, Edition: "for Windows", Listeners: listeners);
        var openssh = Regex.Match(software, @"^OpenSSH[_-]?([\w.]+)", RegexOptions.IgnoreCase);
        if (openssh.Success) return new SoftwareRecord(assetExternalId, "OpenBSD", "OpenSSH", openssh.Groups[1].Value, SoftwareKind.Service, Listeners: listeners);
        var generic = Regex.Match(software, @"^([A-Za-z][A-Za-z.\-]*?)[_\-]?v?(\d[\w.\-]*)?$");
        if (!generic.Success) return new SoftwareRecord(assetExternalId, "", software, "", SoftwareKind.Service, Listeners: listeners);
        var name = generic.Groups[1].Value.TrimEnd('_', '-');
        return new SoftwareRecord(assetExternalId, "", name.Equals("dropbear", StringComparison.OrdinalIgnoreCase) ? "Dropbear SSH" : name, generic.Groups[2].Value, SoftwareKind.Service, Listeners: listeners);
    }

    /// <summary>"nginx/1.24.0", "Apache/2.4.58 (Ubuntu)", "Microsoft-IIS/10.0" to a Service record on the port; unknown servers keep their raw name and an empty vendor.</summary>
    public static SoftwareRecord? FromServerHeader(string assetExternalId, string? serverHeader, int port)
    {
        var header = (serverHeader ?? "").Trim();
        if (header == "") return null;
        var first = header.Split(' ', 2)[0];
        var slash = first.IndexOf('/');
        var name = slash > 0 ? first[..slash] : first;
        var version = slash > 0 ? Regex.Match(first[(slash + 1)..], @"^[\w.\-]+").Value : "";
        if (name == "") return null;
        return Named(assetExternalId, name, version, port);
    }

    /// <summary>Shodan "product" and "version" strings ("Apache httpd", "2.4.58") to a Service record on the port.</summary>
    public static SoftwareRecord? FromProduct(string assetExternalId, string? product, string? version, int port)
    {
        var name = (product ?? "").Trim();
        return name == "" ? null : Named(assetExternalId, name, (version ?? "").Trim(), port);
    }

    private static SoftwareRecord Named(string asset, string name, string version, int port)
    {
        var listeners = new[] { new Listener(port, "tcp") };
        if (Servers.TryGetValue(name, out var known)) return new SoftwareRecord(asset, known.Vendor, known.Product, version, SoftwareKind.Service, Listeners: listeners);
        return new SoftwareRecord(asset, "", name, version, SoftwareKind.Service, Listeners: listeners);
    }

    /// <summary>The Server header value from raw HTTP response text, or null.</summary>
    public static string? ServerHeader(string? httpResponse)
    {
        if (string.IsNullOrEmpty(httpResponse)) return null;
        foreach (var line in httpResponse.Split('\n'))
        {
            var t = line.TrimEnd('\r');
            if (t.StartsWith("Server:", StringComparison.OrdinalIgnoreCase)) return t[7..].Trim();
            if (t == "") break;
        }
        return null;
    }
}
