using System.Text.RegularExpressions;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Snmp;

/// <summary>What sysDescr and sysObjectID say about a device. Named is false when only the vendor is known and the product is a placeholder that will land in the needs-mapping queue.</summary>
public sealed record SnmpDevice(
    string Vendor,
    string Product,
    string Version,
    AssetKind Kind,
    SoftwareKind SoftwareKind,
    bool Named,
    string? OsVendor = null,
    string? OsProduct = null,
    string? OsVersion = null,
    string? OsBuild = null);

/// <summary>
/// Section 9.2 step 8: enterprise number (sysObjectID 1.3.6.1.4.1.n) to vendor, sysDescr to product family, version and
/// asset kind. Deliberately a table plus a handful of per-vendor regexes: anything it cannot name goes to the
/// needs-mapping queue, is mapped once by a person, and is tracked automatically from then on.
/// </summary>
public static class SnmpDeviceMapper
{
    private static readonly Dictionary<int, (string Vendor, AssetKind Kind)> Enterprises = new()
    {
        [9] = ("Cisco", AssetKind.Switch),
        [11] = ("HP", AssetKind.Switch),
        [232] = ("Hewlett Packard Enterprise (HPE)", AssetKind.Server),
        [674] = ("Dell", AssetKind.Server),
        [318] = ("APC", AssetKind.Other),
        [6574] = ("Synology", AssetKind.Storage),
        [24681] = ("QNAP Systems Inc.", AssetKind.Storage),
        [41112] = ("Ubiquiti", AssetKind.NetworkDevice),
        [12356] = ("Fortinet", AssetKind.Switch),
        [641] = ("Lexmark", AssetKind.Printer),
        [2435] = ("Brother", AssetKind.Printer),
        [253] = ("Xerox", AssetKind.Printer),
        [1602] = ("Canon", AssetKind.Printer),
        [18334] = ("Konica Minolta", AssetKind.Printer),
        [10876] = ("Supermicro", AssetKind.OutOfBandManagement),
        [3808] = ("Dell", AssetKind.OutOfBandManagement),
        [2636] = ("Juniper Networks", AssetKind.Switch),
        [14823] = ("Aruba", AssetKind.NetworkDevice),
        [25506] = ("H3C", AssetKind.Switch),
        [8072] = ("Linux", AssetKind.Server),
        [311] = ("Microsoft", AssetKind.Server),
        [2021] = ("Linux", AssetKind.Server),
        [4526] = ("Netgear", AssetKind.Switch),
        [171] = ("D-Link", AssetKind.Switch),
        [890] = ("Zyxel", AssetKind.Switch),
        [43] = ("3Com", AssetKind.Switch),
        [1991] = ("Brocade", AssetKind.Switch),
        [6486] = ("Alcatel-Lucent Enterprise", AssetKind.Switch),
        [3375] = ("F5", AssetKind.NetworkDevice),
        [12325] = ("Netgate", AssetKind.Firewall),
        [30065] = ("Arista Networks", AssetKind.Switch),
        [6876] = ("VMware", AssetKind.Hypervisor),
        [2011] = ("Huawei", AssetKind.Switch),
        [25461] = ("Palo Alto Networks", AssetKind.Firewall),
        [8741] = ("SonicWall", AssetKind.Firewall),
        [3097] = ("WatchGuard", AssetKind.Firewall),
    };

    /// <summary>Windows "Build nnnnn" to the product name the CNA uses.</summary>
    private static readonly (int Build, string Product)[] WindowsBuilds =
    {
        (26100, "Windows Server 2025"), (25398, "Windows Server 2022 (23H2)"), (22631, "Windows 11 Version 23H2"), (22621, "Windows 11 Version 22H2"), (22000, "Windows 11 Version 21H2"),
        (20348, "Windows Server 2022"), (19045, "Windows 10 Version 22H2"), (19044, "Windows 10 Version 21H2"), (17763, "Windows Server 2019"), (14393, "Windows Server 2016"),
        (9600, "Windows Server 2012 R2"), (9200, "Windows Server 2012"), (7601, "Windows Server 2008 R2"),
    };

    /// <summary>1.3.6.1.4.1.674.10892.5 (with or without a leading dot) to 674. Null for non-enterprise or malformed ids.</summary>
    public static int? EnterpriseNumber(string? sysObjectId)
    {
        if (string.IsNullOrWhiteSpace(sysObjectId)) return null;
        var m = Regex.Match(sysObjectId.Trim(), @"^\.?1\.3\.6\.1\.4\.1\.(\d+)");
        return m.Success && int.TryParse(m.Groups[1].Value, out var n) ? n : null;
    }

    public static string? VendorFor(int enterprise) => Enterprises.TryGetValue(enterprise, out var e) ? e.Vendor : null;

    public static SnmpDevice Map(string? sysDescr, string? sysObjectId)
    {
        var d = Regex.Replace(sysDescr ?? "", @"\s+", " ").Trim();
        var ent = EnterpriseNumber(sysObjectId);
        var known = ent is not null && Enterprises.TryGetValue(ent.Value, out var e) ? e : ((string?)null, AssetKind.Other);
        var vendor = known.Item1;
        var kind = known.Item2;

        // ---- out-of-band management first: the enterprise number alone says Dell or HPE, the description says iDRAC or iLO
        if (Has(d, @"Integrated Dell Remote Access Controller|\biDRAC\b|Dell Remote Access"))
        {
            var gen = M(d, @"iDRAC\s?(\d+)") ?? M(d, @"Remote Access Controller\s+(\d+)") ?? "9";
            return new SnmpDevice("Dell", "Integrated Dell Remote Access Controller " + gen, M(d, @"(\d+\.\d+\.\d+\.\d+)") ?? "", AssetKind.OutOfBandManagement, SoftwareKind.Firmware, true);
        }
        if (Has(d, @"Integrated Lights-Out|\biLO\s?\d") )
        {
            var gen = M(d, @"iLO\s?(\d)") ?? M(d, @"Lights-Out\s+(\d)") ?? "5";
            return new SnmpDevice("Hewlett Packard Enterprise (HPE)", "HPE Integrated Lights-Out " + gen + " (iLO " + gen + ")", M(d, @"(?:iLO\s?\d|Lights-Out\s+\d)\s+v?(\d+\.\d+(?:\.\d+)?)") ?? "", AssetKind.OutOfBandManagement, SoftwareKind.Firmware, true);
        }
        if (Has(d, @"\bIPMI\b|\bBMC\b|Baseboard Management") || ent == 10876)
            return new SnmpDevice(vendor ?? "", (vendor is null ? "" : vendor + " ") + "BMC firmware", GenericVersion(d), AssetKind.OutOfBandManagement, SoftwareKind.Firmware, vendor is not null);
        if (ent == 3808) return new SnmpDevice("Dell", "Dell OpenManage", GenericVersion(d), AssetKind.OutOfBandManagement, SoftwareKind.Application, true);

        // ---- named product families
        if (ent == 9 || Has(d, @"^Cisco\b"))
        {
            if (Has(d, @"Adaptive Security Appliance")) return new SnmpDevice("Cisco", "Cisco Adaptive Security Appliance (ASA) Software", M(d, @"Version\s+([0-9][0-9A-Za-z.()\-]*)") ?? "", AssetKind.Firewall, SoftwareKind.Firmware, true);
            if (Has(d, @"IOS[ -]XE")) return new SnmpDevice("Cisco", "Cisco IOS XE Software", M(d, @"Version\s+([0-9][0-9A-Za-z.()\-]*)") ?? "", Has(d, @"ISR|ASR|Router") ? AssetKind.NetworkDevice : AssetKind.Switch, SoftwareKind.Firmware, true);
            if (Has(d, @"NX-OS")) return new SnmpDevice("Cisco", "Cisco NX-OS Software", M(d, @"[Vv]ersion\s+([0-9][0-9A-Za-z.()\-]*)") ?? "", AssetKind.Switch, SoftwareKind.Firmware, true);
            if (Has(d, @"\bIOS\b")) return new SnmpDevice("Cisco", "Cisco IOS", M(d, @"Version\s+([0-9][0-9A-Za-z.()\-]*)") ?? "", Has(d, @"Router|ISR") ? AssetKind.NetworkDevice : AssetKind.Switch, SoftwareKind.Firmware, true);
            if (Has(d, @"Small Business|\bSG\d{3}|\bSF\d{3}")) return new SnmpDevice("Cisco", "Cisco Small Business Switch", GenericVersion(d), AssetKind.Switch, SoftwareKind.Firmware, true);
            return new SnmpDevice("Cisco", "Cisco device", GenericVersion(d), kind, SoftwareKind.Firmware, false);
        }
        if (ent == 12356 || Has(d, @"^Forti"))
        {
            var family = M(d, @"\b(Forti[A-Za-z]+)") ?? "Fortinet device";
            var fkind = family.StartsWith("FortiSwitch") ? AssetKind.Switch : family.StartsWith("FortiAP") ? AssetKind.AccessPoint : family.StartsWith("FortiGate") ? AssetKind.Firewall : AssetKind.NetworkDevice;
            return new SnmpDevice("Fortinet", family == "FortiGate" ? "FortiOS" : family, M(d, @"\bv(\d+\.\d+\.\d+)") ?? GenericVersion(d), fkind, SoftwareKind.Firmware, family != "Fortinet device");
        }
        if (ent == 6574 || Has(d, @"Synology|DiskStation|\bDSM\s+\d"))
            return new SnmpDevice("Synology", "DiskStation Manager (DSM)", M(d, @"DSM\s+(\d[\d.\-]*)") ?? "", AssetKind.Storage, SoftwareKind.Firmware, true,
                OsVendor: "Synology", OsProduct: "DiskStation Manager (DSM)", OsVersion: M(d, @"DSM\s+(\d[\d.]*)"));
        if (ent == 24681 || Has(d, @"\bQNAP\b|\bQTS\s+\d|QuTS hero"))
        {
            var hero = Has(d, @"QuTS hero");
            return new SnmpDevice("QNAP Systems Inc.", hero ? "QuTS hero" : "QTS", M(d, @"(?:QTS|QuTS hero)\s+h?(\d[\d.]*)") ?? "", AssetKind.Storage, SoftwareKind.Firmware, true);
        }
        if (ent == 318 || Has(d, @"^APC\b"))
        {
            var model = M(d, @"MN:\s?(AP\d+\w*)");
            var product = model is null ? "Network Management Card" : model.StartsWith("AP964") ? "Network Management Card 3" : model.StartsWith("AP96") ? "Network Management Card 2" : "Network Management Card (" + model + ")";
            return new SnmpDevice("APC", product, M(d, @"AOS\s+v?(\d[\d.]*)") ?? M(d, @"PF:\s?v?(\d[\d.]*)") ?? GenericVersion(d), AssetKind.Other, SoftwareKind.Firmware, true);
        }
        if (ent == 641 || Has(d, @"^Lexmark\b"))
            return new SnmpDevice("Lexmark", M(d, @"Lexmark\s+([A-Z]+\d+[A-Za-z0-9]*)") ?? "Lexmark printer", M(d, @"version\s+(\S+)") ?? GenericVersion(d), AssetKind.Printer, SoftwareKind.Firmware, true);
        if (ent == 2435 || Has(d, @"^Brother\b"))
            return new SnmpDevice("Brother", M(d, @"Brother\s+([A-Za-z0-9\-]+)") ?? "Brother printer", M(d, @"Ver\.?\s?([A-Za-z]?\d[\d.]*)") ?? GenericVersion(d), AssetKind.Printer, SoftwareKind.Firmware, true);
        if (ent == 253 || Has(d, @"^Xerox\b"))
            return new SnmpDevice("Xerox", M(d, @"Xerox\s+([A-Za-z]+\s?[A-Za-z0-9\-]+)") ?? "Xerox printer", M(d, @"System\s+(\d[\d.]*)") ?? GenericVersion(d), AssetKind.Printer, SoftwareKind.Firmware, true);
        if (ent == 1602 || Has(d, @"^Canon\b"))
            return new SnmpDevice("Canon", M(d, @"Canon\s+([A-Za-z0-9\-]+(?:\s[A-Z][A-Za-z0-9\-]+)?)") ?? "Canon printer", GenericVersion(d), AssetKind.Printer, SoftwareKind.Firmware, true);
        if (ent == 18334 || Has(d, @"KONICA MINOLTA|Konica Minolta"))
            return new SnmpDevice("Konica Minolta", M(d, @"(?i)KONICA MINOLTA\s+(bizhub\s?[A-Za-z0-9]+)") ?? "Konica Minolta printer", GenericVersion(d), AssetKind.Printer, SoftwareKind.Firmware, true);
        if ((ent == 11 || Has(d, @"^HP\b")) && Has(d, @"LaserJet|OfficeJet|PageWide|DesignJet|Color LaserJet|JETDIRECT|ETHERNET MULTI-ENVIRONMENT"))
            return new SnmpDevice("HP", M(d, @"PID:\s?(?:HP\s+)?([^,;]+)") ?? M(d, @"HP\s+((?:Color\s+)?(?:LaserJet|OfficeJet|PageWide|DesignJet)[^,;]*)") ?? "HP printer", M(d, @"(?:FW|Firmware)[:\s]+v?([\w.]+)") ?? GenericVersion(d), AssetKind.Printer, SoftwareKind.Firmware, true);
        if (ent == 14823 || Has(d, @"^Aruba|ArubaOS"))
        {
            if (Has(d, @"AOS-CX|ArubaOS-CX")) return new SnmpDevice("Aruba", "AOS-CX", M(d, @"([A-Z]{2}\.\d+\.\d+\.\d+)") ?? GenericVersion(d), AssetKind.Switch, SoftwareKind.Firmware, true);
            var akind = Has(d, @"\bAP-?\d|Access Point") ? AssetKind.AccessPoint : Has(d, @"Switch|\d{4}M\b|CX\b") ? AssetKind.Switch : AssetKind.NetworkDevice;
            return new SnmpDevice("Aruba", Has(d, @"ArubaOS-Switch|Switch") ? "ArubaOS-Switch" : "ArubaOS", M(d, @"(?:revision|Version)\s+v?([A-Z]{2}\.\d+\.\d+(?:\.\d+)?|\d+\.\d+\.\d+(?:\.\d+)?)") ?? GenericVersion(d), akind, SoftwareKind.Firmware, true);
        }
        if (ent == 11 || Has(d, @"^HP\s+J\d{4}|ProCurve"))
        {
            var rev = M(d, @"(?:revision|Version)\s+([A-Z]{2}\.\d+\.\d+(?:\.\d+)?)");
            var product = Has(d, @"Aruba|\b25\d0|\b29\d0|\b38\d0|\b54\d0") && rev is not null ? "ArubaOS-Switch" : Has(d, @"ProCurve|Switch") ? "ProCurve switch firmware" : "HP device";
            return new SnmpDevice(product == "ArubaOS-Switch" ? "Hewlett Packard Enterprise (HPE)" : "HP", product, rev ?? GenericVersion(d), AssetKind.Switch, SoftwareKind.Firmware, product != "HP device");
        }
        if (ent == 41112 || Has(d, @"\bUniFi\b|\bUAP-|\bUSW-|\bUDM|\bUSG"))
        {
            var model = M(d, @"\b(U(?:AP|SW|DM|SG|XG|CK|6|7)[A-Za-z0-9\-]*)");
            var ukind = model is null ? AssetKind.NetworkDevice : model.StartsWith("USW") || model.StartsWith("US-") ? AssetKind.Switch : model.StartsWith("UAP") || model.StartsWith("U6") || model.StartsWith("U7") ? AssetKind.AccessPoint : model.StartsWith("UDM") || model.StartsWith("USG") || model.StartsWith("UXG") ? AssetKind.Firewall : AssetKind.NetworkDevice;
            var family = ukind switch { AssetKind.Switch => "UniFi Switch", AssetKind.AccessPoint => "UniFi Access Point", AssetKind.Firewall => "UniFi Gateway", _ => "UniFi device" };
            return new SnmpDevice("Ubiquiti", family + (model is null ? "" : " (" + model + ")"), M(d, @"(\d+\.\d+\.\d+(?:\.\d+)?)") ?? "", ukind, SoftwareKind.Firmware, model is not null);
        }
        if (ent == 6876 || Has(d, @"VMware ESXi"))
            return new SnmpDevice("VMware", "ESXi", M(d, @"ESXi\s+(\d[\d.]*)") ?? GenericVersion(d), AssetKind.Hypervisor, SoftwareKind.OperatingSystem, true,
                OsVendor: "VMware", OsProduct: "ESXi", OsVersion: M(d, @"ESXi\s+(\d[\d.]*)"), OsBuild: M(d, @"build-?(\d+)"));
        if (ent == 311 || Has(d, @"Software: Windows"))
        {
            var ver = M(d, @"Windows Version\s+(\d+\.\d+)") ?? "";
            var build = M(d, @"Build\s+(\d+)");
            var product = "Windows";
            if (build is not null && int.TryParse(build, out var b)) product = WindowsBuilds.FirstOrDefault(w => w.Build == b).Product ?? (ver.StartsWith("10.") ? "Windows Server" : "Windows");
            return new SnmpDevice("Microsoft", product, build ?? ver, AssetKind.Server, SoftwareKind.OperatingSystem, product != "Windows", OsVendor: "Microsoft", OsProduct: product, OsVersion: ver, OsBuild: build);
        }
        if (ent == 2636 || Has(d, @"Juniper Networks|JUNOS"))
            return new SnmpDevice("Juniper Networks", "Junos OS", M(d, @"JUNOS\s+([0-9][0-9A-Za-z.\-]*)") ?? GenericVersion(d), Has(d, @"\bsrx|Firewall") ? AssetKind.Firewall : AssetKind.Switch, SoftwareKind.Firmware, true);
        if (ent == 30065 || Has(d, @"Arista Networks"))
            return new SnmpDevice("Arista Networks", "EOS", M(d, @"EOS version\s+([0-9][0-9A-Za-z.]*)") ?? GenericVersion(d), AssetKind.Switch, SoftwareKind.Firmware, true);
        if (ent == 2011 || Has(d, @"Huawei|Versatile Routing Platform"))
            return new SnmpDevice("Huawei", "VRP", M(d, @"(V\d{3}R\d{3}C\d{2}(?:SPC\d{3})?)") ?? M(d, @"Version\s+([\d.]+)") ?? GenericVersion(d), AssetKind.Switch, SoftwareKind.Firmware, true);
        if (ent == 25506 || Has(d, @"^H3C\b"))
            return new SnmpDevice("H3C", "Comware", M(d, @"Version\s+([\d.]+)") ?? GenericVersion(d), AssetKind.Switch, SoftwareKind.Firmware, true);
        if (ent == 3375 || Has(d, @"BIG-IP"))
            return new SnmpDevice("F5", "BIG-IP", M(d, @"BIG-IP\s+(\d[\d.]*)") ?? GenericVersion(d), AssetKind.NetworkDevice, SoftwareKind.Firmware, true);
        if (ent == 12325 || Has(d, @"pfSense|OPNsense"))
        {
            var product = Has(d, @"OPNsense") ? "OPNsense" : Has(d, @"pfSense") ? "pfSense" : "FreeBSD";
            return new SnmpDevice(product == "pfSense" ? "Netgate" : product == "OPNsense" ? "Deciso" : "FreeBSD", product, M(d, @"(\d+\.\d+(?:\.\d+)?)-RELEASE") ?? GenericVersion(d), product == "FreeBSD" ? AssetKind.Server : AssetKind.Firewall, SoftwareKind.OperatingSystem, true);
        }
        if (ent == 25461 || Has(d, @"Palo Alto Networks"))
            return new SnmpDevice("Palo Alto Networks", "PAN-OS", M(d, @"PAN-OS\s+v?(\d[\d.]*)") ?? "", AssetKind.Firewall, SoftwareKind.Firmware, true);
        if (ent == 8741 || Has(d, @"SonicWALL|SonicWall|SonicOS"))
            return new SnmpDevice("SonicWall", "SonicOS", M(d, @"SonicOS(?:\s+Enhanced)?\s+(\d[\w.\-]*)") ?? GenericVersion(d), AssetKind.Firewall, SoftwareKind.Firmware, true);
        if (ent == 3097 || Has(d, @"WatchGuard|Fireware"))
            return new SnmpDevice("WatchGuard", "Fireware OS", M(d, @"Fireware\s+(?:OS\s+)?v?(\d[\d.]*)") ?? GenericVersion(d), AssetKind.Firewall, SoftwareKind.Firmware, true);
        if (ent == 4526 || Has(d, @"^NETGEAR|^Netgear"))
            return new SnmpDevice("Netgear", M(d, @"^(?:NETGEAR\s+|Netgear\s+)?([A-Z]{1,4}\d{3,4}[A-Za-z0-9\-]*)") ?? "Netgear switch", GenericVersion(d), AssetKind.Switch, SoftwareKind.Firmware, true);
        if (ent is 8072 or 2021 || Has(d, @"^Linux\b"))
        {
            var kernel = M(d, @"^Linux\s+\S+\s+(\d+\.\d+\.\d+[\w.\-+]*)");
            return new SnmpDevice("Linux", "Linux kernel", kernel ?? "", AssetKind.Server, SoftwareKind.OperatingSystem, kernel is not null, OsVendor: "Linux", OsProduct: "Linux", OsVersion: kernel);
        }
        if (ent == 232 || Has(d, @"ProLiant"))
            return new SnmpDevice("Hewlett Packard Enterprise (HPE)", Has(d, @"ProLiant") ? "ProLiant Insight Management Agents" : "HPE device", GenericVersion(d), AssetKind.Server, SoftwareKind.Application, Has(d, @"ProLiant"));
        if (ent == 674) return new SnmpDevice("Dell", Has(d, @"OpenManage") ? "Dell OpenManage" : "Dell device", GenericVersion(d), AssetKind.Server, SoftwareKind.Application, Has(d, @"OpenManage"));

        // ---- vendor known, family not: the placeholder lands in the needs-mapping queue
        if (vendor is not null) return new SnmpDevice(vendor, vendor + " device", GenericVersion(d), kind, SoftwareKind.Firmware, false);
        // ---- nothing known: name the device from the first word of sysDescr so a person can map it
        var first = M(d, @"^([A-Za-z][A-Za-z0-9\-]{2,})");
        return new SnmpDevice("", first is null ? "" : first + " device", GenericVersion(d), AssetKind.Other, SoftwareKind.Firmware, false);
    }

    /// <summary>The first dotted version-looking token, when nothing vendor-specific matched.</summary>
    public static string GenericVersion(string d) => M(d, @"(?:^|[\s:(vV])(\d+\.\d+(?:\.\d+){0,3})(?=$|[\s,;)])") ?? "";

    private static bool Has(string s, string pattern) => Regex.IsMatch(s, pattern);
    private static string? M(string s, string pattern, int group = 1) { var m = Regex.Match(s, pattern); return m.Success ? m.Groups[group].Value.Trim() : null; }
}
