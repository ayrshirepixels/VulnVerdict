using System.Runtime.CompilerServices;
using System.Text.Json;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Adapters.Fortinet;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Tests;

/// <summary>
/// The Fortinet adapters against fixture JSON shaped like the documented FortiOS and EMS responses. No live devices:
/// the HTTP layer is replaced by a path-to-fixture function through the adapters' test constructors.
/// </summary>
public class FortinetAdapterTests
{
    private static string FixtureDir([CallerFilePath] string path = "") => Path.Combine(Path.GetDirectoryName(path)!, "Fixtures", "fortinet");
    private static string Fixture(string name) => File.ReadAllText(Path.Combine(FixtureDir(), name));
    private static readonly IReadOnlyDictionary<string, string> NoCreds = new Dictionary<string, string>();

    // ------------------------------------------------------------------ FortiGate

    private static readonly Dictionary<string, string> FgtFiles = new(StringComparer.OrdinalIgnoreCase)
    {
        [FortiGateAdapter.Paths.Status] = "fgt-status.json",
        [FortiGateAdapter.Paths.Global] = "fgt-global.json",
        [FortiGateAdapter.Paths.Interface] = "fgt-interface.json",
        [FortiGateAdapter.Paths.SslVpnSettings] = "fgt-sslvpn.json",
        [FortiGateAdapter.Paths.Vip] = "fgt-vip.json",
        [FortiGateAdapter.Paths.VipGroup] = "fgt-vipgrp.json",
        [FortiGateAdapter.Paths.Policy] = "fgt-policy.json",
        [FortiGateAdapter.Paths.Address] = "fgt-address.json",
        [FortiGateAdapter.Paths.AddressGroup] = "fgt-addrgrp.json",
        [FortiGateAdapter.Paths.ManagedSwitch] = "fgt-switch.json",
        [FortiGateAdapter.Paths.ManagedAp] = "fgt-ap.json",
    };

    private static FortiGateAdapter FortiGate(Func<string, string?>? overrides = null, List<string>? calls = null) => new((path, _) =>
    {
        calls?.Add(path);
        var o = overrides?.Invoke(path);
        if (o is not null) return Task.FromResult(o);
        if (!FgtFiles.TryGetValue(path, out var file)) throw new FortinetApiException("GET " + path, 404, "no fixture");
        return Task.FromResult(Fixture(file));
    });

    [Fact]
    public async Task FortiGate_maps_the_firewall_asset_and_firmware()
    {
        var r = await FortiGate().CollectAsync(NoCreds, null, null, CancellationToken.None);

        var fgt = Assert.Single(r.Assets, a => a.Kind == AssetKind.Firewall);
        Assert.Equal("FG100FTK20012345", fgt.ExternalId);
        Assert.Equal("FGT-EDGE-01", fgt.DisplayName);
        Assert.Equal(Criticality.Critical, fgt.Criticality);
        Assert.Contains("203.0.113.10", fgt.IpAddresses);
        Assert.Contains("10.0.10.1", fgt.IpAddresses);
        Assert.DoesNotContain("0.0.0.0", fgt.IpAddresses);
        Assert.Contains("e8:1c:ba:12:34:56", fgt.MacAddresses);
        Assert.Equal("Fortinet", fgt.OsVendor);
        Assert.Equal("FortiOS", fgt.OsProduct);
        Assert.Equal("7.2.5", fgt.OsVersion);
        Assert.Equal("1517", fgt.OsBuild);

        var fw = Assert.Single(r.Software, s => s.AssetExternalId == fgt.ExternalId);
        Assert.Equal(("Fortinet", "FortiOS", "7.2.5", SoftwareKind.Firmware), (fw.Vendor, fw.Product, fw.Version, fw.Kind));
        Assert.NotNull(fw.Listeners);
        Assert.Contains(fw.Listeners!, l => l.Port == 443 && l.Bind == "wan1" && l.Process == "sslvpnd");
        Assert.Contains(fw.Listeners!, l => l.Port == 8443 && l.Bind == "wan1");
        Assert.True(r.FullSnapshot);
    }

    [Fact]
    public async Task SslVpn_and_admin_https_on_wan1_mark_the_fortigate_internet_facing()
    {
        var r = await FortiGate().CollectAsync(NoCreds, null, null, CancellationToken.None);

        var ex = Assert.Single(r.Exposures, e => e.AssetExternalId == "FG100FTK20012345");
        Assert.Equal(Exposure.Internet, ex.Exposure);
        Assert.Contains("SSL-VPN on wan1:443", ex.Evidence);
        Assert.Contains("admin HTTPS on wan1:8443", ex.Evidence);
        Assert.Contains("admin SSH on wan1:22", ex.Evidence);
        Assert.DoesNotContain("internal", ex.Evidence);   // LAN-side admin access is not exposure
        Assert.DoesNotContain("wan2", ex.Evidence);       // wan2 only allows ping
    }

    [Fact]
    public async Task Vip_behind_a_wan_accept_policy_is_internet_facing()
    {
        var r = await FortiGate().CollectAsync(NoCreds, null, null, CancellationToken.None);

        var ex = Assert.Single(r.Exposures, e => e.IpAddress == "10.0.10.5");
        Assert.Equal(Exposure.Internet, ex.Exposure);
        Assert.Equal("VIP web-vip 203.0.113.11:443 policy 5", ex.Evidence);
        Assert.Null(ex.AssetExternalId);
    }

    [Fact]
    public async Task Vip_only_referenced_by_lan_policies_or_deny_policies_is_not_exposed()
    {
        var r = await FortiGate().CollectAsync(NoCreds, null, null, CancellationToken.None);

        Assert.DoesNotContain(r.Exposures, e => e.IpAddress == "10.0.20.7"); // lan-vip: internal -> dmz only
        Assert.DoesNotContain(r.Exposures, e => e.IpAddress == "10.0.10.9"); // rdp-vip: wan policy is deny
    }

    [Fact]
    public async Task Wan_policy_to_a_single_host_address_object_is_internet_facing()
    {
        var r = await FortiGate().CollectAsync(NoCreds, null, null, CancellationToken.None);

        var ex = Assert.Single(r.Exposures, e => e.IpAddress == "10.0.20.25");
        Assert.Contains("policy 11", ex.Evidence);
        Assert.Contains("dmz-mail", ex.Evidence);
        Assert.Contains("SMTP", ex.Evidence);
        // the outbound "all" policy (12) must not produce anything: dstaddr all is not a host and match-vip is off
        Assert.DoesNotContain(r.Exposures, e => e.Evidence.Contains("policy 12"));
    }

    [Fact]
    public async Task Managed_switches_and_access_points_become_assets_with_firmware()
    {
        var r = await FortiGate().CollectAsync(NoCreds, null, null, CancellationToken.None);

        var sw = Assert.Single(r.Assets, a => a.ExternalId == "S124EF5920010261");
        Assert.Equal(AssetKind.Switch, sw.Kind);
        Assert.Equal("SW-CORE-01", sw.DisplayName);
        Assert.Contains("10.255.1.2", sw.IpAddresses);
        var swFw = Assert.Single(r.Software, s => s.AssetExternalId == sw.ExternalId);
        Assert.Equal(("Fortinet", "FortiSwitch", "7.4.11", SoftwareKind.Firmware), (swFw.Vendor, swFw.Product, swFw.Version, swFw.Kind));
        Assert.Equal("S124EF", swFw.Edition);

        var sw2 = Assert.Single(r.Assets, a => a.ExternalId == "S108EN5920123456");
        Assert.Equal("SW-ACCESS-02", sw2.DisplayName); // falls back to switch-id when there is no name
        Assert.Equal("7.2.8", Assert.Single(r.Software, s => s.AssetExternalId == sw2.ExternalId).Version);

        var ap = Assert.Single(r.Assets, a => a.ExternalId == "FP231FTF21001234");
        Assert.Equal(AssetKind.AccessPoint, ap.Kind);
        Assert.Equal("AP-1F-EAST", ap.DisplayName);
        Assert.Contains("10.0.40.21", ap.IpAddresses);
        Assert.DoesNotContain("0.0.0.0", ap.IpAddresses);
        Assert.Contains("70:4c:a5:11:22:33", ap.MacAddresses);
        var apFw = Assert.Single(r.Software, s => s.AssetExternalId == ap.ExternalId);
        Assert.Equal(("Fortinet", "FortiAP", "7.4.4"), (apFw.Vendor, apFw.Product, apFw.Version));

        var ap2Fw = Assert.Single(r.Software, s => s.AssetExternalId == "FP221ETF19005678");
        Assert.Equal("6.4", ap2Fw.Version);

        Assert.Equal(5, r.Assets.Count); // 1 firewall + 2 switches + 2 APs
    }

    [Fact]
    public async Task No_exposure_for_the_fortigate_when_sslvpn_and_admin_access_are_lan_only()
    {
        var adapter = FortiGate(path => path switch
        {
            FortiGateAdapter.Paths.SslVpnSettings => Fixture("fgt-sslvpn.json").Replace("\"name\": \"wan1\", \"q_origin_key\": \"wan1\"", "\"name\": \"internal\", \"q_origin_key\": \"internal\""),
            FortiGateAdapter.Paths.Interface => Fixture("fgt-interface.json").Replace("\"allowaccess\": \"ping https ssh\", \"status\": \"up\", \"type\": \"physical\", \"role\": \"wan\"", "\"allowaccess\": \"ping\", \"status\": \"up\", \"type\": \"physical\", \"role\": \"wan\""),
            _ => null
        });
        var r = await adapter.CollectAsync(NoCreds, null, null, CancellationToken.None);

        Assert.DoesNotContain(r.Exposures, e => e.AssetExternalId == "FG100FTK20012345");
        Assert.Contains(r.Exposures, e => e.IpAddress == "10.0.10.5"); // the VIP exposure is unaffected
    }

    [Fact]
    public async Task Disabled_sslvpn_is_not_exposure_even_when_bound_to_wan()
    {
        var adapter = FortiGate(path => path == FortiGateAdapter.Paths.SslVpnSettings ? Fixture("fgt-sslvpn.json").Replace("\"status\": \"enable\"", "\"status\": \"disable\"") : null);
        var r = await adapter.CollectAsync(NoCreds, null, null, CancellationToken.None);

        var ex = Assert.Single(r.Exposures, e => e.AssetExternalId == "FG100FTK20012345");
        Assert.DoesNotContain("SSL-VPN", ex.Evidence);
        Assert.Contains("admin HTTPS on wan1:8443", ex.Evidence);
    }

    [Fact]
    public async Task Missing_switch_controller_and_wifi_endpoints_become_warnings_not_failures()
    {
        var calls = new List<string>();
        var adapter = FortiGate(path => null, calls);
        var r = await adapter.CollectAsync(NoCreds, null, null, CancellationToken.None);
        Assert.Empty(r.Warnings);

        // now with no switch controller at all: both the 7.2+ path and the legacy path answer 404
        var noSwitches = new FortiGateAdapter((path, _) =>
        {
            if (path.StartsWith(FortiGateAdapter.Paths.ManagedSwitchLegacy, StringComparison.Ordinal) || path == FortiGateAdapter.Paths.ManagedAp)
                throw new FortinetApiException("GET " + path, 404, "not found");
            return Task.FromResult(Fixture(FgtFiles[path]));
        });
        var r2 = await noSwitches.CollectAsync(NoCreds, null, null, CancellationToken.None);
        Assert.Single(r2.Assets);
        Assert.Equal(2, r2.Warnings.Count);
        Assert.Contains(r2.Warnings, w => w.Contains("managed-switch"));
        Assert.Contains(r2.Warnings, w => w.Contains("managed_ap"));
    }

    [Fact]
    public async Task FortiGate_test_reports_hostname_version_and_serial()
    {
        var t = await FortiGate().TestAsync(NoCreds, CancellationToken.None);
        Assert.True(t.Ok, t.Message);
        Assert.Contains("FGT-EDGE-01", t.Message);
        Assert.Contains("7.2.5", t.Message);
        Assert.Contains("FG100FTK20012345", t.Message);

        var bad = new FortiGateAdapter((path, _) => throw new FortinetApiException("GET " + path, 401, "the FortiGate rejected the API token"));
        var tb = await bad.TestAsync(NoCreds, CancellationToken.None);
        Assert.False(tb.Ok);
        Assert.Contains("401", tb.Message);
    }

    [Fact]
    public void FortiGate_metadata_matches_the_documented_contract()
    {
        var m = new FortiGateAdapter((_, _) => Task.FromResult("{}")).Metadata;
        Assert.Equal("fortigate", m.Id);
        Assert.Equal("Fortinet", m.Vendor);
        Assert.Contains(m.Form, f => f.Key == "apiToken" && f.Type == CredentialTypes.Password);
        Assert.Contains(m.Form, f => f.Key == "verifyTls" && f.Type == CredentialTypes.Bool && f.Default == "true");
        Assert.Contains(m.Form, f => f.Key == "vdom" && !f.Required);
        Assert.Contains("read-only", m.MinimumPermission);
        Assert.StartsWith("https://docs.fortinet.com/", m.DocsUrl);
    }

    // ------------------------------------------------------------------ FortiClient EMS

    private static FortiClientEmsAdapter Ems(List<string>? calls = null) => new((path, _) =>
    {
        calls?.Add(path);
        var q = System.Web.HttpUtility.ParseQueryString(path.Contains('?') ? path[(path.IndexOf('?') + 1)..] : "");
        var device = q["device_id"];
        var offset = int.Parse(q["offset"] ?? "0");
        if (path.StartsWith(FortiClientEmsAdapter.EndpointsPath, StringComparison.Ordinal)) return Task.FromResult(offset == 0 ? Fixture("ems-endpoints.json") : Fixture("ems-empty.json"));
        if (path.StartsWith(FortiClientEmsAdapter.SoftwarePath, StringComparison.Ordinal))
            return Task.FromResult(offset == 0 && device is "1001" or "1002" ? Fixture("ems-software-" + device + ".json") : Fixture("ems-empty.json"));
        if (path.StartsWith(FortiClientEmsAdapter.VulnerabilitiesPath, StringComparison.Ordinal))
            return Task.FromResult(offset == 0 && device == "1001" ? Fixture("ems-vulnerabilities-1001.json") : Fixture("ems-empty.json"));
        throw new FortinetApiException("GET " + path, 404, "no fixture");
    });

    [Fact]
    public async Task Ems_maps_endpoints_with_kind_by_os_and_cna_product_names()
    {
        var r = await Ems().CollectAsync(NoCreds, null, null, CancellationToken.None);
        Assert.Equal(3, r.Assets.Count);

        var laptop = Assert.Single(r.Assets, a => a.ExternalId == "1001");
        Assert.Equal(AssetKind.Endpoint, laptop.Kind);
        Assert.Equal("LT-ACCOUNTS-07", laptop.DisplayName);
        Assert.Contains("LT-ACCOUNTS-07", laptop.Hostnames);
        Assert.Equal(new[] { "10.0.30.57", "192.168.56.1" }, laptop.IpAddresses);
        Assert.Equal(new[] { "3C-52-82-1A-2B-3C" }, laptop.MacAddresses);
        Assert.Equal(("Microsoft", "Windows 11 Version 23H2", "10.0.22631", "22631"), (laptop.OsVendor, laptop.OsProduct, laptop.OsVersion, laptop.OsBuild));
        Assert.Equal("jmackay", laptop.Owner);

        var server = Assert.Single(r.Assets, a => a.ExternalId == "1002");
        Assert.Equal(AssetKind.Server, server.Kind);
        Assert.Equal("Windows Server 2022", server.OsProduct);
        Assert.Equal("10.0.20348", server.OsVersion);
        Assert.Null(server.Owner);

        var mac = Assert.Single(r.Assets, a => a.ExternalId == "1003");
        Assert.Equal(AssetKind.Endpoint, mac.Kind);
        Assert.Equal(("Apple", "macOS", "14.6.1"), (mac.OsVendor, mac.OsProduct, mac.OsVersion));
        Assert.Equal("acampbell", mac.Owner);
    }

    [Fact]
    public async Task Ems_emits_installed_software_with_versions_stripped_from_names_plus_the_agent_and_os()
    {
        var r = await Ems().CollectAsync(NoCreds, null, null, CancellationToken.None);
        var sw = r.Software.Where(s => s.AssetExternalId == "1001").ToList();

        var chrome = Assert.Single(sw, s => s.Product == "Google Chrome");
        Assert.Equal(("Google LLC", "128.0.6613.84", SoftwareKind.Application), (chrome.Vendor, chrome.Version, chrome.Kind));
        Assert.Contains(sw, s => s.Product == "7-Zip" && s.Version == "23.01");
        Assert.Contains(sw, s => s.Product == "Microsoft Edge" && s.Vendor == "Microsoft Corporation");

        // the agent comes from the endpoint record, not the inventory row (which is skipped), so exactly one FortiClient entry
        var agent = Assert.Single(sw, s => s.Product.StartsWith("FortiClient"));
        Assert.Equal(("Fortinet", "FortiClientWindows", "7.2.4"), (agent.Vendor, agent.Product, agent.Version));

        var os = Assert.Single(sw, s => s.Kind == SoftwareKind.OperatingSystem);
        Assert.Equal(("Microsoft", "Windows 11 Version 23H2", "10.0.22631"), (os.Vendor, os.Product, os.Version));

        Assert.Contains(r.Software, s => s.AssetExternalId == "1002" && s.Product == "Veeam Backup & Replication" && s.Version == "12.1.2.172");
        Assert.Contains(r.Software, s => s.AssetExternalId == "1002" && s.Product == "Microsoft SQL Server 2019" && s.Version == "15.0.4382.1");
        Assert.Contains(r.Software, s => s.AssetExternalId == "1003" && s.Product == "FortiClientMac" && s.Version == "7.2.5");
        Assert.Contains(r.Software, s => s.AssetExternalId == "1003" && s.Product == "macOS" && s.Kind == SoftwareKind.OperatingSystem);
    }

    [Fact]
    public async Task Ems_vulnerability_scan_rows_become_findings_keyed_by_cve()
    {
        var r = await Ems().CollectAsync(NoCreds, null, null, CancellationToken.None);
        var findings = r.Findings.Where(f => f.AssetExternalId == "1001").ToList();
        Assert.Equal(2, findings.Count); // the row without a CVE id is dropped

        var chrome = Assert.Single(findings, f => f.RawRef == "ems-vuln-123456");
        Assert.Equal(new[] { "CVE-2026-1234", "CVE-2026-1235" }, chrome.CveIds);
        Assert.Equal("Critical", chrome.Severity);
        Assert.StartsWith("Google Chrome Multiple Vulnerabilities", chrome.Title);

        var zip = Assert.Single(findings, f => f.RawRef == "ems-vuln-123999");
        Assert.Equal(new[] { "CVE-2025-0411" }, zip.CveIds);
        Assert.Equal("High", zip.Severity); // numeric severity 3
        Assert.DoesNotContain(r.Findings, f => f.AssetExternalId != "1001");
        Assert.Empty(r.Warnings);
    }

    [Fact]
    public async Task Ems_pages_through_endpoints_with_offset_and_count()
    {
        var calls = new List<string>();
        string Page(int offset)
        {
            var count = offset == 0 ? FortiClientEmsAdapter.PageSize : 20;
            var items = Enumerable.Range(offset, count).Select(i => new { device_id = i + 1, name = "PC-" + (i + 1), ip_addr = "10.1.0." + (i % 250 + 1), os_version = "Microsoft Windows 10 Enterprise Edition, 64-bit (build 19045)", fct_version = "7.0.12.0510" });
            return JsonSerializer.Serialize(new { result = new { retval = 1, message = "Success" }, data = new { endpoints = items, total = FortiClientEmsAdapter.PageSize + 20 } });
        }
        var adapter = new FortiClientEmsAdapter((path, _) =>
        {
            calls.Add(path);
            if (path.StartsWith(FortiClientEmsAdapter.EndpointsPath, StringComparison.Ordinal))
                return Task.FromResult(Page(path.Contains("offset=0&") ? 0 : FortiClientEmsAdapter.PageSize));
            return Task.FromResult(Fixture("ems-empty.json"));
        });
        var r = await adapter.CollectAsync(NoCreds, null, null, CancellationToken.None);

        Assert.Equal(FortiClientEmsAdapter.PageSize + 20, r.Assets.Count);
        Assert.Contains(calls, c => c.StartsWith(FortiClientEmsAdapter.EndpointsPath + "?offset=0&count=" + FortiClientEmsAdapter.PageSize, StringComparison.Ordinal));
        Assert.Contains(calls, c => c.StartsWith(FortiClientEmsAdapter.EndpointsPath + "?offset=" + FortiClientEmsAdapter.PageSize + "&count=", StringComparison.Ordinal));
        Assert.Equal(2, calls.Count(c => c.StartsWith(FortiClientEmsAdapter.EndpointsPath, StringComparison.Ordinal)));
        Assert.All(r.Assets, a => Assert.Equal("Windows 10 Version 22H2", a.OsProduct));
        Assert.All(r.Software.Where(s => s.Product == "FortiClientWindows"), s => Assert.Equal("7.0.12", s.Version));
    }

    [Fact]
    public async Task Ems_result_retval_other_than_one_fails_the_test()
    {
        var adapter = new FortiClientEmsAdapter((_, _) => Task.FromResult("{\"result\":{\"retval\":-1,\"message\":\"Permission denied\"},\"data\":{}}"));
        var t = await adapter.TestAsync(NoCreds, CancellationToken.None);
        Assert.False(t.Ok);
        Assert.Contains("Permission denied", t.Message);

        var ok = await Ems().TestAsync(NoCreds, CancellationToken.None);
        Assert.True(ok.Ok, ok.Message);
        Assert.Contains("3 endpoint", ok.Message);
    }

    [Fact]
    public void Ems_metadata_matches_the_documented_contract()
    {
        var m = new FortiClientEmsAdapter((_, _) => Task.FromResult("{}")).Metadata;
        Assert.Equal("forticlient-ems", m.Id);
        Assert.Equal("FortiClient EMS (endpoints, software, scan findings)", m.DisplayName);
        Assert.Equal(new[] { "host", "username", "password", "verifyTls", "site" }, m.Form.Select(f => f.Key).ToArray());
        Assert.Equal(CredentialTypes.Password, m.Form.Single(f => f.Key == "password").Type);
        Assert.False(m.Form.Single(f => f.Key == "site").Required);
        Assert.Contains("read-only", m.MinimumPermission);
    }

    // ------------------------------------------------------------------ name normalisation

    [Theory]
    [InlineData("Microsoft Windows 11 Professional Edition, 64-bit (build 22631)", "Microsoft", "Windows 11 Version 23H2", "10.0.22631", "22631")]
    [InlineData("Microsoft Windows 11 Enterprise Edition, 64-bit (build 26100.4351)", "Microsoft", "Windows 11 Version 24H2", "10.0.26100.4351", "26100")]
    [InlineData("Microsoft Windows 10 Enterprise Edition, 64-bit (build 19045)", "Microsoft", "Windows 10 Version 22H2", "10.0.19045", "19045")]
    [InlineData("Microsoft Windows 10 Professional Edition, 64-bit (build 19044)", "Microsoft", "Windows 10 Version 21H2", "10.0.19044", "19044")]
    [InlineData("Microsoft Windows Server 2022 Standard Edition, 64-bit (build 20348)", "Microsoft", "Windows Server 2022", "10.0.20348", "20348")]
    [InlineData("Microsoft Windows Server 2019 Datacenter Edition, 64-bit (build 17763)", "Microsoft", "Windows Server 2019", "10.0.17763", "17763")]
    [InlineData("Microsoft Windows Server Datacenter Edition, 64-bit (build 26100)", "Microsoft", "Windows Server 2025", "10.0.26100", "26100")]
    [InlineData("Microsoft Windows Server 2012 R2 Standard Edition, 64-bit (build 9600)", "Microsoft", "Windows Server 2012 R2", "6.3.9600", "9600")]
    [InlineData("Windows 11", "Microsoft", "Windows 11", null, null)]
    [InlineData("Windows 11 (build 22699)", "Microsoft", "Windows 11", "10.0.22699", "22699")]
    [InlineData("macOS Sonoma 14.6.1", "Apple", "macOS", "14.6.1", null)]
    [InlineData("Mac OS X 13.6.7", "Apple", "macOS", "13.6.7", null)]
    [InlineData("Ubuntu 22.04.4 LTS", "Canonical", "Ubuntu", "22.04.4", null)]
    [InlineData("Red Hat Enterprise Linux 9.4 (Plow)", "Red Hat", "Red Hat Enterprise Linux", "9.4", null)]
    public void Os_strings_normalise_to_cna_names(string text, string? vendor, string product, string? version, string? build)
    {
        var os = FortinetOsNames.Parse(text);
        Assert.Equal(vendor, os.Vendor);
        Assert.Equal(product, os.Product);
        Assert.Equal(version, os.Version);
        Assert.Equal(build, os.Build);
    }

    [Fact]
    public void Os_type_decides_the_family_when_the_text_is_bare()
    {
        Assert.Equal("windows", FortinetOsNames.Parse("11 Pro", "windows").Family);
        Assert.Equal("linux", FortinetOsNames.Parse("Rocky Linux 9.3", "linux").Family);
        Assert.Equal("Rocky Linux", FortinetOsNames.Parse("Rocky Linux 9.3", "linux").Product);
        Assert.Equal("macos", FortinetOsNames.Parse("14.5", "mac").Family);
    }

    [Theory]
    [InlineData("Google Chrome 128.0.6613.84", "Google Chrome")]
    [InlineData("7-Zip 23.01 (x64)", "7-Zip")]
    [InlineData("Adobe Acrobat (64-bit)", "Adobe Acrobat")]
    [InlineData("Python 3.12.4 (64-bit)", "Python")]
    [InlineData("Microsoft 365 Apps for enterprise - en-us", "Microsoft 365 Apps for enterprise - en-us")]
    [InlineData("Mozilla Firefox (x64 en-GB)", "Mozilla Firefox")]
    [InlineData("Microsoft SQL Server 2019 (64-bit)", "Microsoft SQL Server 2019")]
    [InlineData("Notepad++ (64-bit x64)", "Notepad++")]
    public void Product_names_lose_trailing_versions_and_architecture_suffixes(string name, string expected)
    {
        var rec = FortiClientEmsAdapter.MapSoftware("x", JsonSerializer.Deserialize<JsonElement>(JsonSerializer.Serialize(new { name, vendor = "v", version = "1" })));
        Assert.NotNull(rec);
        Assert.Equal(expected, rec!.Product);
    }

    [Theory]
    [InlineData("v7.2.5", "7.2.5")]
    [InlineData("S124EF-v7.4.11-build2878 (GA)", "7.4.11")]
    [InlineData("FP221E-v6.4-build0460", "6.4")]
    [InlineData("7.0.12", "7.0.12")]
    [InlineData("", null)]
    public void Firmware_versions_drop_the_v_and_build(string image, string? expected)
    {
        Assert.Equal(expected, FortinetJson.FirmwareVersion(image));
    }
}
