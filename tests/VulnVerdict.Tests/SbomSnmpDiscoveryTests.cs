using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Adapters.Discovery;
using VulnVerdict.Core.Adapters.External;
using VulnVerdict.Core.Adapters.Sbom;
using VulnVerdict.Core.Adapters.Snmp;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Tests;

public class SbomParserTests
{
    private const string CycloneDx15 = """
    {
      "bomFormat": "CycloneDX",
      "specVersion": "1.5",
      "version": 1,
      "metadata": {
        "component": { "type": "application", "name": "webshop", "version": "2.3.1", "group": "com.example", "bom-ref": "app" }
      },
      "components": [
        { "type": "library", "name": "core", "group": "@angular", "version": "16.2.0", "purl": "pkg:npm/%40angular/core@16.2.0" },
        { "type": "library", "name": "Newtonsoft.Json", "version": "13.0.3", "purl": "pkg:nuget/Newtonsoft.Json@13.0.3", "supplier": { "name": "James Newton-King" } },
        { "type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0" },
        { "type": "library", "name": "log4j-core", "group": "org.apache.logging.log4j", "version": "2.17.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1" },
        { "type": "library", "name": "openssl", "version": "3.0.11-1~deb12u2", "purl": "pkg:deb/debian/openssl@3.0.11-1~deb12u2?arch=amd64&distro=debian-12" },
        { "type": "library", "name": "libssl3", "version": "3.0.2-0ubuntu1.12", "purl": "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.12?distro=ubuntu-22.04" },
        { "type": "library", "name": "gin", "version": "v1.9.1", "purl": "pkg:golang/github.com/gin-gonic/gin@v1.9.1" },
        { "type": "library", "name": "serde", "version": "1.0.188", "purl": "pkg:cargo/serde@1.0.188" },
        { "type": "library", "name": "rails", "version": "7.0.8", "purl": "pkg:gem/rails@7.0.8" },
        { "type": "library", "name": "monolog/monolog", "version": "3.4.0", "purl": "pkg:composer/monolog/monolog@3.4.0" },
        { "type": "library", "name": "openssl-libs", "version": "3.0.7-24.el9", "purl": "pkg:rpm/redhat/openssl-libs@3.0.7-24.el9?arch=x86_64" },
        { "type": "operating-system", "name": "debian", "version": "12" },
        { "type": "file", "name": "README.md" }
      ]
    }
    """;

    private const string Spdx23 = """
    {
      "spdxVersion": "SPDX-2.3",
      "dataLicense": "CC0-1.0",
      "SPDXID": "SPDXRef-DOCUMENT",
      "name": "intranet-portal-1.4.0",
      "documentDescribes": ["SPDXRef-Package-app"],
      "packages": [
        { "SPDXID": "SPDXRef-Package-app", "name": "intranet-portal", "versionInfo": "1.4.0", "supplier": "Organization: Example Ltd (security@example.com)", "downloadLocation": "NOASSERTION" },
        { "SPDXID": "SPDXRef-Package-1", "name": "Microsoft.Data.SqlClient", "versionInfo": "5.1.1", "supplier": "Organization: Microsoft",
          "externalRefs": [ { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:nuget/Microsoft.Data.SqlClient@5.1.1" } ] },
        { "SPDXID": "SPDXRef-Package-2", "name": "jquery", "versionInfo": "3.7.1",
          "externalRefs": [ { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/jquery@3.7.1" },
                            { "referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:jquery:jquery:3.7.1:*:*:*:*:*:*:*" } ] },
        { "SPDXID": "SPDXRef-Package-3", "name": "zlib", "versionInfo": "1.2.13", "supplier": "NOASSERTION",
          "externalRefs": [ { "referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:zlib:zlib:1.2.13:*:*:*:*:*:*:*" } ] }
      ],
      "relationships": [ { "spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-app" } ]
    }
    """;

    [Fact]
    public void CycloneDx_15_application_and_components()
    {
        var r = SbomParser.Parse(CycloneDx15, "webshop.example.com");
        Assert.StartsWith("CycloneDX 1.5", r.Format);
        Assert.Equal("webshop", r.ApplicationName);
        Assert.Equal("2.3.1", r.ApplicationVersion);

        var app = Assert.Single(r.Software, s => s.Kind == SoftwareKind.Application);
        Assert.Equal("com.example", app.Vendor);
        Assert.Equal("webshop", app.Product);
        Assert.Equal("webshop.example.com", app.AssetExternalId);

        Assert.DoesNotContain(r.Software, s => s.Product == "README.md");
        Assert.Contains(r.Software, s => s.Product == "debian" && s.Kind == SoftwareKind.OperatingSystem);

        var angular = Assert.Single(r.Software, s => s.Product == "core");
        Assert.Equal(SoftwareKind.Library, angular.Kind);
        Assert.Equal("npm", angular.Ecosystem);
        Assert.Equal("@angular", angular.Vendor);
        Assert.Equal("pkg:npm/%40angular/core@16.2.0", angular.Purl);

        Assert.Equal("NuGet", Assert.Single(r.Software, s => s.Product == "Newtonsoft.Json").Ecosystem);
        Assert.Equal("James Newton-King", Assert.Single(r.Software, s => s.Product == "Newtonsoft.Json").Vendor);
        Assert.Equal("PyPI", Assert.Single(r.Software, s => s.Product == "requests").Ecosystem);
        var log4j = Assert.Single(r.Software, s => s.Product == "log4j-core");
        Assert.Equal("Maven", log4j.Ecosystem);
        Assert.Equal("org.apache.logging.log4j", log4j.Vendor);
        Assert.Equal("Go", Assert.Single(r.Software, s => s.Product == "gin").Ecosystem);
        Assert.Equal("crates.io", Assert.Single(r.Software, s => s.Product == "serde").Ecosystem);
        Assert.Equal("RubyGems", Assert.Single(r.Software, s => s.Product == "rails").Ecosystem);
        Assert.Equal("Packagist", Assert.Single(r.Software, s => s.Product == "monolog/monolog").Ecosystem);

        var openssl = Assert.Single(r.Software, s => s.Product == "openssl");
        Assert.Equal("Debian", openssl.Ecosystem);
        Assert.Equal(SoftwareKind.Package, openssl.Kind);
        Assert.Equal("Ubuntu", Assert.Single(r.Software, s => s.Product == "libssl3").Ecosystem);
        Assert.Equal("Red Hat", Assert.Single(r.Software, s => s.Product == "openssl-libs").Ecosystem);
    }

    [Fact]
    public void Spdx_23_described_package_is_the_application()
    {
        var r = SbomParser.Parse(Spdx23, "portal.corp.local");
        Assert.Equal("SPDX 2.3", r.Format);
        Assert.Equal("intranet-portal", r.ApplicationName);
        Assert.Equal("1.4.0", r.ApplicationVersion);

        var app = Assert.Single(r.Software, s => s.Kind == SoftwareKind.Application);
        Assert.Equal("Example Ltd", app.Vendor);

        var sql = Assert.Single(r.Software, s => s.Product == "Microsoft.Data.SqlClient");
        Assert.Equal(SoftwareKind.Library, sql.Kind);
        Assert.Equal("NuGet", sql.Ecosystem);
        Assert.Equal("Microsoft", sql.Vendor);

        var jquery = Assert.Single(r.Software, s => s.Product == "jquery");
        Assert.Equal("npm", jquery.Ecosystem);
        Assert.Equal("pkg:npm/jquery@3.7.1", jquery.Purl);
        Assert.Equal("cpe:2.3:a:jquery:jquery:3.7.1:*:*:*:*:*:*:*", jquery.Cpe);

        var zlib = Assert.Single(r.Software, s => s.Product == "zlib");
        Assert.Null(zlib.Purl);
        Assert.Null(zlib.Ecosystem);
        Assert.Equal("", zlib.Vendor);
        Assert.NotNull(zlib.Cpe);
        Assert.Equal(4, r.Software.Count);
    }

    [Theory]
    [InlineData("pkg:npm/%40angular/core@16.2.0", "npm", "@angular", "core", "16.2.0", "npm")]
    [InlineData("pkg:nuget/Newtonsoft.Json@13.0.3", "nuget", null, "Newtonsoft.Json", "13.0.3", "NuGet")]
    [InlineData("pkg:pypi/requests@2.31.0", "pypi", null, "requests", "2.31.0", "PyPI")]
    [InlineData("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1?type=jar", "maven", "org.apache.logging.log4j", "log4j-core", "2.17.1", "Maven")]
    [InlineData("pkg:golang/github.com/gin-gonic/gin@v1.9.1", "golang", "github.com/gin-gonic", "gin", "v1.9.1", "Go")]
    [InlineData("pkg:cargo/serde@1.0.188", "cargo", null, "serde", "1.0.188", "crates.io")]
    [InlineData("pkg:gem/rails@7.0.8", "gem", null, "rails", "7.0.8", "RubyGems")]
    [InlineData("pkg:composer/monolog/monolog@3.4.0", "composer", "monolog", "monolog", "3.4.0", "Packagist")]
    [InlineData("pkg:deb/debian/openssl@3.0.11?distro=debian-12", "deb", "debian", "openssl", "3.0.11", "Debian")]
    [InlineData("pkg:deb/ubuntu/libssl3@3.0.2?distro=ubuntu-22.04", "deb", "ubuntu", "libssl3", "3.0.2", "Ubuntu")]
    [InlineData("pkg:rpm/redhat/openssl-libs@3.0.7-24.el9?arch=x86_64", "rpm", "redhat", "openssl-libs", "3.0.7-24.el9", "Red Hat")]
    [InlineData("pkg:rpm/rocky/bash@5.1.8", "rpm", "rocky", "bash", "5.1.8", "Rocky Linux")]
    [InlineData("pkg:apk/alpine/musl@1.2.4-r2", "apk", "alpine", "musl", "1.2.4-r2", "Alpine")]
    [InlineData("pkg:generic/openssl@3.0.11", "generic", null, "openssl", "3.0.11", null)]
    public void Purl_parts_and_osv_ecosystem(string purl, string type, string? ns, string name, string version, string? ecosystem)
    {
        var p = SbomParser.ParsePurl(purl);
        Assert.NotNull(p);
        Assert.Equal(type, p!.Type);
        Assert.Equal(ns, p.Namespace);
        Assert.Equal(name, p.Name);
        Assert.Equal(version, p.Version);
        Assert.Equal(ecosystem, SbomParser.EcosystemFor(p));
    }

    [Fact]
    public void Rejects_documents_that_are_not_an_sbom()
    {
        Assert.Throws<FormatException>(() => SbomParser.Parse("{\"hello\":\"world\"}", "x"));
        Assert.Throws<FormatException>(() => SbomParser.Parse("", "x"));
    }

    [Fact]
    public void Import_result_merges_on_the_asset_name_as_a_hostname()
    {
        var parsed = SbomParser.Parse(CycloneDx15, "webshop.example.com");
        var result = SbomImportService.BuildResult("webshop.example.com", parsed);
        var asset = Assert.Single(result.Assets);
        Assert.Equal("webshop.example.com", asset.ExternalId);
        Assert.Contains("webshop.example.com", asset.Hostnames);
        Assert.Equal(AssetKind.Other, asset.Kind);
        Assert.True(result.FullSnapshot);
        Assert.Equal(parsed.Software.Count, result.Software.Count);
    }
}

public class SnmpMapperTests
{
    [Theory]
    [InlineData("Integrated Dell Remote Access Controller 9 (iDRAC9) Version 7.10.30.00", "1.3.6.1.4.1.674.10892.5", "Dell", "Integrated Dell Remote Access Controller 9", "7.10.30.00", AssetKind.OutOfBandManagement)]
    [InlineData("Integrated Lights-Out 5 2.78 Jul 27 2023", "1.3.6.1.4.1.232.9.4.11", "Hewlett Packard Enterprise (HPE)", "HPE Integrated Lights-Out 5 (iLO 5)", "2.78", AssetKind.OutOfBandManagement)]
    [InlineData("Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(4)E7, RELEASE SOFTWARE (fc2)", "1.3.6.1.4.1.9.1.1208", "Cisco", "Cisco IOS", "15.2(4)E7", AssetKind.Switch)]
    [InlineData("Cisco IOS XE Software, Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc3)", "1.3.6.1.4.1.9.1.2494", "Cisco", "Cisco IOS XE Software", "17.9.4a", AssetKind.Switch)]
    [InlineData("Linux DS920 4.4.302+ #69057 SMP Fri Jan 12 00:00:00 CST 2024 x86_64 DSM 7.2-64570", "1.3.6.1.4.1.6574.1", "Synology", "DiskStation Manager (DSM)", "7.2-64570", AssetKind.Storage)]
    [InlineData("APC Web/SNMP Management Card (MB:v4.1.0 PF:v7.1.2 PN:apc_hw05_aos_712.bin AF1:v7.1.2 AN1:apc_hw05_sumx_712.bin MN:AP9631 HR:05 SN: ZA1234567890 MD:01/02/2023) (Embedded PowerNet SNMP Agent SW v2.2 compatible)", "1.3.6.1.4.1.318.1.3.27", "APC", "Network Management Card 2", "7.1.2", AssetKind.Other)]
    [InlineData("Lexmark MX611dhe version NH61.GM.N631 kernel 4.17.15 All-N-1", "1.3.6.1.4.1.641.1", "Lexmark", "MX611dhe", "NH61.GM.N631", AssetKind.Printer)]
    [InlineData("USW-24-PoE 6.5.59.14777", "1.3.6.1.4.1.41112.1.5", "Ubiquiti", "UniFi Switch (USW-24-PoE)", "6.5.59.14777", AssetKind.Switch)]
    [InlineData("UAP-AC-Pro 6.5.55.14976", "1.3.6.1.4.1.41112.1.4", "Ubiquiti", "UniFi Access Point (UAP-AC-Pro)", "6.5.55.14976", AssetKind.AccessPoint)]
    [InlineData("FortiSwitch-124E v7.4.3,build0740,240215 (GA)", "1.3.6.1.4.1.12356.106.1.1", "Fortinet", "FortiSwitch", "7.4.3", AssetKind.Switch)]
    [InlineData("HP J9772A 2530-48G-PoEP Switch, revision YA.16.10.0026, ROM YA.15.20 (/ws/swbuildm/rel_yakima_qaoff/code/build/lvm(swbuildm_rel_yakima_qaoff_rel_yakima))", "1.3.6.1.4.1.11.2.3.7.11.152", "Hewlett Packard Enterprise (HPE)", "ArubaOS-Switch", "YA.16.10.0026", AssetKind.Switch)]
    [InlineData("Linux TS-453A 4.14.24-qnap #1 SMP Tue Feb 6 00:00:00 CST 2024 x86_64 QTS 5.1.5", "1.3.6.1.4.1.24681.2", "QNAP Systems Inc.", "QTS", "5.1.5", AssetKind.Storage)]
    [InlineData("VMware ESXi 8.0.2 build-22380479 VMware, Inc. x86_64", "1.3.6.1.4.1.6876.4.1", "VMware", "ESXi", "8.0.2", AssetKind.Hypervisor)]
    [InlineData("Hardware: Intel64 Family 6 Model 85 Stepping 7 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)", "1.3.6.1.4.1.311.1.1.3.1.2", "Microsoft", "Windows Server 2019", "17763", AssetKind.Server)]
    [InlineData("Linux web01 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64", "1.3.6.1.4.1.8072.3.2.10", "Linux", "Linux kernel", "5.15.0-91-generic", AssetKind.Server)]
    [InlineData("Brother NC-8300h, Firmware Ver.1.14 (16.06.30),MID 8C5-B29,FID 2", "1.3.6.1.4.1.2435.2.3.9.1", "Brother", "NC-8300h", "1.14", AssetKind.Printer)]
    [InlineData("Juniper Networks, Inc. ex4300-48t Ethernet Switch, kernel JUNOS 18.4R3-S4.2, Build date: 2021-03-04", "1.3.6.1.4.1.2636.1.1.1.2.63", "Juniper Networks", "Junos OS", "18.4R3-S4.2", AssetKind.Switch)]
    public void Maps_sysDescr_and_sysObjectId(string sysDescr, string sysObjectId, string vendor, string product, string version, AssetKind kind)
    {
        var d = SnmpDeviceMapper.Map(sysDescr, sysObjectId);
        Assert.Equal(vendor, d.Vendor);
        Assert.Equal(product, d.Product);
        Assert.Equal(version, d.Version);
        Assert.Equal(kind, d.Kind);
        Assert.True(d.Named);
    }

    [Fact]
    public void Enterprise_number_parses_with_or_without_leading_dot()
    {
        Assert.Equal(674, SnmpDeviceMapper.EnterpriseNumber("1.3.6.1.4.1.674.10892.5"));
        Assert.Equal(9, SnmpDeviceMapper.EnterpriseNumber(".1.3.6.1.4.1.9.1.1208"));
        Assert.Null(SnmpDeviceMapper.EnterpriseNumber("1.3.6.1.2.1.1"));
        Assert.Null(SnmpDeviceMapper.EnterpriseNumber(null));
        Assert.Equal("Fortinet", SnmpDeviceMapper.VendorFor(12356));
    }

    [Fact]
    public void Unknown_vendor_and_family_land_in_the_mapping_queue()
    {
        var known = SnmpDeviceMapper.Map("SG350-28 28-Port Gigabit Managed Switch", "1.3.6.1.4.1.9.6.1.92.28");
        Assert.Equal("Cisco", known.Vendor);
        Assert.True(known.Named);

        var vendorOnly = SnmpDeviceMapper.Map("Managed Switch", "1.3.6.1.4.1.171.10.76.28");
        Assert.Equal("D-Link", vendorOnly.Vendor);
        Assert.Equal("D-Link device", vendorOnly.Product);
        Assert.False(vendorOnly.Named);

        var nothing = SnmpDeviceMapper.Map("Acme Widget 3.1.4", "1.3.6.1.4.1.99999.1");
        Assert.Equal("", nothing.Vendor);
        Assert.Equal("Acme device", nothing.Product);
        Assert.Equal("3.1.4", nothing.Version);
        Assert.False(nothing.Named);
    }
}

public class BannerParserTests
{
    [Fact]
    public void Ssh_openssh()
    {
        var s = BannerParser.FromSsh("10.0.0.5", "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2\r\n");
        Assert.NotNull(s);
        Assert.Equal("OpenBSD", s!.Vendor);
        Assert.Equal("OpenSSH", s.Product);
        Assert.Equal("9.2p1", s.Version);
        Assert.Equal(SoftwareKind.Service, s.Kind);
        Assert.Equal(22, Assert.Single(s.Listeners!).Port);

        var win = BannerParser.FromSsh("10.0.0.6", "SSH-2.0-OpenSSH_for_Windows_9.5");
        Assert.Equal("OpenSSH", win!.Product);
        Assert.Equal("9.5", win.Version);
        Assert.Equal("for Windows", win.Edition);

        var other = BannerParser.FromSsh("10.0.0.7", "SSH-2.0-dropbear_2022.83");
        Assert.Equal("", other!.Vendor);
        Assert.Equal("Dropbear SSH", other.Product);
        Assert.Equal("2022.83", other.Version);

        Assert.Null(BannerParser.FromSsh("10.0.0.8", "HTTP/1.1 400 Bad Request"));
    }

    [Theory]
    [InlineData("nginx/1.24.0", "F5", "NGINX Open Source", "1.24.0")]
    [InlineData("Apache/2.4.58 (Ubuntu)", "Apache Software Foundation", "Apache HTTP Server", "2.4.58")]
    [InlineData("Microsoft-IIS/10.0", "Microsoft", "Internet Information Services", "10.0")]
    [InlineData("lighttpd/1.4.71", "lighttpd", "lighttpd", "1.4.71")]
    [InlineData("Microsoft-HTTPAPI/2.0", "Microsoft", "HTTP.sys", "2.0")]
    [InlineData("cloudflare", "", "cloudflare", "")]
    [InlineData("Acme-Embedded-Server/3.2", "", "Acme-Embedded-Server", "3.2")]
    public void Server_header(string header, string vendor, string product, string version)
    {
        var s = BannerParser.FromServerHeader("10.0.0.9", header, 443);
        Assert.NotNull(s);
        Assert.Equal(vendor, s!.Vendor);
        Assert.Equal(product, s.Product);
        Assert.Equal(version, s.Version);
        Assert.Equal(443, Assert.Single(s.Listeners!).Port);
    }

    [Fact]
    public void Server_header_is_read_from_raw_http()
    {
        Assert.Equal("nginx/1.24.0", BannerParser.ServerHeader("HTTP/1.1 200 OK\r\nDate: x\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\n\r\n<html>Server: fake</html>"));
        Assert.Null(BannerParser.ServerHeader("HTTP/1.1 200 OK\r\nDate: x\r\n\r\n"));
        Assert.Null(BannerParser.FromServerHeader("x", "   ", 80));
    }

    [Fact]
    public void Shodan_products_map_the_same_way()
    {
        var s = BannerParser.FromProduct("1.2.3.4", "Apache httpd", "2.4.58", 80);
        Assert.Equal("Apache Software Foundation", s!.Vendor);
        Assert.Equal("Apache HTTP Server", s.Product);
        Assert.Equal("Microsoft", BannerParser.FromProduct("1.2.3.4", "Microsoft IIS httpd", "10.0", 80)!.Vendor);
        Assert.Null(BannerParser.FromProduct("1.2.3.4", null, null, 80));
    }
}

public class AddressRangeTests
{
    [Fact]
    public void Expands_cidr_single_addresses_and_ranges()
    {
        var warnings = new List<string>();
        var list = AddressRanges.Expand("192.168.1.0/30\n10.0.0.1\n10.0.0.5-10.0.0.7\n# comment\n\n", 100, warnings, resolveHostnames: false);
        Assert.Equal(new[] { "192.168.1.1", "192.168.1.2", "10.0.0.1", "10.0.0.5", "10.0.0.6", "10.0.0.7" }, list.Select(e => e.Address.ToString()).ToArray());
        Assert.Empty(warnings);

        var capped = AddressRanges.Expand("10.0.0.0/16", 50, warnings, resolveHostnames: false);
        Assert.Equal(50, capped.Count);
        Assert.Contains(warnings, w => w.Contains("capped"));

        var bad = AddressRanges.Expand("not-an-ip", 10, warnings, resolveHostnames: false);
        Assert.Empty(bad);
        Assert.Contains(warnings, w => w.Contains("not-an-ip"));
    }

    [Fact]
    public void Parses_port_lists()
    {
        Assert.Equal(new[] { 22, 80, 443, 8080, 8081, 8082 }, AddressRanges.ParsePorts("22, 80,443,8080-8082, 70000, x", "1"));
        Assert.Equal(new[] { 443, 80 }, AddressRanges.ParsePorts("", "443,80"));
    }

    [Fact]
    public void Discovery_kind_guess()
    {
        Assert.Equal(AssetKind.Server, DiscoverySweepAdapter.GuessKind(new[] { 22, 3389 }));
        Assert.Equal(AssetKind.Printer, DiscoverySweepAdapter.GuessKind(new[] { 80, 9100 }));
        Assert.Equal(AssetKind.OutOfBandManagement, DiscoverySweepAdapter.GuessKind(new[] { 443, 623 }));
        Assert.Equal(AssetKind.Server, DiscoverySweepAdapter.GuessKind(new[] { 22 }));
        Assert.Equal(AssetKind.Other, DiscoverySweepAdapter.GuessKind(new[] { 80, 443 }));
    }
}

public class LiveNetworkTests
{
    private sealed class PlainHttpFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new() { Timeout = TimeSpan.FromSeconds(20) };
    }

    [Fact]
    public async Task Discovery_sweep_of_loopback_completes()
    {
        var adapter = new DiscoverySweepAdapter(NullLogger<DiscoverySweepAdapter>.Instance);
        var creds = new Dictionary<string, string>
        {
            ["subnets"] = "127.0.0.1",
            ["ports"] = DiscoverySweepAdapter.DefaultPorts,
            ["timeoutMs"] = "500",
            ["concurrency"] = "8",
        };
        var test = await adapter.TestAsync(creds, CancellationToken.None);
        Assert.True(test.Ok, test.Message);

        var progress = new List<string>();
        var result = await adapter.CollectAsync(creds, null, new Progress<string>(progress.Add), CancellationToken.None);
        Assert.NotNull(result);
        Assert.True(result.FullSnapshot);
        Assert.Contains(result.Warnings, w => w.Contains("of 1 addresses answered"));
        // open ports on the test machine vary; when something answered it must be reported as 127.0.0.1
        foreach (var a in result.Assets)
        {
            Assert.Equal("127.0.0.1", a.ExternalId);
            Assert.Contains("127.0.0.1", a.IpAddresses);
        }
        foreach (var s in result.Software) Assert.Equal("127.0.0.1", s.AssetExternalId);
        Assert.StartsWith("discovery", adapter.Metadata.Id);
    }

    [Fact]
    public async Task External_cross_check_resolves_dns_google_and_probes_443()
    {
        IPAddress[] resolved;
        try { resolved = await Dns.GetHostAddressesAsync("dns.google"); }
        catch (Exception) { return; } // offline: nothing to check
        if (resolved.Length == 0) return;

        var adapter = new ExternalCrossCheckAdapter(new PlainHttpFactory(), NullLogger<ExternalCrossCheckAdapter>.Instance);
        var creds = new Dictionary<string, string> { ["dnsNames"] = "dns.google", ["ports"] = "443", ["timeoutMs"] = "4000" };
        var result = await adapter.CollectAsync(creds, null, null, CancellationToken.None);
        Assert.NotNull(result);
        Assert.Contains(result.Warnings, w => w.Contains("not from the internet"));

        // only insist on an Internet tag when the console itself can reach 8.8.8.8:443 (proxies and egress filters exist)
        var v4 = resolved.FirstOrDefault(i => i.AddressFamily == AddressFamily.InterNetwork);
        if (v4 is null || !await TcpProbe.IsOpenAsync(v4, 443, 4000, CancellationToken.None)) return;

        var exposure = Assert.Single(result.Exposures, e => e.IpAddress == v4.ToString());
        Assert.Equal(Exposure.Internet, exposure.Exposure);
        Assert.Contains("tcp/443", exposure.Evidence);
        Assert.Equal("dns.google", exposure.Hostname);
        var asset = Assert.Single(result.Assets, a => a.ExternalId == v4.ToString());
        Assert.Contains("dns.google", asset.Hostnames);
        Assert.Equal(AssetKind.Other, asset.Kind);
    }
}
