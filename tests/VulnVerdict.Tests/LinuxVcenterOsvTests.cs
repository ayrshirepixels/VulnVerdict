using System.Net;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Adapters.Linux;
using VulnVerdict.Core.Adapters.Packages;
using VulnVerdict.Core.Adapters.VMware;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Tests;

/// <summary>Skipped when VULNVERDICT_OFFLINE is set, so the suite passes without network access.</summary>
public sealed class LiveOsvFactAttribute : FactAttribute
{
    public LiveOsvFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("VULNVERDICT_OFFLINE") is { Length: > 0 }) Skip = "VULNVERDICT_OFFLINE is set; live OSV test skipped";
    }
}

public class LinuxVcenterOsvTests
{
    private static string FixturePath(string relative, [CallerFilePath] string here = "") =>
        Path.Combine(Path.GetDirectoryName(here)!, "Fixtures", relative.Replace('/', Path.DirectorySeparatorChar));

    private static string Fixture(string relative) => File.ReadAllText(FixturePath(relative));

    // ================================================================== Linux over SSH

    [Fact]
    public void Ubuntu_os_release_maps_to_osv_ecosystem_and_vendor()
    {
        var os = SshLinuxAdapter.ParseOsRelease(Fixture("linux/os-release-ubuntu"));
        Assert.Equal("ubuntu", os["ID"]);
        Assert.Equal("22.04", os["VERSION_ID"]);
        Assert.Equal("Ubuntu 22.04.4 LTS", os["PRETTY_NAME"]);

        var d = SshLinuxAdapter.DistroInfo(os);
        Assert.Equal("Canonical", d.Vendor);
        Assert.Equal("Ubuntu", d.Name);
        Assert.Equal("Ubuntu:22.04:LTS", d.Ecosystem);
        Assert.Equal("ubuntu", d.PurlNamespace);
        Assert.Equal("ubuntu-22.04", d.DistroQualifier);
    }

    [Theory]
    [InlineData("ID=debian\nVERSION_ID=\"12\"\nNAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"", "Debian", "Debian:12", "debian")]
    [InlineData("ID=alpine\nVERSION_ID=3.20.1\nNAME=\"Alpine Linux\"", "Alpine Linux", "Alpine:v3.20", "alpine")]
    [InlineData("ID=\"rhel\"\nVERSION_ID=\"9.4\"\nNAME=\"Red Hat Enterprise Linux\"\nCPE_NAME=\"cpe:/o:redhat:enterprise_linux:9::baseos\"", "Red Hat", "Red Hat:enterprise_linux:9::baseos", "redhat")]
    [InlineData("ID=\"almalinux\"\nVERSION_ID=\"9.4\"\nNAME=\"AlmaLinux\"", "AlmaLinux", "AlmaLinux:9", "almalinux")]
    [InlineData("ID=\"rocky\"\nVERSION_ID=\"9.3\"\nNAME=\"Rocky Linux\"", "Rocky Linux", "Rocky Linux:9", "rocky")]
    [InlineData("ID=ubuntu\nVERSION_ID=\"23.10\"\nVERSION=\"23.10 (Mantic Minotaur)\"\nNAME=\"Ubuntu\"", "Canonical", "Ubuntu:23.10", "ubuntu")]
    [InlineData("ID=\"opensuse-leap\"\nVERSION_ID=\"15.5\"\nNAME=\"openSUSE Leap\"", "SUSE", "openSUSE:Leap:15.5", "opensuse")]
    [InlineData("ID=fedora\nVERSION_ID=40\nNAME=\"Fedora Linux\"", "Fedora Project", null, "fedora")]
    public void Distribution_ecosystem_strings_follow_the_osv_schema(string osRelease, string vendor, string? ecosystem, string ns)
    {
        var d = SshLinuxAdapter.DistroInfo(SshLinuxAdapter.ParseOsRelease(osRelease));
        Assert.Equal(vendor, d.Vendor);
        Assert.Equal(ecosystem, d.Ecosystem);
        Assert.Equal(ns, d.PurlNamespace);
    }

    [Fact]
    public void Dpkg_output_yields_source_packages_and_skips_removed_ones()
    {
        var pkgs = SshLinuxAdapter.ParseDpkg(Fixture("linux/dpkg-sample.txt"));
        Assert.Equal(12, pkgs.Count); // the config-files line is dropped
        var libssl = Assert.Single(pkgs, p => p.Name == "libssl3");
        Assert.Equal("openssl", libssl.Source);
        Assert.Equal("3.0.2-0ubuntu1.10", libssl.Version);
        Assert.Equal("amd64", libssl.Architecture);
        var libcBin = Assert.Single(pkgs, p => p.Name == "libc-bin");
        Assert.Equal("glibc", libcBin.Source);
        Assert.Equal("2.35-0ubuntu3.6", libcBin.Version);
        Assert.Equal("openssh", Assert.Single(pkgs, p => p.Name == "openssh-server").Source);
        Assert.DoesNotContain(pkgs, p => p.Name == "removed-tool");
    }

    [Fact]
    public void Rpm_and_apk_output_parse_with_source_names()
    {
        var rpm = SshLinuxAdapter.ParseRpm("openssl-libs\t1:3.0.7-24.el9\tx86_64\topenssl-3.0.7-24.el9.src.rpm\nkernel-core\t5.14.0-427.13.1.el9_4\tx86_64\tkernel-5.14.0-427.13.1.el9_4.src.rpm\ngpg-pubkey\t8483c65d-5ccc5b19\t(none)\t(none)\n");
        Assert.Equal(2, rpm.Count);
        Assert.Equal("openssl", rpm[0].Source);
        Assert.Equal("1:3.0.7-24.el9", rpm[0].Version);
        Assert.Equal("kernel", rpm[1].Source);

        var apk = SshLinuxAdapter.ParseApk("openssl-3.1.4-r0 x86_64 {openssl} (Apache-2.0) [installed]\nlibssl3-3.1.4-r0 x86_64 {openssl} (Apache-2.0) [installed]\npy3-six-1.16.0-r6 x86_64 {py3-six} (MIT) [installed]\n");
        Assert.Equal(3, apk.Count);
        Assert.Equal("libssl3", apk[1].Name);
        Assert.Equal("openssl", apk[1].Source);
        Assert.Equal("3.1.4-r0", apk[1].Version);
        Assert.Equal("py3-six", apk[2].Name);
        Assert.Equal("1.16.0-r6", apk[2].Version);

        var apkInfo = SshLinuxAdapter.ParseApk("#arch=aarch64\nmusl-1.2.4-r2\nbusybox-1.36.1-r15\n");
        Assert.Equal(2, apkInfo.Count);
        Assert.Equal("aarch64", apkInfo[0].Architecture);
        Assert.Equal("1.2.4-r2", apkInfo[0].Version);
    }

    [Fact]
    public void Ss_output_yields_listeners_with_process_and_bind()
    {
        var listeners = SshLinuxAdapter.ParseSs(Fixture("linux/ss-sample.txt"));
        Assert.Equal(5, listeners.Count); // 22 on 0.0.0.0 and [::] collapse into one
        var ssh = Assert.Single(listeners, l => l.Port == 22);
        Assert.Equal("tcp", ssh.Protocol);
        Assert.Equal("*", ssh.Bind);
        Assert.Equal("sshd", ssh.Process);
        var pg = Assert.Single(listeners, l => l.Port == 5432);
        Assert.Equal("127.0.0.1", pg.Bind);
        Assert.Equal("postgres", pg.Process);
        Assert.Equal("127.0.0.53", Assert.Single(listeners, l => l.Port == 53).Bind);
        Assert.Equal("nginx", Assert.Single(listeners, l => l.Port == 80).Process);
        Assert.Null(Assert.Single(listeners, l => l.Port == 9100).Process);

        var netstat = SshLinuxAdapter.ParseNetstat("Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      812/sshd: /usr/sbin\ntcp6       0      0 :::22                   :::*                    LISTEN      812/sshd: /usr/sbin\ntcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -\n");
        Assert.Equal(2, netstat.Count);
        Assert.Equal("sshd", netstat[0].Process);
        Assert.Null(netstat[1].Process);
    }

    [Fact]
    public void Ip_link_and_addr_output_skip_virtual_interfaces_and_link_local()
    {
        var macs = SshLinuxAdapter.ParseMacs(Fixture("linux/ip-link-sample.txt"));
        Assert.Equal(new[] { "bc:24:11:aa:bb:cc" }, macs);
        var ips = SshLinuxAdapter.ParseIpAddr(Fixture("linux/ip-addr-sample.txt")).ToArray();
        Assert.Equal(new[] { "10.20.0.11", "2001:db8:1::11", "172.17.0.1" }, ips);
        Assert.Equal(new[] { "10.20.0.11" }, SshLinuxAdapter.ParseIps("10.20.0.11 127.0.0.1 fe80::1 \n").ToArray());
    }

    [Theory]
    [InlineData("web01", "web01", 22)]
    [InlineData("web01.example.com:2222", "web01.example.com", 2222)]
    [InlineData("[2001:db8::5]:2200", "2001:db8::5", 2200)]
    [InlineData("2001:db8::5", "2001:db8::5", 22)]
    public void Host_lines_parse_with_optional_port(string line, string host, int port)
    {
        var t = SshTarget.Parse(line);
        Assert.Equal(host, t.Host);
        Assert.Equal(port, t.Port);
        Assert.Equal(line, t.AsTyped);
    }

    [Fact]
    public void Purls_follow_the_deb_rpm_and_apk_conventions()
    {
        Assert.Equal("pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?arch=amd64&distro=ubuntu-22.04", SshLinuxAdapter.BuildPurl("deb", "ubuntu", "openssl", "3.0.2-0ubuntu1.10", "amd64", "ubuntu-22.04"));
        Assert.Equal("pkg:deb/debian/curl@7.88.1-10+deb12u5?arch=amd64&distro=debian-12", SshLinuxAdapter.BuildPurl("deb", "debian", "curl", "7.88.1-10+deb12u5", "amd64", "debian-12"));
        Assert.Equal("pkg:rpm/redhat/openssl@3.0.7-24.el9?arch=x86_64&distro=rhel-9&epoch=1", SshLinuxAdapter.BuildPurl("rpm", "redhat", "openssl", "1:3.0.7-24.el9", "x86_64", "rhel-9"));
        Assert.Equal("pkg:apk/alpine/openssl@3.1.4-r0?arch=x86_64&distro=alpine-3.18", SshLinuxAdapter.BuildPurl("apk", "alpine", "openssl", "3.1.4-r0", "x86_64", "alpine-3.18"));
        Assert.Equal("pkg:deb/ubuntu/openssh@1:8.9p1-3ubuntu0.6?arch=amd64&distro=ubuntu-22.04", SshLinuxAdapter.BuildPurl("deb", "ubuntu", "openssh", "1:8.9p1-3ubuntu0.6", "amd64", "ubuntu-22.04"));
    }

    private static FakeSsh UbuntuHost(bool docker = true)
    {
        var f = new FakeSsh()
            .On("os-release", Fixture("linux/os-release-ubuntu"))
            .On("command -v", docker ? "dpkg-query\nss\ndocker\n" : "dpkg-query\nss\n")
            .On("hostname -f", "web01.example.com\n")
            .On("hostname -I", "10.20.0.11 172.17.0.1 \n")
            .On("ip -o addr", Fixture("linux/ip-addr-sample.txt"))
            .On("ip -o link", Fixture("linux/ip-link-sample.txt"))
            .On("dpkg-query", Fixture("linux/dpkg-sample.txt"))
            .On("ss -tlnp", Fixture("linux/ss-sample.txt"))
            .On("docker ps", "web\tnginx:1.25.3\napi\tregistry.example.com:5000/acme/api:2.3.1\n");
        return f;
    }

    [Fact]
    public async Task Ssh_adapter_maps_an_ubuntu_host_to_asset_os_packages_listeners_and_containers()
    {
        var fake = UbuntuHost();
        var adapter = new SshLinuxAdapter(NullLogger<SshLinuxAdapter>.Instance) { SessionFactory = (_, _, _) => Task.FromResult<ISshSession>(fake) };
        var creds = new Dictionary<string, string> { ["hosts"] = "web01.example.com\n", ["username"] = "vv", ["password"] = "x" };

        var result = await adapter.CollectAsync(creds, null, null, CancellationToken.None);

        Assert.DoesNotContain(fake.Commands, c => c.Contains("sudo"));
        var asset = Assert.Single(result.Assets);
        Assert.Equal("web01.example.com", asset.ExternalId);
        Assert.Equal("web01", asset.DisplayName);
        Assert.Equal(AssetKind.ContainerHost, asset.Kind);
        Assert.Equal("Canonical", asset.OsVendor);
        Assert.Equal("Ubuntu 22.04.4 LTS", asset.OsProduct);
        Assert.Equal("22.04", asset.OsVersion);
        Assert.Contains("web01.example.com", asset.Hostnames);
        Assert.Contains("web01", asset.Hostnames);
        Assert.Contains("10.20.0.11", asset.IpAddresses);
        Assert.Contains("2001:db8:1::11", asset.IpAddresses);
        Assert.Equal(new[] { "bc:24:11:aa:bb:cc" }, asset.MacAddresses);

        var os = Assert.Single(result.Software, s => s.Kind == SoftwareKind.OperatingSystem);
        Assert.Equal("Canonical", os.Vendor);
        Assert.Equal("Ubuntu", os.Product);
        Assert.Equal("22.04", os.Version);
        Assert.NotNull(os.Listeners);
        Assert.Equal(5, os.Listeners!.Length);
        Assert.Contains(os.Listeners, l => l.Port == 22 && l.Process == "sshd");

        var packages = result.Software.Where(s => s.Kind == SoftwareKind.Package).ToList();
        Assert.Equal(8, packages.Count); // one row per source package: adduser, base-files, bash, curl, openssl, openssh, six, glibc
        Assert.All(packages, p => Assert.Equal("Ubuntu:22.04:LTS", p.Ecosystem));
        Assert.All(packages, p => Assert.Equal("Ubuntu", p.Vendor));
        var openssl = Assert.Single(packages, p => p.Product == "openssl");
        Assert.Equal("3.0.2-0ubuntu1.10", openssl.Version);
        Assert.Equal("pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?arch=amd64&distro=ubuntu-22.04", openssl.Purl);
        Assert.Equal("amd64", openssl.Architecture);
        Assert.Equal("deb:openssl:amd64", openssl.ExternalId);
        Assert.Equal("pkg:deb/ubuntu/six@1.16.0-3ubuntu1?arch=all&distro=ubuntu-22.04", Assert.Single(packages, p => p.Product == "six").Purl);
        Assert.DoesNotContain(packages, p => p.Product == "libssl3");

        var containers = result.Software.Where(s => s.Vendor == "container").ToList();
        Assert.Equal(2, containers.Count);
        Assert.Contains(containers, c => c.Product == "nginx" && c.Version == "1.25.3" && c.ExternalId == "container:web" && c.Kind == SoftwareKind.Application);
        Assert.Contains(containers, c => c.Product == "registry.example.com:5000/acme/api" && c.Version == "2.3.1");

        Assert.Contains(result.Warnings, w => w.Contains("not pinned"));
    }

    [Fact]
    public async Task Ssh_adapter_pinned_host_key_and_no_docker_give_a_plain_server_without_warnings()
    {
        var fake = UbuntuHost(docker: false);
        var adapter = new SshLinuxAdapter(NullLogger<SshLinuxAdapter>.Instance) { SessionFactory = (_, _, _) => Task.FromResult<ISshSession>(fake) };
        var creds = new Dictionary<string, string>
        {
            ["hosts"] = "web01.example.com", ["username"] = "vv", ["privateKey"] = "-----BEGIN OPENSSH PRIVATE KEY-----",
            ["knownHostKeys"] = "web01.example.com SHA256:" + fake.HostKeyFingerprint
        };
        var result = await adapter.CollectAsync(creds, null, null, CancellationToken.None);
        Assert.Equal(AssetKind.Server, Assert.Single(result.Assets).Kind);
        Assert.Empty(result.Warnings);

        var test = await adapter.TestAsync(creds, CancellationToken.None);
        Assert.True(test.Ok, test.Message);
        Assert.Contains("Ubuntu 22.04.4 LTS", test.Message);
        Assert.DoesNotContain("first time", test.Message);
    }

    [Fact]
    public async Task Ssh_adapter_test_reports_unpinned_fingerprints_and_failed_hosts()
    {
        var fake = UbuntuHost();
        var adapter = new SshLinuxAdapter(NullLogger<SshLinuxAdapter>.Instance)
        {
            SessionFactory = (t, o, _) => t.Host == "bad" ? throw new InvalidOperationException("connection refused") : Task.FromResult<ISshSession>(fake)
        };
        var creds = new Dictionary<string, string> { ["hosts"] = "web01.example.com\nbad:2222", ["username"] = "vv", ["password"] = "x" };
        var test = await adapter.TestAsync(creds, CancellationToken.None);
        Assert.False(test.Ok);
        Assert.Contains("bad:2222: connection refused", test.Message);
        Assert.Contains("web01.example.com SHA256:" + fake.HostKeyFingerprint, test.Message);

        var collect = await adapter.CollectAsync(creds, null, null, CancellationToken.None);
        Assert.Single(collect.Assets);
        Assert.Contains(collect.Warnings, w => w.StartsWith("bad:2222: connection refused"));
    }

    [Fact]
    public void Ssh_adapter_metadata_states_read_only_minimum_permission()
    {
        var m = new SshLinuxAdapter(NullLogger<SshLinuxAdapter>.Instance).Metadata;
        Assert.Equal("ssh-linux", m.Id);
        Assert.Equal("Linux servers (SSH)", m.DisplayName);
        Assert.Contains("no sudo", m.MinimumPermission);
        Assert.Contains(m.Form, f => f.Key == "acceptAny" && f.Type == CredentialTypes.Bool && f.Default == "false");
        Assert.Contains(m.Form, f => f.Key == "knownHostKeys" && f.Type == CredentialTypes.TextArea);
        Assert.Contains(m.Form, f => f.Key == "password" && f.Type == CredentialTypes.Password && !f.Required);
    }

    // ================================================================== vCenter

    [Fact]
    public void Vm_fixtures_map_to_a_virtual_machine_asset()
    {
        using var list = JsonDocument.Parse(Fixture("vcenter/vm-list.json"));
        using var identity = JsonDocument.Parse(Fixture("vcenter/guest-identity.json"));
        using var interfaces = JsonDocument.Parse(Fixture("vcenter/guest-interfaces.json"));
        using var detail = JsonDocument.Parse(Fixture("vcenter/vm-detail.json"));

        var vm = list.RootElement.EnumerateArray().First();
        var a = VCenterAdapter.MapVm(vm, identity.RootElement, interfaces.RootElement, detail.RootElement);
        Assert.Equal("vm-101", a.ExternalId);
        Assert.Equal("web01", a.DisplayName);
        Assert.Equal(AssetKind.VirtualMachine, a.Kind);
        Assert.Equal(new[] { "web01.example.com" }, a.Hostnames);
        Assert.Equal(new[] { "10.20.0.11" }, a.IpAddresses); // link-local dropped
        Assert.Equal(new[] { "00:50:56:a1:b2:c3" }, a.MacAddresses);
        Assert.Equal("Ubuntu Linux (64-bit)", a.OsProduct);
        Assert.Equal("Canonical", a.OsVendor);

        var off = VCenterAdapter.MapVm(list.RootElement.EnumerateArray().Last(), null, null, detail.RootElement);
        Assert.Equal("vm-103", off.ExternalId);
        Assert.Equal(new[] { "00:50:56:a1:b2:c3" }, off.MacAddresses);
        Assert.Equal("UBUNTU_64", off.OsProduct);
        Assert.Empty(off.Hostnames);
    }

    [Fact]
    public void Host_and_version_fixtures_map_to_hypervisors_and_a_short_version()
    {
        using var hosts = JsonDocument.Parse(Fixture("vcenter/host-list.json"));
        var mapped = hosts.RootElement.EnumerateArray().Select(VCenterAdapter.MapHost).ToList();
        Assert.All(mapped, h => Assert.Equal(AssetKind.Hypervisor, h.Kind));
        Assert.All(mapped, h => Assert.Equal(Criticality.Critical, h.Criticality));
        Assert.Equal(new[] { "esxi01.example.com" }, mapped[0].Hostnames);
        Assert.Equal("ESXi", mapped[0].OsProduct);
        Assert.Equal(new[] { "10.20.0.3" }, mapped[1].IpAddresses);
        Assert.Empty(mapped[1].Hostnames);

        using var version = JsonDocument.Parse(Fixture("vcenter/version.json"));
        var (v, build) = VCenterAdapter.ParseVersion(version.RootElement);
        Assert.Equal("8.0.2", v);
        Assert.Equal("22617221", build);
        Assert.Equal("https://vc.example.com", VCenterAdapter.BaseUrl("vc.example.com/"));
    }

    private static FakeVCenter FullVCenter() => new FakeVCenter()
        .Route("/api/appliance/system/version", Fixture("vcenter/version.json"))
        .Route("/api/vcenter/host", Fixture("vcenter/host-list.json"))
        .Route("/api/vcenter/vm", Fixture("vcenter/vm-list.json"))
        .Route("/api/vcenter/vm/vm-101", Fixture("vcenter/vm-detail.json"))
        .Route("/api/vcenter/vm/vm-101/guest/identity", Fixture("vcenter/guest-identity.json"))
        .Route("/api/vcenter/vm/vm-101/guest/networking/interfaces", Fixture("vcenter/guest-interfaces.json"))
        .Route("/api/vcenter/vm/vm-102", "{\"name\":\"db01\",\"guest_OS\":\"WINDOWS_SERVER_2022\",\"nics\":{\"4000\":{\"mac_address\":\"00:50:56:d1:d2:d3\"}}}")
        .Route("/api/vcenter/vm/vm-102/guest/identity", "{\"family\":\"WINDOWS\",\"full_name\":{\"default_message\":\"Microsoft Windows Server 2022 (64-bit)\",\"id\":\"x\",\"args\":[]},\"host_name\":\"db01.example.com\",\"ip_address\":\"10.20.0.12\",\"name\":\"WINDOWS_SERVER_2022\"}")
        .Route("/api/vcenter/vm/vm-103", "{\"name\":\"legacy-off\",\"guest_OS\":\"CENTOS_7_64\",\"nics\":{\"4000\":{\"mac_address\":\"00:50:56:e1:e2:e3\"}}}");

    [Fact]
    public async Task Vcenter_collection_emits_appliance_hosts_and_the_complete_vm_list()
    {
        var fake = FullVCenter();
        var result = await VCenterAdapter.CollectFromAsync(fake, "vc.example.com", 4, null, CancellationToken.None);

        Assert.Equal(6, result.Assets.Count);
        var vc = Assert.Single(result.Assets, a => a.ExternalId == "vcenter:vc.example.com");
        Assert.Equal(AssetKind.Server, vc.Kind);
        Assert.Equal(Criticality.Critical, vc.Criticality);
        Assert.Equal("22617221", vc.OsBuild);
        var vcSoftware = Assert.Single(result.Software, s => s.Product == "vCenter Server");
        Assert.Equal("VMware", vcSoftware.Vendor);
        Assert.Equal("8.0.2", vcSoftware.Version);
        Assert.Equal(vc.ExternalId, vcSoftware.AssetExternalId);

        Assert.Equal(2, result.Assets.Count(a => a.Kind == AssetKind.Hypervisor));
        Assert.DoesNotContain(result.Software, s => s.Product == "ESXi"); // version not exposed by the REST API
        Assert.Contains(result.Warnings, w => w.Contains("ESXi version"));

        var vms = result.Assets.Where(a => a.Kind == AssetKind.VirtualMachine).ToList();
        Assert.Equal(3, vms.Count);
        Assert.Equal("Microsoft", Assert.Single(vms, v => v.ExternalId == "vm-102").OsVendor);
        Assert.Contains("db01.example.com", Assert.Single(vms, v => v.ExternalId == "vm-102").Hostnames);
        var off = Assert.Single(vms, v => v.ExternalId == "vm-103");
        Assert.Equal(new[] { "00:50:56:e1:e2:e3" }, off.MacAddresses);
        Assert.Equal("CentOS", off.OsVendor);
        Assert.Contains(result.Warnings, w => w.Contains("1 of 3 VMs"));
        Assert.All(fake.Paths, p => Assert.StartsWith("/", p));
    }

    [Fact]
    public async Task Vcenter_adapter_uses_the_session_factory_with_https_base_url()
    {
        var fake = FullVCenter();
        string? seenBase = null; bool? seenVerify = null;
        var adapter = new VCenterAdapter(new StubHttpFactory(), NullLogger<VCenterAdapter>.Instance)
        {
            SessionFactory = (b, u, p, verify, _) => { seenBase = b; seenVerify = verify; return Task.FromResult<IVCenterSession>(fake); }
        };
        Assert.Equal("vcenter", adapter.Metadata.Id);
        Assert.Contains("Read-Only", adapter.Metadata.MinimumPermission);
        var creds = new Dictionary<string, string> { ["host"] = "vc.example.com", ["username"] = "ro@vsphere.local", ["password"] = "x", ["verifyTls"] = "false" };

        var test = await adapter.TestAsync(creds, CancellationToken.None);
        Assert.True(test.Ok, test.Message);
        Assert.Contains("8.0.2", test.Message);
        Assert.Contains("2 ESXi hosts, 3 VMs", test.Message);
        Assert.Equal("https://vc.example.com", seenBase);
        Assert.False(seenVerify);

        var result = await adapter.CollectAsync(creds, null, null, CancellationToken.None);
        Assert.Equal(6, result.Assets.Count);
    }

    // ================================================================== OSV

    [Fact]
    public void Osv_queries_use_ecosystem_and_name_when_known_and_a_stripped_purl_otherwise()
    {
        var eco = OsvPackageVulnSource.BuildQuery(new PackageQuery("k", "Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1.10", "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?arch=amd64&distro=ubuntu-22.04"));
        Assert.Equal("{\"package\":{\"name\":\"openssl\",\"ecosystem\":\"Ubuntu:22.04:LTS\"},\"version\":\"3.0.2-0ubuntu1.10\"}", eco!.ToJsonString());

        var purl = OsvPackageVulnSource.BuildQuery(new PackageQuery("k", "", "curl", "7.81.0-1ubuntu1.16", "pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.16?arch=amd64&distro=ubuntu-22.04"));
        Assert.Equal("{\"package\":{\"purl\":\"pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.16\"}}", purl!.ToJsonString());

        var purlNoVersion = OsvPackageVulnSource.BuildQuery(new PackageQuery("k", "", "curl", "7.81.0", "pkg:deb/ubuntu/curl"));
        Assert.Equal("{\"package\":{\"purl\":\"pkg:deb/ubuntu/curl\"},\"version\":\"7.81.0\"}", purlNoVersion!.ToJsonString());

        Assert.Null(OsvPackageVulnSource.BuildQuery(new PackageQuery("k", "", "", "", null)));
        Assert.Equal("openssl", OsvPackageVulnSource.PurlName("pkg:deb/debian/openssl@1.1.1n-0+deb11u3?arch=amd64"));
    }

    [Fact]
    public void Osv_batch_response_and_vuln_detail_yield_cve_alias_and_fixed_version()
    {
        var batch = OsvPackageVulnSource.ParseBatchResponse(Fixture("osv/querybatch-response.json"));
        Assert.Equal(2, batch.Count);
        Assert.Equal(new[] { "UBUNTU-CVE-2023-2975", "USN-6450-1", "MAL-2024-0001" }, batch[0].Ids);
        Assert.Null(batch[0].NextPageToken);
        Assert.Empty(batch[1].Ids);

        var v = OsvPackageVulnSource.ParseVuln(Fixture("osv/vuln-detail.json"))!;
        Assert.Equal("UBUNTU-CVE-2023-2975", v.Id);
        Assert.Equal(new[] { "CVE-2023-2975" }, v.CveIds); // from upstream and the id; USN in related is not a CVE
        Assert.False(v.Withdrawn);
        var q = new PackageQuery("k", "Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1.10", null);
        Assert.Equal("3.0.2-0ubuntu1.12", OsvPackageVulnSource.FindFixedVersion(v, q)); // the Pro entry without a fix is not preferred

        var usn = OsvPackageVulnSource.ParseVuln(Fixture("osv/vuln-usn.json"))!;
        Assert.Equal(new[] { "CVE-2023-2975", "CVE-2023-3446", "CVE-2023-3817" }, usn.CveIds);

        var alsa = OsvPackageVulnSource.ParseVuln(Fixture("osv/vuln-alsa.json"))!;
        Assert.Equal(new[] { "CVE-2022-4203", "CVE-2022-4304", "CVE-2023-0286" }, alsa.CveIds); // related is the fallback
        Assert.Equal("1:3.0.1-47.el9_1", OsvPackageVulnSource.FindFixedVersion(alsa, new PackageQuery("k", "AlmaLinux:9", "openssl", "1:3.0.1-45.el9", null)));

        var none = OsvPackageVulnSource.ParseVuln("{\"id\":\"MAL-2024-0001\",\"summary\":\"malicious package\",\"affected\":[]}")!;
        Assert.Empty(none.CveIds);
    }

    [Fact]
    public async Task Osv_lookup_batches_fetches_details_once_and_honours_429()
    {
        var handler = new FakeOsvHandler();
        handler.Batch(Fixture("osv/querybatch-response.json"), first429: true);
        handler.Vuln("UBUNTU-CVE-2023-2975", Fixture("osv/vuln-detail.json"));
        handler.Vuln("USN-6450-1", Fixture("osv/vuln-usn.json"));
        handler.Vuln("MAL-2024-0001", "{\"id\":\"MAL-2024-0001\",\"affected\":[]}");
        var source = new OsvPackageVulnSource(new HttpClient(handler)) { MaxConcurrentDetailFetches = 2 };

        var vulns = await source.LookupAsync(new[]
        {
            new PackageQuery("a", "Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1.10", "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?arch=amd64&distro=ubuntu-22.04"),
            new PackageQuery("b", "", "curl", "7.81.0-1ubuntu1.16", "pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.16?arch=amd64&distro=ubuntu-22.04"),
        }, CancellationToken.None);

        Assert.Equal(2, handler.BatchCalls); // one 429, one success
        Assert.Contains("\"ecosystem\":\"Ubuntu:22.04:LTS\"", handler.LastBatchBody);
        Assert.Contains("\"purl\":\"pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.16\"", handler.LastBatchBody);
        Assert.Equal(3, handler.VulnCalls);
        Assert.Equal(5, source.Requests);

        Assert.All(vulns, v => Assert.Equal("a", v.Key));
        Assert.Equal(3, vulns.Count);
        var main = Assert.Single(vulns, v => v.CveId == "CVE-2023-2975");
        Assert.Equal("3.0.2-0ubuntu1.12", main.FixedIn);
        Assert.Equal("OSV UBUNTU-CVE-2023-2975", main.Source);
        Assert.Contains(vulns, v => v.CveId == "CVE-2023-3446" && v.Source == "OSV USN-6450-1" && v.FixedIn == "3.0.2-0ubuntu1.12");

        // a second lookup reuses the cached records
        await source.LookupAsync(new[] { new PackageQuery("a", "Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1.10", null) }, CancellationToken.None);
        Assert.Equal(3, handler.VulnCalls);
    }

    [LiveOsvFact]
    public async Task Osv_live_debian_openssl_purl_returns_at_least_one_cve()
    {
        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        var source = new OsvPackageVulnSource(client);
        var vulns = await source.LookupAsync(new[] { new PackageQuery("live", "", "", "", "pkg:deb/debian/openssl@1.1.1n-0+deb11u3") }, CancellationToken.None);
        Assert.NotEmpty(vulns);
        Assert.All(vulns, v => Assert.Matches(@"^CVE-\d{4}-\d{4,}$", v.CveId));
        Assert.All(vulns, v => Assert.StartsWith("OSV ", v.Source));
        Assert.Contains(vulns, v => v.FixedIn is not null);
    }

    // ================================================================== fakes

    private sealed class FakeSsh : ISshSession
    {
        private readonly List<(string Match, SshCommandResult Result)> _rules = new();
        public string HostKeyFingerprint { get; init; } = "nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8";
        string? ISshSession.HostKeyFingerprint => HostKeyFingerprint;
        public List<string> Commands { get; } = new();
        public FakeSsh On(string contains, string output, int exit = 0, string error = "") { _rules.Add((contains, new SshCommandResult(exit, output, error))); return this; }
        public Task<SshCommandResult> RunAsync(string command, CancellationToken ct)
        {
            Commands.Add(command);
            foreach (var r in _rules) if (command.Contains(r.Match, StringComparison.Ordinal)) return Task.FromResult(r.Result);
            return Task.FromResult(new SshCommandResult(127, "", "command not found"));
        }
        public void Dispose() { }
    }

    private sealed class FakeVCenter : IVCenterSession
    {
        private readonly Dictionary<string, string> _routes = new();
        public List<string> Paths { get; } = new();
        public FakeVCenter Route(string path, string json) { _routes[path] = json; return this; }
        public Task<JsonDocument?> GetAsync(string path, CancellationToken ct)
        {
            lock (Paths) Paths.Add(path);
            return Task.FromResult(_routes.TryGetValue(path, out var j) ? JsonDocument.Parse(j) : null);
        }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class StubHttpFactory : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new();
    }

    private sealed class FakeOsvHandler : HttpMessageHandler
    {
        private string _batch = "{\"results\":[]}";
        private bool _first429;
        private readonly Dictionary<string, string> _vulns = new();
        public int BatchCalls; public int VulnCalls; public string LastBatchBody = "";
        public void Batch(string json, bool first429 = false) { _batch = json; _first429 = first429; }
        public void Vuln(string id, string json) => _vulns[id] = json;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var url = request.RequestUri!.ToString();
            if (url == OsvPackageVulnSource.QueryBatchUrl)
            {
                Interlocked.Increment(ref BatchCalls);
                LastBatchBody = await request.Content!.ReadAsStringAsync(ct);
                if (_first429) { _first429 = false; var r = new HttpResponseMessage((HttpStatusCode)429); r.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.Zero); return r; }
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(_batch, System.Text.Encoding.UTF8, "application/json") };
            }
            if (url.StartsWith(OsvPackageVulnSource.VulnUrl, StringComparison.Ordinal))
            {
                Interlocked.Increment(ref VulnCalls);
                var id = url[OsvPackageVulnSource.VulnUrl.Length..];
                return _vulns.TryGetValue(id, out var json)
                    ? new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json") }
                    : new HttpResponseMessage(HttpStatusCode.NotFound);
            }
            return new HttpResponseMessage(HttpStatusCode.BadRequest);
        }
    }
}
