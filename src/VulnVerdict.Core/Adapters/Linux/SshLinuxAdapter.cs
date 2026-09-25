using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Renci.SshNet;
using Renci.SshNet.Common;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Linux;

/// <summary>Result of one remote command: exit status (-1 when the server sent none), stdout and stderr.</summary>
public sealed record SshCommandResult(int ExitStatus, string Output, string Error)
{
    public bool Ok => ExitStatus == 0;
    public bool HasOutput => !string.IsNullOrWhiteSpace(Output);
}

/// <summary>One open SSH session. The adapter only ever runs read-only commands through it; tests substitute a fake.</summary>
public interface ISshSession : IDisposable
{
    /// <summary>SHA256 host key fingerprint presented by the server (base64, no "SHA256:" prefix), or null when unknown.</summary>
    string? HostKeyFingerprint { get; }
    Task<SshCommandResult> RunAsync(string command, CancellationToken ct);
}

/// <summary>A host line from the form: "host", "host:port" or "[ipv6]:port". AsTyped is the asset's external id.</summary>
public sealed record SshTarget(string AsTyped, string Host, int Port)
{
    public static SshTarget Parse(string line)
    {
        var s = line.Trim();
        var host = s; var port = 22;
        if (s.StartsWith('['))
        {
            var end = s.IndexOf(']');
            if (end > 0)
            {
                host = s[1..end];
                var rest = s[(end + 1)..];
                if (rest.StartsWith(':') && int.TryParse(rest[1..], out var p) && p > 0) port = p;
            }
        }
        else
        {
            var colon = s.LastIndexOf(':');
            if (colon > 0 && s.IndexOf(':') == colon && int.TryParse(s[(colon + 1)..], out var p) && p > 0) { host = s[..colon]; port = p; }
        }
        return new SshTarget(s, host, port);
    }
}

public sealed record SshConnectionOptions(string Username, string? Password, string? PrivateKeyPem, string? Passphrase, TimeSpan Timeout, bool AcceptAnyHostKey, string? ExpectedFingerprint);

/// <summary>One installed package. Source is the source package (what OSV and the distribution trackers key on); Name is the binary package.</summary>
public sealed record LinuxPackage(string Name, string Version, string Architecture, string Source);

public sealed record LinuxContainer(string Name, string Image);

/// <summary>Distribution identity derived from os-release: vendor, OSV ecosystem string and purl namespace.</summary>
public sealed record LinuxDistro(string Id, string Name, string Vendor, string? Ecosystem, string PurlNamespace, string? DistroQualifier);

/// <summary>Raw command output gathered from one host; turned into records by <see cref="SshLinuxAdapter.MapHost"/>.</summary>
public sealed class LinuxHostFacts
{
    public string OsRelease { get; set; } = "";
    public string Fqdn { get; set; } = "";
    public string HostnameIps { get; set; } = "";
    public string IpAddr { get; set; } = "";
    public string IpLink { get; set; } = "";
    /// <summary>"dpkg", "rpm", "apk" or null when none was found.</summary>
    public string? PackageManager { get; set; }
    public string PackageList { get; set; } = "";
    /// <summary>"ss" or "netstat", or null when neither exists.</summary>
    public string? SocketTool { get; set; }
    public string Sockets { get; set; } = "";
    public bool DockerPresent { get; set; }
    public bool DockerReadable { get; set; }
    public string Docker { get; set; } = "";
    public string? HostKeyFingerprint { get; set; }
    public bool HostKeyPinned { get; set; }
}

public sealed record LinuxHostMapping(AssetRecord Asset, List<SoftwareRecord> Software, List<string> Warnings);

/// <summary>
/// Linux over SSH. Reads os-release, the installed package list (dpkg, rpm or apk), listening
/// sockets and running Docker containers as an ordinary user. Every command is read-only and runs without sudo;
/// nothing is written to the host. Packages carry an OSV ecosystem string and a purl so they are matched through
/// OSV rather than through CNA product names.
/// </summary>
public sealed class SshLinuxAdapter : IInventoryAdapter
{
    public const string Id = "ssh-linux";

    public const string DpkgCommand = @"dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Source}\t${db:Status-Status}\n' 2>/dev/null";
    public const string RpmCommand = @"rpm -qa --qf '%{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n' 2>/dev/null";
    public const string ApkListCommand = "apk list -I 2>/dev/null";
    public const string ApkInfoCommand = "apk info -v 2>/dev/null";
    public const string ApkArchCommand = "apk --print-arch 2>/dev/null";
    public const string SsCommand = "ss -tlnp 2>/dev/null";
    public const string NetstatCommand = "netstat -tlnp 2>/dev/null";
    public const string DockerCommand = "docker ps --format '{{.Names}}\\t{{.Image}}' 2>/dev/null";
    public const string OsReleaseCommand = "cat /etc/os-release 2>/dev/null || cat /usr/lib/os-release 2>/dev/null";
    public const string FqdnCommand = "hostname -f 2>/dev/null || hostname 2>/dev/null";
    public const string HostnameIpsCommand = "hostname -I 2>/dev/null || hostname -i 2>/dev/null || true";
    public const string IpAddrCommand = "ip -o addr 2>/dev/null || true";
    public const string IpLinkCommand = "ip -o link 2>/dev/null || true";
    public const string ToolProbeCommand = "for c in dpkg-query rpm apk ss netstat docker; do command -v $c >/dev/null 2>&1 && echo $c; done; true";

    private readonly ILogger<SshLinuxAdapter> _log;

    public SshLinuxAdapter(ILogger<SshLinuxAdapter> log) { _log = log; }

    /// <summary>Opens a session for one target. The default connects with SSH.NET; tests substitute a fake.</summary>
    public Func<SshTarget, SshConnectionOptions, CancellationToken, Task<ISshSession>> SessionFactory { get; set; } = ConnectAsync;

    public int MaxParallelHosts { get; set; } = 4;

    public AdapterMetadata Metadata { get; } = new(
        Id,
        "Linux servers (SSH)",
        "Linux",
        "Connects to each listed host over SSH as an ordinary user and reads os-release, the installed package list (dpkg, rpm or apk), listening sockets (ss or netstat) and running Docker containers. Packages are matched through OSV and the distribution security trackers. Every command is read-only and runs without sudo.",
        new[] { AssetKind.Server, AssetKind.ContainerHost },
        new[]
        {
            new CredentialField("hosts", "Hosts", CredentialTypes.TextArea, "One per line, optionally host:port. Each line becomes one asset."),
            new CredentialField("username", "Username", CredentialTypes.Text, "An ordinary account. sudo is never used."),
            new CredentialField("password", "Password", CredentialTypes.Password, "Leave empty when authenticating with a private key.", Required: false),
            new CredentialField("privateKey", "Private key (PEM)", CredentialTypes.TextArea, "OpenSSH or PEM private key. Leave empty when authenticating with a password.", Required: false),
            new CredentialField("passphrase", "Key passphrase", CredentialTypes.Password, "Only when the private key is encrypted.", Required: false),
            new CredentialField("acceptAny", "Accept any host key", CredentialTypes.Bool, "Off (recommended): host keys are pinned in the list below and a changed key is reported instead of connecting.", Required: false, Default: "false"),
            new CredentialField("knownHostKeys", "Known host keys", CredentialTypes.TextArea, "One per line: host SHA256:fingerprint. Test connection prints the lines to paste for hosts seen for the first time.", Required: false),
            new CredentialField("timeoutSeconds", "Timeout (seconds)", CredentialTypes.Number, "Per connection and per command.", Required: false, Default: "30"),
        },
        "an ordinary user account (no sudo); package lists and listening sockets are world-readable",
        "https://man.openbsd.org/ssh-keygen",
        DefaultIntervalMinutes: 240);

    // ------------------------------------------------------------------ IInventoryAdapter

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        var targets = Targets(credentials);
        if (targets.Count == 0) return new(false, "Enter at least one host.");
        if (Get(credentials, "username") == "") return new(false, "Enter a username.");
        if (Get(credentials, "password") == "" && Get(credentials, "privateKey") == "") return new(false, "Enter a password or a private key.");
        var known = KnownHostKeys(Get(credentials, "knownHostKeys"));
        var acceptAny = GetBool(credentials, "acceptAny");
        var lines = new List<string>(); var toPin = new List<string>(); var failures = 0;
        foreach (var t in targets)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var session = await SessionFactory(t, Options(credentials, t, known), ct);
                var os = await session.RunAsync(OsReleaseCommand, ct);
                var pretty = ParseOsRelease(os.Output).GetValueOrDefault("PRETTY_NAME");
                lines.Add(t.AsTyped + ": " + (string.IsNullOrEmpty(pretty) ? "connected (os-release not readable)" : pretty));
                if (session.HostKeyFingerprint is { Length: > 0 } fp && !acceptAny && !IsPinned(known, t)) toPin.Add(t.AsTyped + " " + FormatFingerprint(fp));
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { failures++; lines.Add(t.AsTyped + ": " + ex.Message); }
        }
        if (toPin.Count > 0)
        {
            lines.Add("Host keys seen for the first time. Paste these lines into Known host keys so a changed key is detected next time:");
            lines.AddRange(toPin);
        }
        return new(failures == 0, string.Join("\n", lines));
    }

    public async Task<CollectResult> CollectAsync(IReadOnlyDictionary<string, string> credentials, DateTime? since, IProgress<string>? progress, CancellationToken ct)
    {
        var targets = Targets(credentials);
        var known = KnownHostKeys(Get(credentials, "knownHostKeys"));
        var acceptAny = GetBool(credentials, "acceptAny");
        var mapped = new LinuxHostMapping?[targets.Count];
        var errors = new ConcurrentDictionary<int, string>();
        var done = 0;
        await Parallel.ForEachAsync(Enumerable.Range(0, targets.Count), new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, MaxParallelHosts), CancellationToken = ct }, async (i, token) =>
        {
            var t = targets[i];
            try
            {
                using var session = await SessionFactory(t, Options(credentials, t, known), token);
                var facts = await GatherAsync(session, token);
                facts.HostKeyPinned = acceptAny || IsPinned(known, t);
                mapped[i] = MapHost(t.AsTyped, facts);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                errors[i] = ex.Message;
                _log.LogWarning("SSH collection failed for {Host}: {Message}", t.AsTyped, ex.Message);
            }
            progress?.Report(Interlocked.Increment(ref done) + "/" + targets.Count + " " + t.AsTyped);
        });

        var result = new CollectResult();
        for (var i = 0; i < targets.Count; i++)
        {
            if (mapped[i] is { } m)
            {
                result.Assets.Add(m.Asset);
                result.Software.AddRange(m.Software);
                result.Warnings.AddRange(m.Warnings);
            }
            else if (errors.TryGetValue(i, out var err)) result.Warnings.Add(targets[i].AsTyped + ": " + err);
        }
        return result;
    }

    // ------------------------------------------------------------------ gathering

    /// <summary>Runs the read-only command set on one host and returns the raw output.</summary>
    public static async Task<LinuxHostFacts> GatherAsync(ISshSession s, CancellationToken ct)
    {
        var f = new LinuxHostFacts { HostKeyFingerprint = s.HostKeyFingerprint };
        f.OsRelease = (await s.RunAsync(OsReleaseCommand, ct)).Output;
        var tools = (await s.RunAsync(ToolProbeCommand, ct)).Output
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToHashSet(StringComparer.Ordinal);
        f.Fqdn = (await s.RunAsync(FqdnCommand, ct)).Output.Trim();
        f.HostnameIps = (await s.RunAsync(HostnameIpsCommand, ct)).Output;
        f.IpAddr = (await s.RunAsync(IpAddrCommand, ct)).Output;
        f.IpLink = (await s.RunAsync(IpLinkCommand, ct)).Output;

        if (tools.Contains("dpkg-query")) { f.PackageManager = "dpkg"; f.PackageList = (await s.RunAsync(DpkgCommand, ct)).Output; }
        else if (tools.Contains("rpm")) { f.PackageManager = "rpm"; f.PackageList = (await s.RunAsync(RpmCommand, ct)).Output; }
        else if (tools.Contains("apk"))
        {
            f.PackageManager = "apk";
            var list = await s.RunAsync(ApkListCommand, ct);
            if (list.Ok && list.HasOutput) f.PackageList = list.Output;
            else
            {
                var info = await s.RunAsync(ApkInfoCommand, ct);
                var arch = (await s.RunAsync(ApkArchCommand, ct)).Output.Trim();
                f.PackageList = (arch != "" ? "#arch=" + arch + "\n" : "") + info.Output;
            }
        }

        if (tools.Contains("ss")) { f.SocketTool = "ss"; f.Sockets = (await s.RunAsync(SsCommand, ct)).Output; }
        else if (tools.Contains("netstat")) { f.SocketTool = "netstat"; f.Sockets = (await s.RunAsync(NetstatCommand, ct)).Output; }

        if (tools.Contains("docker"))
        {
            f.DockerPresent = true;
            var d = await s.RunAsync(DockerCommand, ct);
            if (d.Ok) { f.DockerReadable = true; f.Docker = d.Output; }
        }
        return f;
    }

    // ------------------------------------------------------------------ mapping

    /// <summary>Turns the raw output of one host into an asset record and its software records.</summary>
    public static LinuxHostMapping MapHost(string externalId, LinuxHostFacts f)
    {
        var warnings = new List<string>();
        var os = ParseOsRelease(f.OsRelease);
        var distro = DistroInfo(os);

        var hostnames = new List<string>();
        var fqdn = f.Fqdn.Split('\n')[0].Trim();
        if (fqdn != "" && !IsIp(fqdn))
        {
            hostnames.Add(fqdn);
            var shortName = fqdn.Split('.')[0];
            if (shortName != fqdn && shortName != "") hostnames.Add(shortName);
        }
        var ips = ParseIps(f.HostnameIps).Concat(ParseIpAddr(f.IpAddr)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var macs = ParseMacs(f.IpLink);
        var packages = f.PackageManager switch
        {
            "dpkg" => ParseDpkg(f.PackageList),
            "rpm" => ParseRpm(f.PackageList),
            "apk" => ParseApk(f.PackageList),
            _ => new List<LinuxPackage>()
        };
        var listeners = f.SocketTool switch
        {
            "ss" => ParseSs(f.Sockets),
            "netstat" => ParseNetstat(f.Sockets),
            _ => new List<Listener>()
        };
        var containers = f.DockerReadable ? ParseDocker(f.Docker) : new List<LinuxContainer>();

        var display = hostnames.FirstOrDefault(h => !h.Contains('.')) ?? (fqdn == "" ? externalId : fqdn);
        var versionId = os.GetValueOrDefault("VERSION_ID");
        var asset = new AssetRecord(
            externalId, display,
            containers.Count > 0 ? AssetKind.ContainerHost : AssetKind.Server,
            hostnames.ToArray(), ips, macs,
            OsVendor: distro.Vendor,
            OsProduct: os.GetValueOrDefault("PRETTY_NAME") is { Length: > 0 } pretty ? pretty : distro.Name,
            OsVersion: string.IsNullOrEmpty(versionId) ? null : versionId);

        var software = new List<SoftwareRecord>
        {
            new(externalId, distro.Vendor, distro.Name, versionId ?? "", SoftwareKind.OperatingSystem, ExternalId: "os", Listeners: listeners.Count > 0 ? listeners.ToArray() : null)
        };

        var purlType = f.PackageManager switch { "dpkg" => "deb", "rpm" => "rpm", "apk" => "apk", _ => "generic" };
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var p in packages)
        {
            var key = purlType + ":" + p.Source + ":" + p.Architecture;
            if (!seen.Add(key)) continue; // one row per source package and architecture; binaries built from it share the version
            software.Add(new SoftwareRecord(externalId, distro.Name, p.Source, p.Version, SoftwareKind.Package,
                Purl: BuildPurl(purlType, distro.PurlNamespace, p.Source, p.Version, p.Architecture, distro.DistroQualifier),
                Ecosystem: distro.Ecosystem,
                Architecture: p.Architecture == "" ? null : p.Architecture,
                ExternalId: key));
        }
        foreach (var c in containers)
        {
            var (image, tag) = SplitImage(c.Image);
            software.Add(new SoftwareRecord(externalId, "container", image, tag, SoftwareKind.Application, ExternalId: "container:" + c.Name));
        }

        if (f.PackageManager is null) warnings.Add(externalId + ": no dpkg, rpm or apk found; no package list collected");
        else if (packages.Count == 0) warnings.Add(externalId + ": " + f.PackageManager + " returned no packages");
        if (f.SocketTool is null) warnings.Add(externalId + ": neither ss nor netstat is available; listening ports not collected");
        if (f.DockerPresent && !f.DockerReadable) warnings.Add(externalId + ": docker is installed but the account cannot read the container list (docker group membership is needed)");
        if (distro.Ecosystem is null && packages.Count > 0) warnings.Add(externalId + ": " + distro.Name + " has no OSV ecosystem; packages are recorded but not matched");
        if (!f.HostKeyPinned && f.HostKeyFingerprint is { Length: > 0 } fp) warnings.Add(externalId + ": host key " + FormatFingerprint(fp) + " is not pinned in Known host keys");
        return new LinuxHostMapping(asset, software, warnings);
    }

    /// <summary>Parses os-release (KEY=value, quoted or bare).</summary>
    public static Dictionary<string, string> ParseOsRelease(string text)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line == "" || line.StartsWith('#')) continue;
            var eq = line.IndexOf('=');
            if (eq <= 0) continue;
            var key = line[..eq].Trim();
            var val = line[(eq + 1)..].Trim();
            if (val.Length >= 2 && ((val[0] == '"' && val[^1] == '"') || (val[0] == '\'' && val[^1] == '\''))) val = val[1..^1];
            val = val.Replace("\\\"", "\"").Replace("\\$", "$").Replace("\\\\", "\\");
            d[key] = val;
        }
        return d;
    }

    /// <summary>
    /// Vendor, OSV ecosystem string and purl namespace for a distribution. Ecosystem strings follow the OSV schema
    /// list (Ubuntu:22.04:LTS, Debian:12, Alpine:v3.20, Red Hat:enterprise_linux:9::baseos, AlmaLinux:9, Rocky Linux:9,
    /// openSUSE:Leap:15.5, SUSE:Linux Enterprise Server 15 SP5, Photon OS:5.0, Mageia:9, Wolfi, Chainguard).
    /// Distributions without an OSV ecosystem get null and are recorded but not matched.
    /// </summary>
    public static LinuxDistro DistroInfo(IReadOnlyDictionary<string, string> os)
    {
        var id = (os.GetValueOrDefault("ID") ?? "").Trim().ToLowerInvariant();
        var name = os.GetValueOrDefault("NAME") is { Length: > 0 } n ? n : (id == "" ? "Linux" : id);
        var ver = (os.GetValueOrDefault("VERSION_ID") ?? "").Trim();
        var version = os.GetValueOrDefault("VERSION") ?? "";
        var pretty = os.GetValueOrDefault("PRETTY_NAME") ?? "";
        var codename = (os.GetValueOrDefault("VERSION_CODENAME") ?? "").Trim();
        var cpe = (os.GetValueOrDefault("CPE_NAME") ?? "").Trim();
        var major = ver.Split('.')[0];
        var parts = ver.Split('.');
        var majorMinor = parts.Length >= 2 ? parts[0] + "." + parts[1] : ver;

        return id switch
        {
            "ubuntu" => new(id, name, "Canonical", ver == "" ? null : "Ubuntu:" + ver + (version.Contains("LTS", StringComparison.OrdinalIgnoreCase) ? ":LTS" : ""), "ubuntu", "ubuntu-" + ver),
            "debian" => new(id, name, "Debian", ver != "" ? "Debian:" + ver : "Debian", "debian", "debian-" + (ver != "" ? ver : codename)),
            "alpine" => new(id, name, "Alpine Linux", ver == "" ? null : "Alpine:v" + majorMinor, "alpine", "alpine-" + majorMinor),
            "rhel" => new(id, name, "Red Hat", cpe.StartsWith("cpe:/o:redhat:", StringComparison.OrdinalIgnoreCase) ? "Red Hat:" + cpe["cpe:/o:redhat:".Length..] : "Red Hat:enterprise_linux:" + major, "redhat", "rhel-" + major),
            "almalinux" => new(id, name, "AlmaLinux", "AlmaLinux:" + major, "almalinux", "almalinux-" + major),
            "rocky" => new(id, name, "Rocky Linux", "Rocky Linux:" + major, "rocky", "rocky-" + major),
            "opensuse-leap" => new(id, name, "SUSE", "openSUSE:Leap:" + ver, "opensuse", "opensuse-leap-" + ver),
            "opensuse-tumbleweed" => new(id, name, "SUSE", "openSUSE:Tumbleweed", "opensuse", "opensuse-tumbleweed"),
            "sles" or "sled" or "sle_hpc" => new(id, name, "SUSE", "SUSE:" + (pretty.StartsWith("SUSE ", StringComparison.OrdinalIgnoreCase) ? pretty[5..] : pretty), "suse", "sles-" + ver),
            "photon" => new(id, name, "VMware", "Photon OS:" + ver, "photon", "photon-" + ver),
            "mageia" => new(id, name, "Mageia", "Mageia:" + ver, "mageia", "mageia-" + ver),
            "wolfi" => new(id, name, "Chainguard", "Wolfi", "wolfi", null),
            "chainguard" => new(id, name, "Chainguard", "Chainguard", "chainguard", null),
            "fedora" => new(id, name, "Fedora Project", null, "fedora", "fedora-" + ver),
            "centos" => new(id, name, "CentOS", null, "centos", "centos-" + ver),
            "amzn" => new(id, name, "Amazon", null, "amazon", "amzn-" + ver),
            "ol" => new(id, name, "Oracle", null, "oracle", "ol-" + major),
            "arch" => new(id, name, "Arch Linux", null, "arch", null),
            "raspbian" => new(id, name, "Raspberry Pi Foundation", ver != "" ? "Debian:" + ver : "Debian", "debian", "debian-" + ver),
            _ => new(id == "" ? "linux" : id, name, name, null, id == "" ? "linux" : id, ver == "" ? null : id + "-" + ver)
        };
    }

    /// <summary>dpkg-query output: Package, Version, Architecture, Source (optional, may carry "(version)"), status (optional).</summary>
    public static List<LinuxPackage> ParseDpkg(string text)
    {
        var list = new List<LinuxPackage>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Trim() == "") continue;
            var cols = line.Split('\t');
            if (cols.Length < 2) continue;
            if (cols.Length > 4 && cols[4].Trim() is { Length: > 0 } status && !status.Equals("installed", StringComparison.OrdinalIgnoreCase)) continue;
            var name = cols[0].Trim();
            var colon = name.IndexOf(':');
            if (colon > 0) name = name[..colon];
            var version = cols[1].Trim();
            var arch = cols.Length > 2 ? cols[2].Trim() : "";
            var source = name;
            if (cols.Length > 3 && cols[3].Trim() is { Length: > 0 } src)
            {
                var paren = src.IndexOf(" (", StringComparison.Ordinal);
                if (paren > 0)
                {
                    var sv = src[(paren + 2)..].TrimEnd(')').Trim();
                    if (sv != "") version = sv;
                    src = src[..paren];
                }
                source = src.Trim();
            }
            if (name == "" || version == "") continue;
            list.Add(new LinuxPackage(name, version, arch, source));
        }
        return list;
    }

    /// <summary>rpm -qa output: Name, [epoch:]Version-Release, Arch, SourceRPM.</summary>
    public static List<LinuxPackage> ParseRpm(string text)
    {
        var list = new List<LinuxPackage>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (line.Trim() == "") continue;
            var cols = line.Split('\t');
            if (cols.Length < 2) continue;
            var name = cols[0].Trim(); var version = cols[1].Trim();
            var arch = cols.Length > 2 ? cols[2].Trim() : "";
            if (name == "" || version == "" || name == "gpg-pubkey" || arch == "(none)") continue;
            var source = name;
            if (cols.Length > 3 && cols[3].Trim() is { Length: > 0 } srpm && srpm.EndsWith(".src.rpm", StringComparison.OrdinalIgnoreCase))
            {
                var s = srpm[..^".src.rpm".Length];
                var i = s.LastIndexOf('-');
                if (i > 0) { s = s[..i]; i = s.LastIndexOf('-'); if (i > 0) s = s[..i]; }
                if (s != "") source = s;
            }
            list.Add(new LinuxPackage(name, version, arch, source));
        }
        return list;
    }

    /// <summary>apk list -I output ("name-ver-rN arch {origin} (licence) [installed]") or apk info -v ("name-ver-rN") with an optional "#arch=" header.</summary>
    public static List<LinuxPackage> ParseApk(string text)
    {
        var list = new List<LinuxPackage>();
        var defaultArch = "";
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line == "") continue;
            if (line.StartsWith("#arch=", StringComparison.Ordinal)) { defaultArch = line[6..].Trim(); continue; }
            if (line.StartsWith("WARNING", StringComparison.OrdinalIgnoreCase)) continue;
            var tokens = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var (name, version) = SplitApkNameVersion(tokens[0]);
            if (name == "" || version == "") continue;
            var arch = tokens.Length > 1 && !tokens[1].StartsWith('{') && !tokens[1].StartsWith('(') ? tokens[1] : defaultArch;
            var origin = tokens.FirstOrDefault(t => t.StartsWith('{') && t.EndsWith('}')) is { } o ? o[1..^1] : name;
            list.Add(new LinuxPackage(name, version, arch, origin == "" ? name : origin));
        }
        return list;
    }

    private static (string Name, string Version) SplitApkNameVersion(string s)
    {
        for (var i = 1; i < s.Length - 1; i++)
            if (s[i] == '-' && char.IsDigit(s[i + 1])) return (s[..i], s[(i + 1)..]);
        return (s, "");
    }

    private static readonly Regex LocalAddr = new(@"^(?<bind>.+):(?<port>\d+)$", RegexOptions.Compiled);
    private static readonly Regex SsProcess = new("\\(\\(\"(?<name>[^\"]+)\"", RegexOptions.Compiled);

    /// <summary>ss -tlnp (or -tulnp) output. One listener per protocol, port and bind address.</summary>
    public static List<Listener> ParseSs(string text)
    {
        var list = new List<Listener>(); var seen = new HashSet<string>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line == "" || line.StartsWith("State", StringComparison.Ordinal) || line.StartsWith("Netid", StringComparison.Ordinal)) continue;
            var tokens = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            var proto = tokens[0] is "tcp" or "udp" or "tcp6" or "udp6" ? tokens[0].TrimEnd('6') : "tcp";
            Match? local = null;
            foreach (var t in tokens) { var m = LocalAddr.Match(t); if (m.Success) { local = m; break; } }
            if (local is null || !int.TryParse(local.Groups["port"].Value, out var port)) continue;
            var bind = NormaliseBind(local.Groups["bind"].Value);
            var pm = SsProcess.Match(line);
            var proc = pm.Success ? pm.Groups["name"].Value : null;
            if (seen.Add(proto + "/" + port + "/" + bind)) list.Add(new Listener(port, proto, bind, proc));
        }
        return list;
    }

    /// <summary>netstat -tlnp output.</summary>
    public static List<Listener> ParseNetstat(string text)
    {
        var list = new List<Listener>(); var seen = new HashSet<string>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (!(line.StartsWith("tcp", StringComparison.Ordinal) || line.StartsWith("udp", StringComparison.Ordinal))) continue;
            var tokens = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length < 4) continue;
            var proto = tokens[0].TrimEnd('6');
            if (proto == "tcp" && !tokens.Contains("LISTEN")) continue;
            var m = LocalAddr.Match(tokens[3]);
            if (!m.Success || !int.TryParse(m.Groups["port"].Value, out var port)) continue;
            var bind = NormaliseBind(m.Groups["bind"].Value);
            string? proc = null;
            foreach (var t in tokens.Skip(4))
            {
                var slash = t.IndexOf('/');
                if (slash > 0 && slash < t.Length - 1 && t[..slash].All(char.IsDigit)) { proc = t[(slash + 1)..].TrimEnd(':'); break; }
            }
            if (seen.Add(proto + "/" + port + "/" + bind)) list.Add(new Listener(port, proto, bind, proc));
        }
        return list;
    }

    private static string NormaliseBind(string bind)
    {
        var b = bind.Trim();
        var pct = b.IndexOf('%');
        if (pct > 0) b = b[..pct];
        b = b.Trim('[', ']');
        return b is "" or "*" or "0.0.0.0" or "::" ? "*" : b;
    }

    private static readonly Regex IpLinkLine = new(@"^\d+:\s+(?<name>[^:\s@]+).*?link/ether\s+(?<mac>[0-9a-fA-F:]{17})", RegexOptions.Compiled);
    private static readonly string[] VirtualInterfacePrefixes = { "veth", "docker", "br-", "virbr", "vnet", "tap", "tun", "cali", "flannel", "cni", "kube", "dummy", "lxc", "lxd", "wg" };

    /// <summary>MAC addresses of physical-looking interfaces from ip -o link (bridges, veths and tunnels are skipped).</summary>
    public static string[] ParseMacs(string text)
    {
        var macs = new List<string>();
        foreach (var raw in text.Split('\n'))
        {
            var m = IpLinkLine.Match(raw.Trim());
            if (!m.Success) continue;
            var name = m.Groups["name"].Value;
            if (VirtualInterfacePrefixes.Any(p => name.StartsWith(p, StringComparison.OrdinalIgnoreCase))) continue;
            var mac = m.Groups["mac"].Value.ToLowerInvariant();
            if (mac == "00:00:00:00:00:00" || macs.Contains(mac)) continue;
            macs.Add(mac);
        }
        return macs.ToArray();
    }

    private static readonly Regex InetAddr = new(@"inet6?\s+(?<ip>[0-9a-fA-F.:]+)/\d+", RegexOptions.Compiled);

    /// <summary>Global-scope addresses from ip -o addr.</summary>
    public static IEnumerable<string> ParseIpAddr(string text)
    {
        foreach (var raw in text.Split('\n'))
        {
            if (!raw.Contains("scope global", StringComparison.Ordinal)) continue;
            var m = InetAddr.Match(raw);
            if (m.Success && KeepIp(m.Groups["ip"].Value)) yield return m.Groups["ip"].Value;
        }
    }

    /// <summary>Addresses from hostname -I.</summary>
    public static IEnumerable<string> ParseIps(string text) =>
        text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Where(KeepIp);

    /// <summary>docker ps --format lines: name, tab, image.</summary>
    public static List<LinuxContainer> ParseDocker(string text)
    {
        var list = new List<LinuxContainer>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line == "") continue;
            var cols = line.Contains('\t') ? line.Split('\t') : line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (cols.Length < 2) continue;
            list.Add(new LinuxContainer(cols[0].Trim(), cols[1].Trim()));
        }
        return list;
    }

    /// <summary>"registry:5000/acme/api:2.3.1" to ("registry:5000/acme/api", "2.3.1"); no tag is "latest"; a digest becomes its first 12 hex characters.</summary>
    public static (string Image, string Tag) SplitImage(string image)
    {
        var s = image.Trim();
        var at = s.IndexOf('@');
        if (at > 0)
        {
            var digest = s[(at + 1)..];
            var c = digest.IndexOf(':');
            if (c >= 0) digest = digest[(c + 1)..];
            return (s[..at], digest.Length > 12 ? digest[..12] : digest);
        }
        var slash = s.LastIndexOf('/');
        var colon = s.LastIndexOf(':');
        if (colon > slash && colon > 0) return (s[..colon], s[(colon + 1)..]);
        return (s, "latest");
    }

    /// <summary>
    /// pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?arch=amd64&amp;distro=ubuntu-22.04. For rpm the epoch moves to an
    /// "epoch" qualifier as the purl specification asks. Version characters common in distribution versions
    /// (":", "+", "~") are left readable; only characters that would break the purl grammar are percent-encoded.
    /// </summary>
    public static string BuildPurl(string type, string ns, string name, string version, string? arch, string? distro)
    {
        string? epoch = null; var v = version;
        if (type == "rpm")
        {
            var c = v.IndexOf(':');
            if (c > 0 && v[..c].All(char.IsDigit)) { epoch = v[..c]; v = v[(c + 1)..]; }
        }
        var sb = new StringBuilder("pkg:").Append(type).Append('/').Append(PurlEncode(ns)).Append('/').Append(PurlEncode(type == "deb" ? name.ToLowerInvariant() : name)).Append('@').Append(PurlEncode(v));
        var q = new List<string>();
        if (!string.IsNullOrEmpty(arch)) q.Add("arch=" + PurlEncode(arch));
        if (!string.IsNullOrEmpty(distro)) q.Add("distro=" + PurlEncode(distro));
        if (epoch is not null) q.Add("epoch=" + epoch);
        if (q.Count > 0) sb.Append('?').Append(string.Join("&", q));
        return sb.ToString();
    }

    private static string PurlEncode(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var ch in s)
        {
            if (char.IsAsciiLetterOrDigit(ch) || ch is '.' or '-' or '_' or '~' or '+' or ':') sb.Append(ch);
            else sb.Append(Uri.EscapeDataString(ch.ToString()));
        }
        return sb.ToString();
    }

    // ------------------------------------------------------------------ helpers

    private static bool IsIp(string s) => IPAddress.TryParse(s, out _);

    private static bool KeepIp(string s) =>
        IPAddress.TryParse(s, out var ip) && !IPAddress.IsLoopback(ip) && !ip.IsIPv6LinkLocal && !IPAddress.Any.Equals(ip) && !IPAddress.IPv6Any.Equals(ip) && !s.StartsWith("169.254.", StringComparison.Ordinal);

    private static string Get(IReadOnlyDictionary<string, string> c, string key) => c.TryGetValue(key, out var v) && v is not null ? v.Trim() : "";

    private static bool GetBool(IReadOnlyDictionary<string, string> c, string key) =>
        Get(c, key).ToLowerInvariant() is "true" or "1" or "yes" or "on";

    private static int GetInt(IReadOnlyDictionary<string, string> c, string key, int fallback) =>
        int.TryParse(Get(c, key), out var v) && v > 0 ? v : fallback;

    private static List<SshTarget> Targets(IReadOnlyDictionary<string, string> c) =>
        Get(c, "hosts").Split(new[] { '\n', '\r', ',' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(l => !l.StartsWith('#'))
            .Select(SshTarget.Parse)
            .GroupBy(t => t.AsTyped, StringComparer.OrdinalIgnoreCase).Select(g => g.First())
            .ToList();

    /// <summary>"host SHA256:fingerprint" per line, keyed by host (lower case); the fingerprint is stored normalised.</summary>
    public static Dictionary<string, string> KnownHostKeys(string text)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.Trim();
            if (line == "" || line.StartsWith('#')) continue;
            var parts = line.Split(new[] { ' ', '\t', ',' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;
            d[parts[0]] = NormaliseFingerprint(parts[1]);
        }
        return d;
    }

    private static bool IsPinned(Dictionary<string, string> known, SshTarget t) => known.ContainsKey(t.AsTyped) || known.ContainsKey(t.Host);

    public static string NormaliseFingerprint(string fp)
    {
        var s = fp.Trim();
        if (s.StartsWith("SHA256:", StringComparison.OrdinalIgnoreCase)) s = s[7..];
        return s.TrimEnd('=');
    }

    public static string FormatFingerprint(string fp) => "SHA256:" + NormaliseFingerprint(fp);

    public static bool FingerprintEquals(string? a, string? b) =>
        a is not null && b is not null && string.Equals(NormaliseFingerprint(a), NormaliseFingerprint(b), StringComparison.Ordinal);

    private static SshConnectionOptions Options(IReadOnlyDictionary<string, string> c, SshTarget t, Dictionary<string, string> known)
    {
        var expected = known.GetValueOrDefault(t.AsTyped) ?? known.GetValueOrDefault(t.Host);
        return new SshConnectionOptions(
            Get(c, "username"),
            Get(c, "password") is { Length: > 0 } pw ? pw : null,
            Get(c, "privateKey") is { Length: > 0 } pk ? pk : null,
            Get(c, "passphrase") is { Length: > 0 } pp ? pp : null,
            TimeSpan.FromSeconds(GetInt(c, "timeoutSeconds", 30)),
            GetBool(c, "acceptAny"),
            expected);
    }

    // ------------------------------------------------------------------ SSH.NET session

    private static async Task<ISshSession> ConnectAsync(SshTarget t, SshConnectionOptions o, CancellationToken ct)
    {
        var methods = new List<AuthenticationMethod>();
        if (!string.IsNullOrEmpty(o.PrivateKeyPem))
        {
            var stream = new MemoryStream(Encoding.UTF8.GetBytes(o.PrivateKeyPem.Trim() + "\n"));
            var keyFile = string.IsNullOrEmpty(o.Passphrase) ? new PrivateKeyFile(stream) : new PrivateKeyFile(stream, o.Passphrase);
            methods.Add(new PrivateKeyAuthenticationMethod(o.Username, keyFile));
        }
        if (!string.IsNullOrEmpty(o.Password)) methods.Add(new PasswordAuthenticationMethod(o.Username, o.Password));
        if (methods.Count == 0) throw new InvalidOperationException("No password or private key supplied");

        var info = new ConnectionInfo(t.Host, t.Port, o.Username, methods.ToArray()) { Timeout = o.Timeout };
        var client = new SshClient(info);
        string? presented = null; string? rejected = null;
        client.HostKeyReceived += (_, e) =>
        {
            presented = e.FingerPrintSHA256;
            if (o.AcceptAnyHostKey || o.ExpectedFingerprint is null) { e.CanTrust = true; return; }
            if (FingerprintEquals(o.ExpectedFingerprint, presented)) e.CanTrust = true;
            else { rejected = presented; e.CanTrust = false; }
        };
        try
        {
            await client.ConnectAsync(ct);
        }
        catch (SshConnectionException ex) when (rejected is not null)
        {
            client.Dispose();
            throw new InvalidOperationException("Host key for " + t.AsTyped + " has changed: expected " + FormatFingerprint(o.ExpectedFingerprint!) + ", received " + FormatFingerprint(rejected) + ". Verify the server before updating Known host keys.", ex);
        }
        catch
        {
            client.Dispose();
            throw;
        }
        return new SshNetSession(client, presented, o.Timeout);
    }

    private sealed class SshNetSession : ISshSession
    {
        private readonly SshClient _client;
        private readonly TimeSpan _timeout;

        public SshNetSession(SshClient client, string? fingerprint, TimeSpan timeout) { _client = client; HostKeyFingerprint = fingerprint; _timeout = timeout; }

        public string? HostKeyFingerprint { get; }

        public async Task<SshCommandResult> RunAsync(string command, CancellationToken ct)
        {
            using var cmd = _client.CreateCommand(command);
            cmd.CommandTimeout = _timeout;
            await cmd.ExecuteAsync(ct);
            return new SshCommandResult(cmd.ExitStatus ?? -1, cmd.Result ?? "", cmd.Error ?? "");
        }

        public void Dispose()
        {
            try { if (_client.IsConnected) _client.Disconnect(); } catch { /* best effort */ }
            _client.Dispose();
        }
    }
}
