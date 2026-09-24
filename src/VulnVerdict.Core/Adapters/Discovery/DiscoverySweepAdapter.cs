using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.Discovery;

/// <summary>
/// Section 9.2 step 9: periodic host discovery of the server and management subnets, compared against every
/// adapter's asset list; hosts no adapter claims are listed as unknown (the adapter id starts with "discovery",
/// which is what InventoryService keys on). Pure .NET: TCP connects, reverse DNS and a banner read on a handful of
/// well-known ports. nmap is not required. No vulnerability scripts and no authenticated checks, and it stays that way.
/// </summary>
public sealed class DiscoverySweepAdapter : IInventoryAdapter
{
    public const string DefaultPorts = "22,80,443,445,3389,5985,8080,8443,9100,623,161";
    public const int MaxAddresses = 4096;

    private readonly ILogger<DiscoverySweepAdapter> _log;

    public DiscoverySweepAdapter(ILogger<DiscoverySweepAdapter> log) { _log = log; }

    public AdapterMetadata Metadata { get; } = new(
        Id: "discovery-sweep",
        DisplayName: "Discovery sweep (unknown hosts)",
        Vendor: "VulnVerdict (built in)",
        Description: "TCP host discovery and service banner read of the server and management subnets, compared with every adapter's asset list. Hosts no adapter claims are listed as unknown. This is discovery, not vulnerability scanning: no exploit probes, no authenticated checks, and nmap is not required.",
        Kinds: new[] { AssetKind.Server, AssetKind.Printer, AssetKind.OutOfBandManagement, AssetKind.Other },
        Form: new[]
        {
            new CredentialField("subnets", "Subnets", CredentialTypes.TextArea, "CIDR blocks or single addresses, one per line (for example 10.0.20.0/24). At most " + MaxAddresses + " addresses per run."),
            new CredentialField("ports", "Ports", CredentialTypes.Text, "TCP ports to try, comma separated.", Required: false, Default: DefaultPorts),
            new CredentialField("timeoutMs", "Connect timeout (ms)", CredentialTypes.Number, null, Required: false, Default: "800"),
            new CredentialField("concurrency", "Hosts in parallel", CredentialTypes.Number, null, Required: false, Default: "128"),
        },
        MinimumPermission: "none: outbound TCP from the console to the swept subnets",
        DefaultIntervalMinutes: 1440);

    public Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        var warnings = new List<string>();
        var addresses = AddressRanges.Expand(credentials.GetValueOrDefault("subnets"), MaxAddresses, warnings, resolveHostnames: false);
        var ports = AddressRanges.ParsePorts(credentials.GetValueOrDefault("ports"), DefaultPorts);
        if (addresses.Count == 0) return Task.FromResult(new TestResult(false, warnings.Count > 0 ? string.Join("; ", warnings) : "No subnets given."));
        if (ports.Count == 0) return Task.FromResult(new TestResult(false, "No valid ports."));
        return Task.FromResult(new TestResult(true, "Ready to sweep " + addresses.Count + " addresses on " + ports.Count + " ports (TCP connect, reverse DNS, banner read only; nmap not required)." + (warnings.Count > 0 ? " " + string.Join("; ", warnings) : "")));
    }

    public async Task<CollectResult> CollectAsync(IReadOnlyDictionary<string, string> credentials, DateTime? since, IProgress<string>? progress, CancellationToken ct)
    {
        var result = new CollectResult { FullSnapshot = true };
        var addresses = AddressRanges.Expand(credentials.GetValueOrDefault("subnets"), MaxAddresses, result.Warnings, resolveHostnames: false);
        var ports = AddressRanges.ParsePorts(credentials.GetValueOrDefault("ports"), DefaultPorts);
        var timeout = int.TryParse(credentials.GetValueOrDefault("timeoutMs"), out var t) && t >= 100 ? Math.Min(t, 10000) : 800;
        var concurrency = int.TryParse(credentials.GetValueOrDefault("concurrency"), out var c) && c >= 1 ? Math.Min(c, 512) : 128;
        if (addresses.Count == 0) { result.Warnings.Add("No addresses to sweep."); return result; }
        if (ports.Count == 0) { result.Warnings.Add("No valid ports."); return result; }

        var gate = new SemaphoreSlim(concurrency);
        var done = 0; var found = 0;
        var tasks = addresses.Select(async a =>
        {
            await gate.WaitAsync(ct);
            try
            {
                var host = await ProbeHostAsync(a.Address, ports, timeout, ct);
                if (host is null) return;
                lock (result)
                {
                    found++;
                    result.Assets.Add(host.Asset);
                    result.Software.AddRange(host.Software);
                }
            }
            finally
            {
                gate.Release();
                var n = Interlocked.Increment(ref done);
                if (n % 64 == 0 || n == addresses.Count) progress?.Report("Swept " + n + " of " + addresses.Count + " addresses, " + found + " answering");
            }
        }).ToList();
        await Task.WhenAll(tasks);

        result.Warnings.Add(found + " of " + addresses.Count + " addresses answered on at least one port.");
        _log.LogInformation("Discovery sweep: {Found} of {Total} addresses answered", found, addresses.Count);
        return result;
    }

    // ------------------------------------------------------------------ one host

    private sealed record HostResult(AssetRecord Asset, List<SoftwareRecord> Software);

    private async Task<HostResult?> ProbeHostAsync(IPAddress ip, List<int> ports, int timeout, CancellationToken ct)
    {
        var open = new List<int>();
        var checks = ports.Select(async p => { if (await TcpProbe.IsOpenAsync(ip, p, timeout, ct)) lock (open) open.Add(p); }).ToList();
        await Task.WhenAll(checks);
        if (open.Count == 0) return null;
        open.Sort();

        var ipText = ip.ToString();
        var rdns = await TcpProbe.ReverseDnsAsync(ip, timeout, ct);
        var software = new List<SoftwareRecord>();
        var hostnames = new List<string>();
        if (rdns is not null) hostnames.Add(rdns);

        foreach (var port in open)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                switch (port)
                {
                    case 22:
                        if (BannerParser.FromSsh(ipText, await ReadSshAsync(ip, port, timeout, ct), port) is { } ssh) software.Add(ssh);
                        break;
                    case 80 or 8080:
                        if (BannerParser.FromServerHeader(ipText, await HttpServerHeaderAsync(ip, port, rdns, timeout, ct), port) is { } web) software.Add(web);
                        break;
                    case 443 or 8443:
                        var (server, certName) = await TlsServerHeaderAsync(ip, port, rdns, timeout, ct);
                        if (BannerParser.FromServerHeader(ipText, server, port) is { } tls) software.Add(tls);
                        if (certName is not null && rdns is null && !hostnames.Contains(certName, StringComparer.OrdinalIgnoreCase)) hostnames.Add(certName);
                        break;
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { _log.LogDebug("Banner read {Ip}:{Port} failed: {Error}", ip, port, ex.Message); }
        }

        var kind = GuessKind(open);
        var asset = new AssetRecord(ipText, rdns ?? ipText, kind, hostnames.ToArray(), new[] { ipText }, Array.Empty<string>());
        return new HostResult(asset, software);
    }

    public static AssetKind GuessKind(IReadOnlyCollection<int> open)
    {
        if (open.Any(p => p is 3389 or 445 or 5985)) return AssetKind.Server;
        if (open.Contains(9100)) return AssetKind.Printer;
        if (open.Contains(623)) return AssetKind.OutOfBandManagement;
        if (open.Count > 0 && open.All(p => p == 22)) return AssetKind.Server;
        return AssetKind.Other;
    }

    // ------------------------------------------------------------------ banner reads (identification only)

    private static async Task<string?> ReadSshAsync(IPAddress ip, int port, int timeout, CancellationToken ct)
    {
        using var socket = await TcpProbe.OpenAsync(ip, port, timeout, ct);
        if (socket is null) return null;
        await using var stream = new NetworkStream(socket, ownsSocket: false);
        // the server speaks first; the identification line is the only thing read and nothing is sent
        return await TcpProbe.ReadSomeAsync(stream, 255, Math.Max(timeout * 3, 1500), ct);
    }

    private static async Task<string?> HttpServerHeaderAsync(IPAddress ip, int port, string? host, int timeout, CancellationToken ct)
    {
        using var socket = await TcpProbe.OpenAsync(ip, port, timeout, ct);
        if (socket is null) return null;
        await using var stream = new NetworkStream(socket, ownsSocket: false);
        return await HeadAsync(stream, host ?? ip.ToString(), timeout, ct);
    }

    private static async Task<(string? Server, string? CertName)> TlsServerHeaderAsync(IPAddress ip, int port, string? host, int timeout, CancellationToken ct)
    {
        using var socket = await TcpProbe.OpenAsync(ip, port, timeout, ct);
        if (socket is null) return (null, null);
        await using var net = new NetworkStream(socket, ownsSocket: false);
        // certificate validation is disabled on purpose: the certificate is read for its name, not trusted for anything
        await using var ssl = new SslStream(net, false, static (_, _, _, _) => true);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(Math.Max(timeout * 3, 2000));
        try
        {
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host ?? ip.ToString(),
                EnabledSslProtocols = SslProtocols.None,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            }, cts.Token);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception) { return (null, null); }

        string? certName = null;
        try
        {
            if (ssl.RemoteCertificate is { } raw)
            {
                using var cert = new X509Certificate2(raw);
                var cn = cert.GetNameInfo(X509NameType.DnsName, false);
                if (!string.IsNullOrWhiteSpace(cn) && !cn.Contains('*') && !cn.Contains(' ') && !IPAddress.TryParse(cn, out _) && cn.Contains('.')) certName = cn.Trim();
            }
        }
        catch { }
        var server = await HeadAsync(ssl, host ?? certName ?? ip.ToString(), timeout, ct);
        return (server, certName);
    }

    private static async Task<string?> HeadAsync(Stream stream, string host, int timeout, CancellationToken ct)
    {
        var request = Encoding.ASCII.GetBytes("HEAD / HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: VulnVerdict discovery\r\nConnection: close\r\n\r\n");
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(Math.Max(timeout * 3, 1500));
        try { await stream.WriteAsync(request, cts.Token); await stream.FlushAsync(cts.Token); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception) { return null; }
        var text = await TcpProbe.ReadSomeAsync(stream, 4096, Math.Max(timeout * 3, 1500), ct, stopAtBlankLine: true);
        return BannerParser.ServerHeader(text);
    }
}
