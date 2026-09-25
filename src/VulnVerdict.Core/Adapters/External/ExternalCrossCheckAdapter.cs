using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Adapters.Discovery;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Adapters.External;

/// <summary>
/// External cross-check: resolve the organisation's public DNS names and declared IP ranges and see what answers.
/// Anything answering is tagged Internet regardless of what the firewall adapter says. Shodan is optional and adds
/// the view from outside; the console's own probe proves reachability from wherever the console sits.
/// </summary>
public sealed class ExternalCrossCheckAdapter : IInventoryAdapter
{
    public const string DefaultPorts = "443,80,22,25,3389,8443,5985,21";
    private const int MaxAddresses = 1024;
    private const int Concurrency = 32;

    private readonly IHttpClientFactory _http;
    private readonly ILogger<ExternalCrossCheckAdapter> _log;

    public ExternalCrossCheckAdapter(IHttpClientFactory http, ILogger<ExternalCrossCheckAdapter> log) { _http = http; _log = log; }

    public AdapterMetadata Metadata { get; } = new(
        Id: "external-crosscheck",
        DisplayName: "External cross-check (public DNS and IP ranges)",
        Vendor: "VulnVerdict (built in)",
        Description: "Resolves the organisation's public DNS names and declared IP ranges and probes the listed ports. Anything that answers is tagged Internet-facing regardless of what the firewall adapter says, and unknown internet-facing hosts appear as assets. A Shodan API key adds the view from outside the network.",
        Kinds: new[] { AssetKind.Server, AssetKind.Firewall, AssetKind.Other },
        Form: new[]
        {
            new CredentialField("dnsNames", "Public DNS names", CredentialTypes.TextArea, "Public hostnames, one per line (www, mail, vpn, remote...).", Required: false),
            new CredentialField("ipRanges", "Public IP ranges", CredentialTypes.TextArea, "Public IPs or CIDR blocks the organisation owns, one per line.", Required: false),
            new CredentialField("ports", "Ports", CredentialTypes.Text, "TCP ports to probe, comma separated.", Required: false, Default: DefaultPorts),
            new CredentialField("shodanApiKey", "Shodan API key", CredentialTypes.Password, "Optional. Adds Shodan's open ports and product banners for each address.", Required: false),
            new CredentialField("timeoutMs", "Connect timeout (ms)", CredentialTypes.Number, null, Required: false, Default: "3000"),
        },
        MinimumPermission: "none: outbound DNS and TCP from the console (optional read-only Shodan API key)",
        DefaultIntervalMinutes: 1440);

    public async Task<TestResult> TestAsync(IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        try
        {
            var warnings = new List<string>();
            var names = Lines(credentials.GetValueOrDefault("dnsNames"));
            var ranges = AddressRanges.Expand(credentials.GetValueOrDefault("ipRanges"), MaxAddresses, warnings, resolveHostnames: false);
            if (names.Count == 0 && ranges.Count == 0) return new TestResult(false, "Give at least one public DNS name or IP range.");
            var parts = new List<string>();
            if (names.Count > 0)
            {
                var ips = await ResolveAsync(names[0], ct);
                parts.Add(ips.Count == 0 ? names[0] + " does not resolve" : names[0] + " resolves to " + string.Join(", ", ips.Select(i => i.ToString())));
            }
            if (ranges.Count > 0) parts.Add(ranges.Count + " addresses in the declared ranges");
            var key = credentials.GetValueOrDefault("shodanApiKey")?.Trim();
            if (!string.IsNullOrEmpty(key))
            {
                using var resp = await _http.CreateClient("adapter").GetAsync("https://api.shodan.io/api-info?key=" + Uri.EscapeDataString(key), ct);
                parts.Add(resp.IsSuccessStatusCode ? "Shodan key accepted" : "Shodan key rejected (" + (int)resp.StatusCode + ")");
            }
            if (warnings.Count > 0) parts.AddRange(warnings);
            return new TestResult(true, string.Join("; ", parts));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { return new TestResult(false, ex.Message); }
    }

    public async Task<CollectResult> CollectAsync(IReadOnlyDictionary<string, string> credentials, DateTime? since, IProgress<string>? progress, CancellationToken ct)
    {
        var result = new CollectResult { FullSnapshot = true };
        var names = Lines(credentials.GetValueOrDefault("dnsNames"));
        var ranges = AddressRanges.Expand(credentials.GetValueOrDefault("ipRanges"), MaxAddresses, result.Warnings, resolveHostnames: false);
        var ports = AddressRanges.ParsePorts(credentials.GetValueOrDefault("ports"), DefaultPorts);
        var timeout = int.TryParse(credentials.GetValueOrDefault("timeoutMs"), out var t) && t >= 200 ? Math.Min(t, 15000) : 3000;
        var shodanKey = credentials.GetValueOrDefault("shodanApiKey")?.Trim();
        if (names.Count == 0 && ranges.Count == 0) { result.Warnings.Add("No public DNS names or IP ranges configured."); return result; }

        // ---- resolve names; remember which names point at each address
        progress?.Report("Resolving " + names.Count + " names");
        var namesByIp = new Dictionary<IPAddress, List<string>>();
        foreach (var name in names)
        {
            ct.ThrowIfCancellationRequested();
            var ips = await ResolveAsync(name, ct);
            if (ips.Count == 0) { result.Warnings.Add(name + " does not resolve."); continue; }
            foreach (var ip in ips)
            {
                if (AddressRanges.IsPrivateOrLocal(ip)) { result.Warnings.Add(name + " resolves to the private address " + ip + " from here (split-horizon DNS?); it was skipped."); continue; }
                (namesByIp.TryGetValue(ip, out var l) ? l : namesByIp[ip] = new()).Add(name);
            }
        }
        foreach (var r in ranges) namesByIp.TryAdd(r.Address, new());
        var targets = namesByIp.Keys.ToList();
        if (targets.Count == 0) { result.Warnings.Add("Nothing to probe: no name resolved to a public address and no ranges were given."); return result; }

        // ---- probe from the console
        progress?.Report("Probing " + targets.Count + " addresses on " + ports.Count + " ports");
        var openByIp = new Dictionary<IPAddress, List<int>>();
        var gate = new SemaphoreSlim(Concurrency);
        var probes = targets.Select(async ip =>
        {
            await gate.WaitAsync(ct);
            try
            {
                var open = new List<int>();
                await Task.WhenAll(ports.Select(async p => { if (await TcpProbe.IsOpenAsync(ip, p, timeout, ct)) lock (open) open.Add(p); }));
                open.Sort();
                lock (openByIp) openByIp[ip] = open;
            }
            finally { gate.Release(); }
        }).ToList();
        await Task.WhenAll(probes);

        // ---- Shodan's view from outside (optional, 1 request per second)
        var shodan = new Dictionary<IPAddress, ShodanHost>();
        if (!string.IsNullOrEmpty(shodanKey))
        {
            progress?.Report("Asking Shodan about " + targets.Count + " addresses");
            var client = _http.CreateClient("adapter");
            var keyOk = true;
            foreach (var ip in targets)
            {
                if (!keyOk) break;
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var resp = await client.GetAsync("https://api.shodan.io/shodan/host/" + ip + "?key=" + Uri.EscapeDataString(shodanKey), ct);
                    if (resp.StatusCode == HttpStatusCode.NotFound) { }
                    else if (resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden) { result.Warnings.Add("Shodan rejected the API key (" + (int)resp.StatusCode + "); Shodan results skipped."); keyOk = false; }
                    else if (resp.StatusCode == HttpStatusCode.TooManyRequests) { result.Warnings.Add("Shodan rate limit hit; remaining addresses skipped."); keyOk = false; }
                    else if (resp.IsSuccessStatusCode) shodan[ip] = ParseShodan(await resp.Content.ReadAsStringAsync(ct));
                    else result.Warnings.Add("Shodan answered " + (int)resp.StatusCode + " for " + ip + ".");
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
                catch (Exception ex) { result.Warnings.Add("Shodan lookup for " + ip + " failed: " + ex.Message); }
                await Task.Delay(1100, ct);
            }
        }

        // ---- assets and exposure
        var answering = 0;
        foreach (var ip in targets)
        {
            var open = openByIp.GetValueOrDefault(ip) ?? new();
            shodan.TryGetValue(ip, out var sh);
            var shodanPorts = sh?.Ports.Where(p => !open.Contains(p)).ToList() ?? new();
            if (open.Count == 0 && shodanPorts.Count == 0) continue;
            answering++;
            var ipText = ip.ToString();
            var hostnames = namesByIp[ip].Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (sh is not null) foreach (var h in sh.Hostnames) if (!hostnames.Contains(h, StringComparer.OrdinalIgnoreCase) && hostnames.Count < 10) hostnames.Add(h);
            result.Assets.Add(new AssetRecord(ipText, hostnames.FirstOrDefault() ?? ipText, AssetKind.Other, hostnames.ToArray(), new[] { ipText }, Array.Empty<string>()));

            var evidence = new List<string>();
            if (open.Count > 0) evidence.Add("answers on " + string.Join(", ", open.Select(p => "tcp/" + p)) + " from the console");
            if (shodanPorts.Count > 0) evidence.Add("Shodan reports " + string.Join(", ", shodanPorts.Select(p => "tcp/" + p)) + " open");
            result.Exposures.Add(new ExposureRecord(Exposure.Internet, string.Join("; ", evidence), AssetExternalId: ipText, Hostname: hostnames.FirstOrDefault(), IpAddress: ipText));

            if (sh is not null)
                foreach (var s in sh.Services)
                    if (BannerParser.FromProduct(ipText, s.Product, s.Version, s.Port) is { } rec && !result.Software.Any(x => x.AssetExternalId == ipText && x.Product == rec.Product && x.Version == rec.Version)) result.Software.Add(rec);
        }

        result.Warnings.Add(answering + " of " + targets.Count + " public addresses answered" + (shodan.Count > 0 ? " (including Shodan's view)" : "") + ".");
        result.Warnings.Add("A probe from inside the network proves reachability from the console, not from the internet, unless the console sits outside the perimeter; use the Shodan key or run the console outside for the view from the internet.");
        _log.LogInformation("External cross-check: {Answering} of {Targets} addresses answered", answering, targets.Count);
        return result;
    }

    // ------------------------------------------------------------------ helpers

    private static List<string> Lines(string? text) => (text ?? "").Split(new[] { '\n', '\r', ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        .Where(l => l != "" && !l.StartsWith('#')).Select(l => l.TrimEnd('.').ToLowerInvariant()).Distinct().ToList();

    private static async Task<List<IPAddress>> ResolveAsync(string name, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(5000);
            var ips = await Dns.GetHostAddressesAsync(name, cts.Token);
            return ips.Where(i => i.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6).Distinct().ToList();
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception) { return new(); }
    }

    private sealed record ShodanService(int Port, string? Product, string? Version);
    private sealed record ShodanHost(List<int> Ports, List<string> Hostnames, List<ShodanService> Services);

    private static ShodanHost ParseShodan(string json)
    {
        var host = new ShodanHost(new(), new(), new());
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.TryGetProperty("ports", out var ports) && ports.ValueKind == JsonValueKind.Array)
            foreach (var p in ports.EnumerateArray()) if (p.TryGetInt32(out var port) && !host.Ports.Contains(port)) host.Ports.Add(port);
        if (root.TryGetProperty("hostnames", out var hosts) && hosts.ValueKind == JsonValueKind.Array)
            foreach (var h in hosts.EnumerateArray()) if (h.ValueKind == JsonValueKind.String && h.GetString() is { Length: > 0 } s) host.Hostnames.Add(s.ToLowerInvariant());
        if (root.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array)
            foreach (var d in data.EnumerateArray())
            {
                if (d.ValueKind != JsonValueKind.Object || !d.TryGetProperty("port", out var pe) || !pe.TryGetInt32(out var port)) continue;
                var transport = d.TryGetProperty("transport", out var te) && te.ValueKind == JsonValueKind.String ? te.GetString() : "tcp";
                if (transport != "tcp") continue;
                if (!host.Ports.Contains(port)) host.Ports.Add(port);
                var product = d.TryGetProperty("product", out var pr) && pr.ValueKind == JsonValueKind.String ? pr.GetString() : null;
                var version = d.TryGetProperty("version", out var ve) && ve.ValueKind == JsonValueKind.String ? ve.GetString() : null;
                if (!string.IsNullOrWhiteSpace(product)) host.Services.Add(new ShodanService(port, product, version));
            }
        host.Ports.Sort();
        return host;
    }
}
