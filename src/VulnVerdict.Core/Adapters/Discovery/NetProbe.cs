using System.Net;
using System.Net.Sockets;

namespace VulnVerdict.Core.Adapters.Discovery;

/// <summary>
/// Address-list parsing shared by the discovery sweep, the SNMP adapter and the external cross-check: one entry per
/// line, each a single IP, a CIDR block (IPv4 or IPv6 up to a sane size), an IPv4 range "a.b.c.d-e.f.g.h" or a hostname.
/// </summary>
public static class AddressRanges
{
    public sealed record Entry(string Text, IPAddress Address);

    /// <summary>Expand the text to concrete addresses. Hostnames are resolved; unresolvable or malformed lines become warnings.</summary>
    public static List<Entry> Expand(string? text, int limit, List<string> warnings, bool resolveHostnames = true)
    {
        var result = new List<Entry>();
        var seen = new HashSet<IPAddress>();
        var truncated = false;
        foreach (var raw in (text ?? "").Split('\n', '\r', ',', ';'))
        {
            var line = raw.Trim();
            if (line == "" || line.StartsWith('#')) continue;
            void Add(string label, IPAddress ip)
            {
                if (result.Count >= limit) { truncated = true; return; }
                if (seen.Add(ip)) result.Add(new Entry(label, ip));
            }

            if (line.Contains('/') && TryParseCidr(line, out var network, out var prefix))
            {
                foreach (var ip in EnumerateCidr(network, prefix, limit - result.Count + 1))
                {
                    if (result.Count >= limit) { truncated = true; break; }
                    Add(ip.ToString(), ip);
                }
                continue;
            }
            if (line.Contains('-') && !line.Contains(':'))
            {
                var parts = line.Split('-', 2, StringSplitOptions.TrimEntries);
                if (IPAddress.TryParse(parts[0], out var from) && IPAddress.TryParse(parts[1], out var to)
                    && from.AddressFamily == AddressFamily.InterNetwork && to.AddressFamily == AddressFamily.InterNetwork)
                {
                    var a = ToUInt32(from); var b = ToUInt32(to);
                    if (b < a) (a, b) = (b, a);
                    if (b - a > (uint)limit) { warnings.Add("Range " + line + " is larger than the " + limit + " address limit; truncated."); b = a + (uint)limit; }
                    for (var v = a; v <= b; v++) { var ip = FromUInt32(v); if (result.Count >= limit) { truncated = true; break; } Add(ip.ToString(), ip); if (v == uint.MaxValue) break; }
                    continue;
                }
            }
            if (IPAddress.TryParse(line, out var single)) { Add(line, single); continue; }
            if (!resolveHostnames) { warnings.Add("Not an IP address or CIDR block: " + line); continue; }
            try
            {
                var ips = Dns.GetHostAddresses(line).Where(i => i.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6).ToList();
                if (ips.Count == 0) warnings.Add("No address for " + line);
                foreach (var ip in ips) Add(line, ip);
            }
            catch (Exception ex) { warnings.Add("Could not resolve " + line + ": " + ex.Message); }
        }
        if (truncated) warnings.Add("Address list capped at " + limit + " addresses per run; split the range across connectors.");
        return result;
    }

    public static bool TryParseCidr(string text, out IPAddress network, out int prefix)
    {
        network = IPAddress.None; prefix = 0;
        var parts = text.Split('/', 2);
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0].Trim(), out var ip) || !int.TryParse(parts[1].Trim(), out prefix)) return false;
        var bits = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefix < 0 || prefix > bits) return false;
        network = ip;
        return true;
    }

    /// <summary>Hosts of a CIDR block. IPv4 blocks of /30 and larger skip the network and broadcast addresses. IPv6 blocks are capped at max addresses from the start of the block.</summary>
    public static IEnumerable<IPAddress> EnumerateCidr(IPAddress network, int prefix, int max)
    {
        if (network.AddressFamily == AddressFamily.InterNetwork)
        {
            var mask = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
            var start = ToUInt32(network) & mask;
            var end = start | ~mask;
            var skipEnds = prefix <= 30;
            var count = 0;
            for (ulong v = start; v <= end; v++)
            {
                if (skipEnds && (v == start || v == end)) continue;
                if (count++ >= max) yield break;
                yield return FromUInt32((uint)v);
            }
        }
        else
        {
            var bytes = network.GetAddressBytes();
            for (var i = 0; i < 16; i++)
            {
                var keep = Math.Clamp(prefix - i * 8, 0, 8);
                bytes[i] = (byte)(bytes[i] & (keep == 0 ? 0 : 0xFF << (8 - keep)));
            }
            var hostBits = 128 - prefix;
            var total = hostBits >= 31 ? int.MaxValue : (1 << hostBits);
            for (var n = 0; n < Math.Min(total, max); n++)
            {
                var b = (byte[])bytes.Clone();
                var carry = n;
                for (var i = 15; i >= 0 && carry > 0; i--) { var sum = b[i] + (carry & 0xFF); b[i] = (byte)sum; carry = (carry >> 8) + (sum >> 8); }
                yield return new IPAddress(b);
            }
        }
    }

    public static List<int> ParsePorts(string? text, string defaults)
    {
        var ports = new List<int>();
        foreach (var tok in (string.IsNullOrWhiteSpace(text) ? defaults : text).Split(new[] { ',', ' ', ';', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (tok.Contains('-'))
            {
                var p = tok.Split('-', 2);
                if (int.TryParse(p[0], out var a) && int.TryParse(p[1], out var b) && a is >= 1 and <= 65535 && b is >= 1 and <= 65535 && b >= a && b - a <= 1024)
                    for (var v = a; v <= b; v++) if (!ports.Contains(v)) ports.Add(v);
            }
            else if (int.TryParse(tok, out var v) && v is >= 1 and <= 65535 && !ports.Contains(v)) ports.Add(v);
        }
        return ports;
    }

    public static bool IsPrivateOrLocal(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return true;
        if (ip.AddressFamily == AddressFamily.InterNetworkV6) return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6UniqueLocal || ip.Equals(IPAddress.IPv6Any);
        var b = ip.GetAddressBytes();
        return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254) || (b[0] == 100 && b[1] >= 64 && b[1] <= 127) || b[0] == 0;
    }

    private static uint ToUInt32(IPAddress ip) { var b = ip.GetAddressBytes(); return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3]; }
    private static IPAddress FromUInt32(uint v) => new(new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v });
}

/// <summary>TCP connect probes with a hard timeout. A connect is the only thing sent unless a banner reader asks for more.</summary>
public static class TcpProbe
{
    /// <summary>Returns a connected socket, or null when the port is closed, filtered or the timeout elapsed. Never throws for network conditions.</summary>
    public static async Task<Socket?> OpenAsync(IPAddress ip, int port, int timeoutMs, CancellationToken ct)
    {
        var socket = new Socket(ip.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        try
        {
            await socket.ConnectAsync(new IPEndPoint(ip, port), cts.Token);
            return socket;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { socket.Dispose(); throw; }
        catch (Exception) { socket.Dispose(); return null; }
    }

    public static async Task<bool> IsOpenAsync(IPAddress ip, int port, int timeoutMs, CancellationToken ct)
    {
        var s = await OpenAsync(ip, port, timeoutMs, ct);
        if (s is null) return false;
        try { s.Shutdown(SocketShutdown.Both); } catch { }
        s.Dispose();
        return true;
    }

    /// <summary>Read whatever the peer sends within the timeout (at most max bytes), returning it as ASCII text.</summary>
    public static async Task<string> ReadSomeAsync(Stream stream, int max, int timeoutMs, CancellationToken ct, bool stopAtBlankLine = false)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeoutMs);
        var buffer = new byte[max];
        var total = 0;
        try
        {
            while (total < max)
            {
                var n = await stream.ReadAsync(buffer.AsMemory(total, max - total), cts.Token);
                if (n <= 0) break;
                total += n;
                var text = System.Text.Encoding.ASCII.GetString(buffer, 0, total);
                if (stopAtBlankLine ? text.Contains("\r\n\r\n") || text.Contains("\n\n") : text.Contains('\n')) break;
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception) { }
        return System.Text.Encoding.ASCII.GetString(buffer, 0, total);
    }

    public static async Task<string?> ReverseDnsAsync(IPAddress ip, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(Math.Max(timeoutMs, 1000));
            var entry = await Dns.GetHostEntryAsync(ip.ToString(), cts.Token);
            var name = entry.HostName?.Trim();
            if (string.IsNullOrEmpty(name) || IPAddress.TryParse(name, out _)) return null;
            return name.TrimEnd('.');
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception) { return null; }
    }
}
