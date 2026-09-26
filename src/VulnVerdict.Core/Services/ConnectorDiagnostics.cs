using System.Diagnostics;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Adapters;
using VulnVerdict.Core.Adapters.Endpoints;

namespace VulnVerdict.Core.Services;

/// <summary>
/// Connector diagnostics for bug reports from real systems. Runs a connector's collection once, without applying
/// anything to the inventory, records what its API returned, and writes it out with credentials, device names, users,
/// serial numbers and addresses replaced by consistent placeholders (device-1, ip-1 ...), so the file can be attached to
/// a GitHub issue after the person has looked through it. Request bodies and token responses are never recorded.
/// Connectors that talk SSH, SNMP or WinRM get the summary and a sample of what was read, without raw responses.
/// </summary>
public sealed partial class ConnectorDiagnostics
{
    public const int MaxBodyChars = 200_000;
    public const int MaxTotalChars = 6_000_000;
    public static readonly TimeSpan MaxDuration = TimeSpan.FromMinutes(10);

    private readonly IServiceProvider _sp;
    private readonly ILogger<ConnectorDiagnostics> _log;

    public ConnectorDiagnostics(IServiceProvider sp, ILogger<ConnectorDiagnostics> log) { _sp = sp; _log = log; }

    public sealed record Exchange(string Method, string Url, int Status, string? ContentType, string? Body, bool Truncated);

    /// <summary>Collects via <paramref name="adapter"/> with recording, then returns the redacted diagnostics document as UTF-8 JSON.</summary>
    public async Task<byte[]> RunAsync(IInventoryAdapter adapter, IReadOnlyDictionary<string, string> credentials, CancellationToken ct)
    {
        var recorder = new Recorder();
        var (instance, recorded) = Recording(adapter, recorder);
        var sw = Stopwatch.StartNew();
        CollectResult? result = null; string? error = null;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(MaxDuration);
        try { result = await instance.CollectAsync(credentials, null, null, cts.Token); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { error = "stopped after " + MaxDuration.TotalMinutes + " minutes"; }
        catch (Exception ex) when (ex is not OperationCanceledException) { error = ex.GetType().Name + ": " + ex.Message; }
        _log.LogInformation("Diagnostics for {Adapter}: {Exchanges} responses recorded, {Error}", adapter.Metadata.Id, recorder.Exchanges.Count, error ?? "no error");
        return Build(adapter.Metadata.Id, recorded, recorder.Exchanges, result, error, sw.Elapsed, credentials);
    }

    /// <summary>A second instance of the adapter whose HTTP goes through the recorder, when the adapter is built that way.</summary>
    private (IInventoryAdapter Adapter, bool Recorded) Recording(IInventoryAdapter adapter, Recorder recorder)
    {
        try
        {
            var handlers = _sp.GetService<IHttpMessageHandlerFactory>();
            if (handlers is null) return (adapter, false);
            var factory = new RecordingHttpClientFactory(handlers, recorder);
            var copy = (IInventoryAdapter)ActivatorUtilities.CreateInstance(_sp, adapter.GetType(), factory);
            if (copy is ConfigMgrAdapter cm)
            {
                cm.ClientFactory = creds => new HttpClient(new RecordingHandler(recorder) { InnerHandler = ConfigMgrAdapter.CreateHandler(creds) }) { Timeout = TimeSpan.FromMinutes(5) };
                return (cm, true);
            }
            // adapters that take no IHttpClientFactory (SSH, SNMP, WinRM) are created without it and record nothing
            return (copy, adapter.GetType().GetConstructors().Any(c => c.GetParameters().Any(p => p.ParameterType == typeof(IHttpClientFactory))));
        }
        catch (Exception ex) when (ex is InvalidOperationException or MissingMethodException)
        {
            return (adapter, false);
        }
    }

    // ------------------------------------------------------------------ document (public for tests)

    public static byte[] Build(string adapterId, bool recorded, IReadOnlyList<Exchange> exchanges, CollectResult? result, string? error, TimeSpan elapsed, IReadOnlyDictionary<string, string> credentials)
    {
        var r = new Redactor();
        foreach (var (k, v) in credentials) if (k != HealthNotices.SecretExpiresKey) r.Secret(v);   // a date is not a secret
        if (result is not null)
            foreach (var a in result.Assets)
            {
                r.Known(a.DisplayName, "device"); r.Known(a.Owner, "user");
                foreach (var h in a.Hostnames) r.Known(h, "device");
                foreach (var ip in a.IpAddresses) r.Known(ip, "ip");
                foreach (var m in a.MacAddresses) r.Known(m, "mac");
            }

        var doc = new JsonObject
        {
            ["tool"] = "VulnVerdict connector diagnostics",
            ["consoleVersion"] = AppVersion.Current,
            ["adapter"] = adapterId,
            ["createdAt"] = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"),
            ["seconds"] = Math.Round(elapsed.TotalSeconds, 1),
            ["note"] = "Credentials, device and host names, users, email, serial numbers and IP and MAC addresses are replaced by placeholders such as device-1 and ip-1; the same value always gets the same placeholder. Product names and versions are kept because they are what a fix needs. Request bodies and sign-in responses are never recorded. Please look through this file before attaching it.",
            ["rawResponses"] = recorded ? "recorded" : "not available for this connector (it does not use an HTTP API); the summary and sample below are all there is",
            ["outcome"] = new JsonObject
            {
                ["ok"] = error is null,
                ["error"] = error is null ? null : r.Text(error),
                ["assets"] = result?.Assets.Count ?? 0,
                ["software"] = result?.Software.Count ?? 0,
                ["findings"] = result?.Findings.Count ?? 0,
                ["exposures"] = result?.Exposures.Count ?? 0,
                ["warnings"] = new JsonArray((result?.Warnings ?? new()).Take(50).Select(w => (JsonNode?)JsonValue.Create(r.Text(w))).ToArray()),
            },
        };
        if (result is not null)
        {
            doc["sampleAssets"] = new JsonArray(result.Assets.Take(25).Select(a => (JsonNode?)new JsonObject
            {
                ["name"] = r.Map(a.DisplayName, "device"), ["kind"] = a.Kind.ToString(), ["os"] = string.Join(" ", new[] { a.OsVendor, a.OsProduct, a.OsVersion }.Where(x => !string.IsNullOrWhiteSpace(x))),
                ["addresses"] = a.IpAddresses.Length, ["macs"] = a.MacAddresses.Length,
            }).ToArray());
            doc["sampleSoftware"] = new JsonArray(result.Software.Take(150).Select(s => (JsonNode?)new JsonObject
            {
                ["device"] = r.Map(s.AssetExternalId, "id"), ["vendor"] = s.Vendor, ["product"] = r.Text(s.Product), ["version"] = s.Version, ["kind"] = s.Kind.ToString(), ["cpe"] = s.Cpe,
            }).ToArray());
        }
        var total = 0;
        var arr = new JsonArray();
        foreach (var e in exchanges)
        {
            var body = e.Body is null ? null : r.Body(e.Body, e.ContentType);
            if (body is not null && total + body.Length > MaxTotalChars) { body = null; }
            total += body?.Length ?? 0;
            arr.Add(new JsonObject { ["method"] = e.Method, ["url"] = r.Text(e.Url), ["status"] = e.Status, ["contentType"] = e.ContentType, ["truncated"] = e.Truncated || (e.Body is not null && body is null), ["body"] = body });
        }
        doc["responses"] = arr;
        return Encoding.UTF8.GetBytes(doc.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
    }

    /// <summary>Consistent placeholders for identifying values, by known value, by JSON key, and by address pattern.</summary>
    public sealed partial class Redactor
    {
        private readonly Dictionary<string, string> _known = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, int> _counters = new();
        private readonly List<string> _secrets = new();

        [GeneratedRegex(@"\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", RegexOptions.IgnoreCase)] private static partial Regex MacRx();
        [GeneratedRegex(@"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")] private static partial Regex EmailRx();
        [GeneratedRegex(@"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")] private static partial Regex Ipv4Rx();

        /// <summary>JSON keys whose values identify a device, person or network (compared without case, "_" or "-").</summary>
        private static readonly string[] IdentityKeys =
        {
            "hostname", "dnsname", "fqdn", "computername", "computerdnsname", "devicename", "systemname", "longname", "discoveredname", "localhostname",
            "netbiosname", "resourcenames", "fulldomainname", "domain", "userprincipalname", "upn", "email", "emailaddress", "username", "user", "lastloggedinuser",
            "lastlogonusername", "loggedinuser", "owner", "serialnumber", "serial", "azureaddeviceid", "customername", "sitename", "organizationname",
            "ipaddress", "ipaddresses", "ip", "ipaddr", "lastipaddress", "lastexternalipaddress", "intipaddress", "extipaddress", "publicip", "publicipaddress",
            "macaddress", "macaddresses", "mac", "wifimacaddress", "ethernetmacaddress", "altmacaddress", "bluetoothmacaddress", "uri", "phonenumber", "imei",
        };

        public void Secret(string? value)
        {
            if (string.IsNullOrEmpty(value) || value.Trim().Length < 4) return;
            var v = value.Trim();
            _secrets.Add(v);
            // a URL or host:port credential also appears as its bare host in errors ("acme.api.kandji.io:443"); that
            // host usually names the customer, so it goes too
            var candidate = v.Contains("://", StringComparison.Ordinal) ? v : "https://" + v;
            if (Uri.TryCreate(candidate, UriKind.Absolute, out var u) && u.Host.Contains('.') && u.Host.Length >= 4 && !_secrets.Contains(u.Host)) _secrets.Add(u.Host);
        }
        public void Known(string? value, string kind) { if (!string.IsNullOrWhiteSpace(value) && value.Trim().Length >= 3) Map(value.Trim(), kind); }

        public string Map(string value, string kind)
        {
            if (_known.TryGetValue(value, out var p)) return p;
            _counters[kind] = _counters.GetValueOrDefault(kind) + 1;
            return _known[value] = kind + "-" + _counters[kind];
        }

        public string Text(string text)
        {
            var s = text;
            foreach (var secret in _secrets.OrderByDescending(x => x.Length)) s = s.Replace(secret, "[credential]", StringComparison.Ordinal);
            foreach (var (value, placeholder) in _known.OrderByDescending(k => k.Key.Length).ToList())
                s = Regex.Replace(s, @"(?<![\w.-])" + Regex.Escape(value) + @"(?![\w-]|\.\w)", placeholder, RegexOptions.IgnoreCase);
            s = MacRx().Replace(s, m => Map(m.Value, "mac"));
            s = EmailRx().Replace(s, m => Map(m.Value, "email"));
            return s;
        }

        /// <summary>Addresses in free text (XML, plain text, key-less values) as well; versions with a part above 255 are left alone.</summary>
        public string TextWithAddresses(string text) => Ipv4Rx().Replace(Text(text), m => m.Value is "0.0.0.0" or "127.0.0.1" ? m.Value : Map(m.Value, "ip"));

        public string Body(string body, string? contentType)
        {
            var t = body.TrimStart();
            if (t.StartsWith('{') || t.StartsWith('['))
            {
                try
                {
                    var node = JsonNode.Parse(body);
                    if (node is not null) return Walk(node, null)!.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
                }
                catch (JsonException) { /* not JSON after all: redact as text */ }
            }
            return TextWithAddresses(body);
        }

        private JsonNode? Walk(JsonNode? node, string? key)
        {
            switch (node)
            {
                case JsonObject o:
                    foreach (var p in o.ToList()) o[p.Key] = Walk(p.Value?.DeepClone(), p.Key);
                    return o;
                case JsonArray a:
                    var copy = new JsonArray();
                    foreach (var item in a) copy.Add(Walk(item?.DeepClone(), key));
                    return copy;
                case JsonValue v when v.TryGetValue<string>(out var s):
                    if (key is not null && IsIdentityKey(key) && s.Length > 0) return JsonValue.Create(Map(s, Kind(key)));
                    // no address pattern here: in JSON, addresses sit under the keys above or are values the connector collected,
                    // and the pattern would also catch four-part versions such as 12.1.2.172
                    return JsonValue.Create(Text(s));
                default:
                    return node;
            }
        }

        private static bool IsIdentityKey(string key)
        {
            var k = key.Replace("_", "").Replace("-", "").ToLowerInvariant();
            return IdentityKeys.Contains(k);
        }

        private static string Kind(string key)
        {
            var k = key.ToLowerInvariant();
            return k.Contains("mac") ? "mac" : k.Contains("ip") || k == "uri" ? "ip" : k.Contains("mail") || k.Contains("upn") || k.Contains("principal") ? "email"
                : k.Contains("user") || k.Contains("owner") ? "user" : k.Contains("serial") || k.Contains("imei") || k.Contains("azuread") ? "serial"
                : k.Contains("customer") || k.Contains("site") || k.Contains("organization") || k.Contains("domain") ? "org" : "device";
        }
    }

    // ------------------------------------------------------------------ recording

    public sealed class Recorder
    {
        private readonly object _lock = new();
        private int _chars;
        public List<Exchange> Exchanges { get; } = new();

        public void Add(Exchange e)
        {
            lock (_lock)
            {
                if (_chars > MaxTotalChars) e = e with { Body = null, Truncated = true };
                _chars += e.Body?.Length ?? 0;
                Exchanges.Add(e);
            }
        }
    }

    /// <summary>Records each response; sign-in and token exchanges keep only their status.</summary>
    public sealed class RecordingHandler : DelegatingHandler
    {
        private readonly Recorder _recorder;
        public RecordingHandler(Recorder recorder) => _recorder = recorder;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var response = await base.SendAsync(request, ct);
            var url = request.RequestUri is null ? "" : request.RequestUri.GetLeftPart(UriPartial.Path) + QueryNames(request.RequestUri.Query);
            var path = request.RequestUri?.AbsolutePath.ToLowerInvariant() ?? "";
            var signIn = path.Contains("token") || path.Contains("/auth") || path.Contains("signin") || path.Contains("login") || path.Contains("session");
            string? body = null; var truncated = false;
            if (!signIn && response.Content is not null)
            {
                await response.Content.LoadIntoBufferAsync(ct);
                var text = await response.Content.ReadAsStringAsync(ct);
                truncated = text.Length > MaxBodyChars;
                body = truncated ? text[..MaxBodyChars] : text;
            }
            _recorder.Add(new Exchange(request.Method.Method, url, (int)response.StatusCode, response.Content?.Headers.ContentType?.MediaType, signIn ? "[sign-in response not recorded]" : body, truncated));
            return response;
        }

        /// <summary>"?cursor=abc&amp;pageSize=100" to "?cursor=&amp;pageSize=100": parameter names only, values can hold tokens.</summary>
        private static string QueryNames(string query)
        {
            if (string.IsNullOrEmpty(query) || query == "?") return "";
            var names = query.TrimStart('?').Split('&').Select(p => Uri.UnescapeDataString(p.Split('=')[0])).Where(n => n.Length > 0);
            return "?" + string.Join("&", names.Select(n => n + "="));
        }
    }

    private sealed class RecordingHttpClientFactory : IHttpClientFactory
    {
        private readonly IHttpMessageHandlerFactory _handlers;
        private readonly Recorder _recorder;
        public RecordingHttpClientFactory(IHttpMessageHandlerFactory handlers, Recorder recorder) { _handlers = handlers; _recorder = recorder; }

        public HttpClient CreateClient(string name)
        {
            var client = new HttpClient(new RecordingHandler(_recorder) { InnerHandler = _handlers.CreateHandler(name) }, disposeHandler: false) { Timeout = TimeSpan.FromMinutes(5) };
            client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("VulnVerdict", "0.2"));
            return client;
        }
    }
}
