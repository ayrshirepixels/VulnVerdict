using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json.Nodes;

namespace VulnVerdict.Tests;

/// <summary>Records every request (with its body read eagerly) and answers from ordered routes. Unrouted requests get 404.</summary>
public sealed class FakeHandler : HttpMessageHandler
{
    public sealed class Call
    {
        public HttpMethod Method { get; init; } = HttpMethod.Get;
        public Uri Url { get; init; } = new("http://localhost");
        public string? Body { get; init; }
        public string? ContentType { get; init; }
        public AuthenticationHeaderValue? Auth { get; init; }
        public Dictionary<string, string> Headers { get; init; } = new(StringComparer.OrdinalIgnoreCase);

        public string Path => Url.AbsolutePath;
        public string DecodedQuery => Uri.UnescapeDataString(Url.Query.TrimStart('?'));
        public JsonNode? Json => Body is null ? null : JsonNode.Parse(Body);
        public string? Header(string name) => Headers.TryGetValue(name, out var v) ? v : null;
    }

    private readonly List<(Func<HttpRequestMessage, bool> Match, Func<HttpRequestMessage, string?, HttpResponseMessage> Respond)> _routes = new();
    public List<Call> Calls { get; } = new();

    public FakeHandler On(HttpMethod method, string pathContains, string json, HttpStatusCode status = HttpStatusCode.OK) =>
        On(r => r.Method == method && (r.RequestUri?.PathAndQuery ?? "").Contains(pathContains, StringComparison.OrdinalIgnoreCase), (_, _) => Json(json, status));

    public FakeHandler On(Func<HttpRequestMessage, bool> match, Func<HttpRequestMessage, string?, HttpResponseMessage> respond)
    {
        _routes.Add((match, respond));
        return this;
    }

    public static HttpResponseMessage Json(string json, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(ct);
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var h in request.Headers) headers[h.Key] = string.Join(",", h.Value);
        Calls.Add(new Call
        {
            Method = request.Method, Url = request.RequestUri!, Body = body,
            ContentType = request.Content?.Headers.ContentType?.MediaType, Auth = request.Headers.Authorization, Headers = headers
        });
        foreach (var (match, respond) in _routes)
            if (match(request)) return respond(request, body);
        return Json("{\"error\":\"no fake route for " + request.Method + " " + request.RequestUri + "\"}", HttpStatusCode.NotFound);
    }
}

/// <summary>Hands out clients over one fake handler and remembers which named client was asked for.</summary>
public sealed class FakeHttpClientFactory : IHttpClientFactory
{
    private readonly FakeHandler _handler;
    public List<string> Names { get; } = new();

    public FakeHttpClientFactory(FakeHandler handler) => _handler = handler;

    public HttpClient CreateClient(string name)
    {
        Names.Add(name);
        return new HttpClient(_handler, disposeHandler: false) { BaseAddress = null };
    }
}
