using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Anthropic;
using Anthropic.Models.Messages;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Engine;

namespace VulnVerdict.Core.Services;

/// <summary>
/// Section 12. The model never decides a verdict; it explains one. Two artefacts, both cached with the
/// provider, model and prompt version recorded: a plain-English narrative per CVE, and an attack story per
/// verdict built from abstracted inputs only (no hostnames, IPs or asset names leave the box).
/// Providers: Anthropic (official SDK), OpenAI, or any OpenAI-compatible endpoint such as Ollama.
/// </summary>
public sealed class LlmService
{
    public const string PromptVersion = "2026-09-24.1";
    private const string NarrativeSystem =
        "You explain software vulnerabilities to an IT manager who has no security training and forty other jobs. " +
        "Write exactly three short sentences in plain British English: what the flaw lets an attacker do, what they need in order to do it, and what fixes it. " +
        "No jargon, no acronyms unless you expand them, no severity scores, no drama. Do not invent version numbers or facts that are not in the input.";
    private const string AttackStorySystem =
        "You are a pragmatic senior colleague explaining, to an IT manager with no security team, how a realistic attacker would actually have to go about exploiting one vulnerability in their environment. " +
        "Write one short paragraph (four to six sentences) in plain British English. Cover: where the attacker has to be (internet, inside the network, at the keyboard), what they need (nothing, a login, a user to click), how much skill or luck it takes, and what stops them. " +
        "Be honest when the exposure makes it hard. No jargon, no scores, no fear-mongering. Do not add facts that are not in the input.";

    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly SettingsService _settings;
    private readonly IHttpClientFactory _http;
    private readonly ILogger<LlmService> _log;

    public LlmService(IDbContextFactory<VvDbContext> factory, SettingsService settings, IHttpClientFactory http, ILogger<LlmService> log)
    {
        _factory = factory; _settings = settings; _http = http; _log = log;
    }

    public async Task<bool> IsConfiguredAsync(CancellationToken ct = default) => (await _settings.LoadAsync(ct)).LlmConfigured;

    public async Task<Narrative?> GetCachedAsync(string key, CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        return await db.Narratives.AsNoTracking().FirstOrDefaultAsync(n => n.Key == key, ct);
    }

    /// <summary>Three plain sentences about the CVE itself. Cached per CVE and prompt version.</summary>
    public async Task<Narrative> CveNarrativeAsync(string cveId, bool refresh = false, CancellationToken ct = default)
    {
        var key = "cve:" + cveId;
        if (!refresh && await GetCachedAsync(key, ct) is { } cached && cached.PromptVersion == PromptVersion) return cached;
        await using var db = await _factory.CreateDbContextAsync(ct);
        var cve = await db.Cves.AsNoTracking().FirstOrDefaultAsync(c => c.Id == cveId, ct) ?? throw new KeyNotFoundException(cveId);
        var affected = await db.CveAffected.AsNoTracking().Where(a => a.CveId == cveId).Take(6).ToListAsync(ct);
        var kev = await db.Kev.AsNoTracking().FirstOrDefaultAsync(k => k.CveId == cveId, ct);
        var cvss = CvssVector.Parse(cve.CvssV40Vector) ?? CvssVector.Parse(cve.CvssV31Vector);

        var input = "CVE: " + cve.Id + "\nTitle: " + (cve.Title ?? "(none)") + "\nVendor description: " + (cve.Description ?? "(none)")
            + "\nAffected products: " + string.Join("; ", affected.Select(a => a.Vendor + " " + a.Product + " (" + VersionMatcher.Describe(a.VersionsJson, a.DefaultStatus) + ")"))
            + "\nAttack path from the CVSS vector: " + (cvss is null ? "not stated" : string.Join(", ", cvss.Decode().Select(d => d.Metric + " = " + d.Meaning)))
            + "\nKnown exploited in the wild: " + (kev is null ? "no public confirmation" : "yes, listed by CISA on " + kev.DateAdded.ToString("yyyy-MM-dd") + (kev.RequiredAction is null ? "" : "; CISA advice: " + kev.RequiredAction));
        return await GenerateAndStoreAsync(key, NarrativeSystem, input, ct);
    }

    /// <summary>How an attacker would have to do it here, from abstracted inputs only.</summary>
    public async Task<Narrative> AttackStoryAsync(Guid verdictId, bool refresh = false, CancellationToken ct = default)
    {
        var key = "verdict:" + verdictId;
        if (!refresh && await GetCachedAsync(key, ct) is { } cached && cached.PromptVersion == PromptVersion) return cached;
        await using var db = await _factory.CreateDbContextAsync(ct);
        var v = await db.Verdicts.AsNoTracking().Include(x => x.WatchlistEntry).FirstOrDefaultAsync(x => x.Id == verdictId, ct) ?? throw new KeyNotFoundException();
        var cve = await db.Cves.AsNoTracking().FirstOrDefaultAsync(c => c.Id == v.CveId, ct);
        var cvss = CvssVector.Parse(cve?.CvssV40Vector) ?? CvssVector.Parse(cve?.CvssV31Vector);
        var e = v.WatchlistEntry!;

        // abstracted: product and version only, never the asset name or addresses
        var input = "CVE: " + v.CveId + "\nTitle: " + (cve?.Title ?? "(none)") + "\nVendor description: " + (cve?.Description ?? "(none)")
            + "\nThe organisation runs: " + e.Vendor + " " + e.Product + " " + (e.Version ?? "(version not recorded)")
            + "\nWhere it sits: " + v.DeclaredExposure.Plain() + (v.EffectiveExposure != v.DeclaredExposure ? " (but the attack path does not benefit from that: " + v.AttackVector.Plain() + ")" : "")
            + "\nHow important the system is to the business: " + v.Criticality
            + "\nExploitation status: " + v.Exploitation.Plain() + (v.InKev ? " (CISA Known Exploited Vulnerabilities)" : "") + (v.Epss is { } ep ? "; EPSS probability " + ep.ToString("0.00") : "")
            + "\nAttack path from the CVSS vector: " + (cvss is null ? "not stated" : string.Join(", ", cvss.Decode().Select(d => d.Metric + " = " + d.Meaning)))
            + "\nCan it be done at scale without help: " + (v.Automatable ? "yes" : "no")
            + "\nOur verdict: " + v.Tier.Plain() + (v.FixedIn is null ? "" : "; fixed in " + v.FixedIn);
        return await GenerateAndStoreAsync(key, AttackStorySystem, input, ct);
    }

    public async Task<string> TestAsync(CancellationToken ct = default)
    {
        var s = await _settings.LoadAsync(ct);
        return await CompleteAsync(s, "Reply with one short sentence.", "Confirm you can hear me.", ct);
    }

    private async Task<Narrative> GenerateAndStoreAsync(string key, string system, string input, CancellationToken ct)
    {
        var s = await _settings.LoadAsync(ct);
        if (!s.LlmConfigured) throw new InvalidOperationException("No AI provider is configured. Add one under Settings.");
        var text = await CompleteAsync(s, system, input, ct);
        await using var db = await _factory.CreateDbContextAsync(ct);
        var row = await db.Narratives.FirstOrDefaultAsync(n => n.Key == key, ct);
        if (row is null) { row = new Narrative { Key = key }; db.Narratives.Add(row); }
        row.Text = text.Trim(); row.Provider = s.LlmProvider; row.Model = s.LlmModel; row.PromptVersion = PromptVersion; row.CreatedAt = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);
        return row;
    }

    private async Task<string> CompleteAsync(AppSettings s, string system, string user, CancellationToken ct)
    {
        switch (s.LlmProvider.ToLowerInvariant())
        {
            case "anthropic": return await AnthropicAsync(s, system, user, ct);
            case "openai": return await OpenAiCompatibleAsync(s, "https://api.openai.com/v1", system, user, ct);
            case "openai-compatible":
            case "ollama":
                if (string.IsNullOrWhiteSpace(s.LlmBaseUrl)) throw new InvalidOperationException("Base URL is required for an OpenAI-compatible endpoint (for Ollama: http://ollama:11434/v1).");
                return await OpenAiCompatibleAsync(s, s.LlmBaseUrl.TrimEnd('/'), system, user, ct);
            default: throw new InvalidOperationException("Unknown AI provider " + s.LlmProvider);
        }
    }

    private static async Task<string> AnthropicAsync(AppSettings s, string system, string user, CancellationToken ct)
    {
        var client = new AnthropicClient { ApiKey = s.LlmApiKey };
        var response = await client.Messages.Create(new MessageCreateParams
        {
            Model = s.LlmModel,
            MaxTokens = 1024,
            System = system,
            Messages = [new() { Role = Role.User, Content = user }]
        }, cancellationToken: ct);
        if (response.StopReason == "refusal")
            throw new InvalidOperationException("The model declined to answer" + (response.StopDetails is { } d ? " (" + d.Category + ": " + d.Explanation + ")" : "") + ".");
        var text = string.Concat(response.Content.Select(b => b.Value).OfType<TextBlock>().Select(t => t.Text));
        if (string.IsNullOrWhiteSpace(text)) throw new InvalidOperationException("The model returned no text (stop reason " + response.StopReason + ").");
        return text;
    }

    private async Task<string> OpenAiCompatibleAsync(AppSettings s, string baseUrl, string system, string user, CancellationToken ct)
    {
        var client = _http.CreateClient("llm");
        using var req = new HttpRequestMessage(HttpMethod.Post, baseUrl + "/chat/completions");
        if (!string.IsNullOrWhiteSpace(s.LlmApiKey)) req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", s.LlmApiKey);
        req.Content = JsonContent.Create(new
        {
            model = s.LlmModel,
            messages = new object[] { new { role = "system", content = system }, new { role = "user", content = user } },
            max_completion_tokens = 1024
        });
        using var resp = await client.SendAsync(req, ct);
        var body = await resp.Content.ReadAsStringAsync(ct);
        if (!resp.IsSuccessStatusCode) throw new InvalidOperationException("The AI endpoint returned " + (int)resp.StatusCode + ": " + (body.Length > 300 ? body[..300] : body));
        using var doc = JsonDocument.Parse(body);
        var text = doc.RootElement.GetProperty("choices")[0].GetProperty("message").GetProperty("content").GetString();
        if (string.IsNullOrWhiteSpace(text)) throw new InvalidOperationException("The AI endpoint returned no text.");
        return text;
    }
}
