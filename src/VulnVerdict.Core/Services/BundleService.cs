using System.IO.Compression;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Services;

public enum BundleOutcome { NotConfigured, Skipped, UpToDate, Applied, Refused, Failed }

public sealed record BundleCheck(BundleOutcome Outcome, string? Version, string Reason, DateTime At)
{
    public bool Ok => Outcome is BundleOutcome.UpToDate or BundleOutcome.Applied or BundleOutcome.Skipped or BundleOutcome.NotConfigured;
}

/// <summary>
/// Section 10.2 console side. Polls the central service for the latest signed bundle (hourly, from the worker loop),
/// verifies the manifest signature against the embedded public key, refuses unsigned or downgraded bundles, verifies
/// every file hash and applies the bundle locally. Also applies an uploaded bundle file for air-gapped sites.
/// The customer's inventory never leaves the network: this service only ever downloads.
/// </summary>
public sealed class BundleService
{
    /// <summary>
    /// Public half of the central service's signing key. Replace with the production key before release; the dev key
    /// pair is generated with "dotnet run --project src/VulnVerdict.Central -- keygen".
    /// </summary>
    public const string PublicKeyPem = """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEE6gzWfGIjSdr/BRsZuCVRYu+wZR0
        qc2wOEvYFKLQ2IKDTQJlHF3jD/kZyd3vCzFEF2AXIeIqnFi2SuxR6pbfcQ==
        -----END PUBLIC KEY-----
        """;

    public static readonly TimeSpan PollInterval = TimeSpan.FromHours(1);
    /// <summary>An uploaded (air-gap) bundle keeps the public feeds switched off for this long; after that the console falls back to pulling them.</summary>
    public static readonly TimeSpan UploadedBundleWindow = TimeSpan.FromDays(7);

    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly SettingsService _settings;
    private readonly IHttpClientFactory _http;
    private readonly WorkerOptions _opt;
    private readonly ILogger<BundleService> _log;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private DateTime _lastPoll = DateTime.MinValue;
    private volatile bool _bundleMode;

    public BundleService(IDbContextFactory<VvDbContext> factory, SettingsService settings, IHttpClientFactory http, WorkerOptions opt, ILogger<BundleService> log)
    {
        _factory = factory; _settings = settings; _http = http; _opt = opt; _log = log;
    }

    /// <summary>
    /// True when the console is fed by bundles (a bundle URL is set, or an uploaded bundle was applied in the last
    /// 7 days). The worker must not run the public feeds while this is true. Refreshed by every CheckAndApplyAsync call.
    /// </summary>
    public bool BundleModeEnabled => _bundleMode;

    public BundleCheck? LastCheck { get; private set; }
    public string? Progress { get; private set; }
    public bool Busy => _gate.CurrentCount == 0;

    public static ECDsa PublicKey()
    {
        var key = ECDsa.Create();
        key.ImportFromPem(PublicKeyPem);
        return key;
    }

    /// <summary>Recompute <see cref="BundleModeEnabled"/> from settings and the last applied bundle.</summary>
    public async Task<bool> IsBundleModeAsync(CancellationToken ct = default)
    {
        var s = await _settings.LoadAsync(ct);
        return await RefreshModeAsync(s, ct);
    }

    private async Task<bool> RefreshModeAsync(AppSettings s, CancellationToken ct)
    {
        var enabled = !string.IsNullOrWhiteSpace(s.BundleUrl);
        if (!enabled)
        {
            await using var db = await _factory.CreateDbContextAsync(ct);
            var last = await BundleApplier.CurrentAsync(db, ct);
            enabled = last is not null && last.Source.StartsWith("upload", StringComparison.OrdinalIgnoreCase) && DateTime.UtcNow - last.AppliedAt < UploadedBundleWindow;
        }
        _bundleMode = enabled;
        return enabled;
    }

    public async Task<BundleState?> CurrentAsync(CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        return await BundleApplier.CurrentAsync(db, ct);
    }

    /// <summary>Worker entry point: refreshes the mode flag every call, polls the central service at most hourly.</summary>
    public Task<BundleCheck> CheckAndApplyAsync(CancellationToken ct) => CheckAndApplyAsync(false, ct);

    /// <summary>Poll now regardless of the hourly interval (the "Check now" button).</summary>
    public async Task<BundleCheck> CheckAndApplyAsync(bool force, CancellationToken ct)
    {
        var s = await _settings.LoadAsync(ct);
        await RefreshModeAsync(s, ct);
        if (string.IsNullOrWhiteSpace(s.BundleUrl))
            return Record(new BundleCheck(BundleOutcome.NotConfigured, null, "No bundle URL is configured; the console pulls the public feeds directly.", DateTime.UtcNow));
        if (!force && DateTime.UtcNow - _lastPoll < PollInterval)
            return new BundleCheck(BundleOutcome.Skipped, null, "Next check at " + (_lastPoll + PollInterval).ToString("u"), DateTime.UtcNow);
        if (!await _gate.WaitAsync(0, ct))
            return new BundleCheck(BundleOutcome.Skipped, null, "A bundle is already being applied.", DateTime.UtcNow);
        try
        {
            _lastPoll = DateTime.UtcNow;
            var baseUrl = s.BundleUrl.Trim().TrimEnd('/');
            var http = _http.CreateClient("feeds");
            Progress = "Fetching manifest";
            var manifestJson = await http.GetStringAsync(baseUrl + "/bundle/latest", ct);
            var manifest = BundleManifest.Parse(manifestJson);
            if (manifest is null || string.IsNullOrEmpty(manifest.Version))
                return Record(new BundleCheck(BundleOutcome.Failed, null, "The central service returned an unreadable manifest.", DateTime.UtcNow));
            using (var pub = PublicKey())
            {
                if (!manifest.Verify(pub))
                    return Record(new BundleCheck(BundleOutcome.Refused, manifest.Version, "Bundle " + manifest.Version + " is unsigned or not signed by the trusted key; refused.", DateTime.UtcNow));
            }
            BundleState? current;
            await using (var db = await _factory.CreateDbContextAsync(ct)) current = await BundleApplier.CurrentAsync(db, ct);
            if (current is not null && string.CompareOrdinal(manifest.Version, current.Version) == 0)
                return Record(new BundleCheck(BundleOutcome.UpToDate, manifest.Version, "Bundle " + manifest.Version + " is already applied.", DateTime.UtcNow));
            if (BundleApplier.CheckDowngrade(manifest.Version, current?.Version) is { } why)
                return Record(new BundleCheck(BundleOutcome.Refused, manifest.Version, why, DateTime.UtcNow));

            var inbox = Path.Combine(_opt.DataDir, "bundles", "inbox");
            Directory.CreateDirectory(inbox);
            var zipPath = Path.Combine(inbox, manifest.Version + ".zip");
            try
            {
                Progress = "Downloading bundle " + manifest.Version;
                using (var resp = await http.GetAsync(baseUrl + "/bundle/" + manifest.Version + ".zip", HttpCompletionOption.ResponseHeadersRead, ct))
                {
                    resp.EnsureSuccessStatusCode();
                    await using var src = await resp.Content.ReadAsStreamAsync(ct);
                    await using var dst = File.Create(zipPath);
                    await src.CopyToAsync(dst, ct);
                }
                var host = Uri.TryCreate(baseUrl, UriKind.Absolute, out var u) ? u.Host : baseUrl;
                var result = await ApplyZipAsync(zipPath, manifest, "central " + host, ct);
                _bundleMode = true;
                _log.LogInformation("Applied bundle {Version} from {Url}: {Cves} CVEs, {Kev} KEV, {Epss} EPSS, {Signals} signals", manifest.Version, baseUrl, result.Cves, result.Kev, result.Epss, result.Signals);
                return Record(new BundleCheck(BundleOutcome.Applied, manifest.Version, Describe(result), DateTime.UtcNow));
            }
            finally { try { File.Delete(zipPath); } catch { } }
        }
        catch (BundleRejectedException ex)
        {
            _log.LogWarning("Bundle refused: {Reason}", ex.Message);
            return Record(new BundleCheck(BundleOutcome.Refused, null, ex.Message, DateTime.UtcNow));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            _log.LogError(ex, "Bundle check failed");
            return Record(new BundleCheck(BundleOutcome.Failed, null, ex.Message, DateTime.UtcNow));
        }
        finally { Progress = null; _gate.Release(); }
    }

    /// <summary>
    /// Air-gap mode: apply a bundle zip somebody carried in. The manifest inside the zip must verify against the trusted
    /// key and be newer than the applied bundle. Records an audit entry for <paramref name="actor"/>.
    /// </summary>
    public async Task<BundleCheck> ApplyUploadedAsync(Stream zip, string actor, CancellationToken ct)
    {
        if (!await _gate.WaitAsync(0, ct))
            return new BundleCheck(BundleOutcome.Skipped, null, "A bundle is already being applied.", DateTime.UtcNow);
        var inbox = Path.Combine(_opt.DataDir, "bundles", "inbox");
        Directory.CreateDirectory(inbox);
        var zipPath = Path.Combine(inbox, "upload-" + Guid.NewGuid().ToString("N") + ".zip");
        try
        {
            Progress = "Receiving upload";
            await using (var dst = File.Create(zipPath)) await zip.CopyToAsync(dst, ct);
            var result = await ApplyZipAsync(zipPath, null, "upload by " + actor, ct);
            _bundleMode = true;
            await AuditAsync(actor, "bundle.upload", result.Version, Describe(result), ct);
            _log.LogInformation("Applied uploaded bundle {Version} ({Actor})", result.Version, actor);
            return Record(new BundleCheck(BundleOutcome.Applied, result.Version, Describe(result), DateTime.UtcNow));
        }
        catch (BundleRejectedException ex)
        {
            await AuditAsync(actor, "bundle.refused", "upload", ex.Message, ct);
            return Record(new BundleCheck(BundleOutcome.Refused, null, ex.Message, DateTime.UtcNow));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            _log.LogError(ex, "Uploaded bundle failed");
            return Record(new BundleCheck(BundleOutcome.Failed, null, ex.Message, DateTime.UtcNow));
        }
        finally
        {
            Progress = null; _gate.Release();
            try { File.Delete(zipPath); } catch { }
        }
    }

    /// <summary>Extract, verify (signature when the manifest was not already verified, then hashes) and apply.</summary>
    private async Task<BundleApplyResult> ApplyZipAsync(string zipPath, BundleManifest? trustedManifest, string source, CancellationToken ct)
    {
        var dir = zipPath + ".extract";
        if (Directory.Exists(dir)) Directory.Delete(dir, true);
        Directory.CreateDirectory(dir);
        try
        {
            Progress = "Extracting bundle";
            using (var archive = ZipFile.OpenRead(zipPath))
            {
                foreach (var entry in archive.Entries)
                {
                    // flat archive only: the six data files plus manifest.json at the root
                    if (entry.FullName.EndsWith('/') || entry.Name.Length == 0) continue;
                    var name = Path.GetFileName(entry.FullName);
                    if (name != BundleFiles.Manifest && !BundleFiles.Required.Contains(name)) continue;
                    entry.ExtractToFile(Path.Combine(dir, name), true);
                }
            }
            var manifest = trustedManifest;
            if (manifest is null)
            {
                var manifestPath = Path.Combine(dir, BundleFiles.Manifest);
                if (!File.Exists(manifestPath)) throw new BundleRejectedException("The file is not a VulnVerdict bundle (no manifest.json).");
                manifest = BundleManifest.Parse(await File.ReadAllTextAsync(manifestPath, ct));
                if (manifest is null || string.IsNullOrEmpty(manifest.Version)) throw new BundleRejectedException("manifest.json could not be read.");
                using var pub = PublicKey();
                if (!manifest.Verify(pub)) throw new BundleRejectedException("Bundle " + manifest.Version + " is unsigned or not signed by the trusted key; refused.");
            }
            await using var db = await _factory.CreateDbContextAsync(ct);
            return await BundleApplier.ApplyAsync(db, manifest, dir, source, ct, msg => Progress = msg);
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    private BundleCheck Record(BundleCheck c) { LastCheck = c; return c; }

    private static string Describe(BundleApplyResult r) =>
        "Applied bundle " + r.Version + ": " + r.Cves.ToString("N0") + " CVEs, " + r.Kev.ToString("N0") + " KEV, " + r.Epss.ToString("N0") + " EPSS, "
        + r.Signals.ToString("N0") + " exploit signals, " + r.AliasesAdded.ToString("N0") + " new aliases, " + r.Narratives.ToString("N0") + " narratives.";

    private async Task AuditAsync(string actor, string action, string target, string detail, CancellationToken ct)
    {
        try
        {
            await using var db = await _factory.CreateDbContextAsync(ct);
            db.Audit.Add(new AuditEntry { At = DateTime.UtcNow, Actor = actor, Action = action, Target = target, After = detail });
            await db.SaveChangesAsync(ct);
        }
        catch (Exception ex) { _log.LogWarning(ex, "Audit entry could not be written"); }
    }
}
