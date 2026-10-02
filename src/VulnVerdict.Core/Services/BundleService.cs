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
/// The console side of signed feed bundles. Polls the central service for the latest signed bundle (hourly, from the worker loop),
/// verifies the manifest signature against the embedded public key, refuses unsigned or downgraded bundles, verifies
/// every file hash and applies the bundle locally. Also applies an uploaded bundle file for air-gapped sites.
/// The customer's inventory never leaves the network: this service only ever downloads.
/// </summary>
public sealed class BundleService
{
    /// <summary>
    /// Public half of the production signing key (ECDSA P-256, from release 1.1.0). Feed bundles and licence keys are
    /// accepted only when signed by the matching private key, which lives on the central service and nowhere public.
    /// </summary>
    public const string PublicKeyPem = """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMl9NpZjjxcyperZiwjRrfENfqr3o
        4jCRuvcKzfWd1YMOT2obF0sOghuNC88JTkx2/isL/Qru8GUf2eNPD9WwPg==
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
                    if (await CopyCappedAsync(src, dst, MaxZipBytes, null, ct) < 0) throw new BundleRejectedException("Bundle " + manifest.Version + " is larger than " + (MaxZipBytes >> 30) + " GB; refused.");
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
            await using (var dst = File.Create(zipPath))
                if (await CopyCappedAsync(zip, dst, MaxZipBytes, null, ct) < 0) throw new BundleRejectedException("The file is larger than " + (MaxZipBytes >> 30) + " GB, which no bundle is; refused.");
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
            Progress = "Verifying and extracting bundle";
            BundleManifest manifest;
            using (var pub = PublicKey()) manifest = await ExtractVerifiedAsync(zipPath, dir, trustedManifest, pub, ct);
            await using var db = await _factory.CreateDbContextAsync(ct);
            return await BundleApplier.ApplyAsync(db, manifest, dir, source, ct, msg => Progress = msg);
        }
        finally { try { Directory.Delete(dir, true); } catch { } }
    }

    /// <summary>
    /// Nothing is written to disk on the zip's own say-so. The manifest is read first (a small file, capped) and its
    /// signature checked; only then is each file the signed manifest lists extracted, stopping at the signed size and
    /// hashed as it is written. A zip holding anything the manifest does not list, a file larger than its signed size
    /// (a zip bomb) or a file whose hash differs is refused. With <paramref name="trustedManifest"/> (already verified,
    /// from the central service) the zip's own manifest.json is ignored.
    /// </summary>
    public static async Task<BundleManifest> ExtractVerifiedAsync(string zipPath, string dir, BundleManifest? trustedManifest, ECDsa publicKey, CancellationToken ct)
    {
        ZipArchive archive;
        try { archive = ZipFile.OpenRead(zipPath); }
        catch (InvalidDataException) { throw new BundleRejectedException("The file is not a VulnVerdict bundle (not a zip archive)."); }
        using (archive)
        {
            if (archive.Entries.Count > MaxZipEntries) throw new BundleRejectedException("The file is not a VulnVerdict bundle (too many entries).");
            var manifest = trustedManifest;
            if (manifest is null)
            {
                var entries = archive.Entries.Where(e => e.FullName == BundleFiles.Manifest).ToList();
                if (entries.Count != 1) throw new BundleRejectedException("The file is not a VulnVerdict bundle (no manifest.json).");
                using var buffer = new MemoryStream();
                await using (var src = entries[0].Open())
                    if (await CopyCappedAsync(src, buffer, MaxManifestBytes, null, ct) < 0) throw new BundleRejectedException("manifest.json is too large to be a bundle manifest.");
                manifest = BundleManifest.Parse(System.Text.Encoding.UTF8.GetString(buffer.ToArray()));
                if (manifest is null || string.IsNullOrEmpty(manifest.Version)) throw new BundleRejectedException("manifest.json could not be read.");
                if (!manifest.Verify(publicKey)) throw new BundleRejectedException("Bundle " + manifest.Version + " is unsigned or not signed by the trusted key; refused.");
            }

            // from here on the manifest is trusted: its names, sizes and hashes decide what may be written
            var listed = manifest.Files.ToDictionary(f => f.Name, StringComparer.Ordinal);
            if (listed.Keys.FirstOrDefault(n => !BundleFiles.Required.Contains(n)) is { } unknown) throw new BundleRejectedException("Manifest entry '" + unknown + "' is not a bundle file.");
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var entry in archive.Entries)
            {
                if (entry.FullName == BundleFiles.Manifest) continue;
                if (!listed.TryGetValue(entry.FullName, out var file)) throw new BundleRejectedException("The bundle holds '" + (entry.FullName.Length > 80 ? entry.FullName[..80] : entry.FullName) + "', which its manifest does not list; refused.");
                if (!seen.Add(file.Name)) throw new BundleRejectedException("The bundle holds " + file.Name + " twice; refused.");
                if (entry.Length != file.Bytes) throw new BundleRejectedException(file.Name + " is " + entry.Length + " bytes, manifest says " + file.Bytes);
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                await using (var src = entry.Open())
                await using (var dst = File.Create(Path.Combine(dir, file.Name)))
                    // the size in the zip's directory is the zip's claim; the copy itself stops at the signed size
                    if (await CopyCappedAsync(src, dst, file.Bytes, hash, ct) != file.Bytes) throw new BundleRejectedException(file.Name + " does not have the size its manifest states; refused.");
                if (!Convert.ToHexStringLower(hash.GetHashAndReset()).Equals(file.Sha256, StringComparison.OrdinalIgnoreCase))
                    throw new BundleRejectedException(file.Name + " does not match its manifest hash (tampered or corrupt)");
            }
            return manifest;
        }
    }

    /// <summary>The largest bundle zip accepted, uploaded or downloaded. A full bundle is a few hundred megabytes.</summary>
    public const long MaxZipBytes = 2L << 30;
    private const int MaxManifestBytes = 1 << 20;
    private const int MaxZipEntries = 64;

    /// <summary>Copy at most <paramref name="cap"/> bytes. Returns the bytes copied, or -1 if the source held more.</summary>
    private static async Task<long> CopyCappedAsync(Stream src, Stream dst, long cap, IncrementalHash? hash, CancellationToken ct)
    {
        var buf = new byte[81920];
        long total = 0;
        int n;
        while ((n = await src.ReadAsync(buf, ct)) > 0)
        {
            total += n;
            if (total > cap) return -1;
            hash?.AppendData(buf, 0, n);
            await dst.WriteAsync(buf.AsMemory(0, n), ct);
        }
        return total;
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
