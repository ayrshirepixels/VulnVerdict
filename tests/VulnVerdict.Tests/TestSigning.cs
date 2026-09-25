using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

/// <summary>
/// Test-side issuing of the two things the console verifies: a signed feed bundle and a licence key. The product's
/// issuing side (the central service's bundle builder and licence issuer) is not part of this repository; these
/// helpers produce the same on-disk formats from a seeded in-memory database, with a throwaway key, so the
/// verification and import code can be tested.
/// </summary>
internal static class TestBundleWriter
{
    public const string DefaultSigner = "VulnVerdict Central";
    private static readonly Encoding Utf8NoBom = new UTF8Encoding(false);

    public static async Task<BundleManifest> WriteAsync(VvDbContext db, string outDir, ECDsa privateKey, CancellationToken ct, string signer = DefaultSigner, string? version = null, DateTime? builtAt = null)
    {
        Directory.CreateDirectory(outDir);
        var now = DateTime.SpecifyKind(builtAt ?? DateTime.UtcNow, DateTimeKind.Utc);
        version ??= now.ToString("yyyyMMddHHmm", CultureInfo.InvariantCulture);

        var cves = await db.Cves.AsNoTracking().Include(c => c.Affected).OrderBy(c => c.Id).ToListAsync(ct);
        await File.WriteAllLinesAsync(Path.Combine(outDir, BundleFiles.Cves), cves.Select(c => JsonSerializer.Serialize(BundleCve.From(c), BundleJson.Options)), Utf8NoBom, ct);

        var kev = await db.Kev.AsNoTracking().OrderBy(k => k.CveId).ToListAsync(ct);
        await File.WriteAllTextAsync(Path.Combine(outDir, BundleFiles.Kev), JsonSerializer.Serialize(kev.Select(BundleKev.From).ToList(), BundleJson.Options), Utf8NoBom, ct);

        var epss = await db.Epss.AsNoTracking().OrderBy(e => e.CveId).ToListAsync(ct);
        var csv = new List<string> { "cve,epss,percentile,scoreDate,retrievedAt" };
        csv.AddRange(epss.Select(e => string.Join(',', e.CveId, e.Score.ToString("R", CultureInfo.InvariantCulture), e.Percentile.ToString("R", CultureInfo.InvariantCulture),
            e.ScoreDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), DateTime.SpecifyKind(e.RetrievedAt, DateTimeKind.Utc).ToString("O"))));
        await File.WriteAllLinesAsync(Path.Combine(outDir, BundleFiles.Epss), csv, Utf8NoBom, ct);

        var signals = await db.ExploitSignals.AsNoTracking().OrderBy(s => s.Source).ThenBy(s => s.CveId).ThenBy(s => s.Url).ToListAsync(ct);
        await File.WriteAllLinesAsync(Path.Combine(outDir, BundleFiles.Signals), signals.Select(s => JsonSerializer.Serialize(BundleSignal.From(s), BundleJson.Options)), Utf8NoBom, ct);

        var aliases = await db.Aliases.AsNoTracking().OrderBy(a => a.AliasNorm).ThenBy(a => a.VendorNorm).ThenBy(a => a.ProductNorm).ToListAsync(ct);
        await File.WriteAllTextAsync(Path.Combine(outDir, BundleFiles.Aliases), JsonSerializer.Serialize(aliases.Select(BundleAlias.From).ToList(), BundleJson.Options), Utf8NoBom, ct);

        // only CVE narratives travel; attack stories describe a customer's own asset
        var narratives = await db.Narratives.AsNoTracking().Where(n => n.Key.StartsWith("cve:")).OrderBy(n => n.Key).ToListAsync(ct);
        await File.WriteAllLinesAsync(Path.Combine(outDir, BundleFiles.Narratives), narratives.Select(n => JsonSerializer.Serialize(BundleNarrative.From(n), BundleJson.Options)), Utf8NoBom, ct);

        var manifest = new BundleManifest { Version = version, BuiltAt = now, Signer = signer };
        foreach (var name in BundleFiles.Required)
        {
            var path = Path.Combine(outDir, name);
            manifest.Files.Add(new BundleFile(name, await BundleHash.FileSha256Async(path, ct), new FileInfo(path).Length));
        }
        manifest.Signature = Convert.ToBase64String(privateKey.SignData(Encoding.UTF8.GetBytes(manifest.Canonical()), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        await File.WriteAllTextAsync(Path.Combine(outDir, BundleFiles.Manifest), manifest.ToJson(), Utf8NoBom, ct);
        return manifest;
    }
}

internal static class TestLicence
{
    /// <summary>The key format <see cref="LicenseService.Parse"/> reads: base64url(claims json) "." base64url(signature).</summary>
    public static string Issue(LicenceClaims claims, ECDsa privateKey)
    {
        if (!LicenseService.Tiers.Contains(claims.Tier)) throw new ArgumentException("Tier must be starter, business or msp", nameof(claims));
        var json = JsonSerializer.SerializeToUtf8Bytes(claims, BundleJson.Options);
        var sig = privateKey.SignData(json, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return Base64UrlText.Encode(json) + "." + Base64UrlText.Encode(sig);
    }
}
