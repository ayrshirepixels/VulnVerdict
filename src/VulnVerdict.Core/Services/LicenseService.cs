using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;

namespace VulnVerdict.Core.Services;

/// <summary>What a licence key says. Serialised (camelCase JSON) as the first segment of the key.</summary>
public sealed class LicenceClaims
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Customer { get; set; } = "";
    /// <summary>starter | business | msp</summary>
    public string Tier { get; set; } = "starter";
    /// <summary>0 means no cap (MSP per-client keys carry the client's cap explicitly).</summary>
    public int AssetCap { get; set; }
    public DateTime IssuedAt { get; set; } = DateTime.UtcNow;
    public DateTime Expires { get; set; }
    /// <summary>MSP keys: the token the client console uses to post verdict summaries to the MSP portal.</summary>
    public string? TenantToken { get; set; }
}

public sealed record LicenseInfo(bool Present, bool Valid, string? Customer, string? Tier, int? AssetCap, DateTime? Expires, string? TenantToken, string Reason)
{
    public static readonly LicenseInfo Unlicensed = new(false, false, null, null, null, null, null, "Community (unlicensed): no asset cap, no central service.");
    /// <summary>Genuine key whose expiry date has passed (as of the time it was parsed).</summary>
    public bool Expired { get; init; }
    public string TierName => Tier switch { "starter" => "Starter", "business" => "Business", "msp" => "MSP", null => "Community", var t => t };
    /// <summary>Cap to enforce: the parsed cap when the signature is genuine (even if expired), otherwise none.</summary>
    public int? EnforcedCap => AssetCap is > 0 ? AssetCap : null;
}

/// <summary>
/// Licence keys and tiers: Starter up to 50 assets, Business up to 250, MSP per client. A key is
/// base64url(claims JSON) "." base64url(ECDSA P-256 signature over the claims JSON bytes), signed by the central
/// service and verified with the same embedded public key as the feed bundle. No key at all is the internal build.
/// </summary>
public sealed class LicenseService
{
    public const string Starter = "starter";
    public const string Business = "business";
    public const string Msp = "msp";
    public static readonly string[] Tiers = { Starter, Business, Msp };

    private readonly IDbContextFactory<VvDbContext> _factory;
    private readonly SettingsService _settings;

    public LicenseService(IDbContextFactory<VvDbContext> factory, SettingsService settings) { _factory = factory; _settings = settings; }

    public static int DefaultCap(string tier) => tier switch { Starter => 50, Business => 250, _ => 0 };

    /// <summary>Parse and verify a key. Never throws: an unreadable or tampered key comes back with Valid = false and a reason.</summary>
    public static LicenseInfo Parse(string? key, ECDsa publicKey, DateTime now)
    {
        if (string.IsNullOrWhiteSpace(key)) return LicenseInfo.Unlicensed;
        key = key.Trim();
        var dot = key.IndexOf('.');
        if (dot <= 0 || dot == key.Length - 1) return new LicenseInfo(true, false, null, null, null, null, null, "The licence key is not in the expected format.");
        byte[] json, sig;
        try { json = Base64UrlText.Decode(key[..dot]); sig = Base64UrlText.Decode(key[(dot + 1)..]); }
        catch { return new LicenseInfo(true, false, null, null, null, null, null, "The licence key could not be decoded."); }
        bool genuine;
        try { genuine = publicKey.VerifyData(json, sig, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
        catch { genuine = false; }
        if (!genuine) return new LicenseInfo(true, false, null, null, null, null, null, "The licence key signature is invalid (tampered or issued by another vendor).");
        LicenceClaims? c;
        try { c = JsonSerializer.Deserialize<LicenceClaims>(json, BundleJson.Options); } catch { c = null; }
        if (c is null || string.IsNullOrWhiteSpace(c.Customer) || !Tiers.Contains(c.Tier))
            return new LicenseInfo(true, false, null, null, null, null, null, "The licence key claims are incomplete.");
        var expires = DateTime.SpecifyKind(c.Expires, DateTimeKind.Utc);
        var cap = c.AssetCap > 0 ? c.AssetCap : (int?)null;
        if (expires < now)
            return new LicenseInfo(true, false, c.Customer, c.Tier, cap, expires, c.TenantToken, "The licence expired on " + expires.ToString("d MMM yyyy") + ". Contact your vendor for a renewal.") { Expired = true };
        return new LicenseInfo(true, true, c.Customer, c.Tier, cap, expires, c.TenantToken,
            (c.Tier == Msp ? "MSP client licence" : c.Tier == Business ? "Business" : "Starter") + " for " + c.Customer + (cap is null ? ", no asset cap" : ", up to " + cap + " assets") + ", valid until " + expires.ToString("d MMM yyyy") + ".");
    }

    public static LicenseInfo Parse(string? key)
    {
        using var pub = BundleService.PublicKey();
        return Parse(key, pub, DateTime.UtcNow);
    }

    /// <summary>The licence currently saved in Settings.</summary>
    public async Task<LicenseInfo> GetAsync(CancellationToken ct = default)
    {
        var s = await _settings.LoadAsync(ct);
        return Parse(s.LicenceKey);
    }

    public async Task<int> AssetCountAsync(CancellationToken ct = default)
    {
        await using var db = await _factory.CreateDbContextAsync(ct);
        return await db.Assets.CountAsync(a => !a.Archived, ct);
    }

    /// <summary>
    /// True when the non-archived asset count is within the licensed cap. The internal build (no key) and keys without a
    /// cap never block. A genuine but expired key still enforces its cap; a tampered key is treated as no key.
    /// </summary>
    public async Task<bool> WithinAssetCapAsync(CancellationToken ct = default)
    {
        var l = await GetAsync(ct);
        if (l.EnforcedCap is not { } cap) return true;
        return await AssetCountAsync(ct) <= cap;
    }
}
