using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.Options;

namespace VulnVerdict.Web;

/// <summary>
/// The data-protection key ring opens every stored credential, and it sits in the data volume beside the database
/// and its backups. With a key-ring secret set (VV_KEY_SECRET, kept outside the volume) each key is encrypted at
/// rest, so a copy of the volume or of a backup opens nothing on its own. Without one the keys are stored as before.
/// </summary>
public static class KeyRingProtection
{
    public const string SecretSetting = "KeyProtection:Secret";
    public const string SecretFileSetting = "KeyProtection:SecretFile";
    public const int MinSecretLength = 16;

    private static readonly XNamespace Ns = "http://schemas.asp.net/2015/03/dataProtection";
    private static readonly XName EncryptedSecret = Ns + "encryptedSecret";
    private static readonly XName RequiresEncryption = Ns + "requiresEncryption";
    private const string DecryptorType = "decryptorType";

    /// <summary>What happened at start, logged once the host is built.</summary>
    public static string? StartupNote { get; private set; }
    public static bool Protected { get; private set; }

    /// <summary>The secret from configuration, or from the file a Docker secret is mounted at. Null when neither is set.</summary>
    public static string? ReadSecret(IConfiguration cfg)
    {
        var secret = cfg[SecretSetting];
        var file = cfg[SecretFileSetting];
        if (string.IsNullOrWhiteSpace(secret) && !string.IsNullOrWhiteSpace(file))
        {
            if (!File.Exists(file)) throw new InvalidOperationException("The key-ring secret file " + file + " does not exist.");
            secret = File.ReadAllText(file);
        }
        secret = secret?.Trim();
        if (string.IsNullOrEmpty(secret)) return null;
        if (secret.Length < MinSecretLength) throw new InvalidOperationException("The key-ring secret (VV_KEY_SECRET) must be at least " + MinSecretLength + " characters. Use a long random string.");
        return secret;
    }

    /// <summary>
    /// Call after AddDataProtection. With a secret: new keys are encrypted, keys already on disk are encrypted in
    /// place, and a secret that does not open the existing keys stops the start. Without one: refuses to start if the
    /// keys on disk need a secret, because carrying on would mint a new key and every saved credential would be lost.
    /// </summary>
    public static void Configure(IServiceCollection services, IConfiguration cfg, string keysDir)
    {
        Protected = false; StartupNote = null;
        var secret = ReadSecret(cfg);
        if (secret is null)
        {
            if (AnyProtected(keysDir))
                throw new InvalidOperationException("The encryption keys in " + keysDir + " are protected with a key-ring secret, and none is set. Set VV_KEY_SECRET (KeyProtection__Secret) to the value used before; without it the saved credentials cannot be read.");
            StartupNote = "The encryption keys are stored unprotected in the data folder. Set VV_KEY_SECRET to encrypt them at rest (docs/security.md).";
            return;
        }

        var ring = new KeyRingSecret(secret);
        VerifyOpens(keysDir, ring);
        var wrapped = ProtectExisting(keysDir, ring);
        services.AddSingleton(ring);
        services.AddSingleton<IConfigureOptions<KeyManagementOptions>>(new ConfigureOptions<KeyManagementOptions>(o => o.XmlEncryptor = new SecretXmlEncryptor(ring)));
        Protected = true;
        StartupNote = wrapped > 0 ? "Encrypted " + wrapped + " existing encryption key(s) with the key-ring secret." : null;
    }

    private static IEnumerable<string> KeyFiles(string keysDir) =>
        Directory.Exists(keysDir) ? Directory.EnumerateFiles(keysDir, "key-*.xml") : Array.Empty<string>();

    private static bool IsOurs(XElement e) =>
        e.Name == EncryptedSecret && ((string?)e.Attribute(DecryptorType) ?? "").StartsWith(typeof(SecretXmlDecryptor).FullName + ",", StringComparison.Ordinal);

    private static bool AnyProtected(string keysDir) =>
        KeyFiles(keysDir).Any(f => { try { return XDocument.Load(f).Descendants().Any(IsOurs); } catch (System.Xml.XmlException) { return false; } });

    /// <summary>A wrong secret must stop the start, not quietly start a new key ring.</summary>
    private static void VerifyOpens(string keysDir, KeyRingSecret ring)
    {
        foreach (var file in KeyFiles(keysDir))
        {
            XElement? ours;
            try { ours = XDocument.Load(file).Descendants().FirstOrDefault(IsOurs); } catch (System.Xml.XmlException) { continue; }
            if (ours?.Elements().FirstOrDefault() is not { } encrypted) continue;
            try { ring.Decrypt(encrypted); }
            catch (CryptographicException)
            {
                throw new InvalidOperationException("The key-ring secret (VV_KEY_SECRET) does not open the encryption keys in " + keysDir + ". Set it to the value used before; with a different one the saved credentials cannot be read.");
            }
        }
    }

    /// <summary>
    /// Encrypt keys written before a secret was set, the way the framework would have: each element marked as
    /// needing encryption becomes an encryptedSecret naming our decryptor. Written to a temporary file and renamed, so
    /// the console and the worker starting together cannot leave half a key. Returns how many files changed.
    /// </summary>
    public static int ProtectExisting(string keysDir, KeyRingSecret ring)
    {
        var encryptor = new SecretXmlEncryptor(ring);
        var changed = 0;
        foreach (var file in KeyFiles(keysDir))
        {
            XDocument doc;
            try { doc = XDocument.Load(file); } catch (System.Xml.XmlException) { continue; }
            // only keys stored in the clear: one already wrapped (by us or anything else) is left as it is
            if (doc.Descendants(EncryptedSecret).Any()) continue;
            var open = doc.Descendants().Where(e => (bool?)e.Attribute(RequiresEncryption) == true).ToList();
            if (open.Count == 0) continue;
            foreach (var element in open)
            {
                var info = encryptor.Encrypt(new XElement(element));
                element.ReplaceWith(new XElement(EncryptedSecret, new XAttribute(DecryptorType, info.DecryptorType.AssemblyQualifiedName!), info.EncryptedElement));
            }
            var temp = file + "." + Guid.NewGuid().ToString("N") + ".tmp";
            doc.Save(temp);
            File.Move(temp, file, overwrite: true);
            changed++;
        }
        return changed;
    }
}

/// <summary>The key that wraps the key ring, derived per element from the configured secret.</summary>
public sealed class KeyRingSecret
{
    private const int SaltBytes = 16, NonceBytes = 12, TagBytes = 16, Iterations = 100_000;
    private readonly byte[] _secret;

    public KeyRingSecret(string secret) => _secret = Encoding.UTF8.GetBytes(secret);

    private byte[] Derive(byte[] salt) => Rfc2898DeriveBytes.Pbkdf2(_secret, salt, Iterations, HashAlgorithmName.SHA256, 32);

    /// <summary>AES-256-GCM. Output: salt, nonce, tag, ciphertext.</summary>
    public XElement Encrypt(XElement plaintext)
    {
        var plain = Encoding.UTF8.GetBytes(plaintext.ToString(SaveOptions.DisableFormatting));
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
        var tag = new byte[TagBytes];
        var cipher = new byte[plain.Length];
        using (var aes = new AesGcm(Derive(salt), TagBytes)) aes.Encrypt(nonce, plain, cipher, tag);
        CryptographicOperations.ZeroMemory(plain);
        return new XElement("encryptedKey",
            new XComment(" This key is encrypted with the key-ring secret (VV_KEY_SECRET). "),
            new XElement("value", Convert.ToBase64String(salt.Concat(nonce).Concat(tag).Concat(cipher).ToArray())));
    }

    /// <summary>Throws <see cref="CryptographicException"/> when the secret is not the one the element was encrypted with.</summary>
    public XElement Decrypt(XElement encrypted)
    {
        byte[] blob;
        try { blob = Convert.FromBase64String((string?)encrypted.Element("value") ?? ""); }
        catch (FormatException) { throw new CryptographicException("The encrypted key is not readable."); }
        if (blob.Length < SaltBytes + NonceBytes + TagBytes) throw new CryptographicException("The encrypted key is not readable.");
        var salt = blob.AsSpan(0, SaltBytes).ToArray();
        var nonce = blob.AsSpan(SaltBytes, NonceBytes);
        var tag = blob.AsSpan(SaltBytes + NonceBytes, TagBytes);
        var cipher = blob.AsSpan(SaltBytes + NonceBytes + TagBytes);
        var plain = new byte[cipher.Length];
        using (var aes = new AesGcm(Derive(salt), TagBytes)) aes.Decrypt(nonce, cipher, tag, plain);
        var element = XElement.Parse(Encoding.UTF8.GetString(plain));
        CryptographicOperations.ZeroMemory(plain);
        return element;
    }
}

public sealed class SecretXmlEncryptor : IXmlEncryptor
{
    private readonly KeyRingSecret _ring;
    public SecretXmlEncryptor(KeyRingSecret ring) => _ring = ring;
    public EncryptedXmlInfo Encrypt(XElement plaintextElement) => new(_ring.Encrypt(plaintextElement), typeof(SecretXmlDecryptor));
}

/// <summary>Named in each encrypted key file; the framework creates it with the service provider when it reads the ring.</summary>
public sealed class SecretXmlDecryptor : IXmlDecryptor
{
    private readonly KeyRingSecret _ring;
    public SecretXmlDecryptor(IServiceProvider services) =>
        _ring = services.GetService<KeyRingSecret>() ?? throw new InvalidOperationException("This encryption key is protected with a key-ring secret, and none is set. Set VV_KEY_SECRET (KeyProtection__Secret).");
    public XElement Decrypt(XElement encryptedElement) => _ring.Decrypt(encryptedElement);
}
