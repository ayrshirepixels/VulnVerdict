using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using VulnVerdict.Web;

namespace VulnVerdict.Tests;

public class KeyRingProtectionTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "vv-keys-" + Guid.NewGuid().ToString("N"));
    private const string Secret = "a-long-random-key-ring-secret-0123456789";

    public void Dispose() { try { Directory.Delete(_dir, true); } catch { } }

    private IDataProtector Protector(string? secret)
    {
        var cfg = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?> { [KeyRingProtection.SecretSetting] = secret }).Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection().PersistKeysToFileSystem(new DirectoryInfo(_dir)).SetApplicationName("VulnVerdict");
        KeyRingProtection.Configure(services, cfg, _dir);
        return services.BuildServiceProvider().GetRequiredService<IDataProtectionProvider>().CreateProtector("test");
    }

    private string KeyFileText() => string.Concat(Directory.GetFiles(_dir, "key-*.xml").Select(File.ReadAllText));

    [Fact]
    public void A_new_key_is_encrypted_at_rest_and_still_opens_what_it_protected()
    {
        var sealedText = Protector(Secret).Protect("connector password");
        Assert.DoesNotContain("requiresEncryption", KeyFileText());
        Assert.Contains("SecretXmlDecryptor", KeyFileText());
        Assert.Equal("connector password", Protector(Secret).Unprotect(sealedText));
    }

    [Fact]
    public void Keys_written_before_a_secret_was_set_are_encrypted_in_place_and_keep_working()
    {
        var sealedText = Protector(null).Protect("connector password");
        Assert.Contains("requiresEncryption", KeyFileText());   // stored in the clear, as before
        Assert.False(KeyRingProtection.Protected);

        var after = Protector(Secret);
        Assert.DoesNotContain("requiresEncryption", KeyFileText());
        Assert.Single(Directory.GetFiles(_dir, "key-*.xml"));   // the same key, not a new one
        Assert.Empty(Directory.GetFiles(_dir, "*.tmp"));
        Assert.Equal("connector password", after.Unprotect(sealedText));
        Assert.Equal("connector password", Protector(Secret).Unprotect(sealedText)); // and again: already wrapped, left alone
    }

    [Fact]
    public void A_missing_or_different_secret_stops_the_start_instead_of_starting_a_new_key_ring()
    {
        Protector(Secret).Protect("x");
        var missing = Assert.Throws<InvalidOperationException>(() => Protector(null));
        Assert.Contains("VV_KEY_SECRET", missing.Message);
        var wrong = Assert.Throws<InvalidOperationException>(() => Protector("another-secret-of-the-right-length"));
        Assert.Contains("does not open", wrong.Message);
        Assert.Single(Directory.GetFiles(_dir, "key-*.xml"));
    }

    [Fact]
    public void The_decryptor_keeps_the_name_that_key_files_on_existing_installs_refer_to()
    {
        Assert.StartsWith("VulnVerdict.Web.SecretXmlDecryptor, VulnVerdict.Web,", typeof(SecretXmlDecryptor).AssemblyQualifiedName);
    }

    [Fact]
    public void A_short_secret_is_refused()
    {
        Assert.Throws<InvalidOperationException>(() => Protector("short"));
    }
}
