using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using VulnVerdict.Core.Data;
using VulnVerdict.Core.Services;

namespace VulnVerdict.Tests;

/// <summary>An uploaded bundle is verified before anything is extracted, and extraction never writes more than the signed manifest allows.</summary>
public class BundleUploadTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "vv-upload-" + Guid.NewGuid().ToString("N"));
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _pub = ECDsa.Create();
    private readonly string _bundle, _extract;
    private BundleManifest _manifest = new();

    public BundleUploadTests()
    {
        _bundle = Path.Combine(_dir, "bundle");
        _extract = Path.Combine(_dir, "extract");
        Directory.CreateDirectory(_extract);
        _pub.ImportFromPem(_key.ExportSubjectPublicKeyInfoPem());
    }

    public void Dispose()
    {
        _key.Dispose(); _pub.Dispose();
        try { Directory.Delete(_dir, true); } catch { }
    }

    /// <summary>A small signed bundle on disk, as the central service would build it.</summary>
    private async Task WriteBundleAsync()
    {
        using var conn = new SqliteConnection("Data Source=:memory:");
        conn.Open();
        await using var db = new VvDbContext(new DbContextOptionsBuilder<VvDbContext>().UseSqlite(conn).Options);
        db.Database.EnsureCreated();
        db.Cves.Add(new Cve { Id = "CVE-2026-0001", State = "PUBLISHED", Title = "FortiOS SSL-VPN overflow", RetrievedAt = DateTime.UtcNow });
        await db.SaveChangesAsync();
        _manifest = await TestBundleWriter.WriteAsync(db, _bundle, _key, CancellationToken.None, version: "202609240800");
    }

    private string Zip(Action<ZipArchive> build)
    {
        var path = Path.Combine(_dir, Guid.NewGuid().ToString("N") + ".zip");
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        build(zip);
        return path;
    }

    private void AddBundleFiles(ZipArchive zip, params string[] except)
    {
        foreach (var f in Directory.GetFiles(_bundle))
            if (!except.Contains(Path.GetFileName(f))) zip.CreateEntryFromFile(f, Path.GetFileName(f));
    }

    private static void AddEntry(ZipArchive zip, string name, byte[] content)
    {
        using var s = zip.CreateEntry(name, CompressionLevel.Optimal).Open();
        s.Write(content);
    }

    private Task<BundleManifest> ExtractAsync(string zip) => BundleService.ExtractVerifiedAsync(zip, _extract, null, _pub, CancellationToken.None);

    private long ExtractedBytes() => Directory.GetFiles(_extract).Sum(f => new FileInfo(f).Length);

    [Fact]
    public async Task A_genuine_bundle_is_extracted_and_matches_its_manifest()
    {
        await WriteBundleAsync();
        var manifest = await ExtractAsync(Zip(z => AddBundleFiles(z)));
        Assert.Equal("202609240800", manifest.Version);
        Assert.Equal(BundleFiles.Required.OrderBy(n => n), Directory.GetFiles(_extract).Select(Path.GetFileName).OrderBy(n => n));
        Assert.Null(await BundleApplier.VerifyFilesAsync(manifest, _extract, CancellationToken.None));
    }

    [Fact]
    public async Task An_unsigned_zip_is_refused_before_anything_is_written()
    {
        await WriteBundleAsync();
        // signed by somebody else, and stuffed with a file that would unpack to 64 MB
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var forged = BundleManifest.Parse(_manifest.ToJson())!;
        forged.Signature = Convert.ToBase64String(other.SignData(Encoding.UTF8.GetBytes(forged.Canonical()), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        var zip = Zip(z =>
        {
            AddBundleFiles(z, BundleFiles.Manifest, BundleFiles.Cves);
            AddEntry(z, BundleFiles.Manifest, Encoding.UTF8.GetBytes(forged.ToJson()));
            AddEntry(z, BundleFiles.Cves, new byte[64 << 20]);
        });
        Assert.True(new FileInfo(zip).Length < 1 << 20);

        var ex = await Assert.ThrowsAsync<BundleRejectedException>(() => ExtractAsync(zip));
        Assert.Contains("not signed by the trusted key", ex.Message);
        Assert.Empty(Directory.GetFiles(_extract));
    }

    [Fact]
    public async Task A_zip_bomb_under_a_genuine_manifest_is_refused()
    {
        await WriteBundleAsync();
        // the signed manifest is genuine; the file it names has been swapped for 64 MB of zeros that compress to nothing
        var zip = Zip(z =>
        {
            AddBundleFiles(z, BundleFiles.Cves);
            AddEntry(z, BundleFiles.Cves, new byte[64 << 20]);
        });
        var ex = await Assert.ThrowsAsync<BundleRejectedException>(() => ExtractAsync(zip));
        Assert.Contains(BundleFiles.Cves, ex.Message);
        Assert.Contains("manifest says", ex.Message);
        Assert.True(ExtractedBytes() <= _manifest.Files.Sum(f => f.Bytes));
    }

    [Fact]
    public async Task An_entry_that_lies_about_its_size_stops_at_the_signed_size()
    {
        await WriteBundleAsync();
        var signed = _manifest.Files.Single(f => f.Name == BundleFiles.Cves).Bytes;
        var zip = Zip(z =>
        {
            AddBundleFiles(z, BundleFiles.Cves);
            AddEntry(z, BundleFiles.Cves, new byte[64 << 20]);
        });
        // rewrite the size the zip claims for the entry to the signed size, so only the copy itself can catch it
        PatchUncompressedSize(zip, BundleFiles.Cves, (uint)signed);
        using (var check = ZipFile.OpenRead(zip)) Assert.Equal(signed, check.GetEntry(BundleFiles.Cves)!.Length);

        var ex = await Assert.ThrowsAsync<BundleRejectedException>(() => ExtractAsync(zip));
        Assert.Contains(BundleFiles.Cves, ex.Message);
        // the copy stopped: at most the signed size (plus one read buffer never written) reached the disk
        var written = new FileInfo(Path.Combine(_extract, BundleFiles.Cves));
        Assert.True(!written.Exists || written.Length <= signed);
    }

    [Theory]
    [InlineData("install.sh")]
    [InlineData("../../keys/evil.xml")]
    [InlineData("nested/cves.jsonl")]
    public async Task An_entry_the_manifest_does_not_list_is_refused(string name)
    {
        await WriteBundleAsync();
        var zip = Zip(z =>
        {
            AddBundleFiles(z);
            AddEntry(z, name, Encoding.UTF8.GetBytes("unexpected"));
        });
        var ex = await Assert.ThrowsAsync<BundleRejectedException>(() => ExtractAsync(zip));
        Assert.Contains("does not list", ex.Message);
        Assert.Empty(Directory.GetFiles(_dir, "evil.xml", SearchOption.AllDirectories));
        Assert.Empty(Directory.GetFiles(_extract, "*.sh"));
    }

    [Fact]
    public async Task A_changed_file_of_the_right_size_fails_its_hash()
    {
        await WriteBundleAsync();
        var kev = await File.ReadAllBytesAsync(Path.Combine(_bundle, BundleFiles.Kev));
        kev[0] ^= 1;
        var zip = Zip(z =>
        {
            AddBundleFiles(z, BundleFiles.Kev);
            AddEntry(z, BundleFiles.Kev, kev);
        });
        var ex = await Assert.ThrowsAsync<BundleRejectedException>(() => ExtractAsync(zip));
        Assert.Contains("does not match its manifest hash", ex.Message);
    }

    [Fact]
    public async Task A_file_that_is_not_a_bundle_is_refused()
    {
        await WriteBundleAsync();
        var notZip = Path.Combine(_dir, "notes.zip");
        await File.WriteAllTextAsync(notZip, "this is not a zip archive");
        Assert.Contains("not a zip", (await Assert.ThrowsAsync<BundleRejectedException>(() => ExtractAsync(notZip))).Message);

        var noManifest = Zip(z => AddBundleFiles(z, BundleFiles.Manifest));
        Assert.Contains("no manifest.json", (await Assert.ThrowsAsync<BundleRejectedException>(() => ExtractAsync(noManifest))).Message);

        // a manifest.json far larger than any manifest is not read into memory
        var hugeManifest = Zip(z => AddEntry(z, BundleFiles.Manifest, new byte[8 << 20]));
        Assert.Contains("too large", (await Assert.ThrowsAsync<BundleRejectedException>(() => ExtractAsync(hugeManifest))).Message);

        var twice = Zip(z =>
        {
            AddBundleFiles(z);
            z.CreateEntryFromFile(Path.Combine(_bundle, BundleFiles.Kev), BundleFiles.Kev);
        });
        Assert.Contains("twice", (await Assert.ThrowsAsync<BundleRejectedException>(() => ExtractAsync(twice))).Message);
        Assert.True(BundleService.MaxZipBytes <= 2L << 30);
    }

    /// <summary>Overwrite the uncompressed-size field of one entry in the zip's central directory and local header.</summary>
    private static void PatchUncompressedSize(string zipPath, string entryName, uint size)
    {
        var bytes = File.ReadAllBytes(zipPath);
        var name = Encoding.UTF8.GetBytes(entryName);
        var patched = 0;
        for (var i = 0; i + 46 < bytes.Length; i++)
        {
            var sig = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(i));
            // central directory header: size at 24, name length at 28, name at 46. Local header: size at 22, name length at 26, name at 30.
            var (sizeAt, lenAt, nameAt) = sig == 0x02014b50 ? (24, 28, 46) : sig == 0x04034b50 ? (22, 26, 30) : (0, 0, 0);
            if (sizeAt == 0 || BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(i + lenAt)) != name.Length) continue;
            if (i + nameAt + name.Length > bytes.Length || !bytes.AsSpan(i + nameAt, name.Length).SequenceEqual(name)) continue;
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(i + sizeAt), size);
            patched++;
        }
        Assert.True(patched >= 1, "entry not found in the zip");
        File.WriteAllBytes(zipPath, bytes);
    }
}
