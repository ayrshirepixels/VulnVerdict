using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace VulnVerdict.Core.Services;

/// <summary>
/// Optional passphrase encryption of a backup archive. AES-256-GCM in chunks, with the key derived from the passphrase
/// by PBKDF2-HMAC-SHA256. The file is:
///
///   header (39 bytes): "VVBAK1" | version 1 | kdf 1 (PBKDF2-SHA256) | iterations (uint32 BE) | salt (16) | nonce prefix (7) | chunk size (uint32 BE)
///   frames:            final flag (1 byte, 0 or 1) | plaintext length (uint32 BE) | ciphertext | tag (16)
///
/// Each frame's nonce is prefix | frame counter (uint32 BE) | final flag, and the header is the associated data of
/// every frame, so frames cannot be reordered, dropped, or the file cut short without the tag check failing: the last
/// frame is the only one whose nonce carries the final flag. A wrong passphrase fails on the first frame.
/// </summary>
public static class BackupCrypto
{
    public const int DefaultIterations = 600_000;
    public const int ChunkSize = 1 << 20;
    public const int HeaderLength = 39;
    private const int TagLength = 16;
    private const uint MaxChunk = 16 << 20;
    private static readonly byte[] Magic = "VVBAK1"u8.ToArray();

    /// <summary>True when the stream's first bytes are the encrypted-backup header. Leaves a seekable stream where it was.</summary>
    public static bool IsEncrypted(Stream s)
    {
        var start = s.Position;
        var buf = new byte[Magic.Length];
        var n = s.ReadAtLeast(buf, buf.Length, throwOnEndOfStream: false);
        s.Position = start;
        return n == buf.Length && buf.AsSpan().SequenceEqual(Magic);
    }

    public static bool IsEncryptedFile(string path)
    {
        using var fs = File.OpenRead(path);
        return IsEncrypted(fs);
    }

    private static byte[] DeriveKey(string passphrase, ReadOnlySpan<byte> salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(passphrase), salt, iterations, HashAlgorithmName.SHA256, 32);

    private static void Nonce(Span<byte> nonce, ReadOnlySpan<byte> prefix, uint counter, bool final)
    {
        prefix.CopyTo(nonce);
        BinaryPrimitives.WriteUInt32BigEndian(nonce[7..], counter);
        nonce[11] = final ? (byte)1 : (byte)0;
    }

    /// <summary>Write-only stream: what is written comes out encrypted on <paramref name="inner"/>. Call <see cref="Complete"/> before disposing, or the file has no final frame and will not decrypt.</summary>
    public sealed class EncryptingStream : Stream
    {
        private readonly Stream _inner;
        private readonly AesGcm _aes;
        private readonly byte[] _header = new byte[HeaderLength];
        private readonly byte[] _buffer = new byte[ChunkSize];
        private readonly byte[] _cipher = new byte[ChunkSize];
        private int _filled;
        private uint _counter;
        private bool _completed;

        public EncryptingStream(Stream inner, string passphrase, int iterations = DefaultIterations)
        {
            if (string.IsNullOrEmpty(passphrase)) throw new ArgumentException("A passphrase is required", nameof(passphrase));
            _inner = inner;
            Magic.CopyTo(_header, 0);
            _header[6] = 1; _header[7] = 1;
            BinaryPrimitives.WriteUInt32BigEndian(_header.AsSpan(8), (uint)iterations);
            RandomNumberGenerator.Fill(_header.AsSpan(12, 16));
            RandomNumberGenerator.Fill(_header.AsSpan(28, 7));
            BinaryPrimitives.WriteUInt32BigEndian(_header.AsSpan(35), ChunkSize);
            _aes = new AesGcm(DeriveKey(passphrase, _header.AsSpan(12, 16), iterations), TagLength);
            _inner.Write(_header);
        }

        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> data)
        {
            if (_completed) throw new InvalidOperationException("The stream is complete");
            while (data.Length > 0)
            {
                // a full buffer is only written out when more data follows, so the last frame is never empty by accident
                if (_filled == ChunkSize) Frame(false);
                var n = Math.Min(data.Length, ChunkSize - _filled);
                data[..n].CopyTo(_buffer.AsSpan(_filled));
                _filled += n; data = data[n..];
            }
        }

        private void Frame(bool final)
        {
            Span<byte> nonce = stackalloc byte[12];
            Span<byte> tag = stackalloc byte[TagLength];
            Span<byte> head = stackalloc byte[5];
            Nonce(nonce, _header.AsSpan(28, 7), _counter++, final);
            _aes.Encrypt(nonce, _buffer.AsSpan(0, _filled), _cipher.AsSpan(0, _filled), tag, _header);
            head[0] = final ? (byte)1 : (byte)0;
            BinaryPrimitives.WriteUInt32BigEndian(head[1..], (uint)_filled);
            _inner.Write(head);
            _inner.Write(_cipher, 0, _filled);
            _inner.Write(tag);
            _filled = 0;
        }

        /// <summary>Write the final frame. Nothing can be written afterwards.</summary>
        public void Complete()
        {
            if (_completed) return;
            Frame(true);
            _completed = true;
            _inner.Flush();
        }

        public override void Flush() { }
        protected override void Dispose(bool disposing) { if (disposing) _aes.Dispose(); base.Dispose(disposing); }
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }

    /// <summary>Read-only stream over an encrypted backup. Throws <see cref="CryptographicException"/> on a wrong passphrase, a damaged file or a file cut short.</summary>
    public sealed class DecryptingStream : Stream
    {
        private readonly Stream _inner;
        private readonly AesGcm _aes;
        private readonly byte[] _header = new byte[HeaderLength];
        private readonly uint _chunk;
        private byte[] _plain = Array.Empty<byte>();
        private int _pos, _len;
        private uint _counter;
        private bool _final;

        public DecryptingStream(Stream inner, string passphrase)
        {
            _inner = inner;
            if (inner.ReadAtLeast(_header, HeaderLength, throwOnEndOfStream: false) != HeaderLength || !_header.AsSpan(0, 6).SequenceEqual(Magic))
                throw new CryptographicException("Not an encrypted VulnVerdict backup.");
            if (_header[6] != 1 || _header[7] != 1) throw new CryptographicException("This backup was encrypted by a newer version of VulnVerdict.");
            var iterations = BinaryPrimitives.ReadUInt32BigEndian(_header.AsSpan(8));
            _chunk = BinaryPrimitives.ReadUInt32BigEndian(_header.AsSpan(35));
            if (iterations is < 1 or > 50_000_000 || _chunk is 0 or > MaxChunk) throw new CryptographicException("The backup header is damaged.");
            _aes = new AesGcm(DeriveKey(passphrase ?? "", _header.AsSpan(12, 16), (int)iterations), TagLength);
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            while (_pos == _len)
            {
                if (_final) return 0;
                NextFrame();
            }
            var n = Math.Min(buffer.Length, _len - _pos);
            _plain.AsSpan(_pos, n).CopyTo(buffer);
            _pos += n;
            return n;
        }

        private void NextFrame()
        {
            Span<byte> head = stackalloc byte[5];
            if (_inner.ReadAtLeast(head, 5, throwOnEndOfStream: false) != 5) throw new CryptographicException("The backup is incomplete (cut short).");
            var final = head[0] == 1;
            var len = BinaryPrimitives.ReadUInt32BigEndian(head[1..]);
            if (head[0] > 1 || len > _chunk) throw new CryptographicException("The backup is damaged.");
            var cipher = new byte[len + TagLength];
            if (_inner.ReadAtLeast(cipher, cipher.Length, throwOnEndOfStream: false) != cipher.Length) throw new CryptographicException("The backup is incomplete (cut short).");
            if (_plain.Length < len) _plain = new byte[Math.Max(len, 1)];
            Span<byte> nonce = stackalloc byte[12];
            Nonce(nonce, _header.AsSpan(28, 7), _counter++, final);
            try { _aes.Decrypt(nonce, cipher.AsSpan(0, (int)len), cipher.AsSpan((int)len), _plain.AsSpan(0, (int)len), _header); }
            catch (CryptographicException) { throw new CryptographicException(_counter == 1 ? "Wrong passphrase, or the backup is damaged." : "The backup is damaged."); }
            _pos = 0; _len = (int)len; _final = final;
            if (final && _inner.ReadByte() != -1) throw new CryptographicException("The backup has data after its end.");
        }

        public override void Flush() { }
        protected override void Dispose(bool disposing) { if (disposing) _aes.Dispose(); base.Dispose(disposing); }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}

/// <summary>
/// Command-line entry points the restore script uses, handled before the web host starts:
///   dotnet VulnVerdict.Web.dll backup-decrypt &lt;encrypted file&gt; &lt;output file&gt;   (passphrase in VV_BACKUP_PASSPHRASE)
///   dotnet VulnVerdict.Web.dll backup-verify &lt;archive&gt;                          (passphrase in VV_BACKUP_PASSPHRASE if encrypted)
/// Neither needs the database.
/// </summary>
public static class BackupCli
{
    public const string PassphraseVariable = "VV_BACKUP_PASSPHRASE";

    /// <summary>Returns false when the arguments are not a backup command (the console then starts normally). Sets the process exit code.</summary>
    public static async Task<bool> TryRunAsync(string[] args)
    {
        if (args.Length == 0 || args[0] is not ("backup-decrypt" or "backup-verify")) return false;
        try
        {
            var pass = Environment.GetEnvironmentVariable(PassphraseVariable) ?? "";
            if (args[0] == "backup-decrypt")
            {
                if (args.Length != 3) throw new ArgumentException("usage: backup-decrypt <encrypted file> <output file>");
                if (pass == "") throw new ArgumentException("Set " + PassphraseVariable + " to the backup passphrase.");
                var tmp = args[2] + ".tmp";
                await using (var src = File.OpenRead(args[1]))
                await using (var dec = new BackupCrypto.DecryptingStream(src, pass))
                await using (var dst = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
                    await dec.CopyToAsync(dst);
                File.Move(tmp, args[2], true);
                Console.WriteLine("Decrypted to " + args[2]);
            }
            else
            {
                if (args.Length != 2) throw new ArgumentException("usage: backup-verify <archive>");
                var m = await BackupArchive.VerifyAsync(args[1], pass == "" ? null : pass, CancellationToken.None);
                Console.WriteLine("OK: " + m.Provider + " backup from " + m.CreatedUtc.ToString("u") + ", version " + m.AppVersion + ", database " + m.DatabaseBytes + " bytes, " + m.Keys + " key file(s).");
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            Environment.ExitCode = 1;
        }
        return true;
    }
}
