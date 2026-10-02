using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace VulnVerdict.Core.Services;

/// <summary>
/// Time-based one-time passwords (RFC 6238 over RFC 4226) as authenticator apps implement them: HMAC-SHA1,
/// 30-second steps, six digits. Other parameters are not offered because most apps silently ignore them.
/// </summary>
public static class Totp
{
    public const int StepSeconds = 30;
    public const int Digits = 6;
    /// <summary>160 bits, the SHA-1 block the RFC recommends.</summary>
    public const int SecretBytes = 20;
    private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static byte[] NewSecret() => RandomNumberGenerator.GetBytes(SecretBytes);

    public static long StepAt(DateTime utc) => (long)Math.Floor((utc - DateTime.UnixEpoch).TotalSeconds) / StepSeconds;

    /// <summary>The code for one time step (RFC 4226 dynamic truncation).</summary>
    public static string Code(byte[] secret, long step, int digits = Digits)
    {
        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, step);
        Span<byte> mac = stackalloc byte[20];
        HMACSHA1.HashData(secret, counter, mac);
        var offset = mac[^1] & 0x0F;
        var binary = BinaryPrimitives.ReadInt32BigEndian(mac.Slice(offset, 4)) & 0x7FFFFFFF;
        var modulus = 1;
        for (var i = 0; i < digits; i++) modulus *= 10;
        return (binary % modulus).ToString().PadLeft(digits, '0');
    }

    /// <summary>
    /// The step the code belongs to, looking at the current step and one either side (a phone clock up to 30 seconds
    /// out still works), or null. Every candidate is compared in constant time, whichever matches.
    /// </summary>
    public static long? MatchingStep(byte[] secret, string code, DateTime utcNow, int window = 1)
    {
        var entered = Encoding.ASCII.GetBytes(code);
        var now = StepAt(utcNow);
        long? match = null;
        for (var step = now - window; step <= now + window; step++)
        {
            var same = CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Code(secret, step)), entered);
            if (same && match is null) match = step;
        }
        return match;
    }

    /// <summary>The otpauth:// address an authenticator app reads from the QR code.</summary>
    public static string Uri(string issuer, string account, byte[] secret) =>
        "otpauth://totp/" + System.Uri.EscapeDataString(issuer + ":" + account) + "?secret=" + ToBase32(secret)
        + "&issuer=" + System.Uri.EscapeDataString(issuer) + "&algorithm=SHA1&digits=" + Digits + "&period=" + StepSeconds;

    public static string ToBase32(ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder((data.Length * 8 + 4) / 5);
        int buffer = 0, bits = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b; bits += 8;
            while (bits >= 5) { sb.Append(Base32Alphabet[(buffer >> (bits - 5)) & 31]); bits -= 5; }
        }
        if (bits > 0) sb.Append(Base32Alphabet[(buffer << (5 - bits)) & 31]);
        return sb.ToString();
    }

    public static byte[] FromBase32(string text)
    {
        var bytes = new List<byte>(text.Length * 5 / 8);
        int buffer = 0, bits = 0;
        foreach (var ch in text)
        {
            if (ch is ' ' or '-' or '=') continue;
            var v = Base32Alphabet.IndexOf(char.ToUpperInvariant(ch));
            if (v < 0) throw new FormatException("Not a base32 character: " + ch);
            buffer = ((buffer << 5) | v) & 0xFFFF; bits += 5;
            if (bits >= 8) { bytes.Add((byte)(buffer >> (bits - 8))); bits -= 8; }
        }
        return bytes.ToArray();
    }

    /// <summary>The manual key in groups of four, as authenticator apps show it.</summary>
    public static string Grouped(string base32) => string.Join(" ", base32.Chunk(4).Select(c => new string(c)));
}
