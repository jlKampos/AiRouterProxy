using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace AIRouterProxy;

/// <summary>
/// Non-reversible fingerprint of a detected value, used by detection forensics.
/// The HMAC key is ephemeral: 32 random bytes generated once per process
/// (<see cref="RandomNumberGenerator"/>) and never written anywhere. Consequences:
///  - the fingerprint cannot be reversed to the value;
///  - it cannot be correlated across restarts (a new process = new key = new fingerprints);
///  - it cannot be matched against a precomputed table of known keys.
/// It only answers "same value?" / "different value?" inside the current process lifetime.
/// Only computed when forensics collection is enabled (never on the normal redaction path).
/// </summary>
public static class DetectionFingerprint
{
    private const int FingerprintBytes = 4;

    /// <summary>UTF-8 length (in bytes) that still fits on the stack.</summary>
    private const int StackBufferBytes = 256;

    private static readonly byte[] Key = RandomNumberGenerator.GetBytes(32);

    /// <summary>8 lowercase hex chars (4 bytes of HMAC-SHA256). Empty for null/empty input.</summary>
    public static string Of(string? value) => string.IsNullOrEmpty(value) ? string.Empty : Of(value.AsSpan());

    /// <summary>
    /// Span overload: encodes directly into a stack/pooled buffer instead of materializing a
    /// UTF-8 <c>byte[]</c> (or a sliced <c>string</c>) for every detection.
    /// </summary>
    public static string Of(ReadOnlySpan<char> value)
    {
        if (value.IsEmpty)
        {
            return string.Empty;
        }

        var byteCount = Encoding.UTF8.GetByteCount(value);
        if (byteCount == 0)
        {
            return string.Empty;
        }

        if (byteCount <= StackBufferBytes)
        {
            Span<byte> utf8 = stackalloc byte[StackBufferBytes];
            Encoding.UTF8.GetBytes(value, utf8[..byteCount]);
            return Hash(utf8[..byteCount]);
        }

        var rented = ArrayPool<byte>.Shared.Rent(byteCount);
        try
        {
            var utf8 = rented.AsSpan(0, byteCount);
            Encoding.UTF8.GetBytes(value, utf8);
            return Hash(utf8);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }

        static string Hash(ReadOnlySpan<byte> utf8)
        {
            Span<byte> hash = stackalloc byte[32];
            HMACSHA256.HashData(Key, utf8, hash);
            return Convert.ToHexStringLower(hash[..FingerprintBytes]);
        }
    }
}
