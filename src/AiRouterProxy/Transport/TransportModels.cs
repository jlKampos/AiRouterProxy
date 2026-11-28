using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;

namespace AIRouterProxy;

/// <summary>
/// One observed TLS endpoint identity, captured per connection (metadata only): who
/// answered on the wire, which TLS version/ciphers were negotiated and what the
/// server certificate says. NEVER holds request/response content and never holds a
/// key value - the hashes are fingerprints of the certificate, which is public data.
/// </summary>
public sealed record EndpointIdentity(
    string Route,
    string Host,
    string Ip,
    int Port,
    /// <summary>Full SHA-256 of the SubjectPublicKeyInfo, unpadded base64url (baseline format). Fingerprint of a public cert - not a secret.</summary>
    string SpkiHash,
    /// <summary>SHA-256 cert hash, hex (from GetCertHashString(SHA256)).</summary>
    string CertSha256,
    string Issuer,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string TlsVersion,
    string? CipherSuite,
    string? Alpn,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen,
    /// <summary>"learn" (captured on a real connection) | "config" | "probe" (periodic endpoint probe).</summary>
    string Source)
{
    /// <summary>First 16 hex chars of the SPKI hash - display span for the UI/API (never used for matching).</summary>
    public string SpkiHashShort => TransportHashes.ShortHex16(SpkiHash);
}

/// <summary>
/// One in-memory observation row (the compact, recent view). The ring buffer stores
/// these; the baseline file stores the fuller <see cref="EndpointIdentity"/>.
/// </summary>
public sealed record TransportObservation(
    DateTimeOffset Timestamp,
    string Route,
    string Host,
    string Ip,
    int Port,
    /// <summary>First 16 hex chars of the SPKI SHA-256.</summary>
    string SpkiHashShort,
    /// <summary>First 16 hex chars of the cert SHA-256.</summary>
    string CertSha256Short,
    string Issuer,
    string TlsVersion,
    string? CipherSuite,
    string? Alpn,
    /// <summary>"observed" in Phase 1; Phase 2 adds "warn"/"blocked".</summary>
    string Status);

/// <summary>
/// Effective transport-attestation policy for one route (already resolved from the
/// global <see cref="TransportOptions"/> defaults + the per-route override). Null
/// policy (ForRoute) = attestation disabled for the route - full compatibility.
/// </summary>
public sealed record TransportPolicy(
    bool Enabled,
    /// <summary>Ring buffer capacity for the route (already clamped 10..1000).</summary>
    int BufferCapacity,
    /// <summary>"observe" | "warn" | "block" (Phase 2).</summary>
    string Enforce,
    int? PoolLifetimeMinutes,
    IReadOnlyList<string> ExpectedIps,
    string? TlsFloor,
    int GraceDays,
    IReadOnlyList<string> Pins,
    /// <summary>How often (hours) the endpoint probe re-connects to keep the baseline fresh; 0 = disabled.</summary>
    int ProbeHours);

/// <summary>
/// Pure hash/format helpers for the transport layer. The SPKI/cert fingerprints are
/// hashes of PUBLIC certificate material - they are NOT secrets (the baseline file
/// and the activity summary may carry them freely).
/// </summary>
public static class TransportHashes
{
    /// <summary>SHA-256 of the input, unpadded base64url (the baseline format).</summary>
    public static string Sha256Base64Url(ReadOnlySpan<byte> data)
        => Convert.ToBase64String(SHA256.HashData(data)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>First 16 hex chars of the SHA-256 - the compact span used in the ring rows.</summary>
    public static string Hex16Sha256(ReadOnlySpan<byte> data)
    {
        var hex = Convert.ToHexString(SHA256.HashData(data));
        return hex.Length > 16 ? hex[..16] : hex;
    }

    /// <summary>
    /// Canonicalizes a pin to the baseline's unpadded base64url SHA-256 form so config
    /// pins compare equal to captured SPKIs. Accepts a 64-hex digest or a base64/base64url
    /// digest (43/44 chars, optional padding); returns null when not pin-shaped.
    /// </summary>
    public static string? NormalizePin(string? pin)
    {
        if (string.IsNullOrWhiteSpace(pin))
        {
            return null;
        }

        var value = pin.Trim();

        // 64 hex chars = the SHA-256 digest in hex.
        if (value.Length == 64 && IsHex(value))
        {
            return Base64UrlOfDigest(Convert.FromHexString(value));
        }

        // base64/base64url digest with optional padding.
        if (value.Length is 43 or 44 && IsBase64ish(value))
        {
            var padded = value.Replace('-', '+').Replace('_', '/');
            var rem = padded.Length % 4;
            if (rem == 2)
            {
                padded += "==";
            }
            else if (rem == 3)
            {
                padded += "=";
            }

            try
            {
                return Base64UrlOfDigest(Convert.FromBase64String(padded));
            }
            catch (FormatException)
            {
                return null;
            }
        }

        return null;
    }

    /// <summary>Re-encodes a 32-byte digest as the unpadded base64url form WITHOUT re-hashing it.</summary>
    private static string Base64UrlOfDigest(byte[] digest)
        => Convert.ToBase64String(digest).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static bool IsHex(string value)
    {
        foreach (var c in value)
        {
            var isHexDigit = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!isHexDigit)
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsBase64ish(string value)
    {
        foreach (var c in value)
        {
            if (!char.IsAsciiLetterOrDigit(c) && c is not ('+' or '/' or '-' or '_' or '='))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>First 16 hex chars of a full base64url SHA-256 (decodes the baseline value).</summary>
    public static string ShortHex16(string base64UrlSha256)
    {
        if (string.IsNullOrEmpty(base64UrlSha256))
        {
            return string.Empty;
        }

        try
        {
            var padded = base64UrlSha256.Replace('-', '+').Replace('_', '/');
            var rem = padded.Length % 4;
            if (rem == 2)
            {
                padded += "==";
            }
            else if (rem == 3)
            {
                padded += "=";
            }

            var hex = Convert.ToHexString(Convert.FromBase64String(padded));
            return hex.Length > 16 ? hex[..16] : hex;
        }
        catch (FormatException)
        {
            return string.Empty;
        }
    }

    /// <summary>Normalizes the SslProtocols enum to a display string ("TLS 1.3").</summary>
#pragma warning disable SYSLIB0039 // display-only mapping for legacy protocol names
    public static string FormatTls(SslProtocols protocol) => protocol switch
    {
        SslProtocols.Tls13 => "TLS 1.3",
        SslProtocols.Tls12 => "TLS 1.2",
        SslProtocols.Tls11 => "TLS 1.1",
        SslProtocols.Tls => "TLS 1.0",
        _ => protocol.ToString(),
    };
#pragma warning restore SYSLIB0039

    /// <summary>
    /// Negotiated cipher suite as a string, or null when it is not available
    /// (older platforms / TLS flavours without a named suite). Best effort: never throws.
    /// </summary>
    public static string? TryCipherSuite(SslStream ssl)
    {
        try
        {
            var suite = ssl.NegotiatedCipherSuite;
            return suite == default ? null : suite.ToString();
        }
        catch (PlatformNotSupportedException)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    /// <summary>Negotiated ALPN as a string, or null when none was negotiated.</summary>
    public static string? FormatAlpn(SslStream ssl)
    {
        var value = ssl.NegotiatedApplicationProtocol.ToString();
        return string.IsNullOrEmpty(value) ? null : value;
    }
}

/// <summary>
/// Builds the one-line transport summary attached to an activity entry
/// (e.g. "ip=104.21.55.1 cert=sha256:abcd1234 tls=TLS 1.3 alpn=h2"). Metadata only.
/// </summary>
public static class TransportSummary
{
    public static string Format(TransportObservation o)
    {
        var sb = new StringBuilder(160);
        sb.Append("ip=").Append(o.Ip);
        sb.Append(" cert=sha256:").Append(o.CertSha256Short.Length > 8 ? o.CertSha256Short[..8] : o.CertSha256Short);
        sb.Append(" tls=").Append(o.TlsVersion);
        if (!string.IsNullOrEmpty(o.CipherSuite))
        {
            sb.Append(" cipher=").Append(o.CipherSuite);
        }

        if (!string.IsNullOrEmpty(o.Alpn))
        {
            sb.Append(" alpn=").Append(o.Alpn);
        }

        // Phase 2 verdict appendix: warn/blocked rows carry the attestation outcome.
        if (!string.IsNullOrEmpty(o.Status) && !string.Equals(o.Status, "observed", StringComparison.Ordinal))
        {
            sb.Append(" attestation=").Append(o.Status);
        }

        return sb.ToString();
    }
}
