using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AIRouterProxy;

/// <summary>
/// Metadata-only capture of one completed TLS handshake (remote ip, certificate
/// fingerprints, TLS version/cipher/ALPN) into the <see cref="EndpointIdentity"/> /
/// <see cref="TransportObservation"/> shapes. Shared by the request connect path
/// (<see cref="ConnectTelemetry"/>) and the baseline probe (<see cref="EndpointProbe"/>)
/// so both produce byte-identical rows. Never touches request/response content and never
/// sees a key - the hashes are fingerprints of PUBLIC certificate material.
/// </summary>
public static class TransportCapture
{
    public static bool TryCapture(
        SslStream ssl,
        string route,
        string host,
        string ip,
        int port,
        DateTimeOffset now,
        out EndpointIdentity identity,
        out TransportObservation observation)
    {
        identity = null!;
        observation = null!;
        try
        {
            using var cert = ToX509(ssl.RemoteCertificate);
            if (cert is null)
            {
                return false;
            }

            var spki = cert.PublicKey?.ExportSubjectPublicKeyInfo();
            if (spki is null || spki.Length == 0)
            {
                return false;
            }

            var certSha256 = cert.GetCertHashString(HashAlgorithmName.SHA256);
            var tlsVersion = TransportHashes.FormatTls(ssl.SslProtocol);
            var cipherSuite = TransportHashes.TryCipherSuite(ssl);
            var alpn = TransportHashes.FormatAlpn(ssl);

            // SHA-256 of the SPKI in unpadded base64url - the baseline/pin format. Note
            // Sha256Base64Url/Hex16Sha256 hash their input, so the RAW SPKI goes in
            // (a pre-hash here would produce a double hash and break matching).
            identity = new EndpointIdentity(
                Route: route,
                Host: host,
                Ip: ip,
                Port: port,
                SpkiHash: TransportHashes.Sha256Base64Url(spki),
                CertSha256: certSha256,
                Issuer: cert.Issuer,
                NotBefore: cert.NotBefore,
                NotAfter: cert.NotAfter,
                TlsVersion: tlsVersion,
                CipherSuite: cipherSuite,
                Alpn: alpn,
                FirstSeen: now,
                LastSeen: now,
                Source: "learn");

            observation = new TransportObservation(
                Timestamp: now,
                Route: route,
                Host: host,
                Ip: ip,
                Port: port,
                SpkiHashShort: TransportHashes.Hex16Sha256(spki),
                CertSha256Short: certSha256.Length >= 16 ? certSha256[..16] : certSha256,
                Issuer: cert.Issuer,
                TlsVersion: tlsVersion,
                CipherSuite: cipherSuite,
                Alpn: alpn,
                Status: "observed");

            return true;
        }
        catch
        {
            identity = null!;
            observation = null!;
            return false;
        }
    }

    /// <summary>Owns the certificate copy (RemoteCertificate can be an X509Certificate2 or a legacy X509Certificate).</summary>
    private static X509Certificate2? ToX509(X509Certificate? cert)
    {
        if (cert is null)
        {
            return null;
        }

        if (cert is X509Certificate2 c2)
        {
            return c2;
        }

        return new X509Certificate2(cert);
    }
}
