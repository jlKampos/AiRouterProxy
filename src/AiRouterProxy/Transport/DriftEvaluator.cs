using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace AIRouterProxy;

/// <summary>
/// Root-cause analysis of one observed endpoint against the effective policy: maps the
/// facts (ip, negotiated TLS, pin verdict) to a drift severity ("none" | "low" | "high")
/// plus a machine reason id. Pure and stateless so it is unit-testable without sockets.
/// The chain is strictest first: expected IPs, then TLS floor, then the pin verdict.
/// Only configured checks can fail - an empty expectedIps / null tlsFloor is a pass.
/// </summary>
public static class DriftEvaluator
{
    public const string SeverityNone = "none";
    public const string SeverityLow = "low";
    public const string SeverityHigh = "high";

    public const string ReasonUnexpectedIp = "unexpected-ip";
    public const string ReasonTlsFloor = "tls-floor";
    public const string ReasonSpkiMismatch = "spki-mismatch";
    public const string ReasonNewEndpointGrace = "new-endpoint-grace";

    public static (string Severity, string Reason) Evaluate(
        TransportPolicy policy,
        PinVerdict verdict,
        string ip,
        string tlsVersion)
    {
        if (policy.ExpectedIps is { Count: > 0 } && !string.IsNullOrWhiteSpace(ip) && !IpMatchesAny(ip, policy.ExpectedIps))
        {
            return (SeverityHigh, ReasonUnexpectedIp);
        }

        if (TlsBelowFloor(policy.TlsFloor, tlsVersion))
        {
            return (SeverityHigh, ReasonTlsFloor);
        }

        return verdict switch
        {
            PinVerdict.Grace => (SeverityLow, ReasonNewEndpointGrace),
            PinVerdict.Mismatch => (SeverityHigh, ReasonSpkiMismatch),
            _ => (SeverityNone, string.Empty),
        };
    }

    // ----------------------------------------------------------
    // Expected IPs (plain IP or CIDR; IPv4 + IPv6)
    // ----------------------------------------------------------

    public static bool IpMatchesAny(string ip, IReadOnlyList<string> expected)
    {
        foreach (var entry in expected)
        {
            if (string.IsNullOrWhiteSpace(entry))
            {
                continue;
            }

            if (IpInEntry(ip, entry.Trim()))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IpInEntry(string ip, string entry)
    {
        if (!IPAddress.TryParse(ip, out var address)
            || address.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
        {
            return string.Equals(ip, entry, StringComparison.OrdinalIgnoreCase);
        }

        var slash = entry.IndexOf('/');
        var networkText = slash >= 0 ? entry[..slash] : entry;
        var prefixText = slash >= 0 ? entry[(slash + 1)..] : string.Empty;

        if (!IPAddress.TryParse(networkText, out var network))
        {
            return false;
        }

        if (slash < 0)
        {
            return address.Equals(network);
        }

        if (!int.TryParse(prefixText, out var prefix) || prefix < 0)
        {
            return false;
        }

        var bits = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefix > bits)
        {
            return false;
        }

        var a = address.GetAddressBytes();
        var n = network.GetAddressBytes();
        if (a.Length != n.Length)
        {
            return false;
        }

        for (var i = 0; i < a.Length; i++)
        {
            var remaining = prefix - (i * 8);
            if (remaining <= 0)
            {
                break;
            }

            var mask = remaining >= 8 ? (byte)0xFF : (byte)(0xFF << (8 - remaining));
            if ((a[i] & mask) != (n[i] & mask))
            {
                return false;
            }
        }

        return true;
    }

    // ----------------------------------------------------------
    // TLS floor ("1.2" | "1.3") vs the negotiated version display ("TLS 1.3")
    // ----------------------------------------------------------

    public static bool TlsBelowFloor(string? floor, string? tlsVersion)
    {
        if (string.IsNullOrWhiteSpace(floor))
        {
            return false;
        }

        var (fmaj, fmin) = ParseVersion(floor);
        if (fmaj < 0)
        {
            // Unknown floor string: not enforced at the eval layer (validators reject it).
            return false;
        }

        var (vmaj, vmin) = ParseVersion(tlsVersion);
        if (vmaj < 0)
        {
            // Unknown negotiated version: fail toward suspicion.
            return true;
        }

        return vmaj < fmaj || (vmaj == fmaj && vmin < fmin);
    }

    /// <summary>Parses "1.2", "1.3", "TLS 1.2", "TLSv1.2" - returns (-1, -1) when it cannot.</summary>
    internal static (int Major, int Minor) ParseVersion(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return (-1, -1);
        }

        var match = Regex.Match(text, @"(\d+)[.](\d+)");
        if (!match.Success)
        {
            return (-1, -1);
        }

        return (int.Parse(match.Groups[1].Value), int.Parse(match.Groups[2].Value));
    }
}
