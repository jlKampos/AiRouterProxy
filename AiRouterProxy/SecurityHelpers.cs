using System.Security.Cryptography;
using System.Text;

namespace AIRouterProxy;

public static class SecurityHelpers
{
    public static string? ExtractBearerToken(string authorization)
    {
        if (string.IsNullOrEmpty(authorization))
        {
            return null;
        }

        const string prefix = "Bearer ";
        var index = authorization.IndexOf(prefix, StringComparison.OrdinalIgnoreCase);
        if (index < 0)
        {
            return null;
        }

        var token = authorization[(index + prefix.Length)..].Trim();
        return token.Length == 0 ? null : token;
    }

    public static bool SecureEquals(string? a, string? b)
    {
        if (a is null || b is null)
        {
            return false;
        }

        var bytesA = Encoding.UTF8.GetBytes(a);
        var bytesB = Encoding.UTF8.GetBytes(b);

        if (bytesA.Length != bytesB.Length)
        {
            return false;
        }

        return CryptographicOperations.FixedTimeEquals(bytesA, bytesB);
    }

    public static string Sha256Hex(string value)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    public static string HashShort(string? hash, int length = 12)
    {
        if (string.IsNullOrEmpty(hash))
        {
            return "(empty)";
        }

        return hash.Length <= length ? hash : hash[..length];
    }
}
