using System.Security.Cryptography;
using System.Text;

namespace AiRouterProxy.AdminServices;

/// <summary>
/// Short SHA-256 fingerprints used to identify a caller in UI/logs without ever
/// exposing the key value. Same semantics as UiSessionManager.Fingerprint
/// (SHA-256 hex, first 24 chars) - kept here so the read/write paths share one
/// definition without touching the session middleware.
/// </summary>
public static class AdminHash
{
    public const int DefaultLength = 24;

    public static string Short(string? value, int length = DefaultLength)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "-";
        }

        var hex = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
        return hex.Length <= length ? hex : hex[..length];
    }
}
