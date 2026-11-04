using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace AIRouterProxy;

/// <summary>
/// JSON serialization shared by the SSE protocol adapters. Uses the same relaxed
/// escaping as NoticeInjector / the legacy chunk builder, so notice chunks are
/// byte-for-byte identical to the Sprint 4 output.
/// </summary>
internal static class SseProtocolJson
{
    private static readonly JsonSerializerOptions Options = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static string Serialize(object payload)
        => JsonSerializer.Serialize(payload, Options);

    /// <summary>prefix + data payload + trailing blank line, as UTF-8 bytes.</summary>
    public static byte[] Chunk(string prefix, object payload)
        => Encoding.UTF8.GetBytes(prefix + Serialize(payload) + "\n\n");
}
