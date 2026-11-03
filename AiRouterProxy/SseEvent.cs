namespace AIRouterProxy;

/// <summary>
/// A single Server-Sent Events record, as decoded by <see cref="SseParser"/>.
/// Byte spans are absolute offsets into the raw byte stream that was fed to the parser,
/// so a stream processor can slice and replay the exact original bytes.
/// </summary>
public sealed record SseEvent(
    string? EventName,
    string Data,
    string? Id,
    int? Retry,
    long StartOffset,
    long EndOffset)
{
    /// <summary>True for the standard OpenAI-compatible stream terminator ("[DONE]").</summary>
    public bool IsDone => string.Equals(Data.Trim(), "[DONE]", StringComparison.Ordinal);
}
