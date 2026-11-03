namespace AIRouterProxy;

/// <summary>
/// Shared classification and chunk helpers for SSE protocol adapters.
/// "[DONE]" is the common OpenAI-compatible terminator (kept for every adapter, matching
/// NoticeInjector's behavior); error events carry "event: error" or an "error" JSON
/// property. Session-start detection is protocol-specific (<see cref="IsStartEvent"/>).
/// </summary>
public abstract class SseProtocolAdapterBase : ISseProtocolAdapter
{
    public abstract string Name { get; }

    public abstract bool Matches(SseEvent e);

    public virtual SseEventKind Classify(SseEvent e)
    {
        if (e.IsDone)
        {
            return SseEventKind.Terminal;
        }

        if (IsErrorEvent(e))
        {
            return SseEventKind.Error;
        }

        if (IsStartEvent(e))
        {
            return SseEventKind.Start;
        }

        return SseEventKind.Content;
    }

    public abstract byte[] BuildNoticeChunk(string notice);

    /// <summary>"event: error" or a data payload carrying an "error" property.</summary>
    protected static bool IsErrorEvent(SseEvent e)
        => string.Equals(e.EventName, "error", StringComparison.Ordinal)
           || e.Data.Contains("\"error\"", StringComparison.Ordinal);

    /// <summary>Which event opens a session (overridden per protocol).</summary>
    protected virtual bool IsStartEvent(SseEvent e) => false;

    protected static byte[] BuildChunk(string prefix, object payload)
        => SseProtocolJson.Chunk(prefix, payload);
}
