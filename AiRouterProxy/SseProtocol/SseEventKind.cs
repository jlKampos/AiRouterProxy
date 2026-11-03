namespace AIRouterProxy;

/// <summary>
/// How a protocol adapter classifies an SSE event in the stream lifecycle.
/// Used for diagnostics and tests; the stream processor treats every kind the same
/// (one-event look-behind), except Terminal which places the notice before it.
/// </summary>
public enum SseEventKind
{
    /// <summary>Opening event of a session (e.g. response.created / message_start).</summary>
    Start,

    /// <summary>Regular content-bearing event.</summary>
    Content,

    /// <summary>Stream terminator (e.g. "[DONE]").</summary>
    Terminal,

    /// <summary>Error event (e.g. event: error or an error payload).</summary>
    Error,
}
