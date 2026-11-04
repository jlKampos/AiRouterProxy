namespace AIRouterProxy;

/// <summary>
/// A recognized SSE protocol family. Each adapter can (a) recognize whether an event
/// belongs to it, (b) classify events in the stream lifecycle, and (c) build the
/// well-formed redaction-notice chunk for its protocol.
/// Adapters are stateless singletons.
/// </summary>
public interface ISseProtocolAdapter
{
    /// <summary>Stable identifier used in diagnostics/logs.</summary>
    string Name { get; }

    /// <summary>True when <paramref name="e"/> belongs to this protocol family.</summary>
    bool Matches(SseEvent e);

    /// <summary>Classifies an event in this protocol's stream lifecycle.</summary>
    SseEventKind Classify(SseEvent e);

    /// <summary>
    /// Builds the exact bytes of the SSE chunk that appends <paramref name="notice"/>
    /// to a stream of this protocol (a full event, blank-line terminated).
    /// </summary>
    byte[] BuildNoticeChunk(string notice);
}
