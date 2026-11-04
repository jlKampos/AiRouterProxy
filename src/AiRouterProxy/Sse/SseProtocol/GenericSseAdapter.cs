namespace AIRouterProxy;

/// <summary>
/// Fallback for SSE streams no specific adapter recognizes. Catch-all (Matches is always
/// true), so registry resolution never fails. The notice uses the same interoperable
/// chat content-delta shape as <see cref="OpenAiChatAdapter"/> - the safest default,
/// identical to the legacy behavior for unrecognized streams.
/// </summary>
public sealed class GenericSseAdapter : SseProtocolAdapterBase
{
    public override string Name => "generic";

    public override bool Matches(SseEvent e) => true;

    public override byte[] BuildNoticeChunk(string notice)
        => BuildChunk(
            "\ndata: ",
            new { choices = new[] { new { delta = new { content = "\n\n" + notice } } } });
}
