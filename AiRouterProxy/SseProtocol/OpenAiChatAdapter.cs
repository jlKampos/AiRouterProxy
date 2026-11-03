namespace AIRouterProxy;

/// <summary>
/// OpenAI-compatible chat completions SSE. Recognized by the "choices" payload
/// (streamed chat deltas). The notice is injected as a final choice content delta -
/// the interoperable format most OpenAI-compatible servers accept.
/// </summary>
public sealed class OpenAiChatAdapter : SseProtocolAdapterBase
{
    public override string Name => "chat";

    public override bool Matches(SseEvent e)
        => e.Data.Contains("\"choices\"", StringComparison.Ordinal);

    protected override bool IsStartEvent(SseEvent e)
        => e.Data.Contains("\"role\":\"assistant\"", StringComparison.Ordinal);

    public override byte[] BuildNoticeChunk(string notice)
        => BuildChunk(
            "\ndata: ",
            new { choices = new[] { new { delta = new { content = "\n\n" + notice } } } });
}
