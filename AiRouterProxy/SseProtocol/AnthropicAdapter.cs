namespace AIRouterProxy;

/// <summary>
/// Anthropic (Claude) SSE. Recognized by the content_block_delta event or payload.
/// The notice is injected as a content_block_delta text_delta event.
/// </summary>
public sealed class AnthropicAdapter : SseProtocolAdapterBase
{
    public override string Name => "anthropic";

    public override bool Matches(SseEvent e)
        => e.EventName == "content_block_delta"
           || e.Data.Contains("\"type\":\"content_block_delta\"", StringComparison.Ordinal);

    protected override bool IsStartEvent(SseEvent e)
        => string.Equals(e.EventName, "message_start", StringComparison.Ordinal);

    public override byte[] BuildNoticeChunk(string notice)
        => BuildChunk(
            "event: content_block_delta\ndata: ",
            new
            {
                type = "content_block_delta",
                index = 0,
                delta = new { type = "text_delta", text = "\n\n" + notice },
            });
}
