namespace AIRouterProxy;

/// <summary>
/// Anthropic (Claude) SSE. Recognized by the message_start event (the first event of a
/// real Messages stream) or a content_block_delta event/payload. The notice is injected
/// as a content_block_delta text_delta event, and both content_block_stop and
/// message_stop are stream terminators (Anthropic streams have no "[DONE]").
///
/// content_block_stop is treated as terminal so the notice lands BEFORE the text block
/// closes (between the last delta and the stop): SDKs like @ai-sdk/anthropic discard
/// text deltas for an already-closed block, so injecting at message_stop makes the
/// notice invisible. The processor guard ensures a later message_stop does not inject
/// a second notice.
/// </summary>
public sealed class AnthropicAdapter : SseProtocolAdapterBase
{
    public override string Name => "anthropic";

    public override bool Matches(SseEvent e)
        => e.EventName == "content_block_delta"
           || e.EventName == "message_start"
           || e.Data.Contains("\"type\":\"content_block_delta\"", StringComparison.Ordinal);

    public override SseEventKind Classify(SseEvent e)
        => string.Equals(e.EventName, "message_stop", StringComparison.Ordinal)
           || string.Equals(e.EventName, "content_block_stop", StringComparison.Ordinal)
            ? SseEventKind.Terminal
            : base.Classify(e);

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
