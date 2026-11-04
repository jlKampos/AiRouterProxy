namespace AIRouterProxy;

/// <summary>
/// OpenAI Responses API SSE. Recognized by the "response.*" event names or the
/// "response.output_text.delta" payload. The notice is injected as a
/// response.output_text.delta event.
/// </summary>
public sealed class OpenAiResponsesAdapter : SseProtocolAdapterBase
{
    public override string Name => "responses";

    public override bool Matches(SseEvent e)
        => (e.EventName is not null && e.EventName.StartsWith("response.", StringComparison.Ordinal))
           || e.Data.Contains("\"type\":\"response.output_text.delta\"", StringComparison.Ordinal);

    protected override bool IsStartEvent(SseEvent e)
        => string.Equals(e.EventName, "response.created", StringComparison.Ordinal);

    public override byte[] BuildNoticeChunk(string notice)
        => BuildChunk(
            "event: response.output_text.delta\ndata: ",
            new { type = "response.output_text.delta", delta = "\n\n" + notice });
}
