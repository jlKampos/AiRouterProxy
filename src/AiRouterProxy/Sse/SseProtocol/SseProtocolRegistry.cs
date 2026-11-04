namespace AIRouterProxy;

/// <summary>
/// Ordered set of SSE protocol adapters. The first adapter whose Matches returns true for
/// the stream's first event wins (a stream is homogeneous; the protocol never changes
/// mid-stream). The GenericSseAdapter always matches, so resolution never fails.
/// </summary>
public static class SseProtocolRegistry
{
    /// <summary>Resolution order: most specific protocols first, generic catch-all last.</summary>
    public static readonly IReadOnlyList<ISseProtocolAdapter> Adapters = new ISseProtocolAdapter[]
    {
        new OpenAiResponsesAdapter(),
        new AnthropicAdapter(),
        new OpenAiChatAdapter(),
        new GenericSseAdapter(),
    };

    public static ISseProtocolAdapter Resolve(SseEvent e)
    {
        foreach (var adapter in Adapters)
        {
            if (adapter.Matches(e))
            {
                return adapter;
            }
        }

        return new GenericSseAdapter(); // unreachable: Generic matches everything
    }
}
