namespace AIRouterProxy;

/// <summary>
/// Applies per-route static headers to an upstream request (routes.json "headers").
/// Headers the proxy injects itself (credentials, content framing, hop-by-hop) are
/// reserved and never overridden; empty names/values are skipped.
/// </summary>
public static class RouteHeaders
{
    private static readonly HashSet<string> ReservedSet = new(StringComparer.OrdinalIgnoreCase)
    {
        "authorization",
        "content-type",
        "content-length",
        "transfer-encoding",
        "accept",
        "host",
        "connection",
    };

    /// <summary>
    /// Header names the proxy injects itself and that a per-route static header must never
    /// override. Single source of truth: <c>RouteValidator</c> rejects exactly this list on
    /// save. Case-insensitive.
    /// </summary>
    public static IReadOnlySet<string> Reserved => ReservedSet;

    public static void Apply(HttpRequestMessage request, IReadOnlyDictionary<string, string>? headers)
    {
        if (request is null || headers is null || headers.Count == 0)
        {
            return;
        }

        foreach (var (name, value) in headers)
        {
            if (string.IsNullOrWhiteSpace(name)
                || string.IsNullOrWhiteSpace(value)
                || ReservedSet.Contains(name))
            {
                continue;
            }

            request.Headers.TryAddWithoutValidation(name, value);
        }
    }
}
