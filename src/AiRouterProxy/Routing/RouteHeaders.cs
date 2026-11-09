namespace AIRouterProxy;

/// <summary>
/// Applies per-route static headers to an upstream request (routes.json "headers").
/// Headers the proxy injects itself (credentials, content framing, hop-by-hop) are
/// reserved and never overridden; empty names/values are skipped.
/// </summary>
public static class RouteHeaders
{
    private static readonly HashSet<string> Reserved = new(StringComparer.OrdinalIgnoreCase)
    {
        "authorization",
        "content-type",
        "content-length",
        "transfer-encoding",
        "accept",
        "host",
        "connection",
    };

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
                || Reserved.Contains(name))
            {
                continue;
            }

            request.Headers.TryAddWithoutValidation(name, value);
        }
    }
}
