using System.Collections.Concurrent;

namespace AIRouterProxy;

/// <summary>
/// In-memory, per-route "last attribution" cell (Phase 3): which provider actually
/// served the most recent response on each aggregator route. Metadata only - provider
/// NAMES (bounded), never content, never keys. Same documented race as
/// <see cref="TransportClientFactory.LastObservationSummary"/>: reflects the latest
/// completed response for the route, not necessarily the just-finished one.
/// </summary>
public sealed class AttributionStore
{
    private readonly ConcurrentDictionary<string, string> _last = new(StringComparer.Ordinal);

    /// <summary>Records the provider name that served <paramref name="route"/> (bounded to 120 chars).</summary>
    public void Set(string route, string providerName)
    {
        if (string.IsNullOrWhiteSpace(route))
        {
            return;
        }

        var name = AttributionExtractor.NormalizeProviderName(providerName);
        if (name is null)
        {
            return;
        }

        _last[route] = name;
    }

    /// <summary>Last recorded provider name for a route, or null when never recorded.</summary>
    public string? Get(string route)
        => route is not null && _last.TryGetValue(route, out var name) ? name : null;

    /// <summary>Number of routes with a recorded attribution.</summary>
    public int Count => _last.Count;

    /// <summary>Point-in-time snapshot (route -&gt; provider name), for the admin read model.</summary>
    public IReadOnlyDictionary<string, string> Snapshot() => new Dictionary<string, string>(_last, StringComparer.Ordinal);
}
