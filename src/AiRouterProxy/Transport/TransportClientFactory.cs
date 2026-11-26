using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace AIRouterProxy;

/// <summary>
/// Provides the HttpClient used to forward each route's requests.
///
/// - Routes with an ACTIVE transport policy get their own SocketsHttpHandler whose
///   ConnectCallback performs the attested handshake (<see cref="ConnectTelemetry"/>).
///   The client is cached per route + effective config (a config change - hot reload -
///   produces a new key, so a new handler is built; the stale one is pruned).
/// - Routes WITHOUT an active policy get the shared default client (plain HttpClient,
///   no custom handler) - behaviorally identical to the previous
///   IHttpClientFactory.CreateClient("AIRouter") without the factory indirection.
///
/// Thread-safe: ConcurrentDictionary of Lazy&lt;CachedClient&gt;.
/// </summary>
public sealed class TransportClientFactory
{
    private const int MaxCachedClients = 128;

    private readonly TransportPolicyProvider _policies;
    private readonly AttestationRecorder _recorder;
    private readonly ILogger<TransportClientFactory> _logger;

    /// <summary>
    /// Shared client for routes without an active policy (no custom ConnectCallback).
    /// Its instance Timeout stays <see cref="Timeout.InfiniteTimeSpan"/>: the per-request
    /// deadline is owned by the caller (ProxyMiddleware) through a per-request
    /// CancellationTokenSource - never by mutating a shared client's Timeout, which two
    /// concurrent routes with different timeouts would race on.
    /// </summary>
    private readonly HttpClient _defaultClient = new() { Timeout = Timeout.InfiniteTimeSpan };

    /// <summary>Per-route "last connection observation" cell read by the middleware for the activity summary.</summary>
    private readonly ConcurrentDictionary<string, TransportObservation?> _lastObservation = new(StringComparer.Ordinal);

    /// <summary>Per-route "last enforcement outcome" cell read by the middleware for the attestation response header.</summary>
    private readonly ConcurrentDictionary<string, string?> _lastEnforcement = new(StringComparer.Ordinal);

    /// <summary>Cache keyed by "route name | config hash".</summary>
    private readonly ConcurrentDictionary<string, Lazy<CachedClient>> _clients = new(StringComparer.Ordinal);

    public TransportClientFactory(
        TransportPolicyProvider policies,
        AttestationRecorder recorder,
        ILogger<TransportClientFactory> logger)
    {
        _policies = policies;
        _recorder = recorder;
        _logger = logger;
    }

    public HttpClient DefaultClient => _defaultClient;

    /// <summary>
    /// Client for a route. When the route has an active transport policy a dedicated
    /// client (custom ConnectCallback) is returned; otherwise the shared default client.
    /// The caller applies the per-request deadline via a per-request CancellationTokenSource
    /// (the client's own Timeout stays <see cref="Timeout.InfiniteTimeSpan"/>).
    /// </summary>
    public HttpClient GetClient(string routeName, RouteOptions? activeRoute, int requestTimeoutMs)
    {
        if (activeRoute is null)
        {
            return _defaultClient;
        }

        var policy = _policies.ForRoute(activeRoute.Name);
        // Plain-http upstreams never get the attested callback: attestation is a TLS
        // concept (pins / cert fingerprints / TLS facts), and forcing a TLS handshake
        // here would regress http:// routes to 502. They keep the shared default client
        // (no custom handler), exactly like routes without an active policy.
        if (policy is null || !UsesHttpsUpstream(activeRoute))
        {
            return _defaultClient;
        }

        var cacheKey = routeName + "|" + BuildConfigKey(activeRoute, policy);
        var lazy = _clients.GetOrAdd(cacheKey, k => new Lazy<CachedClient>(
            () => BuildClient(activeRoute, policy),
            LazyThreadSafetyMode.ExecutionAndPublication));

        PruneIfNeeded(cacheKey);
        return lazy.Value.Client;
    }

    /// <summary>
    /// The last observed endpoint summary for a route (only present when an active
    /// policy handler actually completed a TLS connection). Null otherwise.
    /// </summary>
    public string? LastObservationSummary(string routeName)
    {
        if (routeName is null || !_lastObservation.TryGetValue(routeName, out var observation) || observation is null)
        {
            return null;
        }

        return TransportSummary.Format(observation);
    }

    /// <summary>
    /// Attestation response-header value for the route's LAST connection: "block" for a
    /// rejected connection, "&lt;route&gt;:&lt;severity&gt;" for a warn, null when the last
    /// connection was clean (or nothing was observed yet). Same documented race as
    /// <see cref="LastObservationSummary"/>: reflects the latest connection for the route,
    /// not necessarily this exact request.
    /// </summary>
    public string? LastEnforcementHeader(string routeName)
    {
        if (routeName is null || !_lastEnforcement.TryGetValue(routeName, out var header))
        {
            return null;
        }

        return header;
    }

    /// <summary>
    /// The SocketsHttpHandler backing the policy-active route's CURRENT client, for tests
    /// and for future phases (pinning verification). Null when the route has no active
    /// policy (shared default client - no custom handler exists) or the client has not
    /// been built yet (call GetClient first).
    /// </summary>
    public SocketsHttpHandler? GetActiveHandler(string routeName, RouteOptions route)
    {
        var policy = _policies.ForRoute(routeName);
        if (policy is null || !UsesHttpsUpstream(route))
        {
            return null;
        }

        var cacheKey = routeName + "|" + BuildConfigKey(route, policy);
        return _clients.TryGetValue(cacheKey, out var lazy) && lazy.IsValueCreated
            ? lazy.Value.Handler
            : null;
    }

    // ----------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------

    private CachedClient BuildClient(RouteOptions route, TransportPolicy policy)
    {
        // SocketsHttpHandler defaults stay: MaxConnectionsPerServer unlimited, and
        // PooledConnectionLifetime keeps its default (Timeout.InfiniteTimeSpan) unless
        // a positive PoolLifetimeMinutes is configured below.
        var handler = new SocketsHttpHandler();

        // TLS options travel from the handler (see ConnectTelemetry): pass the handler's
        // SslOptions so EVERY connection clones the current values into a per-connection
        // model (the shared handler options are never mutated at runtime). A trust
        // callback set by tests reaches the handshake; production keeps it null so the
        // default chain validation applies.
        handler.ConnectCallback = new ConnectTelemetry(
            route.Name,
            policy.BufferCapacity,
            _recorder,
            _lastObservation,
            _lastEnforcement,
            _logger,
            handler.SslOptions).ConnectAsync;

        if (policy.PoolLifetimeMinutes is int minutes and > 0)
        {
            handler.PooledConnectionLifetime = TimeSpan.FromMinutes(minutes);
        }

        // Same per-request timeout contract as the default client above: the instance
        // Timeout stays InfiniteTimeSpan and the caller (ProxyMiddleware) applies the
        // deadline per request via a linked CancellationTokenSource.
        var httpClient = new HttpClient(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
        return new CachedClient(route.Name, policy, handler, httpClient);
    }

    /// <summary>
    /// Config identity for the cache: upstream + every policy field that changes the
    /// handshake/connection behavior. A change (hot reload) yields a new key -> new client.
    /// </summary>
    private static string BuildConfigKey(RouteOptions route, TransportPolicy policy)
        => string.Join("|",
            route.Upstream ?? string.Empty,
            policy.Enabled,
            policy.BufferCapacity,
            policy.Enforce,
            policy.PoolLifetimeMinutes?.ToString() ?? string.Empty,
            string.Join(",", policy.ExpectedIps ?? Array.Empty<string>()),
            policy.TlsFloor ?? string.Empty,
            policy.GraceDays,
            string.Join(",", policy.Pins ?? Array.Empty<string>()),
            policy.ProbeHours);

    /// <summary>True when the route talks HTTPS (only those routes get the attested callback).</summary>
    private static bool UsesHttpsUpstream(RouteOptions route)
        => Uri.TryCreate(route.Upstream, UriKind.Absolute, out var uri)
           && string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The cache is keyed by config hash, so a hot-reloaded policy creates a fresh entry
    /// while the old one lingers. Keep the dictionary bounded: when it grows past
    /// <see cref="MaxCachedClients"/>, drop every entry that is not the current key.
    /// </summary>
    private void PruneIfNeeded(string currentKey)
    {
        if (_clients.Count <= MaxCachedClients)
        {
            return;
        }

        foreach (var kv in _clients)
        {
            if (string.Equals(kv.Key, currentKey, StringComparison.Ordinal))
            {
                continue;
            }

            if (kv.Value.IsValueCreated)
            {
                try
                {
                    kv.Value.Value.Client.Dispose();
                }
                catch
                {
                    // Best effort - a disposed client is never used again (removed below).
                }
            }

            _clients.TryRemove(kv.Key, out _);
        }
    }

    private sealed class CachedClient
    {
        public string RouteName { get; }
        public TransportPolicy Policy { get; }
        public SocketsHttpHandler Handler { get; }
        public HttpClient Client { get; }

        public CachedClient(string routeName, TransportPolicy policy, SocketsHttpHandler handler, HttpClient client)
        {
            RouteName = routeName;
            Policy = policy;
            Handler = handler;
            Client = client;
        }
    }
}
