using Microsoft.Extensions.Options;

namespace AIRouterProxy;

/// <summary>One route the endpoint probe should keep fresh (metadata only).</summary>
public sealed record ProbeTarget(string Route, string Upstream, int ProbeHours);

/// <summary>
/// Resolves the effective transport-attestation policy per route, layering the
/// per-route <c>routes.json → transport</c> section over the global
/// <c>Proxy.Transport</c> defaults. Re-read per request (IOptionsMonitor), so a hot
/// reload of routes.json applies immediately. Returns null = attestation disabled for
/// the route (default: off - full compatibility with pre-attestation behavior).
/// </summary>
public sealed class TransportPolicyProvider
{
    private readonly IOptionsMonitor<ProxyOptions> _options;

    public TransportPolicyProvider(IOptionsMonitor<ProxyOptions> options)
        => _options = options;

    /// <summary>Current effective options (routes + globals), for the probe/target scans.</summary>
    public ProxyOptions Current => _options.CurrentValue;

    /// <summary>Upstream base of a route (or null/empty when unknown) - for on-demand probes.</summary>
    public string? UpstreamOf(string routeName)
        => _options.CurrentValue.Routes
            ?.FirstOrDefault(r => string.Equals(r.Name, routeName, StringComparison.Ordinal))
            ?.Upstream;

    /// <summary>
    /// Effective policy for a route, or null when the route does not exist or has no
    /// active attestation. Per-route <see cref="RouteTransportOptions.Enabled"/> (bool?)
    /// inherits the global <see cref="TransportOptions.Enabled"/> when null.
    /// </summary>
    public TransportPolicy? ForRoute(string routeName)
    {
        if (string.IsNullOrWhiteSpace(routeName))
        {
            return null;
        }

        var o = _options.CurrentValue;
        var route = o.Routes?.FirstOrDefault(r => string.Equals(r.Name, routeName, StringComparison.Ordinal));
        if (route is null)
        {
            return null;
        }

        var global = o.Transport ?? new TransportOptions();
        var routeTransport = route.Transport;

        // null inherits the global switch; default global = false => disabled (compat).
        if (!(routeTransport?.Enabled ?? global.Enabled))
        {
            return null;
        }

        var capacity = Math.Clamp(global.BufferCapacity, TransportStore.MinCapacity, TransportStore.MaxCapacity);

        return new TransportPolicy(
            Enabled: true,
            BufferCapacity: capacity,
            Enforce: string.IsNullOrWhiteSpace(routeTransport?.Enforce)
                ? "observe"
                : routeTransport!.Enforce,
            PoolLifetimeMinutes: routeTransport?.PoolLifetimeMinutes,
            ExpectedIps: routeTransport?.ExpectedIps ?? new List<string>(),
            TlsFloor: routeTransport?.TlsFloor,
            GraceDays: routeTransport?.GraceDays > 0 ? routeTransport!.GraceDays : 7,
            Pins: routeTransport?.Pins ?? new List<string>(),
            ProbeHours: routeTransport?.ProbeHours > 0 ? routeTransport!.ProbeHours : 0);
    }

    /// <summary>
    /// Every route whose policy is active with probeHours &gt; 0 - the periodic-probe
    /// schedule (see <see cref="EndpointProbe"/>).
    /// </summary>
    public IReadOnlyList<ProbeTarget> GetProbeTargets()
    {
        var targets = new List<ProbeTarget>();
        foreach (var route in _options.CurrentValue.Routes ?? new List<RouteOptions>())
        {
            var policy = ForRoute(route.Name);
            if (policy is not null && policy.ProbeHours > 0 && !string.IsNullOrWhiteSpace(route.Upstream))
            {
                targets.Add(new ProbeTarget(route.Name, route.Upstream, policy.ProbeHours));
            }
        }

        return targets;
    }

    /// <summary>Global defaults (capacity etc.), for the UI / ring-buffer sizing.</summary>
    public TransportPolicy Global
    {
        get
        {
            var global = _options.CurrentValue.Transport ?? new TransportOptions();
            return new TransportPolicy(
                Enabled: global.Enabled,
                BufferCapacity: Math.Clamp(global.BufferCapacity, TransportStore.MinCapacity, TransportStore.MaxCapacity),
                Enforce: "observe",
                PoolLifetimeMinutes: null,
                ExpectedIps: Array.Empty<string>(),
                TlsFloor: null,
                GraceDays: 7,
                Pins: Array.Empty<string>(),
                ProbeHours: 0);
        }
    }
}
