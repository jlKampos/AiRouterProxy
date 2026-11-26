using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AIRouterProxy;

/// <summary>
/// Periodic + on-demand TLS baseline probe (Phase 2). Every route whose policy is active
/// with <c>probeHours &gt; 0</c> is re-probed on that cadence: a plain TCP+TLS connect,
/// then close - NO request is ever sent upstream. The handshake runs the same recording
/// pipeline as real traffic (<see cref="AttestationRecorder"/>), so the durable baseline
/// and the drift feed stay fresh even for routes without traffic. Probe failures are
/// logged and never affect traffic; the probe never blocks an endpoint.
/// </summary>
public sealed class EndpointProbe : BackgroundService
{
    /// <summary>Fixed wall-clock cadence at which the timer checks which routes are due.</summary>
    private static readonly TimeSpan TickInterval = TimeSpan.FromMinutes(15);

    private readonly TransportPolicyProvider _policies;
    private readonly AttestationRecorder _recorder;
    private readonly ILogger<EndpointProbe> _logger;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _lastProbe = new(StringComparer.Ordinal);

    public EndpointProbe(
        TransportPolicyProvider policies,
        AttestationRecorder recorder,
        ILogger<EndpointProbe> logger)
    {
        _policies = policies;
        _recorder = recorder;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TickInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                await ProbeDueAsync(DateTimeOffset.UtcNow, stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            // Shutdown: the background loop ends silently.
        }
    }

    /// <summary>
    /// Probes every route whose policy is active with probeHours &gt; 0 and due.
    /// Returns the number of probes whose handshake was captured and recorded
    /// (failures are logged but not counted).
    /// </summary>
    public async Task<int> ProbeDueAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        var attempts = 0;
        foreach (var target in _policies.GetProbeTargets())
        {
            if (_lastProbe.TryGetValue(target.Route, out var last)
                && now - last < TimeSpan.FromHours(target.ProbeHours))
            {
                continue;
            }

            if (await ProbeRouteAsync(target.Route, target.Upstream, cancellationToken))
            {
                attempts++;
            }
        }

        return attempts;
    }

    /// <summary>On-demand probe of one route (admin "learn now"); false when the route is unknown or the probe failed.</summary>
    public Task<bool> ProbeRouteAsync(string routeName, CancellationToken cancellationToken = default)
    {
        var upstream = _policies.UpstreamOf(routeName);
        return string.IsNullOrWhiteSpace(upstream)
            ? Task.FromResult(false)
            : ProbeRouteAsync(routeName, upstream, cancellationToken);
    }

    private async Task<bool> ProbeRouteAsync(string routeName, string upstream, CancellationToken cancellationToken)
    {
        try
        {
            if (!Uri.TryCreate(upstream, UriKind.Absolute, out var uri) || string.IsNullOrWhiteSpace(uri.Host))
            {
                return false;
            }

            var host = uri.Host;
            var port = uri.IsDefaultPort
                ? (uri.Scheme == Uri.UriSchemeHttps ? 443 : 80)
                : uri.Port;

            // Manual TCP + TLS, then close. No HTTP request is ever made.
            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            await socket.ConnectAsync(new DnsEndPoint(host, port), cancellationToken).ConfigureAwait(false);

            var remote = socket.RemoteEndPoint as IPEndPoint;
            var ip = remote?.Address.ToString() ?? string.Empty;
            var actualPort = remote?.Port ?? 0;

            var tlsOptions = new SslClientAuthenticationOptions
            {
                TargetHost = host,
                // Default certificate validation, like production traffic: an untrusted
                // upstream fails the probe exactly as it would fail a real request.
            };

            using var transport = new NetworkStream(socket, ownsSocket: true);
            using var ssl = new SslStream(transport, leaveInnerStreamOpen: false);
            await ssl.AuthenticateAsClientAsync(tlsOptions, cancellationToken).ConfigureAwait(false);

            var policy = _policies.ForRoute(routeName);
            var recorded = _recorder.Record(
                ssl,
                routeName,
                host,
                ip,
                actualPort,
                DateTimeOffset.UtcNow,
                policy?.BufferCapacity ?? TransportStore.DefaultCapacity,
                lastByRoute: null);

            _lastProbe[routeName] = DateTimeOffset.UtcNow;
            return recorded is not null;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Attestation probe failed | Route={Route} Error={Error}", routeName, ex.Message);
            return false;
        }
    }
}
