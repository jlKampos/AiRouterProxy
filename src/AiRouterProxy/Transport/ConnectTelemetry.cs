using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;

namespace AIRouterProxy;

/// <summary>
/// Phase 1 + 2 of Transport/Endpoint Attestation: owns the manual socket + TLS handshake
/// for one route's outbound connections, records what actually answered (remote IP, cert
/// fingerprints, TLS version/cipher/ALPN - metadata only) AND enforces the Phase 2
/// policy on the handshake result (warn tags the response; block aborts the connection,
/// which the middleware maps to HTTP 526).
///
/// Design notes:
/// - The TLS handshake is performed HERE (manual SslStream) precisely so Phase 2 can
///   enforce pins / expected IPs / TLS floor at this point without touching the pipeline.
/// - On .NET 10 the SocketsHttpConnectionContext no longer exposes SslOptions, so the
///   TLS options travel from the handler instead: TransportClientFactory passes the
///   handler's SslOptions to this class, and every connection clones the CURRENT
///   values into a per-connection model (the shared handler options are never mutated)
///   before applying the per-connection TargetHost and an ALPN list coherent with the
///   request version.
/// - The default remote-certificate chain validation is preserved: ValidationCallback
///   is null (production) - an untrusted server cert fails the handshake exactly like
///   the pre-attestation pipeline. (The tests set it to trust a local self-signed cert.)
/// - A failed handshake propagates the exception (the middleware maps it to 502) and
///   records NO observation. A SUCCESSFUL handshake that fails attestation (block)
///   propagates an <see cref="AttestationException"/> (middleware -> 526) AFTER the
///   observation was recorded, so the unexpected endpoint is visible for review/accept.
/// - The connect callback only exists on per-route clients whose policy is active;
///   routes without an active policy use the shared default handler (no callback at all).
/// - The policy itself is consulted PER CONNECTION (via <see cref="AttestationRecorder"/>),
///   so a hot-reloaded routes.json applies to the very next connection.
/// </summary>
public sealed class ConnectTelemetry
{
    private readonly string _routeName;
    private readonly int _bufferCapacity;
    private readonly AttestationRecorder _recorder;
    private readonly ConcurrentDictionary<string, TransportObservation?> _lastByRoute;
    private readonly ConcurrentDictionary<string, string?> _lastEnforcement;
    private readonly ILogger _logger;
    private readonly SslClientAuthenticationOptions _sslModel;

    public ConnectTelemetry(
        string routeName,
        int bufferCapacity,
        AttestationRecorder recorder,
        ConcurrentDictionary<string, TransportObservation?> lastByRoute,
        ConcurrentDictionary<string, string?> lastEnforcement,
        ILogger logger,
        SslClientAuthenticationOptions? sslModel = null)
    {
        _routeName = routeName;
        _bufferCapacity = bufferCapacity;
        _recorder = recorder;
        _lastByRoute = lastByRoute;
        _lastEnforcement = lastEnforcement;
        _logger = logger;
        _sslModel = sslModel ?? new SslClientAuthenticationOptions();
    }

    /// <summary>
    /// Test hook: when set, it overrides the remote-certificate validation (the unit
    /// harness trusts a local self-signed server cert). Production keeps it null, so the
    /// default chain validation applies and untrusted certificates FAIL the handshake.
    /// </summary>
    public RemoteCertificateValidationCallback? ValidationCallback { get; set; }

    /// <summary>SocketsHttpHandler.ConnectCallback: manual connect + TLS + capture.</summary>
    public async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        // 1. Manual TCP connect. Socket.ConnectAsync(DnsEndPoint) resolves the host async
        //    (Dns.GetHostAddressesAsync semantics) trying each address in order, preserving
        //    IPv4 + IPv6. The real endpoint actually used is read back from the socket.
        //    NOTE: no `using` on the socket - once the connect succeeds, ownership
        //    transfers to the NetworkStream (ownsSocket: true) and then to the SslStream;
        //    disposing it after that point would kill the connection. But when the connect
        //    itself throws (DNS failure / refused / timeout / cancellation), the socket
        //    never reached a stream owner, so it is disposed HERE (before the NetworkStream
        //    is created) to avoid a leaked handle until GC. No double-dispose: after this
        //    try/catch the socket belongs to the NetworkStream.
        var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
        try
        {
            await socket.ConnectAsync(context.DnsEndPoint, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            socket.Dispose();
            throw;
        }

        var remote = socket.RemoteEndPoint as IPEndPoint;
        var ip = remote?.Address.ToString() ?? string.Empty;
        var port = remote?.Port ?? 0;
        var host = context.DnsEndPoint.Host;

        // 2. TLS with the handler's defaults (cloned per connection - never mutate the
        //    shared model), TargetHost preserved for name matching and an ALPN list that
        //    mirrors the default SocketsHttpHandler behavior for the request version.
        var tlsOptions = CloneSslOptions(_sslModel);
        tlsOptions.TargetHost = host;
        tlsOptions.ApplicationProtocols = AlpnFor(context);

        // The handler-sourced validation callback (carried by the cloned SslOptions) is
        // preserved; the test hook only overrides it when explicitly set.
        if (ValidationCallback is not null)
        {
            tlsOptions.RemoteCertificateValidationCallback = ValidationCallback;
        }

        var transport = new NetworkStream(socket, ownsSocket: true);
        var ssl = new SslStream(transport, leaveInnerStreamOpen: false);
        try
        {
            await ssl.AuthenticateAsClientAsync(tlsOptions, cancellationToken).ConfigureAwait(false);

            // 3. Capture + enforce + record (metadata only) - runs only after a SUCCESSFUL
            //    authentication. A "block" verdict throws AttestationException, which the
            //    middleware maps to HTTP 526 (the unexpected endpoint was ALREADY recorded,
            //    so the operator can review and accept it).
            TryRecord(ssl, ip, port, host);

            // The SslStream becomes the transport stream: HttpClient owns and disposes it
            // when the pooled connection closes (leaveInnerStreamOpen: false => the inner
            // NetworkStream/socket go down with it).
            return ssl;
        }
        catch
        {
            // A failed handshake OR a block verdict (TryRecord -> AttestationException)
            // must propagate, and the stream chain must be disposed NOW: HttpClient never
            // receives the stream when the callback throws (SocketsHttpHandler wraps the
            // exception), so without this dispose the socket would leak once per failed
            // handshake / blocked connection. The success path is untouched.
            await ssl.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    private void TryRecord(SslStream ssl, string ip, int port, string host)
    {
        try
        {
            var now = DateTimeOffset.UtcNow;
            var recorded = _recorder.Record(ssl, _routeName, host, ip, port, now, _bufferCapacity, _lastByRoute);
            if (recorded is null)
            {
                return;
            }

            // Phase 2: surface the enforcement outcome of THIS connection so the
            // middleware can tag the response (warn header) and the activity log.
            // Same documented race as LastObservationSummary: concurrent requests of the
            // same route overwrite; per-request correlation is intentionally not attempted.
            _lastEnforcement[_routeName] = EnforcePolicy.HeaderFor(_routeName, recorded.Enforcement);

            if (recorded.Enforcement.Action == EnforcePolicy.ActionBlock)
            {
                throw new AttestationException(_routeName, recorded.Enforcement.Reason);
            }
        }
        catch (AttestationException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning("Transport observation failed | Route={Route} Error={Error}", _routeName, ex.Message);
        }
    }

    /// <summary>
    /// ALPN list mirroring the default SocketsHttpHandler behavior (.NET 10): HTTP/2
    /// requests offer "h2" then "http/1.1"; HTTP/1.1 requests send NO ALPN list (null) -
    /// an explicit http/1.1 offer can be rejected by strict servers, the default never is.
    /// </summary>
    private static List<SslApplicationProtocol>? AlpnFor(SocketsHttpConnectionContext context)
    {
        var version = context.InitialRequestMessage?.Version;
        return version is { Major: >= 2 }
            ? new List<SslApplicationProtocol> { SslApplicationProtocol.Http2, SslApplicationProtocol.Http11 }
            : null;
    }

    /// <summary>
    /// Clone of the handler-sourced TLS model. Every field the handler default sets is
    /// carried over; the shared model itself is never mutated (the clone is per connection).
    /// </summary>
    private static SslClientAuthenticationOptions CloneSslOptions(SslClientAuthenticationOptions source)
    {
        if (source is null)
        {
            return new SslClientAuthenticationOptions();
        }

        var clone = new SslClientAuthenticationOptions
        {
            TargetHost = source.TargetHost,
            ClientCertificates = source.ClientCertificates,
            EnabledSslProtocols = source.EnabledSslProtocols,
            LocalCertificateSelectionCallback = source.LocalCertificateSelectionCallback,
            AllowRenegotiation = source.AllowRenegotiation,
            EncryptionPolicy = source.EncryptionPolicy,
            CipherSuitesPolicy = source.CipherSuitesPolicy,
            RemoteCertificateValidationCallback = source.RemoteCertificateValidationCallback,
            CertificateRevocationCheckMode = source.CertificateRevocationCheckMode,
            ApplicationProtocols = source.ApplicationProtocols,
        };

        // Copying X509CertificateCollection is not trivially cloneable; assign the same
        // reference (read-only during the handshake, never mutated here).
        if (source.ClientCertificates is not null)
        {
            clone.ClientCertificates = source.ClientCertificates;
        }

        // X509ChainPolicy is a mutable policy object; share the reference (never mutated
        // during the handshake) - same trade as ClientCertificates above.
        if (source.CertificateChainPolicy is not null)
        {
            clone.CertificateChainPolicy = source.CertificateChainPolicy;
        }

        return clone;
    }
}
