using System.Diagnostics.CodeAnalysis;

namespace AIRouterProxy;

/// <summary>
/// Pure mapping helper for transport-layer errors (Phase 2 enforcement).
/// <see cref="SocketsHttpHandler"/> wraps exceptions thrown by the ConnectCallback
/// (e.g. <see cref="AttestationException"/> from a "block" verdict) in an
/// <see cref="System.Net.Http.HttpRequestException"/> via
/// ConnectHelper.CreateWrappedException, so a block verdict almost never surfaces as
/// the top-level exception. This helper walks the InnerException chain so the
/// middleware can map it back to HTTP 526 + the attestation header, and so the
/// mapping is unit-testable in isolation.
/// Metadata only - it returns the exception's (route, reason) ids, never content, never keys.
/// </summary>
public static class TransportErrorMapper
{
    /// <summary>
    /// Max chain depth walked, as a guard against pathological exception graphs.
    /// </summary>
    private const int MaxDepth = 16;

    /// <summary>
    /// True when <paramref name="exception"/> (or any exception in its InnerException
    /// chain, up to <see cref="MaxDepth"/>) is an <see cref="AttestationException"/>;
    /// the first one found is returned in <paramref name="attestation"/>.
    /// </summary>
    public static bool TryGetAttestation(Exception? exception, [NotNullWhen(true)] out AttestationException? attestation)
    {
        for (var depth = 0; exception is not null && depth < MaxDepth; depth++)
        {
            if (exception is AttestationException a)
            {
                attestation = a;
                return true;
            }

            exception = exception.InnerException;
        }

        attestation = null;
        return false;
    }
}
