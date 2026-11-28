using System.Collections.Concurrent;
using System.Net.Security;
using Microsoft.Extensions.Logging;

namespace AIRouterProxy;

/// <summary>Outcome of one recorded handshake: the row stored + the enforcement decision.</summary>
public sealed record RecordedAttestation(TransportObservation Observation, EnforceResult Enforcement);

/// <summary>
/// Shared recording + enforcement pipeline for EVERY completed TLS handshake - the
/// request path (via <see cref="ConnectTelemetry"/>) and the periodic/on-demand probes
/// (via <see cref="EndpointProbe"/>). Per connection it:
/// 1. resolves the CURRENT policy from the provider (hot reload - consulted per connect);
/// 2. captures metadata via <see cref="TransportCapture"/>;
/// 3. evaluates pins / expected IPs / TLS floor (<see cref="EnforcePolicy"/>);
/// 4. records the in-memory ring + the durable baseline;
/// 5. fires deduped drift alerts (Event Log) when something drifted.
/// The connect path turns a "block" action into an <see cref="AttestationException"/>;
/// the probe path never blocks (it only observes). Metadata only - never content, never keys.
/// </summary>
public sealed class AttestationRecorder
{
    /// <summary>Effective pin cap: union(config pins + learned pins), config first.</summary>
    public const int MaxEffectivePins = 5;

    private readonly TransportPolicyProvider _policies;
    private readonly LearnedPinStore _learnedPins;
    private readonly DriftStore _drift;
    private readonly TransportStore _store;
    private readonly BaselineStore _baseline;
    private readonly ILogger _logger;

    public AttestationRecorder(
        TransportPolicyProvider policies,
        LearnedPinStore learnedPins,
        DriftStore drift,
        TransportStore store,
        BaselineStore baseline,
        ILogger<AttestationRecorder> logger)
    {
        _policies = policies;
        _learnedPins = learnedPins;
        _drift = drift;
        _store = store;
        _baseline = baseline;
        _logger = logger;
    }

    /// <summary>
    /// Captures + records one handshake. Returns null when nothing was capturable
    /// (cert/SPKI unusable) - the caller then records nothing, exactly like Phase 1.
    /// </summary>
    public RecordedAttestation? Record(
        SslStream ssl,
        string route,
        string host,
        string ip,
        int port,
        DateTimeOffset now,
        int bufferCapacity,
        ConcurrentDictionary<string, TransportObservation?>? lastByRoute)
    {
        if (!TransportCapture.TryCapture(ssl, route, host, ip, port, now, out var identity, out var observation))
        {
            return null;
        }

        // Consulted per connect: a hot-reloaded routes.json/global section applies to the
        // very next connection (the client cache key still rebuilds handlers per config).
        var policy = _policies.ForRoute(route);
        EnforceResult enforcement;
        if (policy is null)
        {
            enforcement = new EnforceResult(EnforcePolicy.ActionAllow, DriftEvaluator.SeverityNone, string.Empty, PinVerdict.Ok);
        }
        else
        {
            var pins = EffectivePins(policy, route);
            var withinGrace = WithinGrace(policy, route, ip, identity.SpkiHash, now);
            enforcement = EnforcePolicy.Evaluate(policy, pins, identity.SpkiHash, ip, identity.TlsVersion, withinGrace);

            if (enforcement.Severity != DriftEvaluator.SeverityNone
                && _drift.TryAlert(route, ip, enforcement.Reason, enforcement.Severity, now))
            {
                _logger.LogWarning("ATTESTATION DRIFT | Route={Route} Ip={Ip} Reason={Reason}", route, ip, enforcement.Reason);
            }
        }

        var status = enforcement.Action switch
        {
            EnforcePolicy.ActionWarn => "warn",
            EnforcePolicy.ActionBlock => "blocked",
            _ => "observed",
        };
        observation = observation with { Status = status };

        if (lastByRoute is not null)
        {
            lastByRoute[route] = observation;
        }

        _store.Add(observation, bufferCapacity);
        _baseline.Record(identity);

        return new RecordedAttestation(observation, enforcement);
    }

    /// <summary>
    /// Effective pins for a route: config pins first (the operator's explicit choices),
    /// then learned pins (admin "accept"), canonicalized, deduped and capped at 5.
    /// </summary>
    public IReadOnlyList<string> EffectivePins(TransportPolicy policy, string route)
        => EffectivePins(policy, route, _learnedPins.GetForRoute(route));

    public static IReadOnlyList<string> EffectivePins(
        TransportPolicy? policy,
        string route,
        IReadOnlyList<string>? learnedPins)
    {
        var result = new List<string>(Math.Min(MaxEffectivePins, (policy?.Pins?.Count ?? 0) + 1));

        void AddFrom(IEnumerable<string> source)
        {
            foreach (var value in source)
            {
                if (result.Count == MaxEffectivePins)
                {
                    return; // cap reached: later sources must not add beyond it
                }

                if (string.IsNullOrWhiteSpace(value))
                {
                    continue;
                }

                var canonical = TransportHashes.NormalizePin(value);
                if (canonical is null || result.Contains(canonical, StringComparer.Ordinal))
                {
                    continue;
                }

                result.Add(canonical);
                if (result.Count == MaxEffectivePins)
                {
                    return;
                }
            }
        }

        AddFrom(policy?.Pins ?? Array.Empty<string>());
        AddFrom(learnedPins ?? Array.Empty<string>());
        return result;
    }

    /// <summary>
    /// True when the endpoint is inside its grace window: known endpoints use their
    /// baseline FirstSeen; a brand-new endpoint (not in the baseline) counts as within
    /// grace (its first observation happens NOW), so a legitimate cert rotation is never
    /// blocked immediately - it is flagged low until the operator accepts or the window passes.
    /// </summary>
    private bool WithinGrace(TransportPolicy policy, string route, string ip, string spki, DateTimeOffset now)
    {
        var graceDays = policy.GraceDays > 0 ? policy.GraceDays : 7;
        var group = _baseline.GetRoute(route);

        DateTimeOffset? firstSeen = null;
        if (group is not null)
        {
            foreach (var entry in group.Entries)
            {
                if (string.Equals(entry.Ip, ip, StringComparison.Ordinal)
                    && string.Equals(entry.SpkiHash, spki, StringComparison.Ordinal))
                {
                    firstSeen = entry.FirstSeen;
                    break;
                }
            }
        }

        var seen = firstSeen ?? now;
        return now - seen <= TimeSpan.FromDays(graceDays);
    }
}
