namespace AIRouterProxy;

/// <summary>
/// Outcome of enforcing the effective policy on one observed endpoint (Phase 2).
/// <see cref="Action"/> is the wire behavior ("allow" | "warn" | "block");
/// <see cref="Severity"/> reasons the decision ("none" | "low" | "high");
/// <see cref="Reason"/> is the machine root cause id (empty when severity is none).
/// </summary>
public sealed record EnforceResult(
    string Action,
    string Severity,
    string Reason,
    PinVerdict Verdict);

/// <summary>
/// Combines <see cref="PinValidator"/> + <see cref="DriftEvaluator"/> into the
/// per-connection decision, honoring the alert-first philosophy:
/// - "observe" never changes the wire behavior (drift is still recorded so the
///   operator sees it in the feed / Event Log);
/// - "warn" tags responses with <c>X-AIRouterProxy-Attestation: route:severity</c>;
/// - "block" rejects the connection (HTTP 526) but ONLY for HIGH severity - a grace
///   endpoint (low) is never blocked, and without pins/expectedIps/TLS floor there is
///   nothing to block on.
/// </summary>
public static class EnforcePolicy
{
    public const string ActionAllow = "allow";
    public const string ActionWarn = "warn";
    public const string ActionBlock = "block";

    public static EnforceResult Evaluate(
        TransportPolicy policy,
        IReadOnlyList<string> pins,
        string observedSpki,
        string observedIp,
        string observedTlsVersion,
        bool withinGrace)
    {
        var verdict = PinValidator.Evaluate(pins, observedSpki, withinGrace);
        var (severity, reason) = DriftEvaluator.Evaluate(policy, verdict, observedIp, observedTlsVersion);

        string action = ActionAllow;
        if (severity != DriftEvaluator.SeverityNone)
        {
            if (policy.Enforce == "block" && severity == DriftEvaluator.SeverityHigh)
            {
                action = ActionBlock;
            }
            else if (policy.Enforce is "warn" or "block")
            {
                action = ActionWarn;
            }
            // "observe": drift is recorded, the wire stays untouched.
        }

        return new EnforceResult(action, severity, reason, verdict);
    }

    /// <summary>
    /// Header value the middleware attaches for warn/block (null = no header):
    /// "block" for a rejected connection, "&lt;route&gt;:&lt;severity&gt;" for a warn.
    /// </summary>
    public static string? HeaderFor(string route, EnforceResult result)
        => result.Action switch
        {
            ActionBlock => "block",
            ActionWarn => route + ":" + result.Severity,
            _ => null,
        };
}

/// <summary>
/// Thrown by the attested connect when enforcement decides "block": it surfaces through
/// HttpClient into the middleware, which maps it to HTTP 526 + the attestation header.
/// Carries only metadata (route + reason id) - never request content, never keys.
/// </summary>
public sealed class AttestationException : Exception
{
    public string Route { get; }

    public string Reason { get; }

    public AttestationException(string route, string reason)
        : base($"Upstream endpoint attestation failed (route '{route}', reason '{reason}').")
    {
        Route = route;
        Reason = reason;
    }
}
