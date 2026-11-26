namespace AIRouterProxy;

/// <summary>
/// Outcome of comparing one observed SPKI fingerprint against the pinned set
/// (Phase 2 - Pinning).
/// </summary>
public enum PinVerdict
{
    /// <summary>
    /// The observed SPKI matches a configured/learned pin, or no pins are configured
    /// (nothing to enforce - the policy decides what to do without pins).
    /// </summary>
    Ok,

    /// <summary>
    /// The SPKI is unknown but the endpoint is still inside its grace window
    /// (first seen recently): allowed, but flagged as drift so the operator reviews it.
    /// </summary>
    Grace,

    /// <summary>
    /// The SPKI does not match any pin and the grace window has passed - a hard mismatch.
    /// </summary>
    Mismatch,
}

/// <summary>
/// Pure pin-comparison logic. Pins are canonicalized to the baseline's unpadded
/// base64url SHA-256 format (see <see cref="TransportHashes.NormalizePin"/>), so config
/// pins (64-hex or base64/base64url) and learned pins compare equal to the observed
/// SPKI fingerprints captured by <see cref="TransportCapture"/>.
/// </summary>
public static class PinValidator
{
    /// <summary>
    /// Evaluates the observed SPKI against the effective pin set.
    /// <paramref name="withinGrace"/> is true when the endpoint's first-seen is inside
    /// the policy grace window (a brand-new endpoint counts as within grace until the
    /// window passes, so a legitimately rotated certificate is not blocked immediately).
    /// </summary>
    public static PinVerdict Evaluate(IReadOnlyList<string>? pins, string? observedSpki, bool withinGrace)
    {
        if (pins is null || pins.Count == 0 || string.IsNullOrWhiteSpace(observedSpki))
        {
            // No pins configured (or nothing was captured): nothing to compare.
            return PinVerdict.Ok;
        }

        foreach (var pin in pins)
        {
            if (Matches(pin, observedSpki))
            {
                return PinVerdict.Ok;
            }
        }

        return withinGrace ? PinVerdict.Grace : PinVerdict.Mismatch;
    }

    /// <summary>
    /// True when <paramref name="pin"/> (64-hex or base64/base64url) canonicalizes to the
    /// observed base64url SPKI. Comparison is ordinal - the canonical forms are exact.
    /// </summary>
    public static bool Matches(string? pin, string? observedSpki)
    {
        if (string.IsNullOrWhiteSpace(pin) || string.IsNullOrWhiteSpace(observedSpki))
        {
            return false;
        }

        var canonical = TransportHashes.NormalizePin(pin);
        return canonical is not null
               && string.Equals(canonical, observedSpki.Trim(), StringComparison.Ordinal);
    }
}
