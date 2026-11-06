namespace AIRouterProxy;

/// <summary>
/// Pure authentication decision module (testable in isolation; the test harness links
/// this file directly). Decides whether a presented local key is accepted.
/// Comparisons are constant-time (<see cref="SecurityHelpers.SecureEquals"/>), one per
/// configured key, so that even with multiple keys no timing signal reveals a match length.
/// </summary>
public static class AuthenticationPolicy
{
    /// <summary>
    /// Accepts the presented key if it matches the single <see cref="KeyOptions.LocalKey"/>
    /// or any entry in <see cref="KeyOptions.LocalKeys"/>.
    /// </summary>
    public static bool IsValidLocalKey(string? presented, KeyOptions? keys)
    {
        if (string.IsNullOrEmpty(presented) || keys is null)
        {
            return false;
        }

        if (SecurityHelpers.SecureEquals(presented, keys.LocalKey))
        {
            return true;
        }

        if (keys.LocalKeys is { Count: > 0 })
        {
            foreach (var candidate in keys.LocalKeys)
            {
                if (SecurityHelpers.SecureEquals(presented, candidate))
                {
                    return true;
                }
            }
        }

        return false;
    }

    /// <summary>
    /// Admin privilege check: accepts ONLY the primary <see cref="KeyOptions.LocalKey"/>.
    /// Extra local keys (<see cref="KeyOptions.LocalKeys"/>, e.g. one per engineer) and
    /// route/upstream keys are deliberately NOT accepted, so engineers can use the proxied
    /// API (the /v1/* paths) without gaining access to /admin.
    /// Comparison is constant-time (<see cref="SecurityHelpers.SecureEquals"/>), like
    /// <see cref="IsValidLocalKey"/>.
    /// </summary>
    public static bool IsValidAdminKey(string? presented, KeyOptions? keys)
    {
        if (string.IsNullOrEmpty(presented) || keys is null)
        {
            return false;
        }

        return SecurityHelpers.SecureEquals(presented, keys.LocalKey);
    }

    /// <summary>Number of accepted local keys (1 primary + extra). Used in logs: with more than
    /// one key the "expected hash" is ambiguous, so logs stop printing a single ExpectedHash.</summary>
    public static int LocalKeyCount(KeyOptions? keys)
    {
        if (keys is null)
        {
            return 0;
        }

        return 1 + (keys.LocalKeys?.Count ?? 0);
    }
}
