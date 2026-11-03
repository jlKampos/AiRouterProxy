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
