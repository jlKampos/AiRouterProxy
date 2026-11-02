namespace AIRouterProxy;

/// <summary>
/// Route resolution (Item 2). Pure module, no middleware dependencies, so it can be
/// tested in isolation: the test harness links this file directly.
/// </summary>
public static class RouteResolver
{
    /// <summary>Resolution result: the winning route + rewritten path + effective key.</summary>
    public sealed record Resolved(RouteOptions Route, string RewrittenPath, string? Key);

    /// <summary>
    /// Finds the route with the longest prefix that matches the path (segment boundary),
    /// rewrites the path by removing the prefix and resolves the key.
    /// Returns null if no route matches (404).
    /// </summary>
    public static Resolved? Resolve(
        IReadOnlyList<RouteOptions> routes,
        IReadOnlyDictionary<string, string> routeKeys,
        string path,
        string? fallbackKey = null)
    {
        RouteOptions? best = null;
        var bestLength = -1;

        foreach (var route in routes)
        {
            var prefix = route.Prefix ?? string.Empty;
            if (!PathMatchesPrefix(path, prefix))
            {
                continue;
            }

            if (prefix.Length > bestLength)
            {
                bestLength = prefix.Length;
                best = route;
            }
        }

        if (best is null)
        {
            return null;
        }

        var rewritten = RewritePath(path, best.Prefix ?? string.Empty);
        var key = GetRouteKey(best, routeKeys, fallbackKey);

        return new Resolved(best, rewritten, key);
    }

    /// <summary>
    /// Matches a path against a prefix. "" matches everything (default route). Non-default
    /// matches the exact prefix or prefix + "/" (e.g. "/openrouter" matches "/openrouter/v1/models", not "/openrouterX").
    /// </summary>
    public static bool PathMatchesPrefix(string path, string prefix)
    {
        if (string.IsNullOrEmpty(prefix))
        {
            return true;
        }

        if (!path.StartsWith(prefix, StringComparison.Ordinal))
        {
            return false;
        }

        return path.Length == prefix.Length || path[prefix.Length] == '/';
    }

    /// <summary>Removes the route prefix from the path; prefix "" returns the path as-is.</summary>
    public static string RewritePath(string path, string prefix)
    {
        if (string.IsNullOrEmpty(prefix))
        {
            return path;
        }

        return path[prefix.Length..];
    }

    /// <summary>
    /// Route key: uses <see cref="RouteOptions.KeyRef"/> in the routeKeys; if the route has no
    /// keyRef (default), uses the fallback key (global UpstreamKey). Returns null = inactive route.
    /// </summary>
    public static string? GetRouteKey(
        RouteOptions route,
        IReadOnlyDictionary<string, string> routeKeys,
        string? fallbackKey = null)
    {
        if (string.IsNullOrWhiteSpace(route.KeyRef))
        {
            return string.IsNullOrWhiteSpace(fallbackKey) ? null : fallbackKey;
        }

        return routeKeys.TryGetValue(route.KeyRef!, out var key) && !string.IsNullOrWhiteSpace(key)
            ? key
            : null;
    }

    /// <summary>
    /// Checks whether the path is in the route's allowed list. Empty list = accepts everything.
    /// Supports a "*" suffix (e.g. "/v1/*" matches any "/v1/...").
    /// </summary>
    public static bool IsPathAllowed(IReadOnlyList<string> allowedPaths, string path)
    {
        if (allowedPaths is null || allowedPaths.Count == 0)
        {
            return true;
        }

        foreach (var allowed in allowedPaths)
        {
            if (string.IsNullOrWhiteSpace(allowed))
            {
                continue;
            }

            if (allowed.EndsWith('*'))
            {
                var prefix = allowed[..^1].TrimEnd('/');
                if (prefix.Length == 0
                    || path == prefix
                    || path.StartsWith(prefix + "/", StringComparison.Ordinal))
                {
                    return true;
                }
            }
            else if (string.Equals(allowed, path, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }
}
