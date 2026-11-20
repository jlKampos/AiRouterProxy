using AiRouterProxy.Dashboard.Models;

namespace AiRouterProxy.AdminValidation;

/// <summary>
/// Validation of the route table before it is written to routes.json. Mirrors the
/// startup validation in Program.cs.ValidateRoutes (name required, prefix starts with
/// '/', unique prefixes, absolute http/https upstream) and extends it with the
/// dashboard rules: at most one "" (default) prefix, segment-boundary-aware prefix
/// conflicts, coherent allowed paths, reserved header names, and keyRef references
/// that must resolve to a declared route key.
/// </summary>
public static class RouteValidator
{
    /// <summary>
    /// Known keyRefs = every keyRef declared in the server config (RouteKeys dictionary
    /// keys - presence, not the value). <paramref name="configuredKeyRefs"/> (optional)
    /// is the subset whose secret value is actually set; a route whose keyRef is declared
    /// but left without a value is inactive until the key is written.
    /// </summary>
    public static void Validate(
        IReadOnlyList<RouteDraft> routes,
        ISet<string> knownKeyRefs,
        out List<string> errors,
        out List<string> warnings,
        ISet<string>? configuredKeyRefs = null)
    {
        errors = new List<string>();
        warnings = new List<string>();
        if (routes is null || routes.Count == 0)
        {
            return;
        }

        var names = new HashSet<string>(StringComparer.Ordinal);
        var prefixes = new List<(string Prefix, string Name)>();

        foreach (var route in routes)
        {
            var name = route.Name ?? string.Empty;
            if (string.IsNullOrWhiteSpace(name))
            {
                errors.Add("Route name is required (every route needs a 'name').");
            }
            else if (!names.Add(name))
            {
                errors.Add($"Route name '{name}' is duplicated.");
            }

            var prefix = route.Prefix ?? string.Empty;
            if (prefix.Length > 0 && !prefix.StartsWith('/'))
            {
                errors.Add($"Route '{NameOf(route)}': prefix must start with '/' ('{prefix}').");
            }

            prefixes.Add((prefix, name));

            var upstream = route.Upstream ?? string.Empty;
            if (string.IsNullOrWhiteSpace(upstream)
                || !Uri.TryCreate(upstream, UriKind.Absolute, out var parsed)
                || (parsed.Scheme != Uri.UriSchemeHttps && parsed.Scheme != Uri.UriSchemeHttp))
            {
                errors.Add($"Route '{NameOf(route)}': upstream must be an absolute http/https URL.");
            }

            foreach (var path in route.SafePaths)
            {
                if (string.IsNullOrWhiteSpace(path))
                {
                    errors.Add($"Route '{NameOf(route)}': allowed paths must not be empty.");
                }
            }

            foreach (var (key, _) in route.SafeHeaders)
            {
                if (string.IsNullOrWhiteSpace(key))
                {
                    errors.Add($"Route '{NameOf(route)}': header names must not be empty.");
                    continue;
                }

                if (HeaderReserved.Contains(key))
                {
                    errors.Add($"Route '{NameOf(route)}': header '{key}' is reserved (the proxy injects it itself).");
                }
            }

            var keyRef = route.KeyRef;
            if (!string.IsNullOrEmpty(keyRef))
            {
                if (knownKeyRefs is null || !knownKeyRefs.Contains(keyRef))
                {
                    errors.Add($"Route '{NameOf(route)}': keyRef '{keyRef}' does not exist - add the key in the Keys panel first.");
                }
                else if (configuredKeyRefs is not null && !configuredKeyRefs.Contains(keyRef))
                {
                    warnings.Add($"Route '{NameOf(route)}' (keyRef '{keyRef}') is inactive until the key is set.");
                }
            }
        }

        // At most one default ("") prefix.
        var defaultCount = prefixes.Count(p => p.Prefix.Length == 0);
        if (defaultCount > 1)
        {
            errors.Add("Only one default route (empty prefix) is allowed.");
        }

        // Prefix uniqueness with segment boundary: two prefixes conflict when one is the
        // other followed by '/' (both would match the same incoming paths). Equal prefixes
        // conflict trivially. This is stricter than the startup check (which only detects
        // exact duplicates) on purpose: a nested prefix silently shadows the outer one.
        for (var i = 0; i < prefixes.Count; i++)
        {
            for (var j = i + 1; j < prefixes.Count; j++)
            {
                var a = prefixes[i];
                var b = prefixes[j];
                // The default ("") route coexists with every other route by design.
                if (a.Prefix.Length == 0 || b.Prefix.Length == 0)
                {
                    continue;
                }

                if (PrefixesConflict(a.Prefix, b.Prefix))
                {
                    errors.Add($"Prefix conflict: '{a.Prefix}' (route '{a.Name}') and '{b.Prefix}' (route '{b.Name}') overlap.");
                }
            }
        }
    }

    private static readonly HashSet<string> HeaderReserved = new(StringComparer.OrdinalIgnoreCase)
    {
        "authorization",
        "content-type",
        "accept",
    };

    private static string NameOf(RouteDraft route) => string.IsNullOrWhiteSpace(route.Name) ? "(unnamed)" : route.Name;

    /// <summary>
    /// True when the two non-empty prefixes overlap: one equals the other, or one is the
    /// other followed by a segment boundary ('/'). Both orders are handled.
    /// </summary>
    private static bool PrefixesConflict(string a, string b)
    {
        if (string.Equals(a, b, StringComparison.Ordinal))
        {
            return true;
        }

        var (shorter, longer) = a.Length < b.Length ? (a, b) : (b, a);
        return longer.StartsWith(shorter, StringComparison.Ordinal) && longer[shorter.Length] == '/';
    }
}
