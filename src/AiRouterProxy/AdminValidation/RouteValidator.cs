using AIRouterProxy;
using AiRouterProxy.Dashboard.Models;

namespace AiRouterProxy.AdminValidation;

/// <summary>
/// Validation of the route table before it is written to routes.json. Mirrors the
/// startup validation in Program.cs.ValidateRoutes (name required, prefix starts with
/// '/', unique prefixes, absolute http/https upstream) and extends it with the
/// dashboard rules: at most one "" (default) prefix, segment-boundary-aware prefix
/// conflicts, coherent allowed paths, reserved header names, and keyRef references.
/// A keyRef that is not declared is a <b>warning</b>, not an error: the route still matches
/// incoming requests but the proxy answers 502 for it until the key is declared/set. This
/// mirrors the startup validation (the proxy boots and warns instead of failing) so the
/// dashboard never blocks a table the engine accepts. A malformed keyRef (whitespace or
/// characters outside the keyRef alphabet) IS an error: the kernel would never resolve it
/// as a RouteKeys name and the route would silently fall back to the global key.
/// </summary>
public static class RouteValidator
{
    /// <summary>
    /// Known keyRefs = every keyRef declared in the server config (RouteKeys dictionary
    /// keys - presence, not the value). <paramref name="configuredKeyRefs"/> (optional)
    /// is the subset whose secret value is actually set; a route whose keyRef is declared
    /// but left without a value is inactive until the key is written. A keyRef absent from
    /// <paramref name="knownKeyRefs"/> produces the same kind of warning (inactive until it is
    /// declared in the Keys panel), never an error - the save is not blocked.
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
        // The route-section merge (headers/transport on PUT) and the dashboard rename logic
        // key routes by trimmed name, so "a" and " a " would collide there. Reject the
        // ambiguity at the source instead of resolving it silently in the merge.
        var trimmedNames = new HashSet<string>(StringComparer.Ordinal);
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
            else if (!trimmedNames.Add(name.Trim()))
            {
                errors.Add($"Route name '{name}' is duplicated: route names must be unique (ignoring surrounding whitespace).");
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

                if (RouteHeaders.Reserved.Contains(key))
                {
                    errors.Add($"Route '{NameOf(route)}': header '{key}' is reserved (the proxy injects it itself).");
                }
            }

            var keyRef = route.KeyRef;
            if (!string.IsNullOrEmpty(keyRef))
            {
                if (!KeyValidator.ValidateRef(keyRef, out _))
                {
                    // A whitespace-only ref (" ") is not empty, so the kernel would NOT fall
                    // back to the global key: it would look up a RouteKeys entry that can
                    // never exist (names never contain whitespace) and the route would be
                    // permanently inactive. Reject the shape instead of silently accepting a
                    // key that does not work - and do not also emit the "not declared" warning.
                    errors.Add($"Route '{NameOf(route)}': keyRef '{keyRef}' is invalid - use a valid keyRef name or leave it empty for the global key.");
                }
                else if (knownKeyRefs is null || !knownKeyRefs.Contains(keyRef))
                {
                    // Declaring first is the normal edit order (Add keyRef -> Add route -> Save),
                    // so an unknown ref is not a structural error. The route is saved but stays
                    // inactive (the proxy returns 502 for it) until the keyRef exists and has a key.
                    warnings.Add($"Route '{NameOf(route)}' (keyRef '{keyRef}') is inactive until the keyRef is declared in the Keys panel (Add keyRef) and a key is set.");
                }
                else if (configuredKeyRefs is not null && !configuredKeyRefs.Contains(keyRef))
                {
                    warnings.Add($"Route '{NameOf(route)}' (keyRef '{keyRef}') is inactive until the key is set.");
                }
            }

            ValidateTransport(route, errors);
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

    // ----------------------------------------------------------
    // Per-route transport section (Phase 2 - pinning + drift). Stricter than the
    // startup validation on purpose: the dashboard must not persist a section the
    // proxy would silently ignore.
    // ----------------------------------------------------------

    private static void ValidateTransport(RouteDraft route, List<string> errors)
    {
        var t = route.Transport;
        if (t is null)
        {
            return;
        }

        var name = NameOf(route);

        if (!string.IsNullOrWhiteSpace(t.Enforce) && t.Enforce is not ("observe" or "warn" or "block"))
        {
            errors.Add($"Route '{name}': transport.enforce must be one of observe|warn|block.");
        }

        if (t.GraceDays is < 1 or > 365)
        {
            // 0 is rejected on purpose: writes never persist a value the UI would have to
            // reinterpret. The read side (RouteDraftJson.FromTransportOptions) projects a
            // hand-edited 0 as the kernel's effective 7, so GET/UI/export stay coherent and
            // a GET -> PUT round-trip keeps 7 instead of clamping to 1.
            errors.Add($"Route '{name}': transport.graceDays must be between 1 and 365 (0 is not a valid window - the proxy would apply its 7-day default).");
        }

        if (t.ProbeHours is < 0 or > 720)
        {
            errors.Add($"Route '{name}': transport.probeHours must be between 0 and 720.");
        }

        if (t.PoolLifetimeMinutes is < 0)
        {
            // Mirrors the kernel (Program.cs warns and ignores negatives) and probeHours.
            // Deliberately asymmetric with the read side: FromTransportOptions projects a
            // hand-edited <= 0 as null (the effective value, so the save of a field the UI
            // does not edit cannot fail), while a write must never persist a negative the
            // kernel would silently ignore.
            errors.Add($"Route '{name}': transport.poolLifetimeMinutes must be >= 0.");
        }

        if (t.TlsFloor is not null && !string.IsNullOrWhiteSpace(t.TlsFloor) && t.TlsFloor is not ("1.2" or "1.3"))
        {
            errors.Add($"Route '{name}': transport.tlsFloor must be one of 1.2|1.3.");
        }

        foreach (var pin in t.SafePins)
        {
            if (!LooksLikePin(pin))
            {
                errors.Add($"Route '{name}': transport pin '{pin}' must be a 64-hex or base64/base64url SHA-256 fingerprint.");
            }
        }

        foreach (var ip in t.SafeExpectedIps)
        {
            if (!LooksLikeCidrOrIp(ip))
            {
                errors.Add($"Route '{name}': expected IP '{ip}' must be an IP or CIDR (e.g. 10.0.0.0/8).");
            }
        }
    }

    private static bool LooksLikePin(string pin)
    {
        if (string.IsNullOrWhiteSpace(pin))
        {
            return false;
        }

        var value = pin.Trim();
        var isHex64 = value.Length == 64
                      && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');
        var isB64 = value.Length is 43 or 44
                    && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '-' or '_' or '=');
        return isHex64 || isB64;
    }

    private static bool LooksLikeCidrOrIp(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var value = text.Trim();
        var slash = value.IndexOf('/');
        var host = slash >= 0 ? value[..slash] : value;
        if (!System.Net.IPAddress.TryParse(host, out var parsed))
        {
            return false;
        }

        if (slash < 0)
        {
            return true;
        }

        var prefix = value[(slash + 1)..];
        var bits = parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128;
        return int.TryParse(prefix, out var prefixBits) && prefixBits >= 0 && prefixBits <= bits;
    }

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
