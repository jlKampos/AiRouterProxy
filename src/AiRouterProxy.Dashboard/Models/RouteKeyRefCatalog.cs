using System;
using System.Collections.Generic;
using System.Linq;

namespace AiRouterProxy.Dashboard.Models;

/// <summary>
/// Minimal route projection for <see cref="RouteKeyRefCatalog"/>. The dashboard assembly
/// cannot reference the host's <c>RouteOptions</c> (the host references the dashboard), so
/// the facade passes only what the catalog needs: the key reference a route uses and the
/// route name that owns it.
/// </summary>
public readonly record struct RouteKeyRefSource(string? KeyRef, string? RouteName);

/// <summary>
/// Builds the KeyRef dropdown catalog (Routes page). It is the union of every key
/// reference declared in <c>Proxy:RouteKeys</c> and every reference actually used by a
/// route, so a key added on the Keys screen is selectable even when no route uses it yet
/// (and a route-only reference is still shown, marked as not configured). Ordinal
/// (case-sensitive), no duplicates, stable order: configured refs first, then alphabetical.
/// </summary>
public static class RouteKeyRefCatalog
{
    public static IReadOnlyList<KeyRefView> Build(
        IReadOnlyList<RouteKeyRefSource>? routes,
        IReadOnlyDictionary<string, string>? routeKeys)
    {
        var usage = new Dictionary<string, int>(StringComparer.Ordinal);
        var owner = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var route in routes ?? Array.Empty<RouteKeyRefSource>())
        {
            var keyRef = route.KeyRef ?? string.Empty;
            if (keyRef.Length == 0)
            {
                continue;
            }

            usage[keyRef] = usage.TryGetValue(keyRef, out var count) ? count + 1 : 1;

            // Owner = the first route (table order) that uses the reference.
            if (!owner.ContainsKey(keyRef))
            {
                owner[keyRef] = route.RouteName ?? string.Empty;
            }
        }

        var configured = new HashSet<string>(StringComparer.Ordinal);
        var names = new HashSet<string>(usage.Keys, StringComparer.Ordinal);

        if (routeKeys is not null)
        {
            foreach (var (keyRef, value) in routeKeys)
            {
                if (string.IsNullOrEmpty(keyRef))
                {
                    continue;
                }

                names.Add(keyRef);
                if (!string.IsNullOrWhiteSpace(value))
                {
                    configured.Add(keyRef);
                }
            }
        }

        return names
            .OrderByDescending(configured.Contains)
            .ThenBy(keyRef => keyRef, StringComparer.Ordinal)
            .Select(keyRef => new KeyRefView(
                keyRef,
                configured.Contains(keyRef),
                usage.TryGetValue(keyRef, out var count) ? count : 0,
                owner.TryGetValue(keyRef, out var routeName) ? routeName : string.Empty))
            .ToList();
    }
}
