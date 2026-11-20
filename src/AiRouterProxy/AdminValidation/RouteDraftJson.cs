using System.Text;
using System.Text.Json.Nodes;
using AiRouterProxy.Dashboard.Models;
using RouteOptions = AIRouterProxy.RouteOptions;

namespace AiRouterProxy.AdminValidation;

/// <summary>
/// Converts route drafts to and from the JSON shape used in routes.json ("Proxy.Routes").
/// Drafts carry camelCase properties matching the kernel's case-insensitive binding.
/// No secrets are involved: only keyRef names.
/// </summary>
public static class RouteDraftJson
{
    public static JsonArray ToArray(IReadOnlyList<RouteDraft> drafts)
    {
        var array = new JsonArray();
        foreach (var draft in drafts)
        {
            array.Add(ToObject(draft));
        }

        return array;
    }

    public static JsonObject ToObject(RouteDraft draft)
    {
        var node = new JsonObject
        {
            ["name"] = draft.Name ?? string.Empty,
            ["prefix"] = draft.Prefix ?? string.Empty,
            ["upstream"] = draft.Upstream ?? string.Empty,
            ["keyRef"] = draft.KeyRef ?? string.Empty,
            ["requestTimeoutMs"] = draft.RequestTimeoutMs,
            ["maxBodySize"] = draft.MaxBodySize,
        };

        var paths = new JsonArray();
        foreach (var path in draft.SafePaths)
        {
            paths.Add(path);
        }

        node["allowedPaths"] = paths;

        var headers = new JsonObject();
        foreach (var (name, value) in draft.SafeHeaders)
        {
            headers[name] = value;
        }

        node["headers"] = headers;
        return node;
    }

    public static RouteDraft FromRouteOptions(RouteOptions route)
    {
        return new RouteDraft(
            route.Name ?? string.Empty,
            route.Prefix ?? string.Empty,
            route.Upstream ?? string.Empty,
            route.KeyRef,
            route.AllowedPaths is { Count: > 0 } ? new List<string>(route.AllowedPaths) : new List<string>(),
            route.RequestTimeoutMs,
            route.MaxBodySize,
            route.Headers is { Count: > 0 }
                ? new Dictionary<string, string>(route.Headers, StringComparer.OrdinalIgnoreCase)
                : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));
    }

    public static string ToDisplayText(RouteDraft draft)
        => string.Join(" ", draft.SafePaths);
}
