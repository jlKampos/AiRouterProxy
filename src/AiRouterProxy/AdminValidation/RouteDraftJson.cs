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

        // transport section (optional): written only when the draft carries one, so
        // routes without attestation stay byte-identical through a dashboard save.
        if (draft.Transport is { } t)
        {
            var transport = new JsonObject
            {
                ["enabled"] = t.Enabled ?? false,
                ["graceDays"] = t.GraceDays,
                ["enforce"] = string.IsNullOrWhiteSpace(t.Enforce) ? "observe" : t.Enforce,
            };

            if (t.ProbeHours > 0)
            {
                transport["probeHours"] = t.ProbeHours;
            }

            if (t.PoolLifetimeMinutes is int minutes)
            {
                transport["poolLifetimeMinutes"] = minutes;
            }

            if (t.TlsFloor is not null)
            {
                transport["tlsFloor"] = t.TlsFloor;
            }

            if (t.SafeExpectedIps.Count > 0)
            {
                var ips = new JsonArray();
                foreach (var ip in t.SafeExpectedIps)
                {
                    ips.Add(ip);
                }

                transport["expectedIps"] = ips;
            }

            if (t.SafePins.Count > 0)
            {
                var pins = new JsonArray();
                foreach (var pin in t.SafePins)
                {
                    pins.Add(pin);
                }

                transport["pins"] = pins;
            }

            // blocklist section (Phase 3, optional): written only when the draft carries
            // one, keeping routes without a blocklist policy byte-identical through saves.
            if (t.Blocklist is { } b)
            {
                var blocklist = new JsonObject
                {
                    ["enabled"] = b.Enabled,
                    ["allowBlocked"] = b.AllowBlocked,
                    ["attribution"] = b.Attribution,
                    ["providerPolicy"] = string.IsNullOrWhiteSpace(b.ProviderPolicy) ? "merge" : b.ProviderPolicy,
                };

                if (b.SafeAggregators.Count > 0)
                {
                    var aggregators = new JsonArray();
                    foreach (var aggregator in b.SafeAggregators)
                    {
                        aggregators.Add(aggregator);
                    }

                    blocklist["aggregators"] = aggregators;
                }

                transport["blocklist"] = blocklist;
            }

            node["transport"] = transport;
        }

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
                : new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase),
            route.Transport is { } t
                ? new RouteTransportDraft(
                    Enabled: t.Enabled,
                    PoolLifetimeMinutes: t.PoolLifetimeMinutes,
                    ExpectedIps: t.ExpectedIps is { Count: > 0 } ? new List<string>(t.ExpectedIps) : new List<string>(),
                    TlsFloor: t.TlsFloor,
                    GraceDays: t.GraceDays,
                    Enforce: t.Enforce,
                    Pins: t.Pins is { Count: > 0 } ? new List<string>(t.Pins) : new List<string>(),
                    ProbeHours: t.ProbeHours,
                    Blocklist: t.Blocklist is { } bl
                        ? new RouteBlocklistDraft(
                            Enabled: bl.Enabled,
                            AllowBlocked: bl.AllowBlocked,
                            Aggregators: bl.Aggregators is { Count: > 0 } ? new List<string>(bl.Aggregators) : new List<string>(),
                            Attribution: bl.Attribution,
                            ProviderPolicy: bl.ProviderPolicy)
                        : null)
                : null);
    }

    public static string ToDisplayText(RouteDraft draft)
        => string.Join(" ", draft.SafePaths);
}
