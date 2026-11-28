using System.Text;
using System.Text.Json.Nodes;
using AiRouterProxy.Dashboard.Models;
using RouteOptions = AIRouterProxy.RouteOptions;
using RouteTransportOptions = AIRouterProxy.RouteTransportOptions;

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

        // headers: written only when the draft carries the section. Null means "not
        // supplied" (the admin service merges the existing routes.json node); an explicit
        // empty object means the operator removed every header and the node is cleared.
        if (draft.Headers is { } headerValues)
        {
            var headers = new JsonObject();
            foreach (var (name, value) in headerValues)
            {
                headers[name] = value;
            }

            node["headers"] = headers;
        }

        // transport section (optional): written only when the draft carries one, so
        // routes without attestation stay byte-identical through a dashboard save.
        if (BuildTransportNode(draft.Transport) is { } transport)
        {
            node["transport"] = transport;
        }

        return node;
    }

    /// <summary>
    /// GET shape of one route (used by /admin/api/v1/routes): the complete editable row,
    /// including the optional "headers"/"transport" sections, so a GET -> PUT round-trip
    /// is semantically equivalent (not byte-identical); out-of-range values the kernel
    /// applies are rejected on save. The "transport" key is always present and null when
    /// the route has no
    /// section; the section itself is projected through the same builder used by
    /// export/import (pins are public SPKI fingerprints, expectedIps/policy fields are
    /// non-sensitive metadata). Route headers are returned in clear text: this endpoint
    /// is admin-only (same local key as /admin/endpoints, which does the same), route
    /// headers never carry the proxy's upstream keys - those stay in the key store behind
    /// "keyRef" - but they may hold static operator headers (API versions, tenant ids).
    /// </summary>
    public static JsonObject ToAdminJson(RouteDraft draft)
    {
        var paths = new JsonArray();
        foreach (var path in draft.SafePaths)
        {
            paths.Add(path);
        }

        var headers = new JsonObject();
        foreach (var (name, value) in draft.SafeHeaders)
        {
            headers[name] = value;
        }

        return new JsonObject
        {
            ["name"] = draft.Name,
            ["prefix"] = draft.Prefix ?? string.Empty,
            ["upstream"] = draft.Upstream,
            ["keyRef"] = draft.KeyRef ?? string.Empty,
            ["allowedPaths"] = paths,
            ["requestTimeoutMs"] = draft.RequestTimeoutMs,
            ["maxBodySize"] = draft.MaxBodySize,
            ["headers"] = headers,
            ["transport"] = BuildTransportNode(draft.Transport),
        };
    }

    private static JsonObject? BuildTransportNode(RouteTransportDraft? t)
    {
        if (t is null)
        {
            return null;
        }

        var transport = new JsonObject
        {
            ["graceDays"] = t.GraceDays,
            ["enforce"] = string.IsNullOrWhiteSpace(t.Enforce) ? "observe" : t.Enforce,
        };

        // null = inherit Proxy.Transport.Enabled. Writing "false" here would override
        // the global switch for a route the operator left inherited.
        if (t.Enabled is bool enabled)
        {
            transport["enabled"] = enabled;
        }

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

        return transport;
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
            FromTransportOptions(route.Transport));
    }

    /// <summary>
    /// Projects the host's per-route transport options into the dashboard draft shape.
    /// Shared by the export bundle and the dashboard facade so both see the same fields.
    /// Values are normalized to what the kernel actually applies
    /// (<see cref="AIRouterProxy.TransportPolicyProvider"/> and
    /// <see cref="AIRouterProxy.TransportClientFactory"/>): graceDays &lt;= 0 becomes 7,
    /// probeHours &lt;= 0 becomes 0 and poolLifetimeMinutes &lt;= 0 becomes null (the
    /// factory only applies a positive pool lifetime). Returning the effective value
    /// keeps GET/export/UI/attestation coherent and makes a GET -> PUT round-trip valid:
    /// a hand-edited 0 would otherwise be rejected by RouteValidator for a field the
    /// dashboard does not even let the operator edit. The asymmetry is deliberate - the
    /// read side projects the effective value, the write side (RouteValidator) still
    /// rejects an explicit graceDays &lt; 1, probeHours &lt; 0 or poolLifetimeMinutes
    /// &lt; 0 sent through the API, because a write must never persist a value the kernel
    /// would silently reinterpret. Values the kernel applies as-is (graceDays &gt; 365,
    /// probeHours &gt; 720) are left untouched: they can only come from a hand-edited
    /// routes.json and the dashboard validator rejects them on save when the section is
    /// supplied; an omitted section is preserved as-is by the merge.
    /// </summary>
    public static RouteTransportDraft? FromTransportOptions(RouteTransportOptions? transport)
        => transport is { } t
            ? new RouteTransportDraft(
                Enabled: t.Enabled,
                PoolLifetimeMinutes: t.PoolLifetimeMinutes is int minutes and > 0 ? minutes : null,
                ExpectedIps: t.ExpectedIps is { Count: > 0 } ? new List<string>(t.ExpectedIps) : new List<string>(),
                TlsFloor: t.TlsFloor,
                GraceDays: t.GraceDays > 0 ? t.GraceDays : 7,
                Enforce: t.Enforce,
                Pins: t.Pins is { Count: > 0 } ? new List<string>(t.Pins) : new List<string>(),
                ProbeHours: t.ProbeHours > 0 ? t.ProbeHours : 0)
            : null;

    public static string ToDisplayText(RouteDraft draft)
        => string.Join(" ", draft.SafePaths);
}
