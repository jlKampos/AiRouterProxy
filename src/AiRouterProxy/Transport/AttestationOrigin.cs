using System.Text.Json;

namespace AIRouterProxy;

/// <summary>
/// Strict-filtered origin of a generation, as returned by
/// GET {aggregator}/api/v1/generation?id=. Only provider_name / model / upstream_id
/// (strings) ever leave the process - everything else in the aggregator payload is
/// dropped (metadata only; keys never leave the process either).
/// </summary>
public sealed record GenerationOriginView(string? ProviderName, string? Model, string? UpstreamId);

/// <summary>
/// Pure helpers for the admin "attestation/origin" read endpoint (Phase 3): aggregator
/// normalization, route discovery and the STRICT response filter. The HTTP call itself
/// lives in the admin service (it needs the route's key, which must stay in-process).
/// </summary>
public static class AttestationOrigin
{
    /// <summary>Short timeout for the outbound aggregator call.</summary>
    public const int TimeoutSeconds = 10;

    /// <summary>Upper bound for the generationId query value (defensive).</summary>
    public const int MaxGenerationIdLength = 256;

    /// <summary>
    /// True when <paramref name="host"/> matches one of the aggregator entries (exact or
    /// "*.domain" wildcard). Full-URL entries are reduced to their host first.
    /// </summary>
    public static bool IsAggregatorHost(string? host, IReadOnlyList<string> aggregators)
        => ProviderBlocklist.IsAggregatorHost(host, aggregators);

    /// <summary>
    /// Finds the first route whose upstream host matches one of the aggregator entries.
    /// Only routes with a resolvable key count (a key is required to call the aggregator).
    /// </summary>
    public static RouteOptions? FindAggregatorRoute(ProxyOptions opts, IReadOnlyList<string> aggregators)
    {
        if (opts?.Routes is not { Count: > 0 } || aggregators is not { Count: > 0 })
        {
            return null;
        }

        foreach (var route in opts.Routes)
        {
            var host = ProviderBlocklist.HostOf(route.Upstream);
            if (host.Length == 0 || !IsAggregatorHost(host, aggregators))
            {
                continue;
            }

            if (RouteResolver.GetRouteKey(route, opts.RouteKeys, opts.Keys?.UpstreamKey) is { Length: > 0 })
            {
                return route;
            }
        }

        return null;
    }

    /// <summary>
    /// Builds the generation URL from the route's upstream base:
    /// "https://openrouter.ai/api" -&gt; "https://openrouter.ai/api/v1/generation?id={escaped}".
    /// A base WITHOUT a path is normalized first ("https://openrouter.ai" -&gt;
    /// "https://openrouter.ai/api/v1/generation?id={escaped}").
    /// </summary>
    public static string BuildGenerationUrl(string upstreamBase, string generationId)
    {
        var baseUrl = (upstreamBase ?? string.Empty).TrimEnd('/');
        if (baseUrl.Length == 0)
        {
            return string.Empty;
        }

        if (Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri)
            && (uri.AbsolutePath.Length <= 1)
            && !baseUrl.EndsWith("/api", StringComparison.OrdinalIgnoreCase))
        {
            baseUrl += "/api";
        }

        return baseUrl + "/v1/generation?id=" + Uri.EscapeDataString(generationId ?? string.Empty);
    }

    /// <summary>
    /// STRICT response filter: parses the aggregator's JSON and keeps ONLY the string
    /// values of provider_name / model / upstream_id (the full whitelist). Any other
    /// field is dropped; malformed JSON or wrong types yield nulls, never content.
    /// </summary>
    public static GenerationOriginView? ParseResponse(byte[] body)
    {
        if (body is null || body.Length == 0)
        {
            return null;
        }

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(body);
        }
        catch (JsonException)
        {
            return null;
        }

        using (doc)
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            // Only the whitelisted fields are read; each is validated to be a string.
            string? provider = null, model = null, upstreamId = null;
            foreach (var property in doc.RootElement.EnumerateObject())
            {
                if (property.Value.ValueKind != JsonValueKind.String)
                {
                    continue;
                }

                if (string.Equals(property.Name, "provider_name", StringComparison.OrdinalIgnoreCase) && provider is null)
                {
                    provider = property.Value.GetString();
                }
                else if (string.Equals(property.Name, "model", StringComparison.OrdinalIgnoreCase) && model is null)
                {
                    model = property.Value.GetString();
                }
                else if (string.Equals(property.Name, "upstream_id", StringComparison.OrdinalIgnoreCase) && upstreamId is null)
                {
                    upstreamId = property.Value.GetString();
                }
            }

            // A generation payload with none of the whitelisted fields is not a
            // generation origin - treat as a shape mismatch (never surface content).
            return provider is null && model is null && upstreamId is null
                ? null
                : new GenerationOriginView(provider, model, upstreamId);
        }
    }
}
