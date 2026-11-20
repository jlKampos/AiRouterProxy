using System.Text.Json.Nodes;

namespace AiRouterProxy.AdminValidation;

/// <summary>
/// Validates an import bundle BEFORE anything is written. An export bundle only ever
/// contains the non-secret sections: "routes", "redaction" and "inspection". Any other
/// top-level property is rejected, and any property that could smuggle key VALUES
/// (RouteKeys / Keys / secret / values / key) is rejected with a clear error - the
/// import pipeline has no way to receive or write secret values.
/// </summary>
public static class ImportValidator
{
    private static readonly string[] AllowedTopLevel = { "routes", "redaction", "inspection" };

    private static readonly string[] SecretLikeNames =
    {
        "routekeys",
        "keys",
        "secret",
        "values",
        "key",
        "localkey",
        "upstreamkey",
        "tokens",
        "credentials",
    };

    public static bool Validate(JsonNode? bundle, out List<string> errors)
    {
        errors = new List<string>();
        if (bundle is not JsonObject root)
        {
            errors.Add("Import bundle must be a JSON object.");
            return false;
        }

        var ok = true;

        foreach (var (property, _) in root)
        {
            if (!AllowedTopLevel.Contains(property, StringComparer.Ordinal))
            {
                var lowered = property.ToLowerInvariant();
                if (SecretLikeNames.Any(name => lowered.Equals(name, StringComparison.Ordinal)
                    || lowered.Contains(name, StringComparison.Ordinal)))
                {
                    errors.Add(
                        $"Import bundle contains '{property}', which could hold key values. Export bundles contain NO secrets - " +
                        "only 'routes', 'redaction' and 'inspection'.");
                }
                else
                {
                    errors.Add($"Import bundle contains unsupported property '{property}' (allowed: routes, redaction, inspection).");
                }

                ok = false;
            }
        }

        if (root["routes"] is { } routes && routes is not JsonArray)
        {
            errors.Add("Bundle 'routes' must be an array.");
            ok = false;
        }

        if (root["redaction"] is { } redaction && redaction is not JsonObject)
        {
            errors.Add("Bundle 'redaction' must be an object.");
            ok = false;
        }

        if (root["inspection"] is { } inspection && inspection is not JsonObject)
        {
            errors.Add("Bundle 'inspection' must be an object.");
            ok = false;
        }

        return ok;
    }

    /// <summary>Whether the bundle contains a routes array (and therefore needs route validation).</summary>
    public static bool HasRoutes(JsonNode? bundle) => bundle is JsonObject root && root["routes"] is JsonArray;

    /// <summary>Whether the bundle contains redaction/inspection sections (and therefore needs security validation).</summary>
    public static bool HasSecurity(JsonNode? bundle) => bundle is JsonObject root && (root["redaction"] is not null || root["inspection"] is not null);
}
