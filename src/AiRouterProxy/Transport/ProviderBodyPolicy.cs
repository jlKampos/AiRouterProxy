using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AIRouterProxy;

/// <summary>
/// Result of merging the blocklist decision into the request body: the (possibly
/// rewritten) body, and - in strict mode - a conflict reason when the client explicitly
/// overrode the policy (the middleware then answers 400 without forwarding).
/// </summary>
public sealed record ProviderMergeResult(byte[] Body, bool Conflict, string? Reason)
{
    /// <summary>The request body unchanged (byte-identical) and nothing to report.</summary>
    public static ProviderMergeResult Unchanged(byte[] body) => new(body, false, null);
}

/// <summary>
/// Merges the provider-blocklist decision into the request's "provider" object
/// (Phase 3). Pure function: parses the JSON body, merges, re-serializes ONLY when
/// something actually changed - otherwise the original bytes come back untouched
/// (byte-equal), so routes without applicable entries pay no rewrite cost.
///
/// Merges:
/// - provider.ignore: union of the client's slugs + the decision's slugs (dedupe,
///   stable order - client first, then the decision in feed order).
/// - RequireZdr         -&gt; provider.zdr: true
/// - DenyDataCollection -&gt; provider.data_collection: "deny"
/// All other provider fields and the rest of the body are preserved as-is.
///
/// Strict mode ("providerPolicy": "strict"): a client provider that explicitly lists a
/// to-ignore slug in provider.only/order, or sends zdr: false while the policy requires
/// zdr, yields a conflict (body untouched - the middleware rejects the request).
/// </summary>
public static class ProviderBodyPolicy
{
    private static readonly JsonSerializerOptions WriteIndented = new() { WriteIndented = true };

    /// <summary>
    /// <paramref name="clientProviderJson"/> is an optional, already-extracted rendering of
    /// the client's "provider" object (the body is the source of truth; this is used as a
    /// fallback when the body has no provider object - e.g. a redactor rewrite).
    /// </summary>
    public static ProviderMergeResult MergeProvider(
        byte[] body,
        BlocklistDecision decision,
        RouteBlocklistOptions blocklist,
        string? clientProviderJson = null)
    {
        if (body is null || body.Length == 0)
        {
            return ProviderMergeResult.Unchanged(body ?? Array.Empty<byte>());
        }

        // Nothing to merge (no provider-tier entries) or the route's policy is off.
        if (decision is null
            || blocklist is not { Enabled: true }
            || (decision.ProviderSlugsToIgnore.Count == 0 && !decision.RequireZdr && !decision.DenyDataCollection))
        {
            return ProviderMergeResult.Unchanged(body);
        }

        JsonObject? root;
        try
        {
            root = JsonNode.Parse(body) as JsonObject;
        }
        catch (JsonException)
        {
            // A body that does not parse cannot be merged - leave it byte-identical.
            return ProviderMergeResult.Unchanged(body);
        }

        if (root is null)
        {
            return ProviderMergeResult.Unchanged(body);
        }

        var provider = root["provider"] as JsonObject;
        if (provider is null && !string.IsNullOrWhiteSpace(clientProviderJson))
        {
            try
            {
                provider = JsonNode.Parse(clientProviderJson) as JsonObject;
            }
            catch (JsonException)
            {
                provider = null;
            }
        }

        var strict = string.Equals(blocklist.ProviderPolicy, "strict", StringComparison.OrdinalIgnoreCase);
        if (strict)
        {
            var conflictReason = FindStrictConflict(provider, decision);
            if (conflictReason is not null)
            {
                return new ProviderMergeResult(body, true, conflictReason);
            }
        }

        // ----------------------------------------------------------
        // Merge
        // ----------------------------------------------------------

        var mergedIgnore = UnionIgnore(provider, decision.ProviderSlugsToIgnore);
        var createdProvider = provider is null;
        var target = provider ?? new JsonObject();
        var changed = false;

        if (mergedIgnore.Count > 0 && !IgnoreEquals(provider?["ignore"], mergedIgnore))
        {
            target["ignore"] = ToArray(mergedIgnore);
            changed = true;
        }

        if (decision.RequireZdr && !IsTrue(provider?["zdr"]))
        {
            target["zdr"] = true;
            changed = true;
        }

        if (decision.DenyDataCollection && !IsDeny(provider?["data_collection"]))
        {
            target["data_collection"] = "deny";
            changed = true;
        }

        // No applicable change (e.g. the client already carries the full ignore list):
        // return the original bytes unchanged.
        if (!changed)
        {
            return ProviderMergeResult.Unchanged(body);
        }

        if (createdProvider)
        {
            root["provider"] = target;
        }

        var json = root.ToJsonString(WriteIndented);
        return new ProviderMergeResult(Encoding.UTF8.GetBytes(json), false, null);
    }

    // ----------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------

    private static string? FindStrictConflict(JsonObject? provider, BlocklistDecision decision)
    {
        if (provider is null)
        {
            return null;
        }

        var slugs = new HashSet<string>(decision.ProviderSlugsToIgnore, StringComparer.Ordinal);
        if (slugs.Count > 0)
        {
            foreach (var key in new[] { "only", "order" })
            {
                if (provider[key] is JsonArray list)
                {
                    foreach (var node in list)
                    {
                        if (node is JsonValue v
                            && v.TryGetValue<string>(out var slug)
                            && slugs.Contains(slug))
                        {
                            return $"provider.{key} contains blocked slug '{slug}'.";
                        }
                    }
                }
            }
        }

        if (decision.RequireZdr
            && provider["zdr"] is JsonValue zdrValue
            && zdrValue.TryGetValue<bool>(out var zdr)
            && !zdr)
        {
            return "provider.zdr is false but the provider policy requires zero data retention.";
        }

        return null;
    }

    private static List<string> UnionIgnore(JsonObject? provider, IReadOnlyList<string> decisionSlugs)
    {
        var result = new List<string>();
        if (provider?["ignore"] is JsonArray existing)
        {
            foreach (var node in existing)
            {
                if (node is JsonValue v
                    && v.TryGetValue<string>(out var slug)
                    && !string.IsNullOrWhiteSpace(slug)
                    && !result.Contains(slug, StringComparer.Ordinal))
                {
                    result.Add(slug);
                }
            }
        }

        foreach (var slug in decisionSlugs ?? Array.Empty<string>())
        {
            if (!string.IsNullOrWhiteSpace(slug) && !result.Contains(slug, StringComparer.Ordinal))
            {
                result.Add(slug);
            }
        }

        return result;
    }

    private static bool IgnoreEquals(JsonNode? ignoreNode, IReadOnlyList<string> merged)
    {
        if (ignoreNode is not JsonArray array || array.Count != merged.Count)
        {
            return false;
        }

        for (var i = 0; i < merged.Count; i++)
        {
            if (array[i] is not JsonValue v
                || !v.TryGetValue<string>(out var s)
                || !string.Equals(s, merged[i], StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsTrue(JsonNode? node)
        => node is JsonValue v && v.TryGetValue<bool>(out var b) && b;

    private static bool IsDeny(JsonNode? node)
        => node is JsonValue v
           && v.TryGetValue<string>(out var s)
           && string.Equals(s, "deny", StringComparison.OrdinalIgnoreCase);

    private static JsonArray ToArray(IReadOnlyList<string> values)
    {
        var array = new JsonArray();
        foreach (var value in values)
        {
            array.Add(value);
        }

        return array;
    }
}
