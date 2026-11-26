using AIRouterProxy;

namespace AiRouterProxy.AdminValidation;

/// <summary>
/// Validation of the providers.json feed (Phase 3) before it is written by the admin
/// API. Mirrors RouteValidator's style: collects human-readable errors, never throws.
/// Rules (spec Fase 3):
/// - id: required, unique (exact, ordinal), &lt;= 64 chars;
/// - severity: one of "info" | "warn" | "block";
/// - at least one of hosts / providerSlugs (both may be present);
/// - hosts and providerSlugs: no empty entries, &lt;= 32 entries, each &lt;= 128 chars;
/// - name &lt;= 128 chars, reason &lt;= 500 chars;
/// - until: optional expiry (not validated here - the feed apply path checks the type).
/// The common case (no usable validation gateway) keeps the feed empty, which is always valid.
/// </summary>
public static class ProviderFeedValidator
{
    public const int MaxId = 64;
    public const int MaxName = 128;
    public const int MaxReason = 500;
    public const int MaxListItems = 32;
    public const int MaxItemLength = 128;

    private static readonly HashSet<string> Severities = new(StringComparer.OrdinalIgnoreCase)
    {
        "info",
        "warn",
        "block",
    };

    public static bool Validate(IReadOnlyList<ProviderEntryOptions>? entries, out List<string> errors)
    {
        errors = new List<string>();
        if (entries is null || entries.Count == 0)
        {
            // An empty feed is always valid (the feature defaults to off).
            return true;
        }

        var ok = true;
        var ids = new HashSet<string>(StringComparer.Ordinal);

        for (var i = 0; i < entries.Count; i++)
        {
            var entry = entries[i];
            var where = string.IsNullOrWhiteSpace(entry.Id) ? $"entry #{i + 1}" : $"entry '{entry.Id}'";

            var id = (entry.Id ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(id))
            {
                errors.Add($"Entry #{i + 1}: 'id' is required.");
                ok = false;
            }
            else if (id.Length > MaxId)
            {
                errors.Add($"Entry '{id}': 'id' must be at most {MaxId} characters.");
                ok = false;
            }
            else if (!ids.Add(id))
            {
                errors.Add($"Entry '{id}': duplicated 'id'.");
                ok = false;
            }

            var name = entry.Name ?? string.Empty;
            if (name.Length > MaxName)
            {
                errors.Add($"{where}: 'name' must be at most {MaxName} characters.");
                ok = false;
            }

            var severity = (entry.Severity ?? string.Empty).Trim();
            if (!Severities.Contains(severity))
            {
                errors.Add($"{where}: 'severity' must be one of info|warn|block (got '{entry.Severity}').");
                ok = false;
            }

            var reason = entry.Reason ?? string.Empty;
            if (reason.Length > MaxReason)
            {
                errors.Add($"{where}: 'reason' must be at most {MaxReason} characters.");
                ok = false;
            }

            var hosts = entry.Hosts ?? new List<string>();
            var slugs = entry.ProviderSlugs ?? new List<string>();
            if (hosts.Count == 0 && slugs.Count == 0)
            {
                errors.Add($"{where}: at least one of 'hosts' or 'providerSlugs' is required.");
                ok = false;
            }

            ok &= ValidateList(where, "hosts", hosts, errors);
            ok &= ValidateList(where, "providerSlugs", slugs, errors);
        }

        return ok;
    }

    private static bool ValidateList(string where, string field, IReadOnlyList<string> values, List<string> errors)
    {
        var ok = true;
        if (values.Count > MaxListItems)
        {
            errors.Add($"{where}: '{field}' must have at most {MaxListItems} entries.");
            ok = false;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i < values.Count; i++)
        {
            var value = values[i] ?? string.Empty;
            if (string.IsNullOrWhiteSpace(value))
            {
                errors.Add($"{where}: '{field}' must not contain empty entries.");
                ok = false;
                continue;
            }

            if (value.Length > MaxItemLength)
            {
                errors.Add($"{where}: '{field}' entry '{Truncate(value)}' must be at most {MaxItemLength} characters.");
                ok = false;
            }

            if (!seen.Add(value))
            {
                errors.Add($"{where}: '{field}' entry '{Truncate(value)}' is duplicated.");
                ok = false;
            }
        }

        return ok;
    }

    private static string Truncate(string value) => value.Length > 24 ? value[..24] + "..." : value;
}
