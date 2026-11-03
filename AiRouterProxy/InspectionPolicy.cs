namespace AIRouterProxy;

/// <summary>
/// Pure decision module for the fail-closed request-body inspection policy.
/// No middleware dependencies, so it can be tested in isolation (the test harness
/// links this file directly).
///
/// Core rule: an uninspected request is never forwarded. Any Content-Type that is not
/// explicitly allowed is blocked (415). "inspect" is only supported for JSON in this
/// iteration; other types declared as "inspect" fail closed until a scanner exists.
/// </summary>
public static class InspectionPolicy
{
    public const string ActionInspect = "inspect";
    public const string ActionBlock = "block";

    /// <summary>
    /// Decides the action for a request. Decisions:
    ///  - "inspect" - read the body, parse as JSON, redact; parse failure = 400 (blocked body);
    ///  - "block"   - reject with 415 (Content-Type not allowed for this proxy);
    /// "inspect" bodies without Content-Type metadata are still read; the parse handles the rest.
    /// </summary>
    public static string Decide(InspectionOptions options, bool methodAllowsBody, string? contentType)
    {
        return Decide(options, methodAllowsBody, contentType, hasBody: true);
    }

    /// <summary>
    /// Overload that also accepts whether the request declares a body. A request without a
    /// body (e.g. GET, or a POST with Content-Length 0) has nothing to inspect and is allowed.
    /// </summary>
    public static string Decide(InspectionOptions options, bool methodAllowsBody, string? contentType, bool hasBody)
    {
        if (!methodAllowsBody || options is null || !options.Enabled)
        {
            return ActionInspect;
        }

        if (!hasBody)
        {
            return ActionInspect;
        }

        var mediaType = NormalizeMediaType(contentType);

        if (string.IsNullOrWhiteSpace(mediaType))
        {
            // No Content-Type on a body-bearing request: fail closed.
            return ActionBlock;
        }

        string action;
        if (options.ByContentType.TryGetValue(mediaType, out var configured))
        {
            action = configured;
        }
        else if (IsJson(mediaType))
        {
            // Any real JSON type (application/json or +json) is inspectable by default - the
            // redactor handles the structure regardless of subtype. Explicit config can override.
            action = ActionInspect;
        }
        else
        {
            action = options.DefaultAction ?? ActionBlock;
        }

        if (!string.Equals(action, ActionInspect, StringComparison.OrdinalIgnoreCase))
        {
            return ActionBlock;
        }

        // "inspect" is only implemented for JSON in this iteration; a type declared as
        // "inspect" but that is not JSON fails closed (blocked) until a scanner exists.
        return IsJson(mediaType) ? ActionInspect : ActionBlock;
    }

    /// <summary>True when the media type is application/json (any parameters, both +json and bare).</summary>
    public static bool IsJson(string? contentType)
    {
        var mediaType = NormalizeMediaType(contentType);
        return mediaType.Equals("application/json", StringComparison.OrdinalIgnoreCase)
            || mediaType.EndsWith("+json", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Extracts the media type, stripping parameters after ";" and trimming whitespace.</summary>
    public static string NormalizeMediaType(string? contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType))
        {
            return string.Empty;
        }

        var index = contentType.IndexOf(';');
        return (index >= 0 ? contentType[..index] : contentType).Trim();
    }
}
