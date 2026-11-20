using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace AiRouterProxy.AdminValidation;

/// <summary>
/// Validates the Redaction and Inspection sections (redaction.json "Proxy.Redaction" /
/// "Proxy.Inspection") before they are written. Booleans must be booleans, entropy must
/// be in range, allow-list entries must compile as regex, and the action enums must be
/// one of the values the kernel actually accepts (checked against InspectionOptions
/// in ProxyOptions.cs: defaultAction/byContentType -&gt; block|pass|inspect,
/// invalidJson -&gt; block|warn).
/// </summary>
public static class SecurityValidator
{
    private static readonly HashSet<string> Actions = new(StringComparer.OrdinalIgnoreCase)
    {
        "block",
        "pass",
        "inspect",
    };

    private static readonly HashSet<string> InvalidJsonActions = new(StringComparer.OrdinalIgnoreCase)
    {
        "block",
        "warn",
    };

    public static bool Validate(JsonNode? redactionSection, JsonNode? inspectionSection, out List<string> errors)
    {
        errors = new List<string>();
        var ok = true;

        if (redactionSection is not null)
        {
            ok &= ValidateRedaction(redactionSection, errors);
        }

        if (inspectionSection is not null)
        {
            ok &= ValidateInspection(inspectionSection, errors);
        }

        return ok;
    }

    private static bool ValidateRedaction(JsonNode section, List<string> errors)
    {
        var ok = true;
        if (section is not JsonObject obj)
        {
            errors.Add("Redaction section must be a JSON object.");
            return false;
        }

        ok &= CheckBool(obj, "enabled", errors);
        ok &= CheckBool(obj, "notifyInResponse", errors);
        if (Prop(obj, "mask") is not null && Prop(obj, "mask") is not JsonValue)
        {
            errors.Add("Redaction 'mask' must be a string.");
            ok = false;
        }

        if (Prop(obj, "warnTemplate") is not null && Prop(obj, "warnTemplate") is not JsonValue)
        {
            errors.Add("Redaction 'warnTemplate' must be a string.");
            ok = false;
        }

        if (Prop(obj, "detect") is JsonObject detect)
        {
            ok &= CheckBool(detect, "byFieldName", errors);
            ok &= CheckBool(detect, "byFormats", errors);
            ok &= CheckBool(detect, "byKeyValueContext", errors);
            ok &= CheckBool(detect, "byLongStrings", errors);
            ok &= CheckBool(detect, "exemptBase64", errors);

            var entropyNode = Prop(detect, "entropyThreshold");
            if (entropyNode is JsonValue entropyValue && entropyValue.TryGetValue<double>(out var entropy))
            {
                if (entropy < 0 || entropy > 8)
                {
                    errors.Add("Redaction 'detect.entropyThreshold' must be between 0 and 8.");
                    ok = false;
                }
            }
            else if (entropyNode is not null)
            {
                errors.Add("Redaction 'detect.entropyThreshold' must be a number.");
                ok = false;
            }
        }
        else if (Prop(obj, "detect") is not null)
        {
            errors.Add("Redaction 'detect' must be an object.");
            ok = false;
        }

        if (Prop(obj, "allow") is JsonArray allowList)
        {
            foreach (var entry in allowList)
            {
                if (entry is null)
                {
                    errors.Add("Redaction 'allow' entries must be non-empty regex patterns.");
                    ok = false;
                    continue;
                }

                // GetValue<string>() would throw on a non-string entry (e.g. a number) -
                // fail as a validation error instead of crashing the request/circuit.
                if (entry is not JsonValue entryValue || !entryValue.TryGetValue<string>(out var pattern))
                {
                    errors.Add("Redaction 'allow' entry must be a string.");
                    ok = false;
                    continue;
                }

                if (string.IsNullOrWhiteSpace(pattern))
                {
                    errors.Add("Redaction 'allow' entries must be non-empty regex patterns.");
                    ok = false;
                    continue;
                }

                try
                {
                    _ = new Regex(pattern, RegexOptions.Compiled, TimeSpan.FromMilliseconds(200));
                }
                catch (ArgumentException)
                {
                    errors.Add($"Redaction 'allow' pattern '{pattern}' is not a valid regex.");
                    ok = false;
                }
            }
        }
        else if (Prop(obj, "allow") is not null)
        {
            errors.Add("Redaction 'allow' must be an array of strings.");
            ok = false;
        }

        return ok;
    }

    private static bool ValidateInspection(JsonNode section, List<string> errors)
    {
        var ok = true;
        if (section is not JsonObject obj)
        {
            errors.Add("Inspection section must be a JSON object.");
            return false;
        }

        ok &= CheckBool(obj, "enabled", errors);
        ok &= CheckAction(obj, "defaultAction", Actions, "defaultAction must be one of: block, pass, inspect.", errors);
        ok &= CheckAction(obj, "invalidJson", InvalidJsonActions, "invalidJson must be one of: block, warn.", errors);

        if (Prop(obj, "byContentType") is JsonObject byType)
        {
            foreach (var (mediaType, actionNode) in byType)
            {
                if (string.IsNullOrWhiteSpace(mediaType))
                {
                    errors.Add("Inspection 'byContentType' keys (media types) must not be empty.");
                    ok = false;
                    continue;
                }

                // GetValue<string>() would throw on a non-string action (e.g. a number) -
                // report a validation error instead of an unhandled exception.
                if (actionNode is not JsonValue actionValue || !actionValue.TryGetValue<string>(out var action))
                {
                    errors.Add($"Inspection 'byContentType.{mediaType}' must be a string.");
                    ok = false;
                    continue;
                }

                if (!Actions.Contains(action))
                {
                    errors.Add($"Inspection 'byContentType.{mediaType}' must be one of: block, pass, inspect.");
                    ok = false;
                }
            }
        }
        else if (Prop(obj, "byContentType") is not null)
        {
            errors.Add("Inspection 'byContentType' must be an object of media type -> action.");
            ok = false;
        }

        return ok;
    }

    /// <summary>
    /// Case-insensitive property lookup: the kernel's option binder is
    /// case-insensitive, so bundles may legitimately use "Enabled"/"DefaultAction".
    /// Scanning the (small) object beats rebuilding it with a case-insensitive
    /// comparer and keeps parse-roundtrips untouched.
    /// </summary>
    private static JsonNode? Prop(JsonObject obj, string name)
    {
        foreach (var (key, value) in obj)
        {
            if (string.Equals(key, name, StringComparison.OrdinalIgnoreCase))
            {
                return value;
            }
        }

        return null;
    }

    private static bool CheckBool(JsonObject obj, string property, List<string> errors)
    {
        var node = Prop(obj, property);
        if (node is null)
        {
            return true; // optional
        }

        if (node is JsonValue value && value.TryGetValue<bool>(out _))
        {
            return true;
        }

        errors.Add($"'{property}' must be a boolean.");
        return false;
    }

    private static bool CheckAction(JsonObject obj, string property, ISet<string> accepted, string message, List<string> errors)
    {
        var node = Prop(obj, property);
        if (node is null)
        {
            return true; // optional
        }

        // GetValue<string>() would throw on a wrong-typed value; TryGetValue reports a
        // clean validation error instead of a 500 / crashed Blazor circuit.
        if (node is not JsonValue value || !value.TryGetValue<string>(out var text))
        {
            errors.Add($"'{property}' must be a string.");
            return false;
        }

        if (accepted.Contains(text))
        {
            return true;
        }

        errors.Add(message);
        return false;
    }

    // ----------------------------------------------------------
    // Known-shape projection (used by the import pipeline)
    // ----------------------------------------------------------

    /// <summary>
    /// Projects a (already validated) Redaction section onto ONLY the properties the
    /// kernel binds in RedactionOptions/DectectOptions, dropping any unknown property or
    /// nested object (smuggled fields must never reach redaction.json). Returns null
    /// when the section is absent or not an object.
    /// </summary>
    public static JsonObject? SanitizeRedaction(JsonNode? section)
    {
        if (section is not JsonObject src)
        {
            return null;
        }

        var dst = new JsonObject();
        CopyKnown(src, dst, "enabled", "mask", "notifyInResponse", "warnTemplate");

        if (Prop(src, "detect") is JsonObject detectSrc)
        {
            var detectDst = new JsonObject();
            CopyKnown(detectSrc, detectDst, "byFieldName", "byFormats", "byKeyValueContext",
                "byLongStrings", "exemptBase64", "entropyThreshold");
            dst["detect"] = detectDst;
        }

        if (Prop(src, "allow") is JsonArray allowSrc)
        {
            var allowDst = new JsonArray();
            foreach (var entry in allowSrc)
            {
                allowDst.Add(entry?.DeepClone());
            }

            dst["allow"] = allowDst;
        }

        return dst;
    }

    /// <summary>
    /// Projects a (already validated) Inspection section onto ONLY the properties the
    /// kernel binds in InspectionOptions. byContentType is a dynamic map, but every entry
    /// was validated as media type -> action before this call. Returns null when the
    /// section is absent or not an object.
    /// </summary>
    public static JsonObject? SanitizeInspection(JsonNode? section)
    {
        if (section is not JsonObject src)
        {
            return null;
        }

        var dst = new JsonObject();
        CopyKnown(src, dst, "enabled", "defaultAction", "invalidJson");

        if (Prop(src, "byContentType") is JsonObject byTypeSrc)
        {
            var byTypeDst = new JsonObject();
            foreach (var (mediaType, action) in byTypeSrc)
            {
                if (!string.IsNullOrWhiteSpace(mediaType))
                {
                    byTypeDst[mediaType] = action?.DeepClone();
                }
            }

            dst["byContentType"] = byTypeDst;
        }

        return dst;
    }

    private static void CopyKnown(JsonObject src, JsonObject dst, params string[] names)
    {
        foreach (var name in names)
        {
            // Case-insensitive lookup (matches Prop): a bundle using "Enabled"/"Mask"
            // must not lose the field silently. The destination always uses the kernel's
            // canonical key casing.
            var value = Prop(src, name);
            if (value is not null)
            {
                dst[name] = value.DeepClone();
            }
        }
    }
}
