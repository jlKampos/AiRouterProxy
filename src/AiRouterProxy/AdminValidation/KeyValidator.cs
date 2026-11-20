namespace AiRouterProxy.AdminValidation;

/// <summary>
/// Validation for key references and secret values. References are short identifiers
/// (<= 64 chars, [A-Za-z0-9._-]) used as dictionary keys in RouteKeys; secrets are the
/// actual API key values. Secret values are validated for shape only and are NEVER
/// logged or exposed by any caller - this class returns errors, not the value.
/// </summary>
public static class KeyValidator
{
    private const int MaxRefLength = 64;
    private const int MaxSecretLength = 1024;

    /// <summary>"" is a legal default-route keyRef but NEVER a RouteKeys dictionary key.</summary>
    public static bool ValidateRef(string? keyRef, out List<string> errors)
    {
        errors = new List<string>();
        if (string.IsNullOrEmpty(keyRef))
        {
            errors.Add("Key reference must not be empty.");
            return false;
        }

        if (keyRef.Length > MaxRefLength)
        {
            errors.Add($"Key reference must be at most {MaxRefLength} characters.");
        }

        if (keyRef.Any(char.IsWhiteSpace))
        {
            errors.Add("Key reference must not contain whitespace.");
        }

        foreach (var ch in keyRef)
        {
            var valid = (ch >= 'a' && ch <= 'z')
                || (ch >= 'A' && ch <= 'Z')
                || (ch >= '0' && ch <= '9')
                || ch is '.' or '_' or '-';
            if (!valid)
            {
                errors.Add($"Key reference contains an invalid character '{ch}' (allowed: letters, digits, '.', '_', '-').");
                break;
            }
        }

        return errors.Count == 0;
    }

    /// <summary>
    /// Shape-only validation of a secret value: non-empty, at most 1024 characters.
    /// The value is intentionally NOT trimmed (key material keeps its exact bytes) and
    /// never appears in any message here.
    /// </summary>
    public static bool ValidateSecret(string? secret, out List<string> errors)
    {
        errors = new List<string>();
        if (string.IsNullOrEmpty(secret))
        {
            errors.Add("Secret value must not be empty.");
            return false;
        }

        if (secret.Length > MaxSecretLength)
        {
            errors.Add($"Secret value must be at most {MaxSecretLength} characters.");
        }

        return errors.Count == 0;
    }

    /// <summary>Validates a list of local key values (extra admin/engineer keys).</summary>
    public static bool ValidateLocalKeys(IReadOnlyList<string>? localKeys, out List<string> errors)
    {
        errors = new List<string>();
        if (localKeys is null || localKeys.Count == 0)
        {
            // Replacing the list with an empty list is valid (keeps only the primary key).
            return true;
        }

        for (var i = 0; i < localKeys.Count; i++)
        {
            var sub = new List<string>();
            if (!ValidateSecret(localKeys[i], out sub))
            {
                errors.Add($"Local key #{i + 1}: {string.Join(" ", sub)}");
            }
        }

        return errors.Count == 0;
    }
}
