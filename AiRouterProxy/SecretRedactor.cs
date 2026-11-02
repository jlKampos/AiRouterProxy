using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AIRouterProxy;

/// <summary>
/// Redacts sensitive content (API keys, passwords, tokens) in the JSON body of requests
/// forwarded by the proxy. Only touches string values - never alters the JSON structure.
/// If nothing is found, returns the original bytes intact.
/// Detection layers (all optional):
///  - byFieldName: value of properties with sensitive names (api_key, password, senha, token...);
///  - byFormats:   known formats (sk-..., ghp_, AIza..., JWT, Bearer, PEM...);
///  - byKeyValueContext: "key: value" / "KEY=value" in text (config excerpts);
///  - byLongStrings: long URL-safe tokens (>= 28 chars) with mixed classes (entropy).
/// </summary>
public static class SecretRedactor
{
    /// <summary>Default mask - fixed bullets (does not reveal the real length).</summary>
    public const string DefaultMask = "\u2022\u2022\u2022\u2022\u2022\u2022"; // ••••••

    private const string KindKeyValue = "key_in_text";
    private const string KindLongString = "suspicious_key";
    private const int LongStringMinLength = 28;

    public sealed class RedactionStats
    {
        public int FieldRedactions { get; internal set; }
        public int FormatRedactions { get; internal set; }
        public int ContextRedactions { get; internal set; }
        public int LongStringRedactions { get; internal set; }
        public int Total => FieldRedactions + FormatRedactions + ContextRedactions + LongStringRedactions;
        public Dictionary<string, int> ByKind { get; } = new(StringComparer.Ordinal);
    }

    public sealed class Result
    {
        /// <summary>Body after redaction; if nothing changed, returns the original bytes.</summary>
        public byte[] Data { get; internal set; } = Array.Empty<byte>();
        public bool Changed { get; internal set; }
        public RedactionStats Stats { get; } = new();
    }

    /// <summary>
    /// Walks the JSON body and returns a redacted version. The document is only re-serialized
    /// if there were changes; otherwise the original bytes are returned (zero cost).
    /// </summary>
    public static Result RedactJson(
        byte[] body,
        bool enabled = true,
        string? mask = null,
        bool detectByFieldName = true,
        bool detectByFormats = true,
        bool detectByKeyValueContext = true,
        bool detectByLongStrings = true)
    {
        var result = new Result { Data = body, Changed = false };

        if (!enabled || body is null || body.Length == 0)
        {
            return result;
        }

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 128 });
        }
        catch (JsonException)
        {
            return result;
        }

        using (doc)
        {
            var maskValue = string.IsNullOrEmpty(mask) ? DefaultMask : mask;

            using var buffer = new MemoryStream(body.Length + 128);
            using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                Indented = false,
            }))
            {
                WriteElement(writer, doc.RootElement, null, maskValue, result.Stats,
                    detectByFieldName, detectByFormats, detectByKeyValueContext, detectByLongStrings);
            }

            if (result.Stats.Total > 0)
            {
                result.Data = buffer.ToArray();
                result.Changed = true;
            }
        }

        return result;
    }

    /// <summary>Human-readable description of the redacted categories (e.g. "password × 1, API key × 2").</summary>
    public static string Summarize(RedactionStats stats)
    {
        if (stats is null || stats.Total == 0)
        {
            return string.Empty;
        }

        var parts = new List<string>(stats.ByKind.Count);
        foreach (var kv in stats.ByKind.OrderByDescending(k => k.Value))
        {
            parts.Add($"{Humanize(kv.Key)} \u00d7 {kv.Value}");
        }

        return string.Join(", ", parts);
    }

    public static string Humanize(string kind) => kind switch
    {
        "api_key" => "API key",
        "password" => "password",
        "secret" => "secret",
        "token" => "token",
        "authorization" => "authorization",
        "private_key" => "private key",
        "jwt" => "JWT token",
        "bearer" => "bearer token",
        "openai" => "OpenAI key",
        "stripe" => "Stripe key",
        "github" => "GitHub token",
        "google" => "Google key",
        "slack" => "Slack token",
        "npm" => "npm token",
        "aws" => "AWS key",
        "key_in_text" => "key in text",
        "suspicious_key" => "suspicious key",
        _ => kind,
    };

    // ------------------------------------------------------------------
    // Layer 1 — FIELD NAME (JSON properties)
    // ------------------------------------------------------------------

    /// <summary>
    /// Decides whether a JSON property value must be redacted. First the exact list,
    /// then known substrings and, finally, the "token" family (only if the name ends in "token",
    /// which naturally excludes max_tokens/total_tokens/prompt_tokens/etc.).
    /// </summary>
    public static bool IsSensitiveFieldName(string name)
    {
        var lower = name.ToLowerInvariant();

        switch (lower)
        {
            case "api_key":
            case "apikey":
            case "api-key":
            case "apikey_secret":
            case "client_secret":
            case "password":
            case "passwd":
            case "senha":
            case "pw":
            case "access_token":
            case "refresh_token":
            case "authorization":
            case "auth":
            case "auth_header":
            case "x-api-key":
            case "localkey":
            case "local_key":
            case "local-key":
            case "secretkey":
            case "secret_key":
            case "secret-key":
            case "privatekey":
            case "private_key":
            case "private-key":
            case "masterkey":
            case "master_key":
            case "master-key":
            case "encryptionkey":
            case "encryption_key":
            case "encryption-key":
                return true;
        }

        if (TokenExcludedFields.Contains(lower))
        {
            return false;
        }

        if (lower.Contains("password")
            || lower.Contains("passwd")
            || lower.Contains("senha")
            || lower.Contains("secret")
            || lower.Contains("credential")
            || lower.Contains("authorization")
            || lower.Contains("apikey")
            || lower.Contains("api_key")
            || lower.Contains("api-key")
            || lower.Contains("access_token")
            || lower.Contains("refresh_token")
            || lower.Contains("client_secret")
            || lower.Contains("bearer_token")
            || lower.Contains("auth_token")
            || lower.Contains("session_token")
            || lower.Contains("id_token")
            || lower.Contains("x-api-key")
            || lower.Contains("localkey")
            || lower.Contains("local_key")
            || lower.Contains("local-key")
            || lower.Contains("secretkey")
            || lower.Contains("secret_key")
            || lower.Contains("secret-key")
            || lower.Contains("privatekey")
            || lower.Contains("private_key")
            || lower.Contains("private-key")
            || lower.Contains("masterkey")
            || lower.Contains("master_key")
            || lower.Contains("master-key")
            || lower.Contains("encryptionkey")
            || lower.Contains("encryption_key")
            || lower.Contains("encryption-key"))
        {
            return true;
        }

        // Generic "token" family: only when the name actually ends in "token"
        // (max_tokens, total_tokens, n_tokens, completion_tokens... end in "tokens").
        return lower.EndsWith("token", StringComparison.Ordinal);
    }

    private static readonly HashSet<string> TokenExcludedFields = new(StringComparer.Ordinal)
    {
        "token_count",
        "tokenizer",
        "tokens_per_message",
        "tokens_per_name",
    };

    private static string FieldKind(string name)
    {
        var lower = name.ToLowerInvariant();

        if (lower is "x-api-key" or "apikey" or "api_key" or "api-key" or "localkey" or "local_key" or "local-key"
            || lower.Contains("apikey") || lower.Contains("api_key") || lower.Contains("api-key")
            || lower.Contains("localkey") || lower.Contains("local_key") || lower.Contains("local-key"))
        {
            return "api_key";
        }

        if (lower.Contains("password") || lower.Contains("passwd") || lower.Contains("senha") || lower is "pw")
        {
            return "password";
        }

        if (lower.Contains("secret") || lower.Contains("client_secret"))
        {
            return "secret";
        }

        if (lower is "auth" or "auth_header" || lower.Contains("authorization") || lower.Contains("credential"))
        {
            return "authorization";
        }

        if (lower.Contains("token") || lower.EndsWith("token", StringComparison.Ordinal))
        {
            return "token";
        }

        return "sensitive_field";
    }

    // ------------------------------------------------------------------
    // Layer 2 — KNOWN FORMAT (any text, incl. code blocks)
    // ------------------------------------------------------------------

    private sealed record FormatPattern(Regex Regex, string Kind, string? PrefixGroup = null);

    private static readonly FormatPattern[] FormatPatterns =
    {
        // OpenAI / Anthropic / project keys
        new(new Regex(@"sk-(?:ant-|proj-|live-|test-)?[A-Za-z0-9_-]{10,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "openai"),
        new(new Regex(@"sk_[A-Za-z0-9]{20,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "openai"),
        // Stripe
        new(new Regex(@"sk_(?:live|test)_[0-9A-Za-z]{10,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "stripe"),
        // GitHub
        new(new Regex(@"gh[pousr]_[A-Za-z0-9]{10,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "github"),
        new(new Regex(@"github_pat_[A-Za-z0-9_]{20,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "github"),
        // Google
        new(new Regex(@"AIza[0-9A-Za-z_-]{20,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "google"),
        // Slack
        new(new Regex(@"xox[baprs]-[0-9A-Za-z-]{10,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "slack"),
        // npm
        new(new Regex(@"npm_[A-Za-z0-9]{20,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "npm"),
        // AWS access key id
        new(new Regex(@"AKIA[0-9A-Z]{16}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "aws"),
        // JWT
        new(new Regex(@"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "jwt"),
        // "Bearer <token>" in text - keeps the prefix, replaces the token
        new(new Regex(@"(Bearer\s+)([A-Za-z0-9._~+/=-]{12,})",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "bearer", "1"),
        // PEM private key blocks
        new(new Regex(@"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "private_key"),
    };

    // ------------------------------------------------------------------
    // Layer 3 — "key: value" CONTEXT in text
    // ------------------------------------------------------------------

    /// <summary>
    /// Catches config excerpts pasted into messages: `"LocalKey": "abc..."`, `LOCAL_KEY=abc...`,
    /// `password: abc...`. The name and separator stay; only the value is masked.
    /// </summary>
    private static readonly Regex KeyValueContextRegex = new(
        @"(?i)(?<![A-Za-z0-9_])"
        + @"(?<name>api[_-]?key|api[_-]?secret|loc[a]?l[_-]?key|secret[_-]?key|secret|private[_-]?key|master[_-]?key|encryption[_-]?key|client[_-]?secret|password|passwd|senha|credential|authorization|access[_-]?token|refresh[_-]?token|bearer[_-]?token)"
        + @"(?<sep>[\""']?\s*[:=]\s*[\""']?)"
        + @"(?<value>[A-Za-z0-9_\.~+/=-]{8,})",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // ------------------------------------------------------------------
    // Layer 4 — LONG STRINGS (URL-safe token >= 28 chars with entropy)
    // ------------------------------------------------------------------

    private static readonly Regex LongStringRegex = new(
        @"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{28,}(?![A-Za-z0-9_-])",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>False-positive guard: requires a mix of classes (lower/upper/digit/symbol).</summary>
    private static bool LooksRandom(string token)
    {
        var lower = false;
        var upper = false;
        var digit = false;
        var symbol = false;

        foreach (var c in token)
        {
            if (char.IsLower(c)) lower = true;
            else if (char.IsUpper(c)) upper = true;
            else if (char.IsDigit(c)) digit = true;
            else symbol = true;
        }

        var classes = (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (symbol ? 1 : 0);
        return classes >= 2;
    }

    // ------------------------------------------------------------------
    // JSON walk
    // ------------------------------------------------------------------

    private static void WriteElement(
        Utf8JsonWriter writer,
        JsonElement element,
        string? parentName,
        string mask,
        RedactionStats stats,
        bool detectByFieldName,
        bool detectByFormats,
        bool detectByKeyValueContext,
        bool detectByLongStrings)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject())
                {
                    writer.WritePropertyName(property.Name);
                    WriteElement(writer, property.Value, property.Name, mask, stats,
                        detectByFieldName, detectByFormats, detectByKeyValueContext, detectByLongStrings);
                }
                writer.WriteEndObject();
                break;

            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    WriteElement(writer, item, null, mask, stats,
                        detectByFieldName, detectByFormats, detectByKeyValueContext, detectByLongStrings);
                }
                writer.WriteEndArray();
                break;

            case JsonValueKind.String:
                var text = element.GetString();
                if (parentName is not null && detectByFieldName && IsSensitiveFieldName(parentName))
                {
                    writer.WriteStringValue(mask);
                    var kind = FieldKind(parentName);
                    stats.FieldRedactions++;
                    stats.ByKind[kind] = stats.ByKind.TryGetValue(kind, out var count) ? count + 1 : 1;
                }
                else
                {
                    writer.WriteStringValue(ApplyScans(text, mask, stats,
                        detectByFormats, detectByKeyValueContext, detectByLongStrings));
                }
                break;

            default:
                element.WriteTo(writer);
                break;
        }
    }

    private static string ApplyScans(
        string? text,
        string mask,
        RedactionStats stats,
        bool detectByFormats,
        bool detectByKeyValueContext,
        bool detectByLongStrings)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text ?? string.Empty;
        }

        var current = text;

        if (detectByFormats)
        {
            current = ApplyFormats(current, mask, stats);
        }

        if (detectByKeyValueContext)
        {
            current = ApplyKeyValueContext(current, mask, stats);
        }

        if (detectByLongStrings)
        {
            current = ApplyLongStrings(current, mask, stats);
        }

        return current;
    }

    private static string ApplyFormats(string current, string mask, RedactionStats stats)
    {
        foreach (var pattern in FormatPatterns)
        {
            var matches = 0;
            current = pattern.Regex.Replace(current, m =>
            {
                matches++;
                return pattern.PrefixGroup is null
                    ? mask
                    : m.Groups[pattern.PrefixGroup].Value + mask;
            });

            if (matches > 0)
            {
                var kind = pattern.Kind;
                stats.FormatRedactions += matches;
                stats.ByKind[kind] = stats.ByKind.TryGetValue(kind, out var count) ? count + matches : matches;
            }
        }

        return current;
    }

    private static string ApplyKeyValueContext(string current, string mask, RedactionStats stats)
    {
        var matches = 0;

        current = KeyValueContextRegex.Replace(current, m =>
        {
            var value = m.Groups["value"];
            if (!value.Success || value.Length == 0)
            {
                return m.Value;
            }

            var start = value.Index - m.Index;
            matches++;
            return m.Value[..start] + mask + m.Value[(start + value.Length)..];
        });

        if (matches > 0)
        {
            stats.ContextRedactions += matches;
            stats.ByKind[KindKeyValue] = stats.ByKind.TryGetValue(KindKeyValue, out var count) ? count + matches : matches;
        }

        return current;
    }

    private static string ApplyLongStrings(string current, string mask, RedactionStats stats)
    {
        var matches = 0;

        current = LongStringRegex.Replace(current, m =>
        {
            if (m.Value.Length < LongStringMinLength || !LooksRandom(m.Value))
            {
                return m.Value;
            }

            matches++;
            return mask;
        });

        if (matches > 0)
        {
            stats.LongStringRedactions += matches;
            stats.ByKind[KindLongString] = stats.ByKind.TryGetValue(KindLongString, out var count) ? count + matches : matches;
        }

        return current;
    }
}
