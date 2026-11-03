using System.Text;
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
///  - byFormats:   known formats (sk-..., ghp_, AIza, JWT, Bearer, PEM...) via SecretDetector;
///  - byKeyValueContext: "key: value" / "KEY=value" in text (config excerpts) via SecretDetector;
///  - byLongStrings: long random-looking tokens (Shannon entropy) via SecretDetector.
/// All text scanners run through <see cref="SecretDetector"/>, so detection lives in one place.
/// </summary>
public static class SecretRedactor
{
    /// <summary>Default mask - fixed bullets (does not reveal the real length).</summary>
    public const string DefaultMask = "\u2022\u2022\u2022\u2022\u2022\u2022"; // ••••••

    /// <summary>
    /// A category-only label of a single detection, used in the response notice.
    /// Deliberately carries no content sample, so no partial credential can leak.
    /// </summary>
    public sealed record RedactionPreview(string Kind);

    public sealed class RedactionStats
    {
        public int FieldRedactions { get; internal set; }
        public int FormatRedactions { get; internal set; }
        public int ContextRedactions { get; internal set; }
        public int LongStringRedactions { get; internal set; }
        public int Total => FieldRedactions + FormatRedactions + ContextRedactions + LongStringRedactions;
        public Dictionary<string, int> ByKind { get; } = new(StringComparer.Ordinal);

        /// <summary>Category-only previews of detected values (never content). Capped.</summary>
        public List<RedactionPreview> Previews { get; } = new();
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
        bool detectByLongStrings = true,
        double detectEntropyThreshold = 3.0)
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
                    detectByFieldName, detectByFormats, detectByKeyValueContext, detectByLongStrings,
                    detectEntropyThreshold);
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
        "anthropic" => "Anthropic key",
        "stripe" => "Stripe key",
        "github" => "GitHub token",
        "google" => "Google key",
        "slack" => "Slack token",
        "npm" => "npm token",
        "aws" => "AWS key",
        "url_cred" => "URL credentials",
        "key_in_text" => "key in text",
        "suspicious_key" => "suspicious key",
        _ => kind,
    };

    private const int PreviewMax = 6;

    /// <summary>Registers a category-only preview (never the value). Capped.</summary>
    private static void AddPreview(RedactionStats stats, string kind)
    {
        if (stats.Previews.Count >= PreviewMax)
        {
            return;
        }

        stats.Previews.Add(new RedactionPreview(kind));
    }

    /// <summary>
    /// Formats the previews for the response notice. Category-only - no value prefix is ever shown.
    /// Example: "OpenAI key detected, GitHub token detected".
    /// </summary>
    public static string FormatPreviews(IReadOnlyList<RedactionPreview>? previews)
    {
        if (previews is null || previews.Count == 0)
        {
            return string.Empty;
        }

        var parts = new List<string>(previews.Count);
        foreach (var preview in previews)
        {
            parts.Add($"{Humanize(preview.Kind)} detected");
        }

        return string.Join(", ", parts);
    }

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
            case "secretaccesskey":
            case "secret_access_key":
            case "secret-access-key":
            case "aws_secret_key":
            case "aws_secret_access_key":
            case "accesskey":
            case "access_key":
            case "access-key":
            case "aws_access_key":
            case "aws_access_key_id":
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
            || lower.Contains("accesskey")
            || lower.Contains("access_key")
            || lower.Contains("access-key")
            || lower.Contains("aws_access_key")
            || lower.Contains("aws_secret_access_key")
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

        // AWS credential names get a dedicated kind (aws), so activity/notices distinguish them.
        if (lower.Contains("aws_secret_access_key") || lower.Contains("aws_secret_key") || lower.Contains("aws_access_key"))
        {
            return "aws";
        }

        // Generic access/secret key names (also covers secret_access_key / access_key_id).
        if (lower.Contains("access_key") || lower.Contains("accesskey") || lower.Contains("access-key")
            || lower.Contains("secret_access_key"))
        {
            return "secret";
        }

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
        bool detectByLongStrings,
        double detectEntropyThreshold)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject())
                {
                    writer.WritePropertyName(property.Name);
                    WriteElement(writer, property.Value, property.Name, mask, stats,
                        detectByFieldName, detectByFormats, detectByKeyValueContext, detectByLongStrings,
                        detectEntropyThreshold);
                }
                writer.WriteEndObject();
                break;

            case JsonValueKind.Array:
                writer.WriteStartArray();
                foreach (var item in element.EnumerateArray())
                {
                    WriteElement(writer, item, null, mask, stats,
                        detectByFieldName, detectByFormats, detectByKeyValueContext, detectByLongStrings,
                        detectEntropyThreshold);
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
                    AddPreview(stats, kind);
                }
                else
                {
                    writer.WriteStringValue(ApplyScans(text, mask, stats,
                        detectByFormats, detectByKeyValueContext, detectByLongStrings, detectEntropyThreshold));
                }
                break;

            default:
                element.WriteTo(writer);
                break;
        }
    }

    // ------------------------------------------------------------------
    // Unified text scanning (formats + context + entropy => SecretDetector)
    // ------------------------------------------------------------------

    private static string ApplyScans(
        string? text,
        string mask,
        RedactionStats stats,
        bool detectByFormats,
        bool detectByKeyValueContext,
        bool detectByLongStrings,
        double detectEntropyThreshold)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text ?? string.Empty;
        }

        var opts = new DetectOptions
        {
            ByFormats = detectByFormats,
            ByKeyValueContext = detectByKeyValueContext,
            ByLongStrings = detectByLongStrings,
            EntropyThreshold = detectEntropyThreshold,
        };

        return ApplyFindings(text, mask, stats, opts);
    }

    /// <summary>
    /// Masks every finding returned by <see cref="SecretDetector.Detect"/> in a single pass,
    /// rebuilding the string around the detected spans. Stats are tallied per detector family.
    /// </summary>
    private static string ApplyFindings(string current, string mask, RedactionStats stats, DetectOptions opts)
    {
        var findings = SecretDetector.Detect(current, opts);
        if (findings.Count == 0)
        {
            return current;
        }

        var sb = new StringBuilder(current.Length + 64);
        var cursor = 0;
        var formatCount = 0;
        var contextCount = 0;
        var entropyCount = 0;
        var byKindCounts = new Dictionary<string, int>(StringComparer.Ordinal);

        foreach (var finding in findings)
        {
            sb.Append(current, cursor, finding.Start - cursor);
            sb.Append(mask);

            if (finding.Detector == SecretDetector.DetectorFormat)
            {
                formatCount++;
            }
            else if (finding.Detector == SecretDetector.DetectorContext)
            {
                contextCount++;
            }
            else
            {
                entropyCount++;
            }

            byKindCounts[finding.Category] = byKindCounts.TryGetValue(finding.Category, out var n) ? n + 1 : 1;
            AddPreview(stats, finding.Category);

            cursor = finding.Start + finding.Length;
        }

        sb.Append(current, cursor, current.Length - cursor);

        if (formatCount > 0)
        {
            stats.FormatRedactions += formatCount;
        }

        if (contextCount > 0)
        {
            stats.ContextRedactions += contextCount;
        }

        if (entropyCount > 0)
        {
            stats.LongStringRedactions += entropyCount;
        }

        foreach (var kv in byKindCounts)
        {
            stats.ByKind[kv.Key] = stats.ByKind.TryGetValue(kv.Key, out var count) ? count + kv.Value : kv.Value;
        }

        return sb.ToString();
    }
}
