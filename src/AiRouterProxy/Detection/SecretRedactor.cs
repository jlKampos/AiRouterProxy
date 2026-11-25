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

        /// <summary>
        /// Forensic metadata of each detection (where/which layer/kind/length/fingerprint).
        /// Only populated when <c>collectForensics</c> is true; capped per request. Never
        /// carries the detected value.
        /// </summary>
        public List<DetectionRecord> Detections { get; } = new();
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
    /// <param name="collectForensics">
    /// When false (default) no forensic metadata is produced: the structural JSON path is not
    /// built and no fingerprint is computed, so the hot path pays nothing for the feature.
    /// When true, each detection records path/layer/kind/length/fingerprint in
    /// <see cref="RedactionStats.Detections"/> (never the value), capped per pass.
    /// </param>
    public static Result RedactJson(
        byte[] body,
        bool enabled = true,
        string? mask = null,
        bool detectByFieldName = true,
        bool detectByFormats = true,
        bool detectByKeyValueContext = true,
        bool detectByLongStrings = true,
        double detectEntropyThreshold = 3.0,
        bool exemptBase64 = true,
        IReadOnlyList<string>? allow = null,
        bool collectForensics = false)
    {
        var result = new Result { Data = body, Changed = false };

        var allowRegexes = CompileAllow(allow);

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
                    detectEntropyThreshold, exemptBase64, allowRegexes, "$", 0, collectForensics);
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
        "google_oauth" => "Google OAuth token",
        "gitlab" => "GitLab token",
        "digitalocean" => "DigitalOcean token",
        "huggingface" => "Hugging Face token",
        "replicate" => "Replicate token",
        "pypi" => "PyPI token",
        "dockerhub" => "Docker Hub token",
        "twilio" => "Twilio API key",
        "sendgrid" => "SendGrid API key",
        "mailgun" => "Mailgun API key",
        "shopify" => "Shopify token",
        "discord" => "Discord token",
        "azure" => "Azure key",
        "db_conn" => "database credentials",
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
            case "auth_token":
            case "authtoken":
            case "auth-token":
            case "session_token":
            case "sessiontoken":
            case "session-token":
            case "id_token":
            case "idtoken":
            case "id-token":
            case "jwtkey":
            case "jwt_key":
            case "jwt-key":
            case "signingkey":
            case "signing_key":
            case "signing-key":
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
            || lower.Contains("jwt")
            || lower.Contains("signing")
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

        if (lower.Contains("jwt") || lower.Contains("signing"))
        {
            return "secret";
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
        double detectEntropyThreshold,
        bool exemptBase64,
        IReadOnlyList<Regex>? allowRegexes,
        string path,
        int depth,
        bool collectForensics)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                writer.WriteStartObject();
                foreach (var property in element.EnumerateObject())
                {
                    writer.WritePropertyName(property.Name);
                    // The path is only built when forensics are on (zero cost otherwise).
                    var childPath = collectForensics ? AppendProperty(path, property.Name, depth + 1) : string.Empty;
                    WriteElement(writer, property.Value, property.Name, mask, stats,
                        detectByFieldName, detectByFormats, detectByKeyValueContext, detectByLongStrings,
                        detectEntropyThreshold, exemptBase64, allowRegexes,
                        childPath, depth + 1, collectForensics);
                }
                writer.WriteEndObject();
                break;

            case JsonValueKind.Array:
                writer.WriteStartArray();
                var index = 0;
                foreach (var item in element.EnumerateArray())
                {
                    var childPath = collectForensics ? AppendIndex(path, index, depth + 1) : string.Empty;
                    WriteElement(writer, item, null, mask, stats,
                        detectByFieldName, detectByFormats, detectByKeyValueContext, detectByLongStrings,
                        detectEntropyThreshold, exemptBase64, allowRegexes,
                        childPath, depth + 1, collectForensics);
                    index++;
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

                    if (collectForensics && !string.IsNullOrEmpty(text))
                    {
                        // An empty value carries no information: no length-0 record.
                        AddDetection(stats, path, "field", kind, text.Length, text.AsSpan());
                    }
                }
                else
                {
                    writer.WriteStringValue(ApplyScans(text, mask, stats,
                        detectByFormats, detectByKeyValueContext, detectByLongStrings, detectEntropyThreshold,
                        exemptBase64, allowRegexes, path, collectForensics));
                }
                break;

            default:
                element.WriteTo(writer);
                break;
        }
    }

    // ------------------------------------------------------------------
    // Detection forensics (opt-in): structural path + category + length + fingerprint
    // ------------------------------------------------------------------

    /// <summary>Hard cap of forensic records per redaction pass (a pathological body cannot grow it).</summary>
    public const int MaxDetections = 50;

    /// <summary>Fixed placeholder used when a property NAME itself looks like a secret.</summary>
    public const string RedactedNamePlaceholder = "<redacted-name>";

    private const int MaxPathDepth = 12;
    private const int MaxPathLength = 200;
    private const int MaxSegmentLength = 40;

    /// <summary>
    /// Test instrumentation: number of path segments built since the last reset. Always 0 when
    /// <c>collectForensics</c> is false - used to prove the zero-cost path without timers.
    /// </summary>
    internal static long PathSegmentsBuilt;

    internal static void ResetPathInstrumentation() => PathSegmentsBuilt = 0;

    /// <summary>
    /// Property NAMES are checked with the high-confidence scanners only: a name is not a value,
    /// so the entropy/long-string heuristic must not apply - it would flag legitimate long
    /// camelCase names with digits (e.g. "responseFormatJsonSchema2024"). Known formats and
    /// "key: value" context still catch a pasted credential used as a property name.
    /// </summary>
    private static readonly DetectOptions SegmentDetectOptions = new()
    {
        ByFormats = true,
        ByKeyValueContext = true,
        ByLongStrings = false,
        ExemptBase64 = true,
    };

    /// <summary>
    /// Registers one forensic record. The value itself is never stored: only its length, a
    /// process-local, non-reversible fingerprint and - for the context layer - the SHAPE of the
    /// pattern (whitelisted name + separator + quote). No-op unless forensics were requested.
    /// The value is accepted as a span so no string is materialized just for the fingerprint.
    /// </summary>
    private static void AddDetection(RedactionStats stats, string path, string layer, string kind, int length,
        ReadOnlySpan<char> value, string? name = null, string? sep = null, string? quote = null)
    {
        if (stats.Detections.Count >= MaxDetections)
        {
            return;
        }

        stats.Detections.Add(new DetectionRecord(
            JsonPath: TruncatePath(path),
            Layer: layer,
            Kind: kind,
            Length: length,
            Fingerprint: DetectionFingerprint.Of(value),
            Name: name,
            Sep: sep,
            Quote: quote));
    }

    /// <summary>Maps a <see cref="SecretFinding"/> detector family to the forensic layer name.</summary>
    private static string LayerOf(SecretFinding finding) => finding.Detector switch
    {
        SecretDetector.DetectorFormat => "format",
        SecretDetector.DetectorContext => "context",
        _ => "entropy",
    };

    /// <summary>
    /// Property segment for the forensic path: control characters removed, capped at 40 chars,
    /// path delimiters escaped ("." / "[" / "]" become "_") so the path stays unambiguous, and
    /// a name whose text looks like a secret replaced by a fixed placeholder (a property NAME
    /// can be a pasted secret too). Never carries a value.
    /// </summary>
    private static string SanitizeSegment(string name)
    {
        if (string.IsNullOrEmpty(name))
        {
            return string.Empty;
        }

        Span<char> buffer = stackalloc char[Math.Min(name.Length, MaxSegmentLength)];
        var written = 0;
        foreach (var ch in name)
        {
            if (char.IsControl(ch))
            {
                continue;
            }

            if (written == buffer.Length)
            {
                break;
            }

            buffer[written++] = ch;
        }

        var segment = new string(buffer[..written]);
        if (segment.Length == 0)
        {
            return string.Empty;
        }

        // A secret-shaped NAME must never reach the path. Only the high-confidence scanners run
        // on names (see SegmentDetectOptions): the entropy heuristic would flag legitimate long
        // camelCase names, so it is deliberately excluded here.
        if (SecretDetector.Detect(segment, SegmentDetectOptions).Count > 0)
        {
            return RedactedNamePlaceholder;
        }

        return segment
            .Replace('.', '_')
            .Replace('[', '_')
            .Replace(']', '_');
    }

    /// <summary>Appends ".name" while the path is shallower than <see cref="MaxPathDepth"/>.</summary>
    private static string AppendProperty(string path, string name, int depth)
    {
        if (depth > MaxPathDepth)
        {
            return path;
        }

        Interlocked.Increment(ref PathSegmentsBuilt);
        return path + "." + SanitizeSegment(name);
    }

    /// <summary>Appends "[i]" while the path is shallower than <see cref="MaxPathDepth"/>.</summary>
    private static string AppendIndex(string path, int index, int depth)
    {
        if (depth > MaxPathDepth)
        {
            return path;
        }

        Interlocked.Increment(ref PathSegmentsBuilt);
        return path + "[" + index + "]";
    }

    /// <summary>Final path cap: 200 chars plus an ellipsis when it had to be shortened.</summary>
    private static string TruncatePath(string path)
        => path.Length <= MaxPathLength ? path : path[..MaxPathLength] + "\u2026";


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
        double detectEntropyThreshold,
        bool exemptBase64,
        IReadOnlyList<Regex>? allowRegexes,
        string path,
        bool collectForensics)
    {
        if (string.IsNullOrEmpty(text))
        {
            return text ?? string.Empty;
        }

        // Rule A: whole value is an image/binary payload - never scanned as text.
        if (exemptBase64 && SecretDetector.IsBase64Payload(text))
        {
            return text;
        }

        var opts = new DetectOptions
        {
            ByFormats = detectByFormats,
            ByKeyValueContext = detectByKeyValueContext,
            ByLongStrings = detectByLongStrings,
            EntropyThreshold = detectEntropyThreshold,
            ExemptBase64 = exemptBase64,
        };

        return ApplyFindings(text, mask, stats, opts, allowRegexes, path, collectForensics);
    }

    /// <summary>
    /// Masks every finding returned by <see cref="SecretDetector.Detect"/> in a single pass,
    /// rebuilding the string around the detected spans. Stats are tallied per detector family.
    /// </summary>
    private static string ApplyFindings(string current, string mask, RedactionStats stats, DetectOptions opts,
        IReadOnlyList<Regex>? allowRegexes, string path, bool collectForensics)
    {
        var findings = SecretDetector.Detect(current, opts, collectShape: collectForensics);
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
            // Rule B: entropy/context findings inside a base64 payload region (image data
            // URL or blob pasted inline) are binary bytes, not text - left untouched.
            // "format" findings are never exempted here (pasted keys still masked), and neither
            // is a merged span that absorbed one: the union must never mask less.
            var neverExempt = finding.Detector == SecretDetector.DetectorFormat || finding.IncludesFormat;
            var inBase64 = opts.ExemptBase64
                && !neverExempt
                && SecretDetector.IsInsideBase64Payload(current, finding);

            if (inBase64 || IsExemptedByAllow(finding, current, allowRegexes))
            {
                cursor = finding.Start + finding.Length;
                continue;
            }

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

            if (collectForensics)
            {
                // The value is only passed as a span (never stored): the record keeps length +
                // fingerprint. Context findings also carry the pattern SHAPE (whitelisted name +
                // separator + quote).
                AddDetection(stats, path, LayerOf(finding), finding.Category, finding.Length,
                    current.AsSpan(finding.Start, finding.Length),
                    finding.Name, finding.Sep, finding.Quote);
            }

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

    /// <summary>
    /// True when a detection is exempted by the configured allow-list (Redaction.allow).
    /// Only the medium-confidence scanners (context / entropy) may be exempted; the
    /// high-confidence format scanner is never exempted (sk-, ghp_, AIza, JWT, Bearer, PEM...),
    /// neither is a merged span that absorbed a format finding, and sensitive JSON field values
    /// are masked before text scanning.
    /// </summary>
    private static bool IsExemptedByAllow(SecretFinding finding, string current, IReadOnlyList<Regex>? allowRegexes)
    {
        if (allowRegexes is null || allowRegexes.Count == 0)
        {
            return false;
        }

        if (finding.Detector == SecretDetector.DetectorFormat || finding.IncludesFormat)
        {
            return false;
        }

        var token = current.Substring(finding.Start, finding.Length);
        foreach (var rx in allowRegexes)
        {
            if (rx.IsMatch(token))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Compiles the allow-list patterns once per redaction pass. Invalid patterns are ignored.</summary>
    private static IReadOnlyList<Regex>? CompileAllow(IReadOnlyList<string>? allow)
    {
        if (allow is null || allow.Count == 0)
        {
            return null;
        }

        var list = new List<Regex>(allow.Count);
        foreach (var pattern in allow)
        {
            if (string.IsNullOrWhiteSpace(pattern))
            {
                continue;
            }

            try
            {
                list.Add(new Regex(pattern, RegexOptions.Compiled | RegexOptions.CultureInvariant));
            }
            catch (ArgumentException)
            {
                // Invalid pattern - ignored; the rest of the allow-list still applies.
            }
        }

        return list.Count == 0 ? null : list;
    }
}

/// <summary>
/// One forensic record of a detection: the structural JSON path where it fired, the layer
/// (field/format/context/entropy), the category, the value length and a non-reversible
/// fingerprint. Never carries the detected value (see <see cref="DetectionFingerprint"/>).
/// </summary>
public sealed record DetectionRecord(
    string JsonPath,
    string Layer,
    string Kind,
    int Length,
    string Fingerprint,
    string? Name = null,
    string? Sep = null,
    string? Quote = null);

