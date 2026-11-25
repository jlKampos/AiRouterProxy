using System.Text.RegularExpressions;

namespace AIRouterProxy;

/// <summary>How strong the signal is. Never a proof by itself - entropy, in particular,
/// is only ever one of several combined signals.</summary>
public enum Confidence
{
    Low,
    Medium,
    High,
}

/// <summary>
/// A single secret detection. Deliberately never carries the matched value - only its
/// position/length in the scanned text, the category, the detector that found it and a
/// confidence. The value itself always stays in the original text and is replaced by the mask.
/// </summary>
public sealed record SecretFinding(
    string Category,
    string Detector,
    int Start,
    int Length,
    Confidence Confidence)
{
    /// <summary>Context scanner (also inherited by `format` when it overlaps a context at the same offset): the identifier before the separator (fixed whitelist - never the value).</summary>
    public string? Name { get; init; }

    /// <summary>Context scanner (also inherited by `format` on the same offset): separator normalized to "=" or ":".</summary>
    public string? Sep { get; init; }

    /// <summary>
    /// Context scanner (also inherited by `format` on the same offset): quote character wrapping
    /// the value (`"`, `'` or "" when unquoted). Null for `field`/`entropy` and for a `format`
    /// that did not inherit a shape, where the shape does not apply.
    /// </summary>
    public string? Quote { get; init; }

    /// <summary>true when an overlapping `format` finding was absorbed; such a span is never exempted</summary>
    public bool IncludesFormat { get; init; }
}

/// <summary>
/// Unified secret-detection engine (pure, testable in isolation; the test harness links
/// this file directly). Scans free text with three layers:
///  A) known formats (sk-, ghp_, AIza, AKIA, JWT, Bearer, PEM...) - High confidence;
///  B) "key: value" / "KEY=value" context (config excerpts)         - Medium;
///  C) long random-looking tokens via Shannon entropy               - Medium (never alone).
/// Findings never carry the matched value.
/// </summary>
public static class SecretDetector
{
    public const string DetectorFormat = "format";
    public const string DetectorContext = "context";
    public const string DetectorEntropy = "entropy";

    /// <summary>Category used for "key: value" context matches (kept for backwards-compatible stats).</summary>
    public const string KindKeyValue = "key_in_text";

    /// <summary>Category used for entropy/long-string matches.</summary>
    public const string KindLongString = "suspicious_key";

    private const int LongStringMinLength = 28;

    // ------------------------------------------------------------------
    // Scanner A — KNOWN FORMATS (specialized prefixes; High confidence)
    // ------------------------------------------------------------------

    private sealed record FormatPattern(Regex Regex, string Kind, Confidence Matches, string? PrefixGroup = null);

    private static readonly FormatPattern[] FormatPatterns =
    {
        // Anthropic (sk-ant-...)
        new(new Regex(@"sk-ant-[A-Za-z0-9_-]{10,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "anthropic", Confidence.High),
        // OpenAI / project keys (sk-... but not sk-ant-...)
        new(new Regex(@"sk-(?!ant-)(?:proj-|live-|test-)?[A-Za-z0-9_-]{10,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "openai", Confidence.High),
        new(new Regex(@"sk_[A-Za-z0-9]{20,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "openai", Confidence.High),
        // Stripe (secret & restricted keys; live/test/prod)
        new(new Regex(@"(?:sk|rk)_(?:live|test|prod)_[0-9A-Za-z]{10,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "stripe", Confidence.High),
        // GitHub (classic PATs are exactly 36 chars after the prefix)
        new(new Regex(@"gh[pousr]_[A-Za-z0-9]{36}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "github", Confidence.High),
        new(new Regex(@"github_pat_[A-Za-z0-9_]{20,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "github", Confidence.High),
        // Google API keys + OAuth 2.0 access tokens (ya29.)
        new(new Regex(@"AIza[0-9A-Za-z_-]{20,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "google", Confidence.High),
        new(new Regex(@"\bya29\.[0-9A-Za-z_-]{20,}\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "google_oauth", Confidence.High),
        // Slack
        new(new Regex(@"xox[baprs]-[0-9A-Za-z-]{10,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "slack", Confidence.High),
        // npm (real tokens: 36 lowercase alphanumeric chars)
        new(new Regex(@"\bnpm_[a-z0-9]{20,}\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "npm", Confidence.Medium),
        // AWS access key id - real prefixes, base32 alphabet (no 0/1/8/9), exactly 16 body chars
        new(new Regex(@"\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "aws", Confidence.High),
        // GitLab personal access token (glpat- + 20 chars)
        new(new Regex(@"\bglpat-[\w-]{20}\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "gitlab", Confidence.High),
        // DigitalOcean personal access token (dop_v1_ + 64 hex)
        new(new Regex(@"\bdop_v1_[a-f0-9]{64}\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "digitalocean", Confidence.High),
        // Hugging Face access token (hf_ + 34 chars)
        new(new Regex(@"\bhf_[A-Za-z0-9]{34}\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "huggingface", Confidence.High),
        // Replicate API token (r8_ + 37 chars)
        new(new Regex(@"\br8_[A-Za-z0-9]{37}\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "replicate", Confidence.High),
        // PyPI upload token (fixed base64 prefix + long body)
        new(new Regex(@"\bpypi-AgEIcHlwaS5vcmc[\w-]{50,}\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "pypi", Confidence.High),
        // Docker Hub personal access token (dckr_pat_ + 27 chars)
        new(new Regex(@"\bdckr_pat_[A-Za-z0-9_-]{27}\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "dockerhub", Confidence.High),
        // Twilio API key SID (SK + 32 hex)
        new(new Regex(@"\bSK[0-9a-fA-F]{32}\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "twilio", Confidence.High),
        // SendGrid API key (SG. + ~66 chars body)
        new(new Regex(@"\bSG\.[A-Za-z0-9_\-\.=]{66}\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "sendgrid", Confidence.High),
        // Mailgun API key (key- + 32 hex)
        new(new Regex(@"\bkey-[a-f0-9]{32}\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "mailgun", Confidence.Medium),
        // Shopify admin/custom/private/shared tokens (32 hex)
        new(new Regex(@"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "shopify", Confidence.High),
        // Discord bot token (heuristic: base64 bot id + 2 segments)
        new(new Regex(@"\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27,}\b",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "discord", Confidence.Medium),
        // Discord webhook URL (id + token path)
        new(new Regex(@"https://(?:www\.|ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{17,20}/[A-Za-z0-9_-]{60,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "discord", Confidence.Medium),
        // Azure Storage account key (88 base64 chars incl. trailing ==)
        new(new Regex(@"AccountKey=[A-Za-z0-9+/]{86}==",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "azure", Confidence.High),
        // Azure Storage connection string
        new(new Regex(@"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "azure", Confidence.High),
        // Database URL credentials (user:pass@) - group 1 = scheme kept, group 2 = masked
        new(new Regex(@"(?i)\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://)([^/\s:@]+:[^@\s/]+@)",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "db_conn", Confidence.High, "1"),
        // JWT
        new(new Regex(@"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "jwt", Confidence.High),
        // "Bearer <token>" in text - group 1 is the prefix (kept), group 2 is the value (masked)
        new(new Regex(@"(Bearer\s+)([A-Za-z0-9._~+/=-]{12,})",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "bearer", Confidence.High, "1"),
        // URL-embedded credentials "scheme://user:pass@host" - group 1 is the scheme (kept),
        // group 2 is the "user:pass@" part (masked). Only http(s)/ftp/ssh use this syntax.
        new(new Regex(@"(?i)(?<![A-Za-z0-9])((?:https?|ftp|ssh)://)([^/\s:@]+:[^@\s/]+@)",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "url_cred", Confidence.High, "1"),
        // PEM private key blocks
        new(new Regex(@"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "private_key", Confidence.High),
    };

    // ------------------------------------------------------------------
    // Scanner B — "key: value" CONTEXT in text (config excerpts)
    // ------------------------------------------------------------------

    /// <summary>
    /// Name alternatives of the "key: value" scanner. Exposed to the test harness so the
    /// whitelist assertion can be derived from the real regex alternatives instead of a
    /// hand-copied list that could silently drift.
    /// </summary>
    internal const string ContextNamePattern =
        @"aws[_-]?secret[_-]?(?:access[_-]?)?key|aws[_-]?access[_-]?key[_-]?(?:id)?|secret[_-]?access[_-]?key|access[_-]?key[_-]?id|access[_-]?key|api[_-]?key|api[_-]?secret|loc[a]?l[_-]?key|secret[_-]?key|secret|private[_-]?key|master[_-]?key|encryption[_-]?key|client[_-]?secret|password|passwd|senha|credential|authorization|access[_-]?token|refresh[_-]?token|bearer[_-]?token|auth[_-]?token|session[_-]?token|id[_-]?token|jwt[_-]?key|signing[_-]?key|token";

    /// <summary>
    /// Matches a complete whitelisted context name (the same alternatives as
    /// <see cref="ContextNamePattern"/>). Used to keep a credential value such as
    /// `SECRET_KEY=&lt;blob&gt;` from being mistaken for a base64 payload.
    /// </summary>
    private static readonly Regex SensitiveContextNameOnly = new(
        "^(?:" + ContextNamePattern + ")$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    /// <summary>
    /// Catches config excerpts pasted into messages: `"LocalKey": "abc..."`, `LOCAL_KEY=abc...`,
    /// `password: abc...`, AWS `aws_secret_access_key=...` (base64 with / + =). Only the value
    /// is masked (the name + separator stay). Values may contain common password symbols
    /// (! @ # $ % ^ &amp; * ( )), but always delimit at ; , space or quotes so connection
    /// strings do not swallow the next key.
    /// </summary>
    private static readonly Regex KeyValueContextRegex = new(
        @"(?i)(?<![A-Za-z0-9_])"
        + @"(?<name>" + ContextNamePattern + @")"
        + @"(?<sep>[\""']?\s*[:=]\s*[\""']?)"
        + @"(?<value>[A-Za-z0-9_~+/=!@#$%^&*().\-]{8,})",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // ------------------------------------------------------------------
    // Scanner C — LONG STRINGS with Shannon entropy
    // ------------------------------------------------------------------

    private static readonly Regex LongStringRegex = new(
        @"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{28,}(?![A-Za-z0-9_-])",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    // Hex-only tokens (git SHAs, UUID-like, hex secrets) max out at 17 distinct chars,
    // so they can never satisfy the wide-alphabet test below: they are excluded on purpose.
    private static readonly Regex HexOnlyRegex = new(
        @"^[0-9a-fA-F-]+$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>Shannon entropy (bits per character): H = -Σ p(c)·log2(p(c)).</summary>
    public static double ShannonEntropy(string s)
    {
        if (string.IsNullOrEmpty(s))
        {
            return 0.0;
        }

        var freq = new Dictionary<char, int>();
        foreach (var c in s)
        {
            freq[c] = freq.TryGetValue(c, out var n) ? n + 1 : 1;
        }

        double h = 0.0;
        foreach (var kv in freq)
        {
            var p = (double)kv.Value / s.Length;
            h -= p * Math.Log2(p);
        }

        return h;
    }

    /// <summary>
    /// Runs every enabled scanner over <paramref name="text"/> and returns the merged,
    /// non-overlapping findings. Overlaps are resolved by detector priority
    /// (format &gt; context &gt; entropy), then by longest match; the surviving finding grows
    /// to cover the union, so the returned spans are never shorter than a single detector's.
    /// </summary>
    /// <param name="collectShape">
    /// When true the context scanner also records the pattern SHAPE (whitelisted name,
    /// normalized separator and quote). False by default so the hot redaction path never
    /// allocates those strings - forensics opt in explicitly.
    /// </param>
    public static IReadOnlyList<SecretFinding> Detect(string? text, DetectOptions? options, bool collectShape = false)
    {
        if (string.IsNullOrEmpty(text))
        {
            return Array.Empty<SecretFinding>();
        }

        options ??= new DetectOptions();
        var findings = new List<SecretFinding>();

        if (options.ByFormats)
        {
            ScanFormats(text, findings);
        }

        if (options.ByKeyValueContext)
        {
            ScanContext(text, findings, collectShape);
        }

        if (options.ByLongStrings)
        {
            ScanEntropy(text, findings, options.EntropyThreshold);
        }

        return Merge(findings);
    }

    private static void ScanFormats(string text, List<SecretFinding> findings)
    {
        foreach (var pattern in FormatPatterns)
        {
            var matches = pattern.Regex.Matches(text);
            if (matches.Count == 0)
            {
                continue;
            }

            foreach (Match m in matches)
            {
                var start = m.Index;
                var length = m.Length;

                if (pattern.PrefixGroup is not null)
                {
                    // Convention: group 1 = prefix kept (e.g. "Bearer "), group 2 = value masked.
                    var value = m.Groups[2];
                    if (!value.Success || value.Length == 0)
                    {
                        continue;
                    }

                    start = value.Index;
                    length = value.Length;
                }

                findings.Add(new SecretFinding(pattern.Kind, DetectorFormat, start, length, pattern.Matches));
            }
        }
    }

    private static void ScanContext(string text, List<SecretFinding> findings, bool collectShape)
    {
        var matches = KeyValueContextRegex.Matches(text);

        foreach (Match m in matches)
        {
            var value = m.Groups["value"];
            if (!value.Success || value.Length == 0)
            {
                continue;
            }

            // Zero-cost path: no shape strings (name/sep/quote) are materialized unless the
            // caller asked for forensics metadata.
            if (!collectShape)
            {
                findings.Add(new SecretFinding(KindKeyValue, DetectorContext, value.Index, value.Length, Confidence.Medium));
                continue;
            }

            var sepRaw = m.Groups["sep"].Value;

            // Quote is derived ONLY from the last non-space character of the separator group,
            // so a closing quote that belongs to the NAME (`"LocalKey" = abc`) does not count.
            var sepTrimmed = sepRaw.TrimEnd();
            var quote = sepTrimmed.EndsWith("\"") ? "\""
                : sepTrimmed.EndsWith("'") ? "'"
                : "";

            findings.Add(new SecretFinding(KindKeyValue, DetectorContext, value.Index, value.Length, Confidence.Medium)
            {
                Name = m.Groups["name"].Value.ToLowerInvariant(),
                Sep = sepRaw.Contains('=') ? "=" : ":",
                Quote = quote,
            });
        }
    }

    private static void ScanEntropy(string text, List<SecretFinding> findings, double threshold)
    {
        var matches = LongStringRegex.Matches(text);

        foreach (Match m in matches)
        {
            var token = m.Value;
            if (token.Length < LongStringMinLength)
            {
                continue;
            }

            if (ShannonEntropy(token) < threshold)
            {
                continue;
            }

            if (!LooksRandom(token))
            {
                continue;
            }

            findings.Add(new SecretFinding(KindLongString, DetectorEntropy, m.Index, token.Length, Confidence.Medium));
        }
    }

    /// <summary>
    /// False-positive guard for the entropy layer. Entropy alone is never enough: a token is only
    /// "random-looking" when it either draws from a wide alphabet (20+ distinct chars, which no
    /// real prose/hex/id string reaches) or is a compact mixed-class value (case + digit + symbol).
    /// </summary>
    private static bool LooksRandom(string token)
    {
        if (HexOnlyRegex.IsMatch(token))
        {
            return false;
        }

        var distinct = new HashSet<char>();
        var lower = false;
        var upper = false;
        var digit = false;
        var symbol = false;

        foreach (var c in token)
        {
            distinct.Add(c);

            if (char.IsLower(c)) lower = true;
            else if (char.IsUpper(c)) upper = true;
            else if (char.IsDigit(c)) digit = true;
            else symbol = true;
        }

        if (distinct.Count >= 20)
        {
            return true;
        }

        var classes = (lower ? 1 : 0) + (upper ? 1 : 0) + (digit ? 1 : 0) + (symbol ? 1 : 0);
        return distinct.Count >= 12 && classes >= 3;
    }

    /// <summary>Below this length a "base64-looking" run is not treated as payload yet.</summary>
    private const int Base64PayloadMinLength = 100;

    private static bool IsBase64Char(char c) =>
        (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
        || c is '+' or '/' or '=' or '-' or '_';

    /// <summary>
    /// True when a whole string value is a binary payload and must bypass text scanning:
    /// a data URL ("data:...;base64,&lt;payload&gt;", e.g. OpenAI image_url.url) or a long
    /// standalone base64 blob (e.g. Anthropic source.data).
    /// <para>
    /// Those payloads are never scanned as text: scanning them neither finds keys (they are
    /// bytes, not pasted text) nor fixes anything - it only corrupts the base64 with the mask
    /// (litellm "only ASCII" errors). Detection is deliberately narrow: structural characters
    /// (/ + =) are required so real random-looking text, hashes, slugs and filenames are still
    /// caught by the entropy layer.
    /// </para>
    /// <para>
    /// A region introduced by a sensitive context name is never treated as payload: the
    /// identifier and the separator are base64 characters too, but `SECRET_KEY=&lt;blob&gt;` is a
    /// credential value that must be masked, not an image.
    /// </para>
    /// </summary>
    public static bool IsBase64Payload(string? text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        var trimmed = text.Trim();
        if (trimmed.StartsWith("data:", StringComparison.OrdinalIgnoreCase)
            && trimmed.Contains(";base64,", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // A region introduced by a sensitive context name is a credential, not payload: the
        // identifier and the separator are base64 characters too, so only the name tells a
        // `SECRET_KEY=<blob>` value apart from a real blob.
        if (IntroducedBySensitiveName(trimmed))
        {
            return false;
        }

        if (trimmed.Length < Base64PayloadMinLength)
        {
            return false;
        }

        var payload = trimmed.AsSpan();
        var structural = false;
        foreach (var c in payload)
        {
            if (c is '/' or '+' or '=')
            {
                structural = true;
            }
            else if (char.IsWhiteSpace(c))
            {
                // Base64 with line breaks is still base64.
                continue;
            }
            else if (!IsBase64Char(c))
            {
                return false;
            }
        }

        return structural;
    }

    /// <summary>
    /// True when an entropy/context finding lies inside a base64 payload region of a longer
    /// text (a data URL or base64 blob pasted inline among prose). "format" findings are never
    /// exempted, even here, so pasted keys next to an image are still masked. A region
    /// introduced by a sensitive context name is never treated as payload, so
    /// `SECRET_KEY=&lt;blob&gt;` is masked like any other credential value.
    /// </summary>
    public static bool IsInsideBase64Payload(string text, SecretFinding finding)
    {
        var start = finding.Start;
        var end = finding.Start + finding.Length;

        while (start > 0 && IsBase64Char(text[start - 1]))
        {
            start--;
        }

        while (end < text.Length && IsBase64Char(text[end]))
        {
            end++;
        }

        // A region introduced by a sensitive context name is a credential, not payload: the
        // identifier and the separator are base64 characters too, so only the name tells them
        // apart (`=` padding lives at the END of a blob, never right after the name).
        // `NAME = <value>` is written with whitespace around the separator, which is not a
        // base64 character - look left across it so the name still reaches the shared rule.
        var namedStart = ExtendLeftOverSeparator(text, start);
        if (namedStart < start && IntroducedBySensitiveName(text.AsSpan(namedStart, end - namedStart)))
        {
            return false;
        }

        if (IntroducedBySensitiveName(text.AsSpan(start, end - start)))
        {
            return false;
        }

        if (end - start < Base64PayloadMinLength)
        {
            return false;
        }

        for (var i = start; i < end; i++)
        {
            if (text[i] is '/' or '+' or '=')
            {
                return true;
            }
        }

        // A payload glued to its marker ("...base64,&lt;blob&gt;") counts as base64 even when
        // the blob itself has no structural symbol (tiny images).
        return text.AsSpan(0, start).EndsWith("base64,", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// True when the first `=` of the region is introduced by a whitelisted context name
    /// (`SECRET_KEY=&lt;blob&gt;`): such a region is a credential value, not a base64 payload.
    /// The identifier is the run of letters/digits/underscore/hyphen IMMEDIATELY before the `=`
    /// (whitespace between the name and `=` is skipped, so `SECRET_KEY = &lt;blob&gt;` counts),
    /// never the whole prefix - prose such as `zz SECRET_KEY=&lt;blob&gt;` is still a credential,
    /// while the run before the padding of a real blob is the blob itself (longer than 40, so
    /// the length bound keeps the legitimate exemption).
    /// </summary>
    private static bool IntroducedBySensitiveName(ReadOnlySpan<char> span)
    {
        var nameEnd = span.IndexOf('=');

        // `=` padding lives at the END of a blob, never right after the name.
        if (nameEnd <= 0 || nameEnd >= span.Length - 1)
        {
            return false;
        }

        // `NAME = value` is still a credential: skip the whitespace between the name and '='.
        while (nameEnd > 0 && (span[nameEnd - 1] == ' ' || span[nameEnd - 1] == '\t'))
        {
            nameEnd--;
        }

        var idStart = nameEnd;
        while (idStart > 0 && (char.IsLetterOrDigit(span[idStart - 1]) || span[idStart - 1] == '_' || span[idStart - 1] == '-'))
        {
            idStart--;
        }

        var id = span[idStart..nameEnd];
        return id.Length >= 2 && id.Length <= 40 && SensitiveContextNameOnly.IsMatch(id);
    }

    /// <summary>
    /// Extends <paramref name="start"/> left over an optional `NAME [ws] = [ws]` separator so a
    /// credential written as `SECRET_KEY = &lt;blob&gt;` keeps its identifier inside the region.
    /// Returns <paramref name="start"/> unchanged when no separator is found. Only the position
    /// is computed here - the caller decides whether the identifier is a sensitive name, so a
    /// non-sensitive `dat = &lt;blob&gt;` keeps exactly the previous behaviour.
    /// </summary>
    private static int ExtendLeftOverSeparator(string text, int start)
    {
        var probe = start;
        while (probe > 0 && (text[probe - 1] == ' ' || text[probe - 1] == '\t'))
        {
            probe--;
        }

        if (probe == 0 || text[probe - 1] != '=')
        {
            return start;
        }

        probe--; // the '=' itself

        // Whitespace between the name and '=' is part of `NAME = value`.
        while (probe > 0 && (text[probe - 1] == ' ' || text[probe - 1] == '\t'))
        {
            probe--;
        }

        while (probe > 0 && IsBase64Char(text[probe - 1]))
        {
            probe--;
        }

        return probe;
    }

    /// <summary>
    /// Sorts by start, then detector priority, then longest match; overlapping candidates are
    /// merged (the union is masked) so the proxy never masks less than any single detector would
    /// at the span level. The base64 and allow-list exemptions are still decided on the merged
    /// span, and a span that covers a `format` finding is never exempted.
    /// </summary>
    private static IReadOnlyList<SecretFinding> Merge(List<SecretFinding> findings)
    {
        if (findings.Count <= 1)
        {
            return findings;
        }

        findings.Sort((a, b) =>
        {
            var byStart = a.Start.CompareTo(b.Start);
            if (byStart != 0)
            {
                return byStart;
            }

            var byDetector = DetectorPriority(a.Detector).CompareTo(DetectorPriority(b.Detector));
            return byDetector != 0 ? byDetector : b.Length.CompareTo(a.Length);
        });

        var merged = new List<SecretFinding>(findings.Count);
        var lastEnd = -1;

        foreach (var finding in findings)
        {
            if (merged.Count > 0 && finding.Start < lastEnd)
            {
                var winner = merged[^1];

                // Shape metadata (name/separator/quote) only applies when both findings describe
                // the same value (same offset) - format wins the layer, context supplies the shape.
                if (finding.Name is not null && winner.Name is null && finding.Start == winner.Start)
                {
                    winner = winner with { Name = finding.Name, Sep = finding.Sep, Quote = finding.Quote };
                }

                // Never mask less than a single detector would: the winner grows to cover the
                // overlapping candidate's tail (a contained candidate leaves the span unchanged).
                var winnerEnd = winner.Start + winner.Length;
                var findingEnd = finding.Start + finding.Length;
                if (findingEnd > winnerEnd)
                {
                    winner = winner with { Length = findingEnd - winner.Start };
                }

                // A span that absorbed a `format` finding must never be exempted (base64 /
                // allow-list): otherwise a context/entropy winner could mask LESS than the
                // format detector alone would have.
                winner = winner with
                {
                    IncludesFormat = winner.IncludesFormat
                        || finding.Detector == DetectorFormat
                        || finding.IncludesFormat,
                };

                merged[^1] = winner;
                // The winner only grows, so its end is the merged span's end by invariant.
                lastEnd = winner.Start + winner.Length;
                continue;
            }

            merged.Add(finding);
            lastEnd = finding.Start + finding.Length;
        }

        return merged;
    }

    private static int DetectorPriority(string detector) => detector switch
    {
        DetectorFormat => 0,
        DetectorContext => 1,
        _ => 2,
    };
}
