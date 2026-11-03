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
    Confidence Confidence);

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
        // Stripe
        new(new Regex(@"sk_(?:live|test)_[0-9A-Za-z]{10,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "stripe", Confidence.High),
        // GitHub
        new(new Regex(@"gh[pousr]_[A-Za-z0-9]{10,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "github", Confidence.High),
        new(new Regex(@"github_pat_[A-Za-z0-9_]{20,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "github", Confidence.High),
        // Google
        new(new Regex(@"AIza[0-9A-Za-z_-]{20,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "google", Confidence.High),
        // Slack
        new(new Regex(@"xox[baprs]-[0-9A-Za-z-]{10,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "slack", Confidence.High),
        // npm
        new(new Regex(@"npm_[A-Za-z0-9]{20,}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "npm", Confidence.Medium),
        // AWS access key id - all real prefixes (AKIA/ASIA/AIDA/AROA/AGPA + exactly 16 base32 chars)
        new(new Regex(@"(?:AKIA|ASIA|AIDA|AROA|AGPA)[0-9A-Z]{16}",
            RegexOptions.Compiled | RegexOptions.CultureInvariant), "aws", Confidence.High),
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
    /// Catches config excerpts pasted into messages: `"LocalKey": "abc..."`, `LOCAL_KEY=abc...`,
    /// `password: abc...`, AWS `aws_secret_access_key=...` (base64 with / + =). Only the value
    /// is masked (the name + separator stay). Values may contain common password symbols
    /// (! @ # $ % ^ &amp; * ( )), but always delimit at ; , space or quotes so connection
    /// strings do not swallow the next key.
    /// </summary>
    private static readonly Regex KeyValueContextRegex = new(
        @"(?i)(?<![A-Za-z0-9_])"
        + @"(?<name>aws[_-]?secret[_-]?(?:access[_-]?)?key|aws[_-]?access[_-]?key[_-]?(?:id)?|secret[_-]?access[_-]?key|access[_-]?key[_-]?id|access[_-]?key|api[_-]?key|api[_-]?secret|loc[a]?l[_-]?key|secret[_-]?key|secret|private[_-]?key|master[_-]?key|encryption[_-]?key|client[_-]?secret|password|passwd|senha|credential|authorization|access[_-]?token|refresh[_-]?token|bearer[_-]?token)"
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
    /// (format &gt; context &gt; entropy), then by longest match.
    /// </summary>
    public static IReadOnlyList<SecretFinding> Detect(string? text, DetectOptions? options)
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
            ScanContext(text, findings);
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

    private static void ScanContext(string text, List<SecretFinding> findings)
    {
        var matches = KeyValueContextRegex.Matches(text);

        foreach (Match m in matches)
        {
            var value = m.Groups["value"];
            if (!value.Success || value.Length == 0)
            {
                continue;
            }

            findings.Add(new SecretFinding(KindKeyValue, DetectorContext, value.Index, value.Length, Confidence.Medium));
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

    /// <summary>Sorts by start, then detector priority, then longest match; drops overlaps.</summary>
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
            if (finding.Start < lastEnd)
            {
                continue; // overlaps an accepted finding
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
