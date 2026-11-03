namespace AIRouterProxy;

public sealed class ProxyOptions
{
    public const string SectionName = "Proxy";

    public string Host { get; set; } = "0.0.0.0";
    public int Port { get; set; } = 4000;
    public string Upstream { get; set; } = "https://api.airouter.ch";
    public List<string> AllowedPaths { get; set; } = new();

    public int RequestTimeoutMs { get; set; } = 300000;
    public long MaxBodySize { get; set; } = 20 * 1024 * 1024;
    public bool Verbose { get; set; } = true;

    public CertOptions Cert { get; set; } = new();
    public KeyOptions Keys { get; set; } = new();
    public RedactionOptions Redaction { get; set; } = new();

    /// <summary>
    /// Fail-closed body inspection policy: decides what to do with each Content-Type
    /// before anything is forwarded (see <see cref="InspectionOptions"/>).
    /// </summary>
    public InspectionOptions Inspection { get; set; } = new();

    /// <summary>
    /// Per-client rate limiting and brute-force protection (see <see cref="RateLimitOptions"/>).
    /// </summary>
    public RateLimitOptions RateLimit { get; set; } = new();

    /// <summary>
    /// Route table (Item 2). If empty, the proxy works as before:
    /// 1 fixed upstream (<see cref="Upstream"/>) + <see cref="AllowedPaths"/>.
    /// </summary>
    public List<RouteOptions> Routes { get; set; } = new();

    /// <summary>
    /// Per-route API keys, referenced by <see cref="RouteOptions.KeyRef"/>.
    /// Live in appsettings.Server.json / env (never in non-secret files).
    /// </summary>
    public Dictionary<string, string> RouteKeys { get; set; } = new(StringComparer.Ordinal);
}

/// <summary>
/// A route: a path prefix on the proxy + an upstream + the key to use.
/// <c>prefix: ""</c> is the default route (the current behavior stays intact).
/// </summary>
public sealed class RouteOptions
{
    /// <summary>Route name (shown in the activity log and on /admin).</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Path prefix that activates this route (e.g. "/openrouter"). "" = default route.
    /// The prefix is removed before forwarding; the rest (/v1/...) goes to the upstream.
    /// </summary>
    public string Prefix { get; set; } = string.Empty;

    /// <summary>Upstream base (e.g. "https://api.openai.com" or "https://openrouter.ai/api").</summary>
    public string Upstream { get; set; } = string.Empty;

    /// <summary>
    /// Key name in <see cref="ProxyOptions.RouteKeys"/>. Empty/null = uses the global "UpstreamKey"
    /// (compatibility: the default route needs nothing else).
    /// </summary>
    public string? KeyRef { get; set; }

    /// <summary>
    /// Allowed paths on this route (matched against the path after prefix removal, e.g. "/v1/chat/completions").
    /// Empty = everything under the prefix is accepted. Supports a "*" suffix (e.g. "/v1/*").
    /// </summary>
    public List<string> AllowedPaths { get; set; } = new();

    /// <summary>Route-specific timeout (ms). 0 = inherits Proxy.RequestTimeoutMs.</summary>
    public int RequestTimeoutMs { get; set; }
}

/// <summary>
/// Redaction of sensitive content in outgoing messages.
/// Optional section in JSON: "Proxy": { "Redaction": { ... } } - the defaults are already
/// safe, so the feature works without configuration.
/// </summary>
public sealed class RedactionOptions
{
    /// <summary>Turns redaction fully on/off (default: on).</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Text that replaces the redacted content (null = "••••••").</summary>
    public string? Mask { get; set; }

    /// <summary>Injects a visible notice at the end of the response when redaction occurs.</summary>
    public bool NotifyInResponse { get; set; } = true;

    /// <summary>
    /// Optional template for the notice; supports {Count} (number of occurrences) and
    /// {Kinds} (summary of categories). Empty/missing = default text.
    /// </summary>
    public string? WarnTemplate { get; set; }

    /// <summary>Detection layers (default: all active).</summary>
    public DetectOptions Detect { get; set; } = new();
}

/// <summary>
/// Fail-closed inspection of request bodies. "Security must fail closed": an uninspected
/// request is never forwarded, regardless of format, parse errors or size.
/// </summary>
public sealed class InspectionOptions
{
    /// <summary>Master switch for body inspection (default: on).</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Action for Content-Types not present in <see cref="ByContentType"/>.
    /// Default: "block" (415) - fail closed.
    /// </summary>
    public string DefaultAction { get; set; } = "block";

    /// <summary>
    /// Handling of a JSON body that does not parse: "block" (400, default) or "warn".
    /// "warn" forwards the body anyway (opt-in escape hatch - do not use without review).
    /// </summary>
    public string InvalidJson { get; set; } = "block";

    /// <summary>
    /// Media type (without parameters) -> action. "inspect" = parse + redact (only supported
    /// for JSON in this iteration); "block" = reject with 415. Unknown types use
    /// <see cref="DefaultAction"/>.
    /// </summary>
    public Dictionary<string, string> ByContentType { get; set; } = new(StringComparer.OrdinalIgnoreCase)
    {
        ["application/json"] = "inspect",
    };
}

public sealed class DetectOptions
{
    /// <summary>Value of properties with sensitive names (api_key, password, senha, token...).</summary>
    public bool ByFieldName { get; set; } = true;

    /// <summary>Known formats (sk-, ghp_, AIza, JWT, Bearer, PEM...).</summary>
    public bool ByFormats { get; set; } = true;

    /// <summary>"key: value" / "KEY=value" in text (config excerpts).</summary>
    public bool ByKeyValueContext { get; set; } = true;

    /// <summary>Long URL-safe tokens (>= 28 chars) with mixed classes.</summary>
    public bool ByLongStrings { get; set; } = true;

    /// <summary>
    /// Minimum Shannon entropy (bits/char) for the long-string scanner (default 3.0).
    /// Entropy is never the only signal - a token must also look random (wide alphabet
    /// or mixed classes) and not be a hex/uuid-like value.
    /// </summary>
    public double EntropyThreshold { get; set; } = 3.0;
}

/// <summary>
/// Rate limiting and brute-force protection, both per client IP.
/// - Requests beyond <see cref="MaxRequestsPerWindow"/> in <see cref="RequestWindowSeconds"/> -> 429.
/// - After <see cref="MaxFailuresPerWindow"/> failed local-key attempts in
///   <see cref="FailureWindowSeconds"/>, the client is locked out for <see cref="LockoutSeconds"/> (429).
/// </summary>
public sealed class RateLimitOptions
{
    /// <summary>Turns per-client rate limiting on/off (default: on - fail closed).</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Maximum requests per client in the window (default: 120).</summary>
    public int MaxRequestsPerWindow { get; set; } = 120;

    /// <summary>Sliding window for the request limit, in seconds (default: 60).</summary>
    public int RequestWindowSeconds { get; set; } = 60;

    /// <summary>Failed authentication attempts tolerated before a lockout (default: 10).</summary>
    public int MaxFailuresPerWindow { get; set; } = 10;

    /// <summary>Sliding window for the failure count, in seconds (default: 300 = 5 min).</summary>
    public int FailureWindowSeconds { get; set; } = 300;

    /// <summary>How long a client stays locked out after too many failures, in seconds (default: 300 = 5 min).</summary>
    public int LockoutSeconds { get; set; } = 300;
}

public sealed class CertOptions
{
    public string? PemCert { get; set; } = "proxy-cert.pem";
    public string? PemKey { get; set; } = "proxy-key.pem";
    public string? PfxPath { get; set; }
    public string? PfxPassword { get; set; }
}

public sealed class KeyOptions
{
    public string? UpstreamKey { get; set; }

    /// <summary>The primary local key (compatibility).</summary>
    public string? LocalKey { get; set; }

    /// <summary>
    /// Additional accepted local keys (e.g. rotation or multiple clients). A request is
    /// authenticated if it matches <see cref="LocalKey"/> or any entry here.
    /// Values live only in appsettings.Server.json / environment (never in non-secret files).
    /// </summary>
    public List<string> LocalKeys { get; set; } = new();
}
