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
    /// Global transport-attestation defaults (see <see cref="TransportOptions"/>). The
    /// feature is OFF by default (Enabled = false) so existing installs behave exactly
    /// as before; enabling it only OBSERVES endpoints (Phase 1), it never blocks.
    /// </summary>
    public TransportOptions Transport { get; set; } = new();

    /// <summary>
    /// Fail-closed body inspection policy: decides what to do with each Content-Type
    /// before anything is forwarded (see <see cref="InspectionOptions"/>).
    /// </summary>
    public InspectionOptions Inspection { get; set; } = new();

    /// <summary>
    /// Provider blocklist feed (Phase 3, non-secret, hot-reloaded from providers.json).
    /// Metadata only: names of blocked hosts/provider slugs + a human reason + severity.
    /// Per-route application is controlled by <see cref="RouteTransportOptions.Blocklist"/>.
    /// </summary>
    public ProviderFeedOptions Providers { get; set; } = new();

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

    /// <summary>Route-specific max request body size (bytes). 0 = inherits Proxy.MaxBodySize.</summary>
    public long MaxBodySize { get; set; }

    /// <summary>
    /// Static headers merged into every request forwarded along this route
    /// (e.g. the "anthropic-version" header the Anthropic API requires).
    /// The proxy's injected credentials and content framing
    /// (Authorization / Content-Type / Accept) are never overridden.
    /// </summary>
    public Dictionary<string, string> Headers { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Optional per-route transport-attestation section (routes.json "transport").
    /// Null = the route inherits the global <see cref="ProxyOptions.Transport"/>.
    /// </summary>
    public RouteTransportOptions? Transport { get; set; }
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

    /// <summary>
    /// Optional allow-list of regex patterns. A detection whose token matches one of these
    /// patterns is left untouched (not masked, not counted) - use it to keep legitimate
    /// file names / internal IDs readable. Exemptions NEVER apply to the high-confidence
    /// format scanner (sk-, ghp_, AIza, JWT, Bearer, PEM...) nor to values of sensitive
    /// JSON fields (api_key, password, token...): those are always redacted.
    /// Empty = current behavior (no exemptions).
    /// </summary>
    public List<string> Allow { get; set; } = new();

    /// <summary>
    /// Detection forensics (metadata only, in memory, off by default). Records WHERE and
    /// WHICH layer fired - never the value (see <see cref="ForensicsOptions"/>).
    /// </summary>
    public ForensicsOptions Forensics { get; set; } = new();
}

/// <summary>
/// Detection forensics: keeps an in-memory ring buffer of detection metadata (JSON path,
/// layer, kind, length, process-local fingerprint) so the dashboard can show where
/// redaction fires. Off by default; nothing is written to disk.
/// </summary>
public sealed class ForensicsOptions
{
    /// <summary>Turns metadata collection on/off (default: off - zero cost on the hot path).</summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Ring buffer size. Configured range 10..1000 (enforced by SecurityValidator and
    /// clamped at use); default 200.
    /// </summary>
    public int Capacity { get; set; } = 200;
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

    /// <summary>
    /// Skips redaction for image/binary payloads: data URLs ("data:...;base64,...")
    /// and long standalone base64 blobs. Those are binary bytes, not text where keys
    /// get pasted - scanning them corrupts the base64 (litellm "only ASCII" errors).
    /// Known formats (sk-, ghp_, ...) and sensitive field values are STILL always
    /// masked, even next to an image. Default: true.
    /// </summary>
    public bool ExemptBase64 { get; set; } = true;
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

/// <summary>
/// Global transport-attestation settings (Proxy.Transport). Phase 1 = observe only:
/// enabling it captures who answered each TLS connection (metadata only) into the
/// in-memory ring and the data/endpoint-baseline.json baseline; it never blocks.
/// Phase 2 (pin/expected-IP enforcement) and Phase 3 (blocklist) build on the same
/// per-route policy resolved by TransportPolicyProvider.
/// </summary>
public sealed class TransportOptions
{
    /// <summary>Master switch (default off - full compatibility).</summary>
    public bool Enabled { get; set; }

    /// <summary>In-memory ring buffer size (clamped 10..1000 at use; default 200).</summary>
    public int BufferCapacity { get; set; } = TransportStore.DefaultCapacity;
}

/// <summary>
/// Per-route transport-attestation section (routes.json "transport"). Every field is
/// optional; null/empty inherits the global defaults. Light validation happens in
/// RouteValidator / startup (invalid values are ignored, never crash the proxy).
/// </summary>
public sealed class RouteTransportOptions
{
    /// <summary>null inherits the global Proxy.Transport.Enabled.</summary>
    public bool? Enabled { get; set; }

    /// <summary>Pooled-connection lifetime for the route's HttpClient (Connection: close after N minutes).</summary>
    public int? PoolLifetimeMinutes { get; set; }

    /// <summary>Expected upstream IPs (CIDRs). Reserved for Phase 2 - not enforced in Phase 1.</summary>
    public List<string> ExpectedIps { get; set; } = new();

    /// <summary>Minimum accepted TLS version ("1.2" | "1.3"). Reserved for Phase 2.</summary>
    public string? TlsFloor { get; set; }

    /// <summary>Grace period (days) before a changed endpoint is considered suspect. Reserved for Phase 2/3.</summary>
    public int GraceDays { get; set; } = 7;

    /// <summary>"observe" (Phase 1) | "warn" | "block" (reserved for Phase 2).</summary>
    public string Enforce { get; set; } = "observe";

    /// <summary>Expected SPKI fingerprints (hex/base64url). Reserved for Phase 2 - not enforced in Phase 1.</summary>
    public List<string> Pins { get; set; } = new();

    /// <summary>
    /// How often (hours) the endpoint probe re-connects to keep the baseline and drift
    /// feed fresh for this route; 0 = probing disabled. Phase 2.
    /// </summary>
    public int ProbeHours { get; set; }

    /// <summary>
    /// Per-route provider-blocklist policy (Phase 3, routes.json "transport.blocklist").
    /// Null/disabled = the feature is off for the route (zero cost on the hot path).
    /// See <see cref="RouteBlocklistOptions"/> for the fields.
    /// </summary>
    public RouteBlocklistOptions? Blocklist { get; set; }
}

/// <summary>
/// Provider blocklist feed (Phase 3): the list of blocked/flagged providers, hosts and
/// provider slugs. Non-secret, hot-reloaded (providers.json, "Proxy.Providers"). Values
/// are human names/reasons - NEVER content or keys.
/// </summary>
public sealed class ProviderFeedOptions
{
    /// <summary>Feed entries; empty array = no policy from the feed.</summary>
    public List<ProviderEntryOptions> Entries { get; set; } = new();
}

/// <summary>
/// One provider-feed entry (metadata only). A host-tier entry matches by upstream host;
/// a provider-tier entry contributes provider slugs (ignore list) and flags when the
/// route is an aggregator and opts in via <see cref="RouteBlocklistOptions"/>.
/// </summary>
public sealed class ProviderEntryOptions
{
    /// <summary>Unique feed id (<= 64 chars).</summary>
    public string Id { get; set; } = string.Empty;

    /// <summary>Display name of the provider/entry (<= 128 chars; optional).</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Upstream hosts this entry applies to (exact match, "*.domain" suffix wildcard supported).</summary>
    public List<string> Hosts { get; set; } = new();

    /// <summary>Provider slugs to add to the request's provider.ignore (e.g. "openrouter/auto").</summary>
    public List<string> ProviderSlugs { get; set; } = new();

    /// <summary>Human reason for the entry (<= 500 chars).</summary>
    public string Reason { get; set; } = string.Empty;

    /// <summary>"info" | "warn" | "block".</summary>
    public string Severity { get; set; } = "info";

    /// <summary>Optional expiry: the entry stops applying after this instant (null = never expires).</summary>
    public DateTimeOffset? Until { get; set; }

    /// <summary>Provider-tier flag: send "provider.zdr": true on aggregator routes.</summary>
    public bool ZdrOnly { get; set; }

    /// <summary>Provider-tier flag: send "provider.data_collection": "deny" on aggregator routes.</summary>
    public bool DataCollectionDeny { get; set; }
}

/// <summary>
/// Per-route provider-blocklist policy (Phase 3, routes.json "transport.blocklist").
/// All disabled by default: a route without this section behaves exactly as before.
/// The host tier (blocked upstream) and the provider tier (ignore/zdr/data_collection)
/// only run when <see cref="Enabled"/> is true.
/// </summary>
public sealed class RouteBlocklistOptions
{
    /// <summary>Master switch for the route's provider-blocklist policy (default off).</summary>
    public bool Enabled { get; set; }

    /// <summary>When true, a "block" host-tier verdict is NOT rejected - the request is forwarded (operator override).</summary>
    public bool AllowBlocked { get; set; }

    /// <summary>
    /// Aggregator hosts this route fronts (e.g. "openrouter.ai"). The provider tier only
    /// applies when the route's upstream host matches one of these (exact or "*.domain").
    /// Values may be bare hosts or full URLs (the host is extracted).
    /// </summary>
    public List<string> Aggregators { get; set; } = new();

    /// <summary>
    /// When true and the route is an aggregator: the proxy sends "X-OpenRouter-Metadata:
    /// enabled" upstream and records the provider that actually served each response
    /// (metadata only: names, in-memory + activity).
    /// </summary>
    public bool Attribution { get; set; }

    /// <summary>
    /// How provider conflicts are handled: "merge" (apply the policy and continue) or
    /// "strict" (a client request that explicitly overrides the policy with
    /// provider.only/order or zdr:false is rejected with 400).
    /// </summary>
    public string ProviderPolicy { get; set; } = "merge";
}
