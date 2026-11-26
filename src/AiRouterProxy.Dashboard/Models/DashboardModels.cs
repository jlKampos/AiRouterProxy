using System;
using System.Text.Json.Nodes;

namespace AiRouterProxy.Dashboard.Models;

/// <summary>Read-only snapshot of proxy status for the dashboard UI.</summary>
public sealed record DashboardStatus(
    string Status,
    string Version,
    DateTimeOffset Timestamp,
    long UptimeSec,
    int ActivityCount,
    bool RoutingEnabled,
    int RouteCount,
    int ConfiguredRouteKeys,
    bool RateLimitEnabled,
    bool RedactionEnabled,
    bool InspectionEnabled);

/// <summary>Route row shown in the UI - never contains secrets.</summary>
public sealed record RouteView(
    string Name,
    string Prefix,
    string Upstream,
    string KeyRef,
    bool Active,
    IReadOnlyList<string> AllowedPaths,
    int RequestTimeoutMs,
    long MaxBodySize);

/// <summary>Proxy-level route defaults: values inherited by routes whose own timeout/max body is 0.</summary>
public sealed record RouteDefaultsView(
    int RequestTimeoutMs,
    long MaxBodySize);

/// <summary>KeyRef row shown in the UI - only configuration state, never the value.</summary>
public sealed record KeyRefView(
    string KeyRef,
    bool Configured,
    int UsageCount,
    string Owner);

/// <summary>Activity row - metadata only (hashes, never keys or payloads).</summary>
public sealed record ActivityView(
    DateTimeOffset Timestamp,
    string Client,
    string Method,
    string Path,
    int Status,
    long DurationMs,
    string Model,
    string Route,
    bool Refused,
    int Redacted,
    string PresentedHash,
    string ExpectedHash,
    string Owner,
    string UA,
    string RedactionKinds,
    string Transport = "-");

public sealed record KeyMetaView(
    string KeyRef,
    string Owner,
    string Purpose);

// ----------------------------------------------------------
// Admin write phase (2.6.0): shared contracts between the host
// services and the dashboard UI. These live in the Dashboard
// assembly because the UI renders them and the Dashboard project
// cannot reference the host (the host references the Dashboard).
// ----------------------------------------------------------

/// <summary>
/// Result of an admin write/validation operation. Messages and errors are always in
/// English and NEVER contain secret values; secrets never leave the server.
/// </summary>
public sealed record AdminResult(
    bool Ok,
    string Message,
    bool Restored,
    string[]? Errors = null,
    string[]? Warnings = null,
    string ErrorType = "ok",
    JsonNode? Data = null)
{
    /// <summary>Error type used by the API layer to pick the HTTP status code.</summary>
    public const string TypeOk = "ok";
    public const string TypeAuthentication = "authentication_error";
    public const string TypeValidation = "validation_error";
    public const string TypeConflict = "conflict";
    public const string TypeNotFound = "not_found";
    public const string TypeInternal = "internal_error";

    /// <summary>Aggregator-origin errors (Phase 3 origin endpoint only): the caller maps these to 422/502.</summary>
    public const string TypeUnprocessable = "unprocessable";
    public const string TypeBadGateway = "bad_gateway";

    public static AdminResult Success(string message, string[]? warnings = null, JsonNode? data = null)
        => new(true, message, false, null, warnings, TypeOk, data);

    public static AdminResult Failure(string message, string errorType, string[]? errors = null, bool restored = false)
        => new(false, message, restored, errors, null, errorType);
}

/// <summary>
/// A route as edited by the dashboard. A draft carries NO secret values - the key is
/// referenced by name only (<see cref="KeyRef"/>), the value stays in the server config.
/// <see cref="Transport"/> is the per-route attestation section (Phase 1: observe only).
/// </summary>
public sealed record RouteDraft(
    string Name,
    string Prefix,
    string Upstream,
    string? KeyRef,
    List<string>? AllowedPaths = null,
    int RequestTimeoutMs = 0,
    long MaxBodySize = 0,
    Dictionary<string, string>? Headers = null,
    RouteTransportDraft? Transport = null)
{
    public List<string> SafePaths => AllowedPaths ?? new List<string>();
    public Dictionary<string, string> SafeHeaders => Headers ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// Per-route transport-attestation section (routes.json "transport") as edited through
/// the API/config bundle. Mirrors the host's RouteTransportOptions; optional and
/// validated by RouteValidator (Phase 2: enforce/pins/graceDays/probeHours are enforced
/// by the proxy when the route opts in).
/// </summary>
public sealed record RouteTransportDraft(
    bool? Enabled = null,
    int? PoolLifetimeMinutes = null,
    List<string>? ExpectedIps = null,
    string? TlsFloor = null,
    int GraceDays = 7,
    string Enforce = "observe",
    List<string>? Pins = null,
    int ProbeHours = 0,
    RouteBlocklistDraft? Blocklist = null)
{
    public List<string> SafeExpectedIps => ExpectedIps ?? new List<string>();
    public List<string> SafePins => Pins ?? new List<string>();
}

/// <summary>
/// Per-route provider-blocklist policy (Phase 3, routes.json "transport.blocklist") as
/// edited through the API/config bundle. All off by default - a route without this
/// section behaves exactly as before. Mirrors the host's RouteBlocklistOptions.
/// </summary>
public sealed record RouteBlocklistDraft(
    bool Enabled = false,
    bool AllowBlocked = false,
    List<string>? Aggregators = null,
    bool Attribution = false,
    string ProviderPolicy = "merge")
{
    public List<string> SafeAggregators => Aggregators ?? new List<string>();
}

/// <summary>
/// One provider-feed entry as edited through the API (Phase 3). Metadata only - human
/// names/reasons, never content, never keys. Validated by ProviderFeedValidator and
/// written into providers.json ("Proxy.Providers.Entries").
/// </summary>
public sealed record ProviderEntryDraft(
    string Id,
    string Name,
    List<string>? Hosts = null,
    List<string>? ProviderSlugs = null,
    string Reason = "",
    string Severity = "info",
    DateTimeOffset? Until = null,
    bool ZdrOnly = false,
    bool DataCollectionDeny = false)
{
    public List<string> SafeHosts => Hosts ?? new List<string>();
    public List<string> SafeProviderSlugs => ProviderSlugs ?? new List<string>();
}

/// <summary>
/// One provider-feed entry as shown by the dashboard (Phase 3). Mirror of
/// <see cref="ProviderEntryDraft"/> for reading - metadata only, never secrets.
/// </summary>
public sealed record ProviderEntryView(
    string Id,
    string Name,
    IReadOnlyList<string> Hosts,
    IReadOnlyList<string> ProviderSlugs,
    string Reason,
    string Severity,
    DateTimeOffset? Until,
    bool ZdrOnly,
    bool DataCollectionDeny);

/// <summary>Admin-only metadata for a route key reference. Never holds the secret value.</summary>
public sealed record KeyMeta(string Owner, string Purpose);

/// <summary>Full security posture snapshot for the Security page (never includes key values).</summary>
public sealed record SecurityOptionsView(
    RedactionSettingsView Redaction,
    InspectionSettingsView Inspection,
    RateLimitSettingsView RateLimit);

public sealed record RedactionSettingsView(
    bool Enabled,
    string? Mask,
    bool NotifyInResponse,
    string? WarnTemplate,
    DetectSettingsView Detect,
    IReadOnlyList<string> Allow,
    ForensicsSettingsView Forensics);

/// <summary>
/// Detection forensics (metadata only): off by default, in memory. Records where/which
/// layer fired - never the value.
/// </summary>
public sealed record ForensicsSettingsView(bool Enabled, int Capacity);

/// <summary>
/// One forensic detection row: structural JSON path, layer, kind, length and a
/// process-local, non-reversible fingerprint. Never contains the detected value.
/// <para>
/// <c>Quote</c> is <c>"\""</c> or <c>"'"</c> when the matched context used that quote,
/// <c>""</c> for a <c>context</c> finding with no quotes - a <c>format</c> that inherits its
/// shape from such an unquoted <c>context</c> also gets <c>""</c> - and <c>null</c> for a layer
/// without shape (<c>field</c>, <c>entropy</c>, or a <c>format</c> that did not inherit a
/// shape from an overlapping <c>context</c> finding at the same offset).
/// </para>
/// </summary>
public sealed record DetectionView(
    DateTimeOffset Timestamp,
    string RequestId,
    string Client,
    string Route,
    string Method,
    string Path,
    string? Model,
    string JsonPath,
    string Layer,
    string Kind,
    int Length,
    string Fingerprint,
    string? Name,
    string? Sep,
    string? Quote);

/// <summary>
/// Pattern column for detection forensics: <c>-</c> when the row has no shape
/// (<c>field</c>/<c>entropy</c>, or a <c>format</c> that inherited nothing), otherwise the
/// identifier plus separator and, when the value was quoted, a quoted ellipsis.
/// Pure formatting kept out of the Razor page so it can be unit-tested.
/// </summary>
public static class DetectionPattern
{
    public static string Format(string? name, string? sep, string? quote)
        => name is null
            ? "-"
            : name + " " + sep
              + (string.IsNullOrEmpty(quote) ? string.Empty : " " + quote + "\u2026" + quote);
}

public sealed record DetectSettingsView(
    bool ByFieldName,
    bool ByFormats,
    bool ByKeyValueContext,
    bool ByLongStrings,
    bool ExemptBase64,
    double EntropyThreshold);

public sealed record InspectionSettingsView(
    bool Enabled,
    string DefaultAction,
    string InvalidJson,
    IReadOnlyDictionary<string, string> ByContentType);

public sealed record RateLimitSettingsView(
    bool Enabled,
    int MaxRequestsPerWindow,
    int RequestWindowSeconds,
    int MaxFailuresPerWindow,
    int FailureWindowSeconds,
    int LockoutSeconds);

/// <summary>Filesystem layout of the running proxy (paths only, never file contents).</summary>
public sealed record ConfigPathsView(
    string ConfigDir,
    string DataDir,
    string BackupDir,
    string AuditLogPath,
    string KeyMetaPath,
    int Retention);

/// <summary>Complete key posture for the Routes &amp; Keys panel (hashes and states, never values).</summary>
public sealed record KeysOverviewView(
    IReadOnlyList<KeyRefDetailView> KeyRefs,
    IReadOnlyList<LocalKeyView> LocalKeys,
    bool HasGlobalKey,
    bool HasPrimaryLocalKey);

public sealed record KeyRefDetailView(
    string KeyRef,
    bool Configured,
    int UsageCount,
    string OwnerRoute,
    string Owner,
    string Purpose);

public sealed record LocalKeyView(string Label, string Hash, bool IsPrimary);

/// <summary>
/// Facade implemented by the HOST (which owns ProxyOptions/ActivityStore/AuthenticationPolicy).
/// The dashboard project references only this interface - no circular dependency.
/// Session/login is handled by the host middleware, not via this interface.
/// </summary>
public interface IDashboardFacade
{
    DashboardStatus GetStatus();
    IReadOnlyList<RouteView> GetRoutes();
    RouteDefaultsView GetRouteDefaults();
    IReadOnlyList<KeyRefView> GetRouteKeyRefs();
    IReadOnlyList<KeyMetaView> GetKeyMeta();
    IReadOnlyList<ActivityView> GetActivity(int hours, int limit);
    int LocalKeyCount();

    // Detection forensics (in memory, metadata only). Reading is a plain facade operation;
    // clearing is destructive and goes through IDashboardAdminService (admin key re-check).
    IReadOnlyList<DetectionView> GetDetections(int limit);

    // Admin write phase (2.6.0): read-only views for the editable screens.
    SecurityOptionsView GetSecurityOptions();
    ConfigPathsView GetConfigPaths();
    KeysOverviewView GetKeysOverview();

    // Post-save refresh (2.6.1): the live snapshot reloads via FileSystemWatcher with a
    // debounce, so immediately after SaveAtomic the monitor still serves the OLD values.
    // These read the saved files directly - the UI must reflect what was just written.
    // Each returns null when its file is absent or unreadable: the page then keeps its
    // current state (what was loaded/written last) instead of the stale live snapshot.
    IReadOnlyList<RouteView>? GetRoutesFromDisk();
    SecurityOptionsView? GetSecurityOptionsFromDisk();
    KeysOverviewView? GetKeysOverviewFromDisk();

    // Transport/Endpoint attestation (Phase 1 - read only): who answered each TLS
    // connection, per route. Metadata only - never request content, never keys.
    IReadOnlyList<AttestationRouteView> GetAttestation();

    // Provider blocklist feed (Phase 3 - read only, metadata only): the entries edited
    // through the Attestation page's Providers panel and written via ApplyProviders.
    IReadOnlyList<ProviderEntryView> GetProviders();

    /// <summary>Provider feed straight from providers.json (the post-save truth - the live
    /// snapshot reloads with a debounce). Null when the file is absent or unreadable.</summary>
    IReadOnlyList<ProviderEntryView>? GetProvidersFromDisk();
}

/// <summary>Per-route attestation card (read-only): status, policy posture, drift episodes + the persistent baseline entries.</summary>
public sealed record AttestationRouteView(
    string Route,
    string Host,
    /// <summary>"observed" / "warn" / "blocked" (recent live connection) | "baseline" (persisted only) | "none".</summary>
    string Status,
    DateTimeOffset? LastSeen,
    IReadOnlyList<AttestationEntryView> Entries,
    IReadOnlyList<DriftView>? Drift = null,
    AttestationPolicyView? Policy = null,
    /// <summary>Last attributed provider name on this route (Phase 3) or null when never recorded.</summary>
    string? ServedBy = null);

/// <summary>Policy posture of one route as the attestation page shows it (metadata only).</summary>
public sealed record AttestationPolicyView(
    string Enforce,
    int GraceDays,
    int ProbeHours,
    IReadOnlyList<string> ExpectedIps,
    string? TlsFloor,
    IReadOnlyList<string> PinsConfigured,
    int PinCount);

/// <summary>One drift episode (metadata only): what drifted, how severe, alert cadence.</summary>
public sealed record DriftView(
    string Route,
    string Ip,
    string Reason,
    string Severity,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastAlerted,
    int AlertCount);

/// <summary>One baseline endpoint entry - metadata only (cert fingerprints, TLS facts).</summary>
public sealed record AttestationEntryView(
    string Ip,
    int Port,
    string SpkiHash,
    string SpkiHashShort,
    string CertSha256,
    string Issuer,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string TlsVersion,
    string? CipherSuite,
    string? Alpn,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen,
    string Source);