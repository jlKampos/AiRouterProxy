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
    string UA);

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

    public static AdminResult Success(string message, string[]? warnings = null, JsonNode? data = null)
        => new(true, message, false, null, warnings, TypeOk, data);

    public static AdminResult Failure(string message, string errorType, string[]? errors = null, bool restored = false)
        => new(false, message, restored, errors, null, errorType);
}

/// <summary>
/// A route as edited by the dashboard. A draft carries NO secret values - the key is
/// referenced by name only (<see cref="KeyRef"/>), the value stays in the server config.
/// </summary>
public sealed record RouteDraft(
    string Name,
    string Prefix,
    string Upstream,
    string? KeyRef,
    List<string>? AllowedPaths = null,
    int RequestTimeoutMs = 0,
    long MaxBodySize = 0,
    Dictionary<string, string>? Headers = null)
{
    public List<string> SafePaths => AllowedPaths ?? new List<string>();
    public Dictionary<string, string> SafeHeaders => Headers ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
}

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
    IReadOnlyList<string> Allow);

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
}