using System.Text.Json.Nodes;

namespace AiRouterProxy.Dashboard.Models;

/// <summary>
/// Write operations of the admin dashboard. Lives in the Dashboard assembly because the
/// UI injects it (and the Dashboard project cannot reference the host - the host
/// references the Dashboard; the host registers its own implementation, which wins over
/// the placeholder). Every write is: validate -&gt; timestamped backup -&gt; atomic
/// write -&gt; re-read + structural confirm (restoring the previous version on failure)
/// -&gt; audit. Secret values are accepted as method parameters, validated for shape,
/// written into the server config and NEVER returned, logged or exposed in any message.
/// </summary>
public interface IDashboardAdminService
{
    /// <summary>True when the presented value equals the primary local key (admin privilege).</summary>
    bool VerifyAdminKey(string key);

    /// <summary>
    /// Replaces the route table in routes.json (hot-reloaded). authKey optional (routes carry no secrets).
    /// Optional sections are preserved, not erased: when a draft has <c>Headers</c> or
    /// <c>Transport</c> = null the section currently stored for the same route name is kept
    /// (an explicit <c>Headers</c> = empty dictionary clears the stored headers; a supplied
    /// <c>Transport</c> replaces the stored section as a whole - there is no field-by-field
    /// merge inside it). A route name with no stored entry starts without either section.
    /// <c>GET /admin/api/v1/routes</c> returns the complete table (headers + transport) so it
    /// can be edited and sent back as-is.
    /// </summary>
    AdminResult ApplyRoutes(IReadOnlyList<RouteDraft> routes, string? authKey = null);

    /// <summary>Writes/rotates one RouteKeys secret in appsettings.Server.json. authKey REQUIRED (sensitive).</summary>
    AdminResult SetRouteKeySecret(string keyRef, string secret, string? authKey = null);

    /// <summary>Removes one RouteKeys entry (and its metadata). Refused while routes use it. authKey REQUIRED.</summary>
    AdminResult DeleteRouteKey(string keyRef, string? authKey = null);

    /// <summary>Stores/updates the non-secret metadata (owner/purpose) for a key reference.</summary>
    AdminResult UpdateKeyMeta(string keyRef, KeyMeta meta, string? authKey = null);

    /// <summary>Replaces the extra local keys list in appsettings.Server.json. authKey REQUIRED.</summary>
    AdminResult ApplyLocalKeys(IReadOnlyList<string> localKeys, string? authKey = null);

    /// <summary>Appends one extra local key to the current list. authKey REQUIRED.</summary>
    AdminResult AddLocalKey(string value, string? authKey = null);

    /// <summary>Removes one extra local key by its short fingerprint (the UI only ever sees fingerprints). authKey REQUIRED.</summary>
    AdminResult RemoveLocalKeyByHash(string shortHash, string? authKey = null);

    /// <summary>Stores the display name (person/PC) of an extra local key, keyed by its fingerprint. Meta only, never the key value.</summary>
    AdminResult SetLocalKeyLabel(string shortHash, string label, string? authKey = null);

    /// <summary>Writes the global upstream key in appsettings.Server.json. authKey REQUIRED.</summary>
    AdminResult SetUpstreamKey(string secret, string? authKey = null);

    /// <summary>Patches Redaction+Inspection in redaction.json (hot-reloaded, non-secret).</summary>
    AdminResult ApplySecurity(JsonNode? redactionSection, JsonNode? inspectionSection, string? authKey = null);

    /// <summary>
    /// Ensures a keyRef is declared in appsettings.Server.json (Proxy.RouteKeys) with an
    /// EMPTY value - avoids the dashboard dead-end of a fresh install, where the route
    /// editor offers no keyRef to pick. Writes into the sensitive server
    /// config, so the same protected flow (backup/confirm/audit, authKey REQUIRED)
    /// applies. Existing refs are a no-op; routes using the new ref stay inactive until
    /// a secret is set. Routes may also reference a keyRef that is not declared at all -
    /// those save with an "inactive until declared" warning - so this is a convenience,
    /// not a prerequisite.
    /// </summary>
    AdminResult EnsureRouteKeyRef(string keyRef, string? authKey = null);

    /// <summary>Builds the no-secrets export bundle ({routes, redaction, inspection}).</summary>
    AdminResult Export();

    /// <summary>Validates an import bundle without writing anything.</summary>
    AdminResult ValidateImport(JsonNode bundle);

    /// <summary>Validates and applies an import bundle (routes + redaction/inspection). authKey REQUIRED.</summary>
    AdminResult Import(JsonNode bundle, string? authKey = null);

    /// <summary>Clears the in-memory activity buffer. Admin key REQUIRED (destructive).</summary>
    AdminResult ClearActivityLog(string? authKey = null);

    /// <summary>Clears the dedicated "AIRouterProxy" Windows Event Log. Admin key REQUIRED (destructive).</summary>
    AdminResult ClearEventLog(string? authKey = null);

    /// <summary>Clears the in-memory detection forensics buffer. Admin key REQUIRED (destructive).</summary>
    AdminResult ClearDetections(string? authKey = null);

    // Transport/Endpoint attestation (Phase 2 - write actions). Every action is audited
    // and requires the primary local key: pinning changes the security posture.
    /// <summary>Pins an SPKI fingerprint (default: the route's latest observed one) into the learned pins. authKey REQUIRED.</summary>
    AdminResult AcceptAttestationPin(string routeName, string? spki, string? authKey = null);

    /// <summary>Runs an on-demand endpoint probe ("learn now") that records the current upstream endpoint. authKey REQUIRED.</summary>
    Task<AdminResult> LearnAttestationNowAsync(string routeName, string? authKey = null);

    /// <summary>Removes the learned pins of one route (null = all routes). authKey REQUIRED.</summary>
    AdminResult ClearAttestationPins(string? routeName, string? authKey = null);

    /// <summary>Clears the in-memory drift feed. Admin key REQUIRED (destructive).</summary>
    AdminResult ClearAttestationDrift(string? authKey = null);

    /// <summary>Re-reads the config files from disk and confirms they reload; restores from backup when broken.</summary>
    AdminResult ReloadConfirm();
}
