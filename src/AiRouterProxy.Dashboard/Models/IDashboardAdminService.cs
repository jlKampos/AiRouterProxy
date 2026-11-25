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

    /// <summary>Replaces the whole route table in routes.json (hot-reloaded). authKey optional (routes carry no secrets).</summary>
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
    /// EMPTY value - fixes the dashboard dead-end of a fresh install: routes cannot
    /// reference a keyRef that is not declared yet. Writes into the sensitive server
    /// config, so the same protected flow (backup/confirm/audit, authKey REQUIRED)
    /// applies. Existing refs are a no-op; routes using the new ref stay inactive until
    /// a secret is set.
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

    /// <summary>Re-reads the config files from disk and confirms they reload; restores from backup when broken.</summary>
    AdminResult ReloadConfirm();
}
