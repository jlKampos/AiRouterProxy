using System.Text.Json.Nodes;

namespace AiRouterProxy.Dashboard.Models;

/// <summary>
/// Dev-standalone fallback for the admin write service (mirrors the placeholder facade).
/// NEVER registered by the host: the host registers its own IDashboardAdminService after
/// AddDashboard(), which wins in DI. Every operation reports "not available" so the UI
/// still renders and explains the limitation in standalone dev mode.
/// </summary>
public sealed class PlaceholderDashboardAdminService : IDashboardAdminService
{
    private const string Unavailable = "Admin write operations are unavailable in standalone dev mode (run the AiRouterProxy service).";

    public bool VerifyAdminKey(string key) => false;

    public AdminResult ApplyRoutes(IReadOnlyList<RouteDraft> routes, string? authKey = null)
        => AdminResult.Failure(Unavailable, AdminResult.TypeInternal);

    public AdminResult SetRouteKeySecret(string keyRef, string secret, string? authKey = null)
        => AdminResult.Failure(Unavailable, AdminResult.TypeInternal);

    public AdminResult DeleteRouteKey(string keyRef, string? authKey = null)
        => AdminResult.Failure(Unavailable, AdminResult.TypeInternal);

    public AdminResult UpdateKeyMeta(string keyRef, KeyMeta meta, string? authKey = null)
        => AdminResult.Failure(Unavailable, AdminResult.TypeInternal);

    public AdminResult ApplyLocalKeys(IReadOnlyList<string> localKeys, string? authKey = null)
        => AdminResult.Failure(Unavailable, AdminResult.TypeInternal);

    public AdminResult AddLocalKey(string value, string? authKey = null)
        => AdminResult.Failure(Unavailable, AdminResult.TypeInternal);

    public AdminResult RemoveLocalKeyByHash(string shortHash, string? authKey = null)
        => AdminResult.Failure(Unavailable, AdminResult.TypeInternal);

    public AdminResult SetLocalKeyLabel(string shortHash, string label, string? authKey = null)
        => AdminResult.Failure(Unavailable, AdminResult.TypeInternal);

    public AdminResult SetUpstreamKey(string secret, string? authKey = null)
        => AdminResult.Failure(Unavailable, AdminResult.TypeInternal);

    public AdminResult ApplySecurity(JsonNode? redactionSection, JsonNode? inspectionSection, string? authKey = null)
        => AdminResult.Failure(Unavailable, AdminResult.TypeInternal);

    public AdminResult EnsureRouteKeyRef(string keyRef, string? authKey = null)
        => AdminResult.Failure(Unavailable, AdminResult.TypeInternal);

    public AdminResult Export() => AdminResult.Failure(Unavailable, AdminResult.TypeInternal);

    public AdminResult ValidateImport(JsonNode bundle) => AdminResult.Failure(Unavailable, AdminResult.TypeInternal);

    public AdminResult Import(JsonNode bundle, string? authKey = null)
        => AdminResult.Failure(Unavailable, AdminResult.TypeInternal);

    public AdminResult ClearActivityLog(string? authKey = null)
        => AdminResult.Failure(Unavailable, AdminResult.TypeInternal);

    public AdminResult ClearEventLog(string? authKey = null)
        => AdminResult.Failure(Unavailable, AdminResult.TypeInternal);

    public AdminResult ClearDetections(string? authKey = null)
        => AdminResult.Failure(Unavailable, AdminResult.TypeInternal);

    // Transport/Endpoint attestation write actions (Phase 2) - unavailable in standalone mode.
    public AdminResult AcceptAttestationPin(string routeName, string? spki, string? authKey = null)
        => AdminResult.Failure(Unavailable, AdminResult.TypeInternal);

    public Task<AdminResult> LearnAttestationNowAsync(string routeName, string? authKey = null)
        => Task.FromResult(AdminResult.Failure(Unavailable, AdminResult.TypeInternal));

    public AdminResult ClearAttestationPins(string? routeName, string? authKey = null)
        => AdminResult.Failure(Unavailable, AdminResult.TypeInternal);

    public AdminResult ClearAttestationDrift(string? authKey = null)
        => AdminResult.Failure(Unavailable, AdminResult.TypeInternal);

    public AdminResult ReloadConfirm() => AdminResult.Failure(Unavailable, AdminResult.TypeInternal);
}
