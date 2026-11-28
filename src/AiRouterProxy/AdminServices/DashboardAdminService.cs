using System.Text.Json;
using System.Text.Json.Nodes;
using AIRouterProxy;
using AiRouterProxy.AdminPersistence;
using AiRouterProxy.AdminValidation;
using AiRouterProxy.Dashboard.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RouteOptions = AIRouterProxy.RouteOptions;

namespace AiRouterProxy.AdminServices;

/// <summary>
/// Host-side implementation of the admin write pipeline. All writes go through the
/// same safety path: validate first, timestamped backup, atomic write, re-read +
/// structural confirm (restore previous version on failure), audit. Config files are
/// the source of truth; this service only patches known sections and preserves the
/// rest of each document (unknown properties survive).
/// </summary>
public sealed class DashboardAdminService : IDashboardAdminService
{
    private const string ServerFile = "appsettings.Server.json";
    private const string RoutesFile = "routes.json";
    private const string RedactionFile = "redaction.json";
    private const string EventLogName = "AIRouterProxy";

    private static readonly JsonSerializerOptions JsonRead = new() { PropertyNameCaseInsensitive = true };

    // Used only for the export fallback when redaction.json is missing on disk: writes
    // camelCase like the config files (never nulls - keep the bundle compact).
    private static readonly JsonSerializerOptions JsonWrite = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly IOptionsMonitor<ProxyOptions> _options;
    private readonly DashboardPaths _paths;
    private readonly ConfigBackup _backups;
    private readonly ReloadConfirmer _confirmer;
    private readonly KeyMetaStore _keyMeta;
    private readonly AuditLog _audit;
    private readonly ActivityStore _activity;
    private readonly IEventLogStore _eventLogs;
    private readonly IDetectionStore _detections;
    private readonly DriftStore? _drift;
    private readonly LearnedPinStore? _learnedPins;
    private readonly EndpointProbe? _probe;
    private readonly BaselineStore? _baseline;
    private readonly ILogger<DashboardAdminService> _logger;

    // Serializes every config write (backup -> write -> confirm -> audit) because the
    // service is a singleton: AtomicJsonWriter reuses a fixed "{name}.tmp" per file and
    // AuditLog.AppendAllText is not concurrency-safe, so two parallel API + UI writes
    // could interleave content or throw IOException. Import is covered too, keeping the
    // multi-file write pair coherent.
    private readonly object _writeLock = new();

    public DashboardAdminService(
        IOptionsMonitor<ProxyOptions> options,
        DashboardPaths paths,
        ConfigBackup backups,
        ReloadConfirmer confirmer,
        KeyMetaStore keyMeta,
        AuditLog audit,
        ActivityStore activity,
        IEventLogStore eventLogs,
        IDetectionStore detections,
        ILogger<DashboardAdminService> logger,
        DriftStore? drift = null,
        LearnedPinStore? learnedPins = null,
        EndpointProbe? probe = null,
        BaselineStore? baseline = null)
    {
        _options = options;
        _paths = paths;
        _backups = backups;
        _confirmer = confirmer;
        _keyMeta = keyMeta;
        _audit = audit;
        _activity = activity;
        _eventLogs = eventLogs;
        _detections = detections;
        _drift = drift;
        _learnedPins = learnedPins;
        _probe = probe;
        _baseline = baseline;
        _logger = logger;
    }

    public bool VerifyAdminKey(string key) => AuthenticationPolicy.IsValidAdminKey(key, _options.CurrentValue.Keys);

    // ----------------------------------------------------------
    // Routes (non-sensitive: never touches keys)
    // ----------------------------------------------------------

    public AdminResult ApplyRoutes(IReadOnlyList<RouteDraft> routes, string? authKey = null)
    {
        lock (_writeLock)
        {
            return ApplyRoutesCore(routes, authKey);
        }
    }

    private AdminResult ApplyRoutesCore(IReadOnlyList<RouteDraft> routes, string? authKey)
    {
        if (!string.IsNullOrEmpty(authKey) && !VerifyAdminKey(authKey))
        {
            return AdminResult.Failure("Invalid admin key.", AdminResult.TypeAuthentication);
        }

        var opts = _options.CurrentValue;
        var (declared, configured) = KnownKeyRefs(opts);

        RouteValidator.Validate(routes, declared, out var errors, out var warnings, configured);
        if (errors.Count > 0)
        {
            return AdminResult.Failure("Route table is invalid - nothing was written.", AdminResult.TypeValidation, errors.ToArray());
        }

        try
        {
            _backups.Backup(_paths.ConfigDir, RoutesFile);
            var root = LoadOrCreateConfig(RoutesFile);
            var proxy = EnsureObject(root, "Proxy");
            var newRoutes = RouteDraftJson.ToArray(routes);
            MergePreservedRouteNodes(proxy["Routes"] as JsonArray, newRoutes, routes);
            proxy["Routes"] = newRoutes;
            AtomicJsonWriter.SaveAtomic(ConfigPaths.ResolveFile(RoutesFile, _paths.ConfigDir), root);

            var confirmed = _confirmer.Confirm(_paths.ConfigDir, RoutesFile, RoutesShape);
            if (!confirmed)
            {
                RecoverAfterFailedConfirm(RoutesFile);
                _audit.Append("routes.apply", RoutesFile, "restored", Actor(authKey));
                return AdminResult.Failure(
                    "routes.json failed to reload after the write - the previous version was restored.",
                    AdminResult.TypeInternal, restored: true);
            }

            _audit.Append("routes.apply", RoutesFile, "ok", Actor(authKey));
            var message = routes.Count switch
            {
                0 => "Route table cleared (single-upstream mode) and the engine reloaded.",
                1 => "1 route saved and the engine reloaded.",
                _ => $"{routes.Count} routes saved and the engine reloaded.",
            };
            return AdminResult.Success(message, warnings.Count > 0 ? warnings.ToArray() : null);
        }
        catch (Exception)
        {
            _audit.Append("routes.apply", RoutesFile, "error", Actor(authKey));
            return AdminResult.Failure("Could not write routes.json - the previous version was kept.", AdminResult.TypeInternal);
        }
    }

    /// <summary>
    /// Carries over the route fields a draft did not supply. The dashboard edits only a
    /// subset of each route: a partial/older client may send Headers=null or Transport=null
    /// because it never loaded them, and the UI sends null for a section the operator did
    /// not touch. Writing the draft as-is would erase those nodes from routes.json, so this
    /// merge is the server-side safety net. A supplied Transport section replaces the stored
    /// one as a whole - there is no field-by-field merge inside it (GET returns the full
    /// section for a round-trip). Match is by route name, Ordinal, with surrounding
    /// whitespace ignored on both sides: routes.json is hand-editable, so a stored
    /// " anthropic " must still match the draft's trimmed "anthropic" (the UI trims the
    /// name before saving) instead of losing its headers/transport. Names are the stable
    /// identifier used by the logs and attestation, and RouteValidator already rejects
    /// duplicates case-sensitively. An explicit empty Headers object is not null and
    /// therefore replaces the old node - that is how the operator clears every header.
    /// </summary>
    private static void MergePreservedRouteNodes(JsonArray? existingRoutes, JsonArray newRoutes, IReadOnlyList<RouteDraft> drafts)
    {
        if (existingRoutes is null || existingRoutes.Count == 0)
        {
            return;
        }

        var byName = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
        foreach (var entry in existingRoutes)
        {
            if (entry is not JsonObject old
                || SectionProp(old, "name") is not JsonValue nameValue
                || !nameValue.TryGetValue<string>(out var oldName))
            {
                continue;
            }

            var key = oldName.Trim();
            if (byName.ContainsKey(key))
            {
                continue;
            }

            byName[key] = old;
        }

        for (var i = 0; i < newRoutes.Count && i < drafts.Count; i++)
        {
            if (newRoutes[i] is not JsonObject target
                || !byName.TryGetValue((drafts[i].Name ?? string.Empty).Trim(), out var old))
            {
                continue;
            }

            if (drafts[i].Transport is null && SectionProp(old, "transport") is { } transport)
            {
                target["transport"] = transport.DeepClone();
            }

            if (drafts[i].Headers is null && SectionProp(old, "headers") is { } headers)
            {
                target["headers"] = headers.DeepClone();
            }
        }
    }

    // ----------------------------------------------------------
    // Route key secrets (sensitive: writes appsettings.Server.json)
    // ----------------------------------------------------------

    public AdminResult SetRouteKeySecret(string keyRef, string secret, string? authKey = null)
    {
        lock (_writeLock)
        {
            return SetRouteKeySecretCore(keyRef, secret, authKey);
        }
    }

    private AdminResult SetRouteKeySecretCore(string keyRef, string secret, string? authKey)
    {
        var auth = Authorize(authKey);
        if (auth is not null)
        {
            return auth;
        }

        if (!KeyValidator.ValidateRef(keyRef, out var refErrors))
        {
            return AdminResult.Failure("Invalid key reference.", AdminResult.TypeValidation, refErrors.ToArray());
        }

        if (!KeyValidator.ValidateSecret(secret, out var secretErrors))
        {
            return AdminResult.Failure("Invalid secret value.", AdminResult.TypeValidation, secretErrors.ToArray());
        }

        try
        {
            var root = LoadOrCreateServerConfig(backup: true);
            var proxy = EnsureObject(root, "Proxy");
            var routeKeys = proxy["RouteKeys"] as JsonObject ?? new JsonObject();
            routeKeys[keyRef] = secret;
            proxy["RouteKeys"] = routeKeys;

            var confirmed = SaveServerConfig(root, confirmOnly: true);
            if (!confirmed)
            {
                _audit.Append("key.secret.set", $"Server #{keyRef}", "restored", Actor(authKey));
                return AdminResult.Failure(
                    "The server config failed to reload after the write - the previous version was restored.",
                    AdminResult.TypeInternal, restored: true);
            }

            _audit.Append("key.secret.set", $"Server #{keyRef}", "ok", Actor(authKey));
            return AdminResult.Success($"Secret for keyRef '{keyRef}' is set. The value itself is never displayed.");
        }
        catch (Exception)
        {
            _audit.Append("key.secret.set", $"Server #{keyRef}", "error", Actor(authKey));
            return AdminResult.Failure("Could not write the server config - the previous version was kept.", AdminResult.TypeInternal);
        }
    }

    public AdminResult DeleteRouteKey(string keyRef, string? authKey = null)
    {
        lock (_writeLock)
        {
            return DeleteRouteKeyCore(keyRef, authKey);
        }
    }

    private AdminResult DeleteRouteKeyCore(string keyRef, string? authKey)
    {
        var auth = Authorize(authKey);
        if (auth is not null)
        {
            return auth;
        }

        if (!KeyValidator.ValidateRef(keyRef, out var refErrors))
        {
            return AdminResult.Failure("Invalid key reference.", AdminResult.TypeValidation, refErrors.ToArray());
        }

        var opts = _options.CurrentValue;
        var usedBy = (opts.Routes ?? new List<RouteOptions>())
            .Where(r => string.Equals(r.KeyRef, keyRef, StringComparison.Ordinal))
            .Select(r => r.Name)
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .ToList();

        if (usedBy.Count > 0)
        {
            return AdminResult.Failure(
                $"KeyRef '{keyRef}' is in use by {usedBy.Count} route(s) and cannot be deleted.",
                AdminResult.TypeConflict,
                usedBy.ToArray());
        }

        try
        {
            var root = LoadOrCreateServerConfig(backup: true);
            var proxy = EnsureObject(root, "Proxy");
            (proxy["RouteKeys"] as JsonObject)?.Remove(keyRef);

            var confirmed = SaveServerConfig(root, confirmOnly: true);
            if (!confirmed)
            {
                _audit.Append("key.delete", $"Server #{keyRef}", "restored", Actor(authKey));
                return AdminResult.Failure(
                    "The server config failed to reload after the write - the previous version was restored.",
                    AdminResult.TypeInternal, restored: true);
            }

            // Drop the metadata too (it refers to a key that no longer exists).
            var meta = _keyMeta.LoadAll().ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);
            meta.Remove(keyRef);
            _keyMeta.Save(meta);

            _audit.Append("key.delete", $"Server #{keyRef}", "ok", Actor(authKey));
            return AdminResult.Success($"KeyRef '{keyRef}' deleted (any route referencing it now falls back to the global key).");
        }
        catch (Exception)
        {
            _audit.Append("key.delete", $"Server #{keyRef}", "error", Actor(authKey));
            return AdminResult.Failure("Could not write the server config - the previous version was kept.", AdminResult.TypeInternal);
        }
    }

    public AdminResult EnsureRouteKeyRef(string keyRef, string? authKey = null)
    {
        lock (_writeLock)
        {
            return EnsureRouteKeyRefCore(keyRef, authKey);
        }
    }

    private AdminResult EnsureRouteKeyRefCore(string keyRef, string? authKey)
    {
        var auth = Authorize(authKey);
        if (auth is not null)
        {
            return auth;
        }

        if (!KeyValidator.ValidateRef(keyRef, out var refErrors))
        {
            return AdminResult.Failure("Invalid key reference.", AdminResult.TypeValidation, refErrors.ToArray());
        }

        try
        {
            // Load first WITHOUT backing up: an existing ref is a no-op and must not
            // clobber the backup history with a pointless copy.
            var path = ConfigPaths.ResolveFile(ServerFile, _paths.ConfigDir);
            var root = AtomicJsonWriter.Load(path) ?? new JsonObject { ["Proxy"] = new JsonObject() };
            var proxy = EnsureObject(root, "Proxy");
            var routeKeys = proxy["RouteKeys"] as JsonObject ?? new JsonObject();
            if (routeKeys.ContainsKey(keyRef))
            {
                return AdminResult.Success($"KeyRef '{keyRef}' already exists - nothing to change.");
            }

            _backups.Backup(_paths.ConfigDir, ServerFile);
            routeKeys[keyRef] = string.Empty; // empty value: ref declared, no secret yet
            proxy["RouteKeys"] = routeKeys;

            var confirmed = SaveServerConfig(root, confirmOnly: true);
            if (!confirmed)
            {
                _audit.Append("key.ref.create", $"Server #{keyRef}", "restored", Actor(authKey));
                return AdminResult.Failure(
                    "The server config failed to reload after the write - the previous version was restored.",
                    AdminResult.TypeInternal, restored: true);
            }

            _audit.Append("key.ref.create", $"Server #{keyRef}", "ok", Actor(authKey));
            return AdminResult.Success(
                $"KeyRef '{keyRef}' created with no secret yet - routes using it are inactive until a key is set.");
        }
        catch (Exception)
        {
            _audit.Append("key.ref.create", $"Server #{keyRef}", "error", Actor(authKey));
            return AdminResult.Failure("Could not write the server config - the previous version was kept.", AdminResult.TypeInternal);
        }
    }

    public AdminResult UpdateKeyMeta(string keyRef, KeyMeta meta, string? authKey = null)
    {
        lock (_writeLock)
        {
            return UpdateKeyMetaCore(keyRef, meta, authKey);
        }
    }

    private AdminResult UpdateKeyMetaCore(string keyRef, KeyMeta meta, string? authKey)
    {
        if (!string.IsNullOrEmpty(authKey) && !VerifyAdminKey(authKey))
        {
            return AdminResult.Failure("Invalid admin key.", AdminResult.TypeAuthentication);
        }

        if (!KeyValidator.ValidateRef(keyRef, out var refErrors))
        {
            return AdminResult.Failure("Invalid key reference.", AdminResult.TypeValidation, refErrors.ToArray());
        }

        try
        {
            var all = _keyMeta.LoadAll().ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);
            all[keyRef] = new KeyMeta(meta.Owner ?? string.Empty, meta.Purpose ?? string.Empty);
            _keyMeta.Save(all);
            _audit.Append("key.meta.update", $"meta #{keyRef}", "ok", Actor(authKey));
            return AdminResult.Success($"Metadata for '{keyRef}' saved.");
        }
        catch (Exception)
        {
            _audit.Append("key.meta.update", $"meta #{keyRef}", "error", Actor(authKey));
            return AdminResult.Failure("Could not write key metadata.", AdminResult.TypeInternal);
        }
    }

    // ----------------------------------------------------------
    // Local keys / upstream key (sensitive: writes appsettings.Server.json)
    // ----------------------------------------------------------

    public AdminResult ApplyLocalKeys(IReadOnlyList<string> localKeys, string? authKey = null)
    {
        lock (_writeLock)
        {
            return ApplyLocalKeysCore(localKeys, authKey);
        }
    }

    private AdminResult ApplyLocalKeysCore(IReadOnlyList<string> localKeys, string? authKey)
    {
        var auth = Authorize(authKey);
        if (auth is not null)
        {
            return auth;
        }

        if (!KeyValidator.ValidateLocalKeys(localKeys, out var errors))
        {
            return AdminResult.Failure("Invalid local key value.", AdminResult.TypeValidation, errors.ToArray());
        }

        try
        {
            var root = LoadOrCreateServerConfig(backup: true);
            var proxy = EnsureObject(root, "Proxy");
            var keys = proxy["Keys"] as JsonObject ?? new JsonObject();
            var list = new JsonArray();
            foreach (var value in localKeys ?? new List<string>())
            {
                list.Add(value);
            }

            keys["LocalKeys"] = list;
            proxy["Keys"] = keys;

            var confirmed = SaveServerConfig(root, confirmOnly: true);
            if (!confirmed)
            {
                _audit.Append("keys.local.apply", ServerFile, "restored", Actor(authKey));
                return AdminResult.Failure(
                    "The server config failed to reload after the write - the previous version was restored.",
                    AdminResult.TypeInternal, restored: true);
            }

            _audit.Append("keys.local.apply", ServerFile, "ok", Actor(authKey));
            return AdminResult.Success($"Local keys updated ({list.Count} extra key(s)).");
        }
        catch (Exception)
        {
            _audit.Append("keys.local.apply", ServerFile, "error", Actor(authKey));
            return AdminResult.Failure("Could not write the server config - the previous version was kept.", AdminResult.TypeInternal);
        }
    }

    public AdminResult AddLocalKey(string value, string? authKey = null)
    {
        lock (_writeLock)
        {
            return AddLocalKeyCore(value, authKey);
        }
    }

    private AdminResult AddLocalKeyCore(string value, string? authKey)
    {
        var auth = Authorize(authKey);
        if (auth is not null)
        {
            return auth;
        }

        if (!KeyValidator.ValidateSecret(value, out var errors))
        {
            return AdminResult.Failure("Invalid local key value.", AdminResult.TypeValidation, errors.ToArray());
        }

        // The UI only sees fingerprints; the current values live in the live options.
        // Re-read INSIDE the lock: the read-modify-write is what the lock serializes
        // (two parallel adds must both see the list, otherwise one overwrites the other).
        var current = new List<string>(_options.CurrentValue.Keys?.LocalKeys ?? new List<string>());
        if (current.Any(v => SecurityHelpers.SecureEquals(v, value)))
        {
            return AdminResult.Failure("That local key is already configured.", AdminResult.TypeConflict);
        }

        current.Add(value);
        return ApplyLocalKeysCore(current, authKey);
    }

    public AdminResult RemoveLocalKeyByHash(string shortHash, string? authKey = null)
    {
        lock (_writeLock)
        {
            return RemoveLocalKeyByHashCore(shortHash, authKey);
        }
    }

    private AdminResult RemoveLocalKeyByHashCore(string shortHash, string? authKey)
    {
        var auth = Authorize(authKey);
        if (auth is not null)
        {
            return auth;
        }

        if (string.IsNullOrWhiteSpace(shortHash))
        {
            return AdminResult.Failure("Missing local key fingerprint.", AdminResult.TypeValidation);
        }

        var current = new List<string>(_options.CurrentValue.Keys?.LocalKeys ?? new List<string>());
        var match = current.FirstOrDefault(v => AdminHash.Short(v).Equals(shortHash, StringComparison.OrdinalIgnoreCase));
        if (match is null)
        {
            return AdminResult.Failure("No local key with that fingerprint is configured.", AdminResult.TypeNotFound);
        }

        current.Remove(match);
        var removed = ApplyLocalKeysCore(current, authKey);
        if (removed.Ok)
        {
            // Drop the stored label too - it belongs to a key that no longer exists.
            _keyMeta.RemoveLocalLabel(shortHash);
        }

        return removed;
    }

    public AdminResult SetLocalKeyLabel(string shortHash, string label, string? authKey = null)
    {
        lock (_writeLock)
        {
            return SetLocalKeyLabelCore(shortHash, label, authKey);
        }
    }

    private AdminResult SetLocalKeyLabelCore(string shortHash, string label, string? authKey)
    {
        if (!string.IsNullOrEmpty(authKey) && !VerifyAdminKey(authKey))
        {
            return AdminResult.Failure("Invalid admin key.", AdminResult.TypeAuthentication);
        }

        if (string.IsNullOrWhiteSpace(shortHash))
        {
            return AdminResult.Failure("Missing local key fingerprint.", AdminResult.TypeValidation);
        }

        var clean = label?.Trim() ?? string.Empty;
        if (clean.Length > 64)
        {
            return AdminResult.Failure("Label must be at most 64 characters.", AdminResult.TypeValidation);
        }

        // The fingerprint must belong to a key that is currently configured.
        var current = _options.CurrentValue.Keys?.LocalKeys ?? new List<string>();
        if (!current.Any(v => AdminHash.Short(v).Equals(shortHash, StringComparison.OrdinalIgnoreCase)))
        {
            return AdminResult.Failure("No local key with that fingerprint is configured.", AdminResult.TypeNotFound);
        }

        try
        {
            var labels = _keyMeta.LoadLocalLabels().ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase);
            if (clean.Length == 0)
            {
                // Clearing the field removes the stored label.
                labels.Remove(shortHash);
            }
            else
            {
                labels[shortHash] = clean;
            }

            _keyMeta.SaveLocalLabels(labels);
            _audit.Append("local-key.label", $"local #{shortHash}", "ok", Actor(authKey));
            return AdminResult.Success($"Label for local key {shortHash} saved.");
        }
        catch (Exception)
        {
            _audit.Append("local-key.label", $"local #{shortHash}", "error", Actor(authKey));
            return AdminResult.Failure("Could not write local key metadata.", AdminResult.TypeInternal);
        }
    }

    public AdminResult SetUpstreamKey(string secret, string? authKey = null)
    {
        lock (_writeLock)
        {
            return SetUpstreamKeyCore(secret, authKey);
        }
    }

    private AdminResult SetUpstreamKeyCore(string secret, string? authKey)
    {
        var auth = Authorize(authKey);
        if (auth is not null)
        {
            return auth;
        }

        if (!KeyValidator.ValidateSecret(secret, out var secretErrors))
        {
            return AdminResult.Failure("Invalid secret value.", AdminResult.TypeValidation, secretErrors.ToArray());
        }

        try
        {
            var root = LoadOrCreateServerConfig(backup: true);
            var proxy = EnsureObject(root, "Proxy");
            var keys = proxy["Keys"] as JsonObject ?? new JsonObject();
            keys["UpstreamKey"] = secret;
            proxy["Keys"] = keys;

            var confirmed = SaveServerConfig(root, confirmOnly: true);
            if (!confirmed)
            {
                _audit.Append("key.upstream.set", ServerFile, "restored", Actor(authKey));
                return AdminResult.Failure(
                    "The server config failed to reload after the write - the previous version was restored.",
                    AdminResult.TypeInternal, restored: true);
            }

            _audit.Append("key.upstream.set", ServerFile, "ok", Actor(authKey));
            return AdminResult.Success("Global upstream key is set (used by routes without a keyRef).");
        }
        catch (Exception)
        {
            _audit.Append("key.upstream.set", ServerFile, "error", Actor(authKey));
            return AdminResult.Failure("Could not write the server config - the previous version was kept.", AdminResult.TypeInternal);
        }
    }

    // ----------------------------------------------------------
    // Log clearing (destructive; never touches config files, so no write lock)
    // ----------------------------------------------------------

    public AdminResult ClearActivityLog(string? authKey = null)
    {
        var auth = Authorize(authKey);
        if (auth is not null)
        {
            return auth;
        }

        var cleared = _activity.Clear();
        var message = $"Activity buffer cleared ({cleared} {(cleared == 1 ? "entry" : "entries")}).";
        if (!TryAudit("logs.clear.activity", "activity buffer", "ok", authKey))
        {
            // The destructive action already happened: never report it as a failure.
            message += " The audit entry could not be written.";
        }

        return AdminResult.Success(message);
    }

    public AdminResult ClearDetections(string? authKey = null)
    {
        var auth = Authorize(authKey);
        if (auth is not null)
        {
            return auth;
        }

        var cleared = _detections.Clear();
        var message = $"Detection buffer cleared ({cleared} {(cleared == 1 ? "entry" : "entries")}).";
        if (!TryAudit("logs.clear.detections", "detection buffer", "ok", authKey))
        {
            // The destructive action already happened: never report it as a failure.
            message += " The audit entry could not be written.";
        }

        return AdminResult.Success(message);
    }

    // ----------------------------------------------------------
    // Transport/Endpoint attestation write actions (Phase 2). Every action changes the
    // security posture (pins) or is destructive (clears), so the same re-auth path as
    // the destructive clears applies: primary local key + audit, no config write lock.
    // ----------------------------------------------------------

    public AdminResult AcceptAttestationPin(string routeName, string? spki, string? authKey = null)
    {
        var auth = Authorize(authKey);
        if (auth is not null)
        {
            return auth;
        }

        if (string.IsNullOrWhiteSpace(routeName))
        {
            return AdminResult.Failure("Route name is required.", AdminResult.TypeValidation);
        }

        if (_learnedPins is null)
        {
            return AdminResult.Failure("The learned-pin store is unavailable.", AdminResult.TypeInternal);
        }

        var opts = _options.CurrentValue;
        if (opts.Routes?.Any(r => string.Equals(r.Name, routeName, StringComparison.Ordinal)) is not true)
        {
            return AdminResult.Failure($"Route '{routeName}' does not exist.", AdminResult.TypeNotFound);
        }

        var pin = string.IsNullOrWhiteSpace(spki) ? LatestObservedSpki(routeName) : spki.Trim();
        if (string.IsNullOrWhiteSpace(pin))
        {
            return AdminResult.Failure($"No endpoint observed for route '{routeName}' yet - nothing to accept.", AdminResult.TypeNotFound);
        }

        var canonical = TransportHashes.NormalizePin(pin);
        if (canonical is null)
        {
            return AdminResult.Failure("The SPKI value is not a valid SHA-256 fingerprint (64 hex or base64url).", AdminResult.TypeValidation);
        }

        var added = _learnedPins.AddPin(routeName, canonical, DateTimeOffset.UtcNow);
        var count = _learnedPins.GetForRoute(routeName).Count;
        var message = added
            ? $"SPKI {TransportHashes.ShortHex16(canonical)} pinned for route '{routeName}' ({count} learned pin{(count == 1 ? "" : "s")})."
            : $"SPKI {TransportHashes.ShortHex16(canonical)} was already pinned for route '{routeName}'.";
        TryAudit("attestation.pin.accept", routeName, "ok", authKey);
        return AdminResult.Success(message);
    }

    public async Task<AdminResult> LearnAttestationNowAsync(string routeName, string? authKey = null)
    {
        var auth = Authorize(authKey);
        if (auth is not null)
        {
            return auth;
        }

        if (string.IsNullOrWhiteSpace(routeName))
        {
            return AdminResult.Failure("Route name is required.", AdminResult.TypeValidation);
        }

        if (_probe is null)
        {
            return AdminResult.Failure("The endpoint probe is unavailable.", AdminResult.TypeInternal);
        }

        var ok = await _probe.ProbeRouteAsync(routeName, CancellationToken.None);
        if (!ok)
        {
            return AdminResult.Failure($"The probe for route '{routeName}' could not complete (unknown route or unreachable upstream).", AdminResult.TypeInternal);
        }

        TryAudit("attestation.learn", routeName, "ok", authKey);
        return AdminResult.Success($"Endpoint probe for route '{routeName}' completed - the observation is in the baseline and the drift feed.");
    }

    public AdminResult ClearAttestationPins(string? routeName, string? authKey = null)
    {
        var auth = Authorize(authKey);
        if (auth is not null)
        {
            return auth;
        }

        if (_learnedPins is null)
        {
            return AdminResult.Failure("The learned-pin store is unavailable.", AdminResult.TypeInternal);
        }

        var removed = string.IsNullOrWhiteSpace(routeName)
            ? _learnedPins.ClearAll()
            : _learnedPins.RemoveRoute(routeName!);

        var message = removed == 0
            ? "No learned pins to clear."
            : string.IsNullOrWhiteSpace(routeName)
                ? $"Learned pins cleared ({removed} pin{(removed == 1 ? "" : "s")} removed)."
                : $"Learned pins for route '{routeName}' cleared ({removed} pin{(removed == 1 ? "" : "s")} removed).";
        TryAudit("attestation.pins.clear", string.IsNullOrWhiteSpace(routeName) ? "all" : routeName, "ok", authKey);
        return AdminResult.Success(message);
    }

    public AdminResult ClearAttestationDrift(string? authKey = null)
    {
        var auth = Authorize(authKey);
        if (auth is not null)
        {
            return auth;
        }

        if (_drift is null)
        {
            return AdminResult.Failure("The drift feed is unavailable.", AdminResult.TypeInternal);
        }

        var cleared = _drift.Clear();
        var message = $"Attestation drift feed cleared ({cleared} {(cleared == 1 ? "episode" : "episodes")}).";
        TryAudit("attestation.drift.clear", "drift feed", "ok", authKey);
        return AdminResult.Success(message);
    }

    /// <summary>The most recent endpoint SPKI observed for a route (durable baseline; the ring only keeps the short display span).</summary>
    private string? LatestObservedSpki(string routeName)
    {
        var group = _baseline?.GetRoute(routeName);
        return group?.Entries
            .OrderByDescending(e => e.LastSeen)
            .FirstOrDefault(e => !string.IsNullOrWhiteSpace(e.SpkiHash))
            ?.SpkiHash;
    }

    public AdminResult ClearEventLog(string? authKey = null)
    {
        var auth = Authorize(authKey);
        if (auth is not null)
        {
            return auth;
        }

        try
        {
            if (!_eventLogs.Exists(EventLogName))
            {
                var missing = "The dedicated Event Log does not exist on this machine - nothing to clear.";
                if (!TryAudit("logs.clear.eventlog", EventLogName, "unavailable", authKey))
                {
                    missing += " The audit entry could not be written.";
                }

                return AdminResult.Success(missing);
            }

            // The count only feeds the message: it must never abort the clear.
            int? count = null;
            try
            {
                count = _eventLogs.Count(EventLogName);
            }
            catch
            {
                // Stat only - never fail the clear for a count.
            }

            _eventLogs.Clear(EventLogName);
            var message = count is int entries
                ? $"Windows Event Log '{EventLogName}' cleared ({entries} entries)."
                : $"Windows Event Log '{EventLogName}' cleared.";
            if (!TryAudit("logs.clear.eventlog", EventLogName, "ok", authKey))
            {
                // The log was already cleared: never report it as a failure.
                message += " The audit entry could not be written.";
            }

            return AdminResult.Success(message);
        }
        catch (Exception ex)
        {
            // Cause stays server-side only; the caller gets the generic message below.
            // In production the only logging provider is the Event Log being cleared: if
            // it is full/removed/unregistered WriteEntry throws, and that must never mask
            // the original failure (or escape as a 500 / circuit crash).
            try
            {
                _logger.LogWarning(ex, "Failed to clear the Event Log {LogName}.", EventLogName);
            }
            catch
            {
                // Logging must never mask the original failure (the provider IS the log being cleared).
            }

            // Never surface the raw exception: it can carry machine paths or log internals.
            TryAudit("logs.clear.eventlog", EventLogName, "error", authKey);
            return AdminResult.Failure("Could not clear the Windows Event Log - it may require elevated rights or be in use.", AdminResult.TypeInternal);
        }
    }

    /// <summary>Best-effort audit append: a failed audit entry must not undo a completed destructive action.</summary>
    private bool TryAudit(string action, string target, string result, string? authKey)
    {
        try
        {
            _audit.Append(action, target, result, Actor(authKey));
            return true;
        }
        catch
        {
            // Never include the target's content or any secret: only the action/target names.
            // Same guard as the clear failure: a broken logging provider (the Event Log we
            // are clearing) must not turn a best-effort audit miss into an exception.
            try
            {
                _logger.LogWarning("Audit entry could not be written for {Action} ({Target}).", action, target);
            }
            catch
            {
                // Logging must never mask the original failure (the provider IS the log being cleared).
            }

            return false;
        }
    }

    // ----------------------------------------------------------
    // Redaction + inspection (non-sensitive: redaction.json)
    // ----------------------------------------------------------

    public AdminResult ApplySecurity(JsonNode? redactionSection, JsonNode? inspectionSection, string? authKey = null)
    {
        lock (_writeLock)
        {
            return ApplySecurityCore(redactionSection, inspectionSection, authKey);
        }
    }

    private AdminResult ApplySecurityCore(JsonNode? redactionSection, JsonNode? inspectionSection, string? authKey)
    {
        if (!string.IsNullOrEmpty(authKey) && !VerifyAdminKey(authKey))
        {
            return AdminResult.Failure("Invalid admin key.", AdminResult.TypeAuthentication);
        }

        if (!SecurityValidator.Validate(redactionSection, inspectionSection, out var errors))
        {
            return AdminResult.Failure("Security configuration is invalid - nothing was written.", AdminResult.TypeValidation, errors.ToArray());
        }

        try
        {
            _backups.Backup(_paths.ConfigDir, RedactionFile);
            var root = LoadOrCreateConfig(RedactionFile);
            var proxy = EnsureObject(root, "Proxy");
            if (redactionSection is not null)
            {
                proxy["Redaction"] = redactionSection;
            }

            if (inspectionSection is not null)
            {
                proxy["Inspection"] = inspectionSection;
            }

            AtomicJsonWriter.SaveAtomic(ConfigPaths.ResolveFile(RedactionFile, _paths.ConfigDir), root);

            var confirmed = _confirmer.Confirm(_paths.ConfigDir, RedactionFile, RedactionShape);
            if (!confirmed)
            {
                RecoverAfterFailedConfirm(RedactionFile);
                _audit.Append("security.apply", RedactionFile, "restored", Actor(authKey));
                return AdminResult.Failure(
                    "redaction.json failed to reload after the write - the previous version was restored.",
                    AdminResult.TypeInternal, restored: true);
            }

            _audit.Append("security.apply", RedactionFile, "ok", Actor(authKey));

            var message = "Security settings applied and the engine reloaded.";

            // Turning forensics OFF purges the in-memory detection buffer: metadata must not
            // linger after the operator disabled collection. Only when there is actually
            // something to drop - a plain Save while already off must not emit an empty audit
            // line or an "0 entries cleared" banner. Best effort only: the config write is
            // already committed, so neither the purge nor its audit entry may fail (or roll
            // back) the operation.
            if (IsForensicsDisabled(redactionSection) && _detections.Count > 0)
            {
                var purged = _detections.Clear();
                TryAudit("logs.clear.detections", "detection buffer", "ok", authKey);
                message += $" Forensics disabled: {purged} buffered {(purged == 1 ? "entry" : "entries")} cleared.";
            }

            return AdminResult.Success(message);
        }
        catch (Exception)
        {
            _audit.Append("security.apply", RedactionFile, "error", Actor(authKey));
            return AdminResult.Failure("Could not write redaction.json - the previous version was kept.", AdminResult.TypeInternal);
        }
    }

    // ----------------------------------------------------------
    // Export / import / reload
    // ----------------------------------------------------------

    public AdminResult Export()
    {
        lock (_writeLock)
        {
            return ExportCore();
        }
    }

    private AdminResult ExportCore()
    {
        try
        {
            var bundle = new JsonObject();

            var routes = (_options.CurrentValue.Routes ?? new List<RouteOptions>())
                .Select(RouteDraftJson.FromRouteOptions)
                .ToList();
            bundle["routes"] = RouteDraftJson.ToArray(routes);

            // Redaction/inspection come from the live redaction.json when present
            // (exact configured shape), falling back to the effective bound options.
            var redaction = AtomicJsonWriter.Load(ConfigPaths.ResolveFile(RedactionFile, _paths.ConfigDir));
            if (redaction is JsonObject redRoot && redRoot["Proxy"] is JsonObject redProxy)
            {
                bundle["redaction"] = redProxy["Redaction"]?.DeepClone() ?? new JsonObject();
                bundle["inspection"] = redProxy["Inspection"]?.DeepClone() ?? new JsonObject();
            }
            else
            {
                bundle["redaction"] = JsonSerializer.SerializeToNode(_options.CurrentValue.Redaction, JsonWrite);
                bundle["inspection"] = JsonSerializer.SerializeToNode(_options.CurrentValue.Inspection, JsonWrite);
            }

            // NEVER include RouteKeys / Keys / any secret value - only keyRef names appear in "routes".
            return AdminResult.Success("Export bundle ready (no secrets included).", data: bundle);
        }
        catch (Exception)
        {
            return AdminResult.Failure("Could not build the export bundle.", AdminResult.TypeInternal);
        }
    }

    public AdminResult ValidateImport(JsonNode bundle)
    {
        var problems = new List<string>();
        var warnings = new List<string>();

        if (!ImportValidator.Validate(bundle, out var bundleErrors))
        {
            problems.AddRange(bundleErrors);
        }

        if (!ImportValidator.HasRoutes(bundle) && !ImportValidator.HasSecurity(bundle))
        {
            problems.Add("Empty import bundle - provide 'routes' and/or 'redaction'/'inspection' sections.");
        }

        if (ImportValidator.HasRoutes(bundle) && bundle["routes"] is JsonArray routeArray)
        {
            var drafts = new List<RouteDraft>();
            foreach (var entry in routeArray)
            {
                try
                {
                    var draft = entry.Deserialize<RouteDraft>(JsonRead);
                    drafts.Add(draft ?? throw new JsonException("null route"));
                }
                catch (JsonException)
                {
                    problems.Add("Bundle 'routes' contains an entry that is not a valid route object.");
                }
            }

            if (problems.Count == 0)
            {
                // Known keyRefs = live snapshot UNION appsettings.Server.json on disk, the same
                // set ApplyRoutes validates against - otherwise a ref just declared (write ahead
                // of the watcher reload) would warn here but not on save.
                var (declared, configured) = KnownKeyRefs(_options.CurrentValue);
                RouteValidator.Validate(drafts, declared, out var routeErrors, out var routeWarnings, configured);
                problems.AddRange(routeErrors);
                warnings.AddRange(routeWarnings);
            }
        }

        if (ImportValidator.HasSecurity(bundle))
        {
            var redaction = bundle["redaction"];
            var inspection = bundle["inspection"];
            if (!SecurityValidator.Validate(redaction, inspection, out var securityErrors))
            {
                problems.AddRange(securityErrors);
            }
        }

        if (problems.Count > 0)
        {
            return new AdminResult(
                Ok: false,
                Message: $"Import bundle has {problems.Count} problem(s) - nothing was applied.",
                Restored: false,
                Errors: problems.ToArray(),
                Warnings: warnings.ToArray(),
                ErrorType: AdminResult.TypeValidation);
        }

        return AdminResult.Success("Import bundle is valid - ready to apply.", warnings.Count > 0 ? warnings.ToArray() : null);
    }

    public AdminResult Import(JsonNode bundle, string? authKey = null)
    {
        lock (_writeLock)
        {
            return ImportCore(bundle, authKey);
        }
    }

    private AdminResult ImportCore(JsonNode bundle, string? authKey)
    {
        var auth = Authorize(authKey);
        if (auth is not null)
        {
            return auth;
        }

        var check = ValidateImport(bundle);
        if (!check.Ok)
        {
            return check;
        }

        // Files this operation has backed up and written - the ONLY rollback scope.
        // A file the import did not touch (e.g. routes.json on a security-only import)
        // must never be deleted or restored from an unrelated older backup.
        var touched = new List<string>();

        try
        {
            var hasRoutes = ImportValidator.HasRoutes(bundle);
            var hasSecurity = ImportValidator.HasSecurity(bundle);
            if (hasRoutes)
            {
                _backups.Backup(_paths.ConfigDir, RoutesFile);
            }

            if (hasSecurity)
            {
                _backups.Backup(_paths.ConfigDir, RedactionFile);
            }

            var wroteRoutes = false;
            var wroteSecurity = false;

            if (hasRoutes && bundle["routes"] is JsonArray routeArray)
            {
                var drafts = DeserializeDrafts(routeArray);
                var routesRoot = LoadOrCreateConfig(RoutesFile);
                EnsureObject(routesRoot, "Proxy")["Routes"] = RouteDraftJson.ToArray(drafts);
                touched.Add(RoutesFile);
                AtomicJsonWriter.SaveAtomic(ConfigPaths.ResolveFile(RoutesFile, _paths.ConfigDir), routesRoot);
                if (!_confirmer.Confirm(_paths.ConfigDir, RoutesFile, RoutesShape))
                {
                    throw new InvalidOperationException("routes");
                }

                wroteRoutes = true;
            }

            if (hasSecurity)
            {
                var securityRoot = LoadOrCreateConfig(RedactionFile);
                var proxy = EnsureObject(securityRoot, "Proxy");
                if (bundle["redaction"] is not null)
                {
                    // Only known properties reach redaction.json - unknown/nested fields
                    // from the bundle (smuggling) are dropped by the whitelist projection.
                    proxy["Redaction"] = SecurityValidator.SanitizeRedaction(bundle["redaction"]);
                }

                if (bundle["inspection"] is not null)
                {
                    proxy["Inspection"] = SecurityValidator.SanitizeInspection(bundle["inspection"]);
                }

                touched.Add(RedactionFile);
                AtomicJsonWriter.SaveAtomic(ConfigPaths.ResolveFile(RedactionFile, _paths.ConfigDir), securityRoot);
                if (!_confirmer.Confirm(_paths.ConfigDir, RedactionFile, RedactionShape))
                {
                    throw new InvalidOperationException("redaction");
                }

                wroteSecurity = true;
            }

            _audit.Append("config.import", $"{RoutesFile}+{RedactionFile}", "ok", Actor(authKey));
            var parts = new List<string>();
            if (wroteRoutes)
            {
                parts.Add("routes");
            }

            if (wroteSecurity)
            {
                parts.Add("redaction/inspection");
            }

            return AdminResult.Success(
                $"Import applied: {string.Join(" + ", parts)} written and the engine reloaded.",
                check.Warnings is { Length: > 0 } ? check.Warnings : null);
        }
        catch (InvalidOperationException)
        {
            // A file was written but did not reload (confirm failed). Roll back ONLY
            // the files this operation wrote, in reverse write order.
            for (var i = touched.Count - 1; i >= 0; i--)
            {
                RecoverAfterFailedConfirm(touched[i]);
            }

            _audit.Append("config.import", $"{RoutesFile}+{RedactionFile}", "restored", Actor(authKey));
            return AdminResult.Failure(
                "Import could not be applied cleanly - the previous configuration was restored.",
                AdminResult.TypeInternal, restored: touched.Count > 0);
        }
        catch (Exception)
        {
            // The second file failed to save (or anything else blew up) after the first
            // was already written. Restore EVERY touched file in reverse write order so
            // "no changes applied" is honest - not just true for the failed file.
            for (var i = touched.Count - 1; i >= 0; i--)
            {
                RecoverAfterFailedConfirm(touched[i]);
            }

            _audit.Append("config.import", $"{RoutesFile}+{RedactionFile}", "error", Actor(authKey));
            return AdminResult.Failure(
                "Import could not be applied cleanly - the import was rolled back, no changes applied.",
                AdminResult.TypeInternal, restored: touched.Count > 0);
        }
    }

    public AdminResult ReloadConfirm()
    {
        lock (_writeLock)
        {
            return ReloadConfirmCore();
        }
    }

    private AdminResult ReloadConfirmCore()
    {
        var restoredAny = false;
        var restoreFailedAny = false;
        var problems = new List<string>();

        CheckFile("routes.json", RoutesShape, problems, ref restoredAny, ref restoreFailedAny);
        CheckFile("redaction.json", RedactionShape, problems, ref restoredAny, ref restoreFailedAny);
        CheckFile(ServerFile, ServerShape, problems, ref restoredAny, ref restoreFailedAny);

        if (problems.Count > 0)
        {
            var suffix = restoreFailedAny
                ? " A backup was found but the restore failed (the file may be locked) - check file permissions and fix the file manually."
                : restoredAny
                    ? " Broken files were restored from backup."
                    : " No backup was available - fix the file manually.";
            return AdminResult.Failure($"Reload check failed ({problems.Count} file(s)):{suffix}", AdminResult.TypeInternal, problems.ToArray(), restored: restoredAny);
        }

        return AdminResult.Success("Reload check passed - all config files are valid and hot-reloaded.");
    }

    // ----------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------

    private AdminResult? Authorize(string? authKey)
    {
        if (string.IsNullOrWhiteSpace(authKey))
        {
            return AdminResult.Failure("Admin key required for this operation.", AdminResult.TypeAuthentication);
        }

        if (!VerifyAdminKey(authKey))
        {
            return AdminResult.Failure("Invalid admin key.", AdminResult.TypeAuthentication);
        }

        return null;
    }

    private string Actor(string? authKey) => string.IsNullOrEmpty(authKey) ? "-" : AdminHash.Short(authKey);

    private static IEnumerable<string> DeclaredKeyRefs(ProxyOptions o)
        => o.RouteKeys is null ? Enumerable.Empty<string>() : o.RouteKeys.Keys;

    /// <summary>
    /// Known keyRefs for route validation = the live IOptionsMonitor snapshot (covers refs
    /// supplied via env vars, which never appear in the config file) UNION the RouteKeys
    /// currently on disk in appsettings.Server.json. The monitor reloads through a
    /// FileSystemWatcher debounce, so right after EnsureRouteKeyRef/SetRouteKeySecret wrote
    /// the file the live snapshot does not yet contain the new ref - validating against the
    /// live snapshot alone would emit a false "not declared in the Keys panel" warning for a
    /// route that was just made saveable (Add keyRef -> Add route -> Save immediately).
    /// Only key NAMES and the empty/non-empty classification of the on-disk values are
    /// consulted; secret values never leave the process (never in results, warnings or the
    /// audit log).
    /// </summary>
    private (HashSet<string> Declared, HashSet<string> Configured) KnownKeyRefs(ProxyOptions opts)
    {
        var declared = new HashSet<string>(DeclaredKeyRefs(opts), StringComparer.Ordinal);
        var configured = new HashSet<string>(
            declared.Where(k => opts.RouteKeys is not null
                && opts.RouteKeys.TryGetValue(k, out var liveValue) && !string.IsNullOrWhiteSpace(liveValue)),
            StringComparer.Ordinal);

        try
        {
            // Fresh read from disk (backup: false - read-only): picks up a keyRef whose
            // write is still ahead of the monitor reload. Best effort: an unreadable or
            // corrupt server config falls back to the live snapshot (pre-union behavior).
            var root = LoadOrCreateServerConfig(backup: false);
            if (root is JsonObject rootNode && rootNode["Proxy"] is JsonObject proxy && proxy["RouteKeys"] is JsonObject routeKeys)
            {
                foreach (var (refName, value) in routeKeys)
                {
                    declared.Add(refName);
                    if (HasSecretOnDisk(value))
                    {
                        configured.Add(refName);
                    }
                }
            }
        }
        catch
        {
            // Best effort - validation must never break because the server config cannot be read right now.
        }

        return (declared, configured);
    }

    /// <summary>True when the on-disk RouteKeys value holds a non-empty secret ("" = declared but unset).</summary>
    private static bool HasSecretOnDisk(JsonNode? value)
        => value is JsonValue jsonValue
           && jsonValue.TryGetValue<string>(out var text)
           && !string.IsNullOrWhiteSpace(text);

    private JsonNode LoadOrCreateConfig(string fileName)
        => AtomicJsonWriter.Load(ConfigPaths.ResolveFile(fileName, _paths.ConfigDir))
           ?? new JsonObject { ["Proxy"] = new JsonObject() };

    /// <summary>Loads appsettings.Server.json or creates the minimal {"Proxy":{}} skeleton, with a backup of the current version.</summary>
    private JsonNode LoadOrCreateServerConfig(bool backup)
    {
        var path = ConfigPaths.ResolveFile(ServerFile, _paths.ConfigDir);
        if (backup && File.Exists(path))
        {
            _backups.Backup(_paths.ConfigDir, ServerFile);
        }

        return AtomicJsonWriter.Load(path) ?? new JsonObject { ["Proxy"] = new JsonObject() };
    }

    private bool SaveServerConfig(JsonNode root, bool confirmOnly)
    {
        AtomicJsonWriter.SaveAtomic(ConfigPaths.ResolveFile(ServerFile, _paths.ConfigDir), root);
        return _confirmer.Confirm(_paths.ConfigDir, ServerFile, ServerShape);
    }

    private static JsonObject EnsureObject(JsonNode parent, string property)
    {
        if (parent[property] is JsonObject existing)
        {
            return existing;
        }

        var created = new JsonObject();
        parent[property] = created;
        return created;
    }

    /// <summary>
    /// True when the submitted Redaction section explicitly disables forensics
    /// (<c>forensics.enabled == false</c>). Case-insensitive, mirroring SecurityValidator.
    /// </summary>
    private static bool IsForensicsDisabled(JsonNode? redactionSection)
    {
        if (redactionSection is not JsonObject section
            || SectionProp(section, "forensics") is not JsonObject forensics)
        {
            return false;
        }

        return SectionProp(forensics, "enabled") is JsonValue enabled
               && enabled.TryGetValue<bool>(out var on)
               && !on;
    }

    /// <summary>Case-insensitive property lookup (the option binder is case-insensitive too).</summary>
    private static JsonNode? SectionProp(JsonObject obj, string name)
    {
        foreach (var (key, value) in obj)
        {
            if (string.Equals(key, name, StringComparison.OrdinalIgnoreCase))
            {
                return value;
            }
        }

        return null;
    }

    private void RecoverAfterFailedConfirm(string fileName)
    {
        var latest = _backups.LatestBackup(_paths.ConfigDir, fileName);
        if (latest is not null)
        {
            try
            {
                _backups.Restore(_paths.ConfigDir, fileName, latest);
                return;
            }
            catch
            {
                // Fall through to deletion attempt - never leave a corrupt file hot-reloading.
            }
        }

        try
        {
            var path = ConfigPaths.ResolveFile(fileName, _paths.ConfigDir);
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Best effort - a locked file keeps failing reload; the service still runs on the old snapshot.
        }
    }

    private void CheckFile(string fileName, Func<JsonNode, bool> shape, List<string> problems, ref bool restoredAny, ref bool restoreFailedAny)
    {
        var path = ConfigPaths.ResolveFile(fileName, _paths.ConfigDir);
        if (!File.Exists(path))
        {
            return; // all three files are optional - absence is a valid state
        }

        JsonNode? node;
        try
        {
            node = AtomicJsonWriter.Load(path);
        }
        catch
        {
            node = null;
        }

        var valid = node is not null && shape(node);
        if (valid)
        {
            return;
        }

        var outcome = _confirmer.ConfirmDetailed(_paths.ConfigDir, fileName, shape);
        problems.Add(fileName);
        restoredAny |= outcome.Restored;
        restoreFailedAny |= outcome.RestoreFailed;
    }

    private static List<RouteDraft> DeserializeDrafts(JsonArray array)
    {
        var drafts = new List<RouteDraft>();
        foreach (var entry in array)
        {
            var draft = entry.Deserialize<RouteDraft>(JsonRead)
                ?? throw new JsonException("null route");
            drafts.Add(draft);
        }

        return drafts;
    }

    // Structural shapes used after every write and on reload checks. These mirror the
    // sections the kernel binds; deep content validation happens in the validators.
    private static bool RoutesShape(JsonNode node)
        => node is JsonObject root
           && (root["Proxy"] is null || (root["Proxy"] is JsonObject proxy && (proxy["Routes"] is null || proxy["Routes"] is JsonArray)));

    private static bool RedactionShape(JsonNode node)
        => node is JsonObject root
           && (root["Proxy"] is null || (root["Proxy"] is JsonObject proxy
               && (proxy["Redaction"] is null || proxy["Redaction"] is JsonObject)
               && (proxy["Inspection"] is null || proxy["Inspection"] is JsonObject)));

    private static bool ServerShape(JsonNode node)
        => node is JsonObject root
           && (root["Proxy"] is null || (root["Proxy"] is JsonObject proxy
               && (proxy["Keys"] is null || proxy["Keys"] is JsonObject)
               && (proxy["RouteKeys"] is null || proxy["RouteKeys"] is JsonObject)));
}
