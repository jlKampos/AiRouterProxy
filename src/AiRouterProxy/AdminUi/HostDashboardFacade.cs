using System.Diagnostics;
using System.Reflection;
using AiRouterProxy.AdminPersistence;
using AiRouterProxy.AdminServices;
using AiRouterProxy.Dashboard.Models;
using Microsoft.Extensions.Options;
using AIRouterProxy;
using RouteOptions = AIRouterProxy.RouteOptions;

namespace AiRouterProxy.AdminUi;

/// <summary>
/// Host-side implementation of the dashboard facade. Reads the live kernel singletons
/// (IOptionsMonitor for hot reload, ActivityStore) and never exposes key values:
/// only counts, states and references are projected into the DTOs.
/// </summary>
public sealed class HostDashboardFacade : IDashboardFacade
{
    private readonly IOptionsMonitor<ProxyOptions> _options;
    private readonly ActivityStore _activity;
    private readonly DashboardPaths _paths;
    private readonly KeyMetaStore _keyMeta;
    private readonly IDetectionStore _detections;
    private readonly DateTimeOffset _started;
    private readonly string _version;

    public HostDashboardFacade(
        IOptionsMonitor<ProxyOptions> options,
        ActivityStore activity,
        DashboardPaths paths,
        KeyMetaStore keyMeta,
        IDetectionStore detections)
    {
        _options = options;
        _activity = activity;
        _paths = paths;
        _keyMeta = keyMeta;
        _detections = detections;

        try
        {
            _started = Process.GetCurrentProcess().StartTime.ToUniversalTime();
        }
        catch
        {
            _started = DateTimeOffset.UtcNow;
        }

        _version = Assembly.GetEntryAssembly()
            ?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion?.Split('+')[0] ?? "0.0.0";
    }

    public DashboardStatus GetStatus()
    {
        var o = _options.CurrentValue;
        return new DashboardStatus(
            Status: "ok",
            Version: _version,
            Timestamp: DateTimeOffset.UtcNow,
            UptimeSec: (long)(DateTimeOffset.UtcNow - _started).TotalSeconds,
            ActivityCount: _activity.Count,
            RoutingEnabled: o.Routes is { Count: > 0 },
            RouteCount: o.Routes?.Count ?? 0,
            ConfiguredRouteKeys: o.RouteKeys?.Count(kv => !string.IsNullOrWhiteSpace(kv.Value)) ?? 0,
            RateLimitEnabled: o.RateLimit?.Enabled ?? true,
            RedactionEnabled: o.Redaction.Enabled,
            InspectionEnabled: o.Inspection.Enabled);
    }

    public IReadOnlyList<RouteView> GetRoutes()
    {
        var o = _options.CurrentValue;
        var routes = o.Routes ?? new List<RouteOptions>();
        return MapRoutes(routes, o);
    }

    public RouteDefaultsView GetRouteDefaults()
    {
        var o = _options.CurrentValue;
        return new RouteDefaultsView(o.RequestTimeoutMs, o.MaxBodySize);
    }

    /// <summary>
    /// Maps a route list into UI rows. 'live' provides the environment-aware key table and
    /// the inherited defaults (timeout/max body); the routes themselves come from either
    /// monitor state or the freshly written disk file.
    /// </summary>
    private IReadOnlyList<RouteView> MapRoutes(IReadOnlyList<RouteOptions> routes, ProxyOptions live)
    {
        return routes.Select(r =>
        {
            var key = RouteResolver.GetRouteKey(r, live.RouteKeys, live.Keys.UpstreamKey);
            return new RouteView(
                r.Name,
                r.Prefix ?? string.Empty,
                r.Upstream ?? string.Empty,
                r.KeyRef ?? string.Empty,
                Active: key is not null,
                r.AllowedPaths.Count > 0 ? r.AllowedPaths : new List<string> { "*" },
                r.RequestTimeoutMs > 0 ? r.RequestTimeoutMs : live.RequestTimeoutMs,
                RouteResolver.EffectiveMaxBodySize(r, live.MaxBodySize));
        }).ToList();
    }

    public IReadOnlyList<KeyRefView> GetRouteKeyRefs()
    {
        var o = _options.CurrentValue;
        var routes = o.Routes ?? new List<RouteOptions>();
        var list = new List<KeyRefView>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var route in routes)
        {
            var keyRef = route.KeyRef ?? string.Empty;
            if (keyRef.Length == 0 || !seen.Add(keyRef))
            {
                continue;
            }

            var configured = o.RouteKeys is not null
                && o.RouteKeys.TryGetValue(keyRef, out var value)
                && !string.IsNullOrWhiteSpace(value);

            var usage = routes.Count(x => string.Equals(x.KeyRef, keyRef, StringComparison.Ordinal));
            list.Add(new KeyRefView(keyRef, configured, usage, route.Name));
        }

        return list;
    }

    public IReadOnlyList<KeyMetaView> GetKeyMeta()
    {
        var o = _options.CurrentValue;
        var routes = o.Routes ?? new List<RouteOptions>();
        var meta = _keyMeta.LoadAll();
        var list = new List<KeyMetaView>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var route in routes)
        {
            var keyRef = route.KeyRef ?? string.Empty;
            if (keyRef.Length == 0 || !seen.Add(keyRef))
            {
                continue;
            }

            var configured = o.RouteKeys is not null
                && o.RouteKeys.TryGetValue(keyRef, out var value)
                && !string.IsNullOrWhiteSpace(value);

            var stored = meta.TryGetValue(keyRef, out var m) ? m : null;
            var owner = stored is not null && !string.IsNullOrWhiteSpace(stored.Owner) ? stored.Owner : route.Name;
            list.Add(new KeyMetaView(keyRef, owner, stored?.Purpose ?? (configured ? "Upstream API key" : "Upstream API key (not set)")));
        }

        return list;
    }

    public IReadOnlyList<ActivityView> GetActivity(int hours, int limit)
    {
        var since = DateTimeOffset.UtcNow.AddHours(-Math.Max(1, hours));
        return _activity.Recent(since, Math.Max(1, limit)).Select(e => new ActivityView(
            e.Timestamp,
            e.Client ?? "-",
            e.Method ?? "GET",
            e.Path ?? "-",
            e.Status,
            e.DurationMs,
            e.Model ?? "-",
            e.Route ?? "-",
            e.Refused,
            e.Redacted,
            e.PresentedHash ?? "-",
            e.ExpectedHash ?? "-",
            e.Route ?? "-",
            e.UA ?? "-",
            e.RedactionKinds ?? "-")).ToList();
    }

    public int LocalKeyCount() => AuthenticationPolicy.LocalKeyCount(_options.CurrentValue.Keys);

    // ----------------------------------------------------------
    // Detection forensics (in memory, metadata only - never the value).
    // ----------------------------------------------------------

    public IReadOnlyList<DetectionView> GetDetections(int limit)
        => _detections.Recent(Math.Clamp(limit, 1, 200)).Select(d => new DetectionView(
            d.Timestamp,
            d.RequestId,
            d.Client,
            d.Route,
            d.Method,
            d.RequestPath,
            d.Model,
            d.JsonPath,
            d.Layer,
            d.Kind,
            d.Length,
            d.Fingerprint,
            d.Name,
            d.Sep,
            d.Quote)).ToList();

    // ----------------------------------------------------------
    // Admin write phase (2.6.0): read-only views for the editable screens.
    // ----------------------------------------------------------

    public SecurityOptionsView GetSecurityOptions()
    {
        var o = _options.CurrentValue;
        return MapSecurity(o);
    }

    /// <summary>
    /// Projects a ProxyOptions (sections already resolved) into the Security UI view.
    /// RateLimit is null-tolerant exactly like the original live mapping.
    /// </summary>
    private SecurityOptionsView MapSecurity(ProxyOptions o)
    {
        return new SecurityOptionsView(
            Redaction: new RedactionSettingsView(
                Enabled: o.Redaction.Enabled,
                Mask: o.Redaction.Mask,
                NotifyInResponse: o.Redaction.NotifyInResponse,
                WarnTemplate: o.Redaction.WarnTemplate,
                Detect: new DetectSettingsView(
                    o.Redaction.Detect.ByFieldName,
                    o.Redaction.Detect.ByFormats,
                    o.Redaction.Detect.ByKeyValueContext,
                    o.Redaction.Detect.ByLongStrings,
                    o.Redaction.Detect.ExemptBase64,
                    o.Redaction.Detect.EntropyThreshold),
                Allow: o.Redaction.Allow ?? new List<string>(),
                Forensics: new ForensicsSettingsView(
                    Enabled: o.Redaction.Forensics?.Enabled ?? false,
                    Capacity: o.Redaction.Forensics?.Capacity ?? 200)),
            Inspection: new InspectionSettingsView(
                Enabled: o.Inspection.Enabled,
                DefaultAction: o.Inspection.DefaultAction,
                InvalidJson: o.Inspection.InvalidJson,
                ByContentType: new Dictionary<string, string>(o.Inspection.ByContentType ?? new(), StringComparer.OrdinalIgnoreCase)),
            RateLimit: new RateLimitSettingsView(
                Enabled: o.RateLimit is { Enabled: true },
                MaxRequestsPerWindow: o.RateLimit?.MaxRequestsPerWindow ?? 0,
                RequestWindowSeconds: o.RateLimit?.RequestWindowSeconds ?? 0,
                MaxFailuresPerWindow: o.RateLimit?.MaxFailuresPerWindow ?? 0,
                FailureWindowSeconds: o.RateLimit?.FailureWindowSeconds ?? 0,
                LockoutSeconds: o.RateLimit?.LockoutSeconds ?? 0));
    }

    public ConfigPathsView GetConfigPaths()
        => new(
            ConfigDir: _paths.ConfigDir,
            DataDir: _paths.DataDir,
            BackupDir: _paths.BackupDir,
            AuditLogPath: _paths.AuditLogPath,
            KeyMetaPath: _paths.KeyMetaPath,
            Retention: ConfigBackup.MaxBackupsPerFile);

    public KeysOverviewView GetKeysOverview()
    {
        var o = _options.CurrentValue;
        var routes = o.Routes ?? new List<RouteOptions>();
        var meta = _keyMeta.LoadAll();
        var routeKeys = o.RouteKeys ?? new Dictionary<string, string>(StringComparer.Ordinal);
        return MapKeysOverview(routes, routeKeys, o.Keys, meta, _keyMeta.LoadLocalLabels());
    }

    /// <summary>
    /// Projects routes + resolved key tables (already merged from disk/live by the caller)
    /// into the Routes &amp; Keys UI view. Key values never leave the process - only hashes,
    /// configured-state and usage counts.
    /// </summary>
    private KeysOverviewView MapKeysOverview(
        IReadOnlyList<RouteOptions> usageRoutes,
        Dictionary<string, string> routeKeys,
        KeyOptions keys,
        IReadOnlyDictionary<string, KeyMeta> meta,
        IReadOnlyDictionary<string, string> localLabels)
    {
        // Union: refs referenced by routes + refs declared in RouteKeys + refs that only
        // have metadata. Each row carries the configured state (value set) and usage.
        var refs = new Dictionary<string, (int Usage, string OwnerRoute, string Owner, string Purpose)>(StringComparer.Ordinal);
        foreach (var route in usageRoutes)
        {
            var keyRef = route.KeyRef ?? string.Empty;
            if (keyRef.Length == 0 || refs.ContainsKey(keyRef))
            {
                continue;
            }

            var usage = usageRoutes.Count(r => string.Equals(r.KeyRef, keyRef, StringComparison.Ordinal));
            refs[keyRef] = (usage, route.Name, route.Name, string.Empty);
        }

        foreach (var keyRef in routeKeys.Keys)
        {
            if (!refs.ContainsKey(keyRef))
            {
                refs[keyRef] = (0, string.Empty, keyRef, string.Empty);
            }
        }

        foreach (var (keyRef, m) in meta)
        {
            if (refs.TryGetValue(keyRef, out var existing))
            {
                refs[keyRef] = (existing.Usage, existing.OwnerRoute, m.Owner, m.Purpose);
            }
            else
            {
                refs[keyRef] = (0, string.Empty, m.Owner, m.Purpose);
            }
        }

        static bool IsConfigured(Dictionary<string, string> routeKeys, string keyRef)
            => routeKeys.TryGetValue(keyRef, out var value)
               && !string.IsNullOrWhiteSpace(value);

        var keyRefViews = refs
            .OrderBy(kv => kv.Key, StringComparer.Ordinal)
            .Select(kv => new KeyRefDetailView(
                KeyRef: kv.Key,
                Configured: IsConfigured(routeKeys, kv.Key),
                UsageCount: kv.Value.Usage,
                OwnerRoute: kv.Value.OwnerRoute,
                Owner: string.IsNullOrWhiteSpace(kv.Value.Owner) ? kv.Value.OwnerRoute : kv.Value.Owner,
                Purpose: kv.Value.Purpose))
            .ToList();

        var localKeys = new List<LocalKeyView>();
        if (keys?.LocalKey is { Length: > 0 })
        {
            localKeys.Add(new LocalKeyView("primary", AdminHash.Short(keys.LocalKey), IsPrimary: true));
        }

        if (keys?.LocalKeys is { Count: > 0 })
        {
            for (var i = 0; i < keys.LocalKeys.Count; i++)
            {
                var hash = AdminHash.Short(keys.LocalKeys[i]);
                var label = localLabels.TryGetValue(hash, out var named) && !string.IsNullOrWhiteSpace(named)
                    ? named
                    : $"extra #{i + 1}";
                localKeys.Add(new LocalKeyView(label, hash, IsPrimary: false));
            }
        }

        return new KeysOverviewView(
            KeyRefs: keyRefViews,
            LocalKeys: localKeys,
            HasGlobalKey: !string.IsNullOrWhiteSpace(keys?.UpstreamKey),
            HasPrimaryLocalKey: !string.IsNullOrWhiteSpace(keys?.LocalKey));
    }

    // ----------------------------------------------------------
    // Post-save refresh (2.6.1): the live snapshot (IOptionsMonitor) reloads through the
    // FileSystemWatcher with debounce, so immediately after a save it is still STALE.
    // These read the files themselves - the freshly written FILE is the truth the UI must
    // reflect. Live/env values fill in only when no file exists (env-only config). When a
    // file is absent or unreadable these return null and the page keeps its current state.
    // ----------------------------------------------------------

    public IReadOnlyList<RouteView>? GetRoutesFromDisk()
    {
        var diskRoutes = ConfigFileReader.ReadRoutes(_paths.ConfigDir);
        if (diskRoutes is null)
        {
            // File absent/corrupt: keep the current page state (the caller does nothing).
            return null;
        }

        // Empty list is a VALID saved state ("route table cleared") - map it normally.
        // Active state stays env-aware: key resolution uses the live key table.
        return MapRoutes(diskRoutes, _options.CurrentValue);
    }

    public SecurityOptionsView? GetSecurityOptionsFromDisk()
    {
        var live = _options.CurrentValue;
        var disk = ConfigFileReader.ReadSecurity(_paths.ConfigDir);
        if (disk is null)
        {
            // File absent/corrupt: keep the current page state (the fields already hold
            // what was just written).
            return null;
        }

        // Sections missing on disk fall back to the live values, exactly like the
        // live mapping (which is already null-tolerant for RateLimit).
        return MapSecurity(new ProxyOptions
        {
            Redaction = disk.Redaction ?? live.Redaction,
            Inspection = disk.Inspection ?? live.Inspection,
            RateLimit = disk.RateLimit ?? live.RateLimit,
        });
    }

    public KeysOverviewView? GetKeysOverviewFromDisk()
    {
        var live = _options.CurrentValue;
        var meta = _keyMeta.LoadAll();
        var localLabels = _keyMeta.LoadLocalLabels();

        // The server config file is the truth just written; the live snapshot is stale.
        // RouteKeys: the disk decides presence as a whole (a deleted ref must not
        // resurrect, a fresh secret marks "set"). Keys: disk first per field, LocalKeys
        // as a unit (the disk list wins even when empty).
        var disk = ConfigFileReader.ReadServerKeys(_paths.ConfigDir);
        if (disk is null)
        {
            // File absent/corrupt: keep the current page state (which already holds the
            // last loaded live/env-fed values).
            return null;
        }

        var routeKeys = ConfigFileReader.MergeRouteKeys(disk.Proxy?.RouteKeys, live.RouteKeys);
        var keys = ConfigFileReader.MergeKeys(disk.Proxy?.Keys, live.Keys);

        // Just-saved routes come from disk; live is still the pre-save snapshot.
        var usageRoutes = ConfigFileReader.ReadRoutes(_paths.ConfigDir)
                          ?? (IReadOnlyList<RouteOptions>)(live.Routes ?? new List<RouteOptions>());

        return MapKeysOverview(usageRoutes, routeKeys, keys, meta, localLabels);
    }
}