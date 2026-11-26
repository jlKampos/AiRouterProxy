using System.Text.Json;
using System.Text.Json.Nodes;
using AIRouterProxy;
using RouteOptions = AIRouterProxy.RouteOptions;

namespace AiRouterProxy.AdminPersistence;

/// <summary>
/// Reads the editable config files (routes.json, redaction.json, appsettings.Server.json)
/// straight from disk, bypassing IOptionsMonitor. The monitor's FileSystemWatcher reload is
/// debounced: right after SaveAtomic it still serves the OLD snapshot, so the UI must refresh
/// from the files themselves. Tolerant reader: never throws, never prints anything. Key values
/// read here stay inside this process; callers only use presence/state derived from them.
/// Uses the same tolerant parse as AtomicJsonWriter.Load (comments/trailing commas accepted).
/// </summary>
public static class ConfigFileReader
{
    private static readonly JsonSerializerOptions Options = new() { PropertyNameCaseInsensitive = true };

    // ----------------------------------------------------------
    // Routes (routes.json -> Proxy.Routes)
    // ----------------------------------------------------------

    /// <summary>Routes from routes.json (Proxy.Routes). Null when the file is absent, unreadable or corrupt.</summary>
    public static IReadOnlyList<RouteOptions>? ReadRoutes(string configDir)
    {
        try
        {
            var node = AtomicJsonWriter.Load(Path.Combine(configDir, "routes.json"));
            return node is JsonObject root ? ReadRoutesFromNode(root["Proxy"]) : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Pure helper: deserializes proxyNode["Routes"]; null when absent or not an array.</summary>
    public static IReadOnlyList<RouteOptions>? ReadRoutesFromNode(JsonNode? proxyNode)
    {
        if (proxyNode?["Routes"] is not JsonArray routes)
        {
            return null;
        }

        try
        {
            return routes.Deserialize<List<RouteOptions>>(Options);
        }
        catch
        {
            return null;
        }
    }

    // ----------------------------------------------------------
    // Providers (providers.json -> Proxy.Providers.Entries)
    // ----------------------------------------------------------

    /// <summary>Provider blocklist feed from providers.json (Proxy.Providers.Entries). Null when the file is absent, unreadable or corrupt.</summary>
    public static IReadOnlyList<ProviderEntryOptions>? ReadProviders(string configDir)
    {
        try
        {
            var node = AtomicJsonWriter.Load(Path.Combine(configDir, "providers.json"));
            return node is JsonObject root ? ReadProvidersFromNode(root["Proxy"]) : null;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Pure helper: deserializes proxyNode["Providers"]["Entries"]; null when absent or not an array.</summary>
    public static IReadOnlyList<ProviderEntryOptions>? ReadProvidersFromNode(JsonNode? proxyNode)
    {
        if (proxyNode?["Providers"] is not JsonObject section || section["Entries"] is not JsonArray entries)
        {
            return null;
        }

        try
        {
            return entries.Deserialize<List<ProviderEntryOptions>>(Options);
        }
        catch
        {
            return null;
        }
    }

    // ----------------------------------------------------------
    // Security (redaction.json -> Proxy.Redaction/Inspection/RateLimit)
    // ----------------------------------------------------------

    /// <summary>Redaction section from the Proxy node; null when absent or not deserializable.</summary>
    public static RedactionOptions? ReadRedaction(JsonNode? proxyNode)
    {
        if (proxyNode?["Redaction"] is not JsonObject section)
        {
            return null;
        }

        try
        {
            return section.Deserialize<RedactionOptions>(Options);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Inspection section from the Proxy node; null when absent or not deserializable.</summary>
    public static InspectionOptions? ReadInspection(JsonNode? proxyNode)
    {
        if (proxyNode?["Inspection"] is not JsonObject section)
        {
            return null;
        }

        try
        {
            return section.Deserialize<InspectionOptions>(Options);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>RateLimit section from the Proxy node; null when absent or not deserializable.</summary>
    public static RateLimitOptions? ReadRateLimit(JsonNode? proxyNode)
    {
        if (proxyNode?["RateLimit"] is not JsonObject section)
        {
            return null;
        }

        try
        {
            return section.Deserialize<RateLimitOptions>(Options);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Whole redaction.json snapshot. Null when the file is absent, unreadable or corrupt.</summary>
    public static SecurityFileSnapshot? ReadSecurity(string configDir)
    {
        try
        {
            var node = AtomicJsonWriter.Load(Path.Combine(configDir, "redaction.json"));
            if (node is not JsonObject root)
            {
                return null;
            }

            var proxy = root["Proxy"];
            return new SecurityFileSnapshot(
                ReadRedaction(proxy),
                ReadInspection(proxy),
                ReadRateLimit(proxy));
        }
        catch
        {
            return null;
        }
    }

    // ----------------------------------------------------------
    // Server keys (appsettings.Server.json -> Proxy with RouteKeys + Keys)
    // ----------------------------------------------------------

    /// <summary>
    /// Proxy section of appsettings.Server.json. Null when the file is absent, unreadable or
    /// corrupt. The values it carries NEVER leave this process - only their presence matters.
    /// </summary>
    public static ServerKeysSnapshot? ReadServerKeys(string configDir)
    {
        try
        {
            var node = AtomicJsonWriter.Load(Path.Combine(configDir, "appsettings.Server.json"));
            if (node is not JsonObject root || root["Proxy"] is not JsonObject proxy)
            {
                return null;
            }

            var deserialized = proxy.Deserialize<ProxyOptions>(Options);
            return new ServerKeysSnapshot(deserialized);
        }
        catch
        {
            return null;
        }
    }

    // ----------------------------------------------------------
    // Merge helpers: disk (file) + live (IOptionsMonitor/env) with DISK-first semantics.
    // Right after a dashboard save the live monitor is still the STALE pre-save snapshot
    // (FileSystemWatcher reload is debounced), so the freshly written file is the truth:
    // a value just saved must win, a ref just deleted must not resurrect. Live fills in
    // only when there is no file at all (env-only config: AIROUTER_API_KEY and
    // LOCAL_PROXY_KEY documented; env-fed RouteKeys is undocumented but harmless).
    // ----------------------------------------------------------

    /// <summary>
    /// Merges RouteKeys maps. When the disk snapshot exists it decides presence as a whole
    /// (no gap-fill from live): a ref the user deleted cannot resurrect and a secret just
    /// written stays "set". When the disk snapshot is null (no appsettings.Server.json,
    /// env-only config) the live map is returned unchanged.
    /// </summary>
    public static Dictionary<string, string> MergeRouteKeys(
        IReadOnlyDictionary<string, string>? disk,
        IReadOnlyDictionary<string, string>? live)
    {
        if (disk is not null)
        {
            return new Dictionary<string, string>(disk, StringComparer.Ordinal);
        }

        return live is null
            ? new Dictionary<string, string>(StringComparer.Ordinal)
            : new Dictionary<string, string>(live, StringComparer.Ordinal);
    }

    /// <summary>
    /// Merges Keys sections field by field, disk first: a field present on disk wins (even
    /// when empty - "not set"), a field absent from disk (null in JSON) falls back to live.
    /// LocalKeys is a unit: the disk list wins as a whole, even empty - a local key just
    /// removed must not resurrect. With the disk snapshot null (env-only config:
    /// AIROUTER_API_KEY / LOCAL_PROXY_KEY) the whole live section is returned.
    /// </summary>
    public static KeyOptions MergeKeys(KeyOptions? disk, KeyOptions? live)
    {
        var liveSafe = live ?? new KeyOptions();
        if (disk is null)
        {
            return new KeyOptions
            {
                UpstreamKey = liveSafe.UpstreamKey,
                LocalKey = liveSafe.LocalKey,
                LocalKeys = liveSafe.LocalKeys ?? new List<string>(),
            };
        }

        return new KeyOptions
        {
            UpstreamKey = disk.UpstreamKey ?? liveSafe.UpstreamKey,
            LocalKey = disk.LocalKey ?? liveSafe.LocalKey,
            LocalKeys = disk.LocalKeys ?? liveSafe.LocalKeys ?? new List<string>(),
        };
    }
}

/// <summary>Parsed redaction.json snapshot; each section is null when absent on disk.</summary>
public sealed record SecurityFileSnapshot(
    RedactionOptions? Redaction,
    InspectionOptions? Inspection,
    RateLimitOptions? RateLimit);

/// <summary>Parsed Proxy section of appsettings.Server.json. Values never leave the process.</summary>
public sealed record ServerKeysSnapshot(ProxyOptions? Proxy);
