using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AiRouterProxy.AdminPersistence;

namespace AIRouterProxy;

/// <summary>One per-route group inside the baseline file: host + up to 8 endpoint entries.</summary>
public sealed record BaselineRouteSnapshot(string Route, string Host, IReadOnlyList<EndpointIdentity> Entries);

/// <summary>
/// Durable, metadata-only baseline of observed upstream TLS endpoints, kept in
/// <c>data/endpoint-baseline.json</c> (written atomically via <see cref="AtomicJsonWriter"/>).
/// It NEVER stores request/response content and never stores keys - only the public
/// certificate fingerprints + negotiated TLS facts. The file is a helper: the proxy
/// works fully without it (absent = empty baseline, no error).
/// </summary>
public sealed class BaselineStore
{
    private const string FileName = "endpoint-baseline.json";
    private const int MaxEntriesPerRoute = 8;
    private const long MaxFileBytes = 64 * 1024;

    /// <summary>Simplified debounce: lastSeen-only refreshes rewrite at most once per this window.</summary>
    private static readonly TimeSpan LastSeenDebounce = TimeSpan.FromSeconds(30);

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
    };

    /// <summary>
    /// Write options matching <see cref="AtomicJsonWriter"/>'s save path (indented only),
    /// so <see cref="SerializedByteCount"/> measures the exact bytes that reach the disk.
    /// </summary>
    private static readonly JsonSerializerOptions SaveOptions = new() { WriteIndented = true };

    private readonly object _lock = new();
    private readonly string _path;
    private readonly Dictionary<string, BaselineGroup> _routes = new(StringComparer.Ordinal);
    private bool _loaded;
    private DateTimeOffset _updatedAt = DateTimeOffset.UtcNow;

    public BaselineStore(DashboardPaths paths)
    {
        _path = System.IO.Path.Combine(paths.DataDir, FileName);
    }

    public string Path => _path;

    public DateTimeOffset UpdatedAt
    {
        get
        {
            lock (_lock)
            {
                return _updatedAt;
            }
        }
    }

    // ----------------------------------------------------------
    // Persistence
    // ----------------------------------------------------------

    /// <summary>Loads the baseline file (absent/corrupt/invalid entries are tolerated - never throws).</summary>
    public void Load()
    {
        lock (_lock)
        {
            LoadLocked();
        }
    }

    private void LoadLocked()
    {
        if (_loaded)
        {
            return;
        }

        _loaded = true;
        try
        {
            var node = AtomicJsonWriter.Load(_path);
            if (node is not JsonObject root)
            {
                return;
            }

            var file = JsonSerializer.Deserialize<BaselineFileV1>(root, JsonOpts);
            if (file?.Endpoints is null)
            {
                return;
            }

            foreach (var group in file.Endpoints)
            {
                if (string.IsNullOrWhiteSpace(group.Route) || group.Entries is null)
                {
                    continue;
                }

                var entries = group.Entries
                    .Where(IsSane)
                    .OrderByDescending(e => e.FirstSeen)
                    .Take(MaxEntriesPerRoute)
                    .OrderBy(e => e.FirstSeen)
                    .ToList();
                if (entries.Count == 0)
                {
                    continue;
                }

                _routes[group.Route] = new BaselineGroup(
                    string.IsNullOrWhiteSpace(group.Host) ? (entries[^1].Host ?? string.Empty) : group.Host,
                    entries);
            }

            _updatedAt = file.UpdatedAt;
        }
        catch
        {
            // Tolerate any corruption on load: an empty baseline is a valid fallback.
            _routes.Clear();
        }
    }

    private static bool IsSane(EndpointIdentity e)
        => e is not null
           && !string.IsNullOrWhiteSpace(e.Ip)
           && !string.IsNullOrWhiteSpace(e.SpkiHash)
           && e.Port is > 0 and <= 65535
           && e.NotBefore <= e.NotAfter;

    // ----------------------------------------------------------
    // Recording (called by the connect callback on successful TLS auth)
    // ----------------------------------------------------------

    /// <summary>
    /// Records an observed endpoint into the baseline. Writes the file only when the
    /// observation is materially new (first-seen for route+ip+spki, TLS metadata drift)
    /// or when <paramref name="now"/> is at least <see cref="LastSeenDebounce"/> past the
    /// last write - the file is not rewritten on every request.
    /// Best effort: file IO errors are swallowed (they must never break a connection).
    /// </summary>
    public void Record(EndpointIdentity identity)
    {
        if (identity is null)
        {
            return;
        }

        try
        {
            lock (_lock)
            {
                LoadLocked();

                var routeName = string.IsNullOrWhiteSpace(identity.Route) ? string.Empty : identity.Route;
                if (!_routes.TryGetValue(routeName, out var group))
                {
                    group = new BaselineGroup(identity.Host ?? string.Empty, new List<EndpointIdentity>());
                    _routes[routeName] = group;
                }

                if (!string.IsNullOrWhiteSpace(identity.Host))
                {
                    group.Host = identity.Host;
                }

                var entries = group.Entries;
                var index = entries.FindIndex(e =>
                    string.Equals(e.Ip, identity.Ip, StringComparison.Ordinal)
                    && string.Equals(e.SpkiHash, identity.SpkiHash, StringComparison.Ordinal));

                var shouldWrite = true;
                if (index >= 0)
                {
                    var existing = entries[index];
                    shouldWrite = TryRefresh(existing, identity, entries, index);
                }
                else
                {
                    entries.Add(identity);
                    if (entries.Count > MaxEntriesPerRoute)
                    {
                        // Drop the oldest entry (by first seen) - keep the most recent 8.
                        var oldest = entries
                            .Select((e, i) => (e, i))
                            .OrderBy(t => t.e.FirstSeen)
                            .First().i;
                        entries.RemoveAt(oldest);
                    }
                }

                if (shouldWrite)
                {
                    _updatedAt = identity.LastSeen;
                    WriteLocked();
                }
            }
        }
        catch
        {
            // Recording is best-effort: a failed baseline write must never break TLS traffic.
        }
    }

    /// <summary>
    /// Refreshes an existing entry (lastSeen + any TLS metadata drift). Returns true when
    /// the file should be rewritten. Entries are immutable records; the list element is swapped.
    /// </summary>
    private static bool TryRefresh(EndpointIdentity existing, EndpointIdentity fresh, List<EndpointIdentity> entries, int index)
    {
        var metaChanged = !string.Equals(existing.TlsVersion, fresh.TlsVersion, StringComparison.Ordinal)
                          || !string.Equals(existing.CipherSuite, fresh.CipherSuite, StringComparison.Ordinal)
                          || !string.Equals(existing.Alpn, fresh.Alpn, StringComparison.Ordinal)
                          || !string.Equals(existing.Issuer, fresh.Issuer, StringComparison.Ordinal);

        // Backfill firstSeen from the oldest observation of the same endpoint; lastSeen advances.
        var merged = existing with
        {
            LastSeen = fresh.LastSeen > existing.LastSeen ? fresh.LastSeen : existing.LastSeen,
            NotBefore = existing.NotBefore == default ? fresh.NotBefore : existing.NotBefore,
            NotAfter = existing.NotAfter == default ? fresh.NotAfter : existing.NotAfter,
            TlsVersion = metaChanged ? fresh.TlsVersion : existing.TlsVersion,
            CipherSuite = metaChanged ? fresh.CipherSuite : existing.CipherSuite,
            Alpn = metaChanged ? fresh.Alpn : existing.Alpn,
            Issuer = metaChanged ? fresh.Issuer : existing.Issuer,
            CertSha256 = string.IsNullOrEmpty(existing.CertSha256) ? fresh.CertSha256 : existing.CertSha256,
        };

        if (!ReferenceEquals(entries[index], merged))
        {
            entries[index] = merged;
        }

        // Refreshing a KNOWN endpoint: rewrite only on metadata drift or a debounced
        // lastSeen refresh (at most once per window). First-seen (new entry) is always written.
        return metaChanged || (merged.LastSeen - existing.LastSeen) >= LastSeenDebounce;
    }

    private void WriteLocked()
    {
        var file = new BaselineFileV1(
            Version: 1,
            UpdatedAt: _updatedAt,
            Endpoints: _routes
                .OrderBy(kv => kv.Key, StringComparer.Ordinal)
                .Select(kv => new BaselineRouteDto(
                    Route: kv.Key,
                    Host: kv.Value.Host,
                    Entries: kv.Value.Entries.OrderByDescending(e => e.LastSeen).ToList()))
                .ToList());

        // Hard size cap, enforced against the EXACT bytes that reach the disk: the file
        // is saved from a JsonNode (AtomicJsonWriter.SaveAtomic -> ToJsonString), and a
        // JsonNode escapes characters the POCO serializer does not (e.g. '+' in the
        // ISO-8601 offsets becomes "\u002B") - measuring with SerializeToUtf8Bytes used
        // to undercount, so the written file could still exceed MaxFileBytes. When the
        // node would exceed 64 KB, drop the oldest entries (across routes, oldest
        // lastSeen first) until it fits; groups emptied by the trim are removed before
        // saving. The in-memory ring stays untouched; the next load rebuilds from the
        // bounded file. Per-route in-memory entries are already capped at
        // MaxEntriesPerRoute, so this only kicks in with many routes / long-lived data.
        var node = JsonSerializer.SerializeToNode(file, JsonOpts);
        while (node is not null
               && SerializedByteCount(node) > MaxFileBytes
               && file.Endpoints.Any(g => g.Entries.Count > 0))
        {
            var oldest = file.Endpoints
                .SelectMany(g => g.Entries.Select((e, i) => (Group: g, Index: i, e)))
                .OrderBy(t => t.e.LastSeen)
                .First();
            oldest.Group.Entries.RemoveAt(oldest.Index);
            node = JsonSerializer.SerializeToNode(file, JsonOpts);
        }

        if (node is null)
        {
            return;
        }

        // Cosmetic: routes whose entries were all trimmed should not linger as empty groups.
        if (file.Endpoints.RemoveAll(g => g.Entries.Count == 0) > 0)
        {
            node = JsonSerializer.SerializeToNode(file, JsonOpts);
            if (node is null)
            {
                return;
            }
        }

        AtomicJsonWriter.SaveAtomic(_path, node);
    }

    /// <summary>
    /// Byte-for-byte serialized size of what <see cref="AtomicJsonWriter.SaveAtomic"/>
    /// writes for <paramref name="node"/> (ToJsonString + UTF-8, no BOM) - the cap metric
    /// and the on-disk file can never disagree.
    /// </summary>
    private static int SerializedByteCount(JsonNode node)
        => Encoding.UTF8.GetByteCount(node.ToJsonString(SaveOptions));

    // ----------------------------------------------------------
    // Reads (snapshots for the facade / admin API)
    // ----------------------------------------------------------

    public BaselineRouteSnapshot? GetRoute(string routeName)
    {
        lock (_lock)
        {
            LoadLocked();
            if (routeName is null || !_routes.TryGetValue(routeName, out var group))
            {
                return null;
            }

            return new BaselineRouteSnapshot(
                routeName,
                group.Host ?? string.Empty,
                group.Entries.OrderByDescending(e => e.LastSeen).ToArray());
        }
    }

    public IReadOnlyList<BaselineRouteSnapshot> GetRoutes()
    {
        lock (_lock)
        {
            LoadLocked();
            return _routes
                .OrderBy(kv => kv.Key, StringComparer.Ordinal)
                .Select(kv => new BaselineRouteSnapshot(kv.Key, kv.Value.Host ?? string.Empty, kv.Value.Entries.OrderByDescending(e => e.LastSeen).ToArray()))
                .ToList();
        }
    }

    /// <summary>Internal mutable group (route + host + entries list), guarded by <c>_lock</c>.</summary>
    private sealed class BaselineGroup
    {
        public string Host;
        public readonly List<EndpointIdentity> Entries;

        public BaselineGroup(string host, List<EndpointIdentity> entries)
        {
            Host = host;
            Entries = entries;
        }
    }

    // ----------------------------------------------------------
    // Serialization shape (the ONLY information this file carries)
    // ----------------------------------------------------------

    private sealed record BaselineFileV1(int Version, DateTimeOffset UpdatedAt, List<BaselineRouteDto> Endpoints);
    private sealed record BaselineRouteDto(string Route, string Host, List<EndpointIdentity> Entries);
}
