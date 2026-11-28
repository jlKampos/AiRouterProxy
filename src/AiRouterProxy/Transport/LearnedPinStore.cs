using System.Text.Json;
using System.Text.Json.Nodes;
using AiRouterProxy.AdminPersistence;

namespace AIRouterProxy;

/// <summary>One learned pin (full base64url SPKI fingerprint) + when it was added.</summary>
public sealed record LearnedPinEntry(string Pin, DateTimeOffset AddedAt);

/// <summary>Per-route learned-pin snapshot used by the facade/API (metadata only).</summary>
public sealed record LearnedPinRouteSnapshot(string Route, IReadOnlyList<LearnedPinEntry> Pins);

/// <summary>
/// Durable, metadata-only store of operator-ACCEPTED pins: <c>data/pins.json</c> (written
/// atomically via <see cref="AtomicJsonWriter"/>). "Accept" pins the current endpoint's
/// SPKI so a legitimately-rotated certificate stops tripping drift. The effective pin set
/// for a route = union(config <c>transport.pins</c> + these learned pins), max 5, with the
/// config pins first (explicit operator pins win). The file holds public certificate
/// fingerprints only - never request content, never keys. Absent/corrupt = empty, no error.
/// </summary>
public sealed class LearnedPinStore
{
    public const int MaxPinsPerRoute = 5;
    private const string FileName = "pins.json";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
    };

    private readonly object _lock = new();
    private readonly string _path;
    private readonly Dictionary<string, List<LearnedPinEntry>> _routes = new(StringComparer.Ordinal);
    private bool _loaded;
    private DateTimeOffset _updatedAt = DateTimeOffset.UtcNow;

    public LearnedPinStore(DashboardPaths paths)
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

            var file = JsonSerializer.Deserialize<PinsFileV1>(root, JsonOpts);
            if (file?.Routes is null)
            {
                return;
            }

            foreach (var (route, entries) in file.Routes)
            {
                if (string.IsNullOrWhiteSpace(route) || entries is null || entries.Count == 0)
                {
                    continue;
                }

                var sane = entries
                    .Where(e => e is not null && !string.IsNullOrWhiteSpace(e.Pin))
                    .OrderByDescending(e => e.AddedAt)
                    .Take(MaxPinsPerRoute)
                    .OrderBy(e => e.AddedAt)
                    .ToList();
                if (sane.Count == 0)
                {
                    continue;
                }

                _routes[route] = sane;
            }

            _updatedAt = file.UpdatedAt;
        }
        catch
        {
            // Tolerate any corruption on load: empty pins are a valid fallback.
            _routes.Clear();
        }
    }

    /// <summary>
    /// Adds a pin to a route (the value must already be canonical base64url - callers
    /// normalize via <see cref="TransportHashes.NormalizePin"/>). Max 5 per route: the
    /// oldest (by AddedAt) is dropped. Returns true when the file was rewritten.
    /// </summary>
    public bool AddPin(string route, string pin, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(route) || string.IsNullOrWhiteSpace(pin))
        {
            return false;
        }

        lock (_lock)
        {
            LoadLocked();

            if (!_routes.TryGetValue(route, out var entries))
            {
                entries = new List<LearnedPinEntry>();
                _routes[route] = entries;
            }

            if (entries.Any(e => string.Equals(e.Pin, pin, StringComparison.Ordinal)))
            {
                return false;
            }

            entries.Add(new LearnedPinEntry(pin, now));
            if (entries.Count > MaxPinsPerRoute)
            {
                var oldest = entries
                    .Select((e, i) => (e, i))
                    .OrderBy(t => t.e.AddedAt)
                    .First().i;
                entries.RemoveAt(oldest);
            }

            _updatedAt = now;
            WriteLocked();
            return true;
        }
    }

    public int RemoveRoute(string route)
    {
        lock (_lock)
        {
            LoadLocked();
            if (route is null || !_routes.Remove(route, out _))
            {
                return 0;
            }

            _updatedAt = DateTimeOffset.UtcNow;
            WriteLocked();
            return 1;
        }
    }

    public int ClearAll()
    {
        lock (_lock)
        {
            LoadLocked();
            var count = _routes.Values.Sum(list => list.Count);
            if (count == 0)
            {
                return 0;
            }

            _routes.Clear();
            _updatedAt = DateTimeOffset.UtcNow;
            WriteLocked();
            return count;
        }
    }

    private void WriteLocked()
    {
        var file = new PinsFileV1(
            Version: 1,
            UpdatedAt: _updatedAt,
            Routes: _routes
                .OrderBy(kv => kv.Key, StringComparer.Ordinal)
                .ToDictionary(kv => kv.Key, kv => kv.Value.OrderByDescending(e => e.AddedAt).ToList(), StringComparer.Ordinal));

        var node = JsonSerializer.SerializeToNode(file, JsonOpts);
        if (node is null)
        {
            return;
        }

        AtomicJsonWriter.SaveAtomic(_path, node);
    }

    // ----------------------------------------------------------
    // Reads
    // ----------------------------------------------------------

    /// <summary>The learned pins of one route (canonical base64url), oldest first.</summary>
    public IReadOnlyList<string> GetForRoute(string routeName)
    {
        lock (_lock)
        {
            LoadLocked();
            if (routeName is null || !_routes.TryGetValue(routeName, out var entries))
            {
                return Array.Empty<string>();
            }

            return entries.OrderBy(e => e.AddedAt).Select(e => e.Pin).ToArray();
        }
    }

    public LearnedPinRouteSnapshot? GetRoute(string routeName)
    {
        lock (_lock)
        {
            LoadLocked();
            if (routeName is null || !_routes.TryGetValue(routeName, out var entries))
            {
                return null;
            }

            return new LearnedPinRouteSnapshot(routeName, entries.OrderByDescending(e => e.AddedAt).ToArray());
        }
    }

    public IReadOnlyList<LearnedPinRouteSnapshot> GetRoutes()
    {
        lock (_lock)
        {
            LoadLocked();
            return _routes
                .OrderBy(kv => kv.Key, StringComparer.Ordinal)
                .Select(kv => new LearnedPinRouteSnapshot(kv.Key, kv.Value.OrderByDescending(e => e.AddedAt).ToArray()))
                .ToList();
        }
    }

    // ----------------------------------------------------------
    // Serialization shape
    // ----------------------------------------------------------

    private sealed record PinsFileV1(int Version, DateTimeOffset UpdatedAt, Dictionary<string, List<LearnedPinEntry>> Routes);
}
