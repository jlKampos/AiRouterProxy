namespace AIRouterProxy;

/// <summary>
/// One forensic detection record: WHERE a detection fired (structural JSON path), WHICH layer
/// produced it, the category and the value length. It never carries the value itself - the
/// fingerprint is a process-local, non-reversible HMAC (see <see cref="DetectionFingerprint"/>).
/// </summary>
public sealed record DetectionEntry(
    DateTimeOffset Timestamp,
    string RequestId,
    string Client,
    string Route,
    string Method,
    string RequestPath,
    string? Model,
    string JsonPath,
    string Layer,
    string Kind,
    int Length,
    string Fingerprint,
    string? Name = null,
    string? Sep = null,
    string? Quote = null);

/// <summary>In-memory store of forensic detections (never persisted to disk).</summary>
public interface IDetectionStore
{
    /// <summary>
    /// Appends entries and trims the oldest ones so the buffer stays within
    /// <paramref name="capacity"/>. This is a low-level ring buffer: it clamps to 1..1000;
    /// the configuration range 10..1000 is enforced by the SecurityValidator and by the
    /// <c>Math.Clamp</c> in ProxyMiddleware before it gets here. The capacity is passed per
    /// call so a hot-reloaded setting applies without rebuilding the singleton.
    /// </summary>
    void AddRange(IReadOnlyList<DetectionEntry> entries, int capacity);

    /// <summary>Newest-first snapshot, at most <paramref name="limit"/> entries.</summary>
    IReadOnlyList<DetectionEntry> Recent(int limit);

    /// <summary>Drops every entry and returns how many were removed.</summary>
    int Clear();

    int Count { get; }
}

/// <summary>
/// Thread-safe ring buffer of <see cref="DetectionEntry"/> (in memory only - nothing is
/// written to disk, nothing survives a restart). Same shape as ActivityStore.
/// </summary>
public sealed class DetectionStore : IDetectionStore
{
    public const int MinCapacity = 1;
    public const int MaxCapacity = 1000;

    private readonly object _lock = new();
    private readonly List<DetectionEntry> _entries = new();

    public void AddRange(IReadOnlyList<DetectionEntry> entries, int capacity)
    {
        if (entries is null || entries.Count == 0)
        {
            return;
        }

        // Low-level store: this is a pure ring buffer and honors any positive capacity
        // (MinCapacity..MaxCapacity). The configuration range (10..1000) is enforced by
        // SecurityValidator and clamped by the caller (ProxyMiddleware) before it gets here.
        var effective = Math.Clamp(capacity, MinCapacity, MaxCapacity);

        lock (_lock)
        {
            for (var i = 0; i < entries.Count; i++)
            {
                _entries.Add(entries[i]);
            }

            if (_entries.Count > effective)
            {
                // Trim the oldest entries; the newest always stay.
                _entries.RemoveRange(0, _entries.Count - effective);
            }
        }
    }

    public IReadOnlyList<DetectionEntry> Recent(int limit)
    {
        // limit 0 (or negative) means "no entries" - the caller asked for none.
        var take = Math.Max(0, limit);

        lock (_lock)
        {
            var result = new List<DetectionEntry>(Math.Min(take, _entries.Count));
            for (var i = _entries.Count - 1; i >= 0 && result.Count < take; i--)
            {
                result.Add(_entries[i]);
            }

            return result;
        }
    }

    public int Clear()
    {
        lock (_lock)
        {
            var count = _entries.Count;
            _entries.Clear();
            return count;
        }
    }

    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _entries.Count;
            }
        }
    }
}
