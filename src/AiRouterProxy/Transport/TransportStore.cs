namespace AIRouterProxy;

/// <summary>
/// In-memory ring buffer of TLS endpoint observations (same shape and semantics as
/// <see cref="DetectionStore"/>): thread-safe, bounded, newest-first reads, in memory
/// only - nothing survives a restart. The persisted view lives in <see cref="BaselineStore"/>.
/// </summary>
public interface ITransportStore
{
    /// <summary>
    /// Appends one observation and trims the oldest so the buffer stays within
    /// <paramref name="capacity"/> (clamped 10..1000 here; callers clamp before).
    /// </summary>
    void Add(TransportObservation entry, int capacity);

    /// <summary>Newest-first snapshot, at most <paramref name="limit"/> entries.</summary>
    IReadOnlyList<TransportObservation> Recent(int limit);

    /// <summary>Drops every entry and returns how many were removed.</summary>
    int Clear();

    int Count { get; }
}

/// <summary>
/// Thread-safe ring buffer of <see cref="TransportObservation"/> (in memory only -
/// the durable baseline lives in <see cref="BaselineStore"/>).
/// </summary>
public sealed class TransportStore : ITransportStore
{
    public const int MinCapacity = 10;
    public const int MaxCapacity = 1000;
    public const int DefaultCapacity = 200;

    private readonly object _lock = new();
    private readonly List<TransportObservation> _entries = new();

    public void Add(TransportObservation entry, int capacity)
    {
        if (entry is null)
        {
            return;
        }

        var effective = Math.Clamp(capacity, MinCapacity, MaxCapacity);

        lock (_lock)
        {
            _entries.Add(entry);
            if (_entries.Count > effective)
            {
                // Trim the oldest entries; the newest always stay.
                _entries.RemoveRange(0, _entries.Count - effective);
            }
        }
    }

    /// <summary>
    /// Appends entries and trims the oldest so the buffer stays within
    /// <paramref name="capacity"/>. Same contract as Add, for batch producers.
    /// </summary>
    public void AddRange(IReadOnlyList<TransportObservation> entries, int capacity)
    {
        if (entries is null || entries.Count == 0)
        {
            return;
        }

        var effective = Math.Clamp(capacity, MinCapacity, MaxCapacity);

        lock (_lock)
        {
            _entries.AddRange(entries);
            if (_entries.Count > effective)
            {
                _entries.RemoveRange(0, _entries.Count - effective);
            }
        }
    }

    public IReadOnlyList<TransportObservation> Recent(int limit)
    {
        var take = Math.Max(0, limit);

        lock (_lock)
        {
            var result = new List<TransportObservation>(Math.Min(take, _entries.Count));
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
