namespace AIRouterProxy;

public sealed class ActivityEntry
{
    public DateTimeOffset Timestamp { get; init; }
    public string? Client { get; init; }
    public string? Method { get; init; }
    public string? Path { get; init; }
    public int Status { get; init; }
    public long DurationMs { get; init; }
    public string? Model { get; init; }
    public string? Route { get; init; }
    public bool Refused { get; init; }
    public int Redacted { get; init; }
    public string? PresentedHash { get; init; }
    public string? ExpectedHash { get; init; }
    public string? UA { get; init; }
}

/// <summary>
/// In-memory buffer with the latest requests (not verbose). Does not survive restarts.
/// </summary>
public sealed class ActivityStore
{
    private readonly object _lock = new();
    private readonly List<ActivityEntry> _entries = new();
    private readonly int _capacity;

    public ActivityStore(int capacity = 500)
    {
        _capacity = capacity;
    }

    public void Add(ActivityEntry entry)
    {
        lock (_lock)
        {
            _entries.Add(entry);
            if (_entries.Count > _capacity)
            {
                _entries.RemoveRange(0, _entries.Count - _capacity);
            }
        }
    }

    /// <summary>Returns the most recent entries within <paramref name="since"/>, up to <paramref name="limit"/>.</summary>
    public IReadOnlyList<ActivityEntry> Recent(DateTimeOffset since, int limit)
    {
        lock (_lock)
        {
            var result = new List<ActivityEntry>(Math.Min(limit, _entries.Count));
            for (var i = _entries.Count - 1; i >= 0 && result.Count < limit; i--)
            {
                var entry = _entries[i];
                if (entry.Timestamp >= since)
                {
                    result.Add(entry);
                }
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
