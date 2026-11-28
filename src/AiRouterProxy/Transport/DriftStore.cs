namespace AIRouterProxy;

/// <summary>One active drift episode (metadata only): what drifted where and how often it was alerted.</summary>
public sealed record DriftEpisode(
    string Route,
    string Ip,
    string Reason,
    string Severity,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastAlerted,
    int AlertCount);

/// <summary>
/// In-memory, bounded feed of attestation drift episodes (Phase 2). Mirrors the ring
/// semantics of <see cref="TransportStore"/> but adds an alert dedupe window: the same
/// episode (route + reason + IP) is re-alerted at most once per hour while it stays
/// active - the "simplest correct" rule so a persistent drift does not spam the Event
/// Log while a new/flapping one still surfaces promptly. A DISTINCT endpoint (different
/// ip) is a new episode and alerts immediately; a strictly higher severity on the same
/// episode also re-alerts (the situation escalated). In memory only; nothing survives
/// a restart.
/// </summary>
public sealed class DriftStore
{
    public const int MinCapacity = 10;
    public const int MaxCapacity = 200;
    public const int DefaultCapacity = 100;

    /// <summary>Re-alert suppression window for one (route, reason, ip) episode.</summary>
    public static readonly TimeSpan DedupeWindow = TimeSpan.FromHours(1);

    private readonly object _lock = new();
    private readonly Dictionary<string, DriftEpisode> _byKey = new(StringComparer.Ordinal);

    // Newest alert LAST (Recent reads it backwards), so trimming from index 0 drops the
    // least recently alerted episodes - the same trim direction as the transport ring.
    private readonly List<DriftEpisode> _recent = new();
    private int _capacity = DefaultCapacity;

    public int Capacity
    {
        get
        {
            lock (_lock)
            {
                return _capacity;
            }
        }
        set
        {
            lock (_lock)
            {
                _capacity = Math.Clamp(value, MinCapacity, MaxCapacity);
                TrimLocked();
            }
        }
    }

    /// <summary>
    /// Registers/refreshes the episode for (route, reason, ip). Returns true when an alert
    /// should be emitted NOW (first occurrence of the endpoint-specific episode, the
    /// previous alert for the same episode is older than <see cref="DedupeWindow"/>, or
    /// the episode's severity escalated to a strictly higher level); false when it is
    /// still inside the window (the episode stays active but no new Event Log line is
    /// written).
    /// </summary>
    public bool TryAlert(string route, string ip, string reason, string severity, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(route) || string.IsNullOrWhiteSpace(reason))
        {
            return false;
        }

        var key = KeyOf(route, reason, ip);

        lock (_lock)
        {
            if (_byKey.TryGetValue(key, out var existing))
            {
                if (now - existing.LastAlerted < DedupeWindow)
                {
                    // Same episode (route + reason + ip) inside the window: a strictly
                    // higher severity re-alerts immediately (the situation escalated) and
                    // bumps the record; otherwise keep the record fresh with no alert.
                    if (SeverityRank(severity) > SeverityRank(existing.Severity))
                    {
                        var escalated = existing with
                        {
                            Severity = severity,
                            LastAlerted = now,
                            AlertCount = existing.AlertCount + 1,
                        };
                        _byKey[key] = escalated;
                        TouchRecentLocked(escalated);
                        return true;
                    }

                    _byKey[key] = existing;
                    TouchRecentLocked(existing);
                    return false;
                }

                var bumped = existing with
                {
                    Ip = ip,
                    Severity = severity,
                    LastAlerted = now,
                    AlertCount = existing.AlertCount + 1,
                };
                _byKey[key] = bumped;
                TouchRecentLocked(bumped);
                return true;
            }

            var episode = new DriftEpisode(route, ip, reason, severity, now, now, 1);
            _byKey[key] = episode;
            _recent.Add(episode);
            TrimLocked();
            return true;
        }
    }

    /// <summary>Newest-alerted-first snapshot, at most <paramref name="limit"/> episodes.</summary>
    public IReadOnlyList<DriftEpisode> Recent(int limit)
    {
        var take = Math.Max(0, limit);

        lock (_lock)
        {
            var result = new List<DriftEpisode>(Math.Min(take, _recent.Count));
            for (var i = _recent.Count - 1; i >= 0 && result.Count < take; i--)
            {
                result.Add(_recent[i]);
            }

            return result;
        }
    }

    /// <summary>Drops every episode and returns how many were removed.</summary>
    public int Clear()
    {
        lock (_lock)
        {
            var count = _byKey.Count;
            _byKey.Clear();
            _recent.Clear();
            return count;
        }
    }

    public int Count
    {
        get
        {
            lock (_lock)
            {
                return _recent.Count;
            }
        }
    }

    /// <summary>Key semantics: the episode identity includes the endpoint (ip).</summary>
    private static string KeyOf(string route, string reason, string ip)
        => route + "|" + reason + "|" + (string.IsNullOrEmpty(ip) ? string.Empty : ip);

    private static string KeyOf(DriftEpisode episode)
        => KeyOf(episode.Route, episode.Reason, episode.Ip);

    /// <summary>Severity ordering for the escalation rule: none &lt; low &lt; high.</summary>
    private static int SeverityRank(string? severity) => severity switch
    {
        DriftEvaluator.SeverityHigh => 2,
        DriftEvaluator.SeverityLow => 1,
        _ => 0, // "none" / unknown never outranks anything
    };

    private static bool SameEpisode(DriftEpisode a, DriftEpisode b)
        => string.Equals(a.Route, b.Route, StringComparison.Ordinal)
           && string.Equals(a.Reason, b.Reason, StringComparison.Ordinal)
           && string.Equals(a.Ip, b.Ip, StringComparison.Ordinal);

    private void TouchRecentLocked(DriftEpisode episode)
    {
        var index = _recent.FindIndex(e => SameEpisode(e, episode));
        if (index >= 0)
        {
            _recent.RemoveAt(index);
        }

        _recent.Add(episode); // newest last
    }

    private void TrimLocked()
    {
        while (_recent.Count > _capacity)
        {
            var oldest = _recent[0];
            _recent.RemoveAt(0);
            _byKey.Remove(KeyOf(oldest));
        }
    }
}
