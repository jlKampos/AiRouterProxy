namespace AIRouterProxy;

/// <summary>
/// In-memory sliding-window rate limiter + brute-force lockout, keyed by client.
/// Thread-safe (all state under one lock), with an injectable clock so the test harness
/// can advance time. Pure: no DI / ASP.NET dependencies, so it is linked and unit-tested
/// in isolation.
/// </summary>
public sealed class RateLimiter
{
    public enum Verdict
    {
        /// <summary>Request allowed.</summary>
        Allow,

        /// <summary>Too many requests in the window -&gt; 429.</summary>
        TooManyRequests,

        /// <summary>Client locked out after too many failed authentication attempts -&gt; 429.</summary>
        LockedOut,
    }

    private readonly object _sync = new();
    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);
    private readonly Func<DateTimeOffset> _clock;

    private readonly int _maxRequests;
    private readonly long _requestWindowTicks;
    private readonly int _maxFailures;
    private readonly long _failureWindowTicks;
    private readonly long _lockoutTicks;

    public RateLimiter(RateLimitOptions options, Func<DateTimeOffset>? clock = null)
    {
        options ??= new RateLimitOptions();
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _maxRequests = Math.Max(1, options.MaxRequestsPerWindow);
        _requestWindowTicks = TimeSpan.FromSeconds(Math.Max(1, options.RequestWindowSeconds)).Ticks;
        _maxFailures = Math.Max(1, options.MaxFailuresPerWindow);
        _failureWindowTicks = TimeSpan.FromSeconds(Math.Max(1, options.FailureWindowSeconds)).Ticks;
        _lockoutTicks = TimeSpan.FromSeconds(Math.Max(0, options.LockoutSeconds)).Ticks;
    }

    private sealed class Entry
    {
        public readonly Queue<long> Requests = new();
        public readonly Queue<long> Failures = new();
        public long LockoutUntilTicks;
    }

    /// <summary>
    /// Counts one request for <paramref name="key"/> and returns the verdict.
    /// Requests older than the window are trimmed first, so the limit is a true sliding window.
    /// </summary>
    public Verdict Check(string key)
    {
        lock (_sync)
        {
            NormalizeKey(ref key);

            if (!_entries.TryGetValue(key, out var entry))
            {
                entry = new Entry();
                _entries[key] = entry;
            }

            var now = _clock().UtcTicks;

            if (entry.LockoutUntilTicks > now)
            {
                return Verdict.LockedOut;
            }

            Trim(entry.Requests, now, _requestWindowTicks);

            if (entry.Requests.Count >= _maxRequests)
            {
                return Verdict.TooManyRequests;
            }

            entry.Requests.Enqueue(now);
            return Verdict.Allow;
        }
    }

    /// <summary>
    /// Records one failed authentication for <paramref name="key"/>. When the failure count in
    /// the window reaches the limit, the client is locked out.
    /// </summary>
    public void RecordFailure(string key)
    {
        lock (_sync)
        {
            NormalizeKey(ref key);

            if (!_entries.TryGetValue(key, out var entry))
            {
                entry = new Entry();
                _entries[key] = entry;
            }

            var now = _clock().UtcTicks;
            Trim(entry.Failures, now, _failureWindowTicks);
            entry.Failures.Enqueue(now);

            if (entry.Failures.Count >= _maxFailures)
            {
                entry.LockoutUntilTicks = now + _lockoutTicks;
            }
        }
    }

    /// <summary>Seconds until the client can try again (for the Retry-After header).</summary>
    public int RetryAfterSeconds(string key)
    {
        lock (_sync)
        {
            NormalizeKey(ref key);

            if (!_entries.TryGetValue(key, out var entry))
            {
                return ToSecondsCeil(_requestWindowTicks);
            }

            var now = _clock().UtcTicks;

            if (entry.LockoutUntilTicks > now)
            {
                return ToSecondsCeil(entry.LockoutUntilTicks - now);
            }

            if (entry.Requests.Count > 0)
            {
                var windowEnd = entry.Requests.Peek() + _requestWindowTicks;
                if (windowEnd > now)
                {
                    return ToSecondsCeil(windowEnd - now);
                }
            }

            return ToSecondsCeil(_requestWindowTicks);
        }
    }

    /// <summary>Current request count for a key (tests / diagnostics).</summary>
    public int RequestCount(string key)
    {
        lock (_sync)
        {
            NormalizeKey(ref key);
            return _entries.TryGetValue(key, out var entry) ? entry.Requests.Count : 0;
        }
    }

    /// <summary>Current failed-authentication count for a key (tests / diagnostics).</summary>
    public int FailureCount(string key)
    {
        lock (_sync)
        {
            NormalizeKey(ref key);
            return _entries.TryGetValue(key, out var entry) ? entry.Failures.Count : 0;
        }
    }

    // ------------------------------------------------------------------

    private static void NormalizeKey(ref string key)
    {
        if (string.IsNullOrEmpty(key))
        {
            key = "unknown";
        }
    }

    private static void Trim(Queue<long> timestamps, long now, long windowTicks)
    {
        var cutoff = now - windowTicks;
        while (timestamps.Count > 0 && timestamps.Peek() <= cutoff)
        {
            timestamps.Dequeue();
        }
    }

    private static int ToSecondsCeil(long ticks)
        => Math.Max(1, (int)((ticks + TimeSpan.TicksPerSecond - 1) / TimeSpan.TicksPerSecond));
}
