namespace AIRouterProxy;

/// <summary>
/// Provider-blocklist decision for one route+feed (Phase 3). Metadata only: tiers,
/// provider slugs to ignore and flags - never request content, never keys.
/// </summary>
public sealed record BlocklistDecision(
    /// <summary>"none" | "info" | "warn" | "block" - severity of the entry whose Hosts matched the route's upstream host.</summary>
    string HostTier,
    IReadOnlyList<string> ProviderSlugsToIgnore,
    bool RequireZdr,
    bool DenyDataCollection,
    IReadOnlyList<string> Reasons)
{
    public static readonly BlocklistDecision None = new("none", Array.Empty<string>(), false, false, Array.Empty<string>());

    /// <summary>True when anything should act on this decision (a tier or a provider flag).</summary>
    public bool IsActive => HostTier != "none" || ProviderSlugsToIgnore.Count > 0 || RequireZdr || DenyDataCollection;
}

/// <summary>
/// Two-tier provider blocklist resolution (Phase 3):
/// - <b>Host tier</b>: entries whose <c>hosts</c> list matches the route's upstream host
///   (exact or a leading "*.domain" wildcard) produce a severity. The strongest severity
///   wins (block &gt; warn &gt; info).
/// - <b>Provider tier</b>: entries with severity &gt;= warn contribute their provider slugs
///   to the ignore list; entries with provider slugs (or whose hosts match the aggregator
///   host) contribute the ZdrOnly / DataCollectionDeny flags. The provider tier only
///   applies when the route has an active <see cref="RouteBlocklistOptions"/> AND its
///   upstream host matches one of the configured aggregators.
/// Pure and stateless; the middleware decides what to DO with the verdict.
/// </summary>
public static class ProviderBlocklist
{
    /// <summary>Lowest severity whose ProviderSlugs feed the ignore list (configurable threshold point).</summary>
    public const string ProviderTierMinSeverity = "warn";

    private static readonly string[] SeverityOrder = { "info", "warn", "block" };

    /// <summary>
    /// Host of an upstream base URL ("https://openrouter.ai/api" -&gt; "openrouter.ai"),
    /// lowercased. Empty when the value is not a usable absolute URL.
    /// </summary>
    public static string HostOf(string? upstream)
    {
        if (string.IsNullOrWhiteSpace(upstream))
        {
            return string.Empty;
        }

        return Uri.TryCreate(upstream, UriKind.Absolute, out var uri) && !string.IsNullOrWhiteSpace(uri.Host)
            ? uri.Host.ToLowerInvariant()
            : string.Empty;
    }

    /// <summary>
    /// True when <paramref name="host"/> matches one of the <paramref name="patterns"/>:
    /// an exact match, or a "*.domain" pattern matches "domain" and any subdomain of it.
    /// Values that parse as full URLs are reduced to their host first.
    /// </summary>
    public static bool IsAggregatorHost(string? host, IReadOnlyList<string>? patterns)
    {
        if (string.IsNullOrWhiteSpace(host) || patterns is not { Count: > 0 })
        {
            return false;
        }

        foreach (var raw in patterns)
        {
            var pattern = NormalizeHostPattern(raw);
            if (pattern.Length == 0)
            {
                continue;
            }

            if (pattern.StartsWith("*.", StringComparison.Ordinal))
            {
                var suffix = pattern[2..];
                if (string.Equals(host, suffix, StringComparison.OrdinalIgnoreCase)
                    || host.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            else if (string.Equals(host, pattern, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Resolves the effective blocklist decision for one request's route. The route's
    /// <see cref="RouteTransportOptions.Blocklist"/> gates the provider tier; the host
    /// tier also only runs when that section is enabled (zero cost when the route has
    /// no active blocklist policy).
    /// </summary>
    public static BlocklistDecision DecideForRoute(RouteOptions? route, ProviderFeedOptions? feed)
        => DecideForRoute(route, feed, route?.Transport?.Blocklist);

    /// <summary>Overload with the blocklist section explicitly passed in (testability).</summary>
    public static BlocklistDecision DecideForRoute(
        RouteOptions? route,
        ProviderFeedOptions? feed,
        RouteBlocklistOptions? blocklist)
    {
        if (route is null || feed?.Entries is not { Count: > 0 })
        {
            return BlocklistDecision.None;
        }

        if (blocklist is not { Enabled: true })
        {
            return BlocklistDecision.None;
        }

        var now = DateTimeOffset.UtcNow;
        var host = HostOf(route.Upstream);

        var hostTier = "none";
        var hostReasons = new List<string>();
        foreach (var entry in feed.Entries)
        {
            if (IsExpired(entry, now) || entry.Hosts is null || entry.Hosts.Count == 0)
            {
                continue;
            }

            if (!HostsMatch(entry.Hosts, host))
            {
                continue;
            }

            if (Rank(entry.Severity) > Rank(hostTier))
            {
                hostTier = entry.Severity;
            }

            hostReasons.Add(ReasonFor(entry, "host"));
        }

        // Provider tier: only when the route is an aggregator (host matches the configured
        // aggregators). "Aggregators" values may be hosts or full URLs.
        var aggregators = blocklist.Aggregators ?? new List<string>();
        var isAggregator = IsAggregatorHost(host, aggregators);

        var ignore = new List<string>();
        var reasons = new List<string>(hostReasons);
        var requireZdr = false;
        var denyDataCollection = false;

        if (isAggregator)
        {
            foreach (var entry in feed.Entries)
            {
                if (IsExpired(entry, now))
                {
                    continue;
                }

                var hasSlugs = entry.ProviderSlugs is { Count: > 0 };
                var hostApplies = entry.Hosts is { Count: > 0 } && HostsMatch(entry.Hosts, host);

                // Slugs come from entries whose severity is at least the provider-tier floor.
                if (hasSlugs && Rank(entry.Severity) >= Rank(ProviderTierMinSeverity))
                {
                    foreach (var slug in entry.ProviderSlugs)
                    {
                        if (!string.IsNullOrWhiteSpace(slug) && !ignore.Contains(slug, StringComparer.Ordinal))
                        {
                            ignore.Add(slug);
                            reasons.Add(ReasonFor(entry, "slug"));
                        }
                    }
                }

                var applies = hasSlugs || hostApplies;
                if (applies)
                {
                    requireZdr |= entry.ZdrOnly;
                    denyDataCollection |= entry.DataCollectionDeny;
                }
            }
        }

        return new BlocklistDecision(
            hostTier,
            ignore,
            requireZdr,
            denyDataCollection,
            reasons.Count == 0 ? Array.Empty<string>() : reasons);
    }

    // ----------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------

    private static bool IsExpired(ProviderEntryOptions entry, DateTimeOffset now)
        => entry.Until is { } until && until <= now;

    private static bool HostsMatch(IReadOnlyList<string> hosts, string host)
    {
        foreach (var h in hosts)
        {
            var pattern = NormalizeHostPattern(h);
            if (pattern.Length == 0)
            {
                continue;
            }

            if (pattern.StartsWith("*.", StringComparison.Ordinal))
            {
                var suffix = pattern[2..];
                if (string.Equals(host, suffix, StringComparison.OrdinalIgnoreCase)
                    || host.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            else if (string.Equals(host, pattern, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Reduces a configured value to a host pattern ("https://openrouter.ai/api" -&gt; "openrouter.ai").</summary>
    private static string NormalizeHostPattern(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var text = value.Trim().ToLowerInvariant();
        if (Uri.TryCreate(text, UriKind.Absolute, out var uri) && !string.IsNullOrWhiteSpace(uri.Host))
        {
            return uri.Host;
        }

        return text.TrimEnd('/');
    }

    private static int Rank(string? severity)
        => severity is null ? -1 : Array.FindIndex(SeverityOrder, s => string.Equals(s, severity, StringComparison.OrdinalIgnoreCase));

    private static string ReasonFor(ProviderEntryOptions entry, string kind)
        => string.IsNullOrWhiteSpace(entry.Id)
            ? $"{kind}: {entry.Reason}"
            : $"{kind}:{entry.Id}: {entry.Reason}";
}
