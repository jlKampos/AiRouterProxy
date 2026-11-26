using System.Text.Json;

namespace AIRouterProxy;

/// <summary>One endpoint reported by an aggregator's metadata block (names only).</summary>
public sealed record AttributedEndpoint(string Provider, bool Selected);

/// <summary>
/// Provider attribution extracted from a response (names only - never any other content).
/// <see cref="Provider"/> is the top-level "provider" field (Chat Completions);
/// <see cref="Endpoints"/> are the "openrouter_metadata.endpoints[]" entries.
/// </summary>
public sealed record AttributionResult(string? Provider, IReadOnlyList<AttributedEndpoint> Endpoints)
{
    /// <summary>
    /// The single provider name to record: the first SELECTED endpoint, else the
    /// top-level provider, else the first endpoint. Null when nothing was reported
    /// (e.g. a cache hit) - callers treat null as "no attribution", not as an error.
    /// </summary>
    public string? ServedBy
    {
        get
        {
            foreach (var e in Endpoints)
            {
                if (e.Selected)
                {
                    return e.Provider;
                }
            }

            if (Provider is { Length: > 0 })
            {
                return Provider;
            }

            return Endpoints.Count == 0 ? null : Endpoints[0].Provider;
        }
    }
}

/// <summary>
/// Extracts which provider actually served a response (Phase 3 attribution). Pure,
/// thread-safe, stateless; returns ONLY provider names (<= 120 chars after
/// normalization) - never request/response content and never keys.
/// Non-stream: <see cref="ExtractProviderFromJson(byte[])"/> (Chat Completions).
/// Streaming: <see cref="ExtractProviderFromSseFinal(byte[])"/>/events reads the stream
/// with the existing <see cref="SseParser"/> and never alters it - the caller keeps the
/// original bytes verbatim.
/// </summary>
public static class AttributionExtractor
{
    public const int MaxProviderName = 120;

    /// <summary>Trims and bounds a provider name (<= 120 chars); null when empty.</summary>
    public static string? NormalizeProviderName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return null;
        }

        var value = name.Trim();
        return value.Length > MaxProviderName ? value[..MaxProviderName] : value;
    }

    /// <summary>
    /// Non-stream extraction (application/json): the top-level "provider" string plus
    /// "openrouter_metadata.endpoints[]" (provider / provider_name + selected).
    /// </summary>
    public static AttributionResult ExtractProviderFromJson(byte[] responseBody)
    {
        if (responseBody is null || responseBody.Length == 0)
        {
            return Empty();
        }

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(responseBody);
        }
        catch (JsonException)
        {
            return Empty();
        }

        using (doc)
        {
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return Empty();
            }

            string? provider = null;
            if (doc.RootElement.TryGetProperty("provider", out var providerProp)
                && providerProp.ValueKind == JsonValueKind.String)
            {
                provider = providerProp.GetString();
            }

            var endpoints = new List<AttributedEndpoint>();
            if (doc.RootElement.TryGetProperty("openrouter_metadata", out var meta)
                && meta.ValueKind == JsonValueKind.Object
                && meta.TryGetProperty("endpoints", out var endpointsProp)
                && endpointsProp.ValueKind == JsonValueKind.Array)
            {
                foreach (var entry in endpointsProp.EnumerateArray())
                {
                    if (entry.ValueKind != JsonValueKind.Object)
                    {
                        continue;
                    }

                    var name = ReadEndpointName(entry);
                    var selected = entry.TryGetProperty("selected", out var sel)
                                   && sel.ValueKind == JsonValueKind.True;
                    if (name is not null)
                    {
                        endpoints.Add(new AttributedEndpoint(name, selected));
                    }
                }
            }

            return new AttributionResult(NormalizeProviderName(provider), endpoints);
        }
    }

    /// <summary>
    /// Streaming extraction from raw SSE bytes: feeds the whole payload to
    /// <see cref="SseParser"/> (read-only - the input bytes are never modified) and
    /// returns the provider name of the LAST event carrying "openrouter_metadata"
    /// before "[DONE]" (covers Messages terminal events too). Null when there is no
    /// metadata (e.g. a cache hit) - never an error.
    /// </summary>
    public static string? ExtractProviderFromSseFinal(byte[] data)
    {
        if (data is null || data.Length == 0)
        {
            return null;
        }

        var parser = new SseParser();
        var events = new List<SseEvent>(parser.Feed(data));
        var final = parser.EndOfStream();
        if (final is not null)
        {
            events.Add(final);
        }

        return ExtractProviderFromSseFinal(events);
    }

    /// <summary>
    /// Streaming extraction from a Stream. Only READS the stream (the original is never
    /// altered - pass a MemoryStream/byte[] when the caller owns the bytes and wants a
    /// byte-identical round-trip). Sync copy is fine for in-memory buffers; the
    /// middleware hot path uses <see cref="ExtractProviderFromSseFinal(byte[])"/>.
    /// </summary>
    public static string? ExtractProviderFromSseFinal(Stream source)
    {
        if (source is null)
        {
            return null;
        }

        using var buffer = new MemoryStream();
        source.CopyTo(buffer);
        return ExtractProviderFromSseFinal(buffer.ToArray());
    }

    /// <summary>Streaming extraction from already-parsed events (the terminal message_stop is included in the list).</summary>
    public static string? ExtractProviderFromSseFinal(IReadOnlyList<SseEvent> events)
    {
        if (events is null || events.Count == 0)
        {
            return null;
        }

        // Walk backwards: the LAST metadata-carrying event before [DONE] is the one the
        // aggregator populates with openrouter_metadata (usage chunk / final event).
        for (var i = events.Count - 1; i >= 0; i--)
        {
            var e = events[i];
            if (e.IsDone)
            {
                continue;
            }

            if (!e.Data.Contains("openrouter_metadata", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var name = ExtractOpenRouterMetadata(e.Data);
            if (name is not null)
            {
                return name;
            }
        }

        return null;
    }

    // ----------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------

    private static AttributionResult Empty() => new(null, Array.Empty<AttributedEndpoint>());

    private static string? ReadEndpointName(JsonElement entry)
    {
        if (entry.TryGetProperty("provider", out var p) && p.ValueKind == JsonValueKind.String)
        {
            return NormalizeProviderName(p.GetString());
        }

        // Real-world OpenRouter payloads use "provider_name".
        if (entry.TryGetProperty("provider_name", out var pn) && pn.ValueKind == JsonValueKind.String)
        {
            return NormalizeProviderName(pn.GetString());
        }

        return null;
    }

    private static string? ExtractOpenRouterMetadata(string dataJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(dataJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object
                || !doc.RootElement.TryGetProperty("openrouter_metadata", out var meta)
                || meta.ValueKind != JsonValueKind.Object
                || !meta.TryGetProperty("endpoints", out var endpointsProp)
                || endpointsProp.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            foreach (var entry in endpointsProp.EnumerateArray())
            {
                if (entry.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var selected = entry.TryGetProperty("selected", out var sel)
                               && sel.ValueKind == JsonValueKind.True;
                var name = ReadEndpointName(entry);
                if (selected && name is not null)
                {
                    return name; // first selected endpoint wins
                }
            }

            foreach (var entry in endpointsProp.EnumerateArray())
            {
                if (entry.ValueKind == JsonValueKind.Object && ReadEndpointName(entry) is { } fallback)
                {
                    return fallback; // no selection: first endpoint name
                }
            }

            return null;
        }
        catch (JsonException)
        {
            return null;
        }
    }
}
