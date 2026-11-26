using System.Text.Json.Nodes;
using AIRouterProxy;
using AiRouterProxy.Dashboard.Models;

namespace AiRouterProxy.AdminValidation;

/// <summary>
/// Conversions between the admin API draft (<see cref="ProviderEntryDraft"/>, Dashboard
/// assembly) and the host's <see cref="ProviderEntryOptions"/> / providers.json shape.
/// The feed is metadata-only (names/reasons/slugs) - never content, never keys.
/// </summary>
public static class ProviderEntryDraftJson
{
    /// <summary>Draft -&gt; options (the shape the proxy binds from providers.json).</summary>
    public static ProviderEntryOptions ToOptions(ProviderEntryDraft d)
    {
        ArgumentNullException.ThrowIfNull(d);
        return new ProviderEntryOptions
        {
            Id = d.Id ?? string.Empty,
            Name = d.Name ?? string.Empty,
            Hosts = new List<string>(d.SafeHosts),
            ProviderSlugs = new List<string>(d.SafeProviderSlugs),
            Reason = d.Reason ?? string.Empty,
            Severity = string.IsNullOrWhiteSpace(d.Severity) ? "info" : d.Severity,
            Until = d.Until,
            ZdrOnly = d.ZdrOnly,
            DataCollectionDeny = d.DataCollectionDeny,
        };
    }

    /// <summary>Options -&gt; draft (for API reads / round-trips).</summary>
    public static ProviderEntryDraft FromOptions(ProviderEntryOptions e)
        => new(
            Id: e.Id ?? string.Empty,
            Name: e.Name ?? string.Empty,
            Hosts: new List<string>(e.Hosts ?? new List<string>()),
            ProviderSlugs: new List<string>(e.ProviderSlugs ?? new List<string>()),
            Reason: e.Reason ?? string.Empty,
            Severity: string.IsNullOrWhiteSpace(e.Severity) ? "info" : e.Severity,
            Until: e.Until,
            ZdrOnly: e.ZdrOnly,
            DataCollectionDeny: e.DataCollectionDeny);

    /// <summary>Draft -&gt; camelCase JsonObject (the providers.json "Entries[]" item shape).</summary>
    public static JsonObject ToJson(ProviderEntryDraft d)
    {
        var node = new JsonObject
        {
            ["id"] = (d.Id ?? string.Empty),
            ["name"] = (d.Name ?? string.Empty),
            ["reason"] = (d.Reason ?? string.Empty),
            ["severity"] = string.IsNullOrWhiteSpace(d.Severity) ? "info" : d.Severity,
            ["zdrOnly"] = d.ZdrOnly,
            ["dataCollectionDeny"] = d.DataCollectionDeny,
        };

        if (d.Hosts is { Count: > 0 })
        {
            node["hosts"] = ToArray(d.Hosts);
        }

        if (d.ProviderSlugs is { Count: > 0 })
        {
            node["providerSlugs"] = ToArray(d.ProviderSlugs);
        }

        if (d.Until is { } until)
        {
            node["until"] = until;
        }

        return node;
    }

    private static JsonArray ToArray(IReadOnlyList<string> values)
    {
        var array = new JsonArray();
        foreach (var value in values)
        {
            array.Add(value);
        }

        return array;
    }
}
