using System.Text.Json;
using System.Text.Json.Nodes;
using AiRouterProxy.Dashboard.Models;

namespace AiRouterProxy.AdminPersistence;

/// <summary>
/// Persists per-keyRef metadata (owner/purpose) and per-local-key labels (name of the
/// person/PC the extra key was issued to) in "data/key-meta.json". This file is
/// NOT a secret store: it only contains the metadata that makes the dashboard readable
/// (who owns each key reference and what it is for). Secret values live exclusively in
/// appsettings.Server.json / environment and never touch this store.
/// </summary>
public sealed class KeyMetaStore
{
    private const string RootProperty = "keyRefs";
    private const string LocalRootProperty = "localKeys";

    private readonly DashboardPaths _paths;

    public KeyMetaStore(DashboardPaths paths) => _paths = paths;

    public IReadOnlyDictionary<string, KeyMeta> LoadAll()
    {
        var node = AtomicJsonWriter.Load(_paths.KeyMetaPath);
        if (node is not JsonObject root || root[RootProperty] is not JsonObject refs)
        {
            return new Dictionary<string, KeyMeta>(StringComparer.Ordinal);
        }

        var result = new Dictionary<string, KeyMeta>(StringComparer.Ordinal);
        foreach (var (keyRef, value) in refs)
        {
            if (value is JsonObject entry)
            {
                result[keyRef] = new KeyMeta(
                    Owner: entry["owner"]?.GetValue<string>() ?? string.Empty,
                    Purpose: entry["purpose"]?.GetValue<string>() ?? string.Empty);
            }
        }

        return result;
    }

    public KeyMeta? Get(string keyRef)
        => LoadAll().TryGetValue(keyRef, out var meta) ? meta : null;

    public void Save(IDictionary<string, KeyMeta> all)
        => WriteBoth(all, AsDict(LoadLocalLabels()));

    public IReadOnlyDictionary<string, string> LoadLocalLabels()
    {
        var node = AtomicJsonWriter.Load(_paths.KeyMetaPath);
        if (node is not JsonObject root || root[LocalRootProperty] is not JsonObject labels)
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (hash, value) in labels)
        {
            if (value is JsonObject entry)
            {
                result[hash] = entry["label"]?.GetValue<string>() ?? string.Empty;
            }
        }

        return result;
    }

    public void SaveLocalLabels(IDictionary<string, string> labelsByHash)
        => WriteBoth(AsDict(LoadAll()), labelsByHash);

    public void RemoveLocalLabel(string hash)
    {
        var labels = LoadLocalLabels().ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase);
        if (labels.Remove(hash))
        {
            WriteBoth(AsDict(LoadAll()), labels);
        }
    }

    private static Dictionary<string, KeyMeta> AsDict(IReadOnlyDictionary<string, KeyMeta> src)
        => src is Dictionary<string, KeyMeta> d ? d : src.ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);

    private static Dictionary<string, string> AsDict(IReadOnlyDictionary<string, string> src)
        => src is Dictionary<string, string> d ? d : src.ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase);

    /// <summary>Writes both metadata sections (keyRefs + local-key labels) in one atomic save.</summary>
    private void WriteBoth(IDictionary<string, KeyMeta> refs, IDictionary<string, string> labels)
    {
        var root = new JsonObject
        {
            [RootProperty] = new JsonObject(),
            [LocalRootProperty] = new JsonObject(),
        };

        var refsNode = (JsonObject)root[RootProperty]!;
        foreach (var (keyRef, meta) in refs.OrderBy(kv => kv.Key, StringComparer.Ordinal))
        {
            refsNode[keyRef] = new JsonObject
            {
                ["owner"] = meta.Owner ?? string.Empty,
                ["purpose"] = meta.Purpose ?? string.Empty,
            };
        }

        var labelsNode = (JsonObject)root[LocalRootProperty]!;
        foreach (var (hash, label) in labels.OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase))
        {
            if (!string.IsNullOrWhiteSpace(label))
            {
                labelsNode[hash] = new JsonObject { ["label"] = label };
            }
        }

        AtomicJsonWriter.SaveAtomic(_paths.KeyMetaPath, root);
    }

    /// <summary>Shape check used after a write: {"keyRefs": { "X": {...} }}.</summary>
    public static bool LooksValid(JsonNode? node)
    {
        if (node is not JsonObject root || root[RootProperty] is not JsonObject refs)
        {
            return false;
        }

        foreach (var pair in refs)
        {
            if (pair.Value is not JsonObject)
            {
                return false;
            }
        }

        return true;
    }
}
