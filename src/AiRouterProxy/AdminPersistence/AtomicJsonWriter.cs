using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AiRouterProxy.AdminPersistence;

/// <summary>
/// Reads and writes config JSON files atomically. Unknown properties are preserved
/// (the config JSONs are the source of truth; the dashboard only patches known
/// sections). Comments/trailing commas are tolerated on read but NOT preserved on
/// write - the output is normalized formatting (WriteIndented).
/// </summary>
public static class AtomicJsonWriter
{
    // UTF-8 without BOM: the parser/config loader rejects a BOM-prefixed file in
    // some environments, and the JSON files must stay plain UTF-8.
    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    private static readonly JsonDocumentOptions DocumentOptions = new()
    {
        CommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    private static readonly JsonSerializerOptions SerializeOptions = new() { WriteIndented = true };

    /// <summary>Parses a JSON file. Comments and trailing commas are accepted. Returns null if the file does not exist.</summary>
    public static JsonNode? Load(string fullPath)
    {
        if (!File.Exists(fullPath))
        {
            return null;
        }

        var text = File.ReadAllText(fullPath);
        return JsonNode.Parse(text, nodeOptions: null, DocumentOptions);
    }

    /// <summary>
    /// Writes the document to <paramref name="fullPath"/> atomically: serialize to a
    /// sibling "{name}.tmp" file, flush to disk, then swap it in with File.Replace
    /// (falling back to Move when Replace is not possible, e.g. cross between different
    /// volumes or when the destination does not exist). On any failure the tmp file is
    /// removed and the original file is left untouched.
    /// </summary>
    public static void SaveAtomic(string fullPath, JsonNode root)
    {
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var tmpPath = fullPath + ".tmp";

        try
        {
            File.WriteAllText(tmpPath, root.ToJsonString(SerializeOptions), Utf8NoBom);

            // Force the bytes to disk before the swap, so a crash right after the rename
            // can never leave a truncated target file (File.Replace/Move is atomic on NTFS).
            using (var stream = new FileStream(tmpPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                stream.Flush(flushToDisk: true);
            }

            try
            {
                File.Replace(tmpPath, fullPath, destinationBackupFileName: null);
            }
            catch (IOException)
            {
                // File.Replace fails when the destination does not exist or lives on a
                // different volume - plain move is the safe fallback.
                File.Move(tmpPath, fullPath, overwrite: true);
            }
        }
        catch
        {
            TryDelete(tmpPath);
            throw;
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Best effort only - the tmp file is inert and harmless.
        }
    }
}
