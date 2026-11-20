using System.Text.Json.Nodes;
using AIRouterProxy;

namespace AiRouterProxy.AdminPersistence;

/// <summary>
/// After an atomic write, re-reads the file from disk and validates it. Because the
/// config files are hot-reloaded (reloadOnChange), a broken write would poison the
/// running proxy - so when the validation fails the previous version is restored from
/// the latest backup and the operation reports failure.
/// </summary>
public class ReloadConfirmer
{
    private readonly ConfigBackup _backups;

    public ReloadConfirmer(ConfigBackup backups) => _backups = backups;

    /// <summary>
    /// Reloads <paramref name="fileName"/> from the config dir and runs
    /// <paramref name="isValid"/> against the parsed document. Returns true when the
    /// file parses and validates. On parse failure or invalid content the latest backup
    /// is restored and false is returned (callers report "restored" to the UI).
    /// </summary>
    public virtual bool Confirm(string configDir, string fileName, Func<JsonNode, bool> isValid)
        => ConfirmDetailed(configDir, fileName, isValid).Valid;

    /// <summary>
    /// Same check as <see cref="Confirm"/> but also reports what happened at restore
    /// time, so callers (reload check) can distinguish the three outcomes: restored
    /// from backup, no backup was available, or a backup existed but restoring FAILED
    /// (e.g. the config file is locked by another process).
    /// </summary>
    public virtual ConfirmOutcome ConfirmDetailed(string configDir, string fileName, Func<JsonNode, bool> isValid)
    {
        var full = ConfigPaths.ResolveFile(fileName, configDir);
        JsonNode? node;
        try
        {
            node = AtomicJsonWriter.Load(full);
        }
        catch
        {
            node = null;
        }

        if (node is not null && isValid(node))
        {
            return new ConfirmOutcome(Valid: true, Restored: false, RestoreFailed: false);
        }

        var latest = _backups.LatestBackup(configDir, fileName);
        if (latest is not null)
        {
            try
            {
                _backups.Restore(configDir, fileName, latest);
                return new ConfirmOutcome(Valid: false, Restored: true, RestoreFailed: false);
            }
            catch
            {
                // A backup exists but could not be copied over the live file (e.g. it
                // is locked). The detection result stays false and callers must NOT
                // report "no backup was available" - the old version may still be the
                // one hot-reloading, which is exactly what the broken write replaced.
                return new ConfirmOutcome(Valid: false, Restored: false, RestoreFailed: true);
            }
        }

        return new ConfirmOutcome(Valid: false, Restored: false, RestoreFailed: false);
    }
}

/// <summary>
/// Result of a reload confirmation: whether the file is valid, whether a backup was
/// actually restored, and whether a backup existed but the restore itself failed
/// (locked file / permissions). RestoreFailed implies Restored == false.
/// </summary>
public sealed record ConfirmOutcome(bool Valid, bool Restored, bool RestoreFailed);
