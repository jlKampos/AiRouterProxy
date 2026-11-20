using AIRouterProxy;

namespace AiRouterProxy.AdminPersistence;

/// <summary>
/// Timestamped backups of the config JSONs before any write operation, so a bad write
/// (or a manual edit that breaks reload) can always be rolled back. Backups live in
/// "data/backups" next to the config folder and are retained per file name (oldest
/// pruned first), so the folder cannot grow unbounded.
/// </summary>
public class ConfigBackup
{
    /// <summary>Maximum number of .bak files kept per config file name.</summary>
    public const int MaxBackupsPerFile = 5;

    private readonly DashboardPaths _paths;

    public ConfigBackup(DashboardPaths paths) => _paths = paths;

    /// <summary>
    /// Copies every existing file in the config dir into the backup folder as
    /// "{name}.{yyyyMMddHHmmssfff}.bak". Files that do not exist are skipped. Returns
    /// the created backup paths. Retention is enforced here (oldest backups pruned).
    /// </summary>
    public IReadOnlyList<string> Backup(string configDir, params string[] fileNames)
    {
        var created = new List<string>();

        foreach (var fileName in fileNames)
        {
            var source = ConfigPaths.ResolveFile(fileName, configDir);
            if (!File.Exists(source))
            {
                continue;
            }

            Directory.CreateDirectory(_paths.BackupDir);
            var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMddHHmmssfff");
            var bakPath = Path.Combine(_paths.BackupDir, $"{fileName}.{stamp}.bak");
            File.Copy(source, bakPath, overwrite: true);
            created.Add(bakPath);

            Prune(fileName);
        }

        return created;
    }

    /// <summary>Newest backup for a config file name, or null when there is none.</summary>
    public string? LatestBackup(string configDir, string fileName)
    {
        var list = ListBackups(fileName);
        return list.Count == 0 ? null : list[^1];
    }

    /// <summary>
    /// Copies a backup over the live config file (atomic-ish via temp + replace).
    /// Virtual so the harness can record restore order / simulate a locked file.
    /// </summary>
    public virtual void Restore(string configDir, string fileName, string bakPath)
    {
        var target = ConfigPaths.ResolveFile(fileName, configDir);
        if (!File.Exists(bakPath))
        {
            throw new FileNotFoundException($"Backup file not found: {bakPath}", bakPath);
        }

        var targetDir = Path.GetDirectoryName(target);
        if (!string.IsNullOrEmpty(targetDir))
        {
            Directory.CreateDirectory(targetDir);
        }

        var tmp = target + ".restore.tmp";
        try
        {
            File.Copy(bakPath, tmp, overwrite: true);
            try
            {
                File.Replace(tmp, target, destinationBackupFileName: null);
            }
            catch (IOException)
            {
                File.Move(tmp, target, overwrite: true);
            }
        }
        catch
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch { /* ignore */ }
            throw;
        }
    }

    private List<string> ListBackups(string fileName)
    {
        if (!Directory.Exists(_paths.BackupDir))
        {
            return new List<string>();
        }

        var prefix = fileName + ".";
        return Directory.GetFiles(_paths.BackupDir, "*.bak")
            .Where(f => Path.GetFileName(f).StartsWith(prefix, StringComparison.Ordinal))
            .OrderBy(f => f, StringComparer.Ordinal) // timestamp suffix sorts lexicographically
            .ToList();
    }

    private void Prune(string fileName)
    {
        var list = ListBackups(fileName);
        while (list.Count > MaxBackupsPerFile)
        {
            try
            {
                File.Delete(list[0]);
            }
            catch
            {
                // If a file is locked, keep it and stop pruning (never delete newer ones).
                break;
            }

            list.RemoveAt(0);
        }
    }
}
