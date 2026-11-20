namespace AiRouterProxy.AdminPersistence;

using AIRouterProxy;

/// <summary>
/// Filesystem layout used by the admin write pipeline. Registered once in Program.cs as a
/// singleton: every persistence/service component resolves its paths from here, so the
/// deploy layout (baseDir\config + baseDir\data) and the dev layout (baseDir + baseDir\data)
/// are handled consistently.
/// </summary>
public sealed record DashboardPaths(string BaseDir, string ConfigDir, string DataDir)
{
    /// <summary>Directory where timestamped .bak copies of config files are kept.</summary>
    public string BackupDir => Path.Combine(DataDir, "backups");

    /// <summary>JSONL audit trail of admin write operations (never contains key values).</summary>
    public string AuditLogPath => Path.Combine(DataDir, "audit.log");

    /// <summary>Per-keyRef metadata file (owner/purpose, never the secret value).</summary>
    public string KeyMetaPath => Path.Combine(DataDir, "key-meta.json");

    /// <summary>
    /// The "data" folder lives NEXT TO the config folder:
    ///  - deploy: configDir = baseDir\config  -> data = baseDir\data
    ///  - dev:    configDir = baseDir         -> data = baseDir\data
    /// </summary>
    public static string ResolveDataDir(string configDir, string baseDir)
    {
        var configName = Path.GetFileName(configDir?.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) ?? string.Empty);
        var root = string.Equals(configName, ConfigPaths.ConfigFolderName, StringComparison.OrdinalIgnoreCase)
            ? Path.GetDirectoryName(configDir)
            : (string.IsNullOrEmpty(configDir) ? baseDir : configDir);
        var safe = string.IsNullOrEmpty(root) ? (string.IsNullOrEmpty(baseDir) ? "." : baseDir) : root;
        return Path.Combine(safe, "data");
    }
}
