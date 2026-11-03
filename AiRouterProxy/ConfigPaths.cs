namespace AIRouterProxy;

/// <summary>
/// Decides where configuration files are read from, relative to the deployed executable.
/// Two layouts:
///  - dev/legacy: every config file lives next to the exe (AppContext.BaseDirectory);
///  - deploy: all editable config (appsettings.*.json, redaction.json, routes.json and the
///    TLS cert files) lives in a "config" subfolder next to the exe, so the deploy root
///    stays clean and config files are easy to find.
/// The layout is auto-detected: if the "config" folder exists next to the exe it wins;
/// otherwise the exe's own folder is used (backwards compatible with existing installs,
/// dev runs and the offline unit harness).
/// </summary>
public static class ConfigPaths
{
    public const string ConfigFolderName = "config";

    /// <summary>
    /// Returns the folder configuration is read from: "&lt;base&gt;/config" when that folder
    /// exists (deploy layout), otherwise <paramref name="baseDir"/> itself (dev/legacy layout).
    /// </summary>
    public static string ResolveConfigDir(string baseDir)
    {
        var configDir = Path.Combine(baseDir, ConfigFolderName);
        return Directory.Exists(configDir) ? configDir : (string.IsNullOrEmpty(baseDir) ? "." : baseDir);
    }

    /// <summary>
    /// Resolves a config-relative path (cert pem/pfx file names from appsettings.Server.json)
    /// against the config folder. Absolute paths are returned untouched; "../" escapes back
    /// up to the deploy root (one level above config), so "..\proxy-cert.pem" still works
    /// when certs are kept next to the exe.
    /// </summary>
    public static string ResolveFile(string? file, string configDir)
    {
        if (string.IsNullOrWhiteSpace(file))
        {
            return file ?? string.Empty;
        }

        return Path.IsPathRooted(file) ? file : Path.GetFullPath(file, configDir);
    }
}