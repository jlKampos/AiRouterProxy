using System.Text;
using System.Text.Json;
using AiRouterProxy.Dashboard.Models;

namespace AiRouterProxy.AdminPersistence;

/// <summary>
/// JSONL audit trail of admin write operations: "data/audit.log", one JSON object per
/// line, UTF-8 without BOM. Records WHO (actor = short fingerprint of the admin key
/// that authenticated the call), WHAT (action + target file) and the OUTCOME. Secret
/// values are NEVER written here - this store has no access to them.
/// </summary>
public sealed class AuditLog
{
    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    private readonly DashboardPaths _paths;

    public AuditLog(DashboardPaths paths) => _paths = paths;

    /// <summary>Appends one audit entry. <paramref name="actorHash"/> is a key fingerprint, never a value.</summary>
    public void Append(string action, string target, string result, string actorHash)
    {
        var line = JsonSerializer.Serialize(new
        {
            ts = DateTimeOffset.UtcNow.ToString("O"),
            action,
            target,
            result,
            actor = actorHash ?? "-",
        });

        var directory = Path.GetDirectoryName(_paths.AuditLogPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.AppendAllText(_paths.AuditLogPath, line + Environment.NewLine, Utf8NoBom);
    }
}
