namespace AIRouterProxy;

/// <summary>
/// Minimal seam over the Windows Event Log so the admin service can be exercised in
/// tests without touching the machine's real log. The production implementation is a
/// thin wrapper; tests inject a fake.
/// </summary>
public interface IEventLogStore
{
    bool Exists(string logName);
    int Count(string logName);
    void Clear(string logName);
}

/// <summary>Production implementation: the real Windows Event Log.</summary>
public sealed class WindowsEventLogStore : IEventLogStore
{
    public bool Exists(string logName) => System.Diagnostics.EventLog.Exists(logName);

    public int Count(string logName)
    {
        using var log = new System.Diagnostics.EventLog(logName);
        return log.Entries.Count;
    }

    public void Clear(string logName)
    {
        using var log = new System.Diagnostics.EventLog(logName);
        log.Clear();
    }
}
