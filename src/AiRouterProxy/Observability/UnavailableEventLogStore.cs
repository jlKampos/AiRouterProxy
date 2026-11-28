namespace AIRouterProxy;

/// <summary>
/// Linux/macOS (including the Docker image): there is no Windows Event Log. The store
/// reports "no log" so the admin service already answers "unavailable" for
/// logs.clear.eventlog (the audit trail records result: unavailable), and the
/// /admin/logs endpoint short-circuits on non-Windows before touching the API.
/// Container logs go to stdout ("docker logs").
/// </summary>
public sealed class UnavailableEventLogStore : IEventLogStore
{
    public bool Exists(string logName) => false;

    public int Count(string logName) => 0;

    public void Clear(string logName) { }
}
