namespace AiRouterProxy.Dashboard.Models;

/// <summary>
/// Fake data so the UI renders in standalone dev (running the dashboard project alone).
/// NEVER registered by the host: the host registers its own facade after AddDashboard(),
/// which wins in DI. No real data, no secrets.
/// </summary>
public sealed class PlaceholderDashboardFacade : IDashboardFacade
{
    private static readonly string[] Models = { "openrouter/auto", "openai/gpt-4o", "anthropic/claude-sonnet-4", "openrouter/llama-4" };
    private static readonly string[] Paths = { "/v1/chat/completions", "/v1/embeddings", "/v1/completions" };
    private static readonly string[] Routes = { "default", "openrouter", "anthropic" };
    private static readonly string[] Clients = { "opencode", "claude-code", "cursor", "studio.code" };

    public DashboardStatus GetStatus() => new("ok", "dev-standalone", DateTimeOffset.UtcNow, 0, 24,
        RoutingEnabled: true, RouteCount: 3, ConfiguredRouteKeys: 3, RateLimitEnabled: true,
        RedactionEnabled: true, InspectionEnabled: true);

    public IReadOnlyList<RouteView> GetRoutes() => new[]
    {
        new RouteView("default", "", "https://api.airrouter.ch", "-", true, new[] { "*" }, 300000, 20 * 1024 * 1024),
        new RouteView("openrouter", "/openrouter", "https://openrouter.ai/api", "openrouter", true, new[] { "*" }, 300000, 20 * 1024 * 1024),
        new RouteView("anthropic", "/anthropic", "https://api.anthropic.com", "anthropic", false, new[] { "/v1/*" }, 180000, 10 * 1024 * 1024),
    };

    public RouteDefaultsView GetRouteDefaults() => new(300000, 20 * 1024 * 1024);

    public IReadOnlyList<KeyRefView> GetRouteKeyRefs() => new[]
    {
        new KeyRefView("openrouter", true, 1, "openrouter"),
        new KeyRefView("anthropic", false, 1, "anthropic"),
    };

    public IReadOnlyList<KeyMetaView> GetKeyMeta() => new[]
    {
        new KeyMetaView("openrouter", "openrouter", "Upstream API key"),
        new KeyMetaView("anthropic", "anthropic", "Upstream API key (not set)"),
    };

    public IReadOnlyList<ActivityView> GetActivity(int hours, int limit)
    {
        var rows = new List<ActivityView>();
        var rnd = new Random(42);
        var now = DateTimeOffset.UtcNow;
        for (var i = 0; i < Math.Min(limit, 12); i++)
        {
            rows.Add(new ActivityView(
                now.AddMinutes(-rnd.Next(1, Math.Max(2, hours * 60))),
                Clients[rnd.Next(Clients.Length)],
                "POST",
                Paths[rnd.Next(Paths.Length)],
                rnd.Next(5) == 0 ? 429 : 200,
                rnd.Next(400, 8000),
                Models[rnd.Next(Models.Length)],
                Routes[rnd.Next(Routes.Length)],
                rnd.Next(5) == 0,
                rnd.Next(4),
                "sh_" + Guid.NewGuid().ToString("N")[..10],
                "sh_" + Guid.NewGuid().ToString("N")[..10],
                Routes[rnd.Next(Routes.Length)],
                "dev/standalone"));
        }
        return rows;
    }

    public int LocalKeyCount() => 1;

    public SecurityOptionsView GetSecurityOptions() => new(
        Redaction: new RedactionSettingsView(true, "••••••", true, "", new DetectSettingsView(true, true, true, true, true, 3.0), new[] { "^ACME-[0-9]{3,5}-" }),
        Inspection: new InspectionSettingsView(true, "block", "block", new Dictionary<string, string> { ["application/json"] = "inspect" }),
        RateLimit: new RateLimitSettingsView(true, 120, 60, 10, 300, 300));

    public ConfigPathsView GetConfigPaths() => new(
        ConfigDir: @"C:\dev\airproxy\config",
        DataDir: @"C:\dev\airproxy\data",
        BackupDir: @"C:\dev\airproxy\data\backups",
        AuditLogPath: @"C:\dev\airproxy\data\audit.log",
        KeyMetaPath: @"C:\dev\airproxy\data\key-meta.json",
        Retention: 5);

    public KeysOverviewView GetKeysOverview() => new(
        KeyRefs: new[]
        {
            new KeyRefDetailView("openrouter", true, 1, "openrouter", "openrouter", "OpenRouter API"),
            new KeyRefDetailView("anthropic", false, 1, "anthropic", "anthropic", "Anthropic API (not set)"),
        },
        LocalKeys: new[] { new LocalKeyView("primary", "ABCDEF1234567890ABCDEF12", true) },
        HasGlobalKey: true,
        HasPrimaryLocalKey: true);

    // Standalone dev: no disk-backed source, so the post-save refresh falls back to the
    // same placeholder data the live views return (never null - always renders).
    public IReadOnlyList<RouteView>? GetRoutesFromDisk() => GetRoutes();
    public SecurityOptionsView? GetSecurityOptionsFromDisk() => GetSecurityOptions();
    public KeysOverviewView? GetKeysOverviewFromDisk() => GetKeysOverview();
}