using AiRouterProxy.Dashboard.Components;
using AiRouterProxy.Dashboard.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AiRouterProxy.Dashboard;

/// <summary>Runtime globals the dashboard needs before DI is available.</summary>
public static class DashboardGlobals
{
    /// <summary>Base path for assets/navigation: "/" in dev, "/admin/ui/" hosted in the proxy service.</summary>
    public static string BaseHref { get; set; } = "/";
}

/// <summary>
/// Registration entry point used by the HOST (same process, single exe).
/// The host registers its own IDashboardFacade after AddDashboard(), which wins in DI.
/// </summary>
public static class DashboardExtensions
{
    public const string BasePath = "/admin/ui";

    public static IServiceCollection AddDashboard(this IServiceCollection services, string basePath = "/")
    {
        DashboardGlobals.BaseHref = basePath.EndsWith('/') ? basePath : basePath + "/";
        services.AddRazorComponents()
            .AddInteractiveServerComponents();
        // Dev-only fallback: lets the standalone dashboard project render without a host.
        services.TryAddSingleton<IDashboardFacade, PlaceholderDashboardFacade>();
        services.TryAddSingleton<IDashboardAdminService, PlaceholderDashboardAdminService>();
        return services;
    }

    public static IEndpointRouteBuilder MapDashboard(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapRazorComponents<App>()
            .AddInteractiveServerRenderMode();
        endpoints.MapStaticAssets();
        return endpoints;
    }
}