using AiRouterProxy.Dashboard;
using AiRouterProxy.Dashboard.Components;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

// Dev-only host. In production the AiRouterProxy service calls AddDashboard()/MapDashboard()
// and serves this UI under /admin/ui in the same process (same port + cert).
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDashboard();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}
app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();
app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();
app.Run();