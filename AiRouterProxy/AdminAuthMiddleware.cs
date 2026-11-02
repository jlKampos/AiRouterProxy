using Microsoft.Extensions.Options;

namespace AIRouterProxy;

/// <summary>
/// Protects the /admin endpoints with the proxy's same local key (Bearer).
/// </summary>
public sealed class AdminAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IOptionsMonitor<ProxyOptions> _options;

    public AdminAuthMiddleware(RequestDelegate next, IOptionsMonitor<ProxyOptions> options)
    {
        _next = next;
        _options = options;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var presented = SecurityHelpers.ExtractBearerToken(context.Request.Headers.Authorization.ToString());
        if (!SecurityHelpers.SecureEquals(presented, _options.CurrentValue.Keys.LocalKey))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.ContentType = "application/json; charset=utf-8";
            await context.Response.WriteAsJsonAsync(new
            {
                error = new { message = "Invalid or missing local key.", type = "authentication_error" },
            });
            return;
        }

        await _next(context);
    }
}
