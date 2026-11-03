using Microsoft.Extensions.Options;

namespace AIRouterProxy;

/// <summary>
/// Protects the /admin endpoints with the proxy's local key (Bearer, single or multi-key)
/// and the same per-client rate limiting used by the proxy path.
/// </summary>
public sealed class AdminAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IOptionsMonitor<ProxyOptions> _options;
    private readonly RateLimiter _rateLimiter;

    public AdminAuthMiddleware(RequestDelegate next, IOptionsMonitor<ProxyOptions> options, RateLimiter rateLimiter)
    {
        _next = next;
        _options = options;
        _rateLimiter = rateLimiter;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var options = _options.CurrentValue;
        var clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        if (options.RateLimit is { Enabled: true }
            && _rateLimiter.Check(clientIp) != RateLimiter.Verdict.Allow)
        {
            context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            context.Response.Headers.RetryAfter =
                Math.Max(1, _rateLimiter.RetryAfterSeconds(clientIp)).ToString();
            context.Response.ContentType = "application/json; charset=utf-8";
            await context.Response.WriteAsJsonAsync(new
            {
                error = new { message = "Too many requests.", type = "rate_limit_error" },
            });
            return;
        }

        var presented = SecurityHelpers.ExtractBearerToken(context.Request.Headers.Authorization.ToString());
        if (!AuthenticationPolicy.IsValidLocalKey(presented, options.Keys))
        {
            if (options.RateLimit is { Enabled: true })
            {
                _rateLimiter.RecordFailure(clientIp);
            }

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
