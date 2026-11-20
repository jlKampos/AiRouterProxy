using System.Security.Cryptography;
using System.Text;
using AIRouterProxy;
using Microsoft.Extensions.Options;

namespace AiRouterProxy.AdminUi;

/// <summary>
/// Issues and validates the dashboard UI session cookie. The token is an HMAC over
/// (expiry | fingerprint of the current primary local key), signed with an ephemeral
/// per-process key: rotating the local key or restarting the service invalidates sessions.
/// Nothing sensitive is ever written to the cookie.
/// </summary>
public sealed class UiSessionManager
{
    public const string CookieName = "airproxy_ui";
    private static readonly TimeSpan Lifetime = TimeSpan.FromHours(12);

    private readonly byte[] _signingKey = RandomNumberGenerator.GetBytes(32);
    private readonly IOptionsMonitor<ProxyOptions> _options;

    public UiSessionManager(IOptionsMonitor<ProxyOptions> options) => _options = options;

    public string CreateToken()
    {
        var expiry = DateTimeOffset.UtcNow.Add(Lifetime).ToUnixTimeSeconds();
        var payload = $"{expiry}|{Fingerprint(_options.CurrentValue.Keys.LocalKey)}";
        return $"{ToUrlSafe(Convert.ToBase64String(Encoding.UTF8.GetBytes(payload)))}.{Sign(payload)}";
    }

    public bool Validate(string? token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return false;
        }

        var dot = token.IndexOf('.');
        if (dot <= 0)
        {
            return false;
        }

        var payloadText = DecodeUrlSafe(token[..dot]);
        if (payloadText is null)
        {
            return false;
        }

        if (!SecurityHelpers.SecureEquals(token[(dot + 1)..], Sign(payloadText)))
        {
            return false;
        }

        var parts = payloadText.Split('|');
        if (parts.Length != 2
            || !long.TryParse(parts[0], out var expiry)
            || expiry < DateTimeOffset.UtcNow.ToUnixTimeSeconds())
        {
            return false;
        }

        var current = Fingerprint(_options.CurrentValue.Keys.LocalKey);
        return SecurityHelpers.SecureEquals(parts[1], current);
    }

    public static CookieOptions CookieTemplate => new()
    {
        HttpOnly = true,
        Secure = true,
        SameSite = SameSiteMode.Strict,
        Path = "/admin/ui",
        IsEssential = true,
    };

    private string Sign(string payload)
    {
        var mac = HMACSHA256.HashData(_signingKey, Encoding.UTF8.GetBytes(payload));
        return ToUrlSafe(Convert.ToBase64String(mac));
    }

    private static string Fingerprint(string? key)
    {
        if (key is null)
        {
            return "-";
        }

        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)))[..24];
    }

    private static string ToUrlSafe(string base64) => base64.TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string? DecodeUrlSafe(string s)
    {
        try
        {
            var base64 = s.Replace('-', '+').Replace('_', '/');
            switch (base64.Length % 4)
            {
                case 2:
                    base64 += "==";
                    break;
                case 3:
                    base64 += "=";
                    break;
            }
            return Encoding.UTF8.GetString(Convert.FromBase64String(base64));
        }
        catch (FormatException)
        {
            return null;
        }
    }
}

/// <summary>
/// Gates every /admin/ui request with a cookie session. Handles the login/logout form POSTs
/// (native HTML forms, no JS) using the same primary local key + rate limiter as /admin.
/// Runs before the proxy guard; the path base has already been stripped by UsePathBase.
/// </summary>
public sealed class UiSessionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly UiSessionManager _sessions;
    private readonly IOptionsMonitor<ProxyOptions> _options;
    private readonly RateLimiter _rateLimiter;

    private static readonly HashSet<string> PublicStaticExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".css", ".js", ".png", ".ico", ".svg", ".avif", ".jpg", ".jpeg", ".gif",
        ".woff", ".woff2", ".ttf", ".eot", ".map", ".webmanifest"
    };

    public UiSessionMiddleware(
        RequestDelegate next,
        UiSessionManager sessions,
        IOptionsMonitor<ProxyOptions> options,
        RateLimiter rateLimiter)
    {
        _next = next;
        _sessions = sessions;
        _options = options;
        _rateLimiter = rateLimiter;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? string.Empty;

        if (HttpMethods.IsPost(context.Request.Method) && path == "/login")
        {
            await HandleLoginAsync(context);
            return;
        }

        if (HttpMethods.IsPost(context.Request.Method) && path == "/logout")
        {
            context.Response.Cookies.Delete(UiSessionManager.CookieName, UiSessionManager.CookieTemplate);
            RedirectTo(context, "/admin/ui/login");
            return;
        }

        if (context.Request.Cookies.TryGetValue(UiSessionManager.CookieName, out var token)
            && _sessions.Validate(token))
        {
            await _next(context);
            return;
        }

        // Public static assets (css/js/images/icons) hold no data and must keep
        // working without a session, otherwise the login page renders unstyled.
        if (IsPublicStaticAsset(path))
        {
            await _next(context);
            return;
        }

        // The login page itself must render without a session.
        if (path.StartsWith('/') && path.StartsWith("/login", StringComparison.Ordinal))
        {
            await _next(context);
            return;
        }

        if (HttpMethods.IsGet(context.Request.Method) || HttpMethods.IsHead(context.Request.Method))
        {
            RedirectTo(context, "/admin/ui/login");
            return;
        }

        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
    }

    private async Task HandleLoginAsync(HttpContext context)
    {
        var clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var verdict = _rateLimiter.Check(clientIp);

        var presented = string.Empty;
        if (context.Request.HasFormContentType)
        {
            var form = await context.Request.ReadFormAsync(context.RequestAborted);
            presented = form["key"].ToString() ?? string.Empty;
        }

        if (verdict == RateLimiter.Verdict.Allow
            && !string.IsNullOrEmpty(presented)
            && AuthenticationPolicy.IsValidAdminKey(presented, _options.CurrentValue.Keys))
        {
            context.Response.Cookies.Append(
                UiSessionManager.CookieName,
                _sessions.CreateToken(),
                UiSessionManager.CookieTemplate);
            RedirectTo(context, "/admin/ui/");
            return;
        }

        if (verdict == RateLimiter.Verdict.Allow && !string.IsNullOrEmpty(presented))
        {
            _rateLimiter.RecordFailure(clientIp);
        }

        var reason = verdict == RateLimiter.Verdict.Allow ? "1" : "lockout";
        RedirectTo(context, $"/admin/ui/login?error={reason}");
    }

    private static bool IsPublicStaticAsset(string path)
    {
        if (path.StartsWith("/_framework/", StringComparison.Ordinal)
            || path.StartsWith("/_content/", StringComparison.Ordinal))
        {
            return true;
        }

        var ext = Path.GetExtension(path);
        return ext.Length > 0 && PublicStaticExtensions.Contains(ext);
    }

    private static void RedirectTo(HttpContext context, string location)
    {
        context.Response.StatusCode = StatusCodes.Status302Found;
        context.Response.Headers.Location = location;
    }
}