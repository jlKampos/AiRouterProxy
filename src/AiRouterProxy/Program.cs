using System.Diagnostics;
using System.Reflection;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using AIRouterProxy;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi;

var baseDir = AppContext.BaseDirectory;
var configDir = ConfigPaths.ResolveConfigDir(baseDir);

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = configDir,
});

// Server-specific config (keys/certificates) - lives only on the target machine.
builder.Configuration.AddJsonFile("appsettings.Server.json", optional: true, reloadOnChange: true);

// Non-secret config (redaction and routes) - editable without restart (hot reload).
// No keys here: values live in appsettings.Server.json or env vars.
builder.Configuration.AddJsonFile("redaction.json", optional: true, reloadOnChange: true);
builder.Configuration.AddJsonFile("routes.json", optional: true, reloadOnChange: true);

builder.Services.Configure<ProxyOptions>(builder.Configuration.GetSection(ProxyOptions.SectionName));
builder.Services.AddHttpClient();
builder.Services.AddWindowsService(options => options.ServiceName = "AIRouterProxy");

builder.Services.AddSingleton<ActivityStore>();

// Swagger / explorable API
// Version comes from the assembly (same value /admin/health reports), so it never drifts from the csproj.
var serviceVersion = typeof(Program).Assembly.GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0] ?? "0.0.0";

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "AIRouterProxy",
        Version = serviceVersion,
        Description = "Local HTTPS proxy for AI model providers - enforces that secrets never leave " +
                      "the machine, with multi-upstream routing. /admin endpoints require the primary local key (Bearer).",
    });

    options.AddSecurityDefinition("LocalKey", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "local key",
        Description = "Local proxy key (see deploy/LOCAL_KEY.txt). Use as: Bearer <key>",
    });

    options.AddSecurityRequirement(document => new OpenApiSecurityRequirement
    {
        [new OpenApiSecuritySchemeReference("LocalKey", document)] = [],
    });
});

if (WindowsServiceHelpers.IsWindowsService())
{
    // Proxy's own log (clearable via /admin/logs without touching other apps' logs).
    builder.Logging.AddEventLog(options =>
    {
        options.LogName = "AIRouterProxy";
        options.SourceName = "AIRouterProxy";
        options.Filter = (_, level) => level >= LogLevel.Warning;
    });
}

var proxyOptions = LoadProxyOptions(builder.Configuration);

// Shared in-memory rate limiter (per client IP). Snapshot taken at startup: changing
// RateLimit options requires a service restart (redaction/routes keep hot reload).
builder.Services.AddSingleton(new RateLimiter(proxyOptions.RateLimit ?? new RateLimitOptions()));

if (string.IsNullOrWhiteSpace(proxyOptions.Keys.UpstreamKey)
    || string.IsNullOrWhiteSpace(proxyOptions.Keys.LocalKey))
{
    throw new InvalidOperationException(
        "[ERROR] AIROUTER_API_KEY and LOCAL_PROXY_KEY must be set (appsettings.Server.json or environment variable).");
}

ValidateRoutes(proxyOptions);

var certificate = LoadServerCertificate(proxyOptions, configDir);

builder.WebHost.ConfigureKestrel(kestrel =>
{
    // The body limit is controlled by the middleware (parity with proxy.js).
    kestrel.Limits.MaxRequestBodySize = null;

    kestrel.Listen(ParseHost(proxyOptions.Host), proxyOptions.Port,
        listen => listen.UseHttps(certificate));
});

var app = builder.Build();

EnsureEventLogExists();

// The proxy forwards everything except /admin and /swagger. The /v1/* paths stay the same.
app.UseWhen(
    ctx => !ctx.Request.Path.StartsWithSegments("/admin") && !ctx.Request.Path.StartsWithSegments("/swagger"),
    branch => branch.UseMiddleware<ProxyMiddleware>());

// Admin endpoints require the same local key (Bearer).
app.UseWhen(ctx => ctx.Request.Path.StartsWithSegments("/admin"),
    branch => branch.UseMiddleware<AdminAuthMiddleware>());

app.UseSwagger();
app.UseSwaggerUI();

// ----------------------------------------------------------
// Administration (authenticated by the middleware above)
// ----------------------------------------------------------

app.MapGet("/admin/endpoints", (IOptionsMonitor<ProxyOptions> opts) =>
{
    var o = opts.CurrentValue;

    var routes = o.Routes.Select(r =>
    {
        var key = RouteResolver.GetRouteKey(r, o.RouteKeys, o.Keys.UpstreamKey);
        return new
        {
            name = r.Name,
            prefix = r.Prefix ?? string.Empty,
            upstream = r.Upstream,
            keyRef = r.KeyRef,
            active = key is not null,
            allowedPaths = r.AllowedPaths.Count > 0 ? r.AllowedPaths : new List<string> { "*" },
            requestTimeoutMs = r.RequestTimeoutMs > 0 ? r.RequestTimeoutMs : o.RequestTimeoutMs,
        };
    }).ToArray();

    return Results.Ok(new
    {
        proxy = new
        {
            upstream = platformsUpstream(o),
            allowedPaths = platformsUpstreamAllowed(o),
            routingEnabled = o.Routes is { Count: > 0 },
            routes,
            methods = new[] { "GET", "POST" },
            streaming = "Responses are streamed as they come from the AI Router (includes SSE).",
            redaction = new
            {
                enabled = o.Redaction.Enabled,
                notifyInResponse = o.Redaction.NotifyInResponse,
                mask = new string('\u2022', 6),
                detect = new
                {
                    byFieldName = o.Redaction.Detect?.ByFieldName ?? true,
                    byFormats = o.Redaction.Detect?.ByFormats ?? true,
                    byKeyValueContext = o.Redaction.Detect?.ByKeyValueContext ?? true,
                    byLongStrings = o.Redaction.Detect?.ByLongStrings ?? true,
                    exemptBase64 = o.Redaction.Detect?.ExemptBase64 ?? true,
                },
                scope = "outgoing messages (JSON requests)",
            },
            rateLimit = new
            {
                enabled = o.RateLimit is { Enabled: true },
                maxRequestsPerWindow = o.RateLimit?.MaxRequestsPerWindow ?? 0,
                requestWindowSeconds = o.RateLimit?.RequestWindowSeconds ?? 0,
                maxFailuresPerWindow = o.RateLimit?.MaxFailuresPerWindow ?? 0,
                failureWindowSeconds = o.RateLimit?.FailureWindowSeconds ?? 0,
                lockoutSeconds = o.RateLimit?.LockoutSeconds ?? 0,
            },
        },
        admin = new[]
        {
            new { method = "GET", path = "/admin/endpoints", description = "Lists the possible endpoints." },
            new { method = "GET", path = "/admin/activity?hours=6&limit=50", description = "Recent activity log (not verbose)." },
            new { method = "GET", path = "/admin/refusals?hours=6&limit=50", description = "Authentication refusals." },
            new { method = "GET", path = "/admin/logs?hours=6&limit=50", description = "Proxy Event Log." },
            new { method = "DELETE", path = "/admin/activity", description = "Clears the activity log." },
            new { method = "DELETE", path = "/admin/logs", description = "Clears the proxy Event Log and the activity log." },
            new { method = "GET", path = "/admin/health", description = "Service status." },
        },
    });
});

// Compatibility: with no routes configured, the proxy uses the single upstream + global paths.
static string platformsUpstream(ProxyOptions o) =>
    o.Routes is { Count: > 0 }
        ? string.Join(", ", o.Routes.Select(r => r.Upstream))
        : o.Upstream;

static string[] platformsUpstreamAllowed(ProxyOptions o) =>
    o.Routes is { Count: > 0 }
        ? o.Routes.SelectMany(r => r.AllowedPaths).Distinct().ToArray()
        : o.AllowedPaths.ToArray();

app.MapGet("/admin/activity", (ActivityStore store, int hours = 6, int limit = 50) =>
{
    limit = Math.Clamp(limit, 1, 1000);
    hours = Math.Clamp(hours, 1, 24 * 30);
    var since = DateTimeOffset.UtcNow.AddHours(-hours);
    var entries = store.Recent(since, limit);
    return Results.Ok(new { count = entries.Count, entries });
});

app.MapGet("/admin/refusals", (ActivityStore store, int hours = 6, int limit = 50) =>
{
    limit = Math.Clamp(limit, 1, 1000);
    hours = Math.Clamp(hours, 1, 24 * 30);
    var since = DateTimeOffset.UtcNow.AddHours(-hours);
    var entries = store.Recent(since, 1000).Where(e => e.Refused).Take(limit).ToList();
    return Results.Ok(new { count = entries.Count, entries });
});

app.MapGet("/admin/logs", (int hours = 6, int limit = 50) =>
{
    limit = Math.Clamp(limit, 1, 200);
    hours = Math.Clamp(hours, 1, 24 * 30);

    var matches = new List<object>();
    try
    {
        if (EventLog.Exists("AIRouterProxy"))
        {
            using var log = new EventLog("AIRouterProxy");
            var since = DateTime.UtcNow.AddHours(-hours).ToLocalTime();

            foreach (EventLogEntry entry in log.Entries)
            {
                if (entry.TimeGenerated >= since)
                {
                    matches.Add(new
                    {
                        time = entry.TimeGenerated.ToString("yyyy-MM-dd HH:mm:ss"),
                        level = entry.EntryType.ToString(),
                        message = TruncateText(entry.Message, 300),
                    });
                }
            }

            matches = matches.Skip(Math.Max(0, matches.Count - limit)).ToList();
            matches.Reverse();
        }
    }
    catch (Exception ex)
    {
        return Results.Problem($"Could not read the AIRouterProxy Event Log: {ex.Message}", statusCode: 500);
    }

    return Results.Ok(new { count = matches.Count, entries = matches });
});

app.MapDelete("/admin/activity", (ActivityStore store) =>
{
    var cleared = store.Clear();
    return Results.Ok(new { cleared = true, activity = cleared });
});

app.MapDelete("/admin/logs", (ActivityStore store, ILoggerFactory loggerFactory) =>
{
    var clearedActivity = store.Clear();
    var logger = loggerFactory.CreateLogger("Admin");

    try
    {
        if (EventLog.Exists("AIRouterProxy"))
        {
            using var log = new EventLog("AIRouterProxy");
            log.Clear();
        }

        return Results.Ok(new { cleared = true, activity = clearedActivity, eventLog = true });
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Failed to clear the dedicated Event Log.");
        return Results.Problem($"Could not clear the Event Log: {ex.Message}", statusCode: 500);
    }
});

app.MapGet("/admin/health", (ActivityStore store) =>
{
    var processStart = Process.GetCurrentProcess().StartTime.ToUniversalTime();
    var uptime = DateTimeOffset.UtcNow - new DateTimeOffset(processStart);

    return Results.Ok(new
    {
        status = "ok",
        version = typeof(Program).Assembly.GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0] ?? "0.0.0",
        timestamp = DateTimeOffset.UtcNow,
        uptimeSec = (long)uptime.TotalSeconds,
        activity = store.Count,
    });
});

app.Run();

// ----------------------------------------------------------
// Helpers
// ----------------------------------------------------------

static void EnsureEventLogExists()
{
    const string source = "AIRouterProxy";
    const string log = "AIRouterProxy";

    try
    {
        if (EventLog.SourceExists(source))
        {
            // Old versions registered the source in the "Application" log. To use the dedicated
            // log (clearable via /admin/logs), re-register the source when it points elsewhere.
            var registeredLog = EventLog.LogNameFromSourceName(source, ".");
            if (!string.Equals(registeredLog, log, StringComparison.OrdinalIgnoreCase))
            {
                EventLog.DeleteEventSource(source);
            }
        }

        if (!EventLog.SourceExists(source))
        {
            EventLog.CreateEventSource(source, log);
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[WARNING] Could not prepare the dedicated Event Log: {ex.Message}");
    }
}

static string TruncateText(string? value, int max)
{
    if (string.IsNullOrEmpty(value))
    {
        return string.Empty;
    }

    return value.Length <= max ? value : value[..max];
}

static ProxyOptions LoadProxyOptions(IConfiguration configuration)
{
    var upstreamEnv = Environment.GetEnvironmentVariable("AIROUTER_API_KEY");
    var localEnv = Environment.GetEnvironmentVariable("LOCAL_PROXY_KEY");

    if (!string.IsNullOrWhiteSpace(upstreamEnv)
        && string.IsNullOrWhiteSpace(configuration["Proxy:Keys:UpstreamKey"]))
    {
        configuration["Proxy:Keys:UpstreamKey"] = upstreamEnv;
    }

    if (!string.IsNullOrWhiteSpace(localEnv)
        && string.IsNullOrWhiteSpace(configuration["Proxy:Keys:LocalKey"]))
    {
        configuration["Proxy:Keys:LocalKey"] = localEnv;
    }

    return configuration.GetSection(ProxyOptions.SectionName).Get<ProxyOptions>() ?? new ProxyOptions();
}

/// <summary>
/// Validates the routes at startup: unique prefixes (segment boundary), upstream with a
/// valid absolute URL, and warnings for routes without a key (keyRef with no value = inactive route).
/// </summary>
static void ValidateRoutes(ProxyOptions options)
{
    if (options.Routes is not { Count: > 0 })
    {
        return;
    }

    var prefixes = new Dictionary<string, string>(StringComparer.Ordinal);

    foreach (var route in options.Routes)
    {
        if (string.IsNullOrWhiteSpace(route.Name))
        {
            throw new InvalidOperationException("[ERROR] routes.json: there is a route without a 'name'.");
        }

        var prefix = route.Prefix ?? string.Empty;
        if (prefix.Length > 0 && !prefix.StartsWith('/'))
        {
            throw new InvalidOperationException($"[ERROR] Route '{route.Name}': prefix must start with '/' ('{prefix}').");
        }

        if (prefixes.TryGetValue(prefix, out var existing))
        {
            throw new InvalidOperationException(
                $"[ERROR] routes.json: prefix '{prefix}' duplicated on routes '{existing}' and '{route.Name}'.");
        }

        prefixes[prefix] = route.Name;

        if (string.IsNullOrWhiteSpace(route.Upstream)
            || !Uri.TryCreate(route.Upstream, UriKind.Absolute, out var upstream)
            || (upstream.Scheme != Uri.UriSchemeHttps && upstream.Scheme != Uri.UriSchemeHttp))
        {
            throw new InvalidOperationException(
                $"[ERROR] Route '{route.Name}': invalid upstream ('{route.Upstream}').");
        }

        if (!string.IsNullOrWhiteSpace(route.KeyRef)
            && (!options.RouteKeys.TryGetValue(route.KeyRef, out var keyValue)
                || string.IsNullOrWhiteSpace(keyValue)))
        {
            Console.WriteLine(
                $"[WARNING] Route '{route.Name}' has no key (keyRef '{route.KeyRef}') - inactive until the key is set.");
        }
    }
}

static X509Certificate2 LoadServerCertificate(ProxyOptions options, string configDir)
{
    var cert = options.Cert;

    if (!string.IsNullOrWhiteSpace(cert.PfxPath))
    {
        var pfx = ConfigPaths.ResolveFile(cert.PfxPath, configDir);

        if (!File.Exists(pfx))
        {
            throw new FileNotFoundException($"Missing PFX certificate: {pfx}", pfx);
        }

        return string.IsNullOrEmpty(cert.PfxPassword)
            ? X509CertificateLoader.LoadPkcs12FromFile(pfx, null)
            : X509CertificateLoader.LoadPkcs12FromFile(pfx, cert.PfxPassword.AsSpan());
    }

    var certPem = ConfigPaths.ResolveFile(cert.PemCert ?? "proxy-cert.pem", configDir);
    var keyPem = ConfigPaths.ResolveFile(cert.PemKey ?? "proxy-key.pem", configDir);

    if (!File.Exists(certPem))
    {
        throw new FileNotFoundException($"Missing TLS certificate: {certPem}", certPem);
    }

    if (!File.Exists(keyPem))
    {
        throw new FileNotFoundException($"Missing TLS key: {keyPem}", keyPem);
    }

    // On Windows, SChannel (Kestrel) refuses certificates whose private key was imported
    // with X509KeyStorageFlags.EphemeralKeySet (Schannel event 36869:
    // "The certificate does not have a private key information property attached")
    // and aborts the handshake. The PKCS12 round-trip with a persisted key solves it.
    using var fromPem = X509Certificate2.CreateFromPemFile(certPem, keyPem);

    return X509CertificateLoader.LoadPkcs12(
        fromPem.Export(X509ContentType.Pkcs12),
        null,
        X509KeyStorageFlags.Exportable);
}

static IPAddress ParseHost(string host)
{
    if (string.IsNullOrWhiteSpace(host) || host == "0.0.0.0")
    {
        return IPAddress.Any;
    }

    if (host is "localhost" or "127.0.0.1")
    {
        return IPAddress.Loopback;
    }

    return IPAddress.Parse(host);
}
