using System.Diagnostics;
using System.Reflection;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using AIRouterProxy;
using AiRouterProxy.AdminApi;
using AiRouterProxy.AdminPersistence;
using AiRouterProxy.AdminServices;
using AiRouterProxy.AdminUi;
using AiRouterProxy.AdminValidation;
using AiRouterProxy.Dashboard;
using AiRouterProxy.Dashboard.Models;
using Microsoft.Extensions.Hosting.WindowsServices;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi;

var baseDir = AppContext.BaseDirectory;
var configDir = ConfigPaths.ResolveConfigDir(baseDir);
var dataDir = DashboardPaths.ResolveDataDir(configDir, baseDir);
var dashboardPaths = new DashboardPaths(baseDir, configDir, dataDir);

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    ContentRootPath = configDir,
    // The deploy layout redirects ContentRoot to the config subfolder so the
    // server config JSONs resolve there. But Blazor static web assets (app.css,
    // blazor.web.js, ...) are resolved relative to the WebRoot (default
    // ContentRoot/wwwroot), which is an empty folder in that layout - so every
    // dashboard asset was served with an empty body (HTTP 200, 0 bytes) and the
    // UI rendered unstyled. Point the WebRoot at the real published wwwroot.
    WebRootPath = Path.Combine(baseDir, "wwwroot"),
});

// Server-specific config (keys/certificates) - lives only on the target machine.
builder.Configuration.AddJsonFile("appsettings.Server.json", optional: true, reloadOnChange: true);

// Non-secret config (redaction, routes and the provider blocklist feed) - editable
// without restart (hot reload). No keys here: values live in appsettings.Server.json
// or env vars.
builder.Configuration.AddJsonFile("redaction.json", optional: true, reloadOnChange: true);
builder.Configuration.AddJsonFile("routes.json", optional: true, reloadOnChange: true);
builder.Configuration.AddJsonFile("providers.json", optional: true, reloadOnChange: true);

builder.Services.Configure<ProxyOptions>(builder.Configuration.GetSection(ProxyOptions.SectionName));
builder.Services.AddHttpClient();
builder.Services.AddWindowsService(options => options.ServiceName = "AIRouterProxy");

builder.Services.AddSingleton<ActivityStore>();
builder.Services.AddSingleton<DetectionStore>();
builder.Services.AddSingleton<IDetectionStore>(sp => sp.GetRequiredService<DetectionStore>());
builder.Services.AddSingleton<IEventLogStore, WindowsEventLogStore>();

// Transport/Endpoint Attestation (Phase 1: capture/observation, metadata only).
// The baseline writes into data\ at runtime; nothing is persisted unless a route
// has an active transport policy and actually completes a TLS connection.
builder.Services.AddSingleton<TransportStore>();
builder.Services.AddSingleton<BaselineStore>();
builder.Services.AddSingleton<TransportPolicyProvider>();

// Phase 2 (pinning + drift): per-connect enforcement pipeline + the periodic endpoint
// probe (hosted background service; routes opt in via transport.probeHours).
builder.Services.AddSingleton<DriftStore>();
builder.Services.AddSingleton<LearnedPinStore>();
builder.Services.AddSingleton<AttestationRecorder>();
builder.Services.AddSingleton<EndpointProbe>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<EndpointProbe>());

builder.Services.AddSingleton<TransportClientFactory>();

// Phase 3 provider attribution: per-route "who served the last response" cell (metadata
// only - provider names in memory, never content, never keys). Fed by the middleware on
// aggregator routes that opt in via transport.blocklist.attribution.
builder.Services.AddSingleton<AttributionStore>();

// Admin dashboard UI - Blazor Web App served under /admin/ui in the same process.
builder.Services.AddDashboard(DashboardExtensions.BasePath);
builder.Services.AddSingleton<UiSessionManager>();
builder.Services.AddSingleton(dashboardPaths);
builder.Services.AddSingleton<ConfigBackup>();
builder.Services.AddSingleton<ReloadConfirmer>();
builder.Services.AddSingleton<KeyMetaStore>();
builder.Services.AddSingleton<AuditLog>();
builder.Services.AddSingleton<IDashboardAdminService, DashboardAdminService>();
builder.Services.AddSingleton<HostDashboardFacade>();
builder.Services.AddSingleton<IDashboardFacade>(sp => sp.GetRequiredService<HostDashboardFacade>());

// Swagger / explorable API
// Version comes from the assembly (same value /admin/health reports), so it never drifts from the csproj.
var serviceVersion = System.Reflection.Assembly.GetExecutingAssembly().GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0] ?? "0.0.0";

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
ValidateProviderFeed(proxyOptions);

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

// Admin UI (Blazor) lives under /admin/ui: the path base is stripped here so the Blazor
// router sees relative paths inside the subtree. UsePathBase only touches /admin/ui requests.
app.UsePathBase(DashboardExtensions.BasePath);
app.UseWhen(
    ctx => ctx.Request.PathBase.HasValue && ctx.Request.PathBase.StartsWithSegments(DashboardExtensions.BasePath),
    branch => branch.UseMiddleware<UiSessionMiddleware>());

// The proxy forwards everything except /admin and /swagger. The /v1/* paths stay the same.
app.UseWhen(
    ctx => !ctx.Request.Path.StartsWithSegments("/admin") && !ctx.Request.Path.StartsWithSegments("/swagger")
        && !ctx.Request.PathBase.StartsWithSegments("/admin"),
    branch => branch.UseMiddleware<ProxyMiddleware>());

// Admin endpoints require the same local key (Bearer). The UI subtree has its own cookie session.
app.UseWhen(ctx => ctx.Request.Path.StartsWithSegments("/admin")
        && !ctx.Request.PathBase.HasValue,
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
            maxBodySize = RouteResolver.EffectiveMaxBodySize(r, o.MaxBodySize),
            headers = r.Headers,
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
            new { method = "GET", path = "/admin/api/v1/status", description = "Write API: status (same Bearer key as /admin)." },
            new { method = "PUT", path = "/admin/api/v1/routes", description = "Write API: replace the route table (routes.json, hot reload)." },
            new { method = "PUT", path = "/admin/api/v1/keys/{keyRef}/secret", description = "Write API: set/rotate a route key secret (write-only)." },
            new { method = "POST", path = "/admin/api/v1/config/import", description = "Write API: import a no-secrets config bundle." },
            new { method = "DELETE", path = "/admin/api/v1/logs/activity", description = "Write API: clear the in-memory activity buffer." },
            new { method = "DELETE", path = "/admin/api/v1/logs/eventlog", description = "Write API: clear the dedicated AIRouterProxy Event Log." },
            new { method = "GET", path = "/admin/api/v1/detections?limit=50", description = "Read API: recent detection forensics (metadata only, never the value)." },
            new { method = "DELETE", path = "/admin/api/v1/detections", description = "Write API: clear the in-memory detection forensics buffer (admin key required)." },
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

app.MapGet("/admin/logs", (ILoggerFactory loggerFactory, int hours = 6, int limit = 50) =>
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
        loggerFactory.CreateLogger("Admin").LogError(ex, "Failed to read the dedicated Event Log.");
        return Results.Problem("Could not read the AIRouterProxy Event Log.", statusCode: 500);
    }

    return Results.Ok(new { count = matches.Count, entries = matches });
});

app.MapGet("/admin/health", (ActivityStore store) =>
{
    var processStart = Process.GetCurrentProcess().StartTime.ToUniversalTime();
    var uptime = DateTimeOffset.UtcNow - new DateTimeOffset(processStart);

    return Results.Ok(new
    {
        status = "ok",
        version = System.Reflection.Assembly.GetExecutingAssembly().GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0] ?? "0.0.0",
        timestamp = DateTimeOffset.UtcNow,
        uptimeSec = (long)uptime.TotalSeconds,
        activity = store.Count,
    });
});

// Admin write API v1 - same Bearer + rate limit gate as the /admin endpoints above,
// mapped to AdminResult responses (400 validation / 401 auth / 409 conflict / 500 sanitized).
app.MapAdminApiV1();

app.UseAntiforgery();
app.MapDashboard();

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

        // Transport section (attestation, Phase 1 = observe only): light validation only.
        // Invalid values are ignored with a warning - a bad section must never crash the
        // proxy or fail the route table (the transport feature is off by default anyway).
        ValidateRouteTransport(route);
    }
}

/// <summary>
/// Light validation of the optional per-route "transport" section. Values that do not
/// parse are ignored (warning only), so a hand-edited routes.json can never take the
/// proxy down. The dashboard-side validation (RouteValidator) is stricter.
/// </summary>
static void ValidateRouteTransport(AIRouterProxy.RouteOptions route)
{
    var t = route.Transport;
    if (t is null)
    {
        return;
    }

    if (!string.IsNullOrWhiteSpace(t.Enforce)
        && t.Enforce is not ("observe" or "warn" or "block"))
    {
        Console.WriteLine($"[WARNING] Route '{route.Name}': transport.enforce '{t.Enforce}' is invalid (observe|warn|block) - ignored.");
    }

    if (!string.IsNullOrWhiteSpace(t.TlsFloor)
        && t.TlsFloor is not ("1.2" or "1.3"))
    {
        Console.WriteLine($"[WARNING] Route '{route.Name}': transport.tlsFloor '{t.TlsFloor}' is invalid (1.2|1.3) - ignored.");
    }

    if (t.PoolLifetimeMinutes is < 0)
    {
        Console.WriteLine($"[WARNING] Route '{route.Name}': transport.poolLifetimeMinutes must be >= 0 - ignored.");
    }

    if (t.ProbeHours < 0)
    {
        Console.WriteLine($"[WARNING] Route '{route.Name}': transport.probeHours must be >= 0 - ignored.");
    }

    if (t.GraceDays is < 0 or > 365)
    {
        Console.WriteLine($"[WARNING] Route '{route.Name}': transport.graceDays must be 0..365 - ignored.");
    }

    foreach (var pin in t.Pins ?? new List<string>())
    {
        if (!IsPinLike(pin))
        {
            Console.WriteLine($"[WARNING] Route '{route.Name}': transport.pin '{pin}' is not a hex/base64url hash - ignored.");
        }
    }

    // Phase 3 per-route provider-blocklist policy: advisory only. A bad section is
    // ignored with a warning - it must never crash the proxy or fail the route table.
    var b = t.Blocklist;
    if (b is null)
    {
        return;
    }

    if (string.IsNullOrWhiteSpace(b.ProviderPolicy)
        || b.ProviderPolicy is not ("merge" or "strict"))
    {
        Console.WriteLine($"[WARNING] Route '{route.Name}': transport.blocklist.providerPolicy '{b.ProviderPolicy}' is invalid (merge|strict) - ignored.");
    }

    foreach (var aggregator in b.Aggregators ?? new List<string>())
    {
        if (string.IsNullOrWhiteSpace(aggregator))
        {
            Console.WriteLine($"[WARNING] Route '{route.Name}': transport.blocklist.aggregators contains an empty entry - ignored.");
        }
    }
}

/// <summary>
/// Validates the provider blocklist feed (Phase 3, providers.json "Proxy.Providers").
/// Bad entries are reported as startup warnings but never crash the proxy: the feed is
/// advisory metadata, and routes without an active transport.blocklist section ignore
/// it entirely. The admin write path (ProviderFeedValidator) is stricter.
/// </summary>
static void ValidateProviderFeed(ProxyOptions options)
{
    if (options.Providers?.Entries is not { Count: > 0 })
    {
        return;
    }

    if (!ProviderFeedValidator.Validate(options.Providers.Entries, out var errors))
    {
        foreach (var error in errors)
        {
            Console.WriteLine($"[WARNING] providers.json: {error}");
        }
    }
}

/// <summary>True when the value looks like a full SHA-256 fingerprint (64 hex chars) or a base64url/base64 hash.</summary>
static bool IsPinLike(string pin)
{
    if (string.IsNullOrWhiteSpace(pin))
    {
        return false;
    }

    var value = pin.Trim();
    var isHex64 = value.Length == 64
                  && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F');
    var isB64 = value.Length is 43 or 44
                && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '-' or '_' or '=');
    return isHex64 || isB64;
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
