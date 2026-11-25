using System.Text.Json;
using System.Text.Json.Nodes;
using AIRouterProxy;
using AiRouterProxy.AdminPersistence;
using AiRouterProxy.AdminServices;
using AiRouterProxy.AdminValidation;
using AiRouterProxy.Dashboard.Models;
using Microsoft.Extensions.Options;
using RouteOptions = AIRouterProxy.RouteOptions;

namespace AiRouterProxy.AdminApi;

/// <summary>
/// Admin write API v1. Every /admin/api/v1/* request is already gated by the existing
/// AdminAuthMiddleware (Bearer primary local key + rate limit) - this layer re-checks the
/// presented key for the sensitive operations (an extra in-depth gate that maps to a
/// clean 401 response) and maps AdminResult to HTTP status codes. Responses NEVER
/// contain secret values; sensitive endpoints are write-only.
/// </summary>
public static class MapAdminApiV1Extensions
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };

    // The host runs with a global Kestrel MaxRequestBodySize=null (the proxy streams
    // bodies up to 128 MB), so the config endpoints enforce their own cap on the import
    // bundle. 5 MB is far beyond any legit export (routes + redaction/inspection).
    private const long MaxImportBodyBytes = 5 * 1024 * 1024;

    private sealed record RoutesBody(IReadOnlyList<RouteDraft>? routes);
    private sealed record SecretBody(string? secret);
    private sealed record KeyMetaBody(string? owner, string? purpose);
    private sealed record SecurityBody(JsonNode? redaction, JsonNode? inspection);
    private sealed record LookupBody(string? hash);
    private sealed record LocalKeyLabelBody(string? label);

    public static WebApplication MapAdminApiV1(this WebApplication app)
    {
        app.MapGet("/admin/api/v1/status", (IDashboardFacade facade) =>
        {
            var s = facade.GetStatus();
            return Results.Ok(new
            {
                status = s.Status,
                version = s.Version,
                timestamp = s.Timestamp,
                uptimeSec = s.UptimeSec,
                activity = s.ActivityCount,
                routing = s.RoutingEnabled,
                routes = s.RouteCount,
                rateLimitEnabled = s.RateLimitEnabled,
                redactionEnabled = s.RedactionEnabled,
                inspectionEnabled = s.InspectionEnabled,
            });
        });

        app.MapGet("/admin/api/v1/routes", (IOptionsMonitor<ProxyOptions> optsMonitor) =>
        {
            var opts = optsMonitor.CurrentValue;
            var drafts = (opts.Routes ?? new List<RouteOptions>())
                .Select(RouteDraftJson.FromRouteOptions)
                .ToList();
            return Results.Ok(new { routes = drafts.Select(ToJson) });
        });

        app.MapPut("/admin/api/v1/routes", async (IDashboardAdminService svc, HttpContext ctx) =>
        {
            var (invalid, body) = await ReadAsync<RoutesBody>(ctx);
            if (invalid)
            {
                return Error(400, "validation_error", "Invalid JSON body.");
            }

            if (body?.routes is null)
            {
                return Error(400, "validation_error", "Body must contain a 'routes' array.");
            }

            return Respond(svc.ApplyRoutes(body.routes, Bearer(ctx)), ctx);
        });

        app.MapGet("/admin/api/v1/keys", (IDashboardFacade facade, KeyMetaStore metaStore, IOptionsMonitor<ProxyOptions> optsMonitor) =>
        {
            var overview = facade.GetKeysOverview();
            var meta = metaStore.LoadAll();
            return Results.Ok(new
            {
                keyRefs = overview.KeyRefs.Select(k => new
                {
                    keyRef = k.KeyRef,
                    configured = k.Configured,
                    usageCount = k.UsageCount,
                    ownerRoute = k.OwnerRoute,
                    owner = k.Owner,
                    purpose = k.Purpose,
                }),
                meta = meta.Select(kv => new { keyRef = kv.Key, owner = kv.Value.Owner, purpose = kv.Value.Purpose }),
                localKeys = overview.LocalKeys.Select(l => new { label = l.Label, hash = l.Hash, primary = l.IsPrimary }),
                hasGlobalKey = overview.HasGlobalKey,
                hasPrimaryLocalKey = overview.HasPrimaryLocalKey,
            });
        });

        app.MapPut("/admin/api/v1/keys/{keyRef}/secret", async (IDashboardAdminService svc, HttpContext ctx, string keyRef) =>
        {
            var (invalid, body) = await ReadAsync<SecretBody>(ctx);
            if (invalid)
            {
                return Error(400, "validation_error", "Invalid JSON body.");
            }

            if (body?.secret is null)
            {
                return Error(400, "validation_error", "Body must contain a 'secret' value.");
            }

            return Respond(svc.SetRouteKeySecret(keyRef, body.secret, Bearer(ctx)), ctx);
        });

        app.MapPut("/admin/api/v1/keys/{keyRef}/meta", async (IDashboardAdminService svc, HttpContext ctx, string keyRef) =>
        {
            var (invalid, body) = await ReadAsync<KeyMetaBody>(ctx);
            if (invalid)
            {
                return Error(400, "validation_error", "Invalid JSON body.");
            }

            var meta = new KeyMeta(body?.owner ?? string.Empty, body?.purpose ?? string.Empty);
            return Respond(svc.UpdateKeyMeta(keyRef, meta, Bearer(ctx)), ctx);
        });

        // Create/ensure a keyRef declaration (empty value, no secret yet) - unblocks a
        // fresh install where routes cannot reference a keyRef that does not exist.
        app.MapPut("/admin/api/v1/keys/{keyRef}", (IDashboardAdminService svc, HttpContext ctx, string keyRef) =>
            Respond(svc.EnsureRouteKeyRef(keyRef, Bearer(ctx)), ctx));

        app.MapDelete("/admin/api/v1/keys/{keyRef}", (IDashboardAdminService svc, HttpContext ctx, string keyRef) =>
            Respond(svc.DeleteRouteKey(keyRef, Bearer(ctx)), ctx));

        // Stores the display name (person/PC) of one extra local key, keyed by its fingerprint.
        app.MapPut("/admin/api/v1/local-keys/{hash}/label", async (IDashboardAdminService svc, HttpContext ctx, string hash) =>
        {
            var (invalid, body) = await ReadAsync<LocalKeyLabelBody>(ctx);
            if (invalid)
            {
                return Error(400, "validation_error", "Invalid JSON body.");
            }

            return Respond(svc.SetLocalKeyLabel(hash, body?.label, Bearer(ctx)), ctx);
        });

        app.MapGet("/admin/api/v1/security", (IDashboardFacade facade) =>
        {
            var s = facade.GetSecurityOptions();
            return Results.Ok(new
            {
                redaction = new
                {
                    enabled = s.Redaction.Enabled,
                    mask = s.Redaction.Mask,
                    notifyInResponse = s.Redaction.NotifyInResponse,
                    warnTemplate = s.Redaction.WarnTemplate,
                    detect = new
                    {
                        byFieldName = s.Redaction.Detect.ByFieldName,
                        byFormats = s.Redaction.Detect.ByFormats,
                        byKeyValueContext = s.Redaction.Detect.ByKeyValueContext,
                        byLongStrings = s.Redaction.Detect.ByLongStrings,
                        exemptBase64 = s.Redaction.Detect.ExemptBase64,
                        entropyThreshold = s.Redaction.Detect.EntropyThreshold,
                    },
                    allow = s.Redaction.Allow,
                },
                inspection = new
                {
                    enabled = s.Inspection.Enabled,
                    defaultAction = s.Inspection.DefaultAction,
                    invalidJson = s.Inspection.InvalidJson,
                    byContentType = s.Inspection.ByContentType,
                },
            });
        });

        app.MapPut("/admin/api/v1/security", async (IDashboardAdminService svc, HttpContext ctx) =>
        {
            var (invalid, body) = await ReadAsync<SecurityBody>(ctx);
            if (invalid)
            {
                return Error(400, "validation_error", "Invalid JSON body.");
            }

            if (body is null)
            {
                return Error(400, "validation_error", "Body must contain 'redaction' and/or 'inspection' sections.");
            }

            // Pass null sections straight through: the service only writes the non-null
            // ones, so a single-section body never blanks the other section.
            return Respond(svc.ApplySecurity(body.redaction, body.inspection, Bearer(ctx)), ctx);
        });

        app.MapPost("/admin/api/v1/keys/lookup", async (HttpContext ctx, IOptionsMonitor<ProxyOptions> optsMonitor, KeyMetaStore metaStore) =>
        {
            var (invalid, body) = await ReadAsync<LookupBody>(ctx);
            if (invalid)
            {
                return Error(400, "validation_error", "Invalid JSON body.");
            }

            var hash = body?.hash;
            if (string.IsNullOrWhiteSpace(hash))
            {
                return Error(400, "validation_error", "Body must contain a 'hash' value.");
            }

            var opts = optsMonitor.CurrentValue;

            if (opts.Keys?.LocalKey is { } primary && Matches(primary, hash))
            {
                return Results.Ok(new { keyRef = (string?)null, owner = "local key (primary)" });
            }

            if (opts.Keys?.LocalKeys is { Count: > 0 })
            {
                for (var i = 0; i < opts.Keys.LocalKeys.Count; i++)
                {
                    if (Matches(opts.Keys.LocalKeys[i], hash))
                    {
                        return Results.Ok(new { keyRef = (string?)null, owner = $"local key #{i + 1}" });
                    }
                }
            }

            if (opts.RouteKeys is { Count: > 0 })
            {
                foreach (var (keyRef, value) in opts.RouteKeys)
                {
                    if (!string.IsNullOrWhiteSpace(value) && Matches(value, hash))
                    {
                        var meta = metaStore.Get(keyRef);
                        return Results.Ok(new { keyRef, owner = meta?.Owner ?? keyRef });
                    }
                }
            }

            return Results.Ok(new { keyRef = (string?)null, owner = (string?)null });
        });

        app.MapGet("/admin/api/v1/config/export", (IDashboardAdminService svc, HttpContext ctx) =>
        {
            var result = svc.Export();
            if (!result.Ok || result.Data is null)
            {
                return Respond(result, ctx);
            }

            ctx.Response.Headers.ContentDisposition = $"attachment; filename=airrouterproxy-config-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}.json";
            return Results.Json(result.Data);
        });

        app.MapPost("/admin/api/v1/config/validate", async (IDashboardAdminService svc, HttpContext ctx) =>
        {
            var (invalid, tooLarge, bundle) = await ReadJsonAsync(ctx);
            if (tooLarge)
            {
                return Error(StatusCodes.Status413PayloadTooLarge, "validation_error", $"Import bundle exceeds the {MaxImportBodyBytes / (1024 * 1024)} MB body limit.");
            }

            if (invalid)
            {
                return Error(400, "validation_error", "Invalid JSON body.");
            }

            if (bundle is null)
            {
                return Error(400, "validation_error", "Body must be a JSON object (import bundle).");
            }

            return Respond(svc.ValidateImport(bundle), ctx);
        });

        app.MapPost("/admin/api/v1/config/import", async (IDashboardAdminService svc, HttpContext ctx) =>
        {
            var (invalid, tooLarge, bundle) = await ReadJsonAsync(ctx);
            if (tooLarge)
            {
                return Error(StatusCodes.Status413PayloadTooLarge, "validation_error", $"Import bundle exceeds the {MaxImportBodyBytes / (1024 * 1024)} MB body limit.");
            }

            if (invalid)
            {
                return Error(400, "validation_error", "Invalid JSON body.");
            }

            if (bundle is null)
            {
                return Error(400, "validation_error", "Body must be a JSON object (import bundle).");
            }

            return Respond(svc.Import(bundle, Bearer(ctx)), ctx);
        });

        app.MapPost("/admin/api/v1/config/reload", (IDashboardAdminService svc, HttpContext ctx) =>
        {
            var result = svc.ReloadConfirm();
            return Results.Ok(new
            {
                applied = result.Ok,
                restored = result.Restored,
                message = result.Message,
            });
        });

        app.MapDelete("/admin/api/v1/logs/activity", (IDashboardAdminService svc, HttpContext ctx) =>
            Respond(svc.ClearActivityLog(Bearer(ctx)), ctx));

        app.MapDelete("/admin/api/v1/logs/eventlog", (IDashboardAdminService svc, HttpContext ctx) =>
            Respond(svc.ClearEventLog(Bearer(ctx)), ctx));

        // Legacy aliases kept for compatibility - they now go through the audited service path.
        app.MapDelete("/admin/activity", (IDashboardAdminService svc, HttpContext ctx) =>
            Respond(svc.ClearActivityLog(Bearer(ctx)), ctx));

        app.MapDelete("/admin/logs", (IDashboardAdminService svc, HttpContext ctx) =>
        {
            var key = Bearer(ctx);
            // Preserve the historical semantics: clear BOTH the Event Log and the in-memory
            // activity buffer (both attempted, like the previous hand-written handler).
            var eventLog = svc.ClearEventLog(key);
            var activity = svc.ClearActivityLog(key);
            if (!eventLog.Ok) return Respond(eventLog, ctx);
            if (!activity.Ok) return Respond(activity, ctx);
            return Respond(AdminResult.Success($"{eventLog.Message} {activity.Message}"), ctx);
        });

        return app;
    }

    // ----------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------

    private static string? Bearer(HttpContext ctx)
        => ctx.Request.Headers.Authorization.ToString() is { Length: > 0 } header
            ? SecurityHelpers.ExtractBearerToken(header)
            : null;

    private static bool Matches(string secret, string hash)
        => AdminHash.Short(secret).Equals(hash, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Reads a typed JSON body. Malformed JSON (JsonException / BadHttpRequestException)
    /// is reported back as a 400 instead of bubbling up as a 500. "null" means a valid
    /// JSON body that declared no object (e.g. "null" or "").
    /// </summary>
    private static async Task<(bool Invalid, T? Value)> ReadAsync<T>(HttpContext ctx)
        where T : class
    {
        try
        {
            return (false, await ctx.Request.ReadFromJsonAsync<T>(JsonOpts, ctx.RequestAborted));
        }
        catch (Exception ex) when (ex is JsonException or BadHttpRequestException)
        {
            return (true, null);
        }
    }

    /// <summary>
    /// Reads a raw JsonNode body with a hard size cap (the host has no global limit).
    /// TooLarge: Content-Length or the streamed body exceeded MaxImportBodyBytes.
    /// Invalid: the body is not valid JSON. Decodes with the same comment/trailing
    /// comma tolerance the config loader uses.
    /// </summary>
    private static async Task<(bool Invalid, bool TooLarge, JsonNode? Node)> ReadJsonAsync(HttpContext ctx)
    {
        if (ctx.Request.ContentLength is { } declared && declared > MaxImportBodyBytes)
        {
            return (false, true, null);
        }

        using var memory = new MemoryStream();
        var buffer = new byte[81920];
        int read;
        while ((read = await ctx.Request.Body.ReadAsync(buffer, ctx.RequestAborted)) > 0)
        {
            if (memory.Length + read > MaxImportBodyBytes)
            {
                return (false, true, null);
            }

            memory.Write(buffer, 0, read);
        }

        memory.Position = 0;
        try
        {
            var options = new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            };
            var node = await JsonNode.ParseAsync(memory, nodeOptions: null, options, ctx.RequestAborted);
            return (false, false, node);
        }
        catch (JsonException)
        {
            return (true, false, null);
        }
    }

    private static IResult Respond(AdminResult result, HttpContext ctx)
    {
        if (result.Ok)
        {
            return Results.Json(new { ok = true, message = result.Message, warnings = result.Warnings ?? Array.Empty<string>() }, statusCode: StatusCodes.Status200OK);
        }

        return result.ErrorType switch
        {
            AdminResult.TypeAuthentication => Error(StatusCodes.Status401Unauthorized, AdminResult.TypeAuthentication, result.Message),
            AdminResult.TypeValidation => Error(StatusCodes.Status400BadRequest, AdminResult.TypeValidation, result.Message, result.Errors),
            AdminResult.TypeConflict => Error(StatusCodes.Status409Conflict, AdminResult.TypeConflict, result.Message, result.Errors),
            AdminResult.TypeNotFound => Error(StatusCodes.Status404NotFound, AdminResult.TypeNotFound, result.Message),
            _ => Error(StatusCodes.Status500InternalServerError, AdminResult.TypeInternal, "Internal error."),
        };
    }

    private static IResult Error(int status, string type, string message, string[]? problems = null)
    {
        if (problems is { Length: > 0 })
        {
            return Results.Json(new { error = new { type, message, problems } }, statusCode: status);
        }

        return Results.Json(new { error = new { type, message } }, statusCode: status);
    }

    private static object ToJson(RouteDraft draft) => new
    {
        name = draft.Name,
        prefix = draft.Prefix ?? string.Empty,
        upstream = draft.Upstream,
        keyRef = draft.KeyRef ?? string.Empty,
        allowedPaths = draft.SafePaths,
        requestTimeoutMs = draft.RequestTimeoutMs,
        maxBodySize = draft.MaxBodySize,
        headers = draft.SafeHeaders,
    };
}
