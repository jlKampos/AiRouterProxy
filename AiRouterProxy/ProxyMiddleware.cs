using System.Diagnostics;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace AIRouterProxy;

public sealed class ProxyMiddleware
{
    private readonly ILogger<ProxyMiddleware> _logger;
    private readonly IOptionsMonitor<ProxyOptions> _options;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ActivityStore _activity;
    private readonly RateLimiter _rateLimiter;

    private static readonly string[] HeadersToForward =
        { "content-type", "cache-control", "retry-after", "x-request-id" };

    public ProxyMiddleware(
        RequestDelegate _next,
        ILogger<ProxyMiddleware> logger,
        IOptionsMonitor<ProxyOptions> options,
        IHttpClientFactory httpClientFactory,
        ActivityStore activity,
        RateLimiter rateLimiter)
    {
        _logger = logger;
        _options = options;
        _httpClientFactory = httpClientFactory;
        _activity = activity;
        _rateLimiter = rateLimiter;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var options = _options.CurrentValue;
        var requestId = Guid.NewGuid().ToString("N");
        var startedAt = Stopwatch.StartNew();

        var clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        // Tracking for the activity log (one entry per request, not verbose).
        var finalStatus = 0;
        string? modelName = null;
        string? presentedHash = null;
        string? expectedHash = null;
        var authRefused = false;
        var redactionCount = 0;
        var redactionKinds = string.Empty;
        List<SecretRedactor.RedactionPreview>? redactionPreviews = null;
        string? routeName = null;

        try
        {

        if (options.Verbose)
        {
            _logger.LogInformation(
                "REQUEST RECEIVED | Id={Id} Method={Method} Path={Path} Client={Client}",
                requestId, context.Request.Method, context.Request.Path, clientIp);
        }

        // Rate limiting (per client) - cheap, fail-closed, runs before local authentication
        // so it also protects against unauthenticated floods and brute-force lockouts.
        if (options.RateLimit is { Enabled: true })
        {
            var verdict = _rateLimiter.Check(clientIp);
            if (verdict != RateLimiter.Verdict.Allow)
            {
                finalStatus = StatusCodes.Status429TooManyRequests;
                context.Response.Headers.RetryAfter =
                    Math.Max(1, _rateLimiter.RetryAfterSeconds(clientIp)).ToString();

                _logger.LogWarning("Rate limit exceeded | Id={Id} Client={Client} Verdict={Verdict}",
                    requestId, clientIp, verdict);

                await SendErrorAsync(context, StatusCodes.Status429TooManyRequests,
                    verdict == RateLimiter.Verdict.LockedOut
                        ? "Too many failed attempts. Try again later."
                        : "Too many requests.",
                    "rate_limit_error");
                return;
            }
        }

        // 1. Local authentication - always first, before any routing/method logic.
        //    Unauthenticated clients must never see route/upstream information.
        var clientKey = SecurityHelpers.ExtractBearerToken(context.Request.Headers.Authorization.ToString());
        if (!AuthenticationPolicy.IsValidLocalKey(clientKey, options.Keys))
        {
            var keyCount = AuthenticationPolicy.LocalKeyCount(options.Keys);

            if (options.RateLimit is { Enabled: true })
            {
                _rateLimiter.RecordFailure(clientIp); // brute-force counter
            }

            var userAgent = Truncate(context.Request.Headers.UserAgent.ToString(), 120);

            presentedHash = string.IsNullOrEmpty(clientKey)
                ? "(empty)"
                : SecurityHelpers.HashShort(SecurityHelpers.Sha256Hex(clientKey));
            expectedHash = keyCount == 1
                ? SecurityHelpers.HashShort(SecurityHelpers.Sha256Hex(options.Keys.LocalKey ?? string.Empty))
                : null;
            finalStatus = StatusCodes.Status401Unauthorized;
            authRefused = true;

            try
            {
                _logger.LogWarning(
                    "Authentication refused | Id={Id} Client={Client} Path={Path} " +
                    "PresentedLen={PresentedLen} PresentedHash={PresentedHash} ExpectedHash={ExpectedHash} KeyCount={KeyCount} UA={UA}",
                    requestId, clientIp, context.Request.Path.Value ?? "/",
                    clientKey?.Length ?? 0,
                    presentedHash,
                    expectedHash ?? "(multiple keys)",
                    keyCount,
                    userAgent);
            }
            catch
            {
                // Logging failures must never block the client response.
            }
            await SendErrorAsync(context, StatusCodes.Status401Unauthorized,
                "Invalid or missing local key.", "authentication_error");
            return;
        }

        // 2. HTTP method
        if (context.Request.Method != HttpMethods.Get && context.Request.Method != HttpMethods.Post)
        {
            context.Response.Headers.Allow = "GET, POST";
            finalStatus = StatusCodes.Status405MethodNotAllowed;
            await SendErrorAsync(context, StatusCodes.Status405MethodNotAllowed,
                "Method not allowed.", "invalid_request_error");
            return;
        }

        // 3. Resolve route (multi-upstream) and validate endpoint
        var pathname = context.Request.Path.Value ?? "/";
        string upstreamBase;
        string upstreamPath;
        string upstreamKey;
        int requestTimeoutMs;

        if (options.Routes is { Count: > 0 })
        {
            var resolved = RouteResolver.Resolve(options.Routes, options.RouteKeys, pathname, options.Keys.UpstreamKey);
            if (resolved is null)
            {
                finalStatus = StatusCodes.Status404NotFound;
                await SendErrorAsync(context, StatusCodes.Status404NotFound,
                    "No proxy route matches this path.", "invalid_request_error");
                return;
            }

            if (resolved.Key is null)
            {
                finalStatus = StatusCodes.Status502BadGateway;
                _logger.LogWarning("Route without a configured key | Id={Id} Route={Route} KeyRef={KeyRef}",
                    requestId, resolved.Route.Name, resolved.Route.KeyRef);
                await SendErrorAsync(context, StatusCodes.Status502BadGateway,
                    "Upstream not configured.", "proxy_error");
                return;
            }

            routeName = resolved.Route.Name;
            upstreamBase = (resolved.Route.Upstream ?? string.Empty).TrimEnd('/');
            upstreamPath = resolved.RewrittenPath;
            upstreamKey = resolved.Key;
            requestTimeoutMs = resolved.Route.RequestTimeoutMs > 0
                ? resolved.Route.RequestTimeoutMs
                : options.RequestTimeoutMs;

            if (!RouteResolver.IsPathAllowed(resolved.Route.AllowedPaths, upstreamPath))            {
                finalStatus = StatusCodes.Status404NotFound;
                await SendErrorAsync(context, StatusCodes.Status404NotFound,
                    "Endpoint not allowed on this proxy route.", "invalid_request_error");
                return;
            }
        }
        else
        {
            // No routes configured: legacy behaviour, 1 fixed upstream.
            routeName = "default";
            upstreamBase = options.Upstream.TrimEnd('/');
            upstreamPath = pathname;
            upstreamKey = options.Keys.UpstreamKey ?? string.Empty;
            requestTimeoutMs = options.RequestTimeoutMs;

            if (!options.AllowedPaths.Contains(pathname))
            {
                finalStatus = StatusCodes.Status404NotFound;
                await SendErrorAsync(context, StatusCodes.Status404NotFound,
                    "Endpoint not allowed by the proxy.", "invalid_request_error");
                return;
            }
        }

        // 4. Request body - fail-closed inspection.
        //    No body is ever forwarded unless it passed inspection (Content-Type policy + JSON parse).
        byte[] bodyBytes = Array.Empty<byte>();
        if (context.Request.Method == HttpMethods.Post)
        {
            var hasBody = context.Request.ContentLength is > 0
                || context.Request.Headers.TransferEncoding.Count > 0;
            var inspectAction = InspectionPolicy.Decide(
                options.Inspection, methodAllowsBody: true, context.Request.ContentType, hasBody);

            if (!string.Equals(inspectAction, InspectionPolicy.ActionInspect, StringComparison.OrdinalIgnoreCase))
            {
                finalStatus = StatusCodes.Status415UnsupportedMediaType;
                if (options.Verbose)
                {
                    _logger.LogWarning(
                        "Request body content-type blocked by policy | Id={Id} ContentType={ContentType}",
                        requestId, InspectionPolicy.NormalizeMediaType(context.Request.ContentType));
                }
                await SendErrorAsync(context, StatusCodes.Status415UnsupportedMediaType,
                    "Unsupported content type.", "invalid_request_error");
                return;
            }

            try
            {
                bodyBytes = await ReadBodyWithLimitAsync(
                    context.Request.Body, options.MaxBodySize, context.RequestAborted);

                if (bodyBytes.Length > 0
                    && InspectionPolicy.IsJson(context.Request.ContentType))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(bodyBytes,
                            new JsonDocumentOptions { MaxDepth = 128 });

                        // For the activity log: extract only the "model", without storing content.
                        if (doc.RootElement.ValueKind == JsonValueKind.Object
                            && doc.RootElement.TryGetProperty("model", out var modelProp)
                            && modelProp.ValueKind == JsonValueKind.String)
                        {
                            modelName = modelProp.GetString();
                        }

                        if (options.Verbose)
                        {
                            var summary = SummarizeRequestBody(doc.RootElement);
                            if (summary is { Count: > 0 })
                            {
                                _logger.LogInformation(
                                    "MODEL PARAMETERS | Id={Id} Params={Params}", requestId, summary);
                            }
                        }
                    }
                    catch (JsonException) when (
                        !options.Inspection.Enabled
                        || string.Equals(options.Inspection.InvalidJson, "warn", StringComparison.OrdinalIgnoreCase))
                    {
                        // Escape hatch (Inspection disabled, or InvalidJson = "warn"): the body is
                        // forwarded without a successful parse. Default ("block") never does this.
                        if (options.Verbose)
                        {
                            _logger.LogWarning(
                                "Request body not recognized as valid JSON (non-blocking) | Id={Id}", requestId);
                        }
                    }
                    catch (JsonException)
                    {
                        // Fail closed: an invalid JSON body is never forwarded.
                        finalStatus = StatusCodes.Status400BadRequest;
                        _logger.LogWarning("Request body failed JSON inspection | Id={Id}", requestId);
                        await SendErrorAsync(context, StatusCodes.Status400BadRequest,
                            "Request body could not be inspected.", "invalid_request_error");
                        return;
                    }
                }
            }
            catch (PayloadTooLargeException)
            {
                finalStatus = StatusCodes.Status413PayloadTooLarge;
                await SendErrorAsync(context, StatusCodes.Status413PayloadTooLarge,
                    "Request body too large.", "invalid_request_error");
                return;
            }
            catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
            {
                finalStatus = 499;
                _logger.LogInformation("Client disconnected while reading the body | Id={Id}", requestId);
                return;
            }
            catch (Exception ex)
            {
                finalStatus = StatusCodes.Status400BadRequest;
                _logger.LogError(ex, "Error reading request body | Id={Id}", requestId);
                await SendErrorAsync(context, StatusCodes.Status400BadRequest,
                    "Could not read the request body.", "invalid_request_error");
                return;
            }
        }

        // 4b. Redact sensitive content in outgoing messages.
        var forwardedBody = bodyBytes;
        if (HttpMethods.IsPost(context.Request.Method)
            && bodyBytes.Length > 0
            && options.Redaction.Enabled
            && InspectionPolicy.IsJson(context.Request.ContentType))
        {
            var redacted = SecretRedactor.RedactJson(
                bodyBytes,
                mask: options.Redaction.Mask,
                detectByFieldName: options.Redaction.Detect?.ByFieldName ?? true,
                detectByFormats: options.Redaction.Detect?.ByFormats ?? true,
                detectByKeyValueContext: options.Redaction.Detect?.ByKeyValueContext ?? true,
                detectByLongStrings: options.Redaction.Detect?.ByLongStrings ?? true,
                detectEntropyThreshold: options.Redaction.Detect?.EntropyThreshold ?? 3.0);
            if (redacted.Changed)
            {
                forwardedBody = redacted.Data;
                redactionCount = redacted.Stats.Total;
                redactionKinds = SecretRedactor.Summarize(redacted.Stats);
                redactionPreviews = redacted.Stats.Previews;

                if (options.Verbose)
                {
                    _logger.LogWarning(
                        "REDACTED CONTENT | Id={Id} Count={Count} Kinds={Kinds} OriginalBytes={Original} RedactedBytes={Redacted}",
                        requestId, redactionCount, redactionKinds, bodyBytes.Length, forwardedBody.Length);
                }
            }
        }

        // 5. Prepare request for the route upstream
        var upstreamUri = new Uri(upstreamBase + upstreamPath + context.Request.QueryString, UriKind.Absolute);

        using var upstreamRequest = new HttpRequestMessage(new HttpMethod(context.Request.Method), upstreamUri);

        upstreamRequest.Headers.TryAddWithoutValidation("Authorization", "Bearer " + upstreamKey);

        var accept = context.Request.Headers.Accept.ToString();
        upstreamRequest.Headers.TryAddWithoutValidation("Accept",
            string.IsNullOrWhiteSpace(accept) ? "application/json" : accept);

        if (context.Request.Headers.TryGetValue("x-request-id", out var clientRequestId))
        {
            upstreamRequest.Headers.TryAddWithoutValidation("x-request-id", clientRequestId.ToString());
        }

        if (HttpMethods.IsPost(context.Request.Method))
        {
            upstreamRequest.Content = new ByteArrayContent(forwardedBody);
            var contentType = context.Request.ContentType;
            if (!string.IsNullOrWhiteSpace(contentType))
            {
                upstreamRequest.Content.Headers.TryAddWithoutValidation("Content-Type", contentType);
            }
        }

        var client = _httpClientFactory.CreateClient("AIRouter");
        client.Timeout = TimeSpan.FromMilliseconds(requestTimeoutMs);

        if (options.Verbose)
        {
            _logger.LogInformation("FORWARDING | Id={Id} Route={Route} Method={Method} Endpoint={Endpoint} Upstream={Upstream}",
                requestId, routeName, context.Request.Method, pathname, upstreamBase);
        }

        // 6. Send and stream the response
        HttpResponseMessage? upstreamResponse = null;

        try
        {
            upstreamResponse = await client.SendAsync(
                upstreamRequest, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted);

            var contentType = upstreamResponse.Content.Headers.ContentType?.ToString();

            if (options.Verbose)
            {
                _logger.LogInformation(
                    "UPSTREAM RESPONSE | Id={Id} Status={Status} ContentType={ContentType} DurationMs={Duration}",
                    requestId, (int)upstreamResponse.StatusCode, contentType, startedAt.ElapsedMilliseconds);
            }

            context.Response.StatusCode = (int)upstreamResponse.StatusCode;
            finalStatus = (int)upstreamResponse.StatusCode;
            ForwardResponseHeaders(upstreamResponse, context.Response);

            // Redaction occurred: signal it in the header and, if configured, inject a
            // readable notice at the end of the response (SSE before [DONE]; JSON in the last choice).
            // In the normal case (no redaction) the response is streamed byte by byte.
            if (redactionCount > 0)
            {
                context.Response.Headers["X-AIRouter-Redacted"] = redactionCount.ToString();
            }

            if (redactionCount > 0 && options.Redaction.NotifyInResponse)
            {
                var mediaType = contentType ?? string.Empty;
                if (mediaType.Contains("text/event-stream", StringComparison.OrdinalIgnoreCase)
                    || mediaType.Contains("application/json", StringComparison.OrdinalIgnoreCase))
                {
                    var fullBody = await upstreamResponse.Content.ReadAsByteArrayAsync(context.RequestAborted);
                    var notice = BuildRedactionNotice(redactionCount, redactionKinds, options.Redaction, redactionPreviews);
                    var injected = NoticeInjector.Inject(fullBody, mediaType, notice);
                    await context.Response.Body.WriteAsync(injected ?? fullBody, context.RequestAborted);
                }
                else
                {
                    await upstreamResponse.Content.CopyToAsync(context.Response.Body, context.RequestAborted);
                }
            }
            else
            {
                await upstreamResponse.Content.CopyToAsync(context.Response.Body, context.RequestAborted);
            }

            if (options.Verbose)
            {
                _logger.LogInformation(
                    "REQUEST COMPLETED | Id={Id} Status={Status} DurationMs={Duration}",
                    requestId, (int)upstreamResponse.StatusCode, startedAt.ElapsedMilliseconds);
            }
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            finalStatus = 499;
            _logger.LogWarning("Client connection closed | Id={Id} DurationMs={Duration}",
                requestId, startedAt.ElapsedMilliseconds);
        }
        catch (OperationCanceledException)
        {
            finalStatus = StatusCodes.Status502BadGateway;
            _logger.LogError("Timeout contacting the AI Router | Id={Id} DurationMs={Duration}",
                requestId, startedAt.ElapsedMilliseconds);

            if (!context.Response.HasStarted)
            {
                await SendErrorAsync(context, StatusCodes.Status502BadGateway,
                    "Could not reach the AI Router.", "proxy_error", requestId);
            }
        }
        catch (Exception ex)
        {
            finalStatus = StatusCodes.Status502BadGateway;
            _logger.LogError(ex, "REQUEST ERROR | Id={Id} DurationMs={Duration}",
                requestId, startedAt.ElapsedMilliseconds);

            if (!context.Response.HasStarted)
            {
                await SendErrorAsync(context, StatusCodes.Status502BadGateway,
                    "Could not reach the AI Router.", "proxy_error", requestId);
            }
            else
            {
                finalStatus = 499;
                context.Abort();
            }
        }
        finally
        {
            upstreamResponse?.Dispose();
        }
        }
        finally
        {
            _activity.Add(new ActivityEntry
            {
                Timestamp = DateTimeOffset.UtcNow,
                Client = clientIp,
                Method = context.Request.Method,
                Path = context.Request.Path.Value ?? "/",
                Status = finalStatus,
                DurationMs = startedAt.ElapsedMilliseconds,
                Model = modelName,
                Route = routeName,
                Refused = authRefused,
                Redacted = redactionCount,
                PresentedHash = presentedHash,
                ExpectedHash = expectedHash,
                UA = authRefused ? Truncate(context.Request.Headers.UserAgent.ToString(), 120) : null,
            });
        }
    }

    // --------------------------------------------------
    // Helpers
    // --------------------------------------------------

    private static string Truncate(string? value, int max)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        return value.Length <= max ? value : value[..max];
    }

    private static async Task<byte[]> ReadBodyWithLimitAsync(Stream body, long maxSize, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];

        while (true)
        {
            var read = await body.ReadAsync(chunk.AsMemory(0, chunk.Length), cancellationToken);
            if (read == 0)
            {
                break;
            }

            if (buffer.Length + read > maxSize)
            {
                throw new PayloadTooLargeException();
            }

            await buffer.WriteAsync(chunk.AsMemory(0, read), cancellationToken);
        }

        return buffer.ToArray();
    }

    private static string BuildRedactionNotice(int count, string kinds, RedactionOptions opts,
        IReadOnlyList<SecretRedactor.RedactionPreview>? previews)
    {
        if (!string.IsNullOrWhiteSpace(opts.WarnTemplate))
        {
            return opts.WarnTemplate
                .Replace("{Count}", count.ToString(), StringComparison.Ordinal)
                .Replace("{Kinds}", kinds, StringComparison.Ordinal)
                .Replace("{Previews}", SecretRedactor.FormatPreviews(previews), StringComparison.Ordinal);
        }

        var what = count == 1
            ? "1 occurrence of sensitive content"
            : $"{count} occurrences of sensitive content";

        if (!string.IsNullOrWhiteSpace(kinds))
        {
            what += $" ({kinds})";
        }

        var previewText = SecretRedactor.FormatPreviews(previews);
        if (!string.IsNullOrWhiteSpace(previewText))
        {
            what += $". Detected values: {previewText}";
        }

        return $"⚠️ **Proxy notice:** the request contained sensitive content which was redacted before being sent to the AI Router ({what}).";
    }

    private static void ForwardResponseHeaders(HttpResponseMessage upstream, HttpResponse destination)
    {
        foreach (var name in HeadersToForward)
        {
            string? value = null;

            if (upstream.Headers.TryGetValues(name, out var fromHeaders)
                || upstream.Content.Headers.TryGetValues(name, out fromHeaders))
            {
                value = string.Join(",", fromHeaders);
            }

            if (value is not null)
            {
                destination.Headers[name] = new StringValues(value);
            }
        }
    }

    private static Dictionary<string, object?>? SummarizeRequestBody(JsonElement body)
    {
        if (body.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        var result = new Dictionary<string, object?>(StringComparer.Ordinal);

        foreach (var name in new[]
                 {
                     "model", "stream", "reasoningEffort", "reasoning_effort",
                     "max_tokens", "max_completion_tokens", "temperature",
                 })
        {
            if (body.TryGetProperty(name, out var value))
            {
                result[name] = Simplify(value);
            }
        }

        foreach (var pair in new[] { ("reasoning", new[] { "effort", "summary" }), ("thinking", new[] { "type", "budget_tokens" }) })
        {
            if (body.TryGetProperty(pair.Item1, out var nested) && nested.ValueKind == JsonValueKind.Object)
            {
                var fields = new Dictionary<string, object?>(StringComparer.Ordinal);

                foreach (var field in pair.Item2)
                {
                    if (nested.TryGetProperty(field, out var value))
                    {
                        fields[field] = Simplify(value);
                    }
                }

                result[pair.Item1] = fields;
            }
        }

        return result.Count == 0 ? null : result;
    }

    private static object? Simplify(JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.String:
                return element.GetString();
            case JsonValueKind.Number:
                return element.TryGetInt32(out var i) ? i : element.GetDouble();
            case JsonValueKind.True:
                return true;
            case JsonValueKind.False:
                return false;
            case JsonValueKind.Null:
                return null;
            case JsonValueKind.Object:
                var obj = new Dictionary<string, object?>(StringComparer.Ordinal);
                foreach (var property in element.EnumerateObject())
                {
                    obj[property.Name] = Simplify(property.Value);
                }
                return obj;
            default:
                return element.GetRawText();
        }
    }

    private static async Task SendErrorAsync(
        HttpContext context, int statusCode, string message, string type, string? requestId = null)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json; charset=utf-8";
        context.Response.Headers.CacheControl = "no-store";

        object payload = requestId is null
            ? new { error = new { message, type } }
            : new { error = new { message, type, request_id = requestId } };

        var json = JsonSerializer.SerializeToUtf8Bytes(payload, new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        });

        await context.Response.Body.WriteAsync(json, context.RequestAborted);
    }

    private sealed class PayloadTooLargeException : Exception;
}
