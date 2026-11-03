using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

// ---------------------------------------------------------------------------
// Black-box integration tests against a REAL deployed proxy + AI Router.
//
//   dotnet run --project tests/Integration -- --key-file <path> [other flags]
//
// Flags:
//   --key-file <path>   File containing the local proxy key (plain text, one line).
//                       The harness reads it at runtime; it is never printed.
//   --base <url>        Proxy base URL (default: https://127.0.0.1:4000).
//   --skip-paid         Skip the calls that can consume tokens (real forward / SSE).
//   --brute-force       Run the 10-failure lockout test LAST (waits ~65s for the
//                       request window to drain, then locks this IP for the lockout
//                       duration - default 5 minutes). Off by default.
// ---------------------------------------------------------------------------
class Program
{
    static int _passed;
    static int _failed;
    static string _key = string.Empty;

    static void Check(string name, Func<bool> fn)
    {
        if (fn()) { _passed++; Console.WriteLine($"PASS  {name}"); }
        else { _failed++; Console.WriteLine($"FAIL  {name}"); }
    }

    static void CheckTrue(string name, Func<bool> fn) => Check(name, fn);
    static void Info(string msg) => Console.WriteLine($"INFO  {msg}");
    static void Warn(string msg) => Console.WriteLine($"WARN  {msg}");

    static async Task<int> Main(string[] args)
    {
        var keyFile = GetArg(args, "--key-file")
                      ?? Environment.GetEnvironmentVariable("AIROUTERPROXY_LOCAL_KEY_FILE");
        var baseUrl = GetArg(args, "--base") ?? "https://127.0.0.1:4000";
        var skipPaid = HasFlag(args, "--skip-paid");
        var bruteForce = HasFlag(args, "--brute-force");

        if (keyFile is null)
        {
            Console.Error.WriteLine("No key file: use --key-file <path> or set AIROUTERPROXY_LOCAL_KEY_FILE.");
            return 2;
        }

        if (!File.Exists(keyFile))
        {
            Console.Error.WriteLine($"Key file not found: {keyFile}");
            Console.Error.WriteLine("Create it with just the local proxy key (one line) and re-run.");
            return 2;
        }

        _key = (await File.ReadAllTextAsync(keyFile)).Trim();
        if (_key.Length == 0)
        {
            Console.Error.WriteLine("Key file is empty.");
            return 2;
        }

        Console.WriteLine($"key file: {keyFile}");
        Console.WriteLine($"key sha256: {ShaPrefix(_key)} (first 8 hex chars - never the key itself)");
        Console.WriteLine($"base url : {baseUrl}");
        Console.WriteLine($"skip paid: {skipPaid}   brute-force: {bruteForce}");
        Console.WriteLine();

        using var client = NewClient(baseUrl);

        // ------------------------------------------------------------------
        // 0. Pre-flight: is the deployed proxy up and does the key work?
        // ------------------------------------------------------------------
        var health = await GetWithKeyAsync(client, "/admin/health");
        if (health.status == 0)
        {
            Console.Error.WriteLine($"Cannot reach the proxy at {baseUrl} - is the service deployed/running (https, port 4000)?");
            return 3;
        }

        Check("health with key -> 200", () => health.status == 200);
        if (health.status == 401)
        {
            Console.Error.WriteLine("The proxy rejected the key from the key file (401). Check the value and re-run.");
            return 4;
        }

        if (health.status == 429)
        {
            Console.Error.WriteLine("The proxy is rate-limiting this IP right now (429). Wait ~60s and re-run.");
            return 4;
        }

        Info($"proxy up: {TrimInfo(health.body)}");

        // ------------------------------------------------------------------
        // 1. Local authentication (401 vs 200)
        // ------------------------------------------------------------------
        var noAuth = await GetNoKeyAsync(client, "/admin/health");
        Check("health without key -> 401", () => noAuth.status == 401);

        var wrongAuth = await GetAsync(client, "/admin/health", key: "definitely-not-the-key-123");
        Check("health with wrong key -> 401", () => wrongAuth.status == 401);

        Check("health with key -> 200 again", () => health.status == 200);

        // ------------------------------------------------------------------
        // 2. /admin surface never leaks the key
        // ------------------------------------------------------------------
        var endpointsNoAuth = await GetNoKeyAsync(client, "/admin/endpoints");
        Check("endpoints without key -> 401", () => endpointsNoAuth.status == 401);

        var endpoints = await GetWithKeyAsync(client, "/admin/endpoints");
        Check("endpoints with key -> 200", () => endpoints.status == 200);

        var chatPath = "/v1/chat/completions";
        Check("endpoints payload has no local key", () => !endpoints.body.Contains(_key, StringComparison.Ordinal));
        Check("endpoints masks the redaction value", () => endpoints.body.Contains("\u2022\u2022\u2022\u2022\u2022\u2022", StringComparison.Ordinal));

        try
        {
            using var edoc = JsonDocument.Parse(endpoints.body);
            var proxyEl = edoc.RootElement.GetProperty("proxy");
            if (proxyEl.GetProperty("routingEnabled").GetBoolean())
            {
                var routes = proxyEl.GetProperty("routes");
                if (routes.GetArrayLength() > 0
                    && routes[0].TryGetProperty("prefix", out var prefixEl)
                    && prefixEl.GetString() is { Length: > 0 } prefix)
                {
                    chatPath = prefix + "/chat/completions";
                }
            }
            else if (proxyEl.GetProperty("allowedPaths").GetArrayLength() > 0)
            {
                var allowed = proxyEl.GetProperty("allowedPaths")[0].GetString();
                if (!string.IsNullOrWhiteSpace(allowed))
                {
                    chatPath = allowed;
                }
            }

            Info($"chat path used for forward tests: {chatPath}");
        }
        catch (JsonException)
        {
            Check("endpoints payload is valid JSON", () => false);
            return 5;
        }

        // ------------------------------------------------------------------
        // 3. Malformed / oversized requests are blocked before the upstream (no cost)
        // ------------------------------------------------------------------
        var badJson = await PostAsync(client, chatPath, """{"messages": [""", "application/json");
        Check("invalid json -> 400", () => badJson.status == 400);

        var textPlain = await PostAsync(client, chatPath, "just text", "text/plain");
        Check("text/plain -> 415", () => textPlain.status == 415);

        var delete = await DeleteAsync(client, chatPath);
        Info($"DELETE -> status={delete.status} allow={delete.allowHeader ?? "<none>"}");
        Check("DELETE -> 405 with Allow header", () =>
            delete.status == 405
            && delete.allowHeader is not null
            && delete.allowHeader.Contains("GET", StringComparison.Ordinal));

        var noRoute = await GetWithKeyAsync(client, "/__no_such_proxy_route__/x");
        Check("unknown route -> 404", () => noRoute.status == 404);

        var big = new string('a', 21 * 1024 * 1024);
        var bigJson = await PostAsync(client, chatPath, $"{{\"messages\":[\"{big}\"]}}", "application/json");
        Check("oversized body -> 413", () => bigJson.status == 413);

        // ------------------------------------------------------------------
        // 4. Real forward to the AI Router (small cost)
        // ------------------------------------------------------------------
        var firstWorkingModel = string.Empty;
        var lastUpstreamStatus = 0;

        if (!skipPaid)
        {
            CheckTrue("real forward reaches the upstream", () =>
            {
                // Model names are limited by the router key; use models the key can access.
                foreach (var model in new[] { "DeepSeek-V4-Flash", "Qwen3.8", "whisper-large-v3-turbo", "Qwen3-Embedding" })
                {
                    var r = SendChatJsonAsync(client, chatPath, model, stream: false, fakeSecret: false);
                    if (r.status == 200) { firstWorkingModel = model; return true; }
                    if (IsProxyError(r.status, r.body)) return false;
                    lastUpstreamStatus = r.status; // 4xx/5xx from the router still means "reached the upstream"
                }

                return lastUpstreamStatus != 0;
            });

            if (firstWorkingModel.Length == 0 && lastUpstreamStatus != 0)
            {
                Info($"no 2xx, but the upstream answered at least once (status {lastUpstreamStatus})");
            }

            CheckTrue("real SSE streams from the upstream", () =>
            {
                var model = firstWorkingModel.Length > 0 ? firstWorkingModel : "gpt-4o-mini";
                var (dataLines, done) = SendChatSseAsync(client, chatPath, model);
                Info($"SSE: data lines={dataLines} done={done}");
                return dataLines >= 1;
            });
        }
        else
        {
            Warn("skipping real forward + SSE (--skip-paid)");
        }

        // ------------------------------------------------------------------
        // 5. Redaction observability: a fake secret triggers redaction counters
        // ------------------------------------------------------------------
        if (!skipPaid)
        {
            SendChatJsonAsync(client, chatPath,
                firstWorkingModel.Length > 0 ? firstWorkingModel : "gpt-4o-mini",
                stream: false, fakeSecret: true);
        }
        else
        {
            Warn("skipping redaction-observability call (--skip-paid)");
        }

        var activity = await GetWithKeyAsync(client, "/admin/activity?hours=6&limit=100");
        Check("activity -> 200", () => activity.status == 200);
        CheckTrue("activity reports a redacted request", () =>
        {
            try
            {
                using var d = JsonDocument.Parse(activity.body);
                foreach (var e in d.RootElement.GetProperty("entries").EnumerateArray())
                {
                    if (e.TryGetProperty("redacted", out var r) && r.GetInt32() > 0)
                    {
                        return true;
                    }
                }

                return false;
            }
            catch (JsonException)
            {
                return false;
            }
        });

        // ------------------------------------------------------------------
        // 6. Log leakage: activity / refusals / logs never contain the key
        // ------------------------------------------------------------------
        Check("activity has no local key", () => !activity.body.Contains(_key, StringComparison.Ordinal));

        var refusals = await GetWithKeyAsync(client, "/admin/refusals?hours=6&limit=100");
        Check("refusals -> 200", () => refusals.status == 200);
        Check("refusals has no local key", () => !refusals.body.Contains(_key, StringComparison.Ordinal));

        var logs = await GetWithKeyAsync(client, "/admin/logs?hours=6&limit=100");
        if (logs.status == 200)
        {
            Check("logs have no local key", () => !logs.body.Contains(_key, StringComparison.Ordinal));
        }
        else
        {
            Warn($"logs endpoint not available (status {logs.status}) - Event Log may be missing; skipping");
        }

        // ------------------------------------------------------------------
        // 7. Rate limit: the window eventually returns 429 + Retry-After
        // ------------------------------------------------------------------
        var saw429 = false;
        var retryAfterOk = false;
        for (var i = 0; i < 140 && !saw429; i++)
        {
            var r = await GetWithKeyAsync(client, "/admin/health");
            if (r.status == 429)
            {
                saw429 = true;
                retryAfterOk = r.retryAfterSeconds >= 1;
            }
            else if (r.status != 200)
            {
                Info($"health burst: unexpected status {r.status} at request {i}");
            }
        }

        Check("rate limit -> 429 after the window", () => saw429);
        Check("429 carries Retry-After >= 1", () => retryAfterOk);

        // ------------------------------------------------------------------
        // 8. Brute-force lockout (optional, LAST: locks this IP for 5 min)
        // ------------------------------------------------------------------
        if (bruteForce)
        {
            Warn("waiting ~65s for the request window to drain before the brute-force test...");
            await Task.Delay(65_000);

            string last = "x";
            for (var i = 0; i < 10; i++)
            {
                last = (await GetAsync(client, "/admin/health", key: $"wrong-key-{i}")).status.ToString();
            }

            Info($"after 10 failures, last status was {last} (expect 401s)");

            var locked = await GetWithKeyAsync(client, "/admin/health");
            Check("after 10 failures the client is locked out (429 even with the right key)", () => locked.status == 429);
            Warn("Brute-force test done: this IP is locked out for the lockout duration (default 5 min).");
            Warn("Wait before using the proxy from this machine again.");
        }

        Console.WriteLine();
        Console.WriteLine($"RESULT: {_passed} PASS, {_failed} FAIL");
        return _failed == 0 ? 0 : 1;
    }

    // ------------------------------------------------------------------
    // HTTP helpers (black box)
    // ------------------------------------------------------------------

    static HttpClient NewClient(string baseUrl)
    {
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, _, _, _) => true, // self-signed local cert
            AutomaticDecompression = DecompressionMethods.All,
        };
        return new HttpClient(handler) { BaseAddress = new Uri(baseUrl), Timeout = TimeSpan.FromSeconds(45) };
    }

    static HttpRequestMessage GetRequest(string path, string? key)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, path);
        if (key is not null)
        {
            req.Headers.Authorization = new("Bearer", key);
        }

        return req;
    }

    static async Task<(int status, string body, int retryAfterSeconds, string? allowHeader)> SendAsync(
        HttpClient client, HttpRequestMessage req)
    {
        try
        {
            using var resp = await client.SendAsync(req);
            var body = await resp.Content.ReadAsStringAsync();
            var retry = resp.Headers.TryGetValues("retry-after", out var rv)
                        && int.TryParse(rv.FirstOrDefault(), out var rs) ? rs : 0;
            // "Allow" is an entity header: HttpClient exposes it under Content.Headers,
            // not the top-level response headers. Read both to be transport-agnostic.
            var allow = (resp.Headers.TryGetValues("allow", out var av) ? string.Join(", ", av) : null)
                ?? (resp.Content.Headers.TryGetValues("allow", out var cav) ? string.Join(", ", cav) : null);
            return ((int)resp.StatusCode, body, retry, allow);
        }
        catch (HttpRequestException ex)
        {
            Info($"request failed: {ex.Message}");
            return (0, string.Empty, 0, null);
        }
    }

    static async Task<(int status, string body, int retryAfterSeconds, string? allowHeader)> GetNoKeyAsync(
        HttpClient client, string path)
    {
        using var req = GetRequest(path, null);
        return await SendAsync(client, req);
    }

    static Task<(int status, string body, int retryAfterSeconds, string? allowHeader)> GetWithKeyAsync(
        HttpClient client, string path)
        => GetWithKeyAsync(client, path, _key);

    static async Task<(int status, string body, int retryAfterSeconds, string? allowHeader)> GetWithKeyAsync(
        HttpClient client, string path, string key)
    {
        using var req = GetRequest(path, key);
        return await SendAsync(client, req);
    }

    static Task<(int status, string body, int retryAfterSeconds, string? allowHeader)> GetAsync(
        HttpClient client, string path, string key)
        => GetWithKeyAsync(client, path, key);

    static async Task<(int status, string body, int retryAfterSeconds, string? allowHeader)> PostAsync(
        HttpClient client, string path, string json, string contentType)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new StringContent(json, Encoding.UTF8, contentType),
        };
        req.Headers.Authorization = new("Bearer", _key);
        return await SendAsync(client, req);
    }

    static async Task<(int status, string body, int retryAfterSeconds, string? allowHeader)> DeleteAsync(
        HttpClient client, string path)
    {
        using var req = new HttpRequestMessage(HttpMethod.Delete, path);
        req.Headers.Authorization = new("Bearer", _key);
        return await SendAsync(client, req);
    }

    static (int status, string body) SendChatJsonAsync(
        HttpClient client, string path, string model, bool stream, bool fakeSecret)
    {
        var content = fakeSecret
            ? "the secret key is sk-test-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 123"
            : "hi";
        var payload = JsonSerializer.Serialize(new
        {
            model,
            messages = new[] { new { role = "user", content } },
            max_tokens = 8,
            stream,
        });

        using var req = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new StringContent(payload, Encoding.UTF8, "application/json"),
        };
        req.Headers.Authorization = new("Bearer", _key);
        using var resp = client.Send(req);
        var body = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        return ((int)resp.StatusCode, body);
    }

    static (int dataLines, bool done) SendChatSseAsync(HttpClient client, string path, string model)
    {
        var payload = JsonSerializer.Serialize(new
        {
            model,
            messages = new[] { new { role = "user", content = "hi" } },
            max_tokens = 8,
            stream = true,
        });

        using var req = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new StringContent(payload, Encoding.UTF8, "application/json"),
        };
        req.Headers.Authorization = new("Bearer", _key);

        using var resp = client.Send(req, HttpCompletionOption.ResponseHeadersRead);
        if ((int)resp.StatusCode >= 400)
        {
            var eb = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            Info($"SSE request failed: status={(int)resp.StatusCode} body={TrimInfo(eb)}");
            return (0, false);
        }

        using var stream = resp.Content.ReadAsStream();
        using var reader = new StreamReader(stream);
        var dataLines = 0;
        var done = false;
        string? line;
        var guard = 0;
        while ((line = reader.ReadLine()) is not null && guard++ < 200_000)
        {
            if (line.StartsWith("data:", StringComparison.Ordinal))
            {
                dataLines++;
                if (line.Contains("[DONE]", StringComparison.Ordinal))
                {
                    done = true;
                }
            }
        }

        return (dataLines, done);
    }

    // ------------------------------------------------------------------
    // Small helpers
    // ------------------------------------------------------------------

    static bool IsProxyError(int status, string body)
        => status is 502 or 503 or 429 or 0
           // A 401 from the PROXY carries the authentication_error error type;
           // a 401 from the UPSTREAM (e.g. "key not allowed to access model")
           // means the proxy itself worked and the request reached the router.
           || (status == 401 && body.Contains("\"authentication_error\"", StringComparison.Ordinal));

    static string ShaPrefix(string value)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)))[..8];

    static string TrimInfo(string body)
        => body.Length <= 160 ? body : body[..160] + "...";

    static string? GetArg(string[] args, string name)
    {
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == name)
            {
                return args[i + 1];
            }
        }

        return null;
    }

    static bool HasFlag(string[] args, string name) => args.Contains(name, StringComparer.Ordinal);
}
