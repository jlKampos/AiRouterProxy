using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using AIRouterProxy;

class Program
{
    static int _passed = 0;
    static int _failed = 0;

    static byte[] Bytes(string s) => Encoding.UTF8.GetBytes(s);
    static string Str(byte[] b) => Encoding.UTF8.GetString(b);

    static void Check(string name, bool cond)
    {
        if (cond) { _passed++; Console.WriteLine($"PASS  {name}"); }
        else { _failed++; Console.WriteLine($"FAIL  {name}"); }
    }

    static void CheckTrue(string name, Func<bool> fn) => Check(name, fn());

    static void Main()
    {
        TestFormats();
        TestVendorFormats();
        TestFieldNames();
        TestConventionNames();
        TestNoChange();
        TestRobustness();
        TestSummarize();
        TestNotices();
        TestExtendedDetection();
        TestRedactionGaps();
        TestConfigPaths();
        TestRedactionAllow();
        TestBase64ImageExemption();
        TestPreviews();
        TestRedactionNotice();
        TestForensics();
        TestForensicsZeroCostAndNames();
        TestForensicsPatternShape();
        TestMergeUnion();
        TestMergeExemptionRules();
        TestDetector();
        TestAuthenticationPolicy();
        TestRateLimiter();
        TestSseParser();
        TestSseProcessor();
        TestSseProtocolAdapters();
        TestSecurityEdges();
        TestRouting();
        TestInspectionPolicy();
        TestRouteHeaders();
        TestRouteMaxBodySize();
        Console.WriteLine();
        Console.WriteLine($"RESULT: {_passed} PASS, {_failed} FAIL");
        Environment.ExitCode = _failed == 0 ? 0 : 1;
    }

    // --------------------------------------------------------------
    static void TestRouteHeaders()
    {
        var req = new HttpRequestMessage(HttpMethod.Post, "http://upstream/v1/messages");
        RouteHeaders.Apply(req, new Dictionary<string, string>
        {
            ["anthropic-version"] = "2023-06-01",
            ["X-Tenant"] = "eng",
            ["Authorization"] = "Bearer injected-by-route",  // reserved -> must not appear
            ["Content-Type"] = "text/plain",                  // reserved -> must not appear
            [""] = "skip",                                    // empty name -> skipped
            ["X-Empty"] = "",                                 // empty value -> skipped
        });

        CheckTrue("route headers applied", () =>
            req.Headers.TryGetValues("anthropic-version", out var v) && string.Join(",", v) == "2023-06-01"
            && req.Headers.Contains("X-Tenant"));
        CheckTrue("route headers reserved ignored", () =>
            !req.Headers.Contains("Authorization")
            && !req.Headers.Any(h => h.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)));
        CheckTrue("route headers empty skipped", () =>
            !req.Headers.Contains("X-Empty"));

        var none = new HttpRequestMessage(HttpMethod.Get, "http://upstream/x");
        RouteHeaders.Apply(none, null);
        RouteHeaders.Apply(none, new Dictionary<string, string>());
        CheckTrue("route headers null/empty no-op", () => none.Headers.Count() == 0);
    }

    static void TestRouteMaxBodySize()
    {
        const long global = 20 * 1024 * 1024;   // Proxy.MaxBodySize default
        const long anthropic = 134217728;       // 128 MB - routes.json "maxBodySize" on /anthropic

        // Legacy mode (null route) always uses the global value.
        CheckTrue("maxBodySize legacy null uses global",
            () => RouteResolver.EffectiveMaxBodySize(null, global) == global);

        // Route without an explicit value (0) inherits the global Proxy.MaxBodySize.
        var inherits = new RouteOptions();
        CheckTrue("maxBodySize default zero",
            () => inherits.MaxBodySize == 0
                  && RouteResolver.EffectiveMaxBodySize(inherits, global) == global);

        // Route with an explicit maxBodySize uses its own value.
        var explicitRoute = new RouteOptions { MaxBodySize = anthropic };
        CheckTrue("maxBodySize route explicit 128MB",
            () => RouteResolver.EffectiveMaxBodySize(explicitRoute, global) == anthropic);

        // Global only kicks in when the route has none - no cross-contamination.
        var small = new RouteOptions { MaxBodySize = 1 * 1024 * 1024 };
        CheckTrue("maxBodySize route smaller than global honored",
            () => RouteResolver.EffectiveMaxBodySize(small, global) == 1 * 1024 * 1024);
    }

    static void TestFormats()
    {
        // sk-... in message content
        var r1 = SecretRedactor.RedactJson(Bytes("{\"messages\":[{\"role\":\"user\",\"content\":\"the key is sk-abc1234567890123 x\"}]}"));
        CheckTrue("sk- in content", () => r1.Changed && !Str(r1.Data).Contains("sk-abc123") && r1.Stats.Total == 1 && r1.Stats.ByKind.GetValueOrDefault("openai") == 1);

        // set of inline key patterns
        var body2 = Bytes("{\"content\":\"hi sk-ant-abcdefghijklmnop ghp_abcdefghijklmnopqrstuvwxyz0123456789 AIza1234567890abcdefghijklmn npm_abcdefghijklmnopqrst xoxb-1234567890-abcdef AKIAABCDEFGHIJKLMNOP abc\"}");
        var r2 = SecretRedactor.RedactJson(body2);
        var s2 = Str(r2.Data);
        CheckTrue("multiple inline keys", () => r2.Changed
            && !s2.Contains("sk-ant-") && !s2.Contains("ghp_") && !s2.Contains("AIza")
            && !s2.Contains("npm_") && !s2.Contains("xoxb-") && !s2.Contains("AKIA")
            && r2.Stats.ByKind.GetValueOrDefault("anthropic") >= 1
            && r2.Stats.ByKind.GetValueOrDefault("github") >= 1
            && r2.Stats.ByKind.GetValueOrDefault("google") >= 1
            && r2.Stats.ByKind.GetValueOrDefault("npm") >= 1
            && r2.Stats.ByKind.GetValueOrDefault("slack") >= 1
            && r2.Stats.ByKind.GetValueOrDefault("aws") >= 1);

        // JWT (3 segments eyJ...)
        var r3 = SecretRedactor.RedactJson(Bytes("{\"c\":\"token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSM ABC\"}"));
        CheckTrue("JWT", () => r3.Changed && !Str(r3.Data).Contains("eyJhbGciOiJIUzI1NiJ9") && r3.Stats.ByKind.GetValueOrDefault("jwt") == 1);

        // Bearer: keeps prefix, replaces the token
        var r4 = SecretRedactor.RedactJson(Bytes("{\"c\":\"use Bearer abcdefghijklmnopqrstuvw at the end\"}"));
        var s4 = Str(r4.Data);
        CheckTrue("Bearer inline", () => r4.Changed && s4.Contains("Bearer ") && !s4.Contains("abcdefghijklmnopqrstuvw") && r4.Stats.ByKind.GetValueOrDefault("bearer") == 1);

        // PEM private key (multiline)
        var pem = "-----BEGIN PRIVATE KEY-----\nMIIEVQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----";
        var body5 = "{ \"c\": \"" + pem + "\" }";
        var r5 = SecretRedactor.RedactJson(Bytes(body5.Replace("\n", "\\n")));
        CheckTrue("PEM private key", () => r5.Changed && !Str(r5.Data).Contains("MIIEVQIB") && r5.Stats.ByKind.GetValueOrDefault("private_key") == 1);

        // Long GitHub key is consumed whole (no partial trace)
        var r6 = SecretRedactor.RedactJson(Bytes("{\"c\":\"ghp_123456789012345678901234567890123456\"}"));
        var s6 = Str(r6.Data);
        CheckTrue("github fully masked", () => r6.Changed
            && s6.Contains("\"c\":\"" + SecretRedactor.DefaultMask + "\"}")
            && !s6.Contains("ghp_")
            && !s6.Contains("123456789012345678901234"));

        // Too-short sk- does not trigger (false positive prevention)
        var r7 = SecretRedactor.RedactJson(Bytes("{\"c\":\"just sk-abc is not a key\"}"));
        CheckTrue("short sk- ignored", () => !r7.Changed);
    }

    // --------------------------------------------------------------
    // Vendor format patterns (2.1.0) - real formats, source: gitleaks master / vendor docs
    // --------------------------------------------------------------
    static void TestVendorFormats()
    {
        var opts = new DetectOptions();
        var noEntropy = new DetectOptions { ByLongStrings = false };

        // Deterministic builders with real alphabets/lengths.
        string Hex(int n) => new(Enumerable.Range(0, n).Select(i => "0123456789abcdef"[i % 16]).ToArray());
        string Base32(int n) => new(Enumerable.Range(0, n).Select(i => "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"[i % 32]).ToArray());
        string Alnum(int n) => new(Enumerable.Range(0, n).Select(i =>
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"[i % 62]).ToArray());

        // DigitalOcean Personal Access Token
        CheckTrue("do dop_v1_", () => SecretDetector.Detect("tok dop_v1_" + Hex(64) + " end", opts) is { Count: 1 } d
            && d[0].Category == "digitalocean");
        // Google OAuth 2.0 access token
        CheckTrue("google oauth ya29", () => SecretDetector.Detect("tok ya29." + Alnum(24) + " end", opts) is { Count: 1 } g
            && g[0].Category == "google_oauth");
        // Hugging Face access token
        CheckTrue("hf token", () => SecretDetector.Detect("tok hf_" + Alnum(34) + " end", opts) is { Count: 1 } h
            && h[0].Category == "huggingface");
        // Replicate API token
        CheckTrue("replicate r8_", () => SecretDetector.Detect("tok r8_" + Alnum(37) + " end", opts) is { Count: 1 } r
            && r[0].Category == "replicate");
        // GitLab personal access token
        CheckTrue("gitlab glpat-", () => SecretDetector.Detect("tok glpat-" + Alnum(20) + " end", opts) is { Count: 1 } gl
            && gl[0].Category == "gitlab");
        // PyPI upload token (public prefix + >= 50 chars body)
        CheckTrue("pypi token", () => SecretDetector.Detect("tok pypi-AgEIcHlwaS5vcmc" + Alnum(60) + " end", opts) is { Count: 1 } py
            && py[0].Category == "pypi");
        // Docker Hub PAT
        CheckTrue("docker dckr_pat_", () => SecretDetector.Detect("tok dckr_pat_" + Alnum(27) + " end", opts) is { Count: 1 } dc
            && dc[0].Category == "dockerhub");
        // Twilio API key SID
        CheckTrue("twilio SK", () => SecretDetector.Detect("tok SK" + Hex(32) + " end", opts) is { Count: 1 } tw
            && tw[0].Category == "twilio");
        // SendGrid API key
        CheckTrue("sendgrid SG.", () => SecretDetector.Detect("tok SG." + Alnum(66) + " end", opts) is { Count: 1 } sg
            && sg[0].Category == "sendgrid");
        // Mailgun API key
        CheckTrue("mailgun key-", () => SecretDetector.Detect("tok key-" + Hex(32) + " end", opts) is { Count: 1 } mg
            && mg[0].Category == "mailgun");
        // Shopify (admin/custom/private/shared)
        CheckTrue("shopify shpat_", () => SecretDetector.Detect("tok shpat_" + Hex(32) + " end", opts) is { Count: 1 } sh
            && sh[0].Category == "shopify");
        CheckTrue("shopify shpss_", () => SecretDetector.Detect("tok shpss_" + Hex(32) + " end", opts) is { Count: 1 } sh2
            && sh2[0].Category == "shopify");
        // Discord bot token (heuristic)
        CheckTrue("discord bot", () => SecretDetector.Detect("tok M" + Alnum(23) + "." + Alnum(6) + "." + Alnum(27) + " end", opts) is { Count: 1 } db
            && db[0].Category == "discord");
        // Discord webhook URL
        CheckTrue("discord webhook", () => SecretDetector.Detect("use https://discord.com/api/webhooks/123456789012345678/" + Alnum(68), opts) is { Count: 1 } dw
            && dw[0].Category == "discord");
        // Azure Storage account key
        CheckTrue("azure account key", () => SecretDetector.Detect("AccountKey=" + Alnum(86) + "==", opts) is { Count: 1 } az
            && az[0].Category == "azure");
        // Azure Storage connection string
        CheckTrue("azure connstr", () => SecretDetector.Detect("DefaultEndpointsProtocol=https;AccountName=s;AccountKey=" + Alnum(88), opts) is { Count: 1 } az2
            && az2[0].Category == "azure");
        // Database URL credentials (only user:pass masked, scheme kept)
        var db = SecretDetector.Detect("postgres://dbuser:DbPass123@db.example.com:5432/app", opts);
        CheckTrue("db connstr", () => db.Count == 1 && db[0].Category == "db_conn");
        // AWS base32 (new), incl. the A3T variant
        CheckTrue("aws base32", () => SecretDetector.Detect("aws AKIA" + Base32(16) + " end", opts) is { Count: 1 } aw
            && aw[0].Category == "aws" && aw[0].Length == 20);
        CheckTrue("aws A3T", () => SecretDetector.Detect("tok A3TQ" + Base32(16) + " end", opts) is { Count: 1 } a3
            && a3[0].Category == "aws");
        // Stripe prod + restricted keys (new)
        CheckTrue("stripe prod", () => SecretDetector.Detect("sk_prod_" + Alnum(30), opts) is { Count: 1 } sp
            && sp[0].Category == "stripe");
        CheckTrue("stripe rk", () => SecretDetector.Detect("rk_live_" + Alnum(30), opts) is { Count: 1 } sr
            && sr[0].Category == "stripe");

        // --- Negatives (no entropy layer: pure format behaviour) ---
        CheckTrue("neg glpat short", () => SecretDetector.Detect("glpat-short", noEntropy).Count == 0);
        CheckTrue("neg hf short", () => SecretDetector.Detect("hf_abc", noEntropy).Count == 0);
        CheckTrue("neg pypi short body", () => SecretDetector.Detect("pypi-AgEIcHlwaS5vcmc" + Alnum(20), noEntropy).Count == 0);
        CheckTrue("neg shpat short", () => SecretDetector.Detect("shpat_" + Hex(8), noEntropy).Count == 0);
        CheckTrue("neg dop_v1 bad alphabet", () => SecretDetector.Detect("dop_v1_" + Alnum(64), noEntropy).Count == 0);
        CheckTrue("neg sendgrid short", () => SecretDetector.Detect("SG." + Alnum(10), noEntropy).Count == 0);
        CheckTrue("neg aws wrong alphabet", () => SecretDetector.Detect("AKIA" + "0123456789abcdefghij", noEntropy).Count == 0);

        // --- End-to-end via the redactor: value masked, kind reported ---
        var vendor = SecretRedactor.RedactJson(Bytes("{\"content\":\"deploy dop_v1_" + Hex(64) + " is set and glpat-" + Alnum(20) + " plus dckr_pat_" + Alnum(27) + "\"}"));
        CheckTrue("vendor redaction e2e", () => vendor.Changed
            && !Str(vendor.Data).Contains("dop_v1_") && !Str(vendor.Data).Contains("glpat-") && !Str(vendor.Data).Contains("dckr_pat_")
            && vendor.Stats.ByKind.GetValueOrDefault("digitalocean") == 1
            && vendor.Stats.ByKind.GetValueOrDefault("gitlab") == 1
            && vendor.Stats.ByKind.GetValueOrDefault("dockerhub") == 1);

        var azureMasked = SecretRedactor.RedactJson(Bytes("{\"c\":\"AccountKey=" + Alnum(86) + "==\"}"));
        CheckTrue("azure e2e fully masked", () => azureMasked.Changed
            && Str(azureMasked.Data).Contains("\"c\":\"" + SecretRedactor.DefaultMask + "\"}")
            && azureMasked.Stats.ByKind.GetValueOrDefault("azure") == 1);
    }

    // --------------------------------------------------------------
    static void TestFieldNames()
    {
        // password by field name; max_tokens (number) untouched
        var r1 = SecretRedactor.RedactJson(Bytes("{\"password\":\"hunter2\",\"max_tokens\":2000}"));
        CheckTrue("password + max_tokens", () => r1.Changed
            && !Str(r1.Data).Contains("hunter2")
            && Str(r1.Data).Contains("2000")
            && !Str(r1.Data).Contains("\"max_tokens\":\"" + SecretRedactor.DefaultMask)
            && r1.Stats.ByKind.GetValueOrDefault("password") == 1);

        // max_tokens as a STRING also stays untouched (name exclusion)
        var r1b = SecretRedactor.RedactJson(Bytes("{\"max_tokens\":\"4096\"}"));
        CheckTrue("max_tokens string untouched", () => !r1b.Changed && Str(r1b.Data).Contains("\"max_tokens\":\"4096\""));

        // nested api_key + exclusions
        var r2 = SecretRedactor.RedactJson(Bytes("{\"outer\":{\"connection\":{\"api_key\":\"abc123\"},\"n\":10},\"tokens\":[\"a\",\"b\"]}"));
        CheckTrue("nested api_key + tokens array", () => r2.Changed
            && !Str(r2.Data).Contains("abc123")
            && Str(r2.Data).Contains("\"tokens\":[\"a\",\"b\"]")
            && r2.Stats.ByKind.GetValueOrDefault("api_key") == 1);

        // null -> empty? numeric value is never masked
        var r3 = SecretRedactor.RedactJson(Bytes("{\"password\":12345}"));
        CheckTrue("numeric password untouched", () => !r3.Changed && Str(r3.Data).Contains("12345"));

        // token-sounding but contextual names (budget_tokens) untouched
        var r4 = SecretRedactor.RedactJson(Bytes("{\"reasoning\":{\"budget_tokens\":50}}"));
        CheckTrue("budget_tokens untouched", () => !r4.Changed);

        // access_token/refresh_token in both styles
        var r5 = SecretRedactor.RedactJson(Bytes("{\"access_token\":\"AAA\",\"refresh_token\":\"BBB\"}"));
        CheckTrue("access/refresh token", () => r5.Changed && !Str(r5.Data).Contains("AAA") && !Str(r5.Data).Contains("BBB") && r5.Stats.ByKind.GetValueOrDefault("token") == 2);

        // "secret" contained in names (client_secret, senha)
        var r6 = SecretRedactor.RedactJson(Bytes("{\"client_secret\":\"x\",\"senha\":\"y\"}"));
        CheckTrue("client_secret + senha", () => r6.Changed && r6.Stats.ByKind.GetValueOrDefault("secret") == 1 && r6.Stats.ByKind.GetValueOrDefault("password") == 1);

        // generic token field
        var r7 = SecretRedactor.RedactJson(Bytes("{\"csrf_token\":\"abc\"}"));
        CheckTrue("csrf_token", () => r7.Changed && r7.Stats.ByKind.GetValueOrDefault("token") == 1);
    }

    // --------------------------------------------------------------
    static void TestConventionNames()
    {
        // Context/text layer is convention-agnostic: snake, camel, Pascal, kebab, plain.
        CheckTrue("auth_token in text", () => SecretRedactor.RedactJson(Bytes("{\"c\":\"auth_token=Value12345 x\"}")).Changed);
        CheckTrue("AuthToken (camel) in text", () => SecretRedactor.RedactJson(Bytes("{\"c\":\"AuthToken=Value12345 x\"}")).Changed);
        CheckTrue("session-token in text", () => SecretRedactor.RedactJson(Bytes("{\"c\":\"session-token=Value12345 x\"}")).Changed);
        CheckTrue("id_token in text", () => SecretRedactor.RedactJson(Bytes("{\"c\":\"id_token=Value12345 x\"}")).Changed);
        CheckTrue("JwtKey (camel) in text", () => SecretRedactor.RedactJson(Bytes("{\"c\":\"JwtKey=Value12345 x\"}")).Changed);
        CheckTrue("SigningKey (camel) in text", () => SecretRedactor.RedactJson(Bytes("{\"c\":\"SigningKey=Value12345 x\"}")).Changed);
        CheckTrue("signing_key in text", () => SecretRedactor.RedactJson(Bytes("{\"c\":\"signing_key=Value12345 x\"}")).Changed);
        CheckTrue("bare Token= in text", () => SecretRedactor.RedactJson(Bytes("{\"c\":\"Token=Value12345 x\"}")).Changed);
        CheckTrue("no separator stays", () => !SecretRedactor.RedactJson(Bytes("{\"c\":\"the token Value12345 is natural text\"}")).Changed);
        CheckTrue("csrf_token short stays", () => !SecretRedactor.RedactJson(Bytes("{\"c\":\"csrf_token=abc x\"}")).Changed);
        CheckTrue("max_tokens stays", () => !SecretRedactor.RedactJson(Bytes("{\"c\":\"max_tokens=8\"}")).Changed);
        CheckTrue("field JwtKey", () => SecretRedactor.RedactJson(Bytes("{\"JwtKey\":\"abc12345\"}")).Changed);
        CheckTrue("field SigningKey", () => SecretRedactor.RedactJson(Bytes("{\"SigningKey\":\"abc12345\"}")).Changed);
        CheckTrue("field AuthToken", () => SecretRedactor.RedactJson(Bytes("{\"AuthToken\":\"abc12345\"}")).Changed);
        CheckTrue("field signing_key", () => SecretRedactor.RedactJson(Bytes("{\"signing_key\":\"abc12345\"}")).Changed);
    }
    static void TestNoChange()
    {
        // No sensitive content -> original bytes intact (zero-cost guarantee)
        var body = "{\"messages\":[{\"role\":\"user\",\"content\":\"good afternoon\",\"extra\":\"23\"}],\"model\":\"x\",\"stream\":true}";
        var input = Bytes(body);
        var r = SecretRedactor.RedactJson(input);
        CheckTrue("no sensitive: identical bytes", () => !r.Changed && input.SequenceEqual(r.Data));

        // Normal prose with common words (token/password as words) - no formats
        var body2 = "{\"messages\":[{\"role\":\"user\",\"content\":\"what is my password in the app? give me an example of a token and a secret please\"}]}";
        var input2 = Bytes(body2);
        var r2 = SecretRedactor.RedactJson(input2);
        CheckTrue("normal prose intact", () => !r2.Changed && input2.SequenceEqual(r2.Data));
    }

    // --------------------------------------------------------------
    static void TestRobustness()
    {
        // Invalid JSON -> returns original, without crashing
        var bad = Bytes("{this is not json");
        var r = SecretRedactor.RedactJson(bad);
        CheckTrue("invalid JSON intact", () => !r.Changed && bad.SequenceEqual(r.Data));

        // Valid JSON after redaction
        var r2 = SecretRedactor.RedactJson(Bytes("{\"m\":\"sk-abcdefghijklmnopqrstuvwxyz\",\"x\":{\"y\":[1,2,{\"z\":\"Bearer qwertyuiopasdfghjklzxcvbnm\"}]}}"));
        CheckTrue("post-redaction parses", () =>
        {
            try { JsonDocument.Parse(r2.Data); return r2.Changed; }
            catch (JsonException) { return false; }
        });

        // Mask is exactly 6 bullets
        CheckTrue("mask = 6 bullets", () => SecretRedactor.DefaultMask == "\u2022\u2022\u2022\u2022\u2022\u2022");

        // Root-level array also works
        var r3 = SecretRedactor.RedactJson(Bytes("[\"sk-abcdefghijklmnop123\", 42, {\"keep\":true}]"));
        CheckTrue("root array", () => r3.Changed && !Str(r3.Data).Contains("sk-abcdefghijklmnop123"));

        // Realism: a realistic OpenCode request
        var realistic = "{\"model\":\"DeepSeek-V4-Flash\",\"stream\":true,\"messages\":[{\"role\":\"system\",\"content\":\"fix this\",\"tools\":[]},{\"role\":\"user\",\"content\":\"my config uses api_key = sk-zyxwvutsrqponmlkjihgfedcba321\"}],\"max_tokens\":4000,\"reasoning\":{\"effort\":\"high\"}}";
        var rr = SecretRedactor.RedactJson(Bytes(realistic));
        var srr = Str(rr.Data);
        CheckTrue("realistic request", () => rr.Changed
            && !srr.Contains("zyxwvutsrqponmlkjihgfedcba321")
            && srr.Contains("max_tokens")
            && srr.Contains("\"effort\":\"high\"")
            && srr.Contains("\"stream\":true"));
    }

    // --------------------------------------------------------------
    static void TestSummarize()
    {
        var r = SecretRedactor.RedactJson(Bytes("{\"password\":\"a\",\"access_token\":\"b\",\"c\":\"sk-abcdefghijklmnop12345\"}"));
        var s = SecretRedactor.Summarize(r.Stats);
        CheckTrue("Summarize", () => s.Contains("password") && s.Contains("OpenAI key") && s.Contains("\u00d7"));
    }

    // --------------------------------------------------------------
    static void TestNotices()
    {
        const string notice = "⚠️ **Proxy notice:** content was redacted.";

        // SSE: injects before [DONE] and keeps the closing
        var sse = Bytes("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n");
        var injected = NoticeInjector.Inject(sse, "text/event-stream; charset=utf-8", notice);
        CheckTrue("SSE injects", () => injected != null);
        var ts = Str(injected!);
        CheckTrue("SSE notice before DONE", () => ts.Contains(notice) && ts.IndexOf(notice) < ts.IndexOf("data: [DONE]") && ts.EndsWith("data: [DONE]\n\n"));

        // The injected chunk is valid JSON
        var beforeDone = ts[..ts.IndexOf("data: [DONE]", StringComparison.Ordinal)];
        var chunk = beforeDone[(beforeDone.LastIndexOf("data: ", StringComparison.Ordinal) + 6)..].Trim();
        CheckTrue("SSE chunk valid JSON", () => JsonNode.Parse(chunk) is JsonObject o && o["choices"] is JsonArray);

        // Non-streaming JSON: appends to the last choice
        var json = Bytes("{\"id\":\"x\",\"object\":\"chat.completion\",\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":\"Hello world\"},\"finish_reason\":\"stop\"}],\"usage\":{\"total_tokens\":3}}");
        var jInjected = NoticeInjector.Inject(json, "application/json", notice);
        CheckTrue("JSON injects", () => jInjected != null);
        var tj = Str(jInjected!);
        CheckTrue("JSON appends to content", () => tj.Contains("Hello world\\n\\n" + notice));
        var parsed = JsonNode.Parse(tj);
        CheckTrue("JSON parses after injection", () => parsed is JsonObject);
        CheckTrue("JSON keeps structure", () => tj.Contains("\"usage\"") && tj.Contains("\"total_tokens\":3"));

        // Without [DONE] -> appends at the end
        var sse2 = Bytes("data: {}\n\n");
        var inj2 = NoticeInjector.Inject(sse2, "text/event-stream", notice);
        CheckTrue("SSE without DONE appends", () => inj2 != null && Str(inj2!).EndsWith("data: [DONE]\n\n") is false && Str(inj2!).Contains(notice));

        // Partitioned content (array) in JSON
        var parts = Bytes("{\"choices\":[{\"message\":{\"content\":[{\"type\":\"text\",\"text\":\"hi\"}]}}]}");
        var inj3 = NoticeInjector.Inject(parts, "application/json", notice);
        CheckTrue("JSON parts append", () => inj3 != null && Str(inj3!).Contains("hi\\n\\n" + notice));

        // Responses API SSE -> response.output_text.delta event before [DONE]
        var rss = Bytes("event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"oi\"}\n\ndata: [DONE]\n\n");
        var injR = NoticeInjector.Inject(rss, "text/event-stream", notice);
        CheckTrue("Responses SSE injects", () => injR != null);
        var tr = Str(injR!);
        CheckTrue("Responses SSE right event", () => tr.Contains("event: response.output_text.delta")
            && tr.Contains("\"type\":\"response.output_text.delta\"")
            && tr.IndexOf(notice) < tr.IndexOf("data: [DONE]")
            && tr.EndsWith("data: [DONE]\n\n"));

        // Anthropic SSE -> content_block_delta event with text_delta
        var ans = Bytes("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\ndata: [DONE]\n\n");
        var injA = NoticeInjector.Inject(ans, "text/event-stream", notice);
        CheckTrue("Anthropic SSE injects", () => injA != null);
        var ta = Str(injA!);
        CheckTrue("Anthropic SSE right event", () => ta.Contains("event: content_block_delta")
            && ta.Contains("\"type\":\"text_delta\"")
            && ta.IndexOf(notice) < ta.IndexOf("data: [DONE]"));

        // Responses API JSON -> appends output_text part
        var rjson = Bytes("{\"id\":\"rsp\",\"object\":\"response\",\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"hi\"}]}]}");
        var injRJ = NoticeInjector.Inject(rjson, "application/json", notice);
        CheckTrue("Responses JSON injects", () => injRJ != null && Str(injRJ!).Contains("output_text") && Str(injRJ!).Contains("hi\\n\\n" + notice));

        // Anthropic Messages API JSON -> appends to the last text block
        var anj = Bytes("{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"Hello\"}],\"stop_reason\":\"end_turn\"}");
        var injAN = NoticeInjector.Inject(anj, "application/json", notice);
        CheckTrue("Anthropic JSON injects", () => injAN != null
            && Str(injAN!).Contains("Hello\\n\\n" + notice)
            && Str(injAN!).Contains("\"stop_reason\""));

        // Anthropic JSON without a text part -> creates one
        var anj2 = Bytes("{\"id\":\"msg_2\",\"type\":\"message\",\"content\":[{\"type\":\"tool_use\",\"id\":\"t\",\"name\":\"x\",\"input\":{}}]}");
        var injAN2 = NoticeInjector.Inject(anj2, "application/json", notice);
        CheckTrue("Anthropic JSON adds text part", () => injAN2 != null
            && Str(injAN2!).Contains("\"type\":\"text\"")
            && Str(injAN2!).Contains(notice));

        // Unsupported content-type -> null (body intact)
        CheckTrue("unknown ctype -> null", () => NoticeInjector.Inject(Bytes("plain"), "text/plain", notice) is null);
    }

    // --------------------------------------------------------------
    // New layers: long strings, key:value context, expanded names
    // --------------------------------------------------------------
    static void TestExtendedDetection()
    {
        // Layer 4 - long strings (URL-safe token >= 28, entropy)
        var l1 = SecretRedactor.RedactJson(Bytes("{\"c\":\"the token is 4v_wJ9rLsbLcFvwOGCOIA5h10EGzD6ZD43UAFNG_bq4 end\"}"));
        CheckTrue("longString 4v_ masked", () => l1.Changed
            && !Str(l1.Data).Contains("4v_wJ9r")
            && l1.Stats.ByKind.GetValueOrDefault("suspicious_key") == 1);

        var l2 = SecretRedactor.RedactJson(Bytes("{\"c\":\"supercalifragilisticexpialidocious simple\"}"));
        CheckTrue("longString monotone not masked", () => !l2.Changed);

        var l3 = SecretRedactor.RedactJson(Bytes("{\"c\":\"AbC12345DeF67890GhIjklmNopQrSt\"}"));
        CheckTrue("longString mixed masked", () => l3.Changed && l3.Stats.LongStringRedactions == 1);

        var l4 = SecretRedactor.RedactJson(Bytes("{\"c\":\"4v_wJ9rLsbLcFvwOGCOIA5h10EGzD6ZD43UAFNG_bq4\"}"), detectByLongStrings: false);
        CheckTrue("longString off passes", () => !l4.Changed && Str(l4.Data).Contains("4v_wJ9r"));

        // Layer 3 - key:value context in text (short 8-char format, so only this layer catches it)
        var content = "config: \\\"LocalKey\\\": \\\"abc12345\\\"";
        var k1 = SecretRedactor.RedactJson(Bytes("{\"messages\":[{\"role\":\"user\",\"content\":\"" + content + "\"}]}"));
        CheckTrue("context LocalKey masks value", () => k1.Changed
            && !Str(k1.Data).Contains("abc12345")
            && Str(k1.Data).Contains("LocalKey")
            && k1.Stats.ByKind.GetValueOrDefault("key_in_text") == 1);

        var k2 = SecretRedactor.RedactJson(
            Bytes("{\"messages\":[{\"role\":\"user\",\"content\":\"" + content + "\"}]}"), detectByKeyValueContext: false);
        CheckTrue("context off passes", () => !k2.Changed && Str(k2.Data).Contains("abc12345"));

        // KEY=value without quotes
        var k3 = SecretRedactor.RedactJson(Bytes("{\"c\":\"use LOCAL_KEY=abcdefgh1234 and continue\"}"));
        CheckTrue("context KEY=value", () => k3.Changed && !Str(k3.Data).Contains("abcdefgh1234"));

        // Layer 1 - expanded names (LocalKey is a sensitive field in structured JSON)
        var f1 = SecretRedactor.RedactJson(Bytes("{\"LocalKey\":\"abc\"}"));
        CheckTrue("field LocalKey", () => f1.Changed
            && Str(f1.Data).Contains("\"LocalKey\":\"" + SecretRedactor.DefaultMask + "\"")
            && f1.Stats.FieldRedactions == 1);

        var f2 = SecretRedactor.RedactJson(Bytes("{\"connection\":{\"local_key\":\"x\"},\"secret_key\":\"y\"}"));
        CheckTrue("fields local_key/secret_key", () => f2.Changed
            && !Str(f2.Data).Contains("local_key\":\"x\"")
            && f2.Stats.FieldRedactions == 2);

        // byFieldName off lets the value through (no formats/context)
        var f3 = SecretRedactor.RedactJson(Bytes("{\"password\":\"hunter2\"}"), detectByFieldName: false);
        CheckTrue("byFieldName off passes", () => !f3.Changed && Str(f3.Data).Contains("hunter2"));

        // Combination: long value in context still counts only 1 (context runs before longStrings)
        var c1 = SecretRedactor.RedactJson(Bytes("{\"c\":\"api_key=\\\"4v_wJ9rLsbLcFvwOGCOIA5h10EGzD6ZD43UAFNG_bq4\\\"\"}"));
        CheckTrue("context+long not duplicated", () => c1.Changed && c1.Stats.ByKind.GetValueOrDefault("key_in_text") == 1
            && c1.Stats.ByKind.GetValueOrDefault("suspicious_key") == 0);
    }

    // --------------------------------------------------------------
    // Round 2 fixes: symbol passwords, AWS keys (context + field + format), URL credentials
    // --------------------------------------------------------------
    static void TestRedactionGaps()
    {
        // 1. Password with symbols - the ENTIRE value is masked (no suffix leak after '!')
        var g1 = SecretRedactor.RedactJson(Bytes("{\"c\":\"Server=wz;Database=app;UserId=sa;Password=SenhaForte!2026#@$;TrustServerCertificate=True\"}"));
        CheckTrue("symbol password fully masked", () => g1.Changed
            && !Str(g1.Data).Contains("SenhaForte")
            && !Str(g1.Data).Contains("!2026")
            && g1.Stats.Total == 1
            && g1.Stats.ByKind.GetValueOrDefault("key_in_text") == 1);

        // 2. AWS secret access key (base64 with / + and =) caught by context name in free text
        var g2 = SecretRedactor.RedactJson(Bytes("{\"c\":\"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY+1\"}"));
        CheckTrue("aws secret base64 context", () => g2.Changed
            && !Str(g2.Data).Contains("wJalr")
            && !Str(g2.Data).Contains("K7MDENG")
            && g2.Stats.Total == 1
            && g2.Stats.ByKind.GetValueOrDefault("key_in_text") == 1);

        // 3. AWS credential names in structured JSON are masked as fields (kind "aws")
        var g3 = SecretRedactor.RedactJson(Bytes("{\"aws\":{\"aws_access_key_id\":\"AKIAIOSFODNN7EXAMPLE\",\"aws_secret_access_key\":\"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"}}"));
        CheckTrue("aws fields masked", () => g3.Changed
            && Str(g3.Data).Contains("\"aws\"")
            && !Str(g3.Data).Contains("AKIAIOSFODNN7")
            && !Str(g3.Data).Contains("wJalr")
            && g3.Stats.FieldRedactions == 2
            && g3.Stats.ByKind.GetValueOrDefault("aws") == 2);

        // 4. Real AWS key id format still matched (all real prefixes now)
        var g4 = SecretRedactor.RedactJson(Bytes("{\"c\":\"credentials AKIAIOSFODNN7EXAMPLE here\"}"));
        CheckTrue("AKIA real format masked", () => g4.Changed
            && !Str(g4.Data).Contains("AKIAIOSFODNN7")
            && g4.Stats.ByKind.GetValueOrDefault("aws") == 1);

        // 5. Regression: AKIA with hyphen/lowercase is NOT a real format -> stays unmasked
        var g5 = SecretRedactor.RedactJson(Bytes("{\"c\":\"access_key_fake: AKIA-test1234567890ABCDEF\"}"));
        CheckTrue("AKIA hyphen stays unmasked", () => !g5.Changed && Str(g5.Data).Contains("AKIA-test"));

        // 6. URL-embedded credentials: scheme kept, user:pass@ masked
        var g6 = SecretRedactor.RedactJson(Bytes("{\"c\":\"https://admin:SuperSecret!123@db.winzone.local:5432/postgres\"}"));
        CheckTrue("url https creds masked", () => g6.Changed
            && Str(g6.Data).Contains("https://")
            && !Str(g6.Data).Contains("admin")
            && !Str(g6.Data).Contains("SuperSecret")
            && g6.Stats.ByKind.GetValueOrDefault("url_cred") == 1);

        var g6b = SecretRedactor.RedactJson(Bytes("{\"c\":\"ftp://deploy:ChaveForte%2026@host.exemplo/arquivos\"}"));
        CheckTrue("url ftp creds masked", () => g6b.Changed
            && Str(g6b.Data).Contains("ftp://")
            && !Str(g6b.Data).Contains("deploy")
            && !Str(g6b.Data).Contains("ChaveForte"));

        // 7. client_secret in free text (context name) still masked, no double count
        var g7 = SecretRedactor.RedactJson(Bytes("{\"c\":\"oauth client_secret=ctest-abcdefghijklmnopqrstuvwxyz123456\"}"));
        CheckTrue("client_secret in text", () => g7.Changed
            && !Str(g7.Data).Contains("ctest-")
            && g7.Stats.ByKind.GetValueOrDefault("key_in_text") == 1
            && g7.Stats.ByKind.GetValueOrDefault("suspicious_key") == 0);
    }

    // --------------------------------------------------------------
    static void TestConfigPaths()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "airproxy-cfgtest-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(tmp);

            // No config/ folder -> the base dir itself is used (legacy/dev layout)
            CheckTrue("cfg falls back to base", () => ConfigPaths.ResolveConfigDir(tmp) == tmp);

            // config/ present -> it wins (deploy layout)
            var cfg = Path.Combine(tmp, "config");
            Directory.CreateDirectory(cfg);
            CheckTrue("cfg detected", () => ConfigPaths.ResolveConfigDir(tmp) == cfg);

            // Relative config file names resolve under the config folder
            CheckTrue("cfg relative file", () => ConfigPaths.ResolveFile("redaction.json", cfg) == Path.Combine(cfg, "redaction.json"));

            // Absolute paths are returned untouched
            var abs = Path.Combine(tmp, "other", "cert.pem");
            CheckTrue("cfg absolute untouched", () => ConfigPaths.ResolveFile(abs, cfg) == abs);

            // "../" escapes back to the deploy root (one level above config)
            CheckTrue("cfg ../ escapes to root", () => ConfigPaths.ResolveFile("..\\proxy-cert.pem", cfg) == Path.Combine(tmp, "proxy-cert.pem"));
        }
        finally
        {
            try { Directory.Delete(tmp, recursive: true); } catch { }
        }
    }

    // --------------------------------------------------------------
    // --------------------------------------------------------------
    static void TestRedactionAllow()
    {
        // 1) No allow-list: the 28-char kebab-case filename is still masked (regression guard).
        var r1 = SecretRedactor.RedactJson(Bytes("{\"prompt\":\"file ACME-1234-v2-WidgetApp-Module-Plan.md x\"}"));
        CheckTrue("allow off: filename masked", () => r1.Changed && !Str(r1.Data).Contains("ACME-1234-v2-WidgetApp-Module-Plan"));

        // 2) Allow-list matches the filename -> left untouched, not counted.
        var r2 = SecretRedactor.RedactJson(Bytes("{\"prompt\":\"file ACME-1234-v2-WidgetApp-Module-Plan.md x\"}"),
            allow: new[] { "^ACME-[0-9]{3,5}-" });
        CheckTrue("allow matches filename", () => !r2.Changed && Str(r2.Data).Contains("ACME-1234-v2-WidgetApp-Module-Plan.md"));

        // 3) Real format keys are NEVER exempted, even under a matching allow pattern.
        var r3 = SecretRedactor.RedactJson(Bytes("{\"prompt\":\"key sk-abc123456789012345678 x\"}"),
            allow: new[] { "^sk-" });
        CheckTrue("allow never exempts sk-", () => r3.Changed && !Str(r3.Data).Contains("sk-abc123456789012345678"));

        // 4) A non-allowed random-looking token is still masked when the allow-list exists.
        var r4 = SecretRedactor.RedactJson(Bytes("{\"prompt\":\"token AaBbCcDdEeFfGgHhIiJjKkLlMm123 x\"}"),
            allow: new[] { "^OTHER-" });
        CheckTrue("allow list keeps other tokens masked", () => r4.Changed);

        // 5) Invalid regex in the allow-list is ignored without crashing.
        var r5 = SecretRedactor.RedactJson(Bytes("{\"prompt\":\"file ACME-1234-v2-WidgetApp-Module-Plan.md x\"}"),
            allow: new[] { "(" });
        CheckTrue("allow invalid regex ignored", () => r5.Changed && !Str(r5.Data).Contains("ACME-1234-v2-WidgetApp-Module-Plan"));

        // 6) byFieldName still masks the whole value even if it matches the allow-list.
        var r6 = SecretRedactor.RedactJson(Bytes("{\"api_key\":\"ACME-1234-v2-WidgetApp-Module-Plan.md\"}"),
            allow: new[] { "^ACME-[0-9]{3,5}-" });
        CheckTrue("allow never exempts sensitive field values", () => r6.Changed && !Str(r6.Data).Contains("ACME-1234"));

        // 7) Works in a full Windows path too (JSON-escaped backslashes).
        var r7 = SecretRedactor.RedactJson(Bytes("{\"prompt\":\"C:\\Users\\demo\\plans\\ACME-1234-v2-WidgetApp-Module-Plan.md\"}"),
            allow: new[] { "^ACME-[0-9]{3,5}-" });
        CheckTrue("allow works in full path", () => !r7.Changed && Str(r7.Data).Contains("C:\\Users\\demo\\plans\\ACME-1234-v2-WidgetApp-Module-Plan.md"));
    }

    // --------------------------------------------------------------
    static void TestBase64ImageExemption()
    {
        // Deterministic high-entropy base64 blob: 28+ alnum runs between structural chars
        // (/ + =) - the exact shape the entropy scanner used to corrupt (litellm ASCII error).
        var rnd = new Random(7);
        static string Run(Random r, int n)
        {
            const string a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var sb = new StringBuilder(n);
            for (var i = 0; i < n; i++) sb.Append(a[r.Next(a.Length)]);
            return sb.ToString();
        }

        var b64 = string.Join("", Run(rnd, 32), "/", Run(rnd, 31), "+", Run(rnd, 30), "=", Run(rnd, 29), "/", Run(rnd, 28));

        // 1) OpenAI image_url.url data URL: intact end-to-end (pure ASCII, nothing masked).
        var body1 = Bytes("{\"model\":\"x\",\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"image_url\",\"image_url\":{\"url\":\"data:image/jpeg;base64," + b64 + "\"}}]}]}");
        var r1 = SecretRedactor.RedactJson(body1);
        CheckTrue("openai image_url data URL untouched", () => !r1.Changed && Str(r1.Data).Contains(b64.Substring(0, 40)));

        // 2) Anthropic source.data standalone base64 blob: intact.
        var body2 = Bytes("{\"type\":\"image\",\"source\":{\"type\":\"base64\",\"media_type\":\"image/jpeg\",\"data\":\"" + b64 + "\"}}");
        var r2 = SecretRedactor.RedactJson(body2);
        CheckTrue("anthropic source.data blob untouched", () => !r2.Changed && Str(r2.Data).Contains(b64.Substring(0, 40)));

        // 3) Data URL inline amid prose: the blob region stays, output still pure ASCII.
        var body3 = Bytes("{\"prompt\":\"look: data:image/png;base64," + b64 + " end\"}");
        var r3 = SecretRedactor.RedactJson(body3);
        CheckTrue("inline data URL in prose intact", () => !r3.Changed && Str(r3.Data).Contains(b64.Substring(0, 40)));

        // 4) A real format key in the same string as a blob is STILL masked (security guard).
        var body4 = Bytes("{\"prompt\":\"key sk-abc123456789012345678, img data:image/png;base64," + b64 + "\"}");
        var r4 = SecretRedactor.RedactJson(body4);
        CheckTrue("format key still masked next to blob", () => r4.Changed && !Str(r4.Data).Contains("sk-abc123456789012345678"));

        // 5) Sensitive field name always masks the whole value, even a data URL.
        var body5 = Bytes("{\"api_key\":\"data:image/jpeg;base64," + b64 + "\"}");
        var r5 = SecretRedactor.RedactJson(body5);
        CheckTrue("api_key field still masks image payload", () => r5.Changed && !Str(r5.Data).Contains(b64.Substring(0, 20)));

        // 6) Toggle off (exemptBase64=false) restores the legacy corruption (regression guard).
        var r6 = SecretRedactor.RedactJson(body1, exemptBase64: false);
        CheckTrue("exemptBase64=false: image payload masked again (legacy)", () => r6.Changed);

        // 7) Kebab-case filename: NOT base64 (no /+=), too short - still masked.
        var r7 = SecretRedactor.RedactJson(Bytes("{\"prompt\":\"file ACME-1234-v2-WidgetApp-Module-Plan.md x\"}"));
        CheckTrue("kebab filename still masked (not base64)", () => r7.Changed && !Str(r7.Data).Contains("ACME-1234-v2-WidgetApp-Module-Plan"));

        // 8) Short token (< 100): never exempted - still scanned and masked.
        var r8 = SecretRedactor.RedactJson(Bytes("{\"prompt\":\"token AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQq1234 x\"}"));
        CheckTrue("short random token still masked", () => r8.Changed);

        // 9) Long pure-alnum run WITHOUT /+= is not base64 by our rule - still masked.
        var longAlnum = Run(rnd, 120);
        var r9 = SecretRedactor.RedactJson(Bytes("{\"prompt\":\"tok " + longAlnum + " x\"}"));
        CheckTrue("long alnum run without /+= still masked", () => r9.Changed && !Str(r9.Data).Contains(longAlnum));

        // 10) Allow-list keeps working together with the base64 exemption.
        var r10 = SecretRedactor.RedactJson(body3, allow: new[] { "^look:" });
        CheckTrue("allow + base64 exemption coexist", () => !r10.Changed && Str(r10.Data).Contains(b64.Substring(0, 40)));
    }

    static void TestPreviews()
    {
        // Format detection collects a category-only preview, never content
        var r1 = SecretRedactor.RedactJson(Bytes("{\"content\":\"use sk-abcdefghijklmnop123 x\"}"));
        CheckTrue("preview format masked", () => r1.Stats.Previews.Count == 1
            && r1.Stats.Previews[0].Kind == "openai");

        // Field-name detection preview
        var r2 = SecretRedactor.RedactJson(Bytes("{\"password\":\"supersecret123\"}"));
        CheckTrue("preview field masked", () => r2.Stats.Previews.Count == 1
            && r2.Stats.Previews[0].Kind == "password");

        // key=value context preview
        var r3 = SecretRedactor.RedactJson(Bytes("{\"c\":\"use LOCAL_KEY=abcdefgh1234 and continue\"}"));
        CheckTrue("preview context masked", () => r3.Stats.Previews.Count == 1
            && r3.Stats.Previews[0].Kind == "key_in_text");

        // Long-string preview (layer still works when enabled)
        var r4 = SecretRedactor.RedactJson(Bytes("{\"c\":\"4v_wJ9rLsbLcFvwOGCOIA5h10EGzD6ZD43UAFNG_bq4\"}"));
        CheckTrue("preview longString masked", () => r4.Stats.Previews.Count == 1
            && r4.Stats.Previews[0].Kind == "suspicious_key");

        // Long strings disabled -> no detection, no preview (current default config)
        var r5 = SecretRedactor.RedactJson(Bytes("{\"c\":\"4v_wJ9rLsbLcFvwOGCOIA5h10EGzD6ZD43UAFNG_bq4\"}"), detectByLongStrings: false);
        CheckTrue("preview longString off none", () => !r5.Changed && r5.Stats.Previews.Count == 0);

        // Previews capped at 6 even with many detections
        var builder = new StringBuilder();
        for (var i = 0; i < 9; i++) { builder.Append("sk-key").Append(i + 1).Append("abcdefghijklmnopqrs "); }
        var many = builder.ToString().TrimEnd();
        var r6 = SecretRedactor.RedactJson(Bytes("{\"c\":\"" + many + "\"}"));
        CheckTrue("previews capped at 6", () => r6.Stats.Total == 9 && r6.Stats.Previews.Count == 6);

        // FormatPreviews renders readable, category-only text (no value prefix)
        var text = SecretRedactor.FormatPreviews(r1.Stats.Previews);
        CheckTrue("FormatPreviews text", () => text.Contains("OpenAI key") && text.Contains("detected") && !text.Contains("sk-a"));
    }

    // --------------------------------------------------------------
    // Multi-upstream router (Item 2)
    // --------------------------------------------------------------
    // --------------------------------------------------------------
    // Fail-closed body inspection (Item: InspectionPolicy)
    // --------------------------------------------------------------
    static void TestInspectionPolicy()
    {
        var def = new InspectionOptions(); // application/json: inspect, default: block

        // Inspect: JSON is allowed.
        CheckTrue("json -> inspect", () => InspectionPolicy.Decide(def, true, "application/json") == InspectionPolicy.ActionInspect);
        CheckTrue("json charset -> inspect", () => InspectionPolicy.Decide(def, true, "application/json; charset=utf-8") == InspectionPolicy.ActionInspect);
        CheckTrue("+json subtype -> inspect", () => InspectionPolicy.Decide(def, true, "application/problem+json") == InspectionPolicy.ActionInspect);
        CheckTrue("case-insensitive", () => InspectionPolicy.Decide(def, true, "Application/JSON") == InspectionPolicy.ActionInspect);

        // Block: unknown / explicitly blocked types with a body.
        CheckTrue("xml -> block", () => InspectionPolicy.Decide(def, true, "application/xml") == InspectionPolicy.ActionBlock);
        CheckTrue("octet-stream -> block", () => InspectionPolicy.Decide(def, true, "application/octet-stream") == InspectionPolicy.ActionBlock);
        CheckTrue("multipart -> block", () => InspectionPolicy.Decide(def, true, "multipart/form-data; boundary=x") == InspectionPolicy.ActionBlock);
        CheckTrue("form-urlencoded -> block", () => InspectionPolicy.Decide(def, true, "application/x-www-form-urlencoded") == InspectionPolicy.ActionBlock);
        CheckTrue("text/plain -> block (default)", () => InspectionPolicy.Decide(def, true, "text/plain") == InspectionPolicy.ActionBlock);
        CheckTrue("no content-type -> block", () => InspectionPolicy.Decide(def, true, null) == InspectionPolicy.ActionBlock);

        // GET (no body allowed) passes regardless of content-type.
        CheckTrue("GET never blocked", () => InspectionPolicy.Decide(def, false, "application/xml") == InspectionPolicy.ActionInspect);
        CheckTrue("no body -> pass", () => InspectionPolicy.Decide(def, true, "application/xml", hasBody: false) == InspectionPolicy.ActionInspect);

        // inspect declared for a non-JSON type fails closed (blocked) in this iteration.
        var custom = new InspectionOptions();
        custom.ByContentType["text/plain"] = "inspect";
        CheckTrue("text/plain inspect -> block (not implemented)", () => InspectionPolicy.Decide(custom, true, "text/plain") == InspectionPolicy.ActionBlock);
        CheckTrue("custom json override -> inspect", () => InspectionPolicy.Decide(custom, true, "application/json") == InspectionPolicy.ActionInspect);

        // Disabled = everything passes.
        var off = new InspectionOptions { Enabled = false };
        CheckTrue("disabled -> inspect", () => InspectionPolicy.Decide(off, true, "application/xml") == InspectionPolicy.ActionInspect);
    }

    // --------------------------------------------------------------
    // Unified secret detector (Sprint 2)
    // --------------------------------------------------------------
    static void TestDetector()
    {
        var opts = new DetectOptions();

        // --- Shannon entropy ---
        CheckTrue("entropy random high", () => SecretDetector.ShannonEntropy("XyZ0pQr9mN2vW7sT4uL8kK1jH6gF5dS3aBc") > 3.0);
        CheckTrue("entropy monotone low", () => SecretDetector.ShannonEntropy(new string('a', 40)) < 0.5);

        // --- Known formats: category + confidence + position, never the value ---
        var openai = SecretDetector.Detect("key sk-abcde12345fghij67890 end", opts);
        CheckTrue("format openai", () => openai.Count == 1 && openai[0].Category == "openai"
            && openai[0].Detector == SecretDetector.DetectorFormat
            && openai[0].Confidence == Confidence.High
            && openai[0].Start == 4 && openai[0].Length == 23);

        var ant = SecretDetector.Detect("use sk-ant-api03-abcdefghijklmnopqrstuvwxyz12", opts);
        CheckTrue("format anthropic", () => ant.Count == 1 && ant[0].Category == "anthropic" && ant[0].Length >= 28);

        var stripe = SecretDetector.Detect("sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz1234567890", opts);
        CheckTrue("format stripe", () => stripe.Count == 1 && stripe[0].Category == "stripe");

        var gh = SecretDetector.Detect("token ghp_12345678901234567890123456789012345678", opts);
        CheckTrue("format github", () => gh.Count == 1 && gh[0].Category == "github" && gh[0].Confidence == Confidence.High);

        var gp = SecretDetector.Detect("github_pat_11ABCDEFG0abcdefghijklmnopqrstuvwxyz1234", opts);
        CheckTrue("format github_pat", () => gp.Count == 1 && gp[0].Category == "github");

        var goog = SecretDetector.Detect("AIzaSyA1234567890abcdefghijklmnopqrstuv", opts);
        CheckTrue("format google", () => goog.Count == 1 && goog[0].Category == "google");

        var slack = SecretDetector.Detect("xoxb-1234567890-123456789012-abcdefghijklmn", opts);
        CheckTrue("format slack", () => slack.Count == 1 && slack[0].Category == "slack");

        var npm = SecretDetector.Detect("npm_ab1c2d3e4f5g6h7i8j9k0l1m2n3o4p5q6r", opts);
        CheckTrue("format npm", () => npm.Count == 1 && npm[0].Category == "npm");

        var aws = SecretDetector.Detect("aws AKIAIOSFODNN7EXAMPLE end", opts);
        CheckTrue("format aws", () => aws.Count == 1 && aws[0].Category == "aws" && aws[0].Length == 20);

        var jwt = SecretDetector.Detect("tok eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSM ABC", opts);
        CheckTrue("format jwt", () => jwt.Count == 1 && jwt[0].Category == "jwt");

        var pem = "-----BEGIN PRIVATE KEY-----\nMIIEVQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----";
        var pk = SecretDetector.Detect(pem, opts);
        CheckTrue("format private_key", () => pk.Count == 1 && pk[0].Category == "private_key");

        var bearer = SecretDetector.Detect("Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456", opts);
        CheckTrue("format bearer masks only the token", () => bearer.Count == 1
            && bearer[0].Category == "bearer"
            && bearer[0].Start == "Authorization: Bearer ".Length);

        // --- Context layer ---
        var ctx = SecretDetector.Detect("config LocalKey: abcdefgh1234 x", opts);
        CheckTrue("context LocalKey", () => ctx.Count == 1
            && ctx[0].Detector == SecretDetector.DetectorContext
            && ctx[0].Category == SecretDetector.KindKeyValue);

        // --- Entropy layer (never alone: threshold + random-look guard) ---
        var ent = SecretDetector.Detect("tok 4v_wJ9rLsbLcFvwOGCOIA5h10EGzD6ZD43UAFNG_bq4 end", opts);
        CheckTrue("entropy long string", () => ent.Count == 1
            && ent[0].Detector == SecretDetector.DetectorEntropy
            && ent[0].Category == SecretDetector.KindLongString);

        // A narrow-alphabet token (~4.3 bits/char) is flagged at the default 3.0 but skipped at 4.5
        var narrowAlphabet = "abcdefghij0123456789";
        var narrow = new string(Enumerable.Range(0, 36).Select(i => narrowAlphabet[i % 20]).ToArray());
        CheckTrue("entropy narrow alphabet flagged at 3.0", () => SecretDetector.Detect(narrow, opts).Count == 1);
        CheckTrue("entropy threshold 4.5 skips", () => SecretDetector.Detect(narrow, new DetectOptions { EntropyThreshold = 4.5 }).Count == 0);

        // --- False positives ---
        CheckTrue("fp git sha ignored", () => SecretDetector.Detect("commit a5f3c8e2b9d147f0e6c8a1b2d3e4f5a6b7c8d9e0", opts).Count == 0);
        CheckTrue("fp uuid ignored", () => SecretDetector.Detect("bug 550e8400-e29b-41d4-a716-446655440000", opts).Count == 0);
        CheckTrue("fp prose ignored", () => SecretDetector.Detect("the quick brown fox jumps over the lazy dog again and again", opts).Count == 0);
        CheckTrue("fp monotone ignored", () => SecretDetector.Detect(new string('a', 40), opts).Count == 0);
        CheckTrue("fp long word ignored", () => SecretDetector.Detect("supercalifragilisticexpialidocious word", opts).Count == 0);

        // --- Layer toggles ---
        CheckTrue("byFormats off", () => SecretDetector.Detect("sk-abcde12345fghij67890", new DetectOptions { ByFormats = false }).Count == 0);
        CheckTrue("byContext off", () => SecretDetector.Detect("LocalKey: abcdefgh1234", new DetectOptions { ByKeyValueContext = false }).Count == 0);
        CheckTrue("byLongStrings off", () => SecretDetector.Detect("4v_wJ9rLsbLcFvwOGCOIA5h10EGzD6ZD43UAFNG_bq4", new DetectOptions { ByLongStrings = false }).Count == 0);
        CheckTrue("null/empty input", () => SecretDetector.Detect(null, opts).Count == 0 && SecretDetector.Detect("", opts).Count == 0);

        // --- Overlap resolution (format > context > entropy) ---
        CheckTrue("overlap format wins over entropy", () =>
            SecretDetector.Detect("sk-abcde12345fghij67890abcdefghijklmnop", opts) is { Count: 1 } f0
                && f0[0].Detector == SecretDetector.DetectorFormat);
        CheckTrue("overlap context wins over entropy", () =>
            SecretDetector.Detect("api_key=\"4v_wJ9rLsbLcFvwOGCOIA5h10EGzD6ZD43UAFNG_bq4\"", opts) is { Count: 1 } f1
                && f1[0].Category == SecretDetector.KindKeyValue);

        // --- End-to-end via the redactor: nested + free text, value never leaks ---
        var nested = SecretRedactor.RedactJson(Bytes("{\"deployment\":{\"environment\":{\"DATABASE_PASSWORD\":\"sup3rS3cr3tValue123\",\"CUSTOM_AUTH\":\"ghp_abcdefghijklmnopqrstuvwxyz0123456789\"}}}"));
        CheckTrue("nested credentials redacted", () => nested.Changed
            && !Str(nested.Data).Contains("sup3rS3cr3tValue123")
            && !Str(nested.Data).Contains("ghp_abcdefghijklmnopqrstuvwxyz0123456789"));

        var freeText = SecretRedactor.RedactJson(Bytes("{\"content\":\"My GitHub token is ghp_abcdefghijklmnopqrstuvwxyz0123456789, never share it\"}"));
        CheckTrue("free text github redacted", () => freeText.Changed && !Str(freeText.Data).Contains("ghp_abcdefghijklmnopqrstuvwxyz0123456789"));

        var noticeSource = SecretRedactor.RedactJson(Bytes("{\"content\":\"key sk-abcdefghijklmnop123 x\"}"));
        var notice = SecretRedactor.FormatPreviews(noticeSource.Stats.Previews);
        CheckTrue("notice leaks no content", () => notice.Contains("OpenAI key") && !notice.Contains("sk-"));
    }

    // --------------------------------------------------------------
    // Incremental SSE parser + streaming processor (Sprint 4)
    // --------------------------------------------------------------
    static List<SseEvent> ParseSse(string raw, int chunkSize)
    {
        var parser = new SseParser();
        var all = new List<SseEvent>();
        var bytes = Encoding.UTF8.GetBytes(raw);

        for (var i = 0; i < bytes.Length; i += chunkSize)
        {
            var count = Math.Min(chunkSize, bytes.Length - i);
            all.AddRange(parser.Feed(bytes.AsSpan(i, count)));
        }

        var final = parser.EndOfStream();
        if (final is not null)
        {
            all.Add(final);
        }

        return all;
    }

    static void TestSseParser()
    {
        var sse = "data: hello\n\ndata: world\n\n";
        var whole = ParseSse(sse, 100);
        CheckTrue("sse two events", () => whole.Count == 2
            && whole[0].Data == "hello" && whole[1].Data == "world"
            && whole[0].StartOffset == 0 && whole[0].EndOffset == 13
            && whole[1].StartOffset == 13 && whole[1].EndOffset == 26);

        var chunked = ParseSse(sse, 1);
        CheckTrue("sse chunked 1B identical", () => chunked.Count == whole.Count
            && chunked.Select(e => e.Data).SequenceEqual(whole.Select(e => e.Data)));

        var crlf = ParseSse("data: a\r\n\r\n", 100);
        CheckTrue("sse CRLF", () => crlf.Count == 1 && crlf[0].Data == "a");

        var multi = ParseSse("data: a\ndata: b\n\n", 100);
        CheckTrue("sse multi-line data", () => multi.Count == 1 && multi[0].Data == "a\nb");

        var named = ParseSse("event: ping\ndata: payload\n\n", 100);
        CheckTrue("sse event name", () => named.Count == 1 && named[0].EventName == "ping" && named[0].Data == "payload");

        var fields = ParseSse("id: 42\nretry: 3000\ndata: z\n\n", 100);
        CheckTrue("sse id/retry", () => fields.Count == 1 && fields[0].Id == "42" && fields[0].Retry == 3000);

        CheckTrue("sse comments no event", () => ParseSse(": keep-alive\n\n", 100).Count == 0);
        CheckTrue("sse empty input", () => ParseSse("", 100).Count == 0);

        var done = ParseSse("data: [DONE]\n\n", 100);
        CheckTrue("sse done", () => done.Count == 1 && done[0].IsDone && done[0].Data == "[DONE]");

        var doneNoBlank = ParseSse("data: [DONE]", 100);
        CheckTrue("sse done at EOF no blank", () => doneNoBlank.Count == 1 && doneNoBlank[0].IsDone);

        var partial = ParseSse("data: hi", 100);
        CheckTrue("sse partial at EOF", () => partial.Count == 1 && partial[0].Data == "hi" && !partial[0].IsDone);

        CheckTrue("sse cut at every boundary", () =>
        {
            const string tricky = "data: [DONE]\n\n";
            for (var size = 1; size <= tricky.Length; size++)
            {
                var evts = ParseSse(tricky, size);
                if (evts.Count != 1 || !evts[0].IsDone || evts[0].EndOffset != tricky.Length)
                {
                    return false;
                }
            }

            return true;
        });

        CheckTrue("sse unicode split", () =>
        {
            const string emoji = "data: olá 👋\ndata: fim\n\n";
            var evts = ParseSse(emoji, 3); // splits mid-multibyte on purpose
            return evts.Count == 1 && evts[0].Data == "olá 👋\nfim";
        });
    }

    static async Task<string> ProcessSseAsync(string input, string notice, int chunk = 1 << 20)
    {
        using var source = new MemoryStream(Encoding.UTF8.GetBytes(input));
        using var result = new MemoryStream();
        await SseStreamProcessor.ProcessAsync(source, result, notice, CancellationToken.None, chunk);
        return Encoding.UTF8.GetString(result.ToArray());
    }

    static void TestSseProcessor()
    {
        const string chat = "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n";
        var outp = ProcessSseAsync(chat, "⚠️ notice").GetAwaiter().GetResult();

        CheckTrue("proc notice before done", () =>
        {
            var idx = outp.IndexOf("⚠️ notice", StringComparison.Ordinal);
            var done = outp.IndexOf("data: [DONE]", StringComparison.Ordinal);
            return idx >= 0 && idx < done && outp.EndsWith("data: [DONE]\n\n");
        });

        CheckTrue("proc notice chunk valid JSON", () =>
        {
            var lastData = outp.LastIndexOf("data: {", StringComparison.Ordinal);
            var chunk = outp[(lastData + 6)..];
            chunk = chunk[..chunk.IndexOf("\n\n", StringComparison.Ordinal)];
            return JsonNode.Parse(chunk) is JsonObject o && o["choices"] is JsonArray;
        });

        var small = ProcessSseAsync(chat, "⚠️ notice", 4).GetAwaiter().GetResult();
        CheckTrue("proc chunking identical", () => small == outp);

        const string noDone = "data: {}\n\n";
        var nd = ProcessSseAsync(noDone, "XX").GetAwaiter().GetResult();
        CheckTrue("proc append when no done", () => nd.StartsWith(noDone) && nd.IndexOf("XX") > nd.IndexOf("data: {}"));
        CheckTrue("proc append exact format", () => nd == noDone + "\ndata: {\"choices\":[{\"delta\":{\"content\":\"\\n\\nXX\"}}]}\n\n");

        const string resp = "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"oi\"}\n\ndata: [DONE]\n\n";
        var ro = ProcessSseAsync(resp, "R").GetAwaiter().GetResult();
        CheckTrue("proc responses event", () => ro.Contains("event: response.output_text.delta\ndata: ")
            && ro.IndexOf("R") < ro.IndexOf("data: [DONE]")
            && ro.EndsWith("data: [DONE]\n\n"));

        const string anth = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\ndata: [DONE]\n\n";
        var ao = ProcessSseAsync(anth, "A").GetAwaiter().GetResult();
        CheckTrue("proc anthropic event", () => ao.Contains("event: content_block_delta\ndata: ")
            && ao.IndexOf("A") < ao.IndexOf("data: [DONE]"));

        // Real Anthropic stream (production shape): message_start -> content_block_start ->
        // deltas -> content_block_stop -> message_delta -> message_stop (no "[DONE]").
        // The notice must land between the last text delta and content_block_stop (while the
        // text block is still open, so @ai-sdk/anthropic renders it), exactly once, and the
        // stream must still end with message_stop.
        const string realAnth =
            "event: message_start\ndata: {\"type\":\"message_start\"}\n\n"
            + "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n"
            + "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n"
            + "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n"
            + "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"max_tokens\"},\"usage\":{}}\n\n"
            + "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
        var ra = ProcessSseAsync(realAnth, "A").GetAwaiter().GetResult();
        CheckTrue("proc real anthropic notice before content_block_stop", () =>
        {
            var iOk = ra.IndexOf("text\":\"ok\"}", StringComparison.Ordinal);
            var iNotice = ra.IndexOf("\\n\\nA", StringComparison.Ordinal);   // the notice delta text
            var iStop = ra.IndexOf("event: content_block_stop", StringComparison.Ordinal);
            var iMsgStop = ra.IndexOf("event: message_stop", StringComparison.Ordinal);
            return iOk >= 0 && iNotice > iOk && iStop >= 0 && iNotice < iStop
                && iMsgStop > iStop
                && ra.EndsWith("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");
        });
        CheckTrue("proc real anthropic notice once (guard)", () =>
        {
            var first = ra.IndexOf("\\n\\nA", StringComparison.Ordinal);
            return first >= 0 && ra.IndexOf("\\n\\nA", first + 1, StringComparison.Ordinal) < 0;
        });

        const string raw = "data: 1\n\ndata: 2\n\n";
        var pt = ProcessSseAsync(raw, string.Empty).GetAwaiter().GetResult();
        CheckTrue("proc passthrough identical", () => pt == raw);
    }

    // --------------------------------------------------------------
    // Protocol adapters (Sprint 5): SseProtocol/ replaces the lightweight
    // in-processor detection with per-protocol adapters + registry.
    // --------------------------------------------------------------
    static SseEvent Evt(string data, string? name = null)
        => new(name, data, null, null, 0, 0);

    static void TestSseProtocolAdapters()
    {
        // Registry resolution: first match wins, generic catch-all last.
        CheckTrue("resolve responses (event name)", () =>
            SseProtocolRegistry.Resolve(Evt("{}", "response.completed")) is OpenAiResponsesAdapter);
        CheckTrue("resolve responses (payload)", () =>
            SseProtocolRegistry.Resolve(Evt("{\"type\":\"response.output_text.delta\",\"delta\":\"oi\"}")) is OpenAiResponsesAdapter);
        CheckTrue("resolve anthropic", () =>
            SseProtocolRegistry.Resolve(Evt("{\"type\":\"content_block_delta\",\"index\":0}", "content_block_delta")) is AnthropicAdapter);
        CheckTrue("resolve anthropic (message_start)", () =>
            SseProtocolRegistry.Resolve(Evt("{}", "message_start")) is AnthropicAdapter);
        CheckTrue("resolve chat", () =>
            SseProtocolRegistry.Resolve(Evt("{\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}")) is OpenAiChatAdapter);
        CheckTrue("resolve generic", () =>
            SseProtocolRegistry.Resolve(Evt("{}")) is GenericSseAdapter
            && SseProtocolRegistry.Resolve(Evt("[DONE]")) is GenericSseAdapter);

        CheckTrue("adapter names", () =>
            new OpenAiResponsesAdapter().Name == "responses"
            && new AnthropicAdapter().Name == "anthropic"
            && new OpenAiChatAdapter().Name == "chat"
            && new GenericSseAdapter().Name == "generic");

        // Classification per protocol
        CheckTrue("classify terminal all protocols", () =>
            new OpenAiChatAdapter().Classify(Evt("[DONE]")) == SseEventKind.Terminal
            && new OpenAiResponsesAdapter().Classify(Evt("[DONE]")) == SseEventKind.Terminal
            && new AnthropicAdapter().Classify(Evt("[DONE]")) == SseEventKind.Terminal
            && new GenericSseAdapter().Classify(Evt("[DONE]")) == SseEventKind.Terminal);

        CheckTrue("classify chat error", () =>
            new OpenAiChatAdapter().Classify(Evt("{\"error\":{\"message\":\"x\"}}")) == SseEventKind.Error
            && new OpenAiChatAdapter().Classify(Evt("{}", "error")) == SseEventKind.Error);

        CheckTrue("classify chat start/content", () =>
            new OpenAiChatAdapter().Classify(Evt("{\"choices\":[{\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}]}")) == SseEventKind.Start
            && new OpenAiChatAdapter().Classify(Evt("{\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}")) == SseEventKind.Content);

        CheckTrue("classify responses start/content", () =>
            new OpenAiResponsesAdapter().Classify(Evt("{}", "response.created")) == SseEventKind.Start
            && new OpenAiResponsesAdapter().Classify(Evt("{\"type\":\"response.output_text.delta\",\"delta\":\"oi\"}")) == SseEventKind.Content);

        CheckTrue("classify anthropic start/content", () =>
            new AnthropicAdapter().Classify(Evt("{}", "message_start")) == SseEventKind.Start
            && new AnthropicAdapter().Classify(Evt("{\"type\":\"content_block_delta\"}", "content_block_delta")) == SseEventKind.Content);

        CheckTrue("classify anthropic message_stop terminal", () =>
            new AnthropicAdapter().Classify(Evt("{}", "message_stop")) == SseEventKind.Terminal);

        CheckTrue("classify anthropic content_block_stop terminal", () =>
            new AnthropicAdapter().Classify(Evt("{}", "content_block_stop")) == SseEventKind.Terminal);

        // Notice chunks: byte-exact per protocol (identical to Sprint 4 output)
        CheckTrue("chat notice chunk exact", () =>
            Str(new OpenAiChatAdapter().BuildNoticeChunk("N"))
                == "\ndata: {\"choices\":[{\"delta\":{\"content\":\"\\n\\nN\"}}]}\n\n");

        CheckTrue("responses notice chunk exact", () =>
            Str(new OpenAiResponsesAdapter().BuildNoticeChunk("N"))
                == "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"\\n\\nN\"}\n\n");

        CheckTrue("anthropic notice chunk exact", () =>
            Str(new AnthropicAdapter().BuildNoticeChunk("N"))
                == "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"\\n\\nN\"}}\n\n");

        CheckTrue("generic notice = chat notice", () =>
            Str(new GenericSseAdapter().BuildNoticeChunk("N"))
                == Str(new OpenAiChatAdapter().BuildNoticeChunk("N")));

        CheckTrue("chat notice chunk valid JSON", () =>
        {
            var chunk = Str(new OpenAiChatAdapter().BuildNoticeChunk("N"));
            var data = chunk[(chunk.IndexOf("data: {", StringComparison.Ordinal) + 6)..];
            var json = data[..data.IndexOf("\n\n", StringComparison.Ordinal)];
            return JsonNode.Parse(json) is JsonObject o && o["choices"] is JsonArray;
        });
    }

    // --------------------------------------------------------------
    // Authentication policy (multi-key) and rate limiting (Sprint 3)
    // --------------------------------------------------------------
    static void TestAuthenticationPolicy()
    {
        var single = new KeyOptions { LocalKey = "abc" };
        CheckTrue("single valid", () => AuthenticationPolicy.IsValidLocalKey("abc", single));
        CheckTrue("single invalid", () => !AuthenticationPolicy.IsValidLocalKey("xyz", single));
        CheckTrue("single null/empty", () => !AuthenticationPolicy.IsValidLocalKey(null, single)
            && !AuthenticationPolicy.IsValidLocalKey(string.Empty, single));
        CheckTrue("null keys", () => !AuthenticationPolicy.IsValidLocalKey("abc", null));

        var multi = new KeyOptions
        {
            LocalKey = "abc",
            LocalKeys = new List<string> { "def", "ghi" },
        };
        CheckTrue("multi primary", () => AuthenticationPolicy.IsValidLocalKey("abc", multi));
        CheckTrue("multi secondary", () => AuthenticationPolicy.IsValidLocalKey("def", multi)
            && AuthenticationPolicy.IsValidLocalKey("ghi", multi));
        CheckTrue("multi invalid", () => !AuthenticationPolicy.IsValidLocalKey("xyz", multi));

        // Admin access: the PRIMARY local key only (extra LocalKeys / route keys never reach /admin).
        CheckTrue("admin primary", () => AuthenticationPolicy.IsValidAdminKey("abc", single));
        CheckTrue("admin primary multi", () => AuthenticationPolicy.IsValidAdminKey("abc", multi));
        CheckTrue("admin extra rejected", () => !AuthenticationPolicy.IsValidAdminKey("def", multi)
            && !AuthenticationPolicy.IsValidAdminKey("ghi", multi));
        CheckTrue("admin invalid rejected", () => !AuthenticationPolicy.IsValidAdminKey("xyz", multi));
        CheckTrue("admin null/empty", () => !AuthenticationPolicy.IsValidAdminKey(null, multi)
            && !AuthenticationPolicy.IsValidAdminKey(string.Empty, multi));
        CheckTrue("admin null keys", () => !AuthenticationPolicy.IsValidAdminKey("abc", null));

        CheckTrue("key count single", () => AuthenticationPolicy.LocalKeyCount(single) == 1);
        CheckTrue("key count multi", () => AuthenticationPolicy.LocalKeyCount(multi) == 3);
        CheckTrue("key count null", () => AuthenticationPolicy.LocalKeyCount(null) == 0);
        CheckTrue("empty extra list", () => AuthenticationPolicy.LocalKeyCount(new KeyOptions { LocalKey = "a" }) == 1);
    }

    static void TestRateLimiter()
    {
        var now = DateTimeOffset.UtcNow;
        var rl = new RateLimiter(new RateLimitOptions
        {
            MaxRequestsPerWindow = 3,
            RequestWindowSeconds = 60,
            MaxFailuresPerWindow = 2,
            FailureWindowSeconds = 60,
            LockoutSeconds = 30,
        }, () => now);

        CheckTrue("allow under limit", () => rl.Check("1.2.3.4") == RateLimiter.Verdict.Allow);
        CheckTrue("allow at limit", () => rl.Check("1.2.3.4") == RateLimiter.Verdict.Allow
            && rl.Check("1.2.3.4") == RateLimiter.Verdict.Allow);
        CheckTrue("deny over limit", () => rl.Check("1.2.3.4") == RateLimiter.Verdict.TooManyRequests);
        CheckTrue("other key independent", () => rl.Check("5.6.7.8") == RateLimiter.Verdict.Allow);
        CheckTrue("request count", () => rl.RequestCount("1.2.3.4") == 3);

        now = now.AddMinutes(2);
        CheckTrue("window slides", () => rl.Check("1.2.3.4") == RateLimiter.Verdict.Allow
            && rl.RequestCount("1.2.3.4") == 1);

        // Brute-force lockout: 2 failures -> locked; lockout expires after 30s
        var now2 = DateTimeOffset.UtcNow;
        var rl2 = new RateLimiter(new RateLimitOptions
        {
            MaxFailuresPerWindow = 2,
            FailureWindowSeconds = 60,
            LockoutSeconds = 30,
        }, () => now2);

        rl2.RecordFailure("9.9.9.9");
        rl2.RecordFailure("9.9.9.9");
        CheckTrue("locked after 2 failures", () => rl2.Check("9.9.9.9") == RateLimiter.Verdict.LockedOut
            && rl2.FailureCount("9.9.9.9") == 2);

        now2 = now2.AddSeconds(31);
        CheckTrue("lockout expires", () => rl2.Check("9.9.9.9") == RateLimiter.Verdict.Allow);

        // Failures expire with their window
        var now3 = DateTimeOffset.UtcNow;
        var rl3 = new RateLimiter(new RateLimitOptions
        {
            MaxFailuresPerWindow = 2,
            FailureWindowSeconds = 60,
            LockoutSeconds = 30,
        }, () => now3);

        rl3.RecordFailure("z");
        now3 = now3.AddSeconds(61);
        rl3.RecordFailure("z");
        CheckTrue("failures expire", () => rl3.FailureCount("z") == 1
            && rl3.Check("z") == RateLimiter.Verdict.Allow);

        // Retry-After is always >= 1s
        CheckTrue("retry-after positive", () => rl.RetryAfterSeconds("5.6.7.8") >= 1
            && rl2.RetryAfterSeconds("9.9.9.9") >= 1);

        // Empty/unknown key maps to "unknown" without crashing
        CheckTrue("null key safe", () => { rl.Check(null!); rl.RecordFailure(null!); return true; });
    }

    // --------------------------------------------------------------
    // Security edges (Sprint 6): bearer parsing, multi-key auth,
    // route enumeration and concurrency (offline, no ASP.NET needed).
    // --------------------------------------------------------------
    static void TestSecurityEdges()
    {
        // Bearer parsing - auth bypass attempts
        CheckTrue("bearer exact", () => SecurityHelpers.ExtractBearerToken("Bearer abc") == "abc");
        CheckTrue("bearer lowercase", () => SecurityHelpers.ExtractBearerToken("bearer abc") == "abc");
        CheckTrue("bearer uppercase", () => SecurityHelpers.ExtractBearerToken("BEARER abc") == "abc");
        CheckTrue("bearer extra spaces", () => SecurityHelpers.ExtractBearerToken("Bearer   abc") == "abc");
        CheckTrue("bearer trailing space", () => SecurityHelpers.ExtractBearerToken("Bearer abc ") == "abc");
        CheckTrue("bearer no key", () => SecurityHelpers.ExtractBearerToken("Bearer") is null);
        CheckTrue("bearer empty value", () => SecurityHelpers.ExtractBearerToken("Bearer   ") is null);
        CheckTrue("basic is not bearer", () => SecurityHelpers.ExtractBearerToken("Basic dXNlcjpwYXNz") is null);
        CheckTrue("no prefix", () => SecurityHelpers.ExtractBearerToken("abc") is null);
        CheckTrue("null/empty", () => SecurityHelpers.ExtractBearerToken(null) is null
            && SecurityHelpers.ExtractBearerToken("") is null);

        // Multi-key auth edges
        var multi = new KeyOptions
        {
            LocalKey = "primary",
            LocalKeys = new List<string> { "second", " third ", "", " " },
        };
        CheckTrue("multi second key", () => AuthenticationPolicy.IsValidLocalKey("second", multi));
        CheckTrue("multi spaces literal", () => AuthenticationPolicy.IsValidLocalKey(" third ", multi)
            && !AuthenticationPolicy.IsValidLocalKey("third", multi));
        CheckTrue("multi blank rejected", () => !AuthenticationPolicy.IsValidLocalKey("", multi));
        CheckTrue("multi case-sensitive", () => !AuthenticationPolicy.IsValidLocalKey("Primary", multi)
            && !AuthenticationPolicy.IsValidLocalKey("SECOND", multi));
        CheckTrue("multi count includes blanks", () => AuthenticationPolicy.LocalKeyCount(multi) == 5);

        // Route enumeration: allowed-path guards, case and traversal
        var airouter = new RouteOptions
        {
            Name = "airouter",
            Prefix = "",
            Upstream = "https://api.airouter.ch",
            KeyRef = "AIROUTER",
            AllowedPaths = { "/v1/models", "/v1/chat/completions", "/v1/embeddings" },
        };
        var openrouter = new RouteOptions
        {
            Name = "openrouter",
            Prefix = "/openrouter",
            Upstream = "https://openrouter.ai/api",
            KeyRef = "OPENROUTER",
            AllowedPaths = { "/v1/*" },
        };
        var routes = new[] { airouter, openrouter };
        var keys = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["AIROUTER"] = "sk-airouter-abc",
            ["OPENROUTER"] = "sk-openrouter-xyz",
        };

        CheckTrue("enum exact allowed", () => RouteResolver.IsPathAllowed(airouter.AllowedPaths, "/v1/chat/completions"));
        CheckTrue("enum trailing slash blocked", () => !RouteResolver.IsPathAllowed(airouter.AllowedPaths, "/v1/chat/completions/"));
        CheckTrue("enum case blocked", () => !RouteResolver.IsPathAllowed(airouter.AllowedPaths, "/V1/CHAT/COMPLETIONS"));
        CheckTrue("enum dotdot blocked", () => !RouteResolver.IsPathAllowed(airouter.AllowedPaths, "/v1/chat/completions/../models"));
        CheckTrue("enum double slash blocked", () => !RouteResolver.IsPathAllowed(airouter.AllowedPaths, "//v1/chat/completions"));
        CheckTrue("enum encoded slash blocked", () => !RouteResolver.IsPathAllowed(airouter.AllowedPaths, "/v1/chat%2fcompletions"));
        CheckTrue("enum unknown path blocked", () => !RouteResolver.IsPathAllowed(airouter.AllowedPaths, "/v1/embeddings2"));

        CheckTrue("enum prefix segment boundary", () =>
            RouteResolver.PathMatchesPrefix("/openrouter/v1/models", "/openrouter")
            && !RouteResolver.PathMatchesPrefix("/openrouterX/v1/models", "/openrouter")
            && !RouteResolver.PathMatchesPrefix("//openrouter/v1", "/openrouter"));

        CheckTrue("enum resolve default", () =>
            RouteResolver.Resolve(routes, keys, "/v1/chat/completions") is { } r1
            && r1.Route.Name == "airouter"
            && r1.RewrittenPath == "/v1/chat/completions");

        CheckTrue("enum rewrite strips prefix", () =>
            RouteResolver.Resolve(routes, keys, "/openrouter/v1/models") is { } r2
            && r2.Route.Name == "openrouter"
            && r2.RewrittenPath == "/v1/models"
            && r2.Key == "sk-openrouter-xyz");

        // Concurrency: the rate limiter stays exact and exception-free under load
        CheckTrue("concurrency allows exactly the limit", () =>
        {
            var rl = new RateLimiter(new RateLimitOptions
            {
                MaxRequestsPerWindow = 100,
                RequestWindowSeconds = 60,
                MaxFailuresPerWindow = 100,
                FailureWindowSeconds = 60,
                LockoutSeconds = 60,
            }, () => DateTimeOffset.UtcNow);

            var allowed = 0;
            Parallel.For(0, 1000, _ =>
            {
                if (rl.Check("1.1.1.1") == RateLimiter.Verdict.Allow)
                {
                    Interlocked.Increment(ref allowed);
                }
            });

            return allowed == 100 && rl.RequestCount("1.1.1.1") == 100;
        });

        CheckTrue("concurrency keys independent", () =>
        {
            var rl = new RateLimiter(new RateLimitOptions { MaxRequestsPerWindow = 50, RequestWindowSeconds = 60 });
            Parallel.For(0, 200, i =>
            {
                rl.Check(i % 2 == 0 ? "a.a.a.a" : "b.b.b.b");
            });

            return rl.RequestCount("a.a.a.a") == 50 && rl.RequestCount("b.b.b.b") == 50;
        });

        CheckTrue("concurrency failures count exact", () =>
        {
            var rl = new RateLimiter(new RateLimitOptions
            {
                MaxFailuresPerWindow = 100,
                FailureWindowSeconds = 60,
                LockoutSeconds = 60,
            });
            Parallel.For(0, 100, _ => rl.RecordFailure("9.9.9.9"));

            return rl.FailureCount("9.9.9.9") == 100 && rl.Check("9.9.9.9") == RateLimiter.Verdict.LockedOut;
        });
    }

    static void TestRouting()
    {
        var airouter = new RouteOptions
        {
            Name = "airouter",
            Prefix = "",
            Upstream = "https://api.airouter.ch",
            KeyRef = "AIROUTER",
            AllowedPaths = { "/v1/models", "/v1/chat/completions", "/v1/embeddings" },
            RequestTimeoutMs = 300000,
        };

        var openrouter = new RouteOptions
        {
            Name = "openrouter",
            Prefix = "/openrouter",
            Upstream = "https://openrouter.ai/api",
            KeyRef = "OPENROUTER",
            AllowedPaths = { "/v1/*" },
        };

        var routes = new[] { airouter, openrouter };
        var keys = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["AIROUTER"] = "sk-airouter-abc",
            ["OPENROUTER"] = "sk-openrouter-xyz",
        };

        // Precedence: "" prefix matches everything, /openrouter matches on segment boundary
        var r1 = RouteResolver.Resolve(routes, keys, "/v1/chat/completions");
        CheckTrue("default route (prefix \"\")", () => r1 is not null && r1.Route.Name == "airouter"
            && r1.RewrittenPath == "/v1/chat/completions" && r1.Key == "sk-airouter-abc");

        var r2 = RouteResolver.Resolve(routes, keys, "/openrouter/v1/chat/completions");
        CheckTrue("openrouter route (longest prefix)", () => r2 is not null && r2.Route.Name == "openrouter"
            && r2.RewrittenPath == "/v1/chat/completions" && r2.Key == "sk-openrouter-xyz");

        // Segment boundary: /openrouterX does NOT match /openrouter -> falls to default
        var r3 = RouteResolver.Resolve(routes, keys, "/openrouterX/v1/models");
        CheckTrue("segment boundary (/openrouterX)", () => r3 is not null && r3.Route.Name == "airouter");

        // Prefix without route: no default route, nothing matches -> null (404); with default, falls into it
        var onlyOpenrouter = new[] { openrouter };
        var r4 = RouteResolver.Resolve(onlyOpenrouter, keys, "/foobar/v1/models");
        CheckTrue("unknown prefix (no default) -> null", () => r4 is null);

        var r4b = RouteResolver.Resolve(routes, keys, "/foobar/v1/models");
        CheckTrue("unknown prefix (with default) -> default", () => r4b is not null && r4b.Route.Name == "airouter");

        // Default without a configured key -> null (502/inactive route)
        var r5 = RouteResolver.Resolve(routes, new Dictionary<string, string>(), "/v1/chat/completions");
        CheckTrue("route without key -> key null", () => r5 is not null && r5.Key is null);

        // IsPathAllowed: exact + wildcard
        CheckTrue("allowed exact", () => RouteResolver.IsPathAllowed(airouter.AllowedPaths, "/v1/models"));
        CheckTrue("allowed block", () => !RouteResolver.IsPathAllowed(airouter.AllowedPaths, "/v1/responses"));
        CheckTrue("allowed wildcard", () => RouteResolver.IsPathAllowed(openrouter.AllowedPaths, "/v1/responses"));
        CheckTrue("allowed wildcard block outside", () => !RouteResolver.IsPathAllowed(openrouter.AllowedPaths, "/v2/completions"));
        CheckTrue("allowed empty = everything", () => RouteResolver.IsPathAllowed(new List<string>(), "/anything/at/all"));

        // Rewrite: prefix removed from the path to the upstream
        CheckTrue("rewrite removes prefix", () => RouteResolver.RewritePath("/openrouter/v1/models", "/openrouter") == "/v1/models");
        CheckTrue("rewrite empty prefix = intact", () => RouteResolver.RewritePath("/v1/models", "") == "/v1/models");

        // Key by keyRef and global fallback
        CheckTrue("keyRef resolves", () => RouteResolver.GetRouteKey(openrouter, keys) == "sk-openrouter-xyz");
        var fallback = new RouteOptions { Name = "x", Prefix = "" };
        CheckTrue("no keyRef uses fallback", () => RouteResolver.GetRouteKey(fallback, keys, "global-key") == "global-key");
        CheckTrue("keyRef without value -> null", () => RouteResolver.GetRouteKey(openrouter, new Dictionary<string, string>()) is null);
    }

    // --------------------------------------------------------------
    // A) Redaction notice: a single line, no redundant "Detected values" list.
    // --------------------------------------------------------------
    static void TestRedactionNotice()
    {
        var previews = new List<SecretRedactor.RedactionPreview> { new("openai") };

        var plural = RedactionNotice.Build(6, "OpenAI key \u00d7 6", null, previews);
        CheckTrue("notice single line", () => plural.Contains("Proxy notice")
            && plural.Contains("6 sensitive values were redacted")
            && !plural.Contains('\n'));
        CheckTrue("notice keeps kinds", () => plural.Contains("OpenAI key \u00d7 6"));
        CheckTrue("notice no detected-values list", () => !plural.Contains("Detected values"));
        CheckTrue("notice kind appears once", () => CountOccurrences(plural, "OpenAI key") == 1);

        var singular = RedactionNotice.Build(1, "API key \u00d7 1", null, null);
        CheckTrue("notice singular", () => singular.Contains("1 sensitive value was redacted")
            && singular.Contains("(API key \u00d7 1)"));

        var bare = RedactionNotice.Build(2, "", null, null);
        CheckTrue("notice without kinds has no parens", () => bare.Contains("2 sensitive values were redacted") && !bare.Contains("("));

        var templated = RedactionNotice.Build(3, "GitHub token \u00d7 3", "T {Count} | {Kinds} | {Previews}", previews);
        CheckTrue("notice template placeholders", () => templated == "T 3 | GitHub token \u00d7 3 | OpenAI key detected");
    }

    static int CountOccurrences(string haystack, string needle)
    {
        var count = 0;
        var index = 0;
        while ((index = haystack.IndexOf(needle, index, StringComparison.Ordinal)) >= 0)
        {
            count++;
            index += needle.Length;
        }

        return count;
    }

    static bool IsHex8(string value)
        => value.Length == 8 && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');

    // --------------------------------------------------------------
    // B) Detection forensics: metadata only (path/layer/kind/length/fingerprint).
    // --------------------------------------------------------------
    static void TestForensics()
    {
        var secret = "sk-" + "proj-" + "a1B2c3D4" + "e5F6g7H8" + "i9J0k1L2" + "m3N4o5P6";
        var body = "{\"messages\":[{\"role\":\"user\",\"content\":\"please use " + secret
                   + " now\"}],\"api_key\":\"abc123\"}";

        // Off by default: no list filled, no fingerprint computed.
        var off = SecretRedactor.RedactJson(Bytes(body));
        CheckTrue("forensics off collects nothing", () => off.Changed && off.Stats.Detections.Count == 0);

        // On: one record per detection, with the structural path and the layer.
        var on = SecretRedactor.RedactJson(Bytes(body), collectForensics: true);
        var content = on.Stats.Detections.FirstOrDefault(d => d.JsonPath == "$.messages[0].content");
        var field = on.Stats.Detections.FirstOrDefault(d => d.JsonPath == "$.api_key");

        CheckTrue("forensics content detection", () => content is not null
            && content.Layer == "format" && content.Kind == "openai" && content.Length > 0);
        CheckTrue("forensics field detection", () => field is not null
            && field.Layer == "field" && field.Kind == "api_key" && field.Length == 6);
        CheckTrue("forensics fingerprints 8 hex", () => content is not null && IsHex8(content.Fingerprint));

        // Never the value: path/kind/fingerprint and the serialized record stay clean.
        CheckTrue("forensics never leaks value", () => on.Stats.Detections.All(d =>
            !d.JsonPath.Contains(secret) && !d.Kind.Contains(secret) && !d.Fingerprint.Contains(secret)
            && !d.JsonPath.Contains("abc123") && !d.Kind.Contains("abc123")));

        var serialized = JsonSerializer.Serialize(on.Stats.Detections);
        CheckTrue("forensics serialized has no secret", () => !serialized.Contains(secret) && !serialized.Contains("abc123"));

        // Fingerprint: stable per value, different across values, empty only for empty input.
        var fp1 = DetectionFingerprint.Of("value-one");
        var fp2 = DetectionFingerprint.Of("value-one");
        var fp3 = DetectionFingerprint.Of("value-two");
        CheckTrue("fingerprint stable", () => fp1 == fp2 && IsHex8(fp1));
        CheckTrue("fingerprint differs", () => fp1 != fp3);
        CheckTrue("fingerprint empty input", () => DetectionFingerprint.Of("") == string.Empty
            && DetectionFingerprint.Of(null) == string.Empty);

        // Multibyte (accents + CJK + emoji): the string and span overloads agree and stay stable.
        var multibyte = "chave-\u00e7\u00e3o-\u5bc6\u94a5-\ud83d\udd11";
        CheckTrue("fingerprint multibyte stable + 8 hex", () =>
            DetectionFingerprint.Of(multibyte) == DetectionFingerprint.Of(multibyte)
            && IsHex8(DetectionFingerprint.Of(multibyte)));
        CheckTrue("fingerprint multibyte string == span", () =>
            DetectionFingerprint.Of(multibyte) == DetectionFingerprint.Of(multibyte.AsSpan()));

        // Pooled path (> 256 UTF-8 bytes): same value via string/span, and only the FULL value
        // enters the HMAC (a 256-byte prefix must not collide with the 300-byte original).
        var longValue = new string('a', 300);
        CheckTrue("fingerprint pooled path stable + string == span", () =>
            DetectionFingerprint.Of(longValue) == DetectionFingerprint.Of(longValue)
            && DetectionFingerprint.Of(longValue) == DetectionFingerprint.Of(longValue.AsSpan())
            && IsHex8(DetectionFingerprint.Of(longValue)));
        CheckTrue("fingerprint pooled path hashes the whole value", () =>
            DetectionFingerprint.Of(longValue) != DetectionFingerprint.Of(longValue[..256]));

        // Regression: empty/null agree with Of(""), and non-empty values always yield 8 hex.
        CheckTrue("fingerprint empty/null agree with Of(\"\")", () =>
            DetectionFingerprint.Of(null) == DetectionFingerprint.Of("")
            && DetectionFingerprint.Of("") == string.Empty);
        CheckTrue("fingerprint non-empty is 8 hex and distinct", () =>
            IsHex8(DetectionFingerprint.Of("a")) && IsHex8(DetectionFingerprint.Of("b"))
            && DetectionFingerprint.Of("a") != DetectionFingerprint.Of("b"));

        // Store: ring buffer, newest first, clear returns the count, capacity clamped.
        var store = new DetectionStore();

        static DetectionEntry Entry(int i) => new(
            DateTimeOffset.UtcNow, "req" + i, "127.0.0.1", "default", "POST", "/v1/chat/completions",
            "model-x", "$.c", "format", "openai", 40, "abcdef0" + (i % 10));

        store.AddRange(new[] { Entry(1), Entry(2), Entry(3), Entry(4), Entry(5) }, 3);
        CheckTrue("store trims to capacity", () => store.Count == 3);

        var recent = store.Recent(10);
        CheckTrue("store keeps newest", () => recent.Count == 3
            && recent[0].RequestId == "req5" && recent[1].RequestId == "req4" && recent[2].RequestId == "req3");
        CheckTrue("store recent limit", () => store.Recent(1).Count == 1 && store.Recent(1)[0].RequestId == "req5");
        CheckTrue("store recent zero returns none", () => store.Recent(0).Count == 0);
        CheckTrue("store clear returns count", () => store.Clear() == 3 && store.Count == 0);

        var clamped = new DetectionStore();
        clamped.AddRange(Enumerable.Range(1, 25).Select(Entry).ToList(), 1);
        CheckTrue("store honors small capacity", () => clamped.Count == 1);

        var upper = new DetectionStore();
        upper.AddRange(Enumerable.Range(1, 25).Select(Entry).ToList(), 5000);
        CheckTrue("store clamps capacity ceiling", () => upper.Count == 25);

        // Path: object/array nesting.
        var nested = SecretRedactor.RedactJson(
            Bytes("{\"a\":{\"b\":[0,1,{\"c\":\"" + secret + "\"}]}}"), collectForensics: true);
        CheckTrue("path nested array/object", () => nested.Stats.Detections.Any(d => d.JsonPath == "$.a.b[2].c"));

        // Path: 60-char property name is capped at 40 chars per segment.
        var longName = new string('n', 60);
        var segment = SecretRedactor.RedactJson(Bytes(Nest(longName, 1, secret)), collectForensics: true);
        CheckTrue("path segment capped", () => segment.Stats.Detections.Count == 1
            && segment.Stats.Detections[0].JsonPath == "$." + new string('n', 40));

        // Path: depth stops extending at 12 levels.
        var deepShort = SecretRedactor.RedactJson(Bytes(Nest("k", 14, secret)), collectForensics: true);
        CheckTrue("path depth capped at 12", () => deepShort.Stats.Detections.Count == 1
            && deepShort.Stats.Detections[0].JsonPath == "$" + string.Concat(Enumerable.Repeat(".k", 12)));

        // Path: final truncation at 200 chars plus an ellipsis.
        var deepLong = SecretRedactor.RedactJson(Bytes(Nest(longName, 6, secret)), collectForensics: true);
        CheckTrue("path truncated with ellipsis", () => deepLong.Stats.Detections.Count == 1
            && deepLong.Stats.Detections[0].JsonPath.Length == 201
            && deepLong.Stats.Detections[0].JsonPath.EndsWith("\u2026"));

        // Cap: at most 50 forensic records per request.
        var many = new StringBuilder("{");
        for (var i = 0; i < 60; i++)
        {
            if (i > 0) { many.Append(','); }
            many.Append("\"password").Append(i).Append("\":\"v").Append(i).Append('"');
        }

        many.Append('}');
        var capped = SecretRedactor.RedactJson(Bytes(many.ToString()), collectForensics: true);
        CheckTrue("forensics capped at 50", () => capped.Stats.FieldRedactions == 60
            && capped.Stats.Detections.Count == SecretRedactor.MaxDetections);
    }

    // --------------------------------------------------------------
    // Forensics cost + path safety: no path work when off (B1), and a secret property
    // NAME never reaches the JsonPath (M1).
    // --------------------------------------------------------------
    static void TestForensicsZeroCostAndNames()
    {
        // --- B1: with forensics off no path segment is built at all. ---
        var array = new StringBuilder("{\"input\":[");
        for (var i = 0; i <= 200; i++)
        {
            if (i > 0) { array.Append(','); }
            array.Append(i);
        }

        array.Append("]}");

        SecretRedactor.ResetPathInstrumentation();
        var off = SecretRedactor.RedactJson(Bytes(array.ToString()));
        CheckTrue("forensics off builds no path", () => SecretRedactor.PathSegmentsBuilt == 0
            && off.Stats.Detections.Count == 0);

        // m2: with forensics off the context scanner must not materialize shape strings either.
        var shapeText = "api_key=" + "abc123" + "def456";
        var shapeOpts = new DetectOptions();
        var noShape = SecretDetector.Detect(shapeText, shapeOpts);
        CheckTrue("forensics off: no shape strings built", () => noShape.Count > 0
            && noShape.All(f => f.Name is null && f.Sep is null && f.Quote is null));

        var withShape = SecretDetector.Detect(shapeText, shapeOpts, collectShape: true);
        CheckTrue("forensics on: shape strings collected", () => withShape.Any(f => f.Name == "api_key"));

        SecretRedactor.ResetPathInstrumentation();
        var on = SecretRedactor.RedactJson(Bytes(array.ToString()), collectForensics: true);
        CheckTrue("forensics on builds paths", () => SecretRedactor.PathSegmentsBuilt > 0
            && on.Stats.Detections.Count == 0);

        // --- M1: a secret used as a property NAME is replaced by a fixed placeholder. ---
        var nameSecret = "sk-" + "proj-" + "n1A2b3C4" + "d5E6f7G8";
        var valueSecret = "sk-" + "ant-" + "api03-" + "a1B2c3D4" + "e5F6g7H8";
        var named = SecretRedactor.RedactJson(
            Bytes("{\"seen\":{\"" + nameSecret + "\":\"" + valueSecret + "\"}}"), collectForensics: true);

        CheckTrue("forensics secret name hidden", () => named.Stats.Detections.Count == 1
            && named.Stats.Detections[0].JsonPath == "$.seen." + SecretRedactor.RedactedNamePlaceholder
            && !named.Stats.Detections[0].JsonPath.Contains("sk-", StringComparison.Ordinal)
            && !named.Stats.Detections[0].JsonPath.Contains("n1A2b3C4", StringComparison.Ordinal));

        // Path delimiters inside a segment are escaped so the path stays unambiguous.
        var delimited = SecretRedactor.RedactJson(
            Bytes("{\"a.b[0]\":\"" + valueSecret + "\"}"), collectForensics: true);
        CheckTrue("forensics path delimiters escaped", () => delimited.Stats.Detections.Count == 1
            && delimited.Stats.Detections[0].JsonPath == "$.a_b_0_");

        // N4: names are checked with the high-confidence layers only - a legitimate long
        // camelCase name with digits stays, while a real key format used as a name is hidden.
        var legitName = SecretRedactor.RedactJson(
            Bytes("{\"responseFormatJsonSchema2024\":{\"password\":\"x\"}}"), collectForensics: true);
        CheckTrue("forensics legit long name kept", () => legitName.Stats.Detections.Count == 1
            && legitName.Stats.Detections[0].JsonPath == "$.responseFormatJsonSchema2024.password");

        CheckTrue("forensics secret name still hidden", () => named.Stats.Detections.Count == 1
            && named.Stats.Detections[0].JsonPath == "$.seen." + SecretRedactor.RedactedNamePlaceholder);

        // An empty sensitive value is masked but records no length-0 detection.
        var empty = SecretRedactor.RedactJson(Bytes("{\"password\":\"\"}"), collectForensics: true);
        CheckTrue("forensics skips empty value", () => empty.Stats.FieldRedactions == 1
            && empty.Stats.Detections.Count == 0);
    }

    // --------------------------------------------------------------
    // Forensics pattern shape (Option 2b): the context layer records WHICH name/separator/quote
    // fired - never the value.
    // --------------------------------------------------------------
    static void TestForensicsPatternShape()
    {
        // Runtime-built fixtures so no key-shaped literal lives in source.
        var contextValue = "abc123" + "def456";
        var quotedValue = "abcdef" + "ghij";

        var eq = SecretRedactor.RedactJson(
            Bytes("{\"c\":\"api_key = " + contextValue + "\"}"), collectForensics: true);
        var eqFinding = eq.Stats.Detections.FirstOrDefault(d => d.Kind == SecretDetector.KindKeyValue);
        CheckTrue("forensics pattern: name/sep/quote (=)", () => eqFinding is not null
            && eqFinding.Name == "api_key" && eqFinding.Sep == "=" && eqFinding.Quote == "");

        var colon = SecretRedactor.RedactJson(
            Bytes("{\"c\":\"\\\"token\\\": \\\"" + quotedValue + "\\\"\"}"), collectForensics: true);
        var colonFinding = colon.Stats.Detections.FirstOrDefault(d => d.Kind == SecretDetector.KindKeyValue);
        CheckTrue("forensics pattern: name/sep/quote (: quoted)", () => colonFinding is not null
            && colonFinding.Name == "token" && colonFinding.Sep == ":" && colonFinding.Quote == "\"");

        // Uppercase names are normalized to the lowercase whitelist spelling.
        var upper = SecretRedactor.RedactJson(
            Bytes("{\"c\":\"ApiKey=" + contextValue + "\"}"), collectForensics: true);
        var upperFinding = upper.Stats.Detections.FirstOrDefault(d => d.Kind == SecretDetector.KindKeyValue);
        CheckTrue("forensics pattern: uppercase name normalized", () => upperFinding is not null
            && upperFinding.Name == "apikey" && upperFinding.Sep == "=" && upperFinding.Quote == "");

        // Single quotes are recorded as the quote character (not a boolean).
        var single = SecretRedactor.RedactJson(
            Bytes("{\"c\":\"password = '" + quotedValue + "'\"}"), collectForensics: true);
        var singleFinding = single.Stats.Detections.FirstOrDefault(d => d.Kind == SecretDetector.KindKeyValue);
        CheckTrue("forensics pattern: single quote", () => singleFinding is not null
            && singleFinding.Name == "password" && singleFinding.Sep == "=" && singleFinding.Quote == "'");

        // The quotes around the NAME (`"LocalKey" = abc`) must not be mistaken for value quotes.
        var nameQuoted = SecretRedactor.RedactJson(
            Bytes("{\"c\":\"\\\"LocalKey\\\" = " + contextValue + "\"}"), collectForensics: true);
        var nameQuotedFinding = nameQuoted.Stats.Detections.FirstOrDefault(d => d.Kind == SecretDetector.KindKeyValue);
        CheckTrue("forensics pattern: name quote is not a value quote", () => nameQuotedFinding is not null
            && nameQuotedFinding.Name == "localkey" && nameQuotedFinding.Sep == "=" && nameQuotedFinding.Quote == "");

        // `token:=<8>`: the separator is `:` but the value group starts at `=`, so Sep is `:`
        // and Len is inflated by one (the `=` is part of the masked span).
        var doubleColon = SecretRedactor.RedactJson(
            Bytes("{\"c\":\"token:=" + contextValue + "\"}"), collectForensics: true);
        var doubleColonFinding = doubleColon.Stats.Detections.FirstOrDefault(d => d.Kind == SecretDetector.KindKeyValue);
        CheckTrue("forensics pattern: token:= keeps Sep=: and inflates Len", () => doubleColonFinding is not null
            && doubleColonFinding.Name == "token" && doubleColonFinding.Sep == ":"
            && doubleColonFinding.Length == contextValue.Length + 1);

        // format without an overlapping context: no shape (the kind already identifies the family).
        var formatSecret = "sk-" + "proj-" + "a1B2c3D4" + "e5F6g7H8";
        var format = SecretRedactor.RedactJson(
            Bytes("{\"c\":\"see " + formatSecret + "\"}"), collectForensics: true);
        var formatFinding = format.Stats.Detections.FirstOrDefault(d => d.Layer == "format");
        CheckTrue("forensics pattern: format has no shape", () => formatFinding is not null
            && formatFinding.Name is null && formatFinding.Sep is null && formatFinding.Quote is null);

        // entropy layer: no pattern shape either.
        var entropySecret = "4v_wJ9rLsbLcFvwOGCOIA5h10EGzD6ZD43UAFNG_bq4";
        var entropy = SecretRedactor.RedactJson(
            Bytes("{\"c\":\"see " + entropySecret + "\"}"), collectForensics: true);
        var entropyFinding = entropy.Stats.Detections.FirstOrDefault(d => d.Layer == "entropy");
        CheckTrue("forensics pattern: entropy has no shape", () => entropyFinding is not null
            && entropyFinding.Name is null && entropyFinding.Sep is null && entropyFinding.Quote is null);

        // field layer: the JSON path already names the field.
        var field = SecretRedactor.RedactJson(Bytes("{\"password\":\"x\"}"), collectForensics: true);
        var fieldFinding = field.Stats.Detections.FirstOrDefault(d => d.Layer == "field");
        CheckTrue("forensics pattern: field has no shape", () => fieldFinding is not null
            && fieldFinding.Name is null && fieldFinding.Sep is null && fieldFinding.Quote is null);

        // --- M1: a context finding discarded by a format finding at the SAME start keeps its
        // shape, so `TOKEN=sk-...` and `"token": "sk-..."` still differ in the Pattern column. ---
        var m1Eq = SecretRedactor.RedactJson(
            Bytes("{\"c\":\"api_key=" + formatSecret + "\"}"), collectForensics: true);
        var m1EqFinding = m1Eq.Stats.Detections.FirstOrDefault(d => d.Layer == "format");
        CheckTrue("forensics M1: format inherits shape (name=)", () => m1EqFinding is not null
            && m1EqFinding.Name == "api_key" && m1EqFinding.Sep == "=" && m1EqFinding.Quote == "");

        var m1Colon = SecretRedactor.RedactJson(
            Bytes("{\"c\":\"\\\"token\\\": \\\"" + formatSecret + "\\\"\"}"), collectForensics: true);
        var m1ColonFinding = m1Colon.Stats.Detections.FirstOrDefault(d => d.Layer == "format");
        CheckTrue("forensics M1: format inherits shape (name :)", () => m1ColonFinding is not null
            && m1ColonFinding.Name == "token" && m1ColonFinding.Sep == ":" && m1ColonFinding.Quote == "\"");

        // No leak: every Name is a full match of the scanner's real name alternatives, and
        // nothing serialized carries a value. The regex is built from the production constant,
        // so the whitelist cannot silently drift from the detector.
        var nameRegex = new Regex("^(?:" + SecretDetector.ContextNamePattern + ")$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        var all = eq.Stats.Detections.Concat(colon.Stats.Detections)
            .Concat(upper.Stats.Detections).Concat(single.Stats.Detections)
            .Concat(nameQuoted.Stats.Detections).Concat(doubleColon.Stats.Detections)
            .Concat(format.Stats.Detections).Concat(entropy.Stats.Detections)
            .Concat(field.Stats.Detections).Concat(m1Eq.Stats.Detections)
            .Concat(m1Colon.Stats.Detections).ToList();

        CheckTrue("forensics pattern: names match the scanner alternatives", () => all
            .Where(d => d.Name is not null)
            .All(d => nameRegex.IsMatch(d.Name!)));

        // The alternate spellings the context regex can produce must all be in the whitelist.
        // Literal list on purpose: adding a spelling to the detector without listing it here
        // fails the assertion below.
        var spellings = new[]
        {
            "apikey", "apisecret", "awssecretaccesskey", "awsaccesskeyid", "secretaccesskey",
            "accesskeyid", "accesskey", "localkey", "locl_key", "secretkey", "secret", "privatekey",
            "masterkey", "encryptionkey", "clientsecret", "password", "passwd", "senha", "credential",
            "authorization", "accesstoken", "refreshtoken", "bearertoken", "authtoken", "sessiontoken",
            "idtoken", "jwtkey", "signingkey", "token",
        };
        CheckTrue("forensics pattern: whitelist covers alternate spellings", () => spellings.All(nameRegex.IsMatch));

        // Anti-drift: the production pattern's top-level alternatives must be EXACTLY the
        // literal snapshot below - a new/changed alternative has to be added here on purpose.
        var expectedAlternatives = new[]
        {
            "aws[_-]?secret[_-]?(?:access[_-]?)?key",
            "aws[_-]?access[_-]?key[_-]?(?:id)?",
            "secret[_-]?access[_-]?key",
            "access[_-]?key[_-]?id",
            "access[_-]?key",
            "api[_-]?key",
            "api[_-]?secret",
            "loc[a]?l[_-]?key",
            "secret[_-]?key",
            "secret",
            "private[_-]?key",
            "master[_-]?key",
            "encryption[_-]?key",
            "client[_-]?secret",
            "password",
            "passwd",
            "senha",
            "credential",
            "authorization",
            "access[_-]?token",
            "refresh[_-]?token",
            "bearer[_-]?token",
            "auth[_-]?token",
            "session[_-]?token",
            "id[_-]?token",
            "jwt[_-]?key",
            "signing[_-]?key",
            "token",
        };
        CheckTrue("forensics pattern: alternatives match the literal whitelist", () =>
            SplitAlternatives(SecretDetector.ContextNamePattern).SequenceEqual(expectedAlternatives));

        // The shape comes from the NAME whitelist, never from the value: no recorded Name
        // contains any fixture used by this test.
        var fixtures = new[] { contextValue, quotedValue, formatSecret, entropySecret };
        CheckTrue("forensics pattern: name never derives from the value", () => all
            .Where(d => d.Name is not null)
            .All(d => fixtures.All(f => !d.Name!.Contains(f, StringComparison.Ordinal))));

        var serialized = JsonSerializer.Serialize(all);
        CheckTrue("forensics pattern: serialized record has no value", () =>
            !serialized.Contains(contextValue, StringComparison.Ordinal)
            && !serialized.Contains(quotedValue, StringComparison.Ordinal)
            && !serialized.Contains(formatSecret, StringComparison.Ordinal)
            && !serialized.Contains(entropySecret, StringComparison.Ordinal));

        // Forensic types must never expose a `value`/`raw` property (the whole point is metadata only).
        CheckTrue("forensics pattern: no value/raw property on forensic types", () =>
            !HasValueOrRawProperty(typeof(DetectionRecord))
            && !HasValueOrRawProperty(typeof(DetectionEntry)));
    }

    // --------------------------------------------------------------
    // Merge union: overlapping candidates are merged so the masked span is the UNION - the
    // proxy must never mask less than any single detector would.
    // --------------------------------------------------------------
    static void TestMergeUnion()
    {
        // Runtime-built fixtures so no key-shaped literal lives in source.
        var key = "sk-" + "proj-" + "a1B2c3D4" + "e5F6g7H8";   // 24 chars, matches `openai`
        var tail = ".T3st";                                    // outside the format class, inside the context value class
        var contextValue = key + tail;

        // 1) Tail outside the format class: `api_key=<key>.T3st`. The context value covers the
        // whole value (dots are in its class) while the format stops at the dot. The format wins
        // the layer (same offset) but must grow to the union - otherwise `.T3st` would travel
        // unmasked. Shape is still inherited (same offset), length becomes the masked span.
        var tailCase = SecretRedactor.RedactJson(
            Bytes("{\"c\":\"api_key=" + contextValue + "\"}"), collectForensics: true);
        var tailBody = Str(tailCase.Data);
        var tailFinding = tailCase.Stats.Detections.FirstOrDefault(d => d.Layer == "format");
        CheckTrue("merge union: format extends over context tail", () => tailFinding is not null
            && tailCase.Stats.Detections.Count == 1
            && tailFinding.Kind == "openai"
            && tailFinding.Name == "api_key" && tailFinding.Sep == "="
            && tailFinding.Length == contextValue.Length
            && !tailBody.Contains(tail, StringComparison.Ordinal)
            && !tailBody.Contains(key, StringComparison.Ordinal));

        // 6) A merged span is ONE detection: Stats/ByKind never count the loser as well.
        CheckTrue("merge union: total counts the span once", () => tailCase.Stats.Total == 1
            && tailCase.Stats.ByKind.GetValueOrDefault("openai") == 1);

        // 2) Contained overlap: `password=<28+ random>` fires `context` AND `entropy` on the SAME
        // span. The candidate ends before the winner, so the union is that span - no growth.
        var random = "XyZ0pQr9mN2vW7sT4uL8kK1jH6gF5dS3aBc";   // 35 chars, mixed classes
        var contained = SecretRedactor.RedactJson(
            Bytes("{\"c\":\"password=" + random + "\"}"), collectForensics: true);
        var containedFinding = contained.Stats.Detections.FirstOrDefault();
        CheckTrue("merge union: contained overlap keeps the span", () => contained.Stats.Detections.Count == 1
            && containedFinding is not null
            && containedFinding.Layer == "context"
            && containedFinding.Length == random.Length
            && !Str(contained.Data).Contains(random, StringComparison.Ordinal));

        // 3) Two disjoint values in the same text: both are still masked (regression).
        var two = SecretRedactor.RedactJson(
            Bytes("{\"c\":\"api_key=" + contextValue + " and password=" + random + "\"}"), collectForensics: true);
        var twoBody = Str(two.Data);
        CheckTrue("merge union: disjoint values both masked", () => two.Stats.Detections.Count == 2
            && two.Stats.Total == 2
            && !twoBody.Contains(contextValue, StringComparison.Ordinal)
            && !twoBody.Contains(random, StringComparison.Ordinal));

        // 4) NOT COVERED - chained overlaps (A extended by B, then B extended by C). Every
        // candidate that can extend past another span either starts at the same offset as the
        // span it covers (context value vs known format) or starts before it (format vs context),
        // and the extenders that could reach further (PEM, Azure connection string, db/url
        // credentials) are themselves the outermost match at their offset. So the real scanners
        // produce at most ONE extension per merged span - the two-link case asserted above. A
        // synthetic three-link chain would only exercise a path no detector can reach.

        // 5) M1 regression: `TOKEN=<key>` keeps the inherited shape on the format layer, and the
        // contained context candidate does not inflate the span.
        var m1 = SecretRedactor.RedactJson(
            Bytes("{\"c\":\"TOKEN=" + key + "\"}"), collectForensics: true);
        var m1Finding = m1.Stats.Detections.FirstOrDefault();
        CheckTrue("merge union: M1 shape kept on format", () => m1.Stats.Detections.Count == 1
            && m1Finding is not null
            && m1Finding.Layer == "format"
            && m1Finding.Name == "token" && m1Finding.Sep == "="
            && m1Finding.Length == key.Length);
    }

    // --------------------------------------------------------------
    // Union + exemptions: a merged span that covers a `format` finding must never be exempted
    // (base64 / allow-list), and a `name=` prefix must not turn a value into "base64 payload".
    // --------------------------------------------------------------
    static void TestMergeExemptionRules()
    {
        // Runtime-built fixtures so no key-shaped/JWT-shaped literal lives in source.
        var rnd = new Random(11);
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        var prefix = new StringBuilder(40);
        for (var i = 0; i < 40; i++)
        {
            prefix.Append(alphabet[rnd.Next(alphabet.Length)]);
        }

        var jwt = "ey" + "J" + "hbGciOiJIUzI1NiJ9"
            + "." + "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0"
            + "." + "c2lnbmF0dXJlLXRlc3QtdmFsdWU";
        var text = "foo=" + prefix + jwt;

        // 1) Partial overlap to the LEFT: the entropy candidate starts on the random run and the
        // JWT starts INSIDE it, so the union grows over the whole JWT. The merged span must carry
        // the format flag - without it the base64 region (structural '=' from "foo=") would
        // exempt the span and neither the run nor the JWT would be masked.
        var findings = SecretDetector.Detect(text, new DetectOptions(), collectShape: true);
        var jwtStart = text.IndexOf(jwt, StringComparison.Ordinal);
        CheckTrue("merge exemption: span covering a format is flagged", () => findings.Count == 1
            && findings[0].IncludesFormat
            && findings[0].Start <= jwtStart
            && findings[0].Start + findings[0].Length >= jwtStart + jwt.Length);

        var overlapped = SecretRedactor.RedactJson(Bytes("{\"c\":\"" + text + "\"}"), collectForensics: true);
        var overlappedBody = Str(overlapped.Data);
        CheckTrue("merge exemption: absorbed format span is never exempted", () => overlapped.Changed
            && overlapped.Stats.Detections.Count == 1
            && !overlappedBody.Contains(prefix.ToString(), StringComparison.Ordinal)
            && !overlappedBody.Contains(jwt, StringComparison.Ordinal));

        // 2) `SECRET_KEY=<128 hex>`: the identifier and the separator are base64 characters too,
        // but they are not payload - the 128-char value must be masked.
        var hexRnd = new Random(13);
        const string hexAlphabet = "0123456789abcdef";
        var secret = new StringBuilder(128);
        for (var i = 0; i < 128; i++)
        {
            secret.Append(hexAlphabet[hexRnd.Next(hexAlphabet.Length)]);
        }
        var secretValue = secret.ToString();

        var named = SecretRedactor.RedactJson(
            Bytes("{\"c\":\"SECRET_KEY=" + secretValue + "\"}"), collectForensics: true);
        CheckTrue("base64 exemption: name= prefix is not payload", () => named.Changed
            && named.Stats.Detections.Count == 1
            && named.Stats.Detections[0].Length == 128
            && !Str(named.Data).Contains(secretValue, StringComparison.Ordinal));

        // 2b) Same credential with prose around it: the identifier before the `=` is the run of
        // letters/digits/underscore IMMEDIATELY before it (`SECRET_KEY`), not the whole prefix
        // (`zz SECRET_KEY`). The whole-prefix check never matched the anchored whitelist, so the
        // 128-char value stayed exempt and leaked.
        var proseSecret = "zz SECRET_KEY=" + secretValue + " zz";
        var prose = SecretRedactor.RedactJson(
            Bytes("{\"c\":\"" + proseSecret + "\"}"), collectForensics: true);
        CheckTrue("base64 exemption: prose + sensitive name= is not payload", () => prose.Changed
            && prose.Stats.Detections.Count >= 1
            && !Str(prose.Data).Contains(secretValue, StringComparison.Ordinal));

        // ...and the rule itself decides on the identifier, not the prefix (direct proof for
        // both directions: credential yes, legitimate `dat=` blob no).
        CheckTrue("base64 rule: prose + sensitive name= is not payload",
            () => !SecretDetector.IsBase64Payload(proseSecret));

        // 3) Regression (A): a legitimate base64 blob made only of alphanumerics (no '+', '/'
        // or padding) preceded by a NON-sensitive name keeps its exemption. `dat=` is then the
        // only structural character, so a name-based rule must not consume it (the old strip
        // did: the blob lost the exemption and got corrupted by the mask).
        var alnumRnd = new Random(17);
        var alnumBlob = Run(alnumRnd, 100);
        var namedBlob = SecretRedactor.RedactJson(Bytes("{\"c\":\"dat=" + alnumBlob + "\"}"));
        CheckTrue("base64 exemption: non-sensitive name= keeps alnum blob exempt", () => !namedBlob.Changed
            && Str(namedBlob.Data).Contains(alnumBlob, StringComparison.Ordinal));

        // ...and the identifier rule leaves the exemption intact (the run before `=` is `dat`,
        // not a whitelisted name).
        CheckTrue("base64 rule: dat=alnum blob is still payload",
            () => SecretDetector.IsBase64Payload("dat=" + alnumBlob));

        // 4) The same shape with a SENSITIVE name is a credential, not payload (B): the
        // identifier and the separator are base64 characters too, so a structural '+'/'/'
        // value used to stay exempt and was never masked.
        var credentialRnd = new Random(19);
        const string b64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var credential = new StringBuilder(120);
        for (var i = 0; i < 120; i++)
        {
            credential.Append(b64Alphabet[credentialRnd.Next(b64Alphabet.Length)]);
        }
        var credentialValue = credential.ToString();

        var sensitiveBlob = SecretRedactor.RedactJson(
            Bytes("{\"c\":\"SECRET_KEY=" + credentialValue + "\"}"), collectForensics: true);
        CheckTrue("base64 exemption: sensitive name= is never payload", () => sensitiveBlob.Changed
            && sensitiveBlob.Stats.Detections.Count == 1
            && sensitiveBlob.Stats.Detections[0].Length == 120
            && !Str(sensitiveBlob.Data).Contains(credentialValue, StringComparison.Ordinal));

        // 4b) FN1: the identifier run includes '-' (`SECRET-KEY`), so a hyphenated sensitive name
        // is a credential too. The 120-char value has structural '+'/'/' (base64 characters).
        var hyphenValue = Run(new Random(29), 118) + "+/";
        var hyphenBlob = SecretRedactor.RedactJson(
            Bytes("{\"c\":\"SECRET-KEY=" + hyphenValue + "\"}"), collectForensics: true);
        CheckTrue("base64 exemption: hyphenated sensitive name= is not payload", () => hyphenBlob.Changed
            && !Str(hyphenBlob.Data).Contains(hyphenValue, StringComparison.Ordinal));

        // 4c) FN1 + whitespace: `SECRET-KEY = <blob>` - the whitespace before '=' is skipped and
        // the hyphen is part of the run.
        var hyphenSpaced = SecretRedactor.RedactJson(
            Bytes("{\"c\":\"SECRET-KEY = " + hyphenValue + "\"}"), collectForensics: true);
        CheckTrue("base64 exemption: spaced hyphenated sensitive name= is not payload", () => hyphenSpaced.Changed
            && !Str(hyphenSpaced.Data).Contains(hyphenValue, StringComparison.Ordinal));

        // 4d) FN2: `SECRET_KEY = <blob>` (space before '=') used to leave the identifier empty.
        var spacedName = SecretRedactor.RedactJson(
            Bytes("{\"c\":\"SECRET_KEY = " + hyphenValue + "\"}"), collectForensics: true);
        CheckTrue("base64 exemption: spaced sensitive name= is not payload", () => spacedName.Changed
            && !Str(spacedName.Data).Contains(hyphenValue, StringComparison.Ordinal));

        // 4e) Non-FP: a legitimate base64 blob with trailing padding, introduced by a
        // NON-sensitive name (`dat=`), keeps its exemption - the final `==` is padding, not a
        // `name=` separator (`token` before it is only the blob body).
        var paddingBlob = "dat=" + Run(new Random(31), 100) + "token==";
        var namedPadding = SecretRedactor.RedactJson(Bytes("{\"c\":\"" + paddingBlob + "\"}"));
        CheckTrue("base64 exemption: non-sensitive name + padding blob stays exempt", () => !namedPadding.Changed
            && Str(namedPadding.Data).Contains(paddingBlob.Substring(0, 40), StringComparison.Ordinal));

        // 5) Regression: a real base64 payload (PNG magic, '+', '/' and '=' padding, no name=) is
        // still exempt - as a standalone value and inline among prose.
        var b64 = "iVBORw0KGgo" + Run(rnd, 40) + "/" + Run(rnd, 40) + "+" + Run(rnd, 30) + "==";

        var standalone = SecretRedactor.RedactJson(Bytes("{\"c\":\"" + b64 + "\"}"));
        CheckTrue("base64 exemption: standalone payload still exempt", () => !standalone.Changed
            && Str(standalone.Data).Contains(b64.Substring(0, 40), StringComparison.Ordinal));

        var inline = SecretRedactor.RedactJson(Bytes("{\"prompt\":\"img " + b64 + " end\"}"));
        CheckTrue("base64 exemption: inline payload still exempt", () => !inline.Changed
            && Str(inline.Data).Contains(b64.Substring(0, 40), StringComparison.Ordinal));

        // 6) Non-vacuous IncludesFormat proof (C). The `context` span starts at the value - the
        // ": " separator is not a base64 character, so the walk-back stops there - and its
        // base64-looking region is 183 chars (4 + 30 + 69 + 80) holding the structural '=' of
        // the inner `foo=`. On its own that region would be exempt, so the union with the JWT
        // `format` finding is the only reason the span is masked (dropping the flag fails here).
        var cRnd = new Random(23);
        var cA = Run(cRnd, 30);                                  // high-entropy run before the JWT
        var cB = Run(cRnd, 80);                                  // tail run absorbed by the union
        var cJwt = "ey" + "J" + "hbGciOiJIUzI1NiJ9"
            + "." + "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0"
            + "." + cB.Substring(0, 20);                          // 20 + 1 + 27 + 1 + 20 = 69
        var cText = "password: foo=" + cA + cJwt + cB;           // 10 + 4 + 30 + 69 + 80 = 193

        var cFindings = SecretDetector.Detect(cText, new DetectOptions(), collectShape: true);
        CheckTrue("merge exemption: absorbed format beats base64 (flag)", () => cFindings.Count == 1
            && cFindings[0].Detector == SecretDetector.DetectorContext
            && cFindings[0].IncludesFormat
            && cFindings[0].Start + cFindings[0].Length == cText.Length);

        var cRedacted = SecretRedactor.RedactJson(
            Bytes("{\"c\":\"" + cText + "\"}"), collectForensics: true);
        var cFinding = cRedacted.Stats.Detections.FirstOrDefault();
        CheckTrue("merge exemption: absorbed format beats base64 (masked)", () => cRedacted.Changed
            && cRedacted.Stats.Detections.Count == 1
            && cFinding is not null
            && cFinding.Layer == "context"
            && !Str(cRedacted.Data).Contains(cB, StringComparison.Ordinal));

        static string Run(Random r, int n)
        {
            const string a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var sb = new StringBuilder(n);
            for (var i = 0; i < n; i++) sb.Append(a[r.Next(a.Length)]);
            return sb.ToString();
        }
    }

    /// <summary>Splits a regex alternation on top-level <c>|</c> only (ignores nested groups).</summary>
    static List<string> SplitAlternatives(string pattern)
    {
        var parts = new List<string>();
        var depth = 0;
        var start = 0;
        for (var i = 0; i < pattern.Length; i++)
        {
            var c = pattern[i];
            if (c == '\\')
            {
                i++;
                continue;
            }

            if (c == '(')
            {
                depth++;
            }
            else if (c == ')')
            {
                depth--;
            }
            else if (c == '|' && depth == 0)
            {
                parts.Add(pattern[start..i]);
                start = i + 1;
            }
        }

        parts.Add(pattern[start..]);
        return parts;
    }

    static bool HasValueOrRawProperty(Type type) => type.GetProperties().Any(p =>
        p.Name.Equals("value", StringComparison.OrdinalIgnoreCase)
        || p.Name.Equals("raw", StringComparison.OrdinalIgnoreCase));

    /// <summary>Builds {"name":{"name":... "value" ...}} with <paramref name="levels"/> nested objects.</summary>
    static string Nest(string name, int levels, string value)
    {
        var sb = new StringBuilder();
        for (var i = 0; i < levels; i++)
        {
            sb.Append("{\"").Append(name).Append("\":");
        }

        sb.Append('"').Append(value).Append('"');

        for (var i = 0; i < levels; i++)
        {
            sb.Append('}');
        }

        return sb.ToString();
    }
}
