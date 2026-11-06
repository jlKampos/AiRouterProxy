using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
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
        TestDetector();
        TestAuthenticationPolicy();
        TestRateLimiter();
        TestSseParser();
        TestSseProcessor();
        TestSseProtocolAdapters();
        TestSecurityEdges();
        TestRouting();
        TestInspectionPolicy();
        Console.WriteLine();
        Console.WriteLine($"RESULT: {_passed} PASS, {_failed} FAIL");
        Environment.ExitCode = _failed == 0 ? 0 : 1;
    }

    // --------------------------------------------------------------
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
}
