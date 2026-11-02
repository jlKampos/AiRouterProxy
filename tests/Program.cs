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
        TestFieldNames();
        TestNoChange();
        TestRobustness();
        TestSummarize();
        TestNotices();
        TestExtendedDetection();
        TestRouting();
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
        var body2 = Bytes("{\"content\":\"hi sk-ant-abcdefghijklmnop ghp_abcdefghijklmnop AIza1234567890abcdefghijklmn npm_abcdefghijklmnopqrst xoxb-1234567890-abcdef AKIAABCDEFGHIJKLMNOP abc\"}");
        var r2 = SecretRedactor.RedactJson(body2);
        var s2 = Str(r2.Data);
        CheckTrue("multiple inline keys", () => r2.Changed
            && !s2.Contains("sk-ant-") && !s2.Contains("ghp_") && !s2.Contains("AIza")
            && !s2.Contains("npm_") && !s2.Contains("xoxb-") && !s2.Contains("AKIA")
            && r2.Stats.ByKind.GetValueOrDefault("openai") >= 1
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
        var r6 = SecretRedactor.RedactJson(Bytes("{\"c\":\"ghp_1234567890123456789012345678901234x\"}"));
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
    // Multi-upstream router (Item 2)
    // --------------------------------------------------------------
    static void TestRouting()
    {
        var airouter = new RouteOptions
        {
            Name = "airouter",
            Prefix = "",
            Upstream = "https://api.airrouter.ch",
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
