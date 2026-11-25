using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using AIRouterProxy;
using AiRouterProxy.AdminPersistence;
using AiRouterProxy.AdminServices;
using AiRouterProxy.AdminValidation;
using AiRouterProxy.Dashboard.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RouteOptions = AIRouterProxy.RouteOptions;

class Program
{
    static int _passed = 0;
    static int _failed = 0;

    static readonly List<string> _tmpRoots = new();

    static void Check(string name, bool cond)
    {
        if (cond) { _passed++; Console.WriteLine($"PASS  {name}"); }
        else { _failed++; Console.WriteLine($"FAIL  {name}"); }
    }

    static void CheckTrue(string name, Func<bool> fn) => Check(name, fn());

    static string TempRoot()
    {
        var dir = Path.Combine(Path.GetTempPath(), "airproxy-dash-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        _tmpRoots.Add(dir);
        return dir;
    }

    /// <summary>All messages that could reach the UI/API, joined - used to prove secrets never surface.</summary>
    static string SafeText(AdminResult r)
        => string.Join(" | ", new[] { r.Message }.Concat(r.Errors ?? Array.Empty<string>()).Concat(r.Warnings ?? Array.Empty<string>()));

    /// <summary>Builds a real DashboardAdminService against a throwaway temp layout (dev layout: config next to base).</summary>
    static (DashboardAdminService Service, string Root, string ConfigDir) MakeService(ProxyOptions options, ReloadConfirmer? confirmer = null)
    {
        var (service, root, configDir, _, _) = MakeServiceWithStore(options, confirmer);
        return (service, root, configDir);
    }

    /// <summary>Same as MakeService but also exposes the ActivityStore and the fake Event Log seam (log-clearing tests).</summary>
    static (DashboardAdminService Service, string Root, string ConfigDir, ActivityStore Store, FakeEventLogStore EventLogs) MakeServiceWithStore(ProxyOptions options, ReloadConfirmer? confirmer = null)
    {
        var root = TempRoot();
        var paths = new DashboardPaths(root, root, Path.Combine(root, "data"));
        var backups = new ConfigBackup(paths);
        var activity = new ActivityStore();
        var eventLogs = new FakeEventLogStore();
        var service = new DashboardAdminService(
            new TestOptionsMonitor<ProxyOptions>(options),
            paths,
            backups,
            confirmer ?? new ReloadConfirmer(backups),
            new KeyMetaStore(paths),
            new AuditLog(paths),
            activity,
            eventLogs,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<DashboardAdminService>.Instance);
        return (service, root, root, activity, eventLogs);
    }

    static void Main()
    {
        TestRouteValidator();
        TestKeyValidator();
        TestSecurityValidator();
        TestImportValidator();
        TestAdminHash();
        TestAtomicWriter();
        TestConfigBackup();
        TestReloadConfirmer();
        TestKeyMetaStore();
        TestAuditLog();
        TestDashboardPaths();
        TestServicePipeline();
        TestSecretsNeverLeak();
        TestImportRollbackScope();
        TestConcurrentWrites();
        TestApplySecurityNullSections();
        TestReloadConfirmRestoreSignaling();
        TestEnsureRouteKeyRef();
        TestFreshKeyRefUsableBeforeWatcherReload();
        TestImportSanitizesSecurity();
        TestEmptyImportBundle();
        TestSecurityWrongTypesAndCaseInsensitive();
        TestImportTransactionalRollback();
        TestImportSaveAtomicFailureRollsBack();
        TestReloadConfirmRestoreFailedSignaling();
        TestConfigFileReader();
        TestLogClearing();
        TestLogClearingResilience();
        TestLogClearingSafety();
        TestLogClearingLoggingFailure();

        foreach (var dir in _tmpRoots)
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }

        Console.WriteLine();
        Console.WriteLine($"RESULT: {_passed} PASS, {_failed} FAIL");
        Environment.ExitCode = _failed == 0 ? 0 : 1;
    }

    // --------------------------------------------------------------
    static void TestRouteValidator()
    {
        RouteDraft Make(string name, string prefix, string keyRef = "", Dictionary<string, string>? headers = null)
            => new(name, prefix, "https://api.example.com", keyRef, null, 0, 0, headers);

        var known = new HashSet<string>(StringComparer.Ordinal) { "ref-a" };
        var configured = new HashSet<string>(StringComparer.Ordinal) { "ref-a" };

        // Prefix conflicts: exact duplicate and nested segment both overlap.
        var dup = new List<RouteDraft> { Make("a", "/v1"), Make("b", "/v1") };
        RouteValidator.Validate(dup, known, out var dupErrors, out _, configured);
        CheckTrue("route: duplicate prefix conflict", () => dupErrors.Any(e => e.Contains("overlap", StringComparison.OrdinalIgnoreCase)));

        var nested = new List<RouteDraft> { Make("a", "/v1"), Make("b", "/v1/models") };
        RouteValidator.Validate(nested, known, out var nestedErrors, out _, configured);
        CheckTrue("route: nested prefix conflict", () => nestedErrors.Any(e => e.Contains("overlap", StringComparison.OrdinalIgnoreCase)));

        var okPair = new List<RouteDraft> { Make("a", "/v1/model"), Make("b", "/v1/models") };
        RouteValidator.Validate(okPair, known, out var okErrors, out _, configured);
        CheckTrue("route: sibling prefixes no conflict", () => okErrors.Count == 0);

        // "" (default) prefix: at most one, coexists with others.
        var twoDefaults = new List<RouteDraft> { Make("a", ""), Make("b", ""), Make("c", "/x") };
        RouteValidator.Validate(twoDefaults, known, out var defErrors, out _, configured);
        CheckTrue("route: two default prefixes rejected", () => defErrors.Any(e => e.Contains("default", StringComparison.OrdinalIgnoreCase)));

        var oneDefault = new List<RouteDraft> { Make("a", ""), Make("b", "/x") };
        RouteValidator.Validate(oneDefault, known, out var oneErrors, out _, configured);
        CheckTrue("route: default coexists", () => oneErrors.Count == 0);

        // keyRef must exist (declared); declared-but-unset is a warning, not an error.
        var missingRef = new List<RouteDraft> { Make("a", "/x", keyRef: "ref-ghost") };
        RouteValidator.Validate(missingRef, known, out var ghostErrors, out _, configured);
        CheckTrue("route: keyRef missing is an error", () => ghostErrors.Any(e => e.Contains("does not exist", StringComparison.OrdinalIgnoreCase)));

        var inactive = new List<RouteDraft> { Make("a", "/x", keyRef: "ref-a") };
        RouteValidator.Validate(inactive, known, out _, out var warnList, new HashSet<string>(StringComparer.Ordinal)); // declared but NOT configured
        CheckTrue("route: declared-but-unset keyRef warns", () => warnList.Count == 1 && warnList[0].Contains("inactive until the key is set", StringComparison.OrdinalIgnoreCase));

        // Reserved headers are refused.
        var badHeader = new List<RouteDraft> { Make("a", "/x", headers: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["Authorization"] = "Bearer x" }) };
        RouteValidator.Validate(badHeader, known, out var headerErrors, out _, configured);
        CheckTrue("route: reserved header rejected", () => headerErrors.Any(e => e.Contains("reserved", StringComparison.OrdinalIgnoreCase)));

        var okHeader = new List<RouteDraft> { Make("a", "/x", headers: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase) { ["anthropic-version"] = "2023-06-01" }) };
        RouteValidator.Validate(okHeader, known, out var headerOk, out _, configured);
        CheckTrue("route: custom header accepted", () => headerOk.Count == 0);

        // Name + upstream requirements.
        var noName = new List<RouteDraft> { new("", "/x", "https://api.example.com", "") };
        RouteValidator.Validate(noName, known, out var nnErrors, out _, configured);
        CheckTrue("route: name required", () => nnErrors.Any(e => e.Contains("name is required", StringComparison.OrdinalIgnoreCase)));

        var badUpstream = new List<RouteDraft> { new("a", "/x", "not-a-url", "") };
        RouteValidator.Validate(badUpstream, known, out var upErrors, out _, configured);
        CheckTrue("route: upstream must be absolute http(s)", () => upErrors.Any(e => e.Contains("upstream", StringComparison.OrdinalIgnoreCase)));
    }

    // --------------------------------------------------------------
    static void TestKeyValidator()
    {
        CheckTrue("key: valid ref", () => KeyValidator.ValidateRef("openai-main_2", out _));
        CheckTrue("key: ref too long", () => !KeyValidator.ValidateRef(new string('a', 65), out _));
        CheckTrue("key: ref with whitespace", () => !KeyValidator.ValidateRef("open ai", out _));
        CheckTrue("key: ref invalid char", () => !KeyValidator.ValidateRef("ref#1", out _));
        CheckTrue("key: empty ref", () => !KeyValidator.ValidateRef("", out _));
        CheckTrue("key: null ref", () => !KeyValidator.ValidateRef(null, out _));

        CheckTrue("key: secret ok", () => KeyValidator.ValidateSecret("sk-abc123", out _));
        CheckTrue("key: secret empty", () => !KeyValidator.ValidateSecret("", out _));
        CheckTrue("key: secret too long", () => !KeyValidator.ValidateSecret(new string('k', 1025), out _));
        CheckTrue("key: secret not trimmed (bytes kept)", () => KeyValidator.ValidateSecret("  sk-abc  ", out _));

        CheckTrue("key: empty local list ok", () => KeyValidator.ValidateLocalKeys(new List<string>(), out _));
        CheckTrue("key: null local list ok", () => KeyValidator.ValidateLocalKeys(null, out _));
        CheckTrue("key: bad local entry flagged", () =>
        {
            var no = !KeyValidator.ValidateLocalKeys(new List<string> { "good", "" }, out var errors);
            return no && errors.Count == 1 && errors[0].Contains("Local key #2", StringComparison.Ordinal);
        });
    }

    // --------------------------------------------------------------
    static void TestSecurityValidator()
    {
        var goodRed = JsonNode.Parse("{\"enabled\":true,\"mask\":\"**\",\"notifyInResponse\":true,\"detect\":{\"byFieldName\":true,\"byFormats\":true,\"byKeyValueContext\":true,\"byLongStrings\":true,\"exemptBase64\":true,\"entropyThreshold\":3.5},\"allow\":[\"^ACME-\"]}");
        var goodInsp = JsonNode.Parse("{\"enabled\":true,\"defaultAction\":\"block\",\"invalidJson\":\"warn\",\"byContentType\":{\"application/json\":\"inspect\"}}");
        CheckTrue("security: valid sections pass", () => SecurityValidator.Validate(goodRed, goodInsp, out _));

        CheckTrue("security: bad defaultAction", () =>
        {
            var no = !SecurityValidator.Validate(goodRed, JsonNode.Parse("{\"defaultAction\":\"run\"}"), out var errors);
            return no && errors.Count > 0 && errors[0].Contains("block, pass, inspect", StringComparison.Ordinal);
        });
        CheckTrue("security: bad invalidJson", () => !SecurityValidator.Validate(goodRed, JsonNode.Parse("{\"invalidJson\":\"foo\"}"), out _));
        CheckTrue("security: empty media type key", () => !SecurityValidator.Validate(goodRed, JsonNode.Parse("{\"byContentType\":{\"\":\"block\"}}"), out _));
        CheckTrue("security: invalid allow regex", () => !SecurityValidator.Validate(JsonNode.Parse("{\"allow\":[\"(\"]}"), goodInsp, out _));
        CheckTrue("security: entropy out of range", () => !SecurityValidator.Validate(JsonNode.Parse("{\"detect\":{\"entropyThreshold\":9.5}}"), null, out _));
        CheckTrue("security: non-boolean enabled", () => !SecurityValidator.Validate(JsonNode.Parse("{\"enabled\":\"yes\"}"), null, out _));
        CheckTrue("security: entropy in range ok", () => SecurityValidator.Validate(JsonNode.Parse("{\"detect\":{\"entropyThreshold\":0}}"), null, out _));
        CheckTrue("security: null sections pass", () => SecurityValidator.Validate(null, null, out _));
    }

    // --------------------------------------------------------------
    static void TestImportValidator()
    {
        var good = JsonNode.Parse("{\"routes\":[],\"redaction\":{\"enabled\":true},\"inspection\":{\"defaultAction\":\"block\"}}");
        CheckTrue("import: valid bundle", () => ImportValidator.Validate(good, out _));
        CheckTrue("import: HasRoutes/HasSecurity", () => ImportValidator.HasRoutes(good) && ImportValidator.HasSecurity(good));

        CheckTrue("import: 'keys' rejected as secret-bearing", () =>
        {
            var no = !ImportValidator.Validate(JsonNode.Parse("{\"keys\":{\"UpstreamKey\":\"x\"}}"), out var errors);
            return no && errors.Any(e => e.Contains("could hold key values", StringComparison.OrdinalIgnoreCase));
        });

        CheckTrue("import: 'RouteKeys' rejected (case-insensitive)", () =>
        {
            var no = !ImportValidator.Validate(JsonNode.Parse("{\"routeKeys\":{}}"), out var errors);
            return no && errors.Any(e => e.Contains("could hold key values", StringComparison.OrdinalIgnoreCase));
        });

        CheckTrue("import: unsupported property", () =>
        {
            var no = !ImportValidator.Validate(JsonNode.Parse("{\"foo\":1}"), out var errors);
            return no && errors.Any(e => e.Contains("unsupported property", StringComparison.OrdinalIgnoreCase));
        });

        CheckTrue("import: routes must be array", () => !ImportValidator.Validate(JsonNode.Parse("{\"routes\":{}}"), out _));
        CheckTrue("import: redaction must be object", () => !ImportValidator.Validate(JsonNode.Parse("{\"redaction\":[]}"), out _));
        CheckTrue("import: not an object", () => !ImportValidator.Validate(JsonNode.Parse("[1,2]"), out _));
        CheckTrue("import: null bundle", () => !ImportValidator.Validate(null, out _));
    }

    // --------------------------------------------------------------
    static void TestAdminHash()
    {
        var hex = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("hello")));
        CheckTrue("hash: short = sha256 24", () => AdminHash.Short("hello") == hex[..24]);
        CheckTrue("hash: deterministic", () => AdminHash.Short("a") == AdminHash.Short("a"));
        CheckTrue("hash: different values differ", () => AdminHash.Short("a") != AdminHash.Short("b"));
        CheckTrue("hash: null -> dash", () => AdminHash.Short(null) == "-");
        CheckTrue("hash: empty -> dash", () => AdminHash.Short("") == "-");
    }

    // --------------------------------------------------------------
    static void TestAtomicWriter()
    {
        var root = TempRoot();
        var file = Path.Combine(root, "routes.json");

        var node = JsonNode.Parse("{\"Proxy\":{\"Routes\":[{\"name\":\"a\",\"prefix\":\"/a\"}],\"unknownProp\":{\"keep\":true}}}")!;
        AtomicJsonWriter.SaveAtomic(file, node);
        CheckTrue("writer: file exists", () => File.Exists(file));

        var bytes = File.ReadAllBytes(file);
        CheckTrue("writer: UTF-8 without BOM", () => bytes.Length >= 1 && bytes[0] != 0xEF);
        CheckTrue("writer: tmp cleaned up", () => !File.Exists(file + ".tmp"));

        var loaded = AtomicJsonWriter.Load(file);
        CheckTrue("writer: roundtrip", () => loaded is JsonObject o && o["Proxy"] is JsonObject p && p["Routes"] is JsonArray && p["unknownProp"] is JsonObject);

        // Patching preserves unknown properties (source of truth stays intact).
        loaded!["Proxy"]!["Routes"] = JsonNode.Parse("[]");
        AtomicJsonWriter.SaveAtomic(file, loaded);
        var reloaded = AtomicJsonWriter.Load(file);
        CheckTrue("writer: unknown props preserved on patch", () => reloaded is JsonObject o2 && o2["Proxy"]!["unknownProp"]!["keep"]!.GetValue<bool>() == true);

        // Comments/trailing commas tolerated on read.
        File.WriteAllText(file, "{\"Proxy\":{\"Routes\":[]},/*c*/}");
        CheckTrue("writer: comments tolerated", () => AtomicJsonWriter.Load(file) is JsonObject);

        CheckTrue("writer: missing file -> null", () => AtomicJsonWriter.Load(Path.Combine(root, "nope.json")) is null);

        // Error path: a failed save must also clean its .tmp (no residue after errors).
        CheckTrue("writer: error path cleans tmp", () =>
        {
            var blocker = Path.Combine(root, "blocked.json");
            Directory.CreateDirectory(blocker);
            try
            {
                try
                {
                    AtomicJsonWriter.SaveAtomic(blocker, JsonNode.Parse("{}")!);
                }
                catch
                {
                    // Expected: the destination is a directory, Replace/Move cannot win.
                }

                return !File.Exists(blocker + ".tmp");
            }
            finally
            {
                Directory.Delete(blocker, recursive: true);
            }
        });
    }

    // --------------------------------------------------------------
    static void TestConfigBackup()
    {
        var root = TempRoot();
        var paths = new DashboardPaths(root, root, Path.Combine(root, "data"));
        var backups = new ConfigBackup(paths);
        var target = Path.Combine(root, "routes.json");

        File.WriteAllText(target, "{\"v\":\"alpha\"}");
        backups.Backup(root, "routes.json");
        CheckTrue("backup: created", () => Directory.Exists(paths.BackupDir) && Directory.GetFiles(paths.BackupDir, "routes.json.*.bak").Length == 1);
        CheckTrue("backup: latest exists", () => backups.LatestBackup(root, "routes.json") is not null);

        // Restore overwrites the live file with the backup content.
        File.WriteAllText(target, "{\"v\":\"beta\"}");
        backups.Restore(root, "routes.json", backups.LatestBackup(root, "routes.json")!);
        CheckTrue("backup: restore", () => File.ReadAllText(target).Contains("\"alpha\"", StringComparison.Ordinal));

        // Retention: max 5 backups per file name, newest stays.
        for (var i = 0; i < 7; i++)
        {
            File.WriteAllText(target, $"{{\"v\":\"v{i}\"}}");
            backups.Backup(root, "routes.json");
            Thread.Sleep(3); // distinct millisecond timestamps
        }

        var remaining = Directory.GetFiles(paths.BackupDir, "routes.json.*.bak");
        CheckTrue("backup: retention caps at 5", () => remaining.Length == 5);
        var latest = backups.LatestBackup(root, "routes.json")!;
        CheckTrue("backup: latest is newest", () => File.ReadAllText(latest).Contains("\"v6\"", StringComparison.Ordinal));

        // Backup of a non-existent file is skipped.
        CheckTrue("backup: missing file skipped", () => backups.Backup(root, "nope.json").Count == 0);
    }

    // --------------------------------------------------------------
    static void TestReloadConfirmer()
    {
        var root = TempRoot();
        var paths = new DashboardPaths(root, root, Path.Combine(root, "data"));
        var backups = new ConfigBackup(paths);
        var confirmer = new ReloadConfirmer(backups);
        var target = Path.Combine(root, "routes.json");
        static bool Shape(JsonNode n) => n is JsonObject o && (o["Proxy"] is null || o["Proxy"] is JsonObject);

        // Valid file -> true, untouched.
        File.WriteAllText(target, "{\"Proxy\":{\"Routes\":[]}}");
        CheckTrue("confirm: valid -> true", () => confirmer.Confirm(root, "routes.json", Shape));
        CheckTrue("confirm: valid file untouched", () => File.ReadAllText(target).Contains("\"Routes\"", StringComparison.Ordinal));

        // Corrupt JSON with a backup -> false and the file is restored.
        File.WriteAllText(target, "{\"Proxy\":{\"Routes\":[]}}");
        backups.Backup(root, "routes.json");
        File.WriteAllText(target, "{this is not json");
        CheckTrue("confirm: corrupt -> false + restored", () =>
        {
            var no = !confirmer.Confirm(root, "routes.json", Shape);
            return no && File.ReadAllText(target).Contains("\"Routes\"", StringComparison.Ordinal);
        });

        // Valid JSON but wrong shape -> false + restored.
        File.WriteAllText(target, "{\"Proxy\":{\"Routes\":[]}}");
        backups.Backup(root, "routes.json");
        File.WriteAllText(target, "[1,2,3]");
        CheckTrue("confirm: wrong shape -> false + restored", () =>
        {
            var no = !confirmer.Confirm(root, "routes.json", Shape);
            return no && File.ReadAllText(target).Contains("\"Routes\"", StringComparison.Ordinal);
        });

        // Corrupt without backup -> false, file left as-is (no crash).
        var lonely = Path.Combine(root, "redaction.json");
        File.WriteAllText(lonely, "{oops");
        CheckTrue("confirm: no backup -> false, no crash", () => !confirmer.Confirm(root, "redaction.json", Shape));

        // ConfirmDetailed reports whether a restore actually happened.
        File.WriteAllText(target, "{\"Proxy\":{\"Routes\":[]}}");
        backups.Backup(root, "routes.json");
        File.WriteAllText(target, "[9,9,9]");
        var outcome = confirmer.ConfirmDetailed(root, "routes.json", Shape);
        CheckTrue("confirm: detailed reports restore", () => !outcome.Valid && outcome.Restored
            && File.ReadAllText(target).Contains("\"Routes\"", StringComparison.Ordinal));

        File.WriteAllText(lonely, "{oops");
        var noBackup = confirmer.ConfirmDetailed(root, "redaction.json", Shape);
        CheckTrue("confirm: detailed reports no backup", () => !noBackup.Valid && !noBackup.Restored);
    }

    // --------------------------------------------------------------
    static void TestKeyMetaStore()
    {
        var root = TempRoot();
        var paths = new DashboardPaths(root, root, Path.Combine(root, "data"));
        var store = new KeyMetaStore(paths);

        CheckTrue("meta: empty store", () => store.LoadAll().Count == 0 && store.Get("x") is null);

        store.Save(new Dictionary<string, KeyMeta>(StringComparer.Ordinal)
        {
            ["openai-main"] = new KeyMeta("ops", "production upstream"),
            ["default"] = new KeyMeta("", ""),
        });

        var all = store.LoadAll();
        CheckTrue("meta: roundtrip", () => all.Count == 2
            && all["openai-main"].Owner == "ops"
            && all["openai-main"].Purpose == "production upstream");
        CheckTrue("meta: get single", () => store.Get("openai-main") is { } m && m.Owner == "ops");
        CheckTrue("meta: file shape valid", () => KeyMetaStore.LooksValid(AtomicJsonWriter.Load(paths.KeyMetaPath)));
        CheckTrue("meta: missing file shape invalid", () => !KeyMetaStore.LooksValid(null));
    }

    // --------------------------------------------------------------
    static void TestAuditLog()
    {
        var root = TempRoot();
        var paths = new DashboardPaths(root, root, Path.Combine(root, "data"));
        var audit = new AuditLog(paths);

        audit.Append("key.secret.set", "Server #ref-a", "ok", AdminHash.Short("admin-key"));
        audit.Append("routes.apply", "routes.json", "restored", "-");

        CheckTrue("audit: file created", () => File.Exists(paths.AuditLogPath));
        var bytes = File.ReadAllBytes(paths.AuditLogPath);
        CheckTrue("audit: UTF-8 without BOM", () => bytes.Length > 0 && bytes[0] != 0xEF);

        var lines = File.ReadAllLines(paths.AuditLogPath).Where(l => !string.IsNullOrWhiteSpace(l)).ToList();
        CheckTrue("audit: two lines", () => lines.Count == 2);
        CheckTrue("audit: JSONL parseable", () => lines.All(l =>
        {
            try { _ = JsonDocument.Parse(l); return true; }
            catch (JsonException) { return false; }
        }));
        CheckTrue("audit: fields present", () =>
        {
            using var doc = JsonDocument.Parse(lines[0]);
            var root = doc.RootElement;
            return root.TryGetProperty("ts", out _)
                && root.TryGetProperty("action", out var a) && a.GetString() == "key.secret.set"
                && root.TryGetProperty("target", out _)
                && root.TryGetProperty("result", out var r) && r.GetString() == "ok"
                && root.TryGetProperty("actor", out var who) && who.GetString() == AdminHash.Short("admin-key");
        });
    }

    // --------------------------------------------------------------
    static void TestDashboardPaths()
    {
        var root = TempRoot();
        var deployBase = Path.Combine(root, "deploy");
        var deployCfg = Path.Combine(deployBase, "config");
        Directory.CreateDirectory(deployCfg);

        // Deploy layout: config/ subfolder -> data sits next to it.
        CheckTrue("paths: deploy data next to config", () => DashboardPaths.ResolveDataDir(deployCfg, deployBase) == Path.Combine(deployBase, "data"));

        // Dev layout: config == base -> data = base\data.
        CheckTrue("paths: dev data under base", () => DashboardPaths.ResolveDataDir(root, root) == Path.Combine(root, "data"));
    }

    // --------------------------------------------------------------
    static void TestServicePipeline()
    {
        var adminKey = "admin-primary-key";

        // --- ApplyRoutes: success writes routes.json + audit entry. ---
        var baseOptions = NewOptions();
        var (svc, root, cfg) = MakeService(baseOptions);
        var routes = new List<RouteDraft>
        {
            new("openai", "/openai", "https://api.openai.com", "openai-main"),
            new("default", "", "https://api.airouter.ch", ""),
        };

        var applied = svc.ApplyRoutes(routes);
        CheckTrue("svc: routes applied ok", () => applied.Ok && !applied.Restored);
        CheckTrue("svc: routes ok message", () => applied.Message.Contains("2 routes", StringComparison.Ordinal));

        var routesFile = Path.Combine(cfg, "routes.json");
        CheckTrue("svc: routes.json written", () =>
            AtomicJsonWriter.Load(routesFile) is JsonObject o
            && o["Proxy"] is JsonObject p
            && p["Routes"] is JsonArray arr
            && arr.Count == 2
            && arr[0]!["name"]!.GetValue<string>() == "openai");

        CheckTrue("svc: routes audit entry", () => File.ReadAllText(Path.Combine(cfg, "data", "audit.log")).Contains("routes.apply", StringComparison.Ordinal));

        // --- ApplyRoutes: validation error writes nothing. ---
        var (svc2, root2, cfg2) = MakeService(NewOptions());
        var dupRoutes = new List<RouteDraft>
        {
            new("same", "/a", "https://api.example.com", ""),
            new("same", "/b", "https://api.example.com", ""),
        };
        var invalid = svc2.ApplyRoutes(dupRoutes);
        CheckTrue("svc: invalid routes rejected", () => !invalid.Ok && invalid.ErrorType == AdminResult.TypeValidation);
        CheckTrue("svc: invalid routes wrote nothing", () => !File.Exists(Path.Combine(cfg2, "routes.json")));

        // --- ApplyRoutes: inactive keyRef surfaces as a warning. ---
        var opts = NewOptions();
        opts.RouteKeys = new Dictionary<string, string>(StringComparer.Ordinal) { ["declared-empty"] = "" };
        var (svc3, _, cfg3) = MakeService(opts);
        var warnRoutes = new List<RouteDraft> { new("x", "/x", "https://api.example.com", "declared-empty") };
        var warned = svc3.ApplyRoutes(warnRoutes);
        CheckTrue("svc: inactive keyRef warning", () => warned.Ok && warned.Warnings is { Length: > 0 }
            && warned.Warnings[0].Contains("inactive until the key is set", StringComparison.OrdinalIgnoreCase));
        _ = cfg3;

        // --- SetRouteKeySecret: writes into server config. ---
        var secret = "sk-SuperSecret123";
        var set = svc.SetRouteKeySecret("openai-main", secret, adminKey);
        CheckTrue("svc: secret set ok", () => set.Ok);
        CheckTrue("svc: secret stored in server config", () =>
            AtomicJsonWriter.Load(Path.Combine(root, "appsettings.Server.json")) is JsonObject so
            && so["Proxy"] is JsonObject sp
            && sp["RouteKeys"] is JsonObject rk
            && rk["openai-main"]!.GetValue<string>() == secret);

        // --- DeleteRouteKey: refused while in use. ---
        var del = svc.DeleteRouteKey("openai-main", adminKey);
        CheckTrue("svc: delete refused while in use", () => !del.Ok && del.ErrorType == AdminResult.TypeConflict);

        // --- UpdateKeyMeta: saved. ---
        var meta = svc.UpdateKeyMeta("openai-main", new KeyMeta("ops", "prod"), adminKey);
        CheckTrue("svc: meta saved", () => meta.Ok);
        CheckTrue("svc: meta persisted", () => File.ReadAllText(Path.Combine(root, "data", "key-meta.json")).Contains("\"ops\"", StringComparison.Ordinal));

        // --- Local keys: add (empty live list), then remove by fingerprint (seeded live list). ---
        var (svc4, root4, _) = MakeService(NewOptions());
        var added = svc4.AddLocalKey("extra-key-1", adminKey);
        CheckTrue("svc: local key added", () => added.Ok && added.Message.Contains("1 extra", StringComparison.Ordinal));
        var file4 = Path.Combine(root4, "appsettings.Server.json");
        CheckTrue("svc: local key persisted", () =>
            AtomicJsonWriter.Load(file4) is JsonObject o4
            && o4["Proxy"] is JsonObject p4
            && p4["Keys"] is JsonObject k4
            && k4["LocalKeys"] is JsonArray la
            && la.Count == 1
            && la[0]!.GetValue<string>() == "extra-key-1");

        var optsL = NewOptions();
        optsL.Keys.LocalKeys = new List<string> { "extra-key-1" };
        var (svcR, rootR, _) = MakeService(optsL);
        var removed = svcR.RemoveLocalKeyByHash(AdminHash.Short("extra-key-1"), adminKey);
        CheckTrue("svc: local key removed by fingerprint", () => removed.Ok);
        CheckTrue("svc: local key removal persisted", () =>
            AtomicJsonWriter.Load(Path.Combine(rootR, "appsettings.Server.json")) is JsonObject oR
            && oR["Proxy"]!["Keys"]!["LocalKeys"] is JsonArray rLa
            && rLa.Count == 0);

        // --- SetLocalKeyLabel: saves, validates, clears and is removed with its key. ---
        var optsLab = NewOptions();
        optsLab.Keys.LocalKeys = new List<string> { "extra-key-lab-1" };
        var (svcLab, rootLab, _) = MakeService(optsLab);
        var hash1 = AdminHash.Short("extra-key-lab-1");
        var lab = svcLab.SetLocalKeyLabel(hash1, "engenheiro 1", adminKey);
        CheckTrue("svc: local key label saved", () => lab.Ok);
        CheckTrue("svc: local key label persisted", () =>
            AtomicJsonWriter.Load(Path.Combine(rootLab, "data", "key-meta.json")) is JsonObject okm
            && okm["localKeys"] is JsonObject lkM
            && lkM[hash1] is JsonObject lkE
            && lkE["label"]!.GetValue<string>() == "engenheiro 1");

        var badHashLab = svcLab.SetLocalKeyLabel("DEADBEEF00", "nobody", adminKey);
        CheckTrue("svc: local key label unknown hash rejected", () => !badHashLab.Ok && badHashLab.ErrorType == AdminResult.TypeNotFound);

        var clearLab = svcLab.SetLocalKeyLabel(hash1, "   ", adminKey);
        CheckTrue("svc: clearing label ok", () => clearLab.Ok);
        CheckTrue("svc: clearing label removes it from the store", () =>
            !(AtomicJsonWriter.Load(Path.Combine(rootLab, "data", "key-meta.json")) is JsonObject ckm
              && ckm["localKeys"] is JsonObject clkM
              && clkM[hash1] is not null));

        var relab = svcLab.SetLocalKeyLabel(hash1, "portatil joao", adminKey);
        CheckTrue("svc: relabel ok", () => relab.Ok);
        var rmLab = svcLab.RemoveLocalKeyByHash(hash1, adminKey);
        CheckTrue("svc: remove labelled key ok", () => rmLab.Ok);
        CheckTrue("svc: label removed together with the key", () =>
            !(AtomicJsonWriter.Load(Path.Combine(rootLab, "data", "key-meta.json")) is JsonObject rkm
              && rkm["localKeys"] is JsonObject rlkM
              && rlkM[hash1] is not null));

        // --- SetUpstreamKey. ---
        var (svc5, root5, _) = MakeService(NewOptions());
        var upstream = svc5.SetUpstreamKey("sk-upstream-live-123", adminKey);
        CheckTrue("svc: upstream key set", () => upstream.Ok);
        CheckTrue("svc: upstream persisted", () =>
            AtomicJsonWriter.Load(Path.Combine(root5, "appsettings.Server.json")) is JsonObject o5
            && o5["Proxy"]!["Keys"]!["UpstreamKey"]!.GetValue<string>() == "sk-upstream-live-123");

        // --- ApplySecurity. ---
        var (svc6, root6, _) = MakeService(NewOptions());
        var red = JsonNode.Parse("{\"enabled\":false,\"detect\":{\"byLongStrings\":false}}")!;
        var insp = JsonNode.Parse("{\"enabled\":true,\"defaultAction\":\"block\",\"invalidJson\":\"warn\"}")!;
        var sec = svc6.ApplySecurity(red, insp);
        CheckTrue("svc: security applied", () => sec.Ok && !sec.Restored);
        CheckTrue("svc: redaction.json written", () =>
            AtomicJsonWriter.Load(Path.Combine(root6, "redaction.json")) is JsonObject o6
            && o6["Proxy"]!["Redaction"]!["enabled"]!.GetValue<bool>() == false);

        // --- Export: no secrets, correct shape. ---
        var exp = svc.Export();
        CheckTrue("svc: export ok with data", () => exp.Ok && exp.Data is not null);
        var json = exp.Data!.ToJsonString();
        CheckTrue("svc: export keeps keyRef names", () => json.Contains("\"openai-main\"", StringComparison.Ordinal));
        CheckTrue("svc: export has sections", () => json.Contains("\"routes\"", StringComparison.Ordinal) && json.Contains("\"redaction\"", StringComparison.Ordinal));
        CheckTrue("svc: export has no secret values", () => !json.Contains(secret, StringComparison.Ordinal)
            && !json.Contains("routeKeys", StringComparison.OrdinalIgnoreCase)
            && !json.Contains("upstreamKey", StringComparison.OrdinalIgnoreCase));

        // --- ValidateImport roundtrip of our own export. ---
        var check = svc.ValidateImport(exp.Data!);
        CheckTrue("svc: own export validates", () => check.Ok);
        CheckTrue("svc: own export has no warnings", () => check.Warnings is null or { Length: 0 });

        // --- Import applies routes + security. ---
        var (svc7, root7, cfg7) = MakeService(NewOptions());
        var bundle = JsonNode.Parse(
            "{\"routes\":[{\"name\":\"imp\",\"prefix\":\"/imp\",\"upstream\":\"https://api.example.com\",\"keyRef\":\"\"}]," +
            "\"redaction\":{\"enabled\":true},\"inspection\":{\"defaultAction\":\"pass\",\"invalidJson\":\"warn\"}}")!;
        var imp = svc7.Import(bundle, adminKey);
        CheckTrue("svc: import applied", () => imp.Ok && imp.Message.Contains("routes", StringComparison.Ordinal));
        CheckTrue("svc: import wrote routes", () =>
            AtomicJsonWriter.Load(Path.Combine(cfg7, "routes.json")) is JsonObject i1 && i1["Proxy"]!["Routes"] is JsonArray ia
            && ia.Count == 1 && ia[0]!["name"]!.GetValue<string>() == "imp");
        CheckTrue("svc: import wrote redaction", () =>
            AtomicJsonWriter.Load(Path.Combine(root7, "redaction.json")) is JsonObject i2 && i2["Proxy"]!["Redaction"]!["enabled"]!.GetValue<bool>() == true);

        // --- ReloadConfirm on a clean temp layout -> ok. ---
        var (svc8, _, cfg8) = MakeService(NewOptions());
        // seed valid files
        File.WriteAllText(Path.Combine(cfg8, "routes.json"), "{\"Proxy\":{\"Routes\":[]}}");
        File.WriteAllText(Path.Combine(cfg8, "redaction.json"), "{\"Proxy\":{\"Redaction\":{\"enabled\":true},\"Inspection\":{\"defaultAction\":\"block\"}}}");
        var rc = svc8.ReloadConfirm();
        CheckTrue("svc: reload confirm ok", () => rc.Ok);

        CheckTrue("svc: missing auth on Import rejected", () =>
        {
            var (s9, _, _) = MakeService(NewOptions());
            var r = s9.Import(JsonNode.Parse("{\"routes\":[]}")!, null);
            return !r.Ok && r.ErrorType == AdminResult.TypeAuthentication;
        });
        _ = root2;
    }

    // --------------------------------------------------------------
    static void TestSecretsNeverLeak()
    {
        var adminKey = "admin-primary-key";
        const string secretA = "sk-topsecret-AAAA-1111";
        const string secretB = "ghp_topsecret-2222";

        var (svc, root, _) = MakeService(NewOptions());

        // Success paths: the messages never echo the just-written value.
        var okA = svc.SetRouteKeySecret("ref-a", secretA, adminKey);
        CheckTrue("leak: set-secret message never contains value", () => okA.Ok && !SafeText(okA).Contains(secretA, StringComparison.Ordinal));

        var okB = svc.SetUpstreamKey(secretB, adminKey);
        CheckTrue("leak: upstream message never contains value", () => okB.Ok && !SafeText(okB).Contains(secretB, StringComparison.Ordinal));

        var okC = svc.AddLocalKey("local-topsecret-333", adminKey);
        CheckTrue("leak: add-local message never contains value", () => okC.Ok && !SafeText(okC).Contains("local-topsecret-333", StringComparison.Ordinal));

        // Failure paths: validation/auth errors never echo the value either.
        var badRef = svc.SetRouteKeySecret("ref with space", secretA, adminKey);
        CheckTrue("leak: invalid-ref errors hide value", () => !badRef.Ok && !SafeText(badRef).Contains(secretA, StringComparison.Ordinal));

        var badAuth = svc.SetRouteKeySecret("ref-a", secretB, "wrong-key");
        CheckTrue("leak: auth error hides value", () => !badAuth.Ok && !SafeText(badAuth).Contains(secretB, StringComparison.Ordinal));

        var dupOpts = NewOptions();
        dupOpts.Keys.LocalKeys = new List<string> { "local-topsecret-333" };
        var (svcDup, _, _) = MakeService(dupOpts);
        var dupLocal = svcDup.AddLocalKey("local-topsecret-333", adminKey);
        CheckTrue("leak: conflict error hides value", () => !dupLocal.Ok && dupLocal.ErrorType == AdminResult.TypeConflict
            && !SafeText(dupLocal).Contains("local-topsecret-333", StringComparison.Ordinal));

        // Export never contains values (even when configured).
        var exp = svc.Export();
        CheckTrue("leak: export hides configured secrets", () => exp.Ok && exp.Data is not null
            && !exp.Data!.ToJsonString().Contains("topsecret", StringComparison.OrdinalIgnoreCase));

        // Import of a bundle smuggling RouteKeys is refused with a clear generic message.
        var smuggling = JsonNode.Parse("{\"routes\":[],\"RouteKeys\":{\"ref-a\":\"sk-smuggled-999\"}}")!;
        var rejected = svc.ValidateImport(smuggling);
        CheckTrue("leak: smuggling bundle rejected", () => !rejected.Ok
            && !SafeText(rejected).Contains("sk-smuggled-999", StringComparison.Ordinal)
            && SafeText(rejected).Contains("could hold key values", StringComparison.OrdinalIgnoreCase));

        // The audit log never contains any of the values that passed through the service.
        var auditText = File.ReadAllText(Path.Combine(root, "data", "audit.log"));
        CheckTrue("leak: audit log clean", () => !auditText.Contains("topsecret", StringComparison.OrdinalIgnoreCase)
            && !auditText.Contains("sk-", StringComparison.Ordinal));
    }

    // --------------------------------------------------------------
    // Review fixes: item 1 - import rollback must only restore files this
    // operation actually wrote (security-only import failing its confirm must
    // leave routes.json untouched).
    // --------------------------------------------------------------
    static void TestImportRollbackScope()
    {
        var adminKey = "admin-primary-key";
        var root = TempRoot();
        var paths = new DashboardPaths(root, root, Path.Combine(root, "data"));
        var backups = new ConfigBackup(paths);
        var failing = new FailingConfirmer(backups);
        var svc = new DashboardAdminService(
            new TestOptionsMonitor<ProxyOptions>(NewOptions()),
            paths,
            backups,
            failing,
            new KeyMetaStore(paths),
            new AuditLog(paths),
            new ActivityStore(),
            new FakeEventLogStore(),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<DashboardAdminService>.Instance);

        var routesPath = Path.Combine(root, "routes.json");
        const string originalRoutes = "{\"Proxy\":{\"Routes\":[{\"name\":\"keep-me\",\"prefix\":\"/keep\",\"upstream\":\"https://api.example.com\",\"keyRef\":\"\"}]}}";
        File.WriteAllText(routesPath, originalRoutes);
        var routesHash = SHA256.HashData(File.ReadAllBytes(routesPath));

        var redPath = Path.Combine(root, "redaction.json");
        const string originalRed = "{\"Proxy\":{\"Redaction\":{\"enabled\":true},\"Inspection\":{\"defaultAction\":\"block\"}}}";
        File.WriteAllText(redPath, originalRed);
        backups.Backup(root, "redaction.json");

        // Security-only import; the redaction confirm fails (fake confirmer).
        var bundle = JsonNode.Parse("{\"redaction\":{\"enabled\":false}}")!;
        var result = svc.Import(bundle, adminKey);

        CheckTrue("rollback: import with failing redaction confirm reports failure+restored",
            () => !result.Ok && result.Restored && result.Message.Contains("restored", StringComparison.OrdinalIgnoreCase));
        CheckTrue("rollback: routes.json byte-identical (never touched)",
            () => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(routesPath))) == Convert.ToHexString(routesHash));
        CheckTrue("rollback: routes.json confirm never requested",
            () => !failing.Confirmed.Contains("routes.json"));
        CheckTrue("rollback: redaction restored to pre-import backup",
            () => File.ReadAllText(redPath) == originalRed);
        CheckTrue("rollback: only redaction confirm was attempted",
            () => failing.Confirmed.Count == 1 && failing.Confirmed[0] == "redaction.json");
    }

    // --------------------------------------------------------------
    // Review fixes: item 2 - concurrent writes through the singleton service
    // are serialized by the internal write lock: final file valid, no .tmp
    // residue, complete audit trail.
    // --------------------------------------------------------------
    static void TestConcurrentWrites()
    {
        const int n = 12;
        var (svc, root, cfg) = MakeService(NewOptions());
        var failures = new List<string>();

        Parallel.For(0, n, i =>
        {
            try
            {
                var drafts = new List<RouteDraft> { new($"r{i}", $"/p{i}", "https://api.example.com", "") };
                var r = svc.ApplyRoutes(drafts);
                if (!r.Ok)
                {
                    lock (failures) failures.Add("ApplyRoutes failed: " + r.Message);
                }
            }
            catch (Exception ex)
            {
                lock (failures) failures.Add("ApplyRoutes threw: " + ex.Message);
            }
        });

        CheckTrue("concurrent: no failures", () => failures.Count == 0);
        CheckTrue("concurrent: final routes.json valid",
            () => AtomicJsonWriter.Load(Path.Combine(cfg, "routes.json")) is JsonObject o
                && o["Proxy"] is JsonObject p && p["Routes"] is JsonArray a && a.Count == 1);
        CheckTrue("concurrent: no .tmp files left", () => Directory.GetFiles(root, "*.tmp", SearchOption.AllDirectories).Length == 0);

        var lines = File.ReadAllLines(Path.Combine(root, "data", "audit.log"))
            .Where(l => !string.IsNullOrWhiteSpace(l)).ToList();
        CheckTrue("concurrent: one audit entry per write", () => lines.Count == n);
    }

    // --------------------------------------------------------------
    // Review fixes: item 3 - ApplySecurity with only one section must leave
    // the other section (and RateLimit) intact.
    // --------------------------------------------------------------
    static void TestApplySecurityNullSections()
    {
        var (svc, root, _) = MakeService(NewOptions());
        var redPath = Path.Combine(root, "redaction.json");
        const string initial = "{\"Proxy\":{\"Redaction\":{\"enabled\":true},\"Inspection\":{\"defaultAction\":\"block\",\"invalidJson\":\"warn\"},\"RateLimit\":{\"enabled\":true}}}";
        File.WriteAllText(redPath, initial);

        // Only redaction supplied -> Inspection + RateLimit survive.
        var redOnly = JsonNode.Parse("{\"enabled\":false,\"detect\":{\"byLongStrings\":false}}")!;
        var r1 = svc.ApplySecurity(redOnly, null);
        CheckTrue("security: redaction-only ok", () => r1.Ok);

        var node1 = AtomicJsonWriter.Load(redPath)!;
        CheckTrue("security: inspection intact", () => node1["Proxy"]!["Inspection"]!["defaultAction"]!.GetValue<string>() == "block");
        CheckTrue("security: rateLimit intact", () => node1["Proxy"]!["RateLimit"]!["enabled"]!.GetValue<bool>() == true);
        CheckTrue("security: redaction updated", () => node1["Proxy"]!["Redaction"]!["enabled"]!.GetValue<bool>() == false);

        // Only inspection supplied -> Redaction survives.
        var inspOnly = JsonNode.Parse("{\"defaultAction\":\"pass\"}")!;
        var r2 = svc.ApplySecurity(null, inspOnly);
        CheckTrue("security: inspection-only ok", () => r2.Ok);

        var node2 = AtomicJsonWriter.Load(redPath)!;
        CheckTrue("security: redaction intact", () => node2["Proxy"]!["Redaction"]!["detect"]!["byLongStrings"]!.GetValue<bool>() == false);
        CheckTrue("security: inspection updated", () => node2["Proxy"]!["Inspection"]!["defaultAction"]!.GetValue<string>() == "pass");
        CheckTrue("security: rateLimit still intact", () => node2["Proxy"]!["RateLimit"]!["enabled"]!.GetValue<bool>() == true);
    }

    // --------------------------------------------------------------
    // Review fixes: item 4 - ReloadConfirm must signal a real restore
    // (Restored==true + file content = backup) instead of always claiming
    // "No backup was available".
    // --------------------------------------------------------------
    static void TestReloadConfirmRestoreSignaling()
    {
        var root = TempRoot();
        var paths = new DashboardPaths(root, root, Path.Combine(root, "data"));
        var backups = new ConfigBackup(paths);
        var svc = new DashboardAdminService(
            new TestOptionsMonitor<ProxyOptions>(NewOptions()),
            paths,
            backups,
            new ReloadConfirmer(backups),
            new KeyMetaStore(paths),
            new AuditLog(paths),
            new ActivityStore(),
            new FakeEventLogStore(),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<DashboardAdminService>.Instance);

        var redPath = Path.Combine(root, "redaction.json");
        const string good = "{\"Proxy\":{\"Redaction\":{\"enabled\":true},\"Inspection\":{\"defaultAction\":\"block\"}}}";
        File.WriteAllText(redPath, good);
        backups.Backup(root, "redaction.json");
        File.WriteAllText(redPath, "{corrupt json");

        var result = svc.ReloadConfirm();
        CheckTrue("reload: failed check reports restore", () => !result.Ok && result.Restored);
        CheckTrue("reload: message mentions the restore", () => result.Message.Contains("restored from backup", StringComparison.OrdinalIgnoreCase));
        CheckTrue("reload: file restored to the backup content", () => File.ReadAllText(redPath) == good);
        CheckTrue("reload: problem listed", () => result.Errors is { Length: > 0 } && result.Errors[0] == "redaction.json");
    }

    // --------------------------------------------------------------
    // Review fixes: item 5 - EnsureRouteKeyRef creates an empty RouteKeys
    // entry (fresh-install dead-end), is a no-op when present, rejects
    // invalid refs, and the declared-but-empty ref flows into route
    // validation as an "inactive" warning (dropdown scenario).
    // --------------------------------------------------------------
    static void TestEnsureRouteKeyRef()
    {
        var adminKey = "admin-primary-key";
        var (svc, root, _) = MakeService(NewOptions());

        var created = svc.EnsureRouteKeyRef("BRAND-NEW", adminKey);
        CheckTrue("keyref: create ok", () => created.Ok && created.Message.Contains("no secret yet", StringComparison.OrdinalIgnoreCase));
        var node = AtomicJsonWriter.Load(Path.Combine(root, "appsettings.Server.json"))!;
        CheckTrue("keyref: empty entry written", () => node["Proxy"]!["RouteKeys"]!["BRAND-NEW"]!.GetValue<string>() == string.Empty);

        // Existing ref -> no-op (no duplicate, no backup churn).
        var again = svc.EnsureRouteKeyRef("BRAND-NEW", adminKey);
        CheckTrue("keyref: existing ref is a no-op", () => again.Ok && again.Message.Contains("already exists", StringComparison.OrdinalIgnoreCase));
        var node2 = AtomicJsonWriter.Load(Path.Combine(root, "appsettings.Server.json"))!;
        CheckTrue("keyref: no duplicate entries", () => node2["Proxy"]!["RouteKeys"] is JsonObject rk && rk.Count == 1);

        // Invalid ref -> validation error.
        var bad = svc.EnsureRouteKeyRef("bad ref!", adminKey);
        CheckTrue("keyref: invalid ref rejected", () => !bad.Ok && bad.ErrorType == AdminResult.TypeValidation);

        // Sensitive file -> admin key required.
        var noAuth = svc.EnsureRouteKeyRef("ANOTHER", null);
        CheckTrue("keyref: admin key required", () => !noAuth.Ok && noAuth.ErrorType == AdminResult.TypeAuthentication);

        // Declared-but-empty ref: a route using it validates with an "inactive"
        // warning (the dropdown lists it, the route waits for the secret).
        var opts = NewOptions();
        opts.RouteKeys = new Dictionary<string, string>(StringComparer.Ordinal) { ["BRAND-NEW"] = string.Empty };
        var (svc2, _, _) = MakeService(opts);
        var drafts = new List<RouteDraft> { new("x", "/x", "https://api.example.com", "BRAND-NEW") };
        var r = svc2.ApplyRoutes(drafts);
        CheckTrue("keyref: route using empty ref warns inactive",
            () => r.Ok && r.Warnings is { Length: > 0 } && r.Warnings[0].Contains("inactive", StringComparison.OrdinalIgnoreCase));
    }

    // --------------------------------------------------------------
    // Debounce fix: a keyRef just written to appsettings.Server.json must be
    // recognized by ApplyRoutes IMMEDIATELY (Add keyRef -> Add route -> Save),
    // without waiting for the FileSystemWatcher reload. TestOptionsMonitor is
    // immutable, so the live snapshot never sees "FRESH" - only the fix's union
    // with the freshly re-read file makes this pass.
    // --------------------------------------------------------------
    static void TestFreshKeyRefUsableBeforeWatcherReload()
    {
        var adminKey = "admin-primary-key";
        var (svc, _, cfg) = MakeService(NewOptions());

        // 1) Create the ref - writes an empty RouteKeys entry to appsettings.Server.json.
        var created = svc.EnsureRouteKeyRef("FRESH", adminKey);
        CheckTrue("debounce: fresh keyRef created", () => created.Ok);

        // 2) IMMEDIATELY save a route that uses it - no watcher delay at all.
        var drafts = new List<RouteDraft> { new("fresh-route", "/fresh", "https://api.example.com", "FRESH") };
        var applied = svc.ApplyRoutes(drafts);
        CheckTrue("debounce: route with just-written keyRef applied ok", () => applied.Ok);
        CheckTrue("debounce: no 'does not exist' error", () => !SafeText(applied).Contains("does not exist", StringComparison.OrdinalIgnoreCase));
        CheckTrue("debounce: declared-but-empty ref warns inactive",
            () => applied.Warnings is { Length: > 0 } && applied.Warnings[0].Contains("inactive", StringComparison.OrdinalIgnoreCase));
        CheckTrue("debounce: route persisted with keyRef", () =>
            AtomicJsonWriter.Load(Path.Combine(cfg, "routes.json")) is JsonObject o
            && o["Proxy"] is JsonObject p
            && p["Routes"] is JsonArray a
            && a.Count == 1
            && a[0]!["keyRef"]!.GetValue<string>() == "FRESH");
    }

    // --------------------------------------------------------------
    // Review fixes: item 7 (service half) - the import pipeline writes ONLY
    // the known redaction/inspection properties; nested-smuggled fields never
    // reach redaction.json.
    // --------------------------------------------------------------
    static void TestImportSanitizesSecurity()
    {
        var adminKey = "admin-primary-key";
        var (svc, root, _) = MakeService(NewOptions());
        var bundle = JsonNode.Parse(
            "{\"redaction\":{\"enabled\":true,\"smuggled\":{\"secret\":\"x\"},\"detect\":{\"byFormats\":true,\"evil\":1}}," +
            "\"inspection\":{\"defaultAction\":\"block\",\"junk\":\"y\"}}")!;

        var r = svc.Import(bundle, adminKey);
        CheckTrue("import: sanitized bundle applied", () => r.Ok);

        var node = AtomicJsonWriter.Load(Path.Combine(root, "redaction.json"))!;
        var red = node["Proxy"]!["Redaction"]!;
        CheckTrue("import: unknown redaction prop dropped", () => red["smuggled"] is null);
        CheckTrue("import: unknown nested detect prop dropped", () => red["detect"] is JsonObject d && d["evil"] is null && d["byFormats"]!.GetValue<bool>() == true);
        CheckTrue("import: known redaction prop kept", () => red["enabled"]!.GetValue<bool>() == true);
        var insp = node["Proxy"]!["Inspection"]!;
        CheckTrue("import: unknown inspection prop dropped", () => insp["junk"] is null && insp["defaultAction"]!.GetValue<string>() == "block");
    }

    // --------------------------------------------------------------
    // Review fixes: item 8 - an empty import bundle is rejected with a clear
    // error instead of being applied as a no-op success.
    // --------------------------------------------------------------
    static void TestEmptyImportBundle()
    {
        var adminKey = "admin-primary-key";

        var (svc, root, _) = MakeService(NewOptions());
        var check = svc.ValidateImport(JsonNode.Parse("{}")!);
        CheckTrue("import: empty bundle rejected", () => !check.Ok && check.ErrorType == AdminResult.TypeValidation
            && check.Errors is { Length: > 0 } && check.Errors[0].Contains("empty import", StringComparison.OrdinalIgnoreCase));

        var (svc2, root2, _) = MakeService(NewOptions());
        var applied = svc2.Import(JsonNode.Parse("{}")!, adminKey);
        CheckTrue("import: empty bundle not applied", () => !applied.Ok
            && !File.Exists(Path.Combine(root2, "routes.json"))
            && !File.Exists(Path.Combine(root2, "redaction.json"))
            && !File.Exists(Path.Combine(root2, "appsettings.Server.json")));
        _ = root;
    }

    // --------------------------------------------------------------
    // Final review fixes: item 1 + 6 - wrong-typed security values are
    // validation errors (no GetValue throw / crash) and property lookups
    // are case-insensitive ("Enabled"/"DefaultAction" validate + apply,
    // preserving the values through the whitelist projection).
    // --------------------------------------------------------------
    static void TestSecurityWrongTypesAndCaseInsensitive()
    {
        var adminKey = "admin-primary-key";

        CheckTrue("security: allow numeric entry rejected", () =>
        {
            var no = !SecurityValidator.Validate(JsonNode.Parse("{\"allow\":[123]}"), null, out var errors);
            return no && errors.Any(e => e.Contains("must be a string", StringComparison.OrdinalIgnoreCase));
        });
        CheckTrue("security: defaultAction numeric rejected", () =>
        {
            var no = !SecurityValidator.Validate(null, JsonNode.Parse("{\"defaultAction\":123}"), out var errors);
            return no && errors.Any(e => e.Contains("must be a string", StringComparison.OrdinalIgnoreCase));
        });
        CheckTrue("security: byContentType numeric action rejected", () =>
        {
            var no = !SecurityValidator.Validate(null, JsonNode.Parse("{\"byContentType\":{\"application/json\":5}}"), out var errors);
            return no && errors.Any(e => e.Contains("must be a string", StringComparison.OrdinalIgnoreCase));
        });

        // Service level: validate AND import both reject as a validation error, nothing
        // is written and no exception escapes (previously GetValue<string> threw).
        var (svc, root, cfg) = MakeService(NewOptions());
        var bundles = new[]
        {
            JsonNode.Parse("{\"redaction\":{\"allow\":[123]}}")!,
            JsonNode.Parse("{\"inspection\":{\"defaultAction\":123}}")!,
            JsonNode.Parse("{\"inspection\":{\"byContentType\":{\"application/json\":5}}}")!,
        };
        for (var i = 0; i < bundles.Length; i++)
        {
            var check = svc.ValidateImport(bundles[i]);
            CheckTrue($"security-type: bundle {i} rejected on validate", () => !check.Ok && check.ErrorType == AdminResult.TypeValidation);
            var applied = svc.Import(bundles[i], adminKey);
            CheckTrue($"security-type: bundle {i} rejected on import", () => !applied.Ok && applied.ErrorType == AdminResult.TypeValidation);
        }

        CheckTrue("security-type: rejected imports wrote nothing", () =>
            !File.Exists(Path.Combine(cfg, "routes.json"))
            && !File.Exists(Path.Combine(cfg, "redaction.json"))
            && !File.Exists(Path.Combine(root, "appsettings.Server.json")));

        // Case-insensitivity: mixed-casing sections validate.
        CheckTrue("security: mixed-case sections validate", () => SecurityValidator.Validate(
            JsonNode.Parse("{\"Enabled\":true,\"Detect\":{\"ByFormats\":true,\"EntropyThreshold\":3.0},\"Allow\":[\"^ACME-\"]}"),
            JsonNode.Parse("{\"Enabled\":true,\"DefaultAction\":\"pass\",\"ByContentType\":{\"text/plain\":\"block\"}}"),
            out _));

        // Case-insensitivity: projection keeps the VALUES (canonical key casing).
        var red = SecurityValidator.SanitizeRedaction(JsonNode.Parse("{\"Enabled\":false,\"Detect\":{\"ByLongStrings\":false},\"Allow\":[\"^X-\"]}"));
        CheckTrue("security: mixed-case redaction projected with values", () =>
            red is JsonObject sr
            && sr["enabled"]!.GetValue<bool>() == false
            && sr["detect"] is JsonObject sd && sd["byLongStrings"]!.GetValue<bool>() == false
            && sr["allow"] is JsonArray sa && sa.Count == 1 && sa[0]!.GetValue<string>() == "^X-");

        var insp = SecurityValidator.SanitizeInspection(JsonNode.Parse("{\"Enabled\":true,\"DefaultAction\":\"inspect\",\"InvalidJson\":\"warn\"}"));
        CheckTrue("security: mixed-case inspection projected with values", () =>
            insp is JsonObject si
            && si["enabled"]!.GetValue<bool>() == true
            && si["defaultAction"]!.GetValue<string>() == "inspect"
            && si["invalidJson"]!.GetValue<string>() == "warn");

        // Case-insensitivity end-to-end through Import.
        var (svc2, root2, _) = MakeService(NewOptions());
        var mixed = JsonNode.Parse(
            "{\"redaction\":{\"Enabled\":false,\"Detect\":{\"ByFormats\":true},\"Allow\":[\"^ACME-\"]}," +
            "\"inspection\":{\"Enabled\":true,\"DefaultAction\":\"pass\",\"ByContentType\":{\"text/plain\":\"block\"}}}")!;
        var r = svc2.Import(mixed, adminKey);
        CheckTrue("security: mixed-case import applied", () => r.Ok);
        var node = AtomicJsonWriter.Load(Path.Combine(root2, "redaction.json"))!;
        CheckTrue("security: mixed-case import redaction values preserved", () =>
            node["Proxy"]!["Redaction"]!["enabled"]!.GetValue<bool>() == false
            && node["Proxy"]!["Redaction"]!["detect"]!["byFormats"]!.GetValue<bool>() == true
            && node["Proxy"]!["Redaction"]!["allow"] is JsonArray ar && ar.Count == 1 && ar[0]!.GetValue<string>() == "^ACME-");
        CheckTrue("security: mixed-case import inspection values preserved", () =>
            node["Proxy"]!["Inspection"]!["enabled"]!.GetValue<bool>() == true
            && node["Proxy"]!["Inspection"]!["defaultAction"]!.GetValue<string>() == "pass"
            && node["Proxy"]!["Inspection"]!["byContentType"]!["text/plain"]!.GetValue<string>() == "block");
    }

    // --------------------------------------------------------------
    // Final review fixes: item 3a - a combined routes+redaction import whose
    // SECOND confirm fails rolls back BOTH files, in reverse write order.
    // --------------------------------------------------------------
    static void TestImportTransactionalRollback()
    {
        var adminKey = "admin-primary-key";
        var root = TempRoot();
        var paths = new DashboardPaths(root, root, Path.Combine(root, "data"));
        var backups = new RecordingBackup(paths);
        var failing = new FailingConfirmer(backups, "redaction.json");
        var svc = new DashboardAdminService(
            new TestOptionsMonitor<ProxyOptions>(NewOptions()),
            paths,
            backups,
            failing,
            new KeyMetaStore(paths),
            new AuditLog(paths),
            new ActivityStore(),
            new FakeEventLogStore(),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<DashboardAdminService>.Instance);

        var routesPath = Path.Combine(root, "routes.json");
        const string originalRoutes = "{\"Proxy\":{\"Routes\":[{\"name\":\"a\",\"prefix\":\"/a\",\"upstream\":\"https://api.example.com\",\"keyRef\":\"\"}]}}";
        File.WriteAllText(routesPath, originalRoutes);

        var redPath = Path.Combine(root, "redaction.json");
        const string originalRed = "{\"Proxy\":{\"Redaction\":{\"enabled\":true},\"Inspection\":{\"defaultAction\":\"block\"}}}";
        File.WriteAllText(redPath, originalRed);

        var bundle = JsonNode.Parse(
            "{\"routes\":[{\"name\":\"b\",\"prefix\":\"/b\",\"upstream\":\"https://api.example.com\",\"keyRef\":\"\"}]," +
            "\"redaction\":{\"enabled\":false}}")!;
        var result = svc.Import(bundle, adminKey);

        CheckTrue("tximport: confirm-fail reports failure + restored", () => !result.Ok && result.Restored
            && result.Message.Contains("restored", StringComparison.OrdinalIgnoreCase));
        CheckTrue("tximport: routes.json restored to original", () => File.ReadAllText(routesPath) == originalRoutes);
        CheckTrue("tximport: redaction.json restored to original", () => File.ReadAllText(redPath) == originalRed);
        CheckTrue("tximport: both confirms attempted in write order", () => failing.Confirmed.Count == 2
            && failing.Confirmed[0] == "routes.json" && failing.Confirmed[1] == "redaction.json");
        CheckTrue("tximport: restores happen in reverse write order", () => backups.Restored.Count == 2
            && backups.Restored[0] == "redaction.json" && backups.Restored[1] == "routes.json");
    }

    // --------------------------------------------------------------
    // Final review fixes: item 3b - when the SECOND file's SaveAtomic throws
    // (target path is a directory instead of a file), the FIRST file that was
    // already written is rolled back and the message admits it.
    // --------------------------------------------------------------
    static void TestImportSaveAtomicFailureRollsBack()
    {
        var adminKey = "admin-primary-key";
        var root = TempRoot();
        var paths = new DashboardPaths(root, root, Path.Combine(root, "data"));
        var backups = new RecordingBackup(paths);
        var svc = new DashboardAdminService(
            new TestOptionsMonitor<ProxyOptions>(NewOptions()),
            paths,
            backups,
            new ReloadConfirmer(backups),
            new KeyMetaStore(paths),
            new AuditLog(paths),
            new ActivityStore(),
            new FakeEventLogStore(),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<DashboardAdminService>.Instance);

        var routesPath = Path.Combine(root, "routes.json");
        const string originalRoutes = "{\"Proxy\":{\"Routes\":[{\"name\":\"a\",\"prefix\":\"/a\",\"upstream\":\"https://api.example.com\",\"keyRef\":\"\"}]}}";
        File.WriteAllText(routesPath, originalRoutes);

        // redaction.json is a DIRECTORY: SaveAtomic's Replace/Move cannot win, so the
        // 2nd file's write throws after the 1st file was already applied.
        Directory.CreateDirectory(Path.Combine(root, "redaction.json"));

        var bundle = JsonNode.Parse(
            "{\"routes\":[{\"name\":\"b\",\"prefix\":\"/b\",\"upstream\":\"https://api.example.com\",\"keyRef\":\"\"}]," +
            "\"redaction\":{\"enabled\":false}}")!;
        var result = svc.Import(bundle, adminKey);

        CheckTrue("tximport-save: reports rollback honestly", () => !result.Ok
            && result.Message.Contains("rolled back", StringComparison.OrdinalIgnoreCase)
            && result.Message.Contains("no changes applied", StringComparison.OrdinalIgnoreCase));
        CheckTrue("tximport-save: signals restored", () => result.Restored);
        CheckTrue("tximport-save: first written file restored", () => File.ReadAllText(routesPath) == originalRoutes);
        CheckTrue("tximport-save: only the written file was restored", () => backups.Restored.Count == 1 && backups.Restored[0] == "routes.json");
        CheckTrue("tximport-save: no tmp residue", () => !File.Exists(routesPath + ".tmp") && !File.Exists(routesPath + ".restore.tmp"));
    }

    // --------------------------------------------------------------
    // Final review fixes: item 4 - a backup that exists but cannot be restored
    // (locked file) surfaces as RestoreFailed with an honest message, not
    // "No backup was available".
    // --------------------------------------------------------------
    static void TestReloadConfirmRestoreFailedSignaling()
    {
        var root = TempRoot();
        var paths = new DashboardPaths(root, root, Path.Combine(root, "data"));
        var restorer = new FailingRestorer(paths);
        var confirmer = new ReloadConfirmer(restorer);
        var svc = new DashboardAdminService(
            new TestOptionsMonitor<ProxyOptions>(NewOptions()),
            paths,
            restorer,
            confirmer,
            new KeyMetaStore(paths),
            new AuditLog(paths),
            new ActivityStore(),
            new FakeEventLogStore(),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<DashboardAdminService>.Instance);

        var redPath = Path.Combine(root, "redaction.json");
        const string good = "{\"Proxy\":{\"Redaction\":{\"enabled\":true}}}";
        File.WriteAllText(redPath, good);
        restorer.Backup(root, "redaction.json");
        File.WriteAllText(redPath, "{corrupt json");
        static bool Shape(JsonNode n) => n is JsonObject o && o["Proxy"] is JsonObject;

        // Direct tri-state outcome: backup found, restore FAILED.
        var outcome = confirmer.ConfirmDetailed(root, "redaction.json", Shape);
        CheckTrue("reload: restore-failed tri-state", () => !outcome.Valid && !outcome.Restored && outcome.RestoreFailed);
        CheckTrue("reload: restore attempt recorded", () => restorer.Attempted.Count == 1 && restorer.Attempted[0] == "redaction.json");

        // Service level: honest message, no "No backup was available" claim.
        var result = svc.ReloadConfirm();
        CheckTrue("reload: failed check flagged", () => !result.Ok);
        CheckTrue("reload: message reports restore failure", () => result.Message.Contains("restore failed", StringComparison.OrdinalIgnoreCase)
            && result.Message.Contains("permissions", StringComparison.OrdinalIgnoreCase));
        CheckTrue("reload: message no longer claims no backup", () => !result.Message.Contains("No backup was available", StringComparison.OrdinalIgnoreCase));
        CheckTrue("reload: problem listed", () => result.Errors is { Length: > 0 } && result.Errors[0] == "redaction.json");
    }

    // --------------------------------------------------------------
    // 2.6.1: ConfigFileReader - post-save refresh straight from disk
    // (the FileSystemWatcher reload is debounced, so the live snapshot
    // is still stale right after SaveAtomic).
    // --------------------------------------------------------------
    static void TestConfigFileReader()
    {
        var root = TempRoot();

        // Pure node reader: correct list, absent Routes -> null, null proxy node -> null.
        var node = JsonNode.Parse(
            "{\"Routes\":[" +
            "{\"name\":\"a\",\"prefix\":\"/a\",\"upstream\":\"https://a.example.com\",\"keyRef\":\"KA\"}," +
            "{\"name\":\"b\",\"prefix\":\"/b\",\"upstream\":\"https://b.example.com\"}]}")!;
        var routes = ConfigFileReader.ReadRoutesFromNode(node);
        CheckTrue("disk-read: routes from node", () => routes is { Count: 2 }
            && routes[0].Name == "a" && routes[0].Prefix == "/a" && routes[0].KeyRef == "KA"
            && routes[1].Name == "b" && routes[1].KeyRef is null);
        CheckTrue("disk-read: routes node without Routes -> null", () => ConfigFileReader.ReadRoutesFromNode(JsonNode.Parse("{}")) is null);
        CheckTrue("disk-read: routes null proxy node -> null", () => ConfigFileReader.ReadRoutesFromNode(null) is null);

        // camelCase property names map through (case-insensitive deserialization).
        var mixed = JsonNode.Parse(
            "{\"Routes\":[{\"Name\":\"X\",\"Prefix\":\"/x\",\"Upstream\":\"https://x.example.com\",\"AllowedPaths\":[\"/v1/*\"],\"RequestTimeoutMs\":5000}]}")!;
        var mixedRoutes = ConfigFileReader.ReadRoutesFromNode(mixed);
        CheckTrue("disk-read: camelCase mapped (case-insensitive)", () => mixedRoutes is { Count: 1 }
            && mixedRoutes[0].Name == "X" && mixedRoutes[0].Prefix == "/x"
            && mixedRoutes[0].AllowedPaths.Count == 1 && mixedRoutes[0].AllowedPaths[0] == "/v1/*"
            && mixedRoutes[0].RequestTimeoutMs == 5000);

        // File-level routes: comments/trailing commas tolerated, corrupt -> null, missing -> null.
        File.WriteAllText(Path.Combine(root, "routes.json"),
            "{\n// route table\n\"Proxy\": {\"Routes\": [{\"name\":\"c\",\"prefix\":\"/c\",\"upstream\":\"https://c.example.com\"}]},\n}");
        CheckTrue("disk-read: routes file with comments parses", () => ConfigFileReader.ReadRoutes(root) is { Count: 1 } r && r[0].Name == "c");

        File.WriteAllText(Path.Combine(root, "routes.json"), "{not json");
        CheckTrue("disk-read: corrupt routes file -> null", () => ConfigFileReader.ReadRoutes(root) is null);

        CheckTrue("disk-read: missing routes file -> null", () => ConfigFileReader.ReadRoutes(Path.Combine(root, "empty-dir")) is null);

        // Empty route table is a VALID saved state ("route table cleared"): empty non-null.
        File.WriteAllText(Path.Combine(root, "routes.json"), "{\"Proxy\":{\"Routes\":[]}}");
        CheckTrue("disk-read: empty routes table -> empty list (valid state)",
            () => ConfigFileReader.ReadRoutes(root) is { Count: 0 });

        // ReadSecurity: only the Redaction section present -> others null; corrupt/missing -> null.
        File.WriteAllText(Path.Combine(root, "redaction.json"),
            "{\"Proxy\":{\"Redaction\":{\"enabled\":false,\"mask\":\"**\",\"detect\":{\"byLongStrings\":false}}}}");
        var sec = ConfigFileReader.ReadSecurity(root);
        CheckTrue("disk-read: security redaction only", () => sec is { Redaction: not null }
            && sec.Redaction!.Enabled == false && sec.Redaction.Mask == "**"
            && sec.Redaction.Detect.ByLongStrings == false
            && sec.Inspection is null && sec.RateLimit is null);

        File.WriteAllText(Path.Combine(root, "redaction.json"),
            "{\"Proxy\":{\"Inspection\":{\"enabled\":true,\"defaultAction\":\"pass\"},\"RateLimit\":{\"enabled\":false,\"maxRequestsPerWindow\":99}}}");
        var sec2 = ConfigFileReader.ReadSecurity(root);
        CheckTrue("disk-read: security inspection+ratelimit sections", () => sec2 is { Inspection: not null, RateLimit: not null }
            && sec2.Inspection!.Enabled == true && sec2.Inspection.DefaultAction == "pass"
            && sec2.Redaction is null
            && sec2.RateLimit!.Enabled == false && sec2.RateLimit.MaxRequestsPerWindow == 99);

        File.WriteAllText(Path.Combine(root, "redaction.json"), "{broken");
        CheckTrue("disk-read: corrupt redaction file -> null", () => ConfigFileReader.ReadSecurity(root) is null);

        CheckTrue("disk-read: missing redaction file -> null", () => ConfigFileReader.ReadSecurity(Path.Combine(root, "empty-dir")) is null);

        // ReadServerKeys: RouteKeys + Keys read. Values stay in-process; the UI only ever
        // sees PRESENCE derived from them (asserted by the ConfiguredKeys projection in the
        // merge tests below - the service-level tests corroborate the write-only contract
        // for views/messages).
        const string fake = "sk-test-abc-1234567890abcdef";
        File.WriteAllText(Path.Combine(root, "appsettings.Server.json"),
            "{\"Proxy\":{\"RouteKeys\":{\"FAKE\":\"" + fake + "\"}," +
            "\"Keys\":{\"UpstreamKey\":\"" + fake + "\",\"LocalKey\":\"local-dev\",\"LocalKeys\":[\"extra-1\"]}}}");

        var snap = ConfigFileReader.ReadServerKeys(root);
        CheckTrue("disk-read: server keys snapshot", () => snap is { Proxy: not null }
            && snap.Proxy!.RouteKeys["FAKE"] == fake
            && snap.Proxy.Keys!.UpstreamKey == fake
            && snap.Proxy.Keys.LocalKey == "local-dev"
            && snap.Proxy.Keys.LocalKeys.Count == 1);

        CheckTrue("disk-read: missing server keys -> null", () => ConfigFileReader.ReadServerKeys(Path.Combine(root, "empty-dir")) is null);

        File.WriteAllText(Path.Combine(root, "appsettings.Server.json"), "\"not-an-object\"");
        CheckTrue("disk-read: wrong-shape server keys -> null", () => ConfigFileReader.ReadServerKeys(root) is null);

        // Merge helpers: DISK-first. The file just written is the truth; the live snapshot
        // is stale right after a save (debounced watcher reload) and must never resurrect a
        // deleted ref nor overwrite a fresh value. Disk null = no appsettings.Server.json
        // (env-only config) - then the live map is returned unchanged.

        // Presence projection: the ONLY strings the UI derives from a merged RouteKeys map.
        // Key VALUES never enter it (or any view/message) - only "configured"/"not-set".
        static string ConfiguredKeys(Dictionary<string, string> merged)
            => string.Join(",", merged
                .OrderBy(kv => kv.Key, StringComparer.Ordinal)
                .Select(kv => kv.Key + ":" + (string.IsNullOrWhiteSpace(kv.Value) ? "not-set" : "configured")));

        const string mergeFake = "sk-secret";
        var diskRouteKeys = new Dictionary<string, string>(StringComparer.Ordinal) { ["A"] = mergeFake, ["B"] = "" };
        var staleLiveRouteKeys = new Dictionary<string, string>(StringComparer.Ordinal) { ["A"] = "", ["C"] = "env-only" };
        var mergedKeys = ConfigFileReader.MergeRouteKeys(diskRouteKeys, staleLiveRouteKeys);
        CheckTrue("merge: routeKeys disk decides presence (no gap-fill from stale live)", () => mergedKeys.Count == 2
            && mergedKeys["A"] == mergeFake && mergedKeys["B"] == "");
        CheckTrue("merge: fresh disk value wins over stale empty live (configured)",
            () => ConfiguredKeys(mergedKeys).Contains("A:configured", StringComparison.Ordinal));
        CheckTrue("merge: secret never appears in the presence projection",
            () => !ConfiguredKeys(mergedKeys).Contains(mergeFake, StringComparison.Ordinal));

        var nullMerged = ConfigFileReader.MergeRouteKeys(null, staleLiveRouteKeys);
        CheckTrue("merge: routeKeys null disk (env-only) -> live pure", () => nullMerged.Count == 2
            && nullMerged["A"] == "" && nullMerged["C"] == "env-only");
        CheckTrue("merge: routeKeys null live -> disk pure", () => ConfigFileReader.MergeRouteKeys(diskRouteKeys, null)["B"] == "");

        // Keys: per-field disk first; LocalKeys is a unit (the disk list wins even empty).
        var diskKeyOpts = new KeyOptions { UpstreamKey = "fresh", LocalKeys = new List<string>() };
        var staleLiveKeys = new KeyOptions { UpstreamKey = "", LocalKey = "lk", LocalKeys = new List<string> { "x", "y" } };
        var m1 = ConfigFileReader.MergeKeys(diskKeyOpts, staleLiveKeys);
        CheckTrue("merge: keys disk-first per field, local list as a unit", () => m1.UpstreamKey == "fresh"
            && m1.LocalKey == "lk" && m1.LocalKeys.Count == 0);

        var diskWithExtras = new KeyOptions { UpstreamKey = "disk-up", LocalKey = "disk-local", LocalKeys = new List<string> { "disk-extra" } };
        var fullLive = new KeyOptions { UpstreamKey = "live-up", LocalKey = "live-local", LocalKeys = new List<string> { "live-extra" } };
        var m2 = ConfigFileReader.MergeKeys(diskWithExtras, fullLive);
        CheckTrue("merge: keys disk list wins even when live has extras", () => m2.UpstreamKey == "disk-up"
            && m2.LocalKey == "disk-local" && m2.LocalKeys.Count == 1 && m2.LocalKeys[0] == "disk-extra");

        var nullMergedKeys = ConfigFileReader.MergeKeys(null, fullLive);
        CheckTrue("merge: keys null disk (env-only) -> live pure", () => nullMergedKeys.UpstreamKey == "live-up" && nullMergedKeys.LocalKeys[0] == "live-extra");
        var nullLiveKeys = ConfigFileReader.MergeKeys(diskKeyOpts, null);
        CheckTrue("merge: keys null live -> disk pure", () => nullLiveKeys.UpstreamKey == "fresh"
            && nullLiveKeys.LocalKey is null && nullLiveKeys.LocalKeys.Count == 0);
    }

    // --------------------------------------------------------------
    // Log clearing: destructive operations require the admin key, the
    // activity buffer is emptied only after auth, and the audit log records
    // the clear. Event Log behaviour is exercised through the IEventLogStore
    // fake - these checks NEVER touch the machine's real Windows Event Log.
    // --------------------------------------------------------------
    static void TestLogClearing()
    {
        var adminKey = "admin-primary-key";
        var (svc, root, cfg, store, eventLogs) = MakeServiceWithStore(NewOptions());

        store.Add(new ActivityEntry { Timestamp = DateTimeOffset.UtcNow, Client = "test", Method = "GET", Path = "/one", Status = 200 });
        store.Add(new ActivityEntry { Timestamp = DateTimeOffset.UtcNow, Client = "test", Method = "POST", Path = "/two", Status = 401 });

        var noAuth = svc.ClearActivityLog(null);
        CheckTrue("logs: clear activity requires admin key", () => !noAuth.Ok && noAuth.ErrorType == AdminResult.TypeAuthentication);
        CheckTrue("logs: unauthorized clear keeps the entries", () => store.Count == 2);

        var wrongKey = svc.ClearActivityLog("wrong");
        CheckTrue("logs: clear activity wrong key rejected", () => !wrongKey.Ok && wrongKey.ErrorType == AdminResult.TypeAuthentication);
        CheckTrue("logs: wrong key keeps the entries", () => store.Count == 2);

        var cleared = svc.ClearActivityLog(adminKey);
        CheckTrue("logs: clear activity ok", () => cleared.Ok);
        CheckTrue("logs: activity buffer emptied", () => store.Count == 0);
        CheckTrue("logs: activity clear audited", () =>
            File.ReadAllText(Path.Combine(cfg, "data", "audit.log")).Contains("logs.clear.activity", StringComparison.Ordinal));

        // Unauthorized Event Log clear must not reach the log at all.
        var noAuthEvent = svc.ClearEventLog(null);
        CheckTrue("logs: clear event log requires admin key", () => !noAuthEvent.Ok && noAuthEvent.ErrorType == AdminResult.TypeAuthentication);
        CheckTrue("logs: unauthorized event log clear never calls the log", () => eventLogs.ClearCalls == 0);

        // Log does not exist -> success ("nothing to clear"), no Clear call, audited unavailable.
        eventLogs.ExistsResult = false;
        var missing = svc.ClearEventLog(adminKey);
        CheckTrue("logs: missing event log -> ok", () => missing.Ok);
        CheckTrue("logs: missing event log -> nothing to clear", () => missing.Message.Contains("nothing to clear", StringComparison.OrdinalIgnoreCase));
        CheckTrue("logs: missing event log -> no clear call", () => eventLogs.ClearCalls == 0);
        CheckTrue("logs: missing event log audited unavailable", () =>
        {
            var audit = File.ReadAllText(Path.Combine(cfg, "data", "audit.log"));
            return audit.Contains("\"logs.clear.eventlog\"", StringComparison.Ordinal)
                && audit.Contains("\"unavailable\"", StringComparison.Ordinal);
        });

        // Existing log -> success with the entry count, exactly one Clear call.
        eventLogs.ExistsResult = true;
        eventLogs.CountResult = 3;
        var clearedEvent = svc.ClearEventLog(adminKey);
        CheckTrue("logs: event log cleared ok", () => clearedEvent.Ok);
        CheckTrue("logs: event log message carries the count", () => clearedEvent.Message.Contains("3", StringComparison.Ordinal));
        CheckTrue("logs: event log cleared exactly once", () => eventLogs.ClearCalls == 1);

        // Clear throws -> clean internal failure, generic message, never rethrown.
        eventLogs.ThrowOnClear = true;
        AdminResult? throwing = null;
        CheckTrue("logs: event log clear failure never throws", () =>
        {
            try
            {
                throwing = svc.ClearEventLog(adminKey);
                return true;
            }
            catch
            {
                return false;
            }
        });
        CheckTrue("logs: event log clear failure is internal", () =>
            throwing is not null && !throwing.Ok && throwing.ErrorType == AdminResult.TypeInternal);
        CheckTrue("logs: event log failure message is generic", () =>
            throwing is not null
            && !SafeText(throwing).Contains("UnauthorizedAccess", StringComparison.OrdinalIgnoreCase)
            && !SafeText(throwing).Contains("InvalidOperationException", StringComparison.OrdinalIgnoreCase)
            && !SafeText(throwing).Contains("boom", StringComparison.OrdinalIgnoreCase));
        _ = root;
    }

    // --------------------------------------------------------------
    // Log clearing resilience (review fixes):
    //  R3 - a failing audit write must NOT fail (or undo) the destructive clear;
    //  R2 - concurrent audit appends must all land as parseable JSONL lines;
    //  generic message - the Event Log failure must not leak the exception text,
    //  machine paths or the exception type.
    // --------------------------------------------------------------
    static void TestLogClearingResilience()
    {
        var adminKey = "admin-primary-key";

        // R3: DataDir is a FILE, so AuditLog's Directory.CreateDirectory fails and
        // every audit append throws. The clear must still succeed and say so.
        var root = TempRoot();
        File.WriteAllText(Path.Combine(root, "blocked"), "x");
        var paths = new DashboardPaths(root, root, Path.Combine(root, "blocked"));
        var backups = new ConfigBackup(paths);
        var activity = new ActivityStore();
        var svc = new DashboardAdminService(
            new TestOptionsMonitor<ProxyOptions>(NewOptions()),
            paths,
            backups,
            new ReloadConfirmer(backups),
            new KeyMetaStore(paths),
            new AuditLog(paths),
            activity,
            new FakeEventLogStore(),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<DashboardAdminService>.Instance);

        activity.Add(new ActivityEntry { Timestamp = DateTimeOffset.UtcNow, Client = "test", Method = "GET", Path = "/one", Status = 200 });
        activity.Add(new ActivityEntry { Timestamp = DateTimeOffset.UtcNow, Client = "test", Method = "POST", Path = "/two", Status = 401 });

        var auditFailed = svc.ClearActivityLog(adminKey);
        CheckTrue("logs-audit: failing audit does not fail the clear", () => auditFailed.Ok);
        CheckTrue("logs-audit: failing audit still empties the buffer", () => activity.Count == 0);
        CheckTrue("logs-audit: failing audit is disclosed to the caller", () =>
            auditFailed.Message.Contains("audit entry could not be written", StringComparison.OrdinalIgnoreCase));

        // R2: 50 concurrent appends -> 50 non-empty, individually parseable JSON lines.
        var auditRoot = TempRoot();
        var auditPaths = new DashboardPaths(auditRoot, auditRoot, Path.Combine(auditRoot, "data"));
        var audit = new AuditLog(auditPaths);
        Parallel.For(0, 50, i => audit.Append("test", "t", "ok", "-"));

        var lines = File.ReadAllLines(auditPaths.AuditLogPath).Where(l => l.Length > 0).ToList();
        CheckTrue("audit: 50 concurrent appends produce 50 lines", () => lines.Count == 50);
        CheckTrue("audit: every concurrent line is valid JSON", () =>
        {
            foreach (var line in lines)
            {
                try
                {
                    using var doc = JsonDocument.Parse(line);
                }
                catch (JsonException)
                {
                    return false;
                }
            }

            return true;
        });

        // Generic message: the exception carries "Access denied" + a machine path, none
        // of which may reach the caller.
        var genericRoot = TempRoot();
        var genericPaths = new DashboardPaths(genericRoot, genericRoot, Path.Combine(genericRoot, "data"));
        var genericBackups = new ConfigBackup(genericPaths);
        var throwingLogs = new FakeEventLogStore
        {
            ExistsResult = true,
            ClearException = new UnauthorizedAccessException(@"Access denied for C:\Services\AIRouterProxy"),
        };
        var genericSvc = new DashboardAdminService(
            new TestOptionsMonitor<ProxyOptions>(NewOptions()),
            genericPaths,
            genericBackups,
            new ReloadConfirmer(genericBackups),
            new KeyMetaStore(genericPaths),
            new AuditLog(genericPaths),
            new ActivityStore(),
            throwingLogs,
            Microsoft.Extensions.Logging.Abstractions.NullLogger<DashboardAdminService>.Instance);

        var denied = genericSvc.ClearEventLog(adminKey);
        const string expected = "Could not clear the Windows Event Log - it may require elevated rights or be in use.";
        CheckTrue("logs-eventlog: failure message is exactly the generic one", () => denied.Message == expected);
        CheckTrue("logs-eventlog: failure leaks no exception detail", () =>
            !SafeText(denied).Contains("Access denied", StringComparison.OrdinalIgnoreCase)
            && !SafeText(denied).Contains(@"C:\Services", StringComparison.OrdinalIgnoreCase)
            && !SafeText(denied).Contains("UnauthorizedAccess", StringComparison.OrdinalIgnoreCase));
    }

    // --------------------------------------------------------------
    // Log clearing safety (review fix M6): the destructive clears touch ONLY
    // the in-memory activity buffer and the (fake) Event Log. The audit trail
    // and the config files/backups are never deleted or modified - they are
    // not clearable through this surface.
    // --------------------------------------------------------------
    static void TestLogClearingSafety()
    {
        var adminKey = "admin-primary-key";
        var (svc, root, cfg, store, eventLogs) = MakeServiceWithStore(NewOptions());

        // Pre-existing audit trail (sentinel line) + a config file with a backup.
        var dataDir = Path.Combine(root, "data");
        Directory.CreateDirectory(dataDir);
        var auditPath = Path.Combine(dataDir, "audit.log");
        const string sentinel = "{\"ts\":\"sentinel\",\"action\":\"pre-existing\"}";
        File.WriteAllText(auditPath, sentinel + Environment.NewLine);

        var routesPath = Path.Combine(cfg, "routes.json");
        const string routesContent = "{\"Proxy\":{\"Routes\":[]}}";
        File.WriteAllText(routesPath, routesContent);

        var backups = new ConfigBackup(new DashboardPaths(root, root, dataDir));
        var created = backups.Backup(cfg, "routes.json");
        CheckTrue("logs-safety: routes.json backup created", () => created.Count == 1 && File.Exists(created[0]));

        store.Add(new ActivityEntry { Timestamp = DateTimeOffset.UtcNow, Client = "test", Method = "GET", Path = "/one", Status = 200 });
        eventLogs.ExistsResult = true;
        eventLogs.CountResult = 5;

        var activity = svc.ClearActivityLog(adminKey);
        var eventLog = svc.ClearEventLog(adminKey);
        CheckTrue("logs-safety: both clears succeed", () => activity.Ok && eventLog.Ok);
        CheckTrue("logs-safety: activity buffer emptied", () => store.Count == 0);
        CheckTrue("logs-safety: event log cleared", () => eventLogs.ClearCalls == 1);

        // Nothing besides the logs: audit trail keeps its pre-existing line, routes.json
        // keeps its exact content and the backup survives.
        CheckTrue("logs-safety: audit trail keeps the pre-existing line", () =>
            File.Exists(auditPath) && File.ReadAllText(auditPath).Contains(sentinel, StringComparison.Ordinal));
        CheckTrue("logs-safety: routes.json is untouched", () =>
            File.Exists(routesPath) && File.ReadAllText(routesPath) == routesContent);
        CheckTrue("logs-safety: routes.json backup survives the clears", () => File.Exists(created[0]));

        // Wrong key on the Event Log: rejected before any destructive call.
        var (svc2, _, _, _, eventLogs2) = MakeServiceWithStore(NewOptions());
        eventLogs2.ExistsResult = true;
        eventLogs2.CountResult = 5;
        var wrong = svc2.ClearEventLog("wrong-key");
        CheckTrue("logs-safety: wrong key rejected for the event log", () =>
            !wrong.Ok && wrong.ErrorType == AdminResult.TypeAuthentication);
        CheckTrue("logs-safety: wrong key never calls the event log", () => eventLogs2.ClearCalls == 0);
        CheckTrue("logs-safety: wrong key never touches the log at all", () => eventLogs2.ExistsCalls == 0);

        // A failing Count is stat-only: the clear must still happen, message without a count.
        var (svc3, _, _, _, eventLogs3) = MakeServiceWithStore(NewOptions());
        eventLogs3.ExistsResult = true;
        eventLogs3.ThrowOnCount = true;
        var countFailed = svc3.ClearEventLog(adminKey);
        CheckTrue("logs-safety: failing count does not abort the clear", () =>
            countFailed.Ok && eventLogs3.ClearCalls == 1);
        CheckTrue("logs-safety: message omits the count when it is unknown", () =>
            !countFailed.Message.Contains("entries", StringComparison.OrdinalIgnoreCase));
    }

    // --------------------------------------------------------------
    // Log clearing with a broken logging provider (review N-A/N-B): in
    // production the only logging provider is the Event Log being cleared,
    // so a LogWarning can itself throw (log full/removed/source
    // unregistered). That warning must never escape and mask the failure.
    // --------------------------------------------------------------
    static void TestLogClearingLoggingFailure()
    {
        var adminKey = "admin-primary-key";
        var root = TempRoot();
        var paths = new DashboardPaths(root, root, Path.Combine(root, "data"));
        var backups = new ConfigBackup(paths);
        var svc = new DashboardAdminService(
            new TestOptionsMonitor<ProxyOptions>(NewOptions()),
            paths,
            backups,
            new ReloadConfirmer(backups),
            new KeyMetaStore(paths),
            new AuditLog(paths),
            new ActivityStore(),
            new FakeEventLogStore { ExistsResult = true, ThrowOnClear = true },
            new ThrowingLogger());

        AdminResult? result = null;
        CheckTrue("logs-logger: a throwing LogWarning never escapes", () =>
        {
            try
            {
                result = svc.ClearEventLog(adminKey);
                return true;
            }
            catch
            {
                return false;
            }
        });
        CheckTrue("logs-logger: failure is still internal", () =>
            result is not null && !result.Ok && result.ErrorType == AdminResult.TypeInternal);
        CheckTrue("logs-logger: generic message is preserved", () =>
            result is not null
            && result.Message == "Could not clear the Windows Event Log - it may require elevated rights or be in use.");
    }

    private static ProxyOptions NewOptions()
        => new()
        {
            Keys = new KeyOptions
            {
                LocalKey = "admin-primary-key",
                LocalKeys = new List<string>(),
                UpstreamKey = "sk-global-default",
            },
            RouteKeys = new Dictionary<string, string>(StringComparer.Ordinal) { ["openai-main"] = "sk-aaaaaaaaaaaaaaaaaaaa" },
            Routes = new List<RouteOptions>
            {
                new() { Name = "openai", Prefix = "/openai", Upstream = "https://api.openai.com", KeyRef = "openai-main" },
            },
            Redaction = new RedactionOptions { Enabled = true },
            Inspection = new InspectionOptions { Enabled = true },
            RateLimit = new RateLimitOptions { Enabled = false },
        };
}

/// <summary>Minimal IOptionsMonitor implementation for the harness (no host DI).</summary>
sealed class TestOptionsMonitor<T> : IOptionsMonitor<T>
{
    private readonly T _value;

    public TestOptionsMonitor(T value) => _value = value;

    public T CurrentValue => _value;

    public T Get(string? name) => _value;

    public IDisposable? OnChange(Action<T, string?> listener) => null;
}

/// <summary>
/// Test seam over ReloadConfirmer: Confirm fails for the given file names (all of them
/// when none are provided), as if the just-written file did not reload. Records which
/// files were confirmed, so tests can prove what an operation never touched
/// (rollback scope) and in which order confirms were attempted.
/// </summary>
sealed class FailingConfirmer : ReloadConfirmer
{
    public readonly List<string> Confirmed = new();
    private readonly HashSet<string>? _failThese;

    public FailingConfirmer(ConfigBackup backups, params string[] failThese) : base(backups)
    {
        _failThese = failThese.Length == 0 ? null : new HashSet<string>(failThese, StringComparer.Ordinal);
    }

    public override bool Confirm(string configDir, string fileName, Func<JsonNode, bool> isValid)
    {
        Confirmed.Add(fileName);
        if (_failThese is null || _failThese.Contains(fileName))
        {
            return false;
        }

        return base.Confirm(configDir, fileName, isValid);
    }
}

/// <summary>
/// Test seam over ConfigBackup: records every Restore call (fileName), so tests can
/// verify the rollback restores touched files in reverse write order. Backup/LatestBackup
/// behave normally - only the restore is observed.
/// </summary>
sealed class RecordingBackup : ConfigBackup
{
    public readonly List<string> Restored = new();

    public RecordingBackup(DashboardPaths paths) : base(paths)
    {
    }

    public override void Restore(string configDir, string fileName, string bakPath)
    {
        Restored.Add(fileName);
        base.Restore(configDir, fileName, bakPath);
    }
}

/// <summary>
/// Test seam over ConfigBackup: a backup exists but Restore always throws, simulating a
/// config file locked by another process. Lets ReloadConfirmer's RestoreFailed state be
/// exercised (item: "backup found but restore failed").
/// </summary>
sealed class FailingRestorer : ConfigBackup
{
    public readonly List<string> Attempted = new();

    public FailingRestorer(DashboardPaths paths) : base(paths)
    {
    }

    public override void Restore(string configDir, string fileName, string bakPath)
    {
        Attempted.Add(fileName);
        throw new IOException("simulated locked config file");
    }
}

/// <summary>
/// In-memory IEventLogStore fake: never touches the machine's real Windows Event Log.
/// Lets the log-clearing tests drive exists/count/clear outcomes deterministically.
/// </summary>
sealed class FakeEventLogStore : IEventLogStore
{
    public bool ExistsResult { get; set; }
    public int CountResult { get; set; }
    public bool ThrowOnCount { get; set; }
    public bool ThrowOnClear { get; set; }

    /// <summary>When set, Clear throws this instance instead of the generic simulated failure.</summary>
    public Exception? ClearException { get; set; }
    public int ExistsCalls { get; private set; }
    public int ClearCalls { get; private set; }
    public string? LastClearedLog { get; private set; }

    public bool Exists(string logName)
    {
        ExistsCalls++;
        return ExistsResult;
    }

    public int Count(string logName)
        => ThrowOnCount ? throw new InvalidOperationException("simulated count failure") : CountResult;

    public void Clear(string logName)
    {
        ClearCalls++;
        LastClearedLog = logName;
        if (ClearException is not null)
        {
            throw ClearException;
        }

        if (ThrowOnClear)
        {
            throw new InvalidOperationException("simulated event log failure");
        }
    }
}

/// <summary>
/// ILogger fake whose LogWarning throws, mirroring the production hazard: the only
/// logging provider is the Event Log being cleared, and EventLog.WriteEntry throws
/// when the log is full, removed or its source unregistered. All other levels no-op.
/// </summary>
sealed class ThrowingLogger : ILogger<DashboardAdminService>
{
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        if (logLevel == LogLevel.Warning)
        {
            throw new InvalidOperationException("logger down");
        }
    }
}

/// <summary>No-op scope returned by <see cref="ThrowingLogger"/>.</summary>
sealed class NullScope : IDisposable
{
    public static readonly NullScope Instance = new();

    public void Dispose()
    {
    }
}
