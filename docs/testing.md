# Tests

[← Back to README](../README.md)

## Unit harness (offline, no framework, no packages)

Links the proxy's real sources in isolation and asserts them with the in-repo `Check`/`CheckTrue`
helpers (no xUnit). Covers redaction (4 layers), the one-line redaction notice, detection
forensics (JSON path/layer/kind/fingerprint, zero cost when off), fail-closed inspection policy,
route resolution/allowed-path enumeration (traversal, case, `%2f`), auth edges + multi-key, rate
limiter/lockout (including exact concurrency via `Parallel.For`), the SSE protocol adapters, the
attestation stores/pinning/drift logic.

```powershell
dotnet run --project tests/Unit/RedactorTests.csproj -c Release
# -> RESULT: 551 PASS, 0 FAIL
```

## Dashboard harness (offline, no framework, no packages)

Same `Check`/`CheckTrue` philosophy (no xUnit), compiled against the dashboard sources
(`AdminServices`, `AdminPersistence`, `AdminValidation`, `AdminUi` facade). Covers the admin
write path (validate -> backup -> atomic write -> re-read/confirm -> audit), route/key/secret
operations, KeyMetaStore persistence (owner/purpose + local-key labels), config export/
validate/import/reload, the security validator + forensics round-trip, the UI session token
rules (restart, key rotation, multi-key) and the `/admin/ui` middleware (`/_blazor` 401),
the attestation admin actions and the route-validator transport rules (including
`graceDays` 1..365 and `poolLifetimeMinutes` >= 0), the route-save preservation rules
(omitted `headers`/`transport` preserved, a new route inheriting nothing, `export` ->
`import` keeping the `transport` section, a save with no `routes.json` present, a rename
carrying its sections, and the GET projection normalizing `graceDays` 0 to 7), plus the
runtime dashboard state:

```powershell
dotnet run --project tests/Dashboard.Tests/DashboardTests.csproj -c Release
# -> RESULT: 403 PASS, 0 FAIL
```

## Integration harness (black box, against the REAL deployed proxy + AI Router)

`tests/Integration/` is a standalone console app (no app references, no packages) that talks HTTP
with the deployed service, validates the certificate is ignored (self-signed local cert) and derives
the chat path from `/admin/endpoints`. It reads the local key from a file at runtime and never prints
it (only a sha256 prefix):

```powershell
dotnet run --project tests/Integration/Integration.csproj -c Release `
  -- --key-file C:\Users\jlkampos\secrets\airouterproxy-local.key
# -> RESULT: 24 PASS, 0 FAIL
```

> Last known result: the integration battery was **not** re-executed for this documentation update -
> `24 PASS` is the last known run, against the real deployed proxy + AI Router.

Key file flag (`--key-file <path>` or `AIROUTERPROXY_LOCAL_KEY_FILE`) points at a file containing
only the proxy **LocalKey** (one line). Flags: `--base <url>`, `--skip-paid` (skip token-consuming
calls), `--brute-force` (10-failure lockout test, LAST - locks the IP ~5 min), `--perf` (performance
battery: TTFT / total SSE latency per model, small token spend), `--anthropic` (Claude live battery
— **⚠ consumes Anthropic account credits**; opt-in, combined with `--skip-paid` it is ignored).

What it verifies: health/auth (401 vs 200), `/admin` never leaks the key (payload + activity +
refusals + logs), malformed/oversized requests blocked upstream-free (400/415/405+Allow/404/413),
real forward + SSE streaming, redaction observability (`redacted>0` in activity), rate limit
(429 + `Retry-After >= 1`); with `--anthropic`, the real Claude route: the redaction notice is
delivered as a `content_block_delta` **before** `content_block_stop` on the stream (so
`@ai-sdk/anthropic` renders it), the fake key never reaches the response, and the non-stream
JSON carries the appended notice + `X-AIRouter-Redacted: 1`.

> Note: the `Allow` response header is an **entity header** - `HttpClient` exposes it under
> `resp.Content.Headers`, so the harness reads it from both the response and the content headers.
