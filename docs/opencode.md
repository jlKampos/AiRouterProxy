# Using from OpenCode (opencode.json)

[← Back to README](../README.md)

Local clients talk to the proxy with the **LocalKey** (Bearer); the proxy authenticates the request and
injects the correct upstream key per route. The `apiKey` in the client config MUST be the proxy's
**LocalKey** (`LOCAL_KEY.txt`, also `Proxy:Keys:LocalKey` in `appsettings.Server.json`) - **never** the
upstream OpenRouter key, which only exists server-side (as `Proxy:RouteKeys:OPENROUTER`) and never goes
into a client config.

## Ready-made configs

Two complete, working `opencode.json` examples ship in the repo — pick the one that matches the
route you want as the default:

| File | Default route | Models |
|---|---|---|
| [`opencode_configs/opencode_airouter.json`](../opencode_configs/opencode_airouter.json) | `/v1` -> AI Router | `airouter/Qwen3.8`, `airouter/DeepSeek-V4-Flash` |
| [`opencode_configs/opencode_openrouter.json`](../opencode_configs/opencode_openrouter.json) | `/openrouter` -> OpenRouter | `openrouter-local/deepseek/deepseek-v4.1-flash-1017` |

Both are validated on OpenCode V2 and declare the same three providers (`airouter`,
`openrouter-local`, `anthropic-local`). They differ in the default `model`, in the model each agent
uses, and in how much reasoning configuration is declared per model (the OpenRouter model also
declares `variants` and `reasoning`), and in the OpenRouter model slug each file pins, so switching
route is a matter of copying the other file.

**How to use**

1. Copy the file to your OpenCode config and **rename it to `opencode.json`** (OpenCode only loads
   `opencode.json` / `opencode.jsonc`):
   ```powershell
   New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.config\opencode" | Out-Null
   Copy-Item .\opencode_configs\opencode_openrouter.json "$env:USERPROFILE\.config\opencode\opencode.json"
   ```
   (back up an existing `opencode.json` first — `Copy-Item` overwrites it)
2. Set `AIROUTER_API_KEY` to the proxy **LocalKey** (`LOCAL_KEY.txt`, also `Proxy:Keys:LocalKey` in
   `appsettings.Server.json`). Every provider block reads `{env:AIROUTER_API_KEY}`, so the key never
   goes into the file.
3. The shipped `baseURL`s point at `https://192.168.1.77:4000/...` — replace that host with your
   proxy's machine name or LAN IP (the names covered by the mkcert certificate; see
   [Certificates](certificates.md)). Use `https://localhost:4000/...` when the proxy runs on the same
   machine.
4. OpenCode hot-reloads the config — no restart needed. Pick a model with `/models`.

**What each file already gives you**

- **`providers`** — one block per route, all pointing at the proxy and all reading
  `{env:AIROUTER_API_KEY}`. They use custom provider IDs (`airouter`, `openrouter-local`,
  `anthropic-local`) instead of the reserved upstream IDs, so the proxy `baseURL` is honored and the
  model list is limited to what you declare. The upstream keys (AI Router / OpenRouter / Anthropic)
  live only server-side, in `Proxy:RouteKeys` - never in a client config.
- **Routing pin** — to force the upstream provider on the OpenRouter route, add a `body` to the
  `openrouter-local` model: `"body": { "provider": { "order": ["DeepInfra"], "allow_fallbacks": false } }`.
- **`watcher` + `permissions`** - the **client-side** layer of the defense in depth (layer 2): secret
  files are never read or edited, `git push` / `git fetch` are denied, every SQL client is denied,
  and access outside the project asks first. It does not replace the proxy — it stops the secret
  from reaching the prompt at all.
- **`agents`** - a small orchestration team: `orchestrator` (primary; plans and delegates, and asks
  before handing work to `build` — it cannot edit files itself) coordinating the read-only
  `explore` / `brainstorm` / `plan`, the implementing `build`, the independent `reviewer` and the
  `tester`. Each has its own `permissions`, so a read-only agent cannot edit files even when it
  runs as a subagent.
- **`mcp`** — one remote MCP server is declared (`figma`, `https://mcp.figma.com/mcp`). Remove the
  `mcp` block if you don't use it; OpenCode asks you to sign in the first time it connects.

A denied read shows the agent a clear "access denied" notice — the file content is never touched:

![Access to secret files blocked by permissions](../images/opencode_file_permissions.png)

## What `watcher.ignore` and `permissions` do

These two blocks are the **client-side guardrail** (layer 2 of the defense in depth). They do not
replace the proxy — they stop secret files from being read, edited or sent in the first place.

- **`watcher.ignore`** — a glob list of files and folders the agent's file watcher/snapshot should
  never index. `**/appsettings.*.json`, `**/*.pem`, `**/.env*`, etc. are excluded from context, so
  the agent does not even see these paths as readable content.
- **`permissions`** — hard deny rules the agent must ask for (or is blocked from) before any action:
  - **read** deny for `appsettings*.json`, `{secrets.json,credentials.json}`, `.env*`,
    `*.{pem,key,crt,cer,p12,pfx,jks,keystore}`, `connectionstrings.config`,
    `bin/obj/node_modules/logs`, `deploy/`, `publish-tmp/`, `*.{db,sqlite,sqlite3,sql,bak}`;
  - **edit** deny for the same secret/protected files, plus `bin/`, `obj/` and
    `Properties/PublishProfiles/`;
  - **shell** deny for `git push`, `git fetch` and every SQL client (`sqlcmd`, `sqlplus`, `psql`,
    `mysql`, `sqlite3`, `mongosh`), with `ask` for everything else;
  - **external_directory** `ask` — reading or editing outside the project always asks.

If the agent tries any of these, the request is refused — nothing is read, nothing is sent. The proxy
remains the last layer in case a secret still sneaks into a prompt.

## Anthropic (Claude) route — example config

Added in 2.4.0: the route table accepts a `headers` object per route, so the proxy can
attach the **static headers a provider demands** — the Anthropic Messages API rejects
requests without `anthropic-version`, and that header has no OpenAI-compatible
counterpart the proxy could forward, so it is declared in `routes.json` and merged into
every request along the route.

**Configure in three steps:**

1. **Route + static header** — a ready-made `/anthropic` route ships in the repo's
   `routes.json` (see above):
   ```jsonc
   {
     "name": "anthropic",
     "prefix": "/anthropic",                          // activates on /anthropic/...
     "upstream": "https://api.anthropic.com",
     "headers": { "anthropic-version": "2023-06-01" } // required by the Anthropic API
   }
   ```
   Only the upstream key is filled **server-side** — `appsettings.Server.json`
   `Proxy:RouteKeys:ANTHROPIC` (sensitive; see [appsettings.Server.json](configuration.md#appsettingsserverjson)).
   The route answers `502` while it is missing; routes hot-reload, no restart needed.

2. **OpenCode provider** - the `anthropic-local` block, already present in both ready-made configs
   (see [Ready-made configs](#ready-made-configs), with the shipped host — see step 3):

   ```jsonc
   "anthropic-local": {
     "name": "Anthropic via proxy",
     "package": "@opencode/ai/providers/anthropic",
     "settings": {
       "baseURL": "https://localhost:4000/anthropic/v1",   // /anthropic route -> Anthropic
       "apiKey": "{env:AIROUTER_API_KEY}",                 // sent as x-api-key; the proxy ignores it
       "headers": {
         "authorization": "Bearer {env:AIROUTER_API_KEY}"  // this is what the proxy authenticates
       }
     },
     "models": {
       "claude-haiku-4-5": { "name": "Claude Haiku 4.5", "capabilities": { "tools": true } }
     }
   }
   ```

3. **Test — offline first (free); live only if you accept the cost:**

   - **⚠ Live calls spend Anthropic credits.** The real API bills your Anthropic account
     (e.g. the $5 trial). Keep live runs opt-in: the integration harness only runs its
     Claude battery with an explicit `--anthropic` flag (see [below](testing.md#integration-harness-black-box-against-the-real-deployed-proxy--ai-router)).
   - **Free path:** `scripts\mock-anthropic.ps1` is a local mock of the Messages API
     (`http://127.0.0.1:9999`, SSE + JSON) that enforces the same contract as the real
     API: `400` when `anthropic-version` is missing, `401` without a Bearer token. To
     test end-to-end against the mock in a sandbox:
     1. Change the `anthropic` route's `upstream` to `http://127.0.0.1:9999` (sandbox copy).
     2. Add a dummy `Proxy:RouteKeys:ANTHROPIC` in the sandbox's `appsettings.Server.json`
        (sensitive — the route is `502` while it is missing; keep the real value out of repos).
     3. Run `powershell -ExecutionPolicy Bypass -File .\scripts\mock-anthropic.ps1`.
     4. Call through the proxy — stream and non-stream, with and without redaction — and check
        `/admin/endpoints` shows the route `headers` and `/admin/activity` records the route.

   Live call (against the real API — remember the cost):
   ```powershell
   curl.exe --ssl-no-revoke https://localhost:4000/anthropic/v1/messages `
     -H "Authorization: Bearer sk-...your-LocalKey..." `
     -H "Content-Type: application/json" `
     -d "{\"model\":\"claude-haiku-4-5\",\"max_tokens\":64,\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}"
   ```

One honest note: the `@opencode/ai/providers/anthropic` package authenticates with the **`x-api-key`**
header, which the proxy intentionally drops — it only ever accepts **`Authorization:
Bearer`** (the proxy's own credentials, from `Proxy:RouteKeys:ANTHROPIC`, are what the
upstream sees). The provider block therefore passes the LocalKey via an explicit
`authorization` header in the provider's `settings.headers`, and `apiKey` (sent as `x-api-key`
by the SDK) is ignored by the proxy - the examples simply reuse the LocalKey, so any non-empty
value works. A plain HTTP client (curl, etc.) just uses `Authorization: Bearer <LocalKey>`.

**Response-header parity** — the proxy re-forwards `request-id`,
`anthropic-organization-id`, `anthropic-workspace-id` and the `anthropic-ratelimit-*`
headers (`-requests-limit/-requests-remaining/-requests-reset`,
`-tokens-limit/-tokens-remaining/-tokens-reset`) from every upstream response, next to
the usual `content-type`/`cache-control`/`retry-after`/`x-request-id`. Client-sent
`anthropic-beta`, `anthropic-workspace-id` and `x-api-key` are **ignored by design**
(the proxy never forwards client credentials or beta flags) — declare the route's static
`headers` in `routes.json` instead.

**API-surface limitations** — the **Message Batches API is supported** (batch requests
are JSON, so they are inspected and redacted like any other body; results are fetched
with `GET`). The **Files API is not supported**: file uploads are `multipart`/non-JSON,
which the fail-closed inspection rejects with **415**, and `DELETE` is refused with
**405 + `Allow: GET, POST`** (the proxy only forwards `GET` and `POST`).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `401` | Wrong LocalKey | Run `scripts\genApiKey.ps1` and copy `LOCAL_KEY.txt` |
| `404 No proxy route matches` | Prefix not present in routes.json | Check `routes.json` reloaded (hot reload) |
| `502 Route 'X' has no API key configured` | Upstream key missing | Fill `Proxy:RouteKeys:X` or `UpstreamKey` in appsettings.Server.json |
| `DEPTH_ZERO_SELF_SIGNED_CERT` | The proxy's self-signed cert is rejected by Node/Bun — the browser and `curl -k` accept it, Node does not use the OS trust store | Serve a mkcert cert (`mkcert -install` + `config/proxy-cert.pem` in Docker, then `docker compose restart`) and export `NODE_EXTRA_CA_CERTS` **before** starting OpenCode: Windows `$env:NODE_EXTRA_CA_CERTS = "$(mkcert -CAROOT)\rootCA.pem"`; Linux/macOS `export NODE_EXTRA_CA_CERTS="$(mkcert -CAROOT)/rootCA.pem"`. See [docker.md](docker.md#opencode--node-depth_zero_self_signed_cert) and [certificates.md](certificates.md). `NODE_TLS_REJECT_UNAUTHORIZED=0` only for a quick test |
| `UNABLE_TO_VERIFY_LEAF_SIGNATURE` / `unable to verify the first certificate` | The cert is already the mkcert one (`curl` returns `401`, not a TLS error), but the mkcert CA (`rootCA.pem`) is **not** in the trust of the running Node/Bun process — `NODE_EXTRA_CA_CERTS` is unset, points elsewhere, or was set **after** OpenCode started | Set the CA and **restart the consumer**: `NODE_EXTRA_CA_CERTS = "$(mkcert -CAROOT)\rootCA.pem"` (Windows) / `"$(mkcert -CAROOT)/rootCA.pem"` (Linux/macOS). **Reopening is mandatory** — the variable only counts for processes launched afterwards: kill the running instances (`Get-Process opencode \| Stop-Process -Force`), open a **new** terminal, confirm `echo $env:NODE_EXTRA_CA_CERTS` (PowerShell) / `echo $NODE_EXTRA_CA_CERTS` (bash), and only then start `opencode`. Variables defined after startup are not picked up — that includes the TUI's server/daemon |
| TLS/certificate error on the client | CA not trusted | `mkcert -install` (or install the CA root store as above) |
| Service installed but stays `Stopped` immediately | **Smart App Control** blocks the unsigned build (CodeIntegrity 3033/3077) | Disable SAC: Windows Security > App & browser control > Smart App Control > **Off** (menu option 1/3/4 warn when it is active) |
