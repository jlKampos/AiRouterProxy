# AiRouterProxy

Local HTTPS proxy for the AI Router with a **multi-upstream router**: a per-path
route table lets you forward to several OpenAI-compatible providers, each with its own key.
**Current version:** 2.5.0 ([releases](https://github.com/jlKampos/AiRouterProxy/releases))

☕ Found this useful? [**Support the project**](https://buymeacoffee.com/jlkampos) with a coffee — every cup keeps the redaction growing.

## Table of contents

- [Why: a security layer](#why-a-security-layer-for-development-environments)
  - [How it started](#how-it-started)
- [Stack](#stack)
- [Structure](#structure)
- [Configuration](#configuration)
  - [Files: secret vs non-secret](#files-secret-vs-non-secret)
  - [Quick reference](#quick-reference)
  - [appsettings.json](#appsettingsjson)
  - [appsettings.Development.json](#appsettingsdevelopmentjson)
  - [appsettings.Server.json](#appsettingsserverjson)
  - [routes.json](#routesjson)
  - [redaction.json](#redactionjson)
  - [Inspection (fail-closed body handling)](#inspection-fail-closed-body-handling)
  - [Rate limiting](#rate-limiting)
  - [How to edit](#how-to-edit)
  - [Verify your changes](#verify-your-changes)
  - [Hot reload](#hot-reload)
- [Local key](#local-key)
- [Certificates](#certificates)
- [Using from OpenCode (opencode.json)](#using-from-opencode-opencodejson)
- [Tests](#tests)
- [Interactive menu (proxy-menu.ps1)](#interactive-menu-proxymenups1)
- [Deploy (installed service)](#deploy-installed-service)

## Why: a security layer for development environments

AiRouterProxy exists to **enforce that secrets never leave the machine** to AI model providers -
in both **personal and corporate development environments**. It is a local HTTPS guardrail that
sits between your AI coding agent and the model provider.

### How it started

AiRouterProxy started life as a **personal** security layer: a local HTTPS guardrail I ran
between my own coding agents and the AI model providers, to make sure secrets never left the
machine. As it proved itself in real use - redaction, fail-closed inspection, per-client rate
limiting, SSE streaming - it became clear the utility was bigger than one machine, so the
project went **public**. The repo layout (`src/`, `tests/`, `scripts/`), the full configuration
reference and this story are all part of making it easy for anyone else to adopt and trust the
same guardrail.

### Defense in depth

A safe agent setup has three layers:

1. **Instructions** - `AGENTS.md` / `CLAUDE.md` tell the agent not to read secret files.
2. **Client-side blocking** - permissions/hooks deny reading `appsettings.*.json`, `.env`,
   `*.pem`, etc.
3. **Edge filter (this proxy)** - the last line of defense. It inspects every outgoing request
   and masks sensitive content before it is forwarded, catching what slips past the first two
   layers: a key pasted in free text, a secret in a code block, a config pasted into a prompt.

The proxy is **provider-agnostic**: it works with any OpenAI-compatible upstream, so it fits
corporate policies that require EU-resident / zero-data-retention gateways.

### What it masks

- by **field name** (`api_key`, `password`, `token`, ...), including the token/signing-key
  families (`auth/session/id` token, `jwt`/`signing` key) in any casing/separator convention,
- by **known format** (`sk-...`, `ghp_`, `AIza`, `ya29.`, `AKIA/ASIA`, `glpat-`, `dop_v1_`,
  `hf_`, `pypi-`, Discord, Azure, Stripe, Twilio, SendGrid, JWT, `Bearer`, PEM private keys, ...),
- by **`key=value` / `"key": "value"` context**,
- and optionally by **long high-entropy tokens** (configurable).

The mask is a fixed 6-character string (it never reveals the real length), and the JSON structure
is never changed.

**Image/binary payloads are never scanned as text**: `data:...;base64,...` data URLs (OpenAI
`image_url.url`, Anthropic `source.data`) and long base64 blobs pass through untouched —
they are binary bytes, not text where a key gets pasted, and scanning them would corrupt the
base64. Configurable via `detect.exemptBase64` (default: on). Real keys and known formats are
always masked, even in text next to an image.

### In action

The agent gets a visible notice when a request was censored:

![Proxy notice when a request contained censored content](images/proxy_guardrails.png)

And the model only ever sees the masked value - never the real secret:

![The request as it reaches the model, sensitive value masked](images/proxy_guardrails_II.png)

### See the proxy in action

A short demo: an appsettings-style config full of fake secrets is pasted into OpenCode, and the
proxy redacts them before they reach the model - watch the notice, the masking and the
non-sensitive content passing through untouched:

[![AiRouterProxy redaction demo](https://img.youtube.com/vi/29nyYgkqx7E/hqdefault.jpg)](https://www.youtube.com/watch?v=29nyYgkqx7E)

## Stack

- .NET 10 / ASP.NET Core (Kestrel + TLS); publish **self-contained win-x64** (embeds the runtime - the
  host has no x64 .NET runtime installed, so a framework-dependent publish fails to start)
- Path-prefix router (`routes.json`)
- Sensitive-content redaction on outgoing requests (`redaction.json`, hot reload)
- **Fail-closed request body inspection** (only inspected JSON is ever forwarded; unknown content types
  `415`, invalid JSON `400`, oversized `413`)
- **Per-client rate limiting and brute-force lockout** (429 + `Retry-After`; failure lockout)
- **Multiple accepted local keys** (`Proxy:Keys:LocalKeys`) for auth rotation
- **SSE protocol adapters** (`src/AiRouterProxy/Sse/SseProtocol/`) for streamed forwards (OpenAI chat/responses,
  Anthropic, generic)
- Admin endpoints protected by the primary local key only (`/admin/*`)
- Windows Service (`AIRouterProxy`, port 4000)
- Versioned via assembly info (SemVer, e.g. 2.0.4); reported by /admin/health

## Structure

```
AiRouterProxy/
|-- src/
|   `-- AiRouterProxy/             # C# source, grouped by responsibility
|       |-- Program.cs             # bootstrap + pipeline wiring
|       |-- Pipeline/              # request pipeline (rate limit -> auth -> method -> route -> inspect -> redact -> forward)
|       |   |-- ProxyMiddleware.cs
|       |   `-- AdminAuthMiddleware.cs     # /admin Bearer auth
|       |-- Detection/             # secret detection + redaction
|       |   |-- SecretDetector.cs          # secret detection (4 layers)
|       |   |-- SecretRedactor.cs          # secret redaction (preserves JSON structure)
|       |   `-- SecurityHelpers.cs         # bearer extraction, hashing
|       |-- Policies/              # cross-cutting enforcement policies
|       |   |-- AuthenticationPolicy.cs    # local multi-key auth
|       |   |-- RateLimiter.cs             # per-IP rate limit + brute-force lockout
|       |   `-- InspectionPolicy.cs        # fail-closed content-type inspection decisions
|       |-- Routing/               # route table + options + config paths
|       |   |-- RouteResolver.cs           # route resolution (longest prefix) + allowed-path guards
|       |   |-- ProxyOptions.cs            # Proxy/Routes/Redaction/Inspection/RateLimit options
|       |   `-- ConfigPaths.cs             # config/ resolution (dev vs deployed layout)
|       |-- Sse/                   # streaming forwarder (protocol-agnostic)
|       |   |-- SseStreamProcessor.cs
|       |   |-- SseParser.cs / SseEvent.cs # minimal SSE parse/emit
|       |   `-- SseProtocol/                # SSE protocol adapters (OpenAI chat, OpenAI responses, Anthropic, generic) + registry
|       |-- Observability/         # activity log + response notices
|       |   |-- ActivityStore.cs           # activity log (/admin/activity)
|       |   `-- NoticeInjector.cs          # notice at the end of the response (SSE/JSON)
|       |-- Config/                # non-secret config (copied to config\ on deploy)
|       |   |-- appsettings.json
|       |   |-- appsettings.Development.json
|       |   |-- appsettings.Server.example.json  # TEMPLATE for the keys (copy to appsettings.Server.json)
|       |   |-- redaction.json
|       |   `-- routes.json
|       `-- Properties/launchSettings.json
|-- tests/
|   |-- Unit/                      # offline unit harness (compiles the app sources directly)
|   |   |-- Program.cs             #   no framework - 302 PASS
|   |   `-- RedactorTests.csproj
|   `-- Integration/               # black-box integration harness against a REAL deployed proxy
|-- scripts/
|   |-- proxy-menu.ps1             # interactive menu (build/deploy/verify/keys/event log) - the day-to-day entry point
|   |-- deploy-update.ps1          # deploy engine (preserves secrets/certs; registers the Windows service on FIRST INSTALL)
|   `-- genApiKey.ps1              # generates/prints/rotates local keys (-Print / -Write)
|-- images/                        # README screenshots
|-- README.md, LICENSE, .gitignore, AIRouterProxy.slnx
```

## Configuration

### Files: secret vs non-secret

| File | Content | In the repo? |
|---|---|---|
| `appsettings.Server.json` | Keys and certificates config (SECRET) | **No** (gitignored). Copy it from `appsettings.Server.example.json` |
| `appsettings.json` | Non-secret proxy defaults (host, port, body size, timeout) | Yes |
| `appsettings.Development.json` | Development overrides (active when `ASPNETCORE_ENVIRONMENT=Development`) | Yes |
| `routes.json` | Route table (upstreams, prefixes, key refs by name - no key values) | Yes |
| `redaction.json` | Redaction flags, mask, allow-list + inspection & rate-limit policy (non-secret) | Yes |
| `proxy-cert.pem` / `proxy-key.pem` | TLS certificate + private key (SECRET) | **No** (gitignored). Generated on the server |
| `LOCAL_KEY.txt` | Last local key generated (SECRET) | **No** (gitignored) |
| `deploy/`, `publish-tmp/` | Local service install and build output | **No** (gitignored) |

> At the installed service, all config files live in a config subfolder next to the exe (the server reads from there when present - see [Deploy (installed service)](#deploy-installed-service)).

### Quick reference

| I want to... | File | Section / key | Applies live? |
|---|---|---|---|
| Change the proxy host / port | `appsettings.json` | `Proxy:Host` / `Proxy:Port` | restart |
| Change the default upstream | `appsettings.json` | `Proxy:Upstream` | restart |
| Change request timeout / max body | `appsettings.json` | `Proxy:RequestTimeoutMs` / `Proxy:MaxBodySize` | restart |
| Add / change a route | `routes.json` | `Proxy:Routes[]` | ✓ hot reload |
| Add a named upstream key | `appsettings.Server.json` | `Proxy:RouteKeys:<KEYREF>` | ✓ hot reload |
| Rotate / add the local key | `appsettings.Server.json` | `Proxy:Keys:LocalKey` / `LocalKeys` | ✓ hot reload |
| Leave a file name / internal ID unmasked | `redaction.json` | `Proxy:Redaction.Allow` | ✓ hot reload |
| Tune a detection layer | `redaction.json` | `Proxy:Redaction.Detect.*` | ✓ hot reload |
| Stop redacting image/base64 payloads | `redaction.json` | `Proxy:Redaction.Detect.ExemptBase64` | ✓ hot reload |
| Tighten body inspection (fail closed) | `redaction.json` | `Proxy:Inspection.*` | ✓ hot reload |
| Tighten rate limiting / lockout | `redaction.json` | `Proxy:RateLimit.*` | ✓ hot reload |

> This is the *dev point of view*. On the installed service the same files are read from the
> `config\` subfolder next to the exe.

### appsettings.json

Non-secret **defaults** (host, port, limits). Lives in the repo and is copied to `config\` on deploy:

```jsonc
{
  "Proxy": {
    "Host": "0.0.0.0",                       // interface to listen on (0.0.0.0 = all interfaces)
    "Port": 4000,                            // HTTPS port (Kestrel) - changing it requires a restart
    "Upstream": "https://api.airouter.ch",  // upstream used when no route matches ("" prefix)
    "RequestTimeoutMs": 300000,              // per-request upstream timeout (5 min) - timeouts surface as 502
    "MaxBodySize": 20971520,                 // max request body in bytes (20 MB) - larger -> 413
    "Verbose": true                          // detailed logging (request ids, redaction warnings)
  }
}
```

| Key | Default | What it does |
|---|---|---|
| `Host` | `0.0.0.0` | Listen interface. `127.0.0.1` = this machine only. Restart to apply. |
| `Port` | `4000` | HTTPS port. Restart to apply. |
| `Upstream` | `https://api.airouter.ch` | Fallback upstream when no route matches. |
| `RequestTimeoutMs` | `300000` | Upstream timeout (ms); a timed-out forward returns 502. |
| `MaxBodySize` | `20971520` | Requests larger than this are rejected with 413 before forwarding. |
| `Verbose` | `true` | Extra detail in the logs (request ids, redaction notices). |

### appsettings.Development.json

Optional overrides applied only when the app runs with `ASPNETCORE_ENVIRONMENT=Development`
(the installed Windows Service does not set it, so this file is ignored there). Use it in dev
to e.g. raise `Verbose` or lower `RequestTimeoutMs` without touching the shipped defaults.

### appsettings.Server.json

The only place where keys live. Created on the target machine (never committed):

```json
{
  "Proxy": {
    "Cert": {
      "PemCert": "proxy-cert.pem",
      "PemKey": "proxy-key.pem"
    },
    "Keys": {
      "UpstreamKey": "sk-...  (default route key, e.g. aiRouter)",
      "LocalKey": "sk-...  (primary local key clients use to talk to the proxy)",
      "LocalKeys": [
        "sk-...  (optional extra local keys - one per engineer/agent)",
        "sk-...  (a request authenticates if it matches any of these)"
      ]
    },
    "RouteKeys": {
      "OPENROUTER": "sk-or-...  (key used by the /openrouter route)",
      "GROQ": "gsk_...  (optional, used by any route with keyRef GROQ)",
      "ANTHROPIC": "sk-ant-...  (key used by the /anthropic route)"
    }
  }
}
```

- `Proxy:Keys:UpstreamKey` - key for the **default route** (`prefix: ""`).
- `Proxy:Keys:LocalKey` - the **primary local key**: full access. It authenticates the proxied API (`/v1/*`) and is the **only** key accepted on `/admin/*`. Generate one with `scripts\genApiKey.ps1`.
- `Proxy:Keys:LocalKeys` - optional list of **additional** local keys, one per engineer/agent. They authenticate the proxied API (`/v1/*`) but are **never accepted on `/admin/*`** (`401`): API access without admin. A request is accepted if it matches the primary `LocalKey` **or** any entry here. Add/remove one entry to rotate or revoke a single key without touching the others - hot-reloaded, no restart, no re-deploy. Values live only in `appsettings.Server.json` / environment (never in non-secret files).
- Local keys must be **real generated values** - `sk-` + unpadded base64url (46 chars each), as produced by `scripts\genApiKey.ps1`. Never leave the `"sk-..."` placeholders or empty entries in the deployed `appsettings.Server.json` - an empty/placeholder key never authenticates.
- `Proxy:RouteKeys` - dictionary of `keyRef` -> key. Each named route points to one entry.
- Environment variables `AIROUTER_API_KEY` and `LOCAL_PROXY_KEY` are also honored if the config values are empty.

### routes.json

The route table decides which upstream serves each path prefix. The prefix is stripped before forwarding
and the route key is selected by `keyRef`:

```jsonc
{
  "Proxy": {
    "Routes": [
      {
        "name": "airouter",
        "prefix": "",                                 // "" = default route (accepts any path)
        "upstream": "https://api.airouter.ch",
        "keyRef": "",                                 // empty -> uses Proxy:Keys:UpstreamKey
        "allowedPaths": ["/v1/*"],
        "requestTimeoutMs": 300000
      },
      {
        "name": "openrouter",
        "prefix": "/openrouter",                      // activates on /openrouter/...
        "upstream": "https://openrouter.ai/api",
        "keyRef": "OPENROUTER",                       // uses Proxy:RouteKeys:OPENROUTER
        "allowedPaths": ["/v1/*"],
        "requestTimeoutMs": 300000
      },
      {
        "name": "anthropic",
        "prefix": "/anthropic",                       // activates on /anthropic/...
        "upstream": "https://api.anthropic.com",
        "keyRef": "ANTHROPIC",                        // uses Proxy:RouteKeys:ANTHROPIC
        "allowedPaths": ["/v1/*"],
        "requestTimeoutMs": 300000,
        "maxBodySize": 134217728,                     // 128 MB (routes.json "maxBodySize"); 0/omission = Proxy.MaxBodySize (20 MB)
        "headers": {                                  // static headers merged into every request
          "anthropic-version": "2023-06-01"           // required by the Anthropic API
        }
      }
    ]
  }
}
```

Mapping example:
- `https://localhost:4000/v1/chat/completions` -> `https://api.airouter.ch/v1/chat/completions` (default route)
- `https://localhost:4000/openrouter/v1/chat/completions` -> `https://openrouter.ai/api/v1/chat/completions` (prefix removed before forwarding)
- `https://localhost:4000/anthropic/v1/messages` -> `https://api.anthropic.com/v1/messages` (prefix removed before forwarding)

Rules:
- Only one route can have `prefix: ""`.
- `prefix` must start with `/` and match on a **segment boundary** (`/openrouter` does not match `/openrouterX`).
- `allowedPaths` matches the path **after** prefix removal; supports a trailing `*`.
- A route whose key is missing is **inactive** (returns 502, not a proxy crash).
- `maxBodySize` (optional, bytes) is the route's own request-body cap: requests larger than it
  are rejected with **413** before anything is forwarded. `0` (or omitted) inherits the global
  `Proxy:MaxBodySize` (default 20 MB) - use it to raise the cap for routes that legitimately
  carry large payloads (e.g. `"maxBodySize": 134217728` = 128 MB on the `/anthropic` route).
  Hot reload applies (edit `routes.json`, no restart).
  **Memory trade-off:** every in-flight request is fully buffered up to the route cap
  (read + parse + re-serialization ≈ up to ~4x the body size), so size the value for the
  largest legitimate body and the number of concurrent requests - e.g. 128 MB × N simultaneous
  requests consumes roughly ~0.5-1 GB transient per request. Local auth + rate-limit run
  **before** the buffer is allocated, so the exposure is limited to whoever already holds a
  local key.
- `headers` (optional) adds **static headers** to every request forwarded along the route — e.g. the `anthropic-version` header the Anthropic API requires. Reserved headers the proxy sets itself (`Authorization`, `Content-Type`, `Accept`, ...) are **never overridden** — the proxy's credentials and content framing always win. Supports hot reload (edit `routes.json`, no restart).

### redaction.json

Non-secret policy file. Besides the **redaction** rules it also holds the **inspection**
(fail-closed body handling) and **rate limiting** sections - all under the same `Proxy` block.

**Precedence:** config files are loaded in order — `appsettings.json`, `appsettings.{Env}.json`,
`appsettings.Server.json`, then `redaction.json` and `routes.json`. Later files override earlier
ones **per key** (not per block): if the same key exists in both `appsettings.json` and
`redaction.json`, `redaction.json` wins; keys present only in `appsettings.json` keep their value.
Both are watched (hot reload), so edits apply without a restart.

#### Redaction — what gets masked

```jsonc
{
  "Proxy": {
    "Redaction": {
      "enabled": true,              // master switch for redaction
      "mask": "••••••",             // fixed hidden text (never reveals the real length)
      "notifyInResponse": true,     // appends a visible notice to the model response (SSE/JSON)
      "warnTemplate": "",           // optional notice template - placeholders: {Count}, {Kinds}, {Previews}
      "detect": {
        "byFieldName": true,        // value of properties named api_key, password, token, senha...
        "byFormats": true,          // known formats: sk-, ghp_, AIza, JWT, Bearer, PEM...
        "byKeyValueContext": true,  // "key": "value" / KEY=value config excerpts pasted in prompts
        "byLongStrings": true,      // long random-looking tokens (Shannon entropy, >= 28 chars)
        "exemptBase64": true,       // image/binary payloads pass untouched (data URLs, base64 blobs)
        "entropyThreshold": 3.0     // minimum bits/char for the long-string scanner
      },
      "allow": [                    // optional: a detected token matching one of these regexes is
        "^ACME-[0-9]{3,5}-"          //   left unmasked (e.g. project file names / internal IDs)
      ]
    }
  }
}
```

**detect flags:**
- `byFieldName` - masks the value of any property whose name matches a sensitive name
  (`api_key`, `password`, `token`, `senha`, ...). Name matching is **convention-agnostic**:
  `ApiKey`/`API_KEY`/`api-key`/`apikey` are all caught, as are the auth/session/id-token and
  JWT/signing-key families (`AuthToken`, `JwtKey`, `signing_key`, `SigningKeyPem`, ...). A
  `*_tokens` family is excluded automatically so usage counters like `max_tokens` are never touched.
- `byFormats` - high-confidence formats: OpenAI/Anthropic `sk-...`, `ghp_`, `AIza`, Slack `xox*`,
  AWS `AKIA/ASIA/ABIA/ACCA/A3T` (base32), GitLab `glpat-`, DigitalOcean `dop_v1_`, Hugging Face
  `hf_`, Replicate `r8_`, PyPI, Docker Hub `dckr_pat_`, Discord, Azure Storage, Twilio, SendGrid,
  Mailgun, Shopify, Stripe (`live`/`test`/`prod`), JWT, `Bearer <value>`, `scheme://user:pass@`
  URLs and PEM private key blocks.
- `byKeyValueContext` - `"key": "value"` / `KEY=value` config excerpts (only the value is masked).
  Detection is **convention-agnostic** (`AuthToken`, `session-token`, `id_token`, `JwtKey`,
  `signing_key`, bare `token` ...) so pasted configs are covered whatever naming style the
  app uses.
- `byLongStrings` - long URL-safe tokens (≥ 28 chars) that look random (entropy + mixed classes).
  This is the layer that flags file names/IDs - see `allow`.
- `exemptBase64` - image/binary payloads (OpenAI `image_url.url` data URLs, Anthropic
  `source.data`, `b64_json`) are **not scanned as text**: scanning them would corrupt the base64
  with the mask. Known formats and sensitive field values are **still always** masked.
- `entropyThreshold` - minimum Shannon entropy (bits/char) for `byLongStrings`.

**`allow` (optional):** a list of regex patterns. When a detected token matches one of them it
is **not masked** (nor counted / notified) - use it to keep legitimate file names and internal
IDs (e.g. ``ACME-1234-v2-WidgetApp-Module-Plan.md``) readable even though the long-string scanner
would flag them. Exemptions **never** apply to the high-confidence format scanner (`sk-`, `ghp_`,
`AIza`, JWT, `Bearer`, PEM...) nor to values of sensitive JSON fields (`api_key`, `password`,
`token`...): those are always redacted. Invalid regexes are ignored.

### Inspection (fail-closed body handling)

Decides what happens to each request body **before** anything is forwarded. Security fails
closed: an uninspected request is never forwarded.

```jsonc
{
  "Proxy": {
    "Inspection": {
      "enabled": true,
      "defaultAction": "block",     // action for content types not listed in byContentType
      "invalidJson": "block",       // what to do with a JSON body that does not parse
      "byContentType": {
        "application/json": "inspect",
        "application/xml": "block",
        "application/octet-stream": "block",
        "multipart/form-data": "block",
        "application/x-www-form-urlencoded": "block"
      }
    }
  }
}
```

- `"inspect"` = parse + redact (only JSON is supported in this iteration).
- `"block"` = reject with **415** (`invalidJson: "block"` rejects with **400**).
- `"warn"` = forward a body that failed inspection anyway (**escape hatch - do not use without
  review**).
- `defaultAction` applies to any content type that is not present in `byContentType`, including
  requests with no content type at all (blocked by default).
- Oversized bodies are rejected with **413** before any of this (see `Proxy:MaxBodySize`).

### Rate limiting

Per-client (by IP) request limiting and brute-force lockout.

```jsonc
{
  "Proxy": {
    "RateLimit": {
      "enabled": true,
      "maxRequestsPerWindow": 120,  // allowed requests...
      "requestWindowSeconds": 60,   //   ...per this window (per client IP)
      "maxFailuresPerWindow": 10,   // failed local-key attempts tolerated...
      "failureWindowSeconds": 300,  //   ...in this window (5 min)
      "lockoutSeconds": 300         // how long a client stays locked out (5 min)
    }
  }
}
```

- Requests beyond `maxRequestsPerWindow` in the window → **429** with `Retry-After`.
- After `maxFailuresPerWindow` failed auth attempts → the client is locked out for
  `lockoutSeconds` (also 429 + `Retry-After`).

### How to edit

- **Development:** edit the files in `src/AiRouterProxy/` in the repo (`appsettings.json`,
  `redaction.json`, `routes.json`, ...) and run / publish the app.
- **Installed service:** every config file lives in the **`config\` subfolder** next to the exe
  (e.g. `C:\Services\AiRouterProxy\config\`). Edit the files there directly - the service reads
  from `config\` when it exists and falls back to the exe folder otherwise.
- **Keep valid JSON:** the examples here use `jsonc` (with comments) only for readability. The
  real files must be **strict JSON** - no comments, no trailing commas.
- **Back up before editing:** keep a copy of the current file (the deploy scripts already
  preserve `config\appsettings.*.json`, `redaction.json`, `routes.json` and the certs on update).

### Verify your changes

`/admin` endpoints are protected by the local key (`Proxy:Keys:LocalKey`):

```powershell
curl.exe --ssl-no-revoke https://localhost:4000/admin/health -H "Authorization: Bearer <LocalKey>"
# {"status":"ok","version":"2.0.4",...}

curl.exe --ssl-no-revoke https://localhost:4000/admin/endpoints -H "Authorization: Bearer <LocalKey>"
# routes + allowed paths + current redaction flags (including exemptBase64)

curl.exe --ssl-no-revoke https://localhost:4000/admin/activity?hours=6 -H "Authorization: Bearer <LocalKey>"
# recent requests; entries with "redacted" > 0 had content masked
```

### Who can access `/admin` (swagger)

Only local keys authenticate clients; `/admin` is stricter and accepts **only the primary
local key** (`Proxy:Keys:LocalKey`) - never the extra ones:

| Key | Where it lives | `/v1/*` (API) | `/admin/*` (swagger ops) |
|---|---|---|---|
| `LocalKey` (primary) | `Proxy:Keys:LocalKey` | ✅ | ✅ the only one with admin |
| Extra local keys (per engineer/agent) | `Proxy:Keys:LocalKeys` | ✅ | ❌ `401` |
| Route / upstream keys | `Proxy:RouteKeys` (`keyRef`) | ❌ never accepted from clients | ❌ |

- Engineer/agent keys in `LocalKeys` use the proxied API (`/v1/*`) but get `401` on all
  `/admin/*` - by design, there are no per-key admin grants.
- `Proxy:RouteKeys` are upstream credentials the proxy uses server-side; they are never
  accepted as a client `Bearer` and grant nothing client-facing.
- The `/swagger` UI page itself is served without auth (read-only documentation); calling any
  documented operation requires the primary local key.

When a request is censored the response carries `X-AIRouter-Redacted: <count>` and, if
`notifyInResponse` is set, a visible notice - use both to confirm a redaction rule behaves as
expected.

### Hot reload

`appsettings.Server.json`, `routes.json` and `redaction.json` are watched with `reloadOnChange` -
edits apply **without a restart**. `Host`/`Port` and the TLS certificates are read at startup
(the Kestrel listener binds once), so changing those still requires a restart.

## Local key / `genApiKey.ps1`

`scripts\genApiKey.ps1` generates keys in OpenAI format (`sk-` + unpadded base64url, 46 chars, from a CSPRNG).

| Mode | Effect |
|---|---|
| *(no flags)* | Prints usage help and exits. |
| `-Print` | Generates a key and **prints it to the console** (nothing else). Use it to create a per-engineer key: add the printed value to `Proxy:Keys:LocalKeys` on the server. That key gets `/v1/*` but **not** `/admin/*`. |
| `-Write` | Generates a key and **writes it as the primary `LocalKey`** into the deployed `appsettings.Server.json` (backup `.bak`, `LOCAL_KEY.txt`, immediate `/v1` test). |
| `-DeployDir <path>` | Target install (used with `-Write`). Default: `<repo>\deploy`. |

```powershell
# per-engineer key: prints the key to the console - add it to Proxy:Keys:LocalKeys on the server
powershell -ExecutionPolicy Bypass -File .\scripts\genApiKey.ps1 -Print

# rotate the primary local key (writes appsettings.Server.json + LOCAL_KEY.txt)
powershell -ExecutionPolicy Bypass -File .\scripts\genApiKey.ps1 -Write

# rotate on an existing install elsewhere
powershell -ExecutionPolicy Bypass -File .\scripts\genApiKey.ps1 -Write -DeployDir "C:\Path\To\deploy"
```

With `-Write`, the script prints the key hash (never the key itself) and stores the key in
`LOCAL_KEY.txt` for the client to copy.

## Certificates

The proxy serves HTTPS on `https://localhost:4000`. The certificate is a self-signed cert trusted
only by machines that trust its CA. Recommended tool: **mkcert** (installs a local CA in Windows trust store).

### 1. Generate (on the server machine)

```powershell
# install mkcert (winget)
winget install FiloSottile.mkcert

# create and trust the local CA
mkcert -install

# generate cert + key covering the hostnames the proxy is reached by
# (run inside the folder the service reads the certs from, e.g. deploy/)
cd C:\Path\To\deploy
mkcert -key-file proxy-key.pem -cert-file proxy-cert.pem localhost winzone 127.0.0.1
```

Add every name clients will use (localhost, the machine name, LAN IP...). The files stay in the deploy
folder next to the exe - `appsettings.Server.json` must point at them (`PemCert` / `PemKey`).

### 2. Trust the cert on the client machine

- **Same machine** (typical usage): `mkcert -install` already added the CA to the Windows
  "Trusted Root Certification Authorities" store, so the client (OpenCode/Node/curl) accepts the cert.
- **Other machines / VMs**: copy the CA file and install it in the Root store:
  ```powershell
  # CA file created by mkcert (elevated PowerShell):
  certutil -addstore Root "%USERPROFILE%\.local\share\mkcert\rootCA.pem"
  ```
  Or open `rootCA.pem`, then Certificate -> Install Certificate -> Current User -> "Trusted Root Certification Authorities".

Verification: `curl.exe --ssl-no-revoke https://localhost:4000/admin/health -H "Authorization: Bearer <LocalKey>"` should return a JSON body (`status: ok`).

### Alternative without mkcert (PFX)

```powershell
$cert = New-SelfSignedCertificate -DnsName "localhost","winzone" -CertStoreLocation Cert:\LocalMachine\My
$pwd = ConvertTo-SecureString "a-password" -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath proxy-cert.pfx -Password $pwd
```

Then in `appsettings.Server.json` use `PfxPath`/`PfxPassword` instead of PEM files. Note: the client
must trust this cert's store too.

### Validity / rotation

The packaged certs expire (the current one is valid until 27/01/2029). Regenerate before that date,
then restart the service. The trusted CA stays valid.

## Using from OpenCode (opencode.json)

Local clients talk to the proxy with the **LocalKey** (Bearer); the proxy authenticates the request and
injects the correct upstream key per route. The `apiKey` in the client config MUST be the proxy's
**LocalKey** (`LOCAL_KEY.txt`, also `Proxy:Keys:LocalKey` in `appsettings.Server.json`) - **never** the
upstream OpenRouter key, which only exists server-side (as `Proxy:RouteKeys:OPENROUTER`) and never goes
into a client config.

### OpenRouter route - working example (full OpenCode config)

Use a **custom provider ID** such as `openrouter-local`, not the reserved `openrouter` ID: the custom ID
forces the agent to honor the proxy `baseURL` and keeps the model list limited to what you define (the
reserved ID merges the whole models.dev catalog and may ignore `baseURL`).

The example below is a complete `opencode.json` for this setup: the `watcher` ignore list and the
`permissions` block are the **client-side layer** of the defense in depth, and the `providers` block
sends OpenRouter traffic through the proxy.

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "watcher": {
    "ignore": [
      "**/appsettings.json",
      "**/appsettings.*.json",
      "**/secrets.json",
      "**/.microsoft/usersecrets/**",
      "**/.env",
      "**/.env.*",
      "**/google-services.json",
      "**/GoogleService-Info.plist",
      "**/firebase-config.json",
      "**/firebase-secrets.json",
      "**/firebase*.json",
      "**/*cloud_services_config.json",
      "cloud_services_config.json",
      "**/*.keystore",
      "**/*.jks",
      "**/*.p12",
      "**/*.pfx",
      "**/*.pem",
      "**/*.key",
      "**/*.crt",
      "**/*.cer",
      "**/bin/**",
      "**/obj/**",
      "**/.vs/**",
      "**/.vscode/**",
      "**/publish/**",
      "**/*.suo",
      "**/*.user",
      "**/*.userprefs",
      "**/logs/**",
      "**/*.log",
      "**/*.db",
      "**/*.sqlite",
      "**/*.sqlite3",
      "**/Properties/PublishProfiles/**",
      "**/AndroidManifest.xml",
      "**/Platforms/Android/google-services.json",
      "**/node_modules/**",
      "**/.git/**",
      "**/.idea/**"
    ]
  },
  "permissions": [
    { "action": "read",  "resource": "**/appsettings*.json",                      "effect": "deny" },
    { "action": "read",  "resource": "**/{secrets.json,credentials.json}",        "effect": "deny" },
    { "action": "read",  "resource": "**/.env*",                                  "effect": "deny" },
    { "action": "read",  "resource": "**/*.{pem,key,crt,cer,p12,pfx,jks,keystore}","effect": "deny" },
    { "action": "read",  "resource": "**/connectionstrings.config",               "effect": "deny" },
    { "action": "read",  "resource": "**/{bin,obj,node_modules,logs,Logs}/**",     "effect": "deny" },
    { "action": "edit",  "resource": "**/*.Designer.cs",                          "effect": "deny" },
    { "action": "edit",  "resource": "**/*.resx",                                 "effect": "deny" },
    { "action": "shell", "resource": "git push *",                                "effect": "deny" },
    { "action": "shell", "resource": "git fetch *",                               "effect": "deny" },
    { "action": "shell", "resource": "*{sqlcmd,sqlplus,sql,sqsh,psql}*",           "effect": "deny" }
  ],
  "model": "openrouter-local/v4-flash",
  "providers": {
    "openrouter-local": {
      "name": "OpenRouter via proxy",
      "package": "@opencode/ai/providers/openai-compatible",
      "settings": {
        "baseURL": "https://localhost:4000/openrouter/v1",
        "apiKey": "sk-...your-LocalKey..."               // proxy LOCAL key, NOT the OpenRouter key
      },
      "models": {
        "v4-flash": {
          "modelID": "deepseek/deepseek-v4-flash-0731",  // OpenRouter model slug sent upstream
          "name": "DeepSeek V4 Flash 0731"
        }
      }
    }
  }
}
```

- `apiKey`: the proxy's **LocalKey** - never the OpenRouter key.
- `baseURL`: the `/openrouter` route (prefix is stripped before forwarding).
- `modelID`: the OpenRouter model slug; requests reach `.../openrouter/v1/chat/completions` with it.
- Pin routing with a provider/model `body`, e.g.
  `"body": { "provider": { "order": ["DeepInfra"], "allow_fallbacks": false } }`.
- Use the model as `openrouter-local/v4-flash`.

#### What `watcher.ignore` and `permissions` do

These two blocks are the **client-side guardrail** (layer 2 of the defense in depth). They do not
replace the proxy - they stop secret files from being read, edited or sent in the first place.

- **`watcher.ignore`** - a glob list of files and folders the agent's file watcher/snapshot should never
  index. `**/appsettings.*.json`, `**/*.pem`, `**/.env*`, etc. are excluded from context, so the agent
  does not even see these paths as readable content.
- **`permissions`** - hard deny rules the agent must ask for (or is blocked from) before any action:
  - **read** deny for `appsettings*.json`, `{secrets.json,credentials.json}`, `.env*`,
    `*.{pem,key,crt,cer,p12,pfx,jks,keystore}`, `connectionstrings.config`, `bin/obj/node_modules/logs`;
  - **edit** deny for `*.Designer.cs` and `*.resx` (generated/designer files, not for the agent to change);
  - **shell** deny for `git push`, `git fetch` (no remote changes from the agent) and for SQL clients
    (`sqlcmd`, `sqlplus`, `psql`, ...) so the agent never touches a database.

If the agent tries any of these, the request is refused - nothing is read, nothing is sent. The proxy
remains the last layer in case a secret still sneaks into a prompt.

A denied read shows the agent a clear "access denied" notice - the file content is never touched:

![Access to secret files blocked by permissions](images/opencode_file_permissions.png)

### aiRouter route - example config

Separate provider for the default route (`/v1` -> aiRouter). This is the provider block used in the
working setup (legacy `provider`/`npm`/`options` form; the schema accepts both this and the V2 form
shown above for OpenRouter):

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "model": "airouter/DeepSeek-V4-Flash",
  "provider": {
    "airouter": {
      "name": "airouter-proxy",
      "npm": "@ai-sdk/openai-compatible",
      "options": {
        "baseURL": "https://localhost:4000/v1",
        "apiKey": "sk-...your-LocalKey..."               // proxy LOCAL key, NOT the upstream key
      },
      "models": {
        "Qwen3.8": {
          "name": "Qwen3.8 (local)",
          "variants": {
            "none":    { "reasoningEffort": "none" },
            "low":     { "reasoningEffort": "low" },
            "medium":  { "reasoningEffort": "medium" },
            "xhigh":   { "reasoningEffort": "xhigh" }
          },
          "limit": {
            "context": 262144,
            "input": 196608,
            "output": 65536
          },
          "modalities": {
            "input":  ["text", "image"],
            "output": ["text"]
          },
          "reasoning": true,
          "tool_call": true,
          "options": {
            "reasoningEffort": "xhigh",
            "temperature": 0.6,
            "topP": 0.95,
            "topK": 20,
            "minP": 0.0,
            "presencePenalty": 0.0,
            "repetitionPenalty": 1.0
          }
        },
        "DeepSeek-V4-Flash": {
          "name": "DeepSeek-V4-Flash (local)",
          "variants": {
            "none":     { "reasoningEffort": "none" },
            "minimal":  { "reasoningEffort": "minimal" },
            "low":      { "reasoningEffort": "low" },
            "medium":   { "reasoningEffort": "medium" },
            "high":     { "reasoningEffort": "high" },
            "xhigh":    { "reasoningEffort": "xhigh" }
          },
          "limit": {
            "context": 262144,
            "input": 229376,
            "output": 32768
          },
          "modalities": {
            "input":  ["text", "image"],
            "output": ["text"]
          },
          "reasoning": true,
          "tool_call": true,
          "options": {
            "reasoningEffort": "xhigh",
            "textVerbosity": "low",
            "reasoningSummary": "auto"
          }
        }
      }
    }
  }
}
```

Use the models as `airouter/Qwen3.8` or `airouter/DeepSeek-V4-Flash`.

### All routes, one config — global example

All routes in a single `opencode.json`: the default route (`/v1`) serves the AI
Router, `/openrouter` serves OpenRouter and `/anthropic` serves Anthropic — all
through the same proxy. This is a complete working setup — the client-side
guardrails (`watcher` + `permissions`), a remote MCP server, the providers and two
primary agents (`plan`, `build`) — validated on OpenCode V2.

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "watcher": {
    "ignore": [
      "**/appsettings.json",
      "**/appsettings.*.json",
      "**/secrets.json",
      "**/.microsoft/usersecrets/**",
      "**/.env",
      "**/.env.*",
      "**/google-services.json",
      "**/GoogleService-Info.plist",
      "**/firebase-config.json",
      "**/firebase-secrets.json",
      "**/firebase*.json",
      "**/*cloud_services_config.json",
      "cloud_services_config.json",
      "**/*.keystore",
      "**/*.jks",
      "**/*.p12",
      "**/*.pfx",
      "**/*.pem",
      "**/*.key",
      "**/*.crt",
      "**/*.cer",
      "**/bin/**",
      "**/obj/**",
      "**/.vs/**",
      "**/.vscode/**",
      "**/publish/**",
      "**/*.suo",
      "**/*.user",
      "**/*.userprefs",
      "**/logs/**",
      "**/*.log",
      "**/*.db",
      "**/*.sqlite",
      "**/*.sqlite3",
      "**/Properties/PublishProfiles/**",
      "**/AndroidManifest.xml",
      "**/Platforms/Android/google-services.json",
      "**/node_modules/**",
      "**/.git/**",
      "**/.idea/**"
    ]
  },
  "permissions": [
    { "action": "read",  "resource": "**/appsettings*.json",                        "effect": "deny" },
    { "action": "read",  "resource": "**/{secrets.json,credentials.json}",          "effect": "deny" },
    { "action": "read",  "resource": "**/.env*",                                    "effect": "deny" },
    { "action": "read",  "resource": "**/*.{pem,key,crt,cer,p12,pfx,jks,keystore}",  "effect": "deny" },
    { "action": "read",  "resource": "**/connectionstrings.config",                 "effect": "deny" },
    { "action": "read",  "resource": "**/{bin,obj,node_modules,logs,Logs}/**",       "effect": "deny" },
    { "action": "edit",  "resource": "**/*.Designer.cs",                            "effect": "deny" },
    { "action": "edit",  "resource": "**/*.resx",                                   "effect": "deny" },
    { "action": "shell", "resource": "git push *",                                  "effect": "deny" },
    { "action": "shell", "resource": "git fetch *",                                 "effect": "deny" },
    { "action": "shell", "resource": "*{sqlcmd,sqlplus,sql,sqsh,psql}*",             "effect": "deny" }
  ],
  "mcp": {
    "servers": {
      "figma": {
        "type": "remote",
        "url": "https://mcp.figma.com/mcp"
      }
    }
  },
  "provider": {
    "airouter": {
      "name": "airouter-proxy",
      "npm": "@ai-sdk/openai-compatible",
      "options": {
        "baseURL": "https://localhost:4000/v1",        // default route -> AI Router ("" prefix)
        "apiKey": "sk-...your-LocalKey..."             // proxy LOCAL key, NOT the upstream key
      },
      "models": {
        "Qwen3.8": {
          "name": "Qwen3.8 (local)",
          "variants": {
            "none":   { "reasoningEffort": "none" },
            "low":    { "reasoningEffort": "low" },
            "medium": { "reasoningEffort": "medium" },
            "xhigh":  { "reasoningEffort": "xhigh" }
          },
          "limit": {
            "context": 262144,
            "input": 196608,
            "output": 65536
          },
          "modalities": {
            "input":  ["text", "image"],
            "output": ["text"]
          },
          "reasoning": true,
          "tool_call": true,
          "options": {
            "reasoningEffort": "xhigh",
            "temperature": 0.6,
            "topP": 0.95,
            "topK": 20,
            "minP": 0.0,
            "presencePenalty": 0.0,
            "repetitionPenalty": 1.0
          }
        },
        "DeepSeek-V4-Flash": {
          "name": "DeepSeek-V4-Flash (local)",
          "variants": {
            "none":    { "reasoningEffort": "none" },
            "minimal": { "reasoningEffort": "minimal" },
            "low":     { "reasoningEffort": "low" },
            "medium":  { "reasoningEffort": "medium" },
            "high":    { "reasoningEffort": "high" },
            "xhigh":   { "reasoningEffort": "xhigh" }
          },
          "limit": {
            "context": 262144,
            "input": 229376,
            "output": 32768
          },
          "modalities": {
            "input":  ["text", "image"],
            "output": ["text"]
          },
          "reasoning": true,
          "tool_call": true,
          "options": {
            "reasoningEffort": "xhigh",
            "textVerbosity": "low",
            "reasoningSummary": "auto"
          }
        }
      }
    },
    "openrouter-local": {
      "name": "OpenRouter via proxy",
      "npm": "@ai-sdk/openai-compatible",
      "options": {
        "baseURL": "https://localhost:4000/openrouter/v1",   // /openrouter route -> OpenRouter
        "apiKey": "sk-...your-LocalKey..."                   // proxy LOCAL key, NOT the OpenRouter key
      },
      "models": {
        "deepseek/deepseek-v4-flash-0731": {
          "name": "DeepSeek V4 Flash 0731",
          "tool_call": true
        }
      }
    },
    "anthropic-local": {
      "name": "Anthropic via proxy",
      "npm": "@ai-sdk/anthropic",
      "options": {
        "baseURL": "https://localhost:4000/anthropic/v1",   // /anthropic route -> Anthropic
        "apiKey": "sk-...your-LocalKey...",                 // SDK sends this as x-api-key (proxy ignores it)
        "headers": {
          "authorization": "Bearer sk-...your-LocalKey..."  // this is what the proxy authenticates
        }
      },
      "models": {
        "claude-haiku-4-5": {
          "name": "Claude Haiku 4.5",
          "tool_call": true
        },
        "claude-sonnet-4-5": {
          "name": "Claude Sonnet 4.5",
          "tool_call": true
        }
      }
    }
  },
  "model": "airouter/DeepSeek-V4-Flash",
  "default_agent": "plan",
  "agents": {
    "plan": {
      "description": "Complex planning and analysis",
      "mode": "primary",
      "model": "airouter/DeepSeek-V4-Flash",
      "permissions": [
        { "action": "edit", "resource": "*", "effect": "deny" }
      ]
    },
    "build": {
      "description": "Fast implementation",
      "mode": "primary",
      "model": "airouter/DeepSeek-V4-Flash"
    }
  }
}
```

- `apiKey` is the proxy's **LocalKey** in **all three** provider blocks — never an upstream key (AI Router / OpenRouter / Anthropic; those live only server-side, see [appsettings.Server.json](#appsettingsserverjson) `Proxy:RouteKeys`).
- `baseURL` uses `localhost`; on a network machine replace it with `https://<machine-name>:4000/...` — the mkcert certificate covers `localhost`, the machine name and the LAN IP (see [Certificates](#certificates)).
- The provider blocks use the proven `provider`/`npm`/`options` form (the schema also accepts the V2 `providers`/`package`/`settings` form shown in the OpenRouter example above); the agents use V2-native `agents` + `permissions` — `plan` is read-only (`edit` denied), `build` implements, and `default_agent: "plan"` opens each session in planning mode.

### Complete OpenCode V2 config - all routes + orchestration agents

The same three routes (AI Router, OpenRouter, Anthropic) in a single V2-form
`opencode.json`, with the client-side guardrails (`watcher` + `permissions`),
a remote MCP server, the three providers and a full team of specialized agents
(`orchestrator` coordinating `explore` / `brainstorm` / `plan` / `build` /
`reviewer`), `default_agent: "orchestrator"`. Validated on OpenCode V2.

```json
{
    "$schema": "https://opencode.ai/config.json",
    "watcher": {
        "ignore": [
            "**/appsettings.json",
            "**/appsettings.*.json",
            "**/secrets.json",
            "**/credentials.json",
            "**/.microsoft/usersecrets/**",
            "**/.env",
            "**/.env.*",
            "**/google-services.json",
            "**/GoogleService-Info.plist",
            "**/firebase-config.json",
            "**/firebase-secrets.json",
            "**/firebase*.json",
            "**/*cloud_services_config.json",
            "cloud_services_config.json",
            "**/*.keystore",
            "**/*.jks",
            "**/*.p12",
            "**/*.pfx",
            "**/*.pem",
            "**/*.key",
            "**/*.crt",
            "**/*.cer",
            "**/bin/**",
            "**/obj/**",
            "**/.vs/**",
            "**/.vscode/**",
            "**/publish/**",
            "**/publish-tmp/**",
            "**/deploy/**",
            "**/*.suo",
            "**/*.user",
            "**/*.userprefs",
            "**/logs/**",
            "**/Logs/**",
            "**/*.log",
            "**/*.db",
            "**/*.sqlite",
            "**/*.sqlite3",
            "**/*.bak",
            "**/LOCAL_KEY.txt",
            "**/Properties/PublishProfiles/**",
            "**/AndroidManifest.xml",
            "**/Platforms/Android/google-services.json",
            "**/node_modules/**",
            "**/.git/**",
            "**/.idea/**"
        ]
    },
    "permissions": [
        { "action": "*", "resource": "*", "effect": "allow" },
        { "action": "read", "resource": "**/appsettings*.json", "effect": "deny" },
        { "action": "read", "resource": "**/secrets.json", "effect": "deny" },
        { "action": "read", "resource": "**/credentials.json", "effect": "deny" },
        { "action": "read", "resource": "**/.env*", "effect": "deny" },
        { "action": "read", "resource": "**/*.pem", "effect": "deny" },
        { "action": "read", "resource": "**/*.key", "effect": "deny" },
        { "action": "read", "resource": "**/*.crt", "effect": "deny" },
        { "action": "read", "resource": "**/*.cer", "effect": "deny" },
        { "action": "read", "resource": "**/*.p12", "effect": "deny" },
        { "action": "read", "resource": "**/*.pfx", "effect": "deny" },
        { "action": "read", "resource": "**/*.jks", "effect": "deny" },
        { "action": "read", "resource": "**/*.keystore", "effect": "deny" },
        { "action": "read", "resource": "**/connectionstrings.config", "effect": "deny" },
        { "action": "read", "resource": "**/bin/**", "effect": "deny" },
        { "action": "read", "resource": "**/obj/**", "effect": "deny" },
        { "action": "read", "resource": "**/node_modules/**", "effect": "deny" },
        { "action": "read", "resource": "**/logs/**", "effect": "deny" },
        { "action": "read", "resource": "**/Logs/**", "effect": "deny" },
        { "action": "read", "resource": "**/Properties/PublishProfiles/**", "effect": "deny" },
        { "action": "read", "resource": "**/google-services.json", "effect": "deny" },
        { "action": "read", "resource": "**/GoogleService-Info.plist", "effect": "deny" },
        { "action": "read", "resource": "**/cloud_services_config.json", "effect": "deny" },
        { "action": "read", "resource": "**/firebase*.json", "effect": "deny" },
        { "action": "read", "resource": "**/LOCAL_KEY.txt", "effect": "deny" },
        { "action": "read", "resource": "**/.microsoft/usersecrets/**", "effect": "deny" },
        { "action": "read", "resource": "**/deploy/**", "effect": "deny" },
        { "action": "read", "resource": "**/publish-tmp/**", "effect": "deny" },
        { "action": "read", "resource": "**/*.bak", "effect": "deny" },
        { "action": "edit", "resource": "**/appsettings*.json", "effect": "deny" },
        { "action": "edit", "resource": "**/secrets.json", "effect": "deny" },
        { "action": "edit", "resource": "**/credentials.json", "effect": "deny" },
        { "action": "edit", "resource": "**/.env*", "effect": "deny" },
        { "action": "edit", "resource": "**/*.pem", "effect": "deny" },
        { "action": "edit", "resource": "**/*.key", "effect": "deny" },
        { "action": "edit", "resource": "**/*.crt", "effect": "deny" },
        { "action": "edit", "resource": "**/*.cer", "effect": "deny" },
        { "action": "edit", "resource": "**/*.p12", "effect": "deny" },
        { "action": "edit", "resource": "**/*.pfx", "effect": "deny" },
        { "action": "edit", "resource": "**/*.jks", "effect": "deny" },
        { "action": "edit", "resource": "**/*.keystore", "effect": "deny" },
        { "action": "edit", "resource": "**/connectionstrings.config", "effect": "deny" },
        { "action": "edit", "resource": "**/google-services.json", "effect": "deny" },
        { "action": "edit", "resource": "**/GoogleService-Info.plist", "effect": "deny" },
        { "action": "edit", "resource": "**/*.Designer.cs", "effect": "deny" },
        { "action": "edit", "resource": "**/*.resx", "effect": "deny" },
        { "action": "edit", "resource": "**/bin/**", "effect": "deny" },
        { "action": "edit", "resource": "**/obj/**", "effect": "deny" },
        { "action": "edit", "resource": "**/Properties/PublishProfiles/**", "effect": "deny" },
        { "action": "edit", "resource": "**/cloud_services_config.json", "effect": "deny" },
        { "action": "edit", "resource": "**/firebase*.json", "effect": "deny" },
        { "action": "edit", "resource": "**/LOCAL_KEY.txt", "effect": "deny" },
        { "action": "edit", "resource": "**/.microsoft/usersecrets/**", "effect": "deny" },
        { "action": "edit", "resource": "**/deploy/**", "effect": "deny" },
        { "action": "edit", "resource": "**/publish-tmp/**", "effect": "deny" },
        { "action": "edit", "resource": "**/*.bak", "effect": "deny" },
        { "action": "shell", "resource": "*", "effect": "ask" },
        { "action": "shell", "resource": "git status *", "effect": "allow" },
        { "action": "shell", "resource": "git diff *", "effect": "allow" },
        { "action": "shell", "resource": "git log *", "effect": "allow" },
        { "action": "shell", "resource": "git branch *", "effect": "allow" },
        { "action": "shell", "resource": "git show *", "effect": "allow" },
        { "action": "shell", "resource": "git push *", "effect": "deny" },
        { "action": "shell", "resource": "git fetch *", "effect": "deny" },
        { "action": "shell", "resource": "*sqlcmd*", "effect": "deny" },
        { "action": "shell", "resource": "*sqlplus*", "effect": "deny" },
        { "action": "shell", "resource": "*sqsh*", "effect": "deny" },
        { "action": "shell", "resource": "*psql*", "effect": "deny" },
        { "action": "shell", "resource": "*Invoke-Sqlcmd*", "effect": "deny" },
        { "action": "shell", "resource": "*mysql*", "effect": "deny" },
        { "action": "shell", "resource": "*sqlite3*", "effect": "deny" },
        { "action": "shell", "resource": "*mongosh*", "effect": "deny" },
        { "action": "external_directory", "resource": "*", "effect": "ask" }
    ],
    "mcp": {
        "servers": {
            "figma": {
                "type": "remote",
                "url": "https://mcp.figma.com/mcp"
            }
        }
    },
    "providers": {
        "airouter": {
            "name": "airouter-proxy",
            "package": "@opencode/ai/providers/openai-compatible",
            "settings": {
                "baseURL": "https://winzone:4000/v1",
                "apiKey": "{env:AIROUTER_API_KEY}"
            },
            "models": {
                "Qwen3.8": {
                    "name": "Qwen3.8 (local)",
                    "capabilities": {
                        "tools": true,
                        "input": ["text", "image"],
                        "output": ["text"],
                        "reasoning": { "supported": true }
                    },
                    "limit": {
                        "context": 262144,
                        "input": 196608,
                        "output": 65536
                    },
                    "settings": {
                        "reasoningEffort": "xhigh",
                        "temperature": 0.6,
                        "topP": 0.95,
                        "topK": 20,
                        "minP": 0.0,
                        "presencePenalty": 0.0,
                        "repetitionPenalty": 1.0
                    },
                    "variants": [
                        { "id": "none", "settings": { "reasoningEffort": "none" } },
                        { "id": "low", "settings": { "reasoningEffort": "low" } },
                        { "id": "medium", "settings": { "reasoningEffort": "medium" } },
                        { "id": "xhigh", "settings": { "reasoningEffort": "xhigh" } }
                    ]
                },
                "DeepSeek-V4-Flash": {
                    "name": "DeepSeek-V4-Flash (local)",
                    "capabilities": {
                        "tools": true,
                        "input": ["text", "image"],
                        "output": ["text"],
                        "reasoning": { "supported": true }
                    },
                    "limit": {
                        "context": 262144,
                        "input": 229376,
                        "output": 32768
                    },
                    "settings": {
                        "reasoningEffort": "xhigh",
                        "textVerbosity": "low",
                        "reasoningSummary": "auto"
                    },
                    "variants": [
                        { "id": "none", "settings": { "reasoningEffort": "none" } },
                        { "id": "minimal", "settings": { "reasoningEffort": "minimal" } },
                        { "id": "low", "settings": { "reasoningEffort": "low" } },
                        { "id": "medium", "settings": { "reasoningEffort": "medium" } },
                        { "id": "high", "settings": { "reasoningEffort": "high" } },
                        { "id": "xhigh", "settings": { "reasoningEffort": "xhigh" } }
                    ]
                }
            }
        },
        "openrouter-local": {
            "name": "OpenRouter via proxy",
            "package": "@opencode/ai/providers/openai-compatible",
            "settings": {
                "baseURL": "https://winzone:4000/openrouter/v1",
                "apiKey": "{env:AIROUTER_API_KEY}"
            },
            "models": {
                "deepseek/deepseek-v4-flash-0731": {
                    "name": "DeepSeek V4 Flash 0731",
                    "capabilities": { "tools": true }
                }
            }
        },
        "anthropic-local": {
            "name": "Anthropic via proxy",
            "package": "@opencode/ai/providers/anthropic",
            "settings": {
                "baseURL": "https://winzone:4000/anthropic/v1",
                "apiKey": "{env:AIROUTER_API_KEY}",
                "headers": {
                    "authorization": "Bearer {env:AIROUTER_API_KEY}"
                }
            },
            "models": {
                "claude-haiku-4-5": {
                    "name": "Claude Haiku 4.5",
                    "capabilities": {
                        "tools": true
                    }
                }
            }
        }
    },
    "model": "airouter/DeepSeek-V4-Flash",
    "default_agent": "orchestrator",
    "agents": {
        "orchestrator": {
            "description": "Primary agent that coordinates research, solution design, planning, implementation, and review.",
            "mode": "primary",
            "model": "airouter/DeepSeek-V4-Flash",
            "system": "You are a senior software architect and the project's main orchestrator.\n\nObjective:\nCoordinate the work and delegate each phase to the appropriate specialized agent. Don't do all the work alone when delegation adds value.\n\nFlow:\n1. Clarify requirements only when there is blocking ambiguity.\n2. Use Explore to investigate the code and identify existing patterns.\n3. Use Brainstorm to compare approaches when there are architectural decisions or more than one reasonable solution.\n4. Use Plan to structure complex changes.\n5. Use Build to implement.\n6. Use Reviewer to review the implementation.\n7. Consolidate the results, tests, limitations, and decisions for the user.\n\nRules:\n- Don't invent files, APIs, test results, or capabilities.\n- Before proposing changes, consider the existing architecture and conventions.\n- For small tasks, avoid unnecessary delegation.\n- Don't ask every agent to do the same analysis.\n- Don't bypass permissions or read protected files.\n- Don't run destructive operations, deploys, commits, pushes, infrastructure changes, or SQL commands without explicit approval.\n- If the review finds issues, route fixes to Build and request review again.\n- Respond in European Portuguese unless instructed otherwise.\n- At the end, present a summary, changed files, tests run, and risks/pending items.",
            "permissions": [
                { "action": "edit", "resource": "*", "effect": "deny" },
                { "action": "shell", "resource": "*", "effect": "allow" },
                { "action": "subagent", "resource": "*", "effect": "deny" },
                { "action": "subagent", "resource": "explore", "effect": "allow" },
                { "action": "subagent", "resource": "brainstorm", "effect": "allow" },
                { "action": "subagent", "resource": "plan", "effect": "allow" },
                { "action": "subagent", "resource": "build", "effect": "allow" },
                { "action": "subagent", "resource": "reviewer", "effect": "allow" }
            ]
        },
        "explore": {
            "description": "Investigates the codebase, architecture, dependencies, and integration points without changing files.",
            "mode": "all",
            "model": "airouter/Qwen3.8#medium",
            "system": "You are a senior software engineer specialized in code exploration.\n\nInvestigate the project structure, technologies, dependencies, patterns, classes, interfaces, flows, and integration points relevant to the task.\n\nConstraints:\n- Strictly read-only mode: never create, edit, delete, or apply patches.\n- Don't implement solutions.\n- Don't read secret files or protected configurations.\n- Don't run commands that change the project's state.\n- Use targeted search and reading; avoid dumping huge files unnecessarily.\n\nDeliverables:\n1. Summary of relevant architecture.\n2. Important files and symbols (with paths).\n3. Current behavior.\n4. Dependencies and integrations.\n5. Risks or technical debt.\n6. Factual recommendations for the Orchestrator.\nAlways distinguish observed facts from hypotheses.",
            "permissions": [
                { "action": "edit", "resource": "*", "effect": "deny" },
                { "action": "shell", "resource": "*", "effect": "allow" },
                { "action": "subagent", "resource": "*", "effect": "deny" }
            ]
        },
        "brainstorm": {
            "description": "Generates and compares technical solutions, architectural options, and design patterns without changing code.",
            "mode": "all",
            "model": "airouter/DeepSeek-V4-Flash",
            "system": "You are a senior software architect specialized in systems design and alternatives analysis.\n\nAnalyze the problem and, when it makes sense, present up to three technically distinct approaches. Consider compatibility with the existing architecture, simplicity, security, performance, scalability, observability, testability, and maintainability.\n\nDon't:\n- change files;\n- implement code in the project;\n- assume requirements that were not provided;\n- recommend dependencies without justifying the cost.\n\nDeliverables:\n1. Interpretation of the problem and assumptions.\n2. Possible options.\n3. Advantages and disadvantages of each option.\n4. Risks and impact.\n5. Well-founded recommendation.\n6. High-level plan for implementation.\nIf there is only one reasonable option, explain why instead of inventing alternatives.",
            "permissions": [
                { "action": "edit", "resource": "*", "effect": "deny" },
                { "action": "shell", "resource": "*", "effect": "ask" },
                { "action": "subagent", "resource": "*", "effect": "deny" }
            ]
        },
        "plan": {
            "description": "Transforms requirements and research into a phased technical plan without changing code.",
            "mode": "all",
            "model": "airouter/DeepSeek-V4-Flash",
            "system": "You are a technical lead responsible for producing clear and verifiable implementation plans.\n\nUse the available requirements and research. Identify dependencies, execution order, likely files, acceptance criteria, tests, and risks.\n\nConstraints:\n- Don't change application files.\n- Don't implement the solution.\n- Don't assume a file or component exists without evidence.\n- Keep the plan proportional to the size of the task.\n\nDeliverables:\n1. Objective and scope.\n2. Technical decisions and assumptions.\n3. Ordered steps.\n4. Components/files to analyze or change.\n5. Acceptance criteria.\n6. Testing strategy.\n7. Risks and rollback, when applicable.",
            "permissions": [
                { "action": "edit", "resource": "*", "effect": "deny" },
                { "action": "shell", "resource": "*", "effect": "allow" },
                { "action": "subagent", "resource": "*", "effect": "deny" }
            ]
        },
        "build": {
            "description": "Implements code changes following the approved plan and the project's existing patterns.",
            "mode": "all",
            "model": "airouter/DeepSeek-V4-Flash",
            "system": "You are a senior software engineer responsible for implementation.\n\nRules:\n- Follow the requirements and the approved plan.\n- Inspect the context before editing.\n- Respect the architecture, conventions, style, and versions already used in the project.\n- Make small, cohesive, necessary changes.\n- Don't introduce dependencies without justification.\n- Don't change generated files, secrets, protected configurations, or out-of-scope files.\n- Don't run deploy, commit, push, destructive operations, or SQL commands.\n- Request approval for shell commands that require it.\n- Run appropriate tests/builds when allowed.\n- Don't claim tests passed if you didn't run them.\n\nAt the end, report:\n1. What was implemented.\n2. Changed files.\n3. Tests/builds run and results.\n4. Limitations, risks, or pending work.",
            "permissions": [
                { "action": "edit", "resource": "*", "effect": "allow" },
                { "action": "edit", "resource": "**/appsettings*.json", "effect": "deny" },
                { "action": "edit", "resource": "**/secrets.json", "effect": "deny" },
                { "action": "edit", "resource": "**/credentials.json", "effect": "deny" },
                { "action": "edit", "resource": "**/.env*", "effect": "deny" },
                { "action": "edit", "resource": "**/*.pem", "effect": "deny" },
                { "action": "edit", "resource": "**/*.key", "effect": "deny" },
                { "action": "edit", "resource": "**/*.crt", "effect": "deny" },
                { "action": "edit", "resource": "**/*.cer", "effect": "deny" },
                { "action": "edit", "resource": "**/*.p12", "effect": "deny" },
                { "action": "edit", "resource": "**/*.pfx", "effect": "deny" },
                { "action": "edit", "resource": "**/*.jks", "effect": "deny" },
                { "action": "edit", "resource": "**/*.keystore", "effect": "deny" },
                { "action": "edit", "resource": "**/connectionstrings.config", "effect": "deny" },
                { "action": "edit", "resource": "**/google-services.json", "effect": "deny" },
                { "action": "edit", "resource": "**/GoogleService-Info.plist", "effect": "deny" },
                { "action": "edit", "resource": "**/*.Designer.cs", "effect": "deny" },
                { "action": "edit", "resource": "**/*.resx", "effect": "deny" },
                { "action": "edit", "resource": "**/bin/**", "effect": "deny" },
                { "action": "edit", "resource": "**/obj/**", "effect": "deny" },
                { "action": "edit", "resource": "**/Properties/PublishProfiles/**", "effect": "deny" },
                { "action": "edit", "resource": "**/cloud_services_config.json", "effect": "deny" },
                { "action": "edit", "resource": "**/firebase*.json", "effect": "deny" },
                { "action": "edit", "resource": "**/LOCAL_KEY.txt", "effect": "deny" },
                { "action": "edit", "resource": "**/.microsoft/usersecrets/**", "effect": "deny" },
                { "action": "edit", "resource": "**/deploy/**", "effect": "deny" },
                { "action": "edit", "resource": "**/publish-tmp/**", "effect": "deny" },
                { "action": "edit", "resource": "**/*.bak", "effect": "deny" },
                { "action": "shell", "resource": "*", "effect": "ask" },
                { "action": "shell", "resource": "git push *", "effect": "deny" },
                { "action": "shell", "resource": "git fetch *", "effect": "deny" },
                { "action": "shell", "resource": "*sqlcmd*", "effect": "deny" },
                { "action": "shell", "resource": "*sqlplus*", "effect": "deny" },
                { "action": "shell", "resource": "*sqsh*", "effect": "deny" },
                { "action": "shell", "resource": "*psql*", "effect": "deny" },
                { "action": "shell", "resource": "*Invoke-Sqlcmd*", "effect": "deny" },
                { "action": "shell", "resource": "*mysql*", "effect": "deny" },
                { "action": "shell", "resource": "*sqlite3*", "effect": "deny" },
                { "action": "shell", "resource": "*mongosh*", "effect": "deny" },
                { "action": "subagent", "resource": "*", "effect": "deny" }
            ]
        },
        "reviewer": {
            "description": "Reviews changes without modifying them, focusing on bugs, security, performance, and maintainability.",
            "mode": "subagent",
            "model": "airouter/DeepSeek-V4-Flash#high",
            "system": "You are an independent and rigorous code reviewer.\n\nReview the changes against the requirements. Look for bugs, regressions, security issues, insufficient validation, error handling, concurrency, performance, accessibility when applicable, and lack of tests.\n\nConstraints:\n- Read-only: don't change files or apply fixes.\n- Don't flag stylistic preferences as bugs.\n- Don't invent issues without evidence.\n- Prioritize concrete, reproducible issues.\n\nFor each finding, indicate:\n- Severity (critical, high, medium, low).\n- File and location.\n- Issue and impact.\n- Condition under which it occurs.\n- Fix recommendation.\n\nEnd with a conclusion: approved, approved with reservations, or changes required.",
            "permissions": [
                { "action": "edit", "resource": "*", "effect": "deny" },
                { "action": "shell", "resource": "*", "effect": "ask" },
                { "action": "subagent", "resource": "*", "effect": "deny" }
            ]
        }
    }
}
```

- `apiKey` reads `{env:AIROUTER_API_KEY}` in every provider - set that environment
  variable to the proxy **LocalKey** (never an upstream key; see
  [appsettings.Server.json](#appsettingsserverjson)).
- `baseURL` uses `https://winzone:4000/...` - on a network machine replace
  `winzone` with the machine name or LAN IP covered by the mkcert certificate
  (see [Certificates](#certificates)).
- `permissions` starts with an explicit `allow-all` baseline and then hard-denies
  reading and editing secret files (`appsettings*.json`, `.env*`, `*.pem`/`*.key`,
  `secrets.json`, ...), shell `git push`/`git fetch` and every SQL client, and asks
  before `external_directory` access - the same client-side guardrail pattern as the
  [global example above](#all-routes-one-config--global-example).
- `default_agent: "orchestrator"` opens every session in the orchestrator agent, which
  delegates each phase to the right specialist (read-only `explore`/`brainstorm`/
  `plan`, implementing `build`, independent `reviewer`).

### Anthropic (Claude) route — example config

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
   `Proxy:RouteKeys:ANTHROPIC` (sensitive; see [appsettings.Server.json](#appsettingsserverjson)).
   The route answers `502` while it is missing; routes hot-reload, no restart needed.

2. **OpenCode provider** — the `anthropic-local` block, exactly as tested (annotated):
   ```jsonc
   "anthropic-local": {
     "name": "Anthropic via proxy",
     "npm": "@ai-sdk/anthropic",
     "options": {
       "baseURL": "https://localhost:4000/anthropic/v1",  // /anthropic route -> Anthropic
       "apiKey": "",                                      // any value: the proxy ignores x-api-key
       "headers": {
         "authorization": "Bearer sk-...your-LocalKey..." // this is what the proxy authenticates
       }
     },
     "models": {
       "claude-haiku-4-5":  { "name": "Claude Haiku 4.5",  "tool_call": true },
       "claude-sonnet-4-5": { "name": "Claude Sonnet 4.5", "tool_call": true }
     }
   }
   ```
   This block is also part of the [global example](#all-routes-one-config--global-example) above.

3. **Test — offline first (free); live only if you accept the cost:**

   - **⚠ Live calls spend Anthropic credits.** The real API bills your Anthropic account
     (e.g. the $5 trial). Keep live runs opt-in: the integration harness only runs its
     Claude battery with an explicit `--anthropic` flag (see [below](#integration-harness-black-box-against-the-real-deployed-proxy--ai-router)).
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

One honest note: the `@ai-sdk/anthropic` package authenticates with the **`x-api-key`**
header, which the proxy intentionally drops — it only ever accepts **`Authorization:
Bearer`** (the proxy's own credentials, from `Proxy:RouteKeys:ANTHROPIC`, are what the
upstream sees). The provider block therefore passes the LocalKey via an explicit
`authorization` header in `options.headers`, and `apiKey` (sent as `x-api-key` by the
SDK) is ignored by the proxy — it may be left empty. A plain HTTP client (curl, etc.)
just uses `Authorization: Bearer <LocalKey>`.

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

### Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `401` | Wrong LocalKey | Run `scripts\genApiKey.ps1` and copy `LOCAL_KEY.txt` |
| `404 No proxy route matches` | Prefix not present in routes.json | Check `routes.json` reloaded (hot reload) |
| `502 Route 'X' has no API key configured` | Upstream key missing | Fill `Proxy:RouteKeys:X` or `UpstreamKey` in appsettings.Server.json |
| TLS/certificate error on the client | CA not trusted | `mkcert -install` (or install the CA root store as above) |
| Service installed but stays `Stopped` immediately | **Smart App Control** blocks the unsigned build (CodeIntegrity 3033/3077) | Disable SAC: Windows Security > App & browser control > Smart App Control > **Off** (menu option 1/3/4 warn when it is active) |

## Tests

### Unit harness (offline, no framework, no packages)

Links the proxy's real sources in isolation and asserts them with the in-repo `Check`/`CheckTrue`
helpers (no xUnit). Covers redaction (4 layers), fail-closed inspection policy, route
resolution/allowed-path enumeration (traversal, case, `%2f`), auth edges + multi-key, rate
limiter/lockout (including exact concurrency via `Parallel.For`) and the SSE protocol adapters.

```powershell
dotnet run --project tests/Unit/RedactorTests.csproj -c Release
# -> RESULT: 302 PASS, 0 FAIL
```

### Integration harness (black box, against the REAL deployed proxy + AI Router)

`tests/Integration/` is a standalone console app (no app references, no packages) that talks HTTP
with the deployed service, validates the certificate is ignored (self-signed local cert) and derives
the chat path from `/admin/endpoints`. It reads the local key from a file at runtime and never prints
it (only a sha256 prefix):

```powershell
dotnet run --project tests/Integration/Integration.csproj -c Release `
  -- --key-file C:\Users\jlkampos\secrets\airouterproxy-local.key
# -> RESULT: 24 PASS, 0 FAIL
```

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

## Interactive menu (proxy-menu.ps1)

`scripts\proxy-menu.ps1` is the **single entry point** for the day-to-day build/deploy/verify/key
workflows. It **delegates** to the engine scripts (`deploy-update.ps1`, `genApiKey.ps1`) - it never
re-implements them and never reads sensitive files.

```powershell
# run the menu
powershell -ExecutionPolicy Bypass -File .\scripts\proxy-menu.ps1
```

| Option | What it does | Elevates? |
|---|---|---|
| `1` | Build + deploy + verify (full pipeline, end-to-end) | yes (UAC) |
| `2` | Build only (`dotnet publish` -> `publish-tmp`) | no |
| `3` | Deploy only (from an existing `publish-tmp`) | yes (UAC) |
| `4` | Verify service (port 4000 + version + status + `/admin/health`) | no |
| `5` | Generate an engineer key (prints only, writes nothing) | no |
| `6` | View Event Log (latest `AIRouterProxy` events) | no |
| `7` | Certificate docs (show mkcert setup commands) | no |
| `8` | ⚠ ROTATE PRIMARY KEY (edits `appsettings.Server.json`) | yes (UAC) |
| `0` | Exit | - |

- Options **1 / 3 / 8 self-elevate** (UAC) and run in a second, elevated window - the deploy and
  its confirmations happen there.
- Options **1 and 3** run a pre-flight check first: missing `dotnet`, missing destination certs /
  `appsettings.Server.json` (**FIRST INSTALL** - the service will register but not serve yet),
  and a **Smart App Control (SAC)** warning when the OS would block unsigned builds.
- Option **4** checks the service port with TCP connect (works non-elevated) and
  `GET /admin/health` (HTTP 401 while up, key required).

Useful parameters:

```powershell
# deploy to a custom folder and/or under a custom service name (e.g. a sandbox)
powershell -ExecutionPolicy Bypass -File .\scripts\proxy-menu.ps1 -DeployDir "C:\Services\AiRouterProxy-TEST" -ServiceName "AiRouterProxy-TEST"

# non-interactive single action (used by the elevated child windows; handy for scripts / the event log)
powershell -ExecutionPolicy Bypass -File .\scripts\proxy-menu.ps1 -Action Verify
#   -Action: BuildDeploy | Build | Deploy | RotateKey | EventLog | Verify
```

> **Smart App Control (SAC) - Windows 11:** `AIRouterProxy.exe` is a local build and is **not
> signed**. If SAC is **On**, Windows blocks it at startup (the service registers but stays
> `Stopped`; Event Log shows CodeIntegrity 3033/3077 "Enterprise signing level"). Fix: disable SAC
> in **Windows Security > App & browser control > Smart App Control > select Off**. Defender
> (antivirus) stays active and SAC can be turned back on later. The menu warns before the deploy
> when SAC is active - it is the common cause of a service that never starts.

## Deploy (installed service)

The service runs as a Windows Service (`AIRouterProxy`) whose executable is deployed to a service
folder. The recommended layout puts it under `C:\Services` (outside any repo), e.g.
`C:\Services\AiRouterProxy\`. All config files (appsettings.*.json, redaction.json, routes.json and the TLS certs) live in a **`config`** subfolder next to the exe, so the deploy root only has the executable and the configs are easy to find (the server auto-detects `config/`; a flat install without it keeps working).

**First install is automatic:** when the service is not registered on the destination, the deploy
engine registers it itself (`New-Service`, auto-start, LocalSystem) pointing at the freshly
deployed exe - no manual `sc.exe create` / `binPath` steps. The menu (option 1/3) and a direct
`deploy-update.ps1` call both do this. A destination without `config\appsettings.Server.json`
warns FIRST INSTALL before the deploy: the service is installed but will not serve until the
following files are created in `config\` (the deploy never fabricates secrets):
`appsettings.Server.json` (copy the `appsettings.Server.example.json` template) and the TLS
`proxy-cert.pem` / `proxy-key.pem` (see [Certificates](#certificates) / menu option 7).

### Regular update of an existing service

The **fastest** path is the menu: option **1** (build + deploy + verify) or **3** (deploy only).
Below is the same thing done by hand - useful when you want the steps explicit or in a script.

```powershell
# self-contained is REQUIRED: the host has no x64 .NET runtime installed, so a
# framework-dependent publish fails to start ("No frameworks were found").
# Publish to a folder OUTSIDE the repo when you must not touch publish-tmp/.
dotnet publish src/AiRouterProxy/AIRouterProxy.csproj -c Release -r win-x64 --self-contained true -o publish-tmp
# elevated (UAC); deploys to the project's deploy/ folder by default (override with -DeployDir)
powershell -ExecutionPolicy Bypass -File .\scripts\deploy-update.ps1
# installed service under C:\Services:
powershell -ExecutionPolicy Bypass -File .\scripts\deploy-update.ps1 -DeployDir "C:\Services\AiRouterProxy"
# (optional) custom service name, e.g. a sandbox install:
powershell -ExecutionPolicy Bypass -File .\scripts\deploy-update.ps1 -DeployDir "C:\Services\AiRouterProxy-TEST" -ServiceName "AiRouterProxy-TEST"
```

`deploy-update.ps1` preserves config/certs (keeping them in the destination `config/` folder and migrating an older flat install automatically), registers the service when it is missing (**first install**, see above) and restarts it (when installed as a Windows Service). If the deploy carries inspection/rate-limit changes, refresh the destination `redaction.json` from the repo copy afterwards (the deploy script preserves the destination file by design).

### Moving the deployed service to a new folder (generic)

These steps move an existing install from one folder to another (e.g. from the repo's `deploy/` or an
old location to a fresh layout under `C:\Services`). Define `$From` (old) and `$To` (new) once and use
them in every step - adjust only those two values.

```powershell
$From = "C:\Path\To\Old\AiRouterProxy"   # old install folder
$To   = "C:\Services\AiRouterProxy"      # new install folder
```

1. **Stop the old service** (elevated):
   ```powershell
   sc.exe stop AIRouterProxy
   ```
2. **Build and deploy into the new folder** (from the repo root):
   ```powershell
   dotnet publish src/AiRouterProxy/AIRouterProxy.csproj -c Release -r win-x64 --self-contained true -o publish-tmp
   powershell -ExecutionPolicy Bypass -File .\scripts\deploy-update.ps1 -DeployDir $To
   ```
   The publish does not include secrets. Copy them manually once into the new folder:
   ```powershell
   Copy-Item "$From\config\appsettings.Server.json" "$To\config\"
   Copy-Item "$From\config\proxy-cert.pem"          "$To\config\"
   Copy-Item "$From\config\proxy-key.pem"           "$To\config\"
   ```
   (`deploy-update.ps1` preserves these files on future updates, so you only do this once. If the old install was flat - configs next to the exe - `deploy-update.ps1` migrates them into `config/` automatically on the next update.)
3. **Point the Windows Service at the new path** (elevated):
   ```powershell
   sc.exe config AIRouterProxy binPath= "$To\AIRouterProxy.exe"
   ```
4. **Start and verify** (elevated):
   ```powershell
   sc.exe start AIRouterProxy
   Get-NetTCPConnection -LocalPort 4000 -State Listen       # should show listening
   ```
5. **Delete the old folder only after** the new service is Running and responding - and only after also
   removing the old `appsettings.Server.json` reference from any other consumer:
   ```powershell
   Remove-Item -Recurse -Force $From
   ```

> The service runs under LocalSystem; the new deploy path must be readable by it (a plain user folder under `C:\Services` is fine).
