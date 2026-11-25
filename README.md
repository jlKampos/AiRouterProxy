# AiRouterProxy — Security Gateway for AI Coding Agents

*Your AI agent can read your code. It doesn't need to expose your secrets.*


Local HTTPS proxy for the AI Router with a **multi-upstream router**: a per-path
route table lets you forward to several OpenAI-compatible providers, each with its own key.
**Current version:** 2.7.0 ([releases](https://github.com/jlKampos/AiRouterProxy/releases)) — the latest release, including the
admin dashboard and the admin REST API v1 described below, detection forensics (metadata only),
and log maintenance from the dashboard — clear the in-memory activity buffer or the dedicated
Windows Event Log, audited and re-authenticated with the primary local key.

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
- [Local key](#local-key--genapikeyps1)
- [Dashboard (admin UI)](#dashboard-admin-ui)
- [Admin API (v1)](#admin-api-v1)
- [Triaging detection forensics](#triaging-detection-forensics)
- [Certificates](#certificates)
- [Using from OpenCode (opencode.json)](#using-from-opencode-opencodejson)
- [Tests](#tests)
- [Interactive menu (proxy-menu.ps1)](#interactive-menu-proxy-menups1)
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
always masked, even in text next to an image. A value introduced by a sensitive name
(`SECRET_KEY=<blob>`, `SECRET-KEY = <blob>`) is a credential, not payload; names are matched
with the detector's own variants (`secret_key`, `secret-key`, `secret key =` is not covered).

The exemption is **name-exact**, so *prefixed*/*suffixed* identifiers are out of scope by design
too: `OPENAI_API_KEY=`, `MY_SECRET_KEY=` and `x-SECRET_KEY=` are not whitelisted names, and
`OPENAI_API_KEY=<120 base64 chars with +/>` is still treated as a payload and left untouched.
Keep secrets shorter than ~100 characters, or avoid `name=` prefixes on large blobs.

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
- **Detection forensics** (metadata only, off by default): per-detection JSON path, layer, kind,
  mask span length, pattern shape (`name`/`sep`/`quote` - from `context`, or inherited by `format`
  from an overlapping context at the same offset) and an ephemeral 8-char fingerprint -
  never the value, in memory only
- **Fail-closed request body inspection** (only inspected JSON is ever forwarded; unknown content types
  `415`, invalid JSON `400`, oversized `413`)
- **Per-client rate limiting and brute-force lockout** (429 + `Retry-After`; failure lockout)
- **Multiple accepted local keys** (`Proxy:Keys:LocalKeys`) for auth rotation
- **SSE protocol adapters** (`src/AiRouterProxy/Sse/SseProtocol/`) for streamed forwards (OpenAI chat/responses,
  Anthropic, generic)
- Admin Blazor dashboard (`/admin/ui`) + admin REST API v1 (`/admin/api/v1/*`) - both protected by
  the primary local key only (`/admin/*`)
- Windows Service (`AIRouterProxy`, port 4000)
- Versioned via assembly info (SemVer, e.g. 2.7.0); reported by /admin/health

## Structure

```
AiRouterProxy/
|-- src/
|   |-- AiRouterProxy/             # C# source (host), grouped by responsibility
|       |-- Program.cs             # bootstrap + pipeline wiring
|       |-- Pipeline/              # request pipeline (rate limit -> auth -> method -> route -> inspect -> redact -> forward)
|       |   |-- ProxyMiddleware.cs
|       |   `-- AdminAuthMiddleware.cs     # /admin Bearer auth
|       |-- Detection/             # secret detection + redaction
|       |   |-- SecretDetector.cs          # secret detection (4 layers)
|       |   |-- SecretRedactor.cs          # secret redaction (preserves JSON structure)
|       |   |-- DetectionFingerprint.cs   # ephemeral HMAC fingerprint for forensics (never reversible)
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
|       |-- Observability/         # activity log + response notices + detection forensics
|       |   |-- ActivityStore.cs           # activity log (/admin/activity)
|       |   |-- DetectionStore.cs          # in-memory detection forensics (ring buffer)
|       |   |-- NoticeInjector.cs          # notice at the end of the response (SSE/JSON)
|       |   `-- RedactionNotice.cs         # one-line notice builder (count + categories)
|       |-- Config/                # non-secret config (copied to config\ on deploy)
|       |   |-- appsettings.json
|       |   |-- appsettings.Development.json
|       |   |-- appsettings.Server.example.json  # TEMPLATE for the keys (copy to appsettings.Server.json)
|       |   |-- redaction.json
|       |   `-- routes.json
|       |-- AdminUi/               # dashboard facade + read models (consumed by the Blazor pages)
|       |   `-- HostDashboardFacade.cs
|       |-- AdminApi/              # /admin/api/v1 REST endpoints (MapAdminApiV1.cs)
|       |-- AdminServices/         # dashboard write operations (validate -> backup -> atomic write -> confirm -> audit)
|       |   `-- DashboardAdminService.cs
|       |-- AdminPersistence/      # config file IO, atomic writes, backups, key meta, audit log
|       |   |-- ConfigFileReader.cs
|       |   |-- AtomicJsonWriter.cs
|       |   |-- ConfigBackup.cs            # timestamped backups in data\backups
|       |   |-- KeyMetaStore.cs           # data\key-meta.json (owner/purpose + local-key labels)
|       |   `-- AuditLog.cs               # data\audit.log (JSONL)
|       |-- AdminValidation/       # dashboard model validation (routes/keys/security)
|       `-- Properties/launchSettings.json
|   `-- AiRouterProxy.Dashboard/   # Blazor Web App (admin UI): Components/Pages (Login, RoutesKeys, ActivityLog, Security, Settings, Home)
|-- tests/
|   |-- Unit/                      # offline unit harness (compiles the app sources directly)
|   |   |-- Program.cs             #   no framework - 383 PASS
|   |   `-- RedactorTests.csproj
|   |-- Dashboard.Tests/           # admin dashboard harness (compiles app sources directly)
|   |   |-- Program.cs             #   no framework - 331 PASS
|   |   `-- DashboardTests.csproj
|   `-- Integration/               # black-box integration harness against a REAL deployed proxy
|-- scripts/
|   |-- proxy-menu.ps1             # interactive menu (build/deploy/verify/keys/event log) - the day-to-day entry point
|   |-- deploy-update.ps1          # deploy engine (preserves secrets/certs; registers the Windows service on FIRST INSTALL)
|   `-- genApiKey.ps1              # generates/prints/rotates local keys (-Print / -Write)
|-- images/                        # README screenshots
|-- opencode_configs/              # ready-made opencode.json examples (aiRouter + OpenRouter routes)
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
| `data/key-meta.json` | Dashboard metadata only: keyRef owner/purpose + labels of extra local keys (fingerprints, **never key values**) | **No** (generated at runtime) |
| `data/audit.log` | JSONL audit trail of dashboard admin writes (never secrets) | **No** (generated at runtime) |
| `data/backups/` | Timestamped config backups taken before each dashboard write | **No** (generated at runtime) |
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
      "forensics": {                // detection forensics: metadata only - where/which layer fired, never the value
        "enabled": false,           //   off by default (zero cost on the hot path); nothing is written to disk
        "capacity": 200             //   in-memory ring buffer size (10..1000)
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
`token`...): those are always redacted. Invalid regexes are ignored. The pattern is tested against
the **masked span** (the union when candidates overlap), not against each detector's raw match.

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

`/admin` endpoints are protected by the local key (`Proxy:Keys:LocalKey`). The admin REST API
v1 is the current interface; the legacy endpoints below still work unchanged:

```powershell
# admin API v1 (current)
curl.exe --ssl-no-revoke https://localhost:4000/admin/api/v1/status -H "Authorization: Bearer <LocalKey>"
# {"status":"ok","version":"2.7.x","routes":N,"redactionEnabled":true,...}

curl.exe --ssl-no-revoke https://localhost:4000/admin/api/v1/routes -H "Authorization: Bearer <LocalKey>"
# the current route table (key refs, never key values)

curl.exe --ssl-no-revoke https://localhost:4000/admin/api/v1/keys -H "Authorization: Bearer <LocalKey>"
# key refs (set/not set, in use) + local keys (fingerprints + labels)

# legacy endpoints (still available, same answers)
curl.exe --ssl-no-revoke https://localhost:4000/admin/health -H "Authorization: Bearer <LocalKey>"
# {"status":"ok","version":"2.7.x",...}

curl.exe --ssl-no-revoke https://localhost:4000/admin/endpoints -H "Authorization: Bearer <LocalKey>"
# routes + allowed paths + current redaction flags (including exemptBase64)

curl.exe --ssl-no-revoke https://localhost:4000/admin/activity?hours=6 -H "Authorization: Bearer <LocalKey>"
# recent requests; entries with "redacted" > 0 had content masked
```

### Who can access `/admin` (dashboard UI + admin REST API v1)

Only local keys authenticate clients; `/admin` is stricter and accepts **only the primary
local key** (`Proxy:Keys:LocalKey`) - never the extra ones. This covers the Blazor dashboard
(`/admin/ui/*`) and the admin REST API v1 (`/admin/api/v1/*`), plus the legacy `/admin/*`
endpoints:

| Key | Where it lives | Proxied API (`/v1/*`) | Dashboard + admin API (`/admin/*`) |
|---|---|---|---|
| `LocalKey` (primary) | `Proxy:Keys:LocalKey` | ✅ | ✅ the only one with admin |
| Extra local keys (per engineer/agent) | `Proxy:Keys:LocalKeys` | ✅ | ❌ `401` |
| Route / upstream keys | `Proxy:RouteKeys` (`keyRef`) | ❌ never accepted from clients | ❌ |

- Engineer/agent keys in `LocalKeys` use the proxied API (`/v1/*`) but get `401` on the
  dashboard login and on every `/admin/*` call - by design, there are no per-key admin grants.
- `Proxy:RouteKeys` are upstream credentials the proxy uses server-side; they are never
  accepted as a client `Bearer` and grant nothing client-facing.
- Secret values are **write-only everywhere**: the dashboard UI, the admin API and the audit
  log only ever handle fingerprints/hashes, never the keys themselves.
- Swagger still serves the legacy admin surface at `/swagger` (read-only docs, no auth for
  the page itself; calling any operation still requires the primary local key).

When a request is censored the response carries `X-AIRouter-Redacted: <count>` and, if
`notifyInResponse` is set, a visible **one-line** notice (e.g. `⚠️ **Proxy notice:** 4 sensitive
values were redacted before reaching the AI Router (OpenAI key × 4).`). The category summary is
the only detail: the notice has no "Detected values" list and never shows any part of the value.
Use the header and the notice to confirm a redaction rule behaves as expected.

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

## Dashboard (admin UI)

A Blazor Web App served by the proxy itself at `https://<host>:4000/admin/ui/...`, protected by
the **primary local key only** (the extra keys authenticate the proxied API but never `/admin`).
It is a *helper*: every write goes through the same config files (`config\routes.json`,
`config\redaction.json`, `config\appsettings.Server.json`) that the proxy hot-reloads, so the
proxy works fully without the dashboard and the JSON files remain the source of truth.

- **Login** (`/admin/ui/login`) - enter the primary local key once; a signed session cookie keeps
  you authenticated for 12 h. The cookie signing key is derived from the primary local key, so the
  session **survives a service restart** (deploys no longer force a re-login) but is invalidated by
  rotating the primary key; logout clears it. Keys are **write-only**: the UI and the API only ever
  see fingerprints/hashes, never the values.
  If the circuit drops, the UI rejoins automatically and reloads the page when the circuit is gone
  (at most 3 reloads per minute) instead of leaving the "Rejoining the server..." dialog stuck.
- **Routes & Keys** (`/admin/ui/routes`)
  - Route table: add/edit/delete routes (prefix, upstream, keyRef, headers, timeouts). Saves to
    `routes.json` with hot reload; new rows come pre-filled with the proxy defaults
    (300000 ms timeout / 20971520 bytes max body).
  - Route keys (`keyRef`): each ref shows a **chip** — `set` / `not set` — plus `in use` when a
    route references it; set/rotate the secret (write-only) or delete the ref (refused while in
    use). Optional owner/purpose metadata per ref (non-secret, stored in `data/key-meta.json`).
  - Local keys: the primary is fixed as `primary (admin)`; each extra key can carry a display
    **label** (e.g. the engineer's name or the laptop it was assigned to) that replaces the
    default `extra #N` — saved via `PUT /admin/api/v1/local-keys/{hash}/label`. Labels are
    metadata (fingerprint -> name) in `data/key-meta.json`; the secret values never live there.
  - Upstream key: set/rotate the key used for the default upstream when no route matches.
- **Activity** (`/admin/ui/activity`) - per-request log. Every entry shows the **presented
  hash** (fingerprint of the key that made the request, so usage is attributable by owner
  without exposing keys); refused requests additionally show the **expected hash** (or
  `(multiple keys)` when several keys match and the presented value is ambiguous) and are
  highlighted in red.
- **Security** (`/admin/ui/security`) - redaction, inspection and rate-limit settings (the
  same knobs as `redaction.json`), with restore/rollback on failed reload. Five status cards
  (local keys, rate limit, redaction, forensics, inspection) show the **saved** state; the
  Redaction/Inspection/Forensics cards add `· unsaved` while the form differs from the file.
- **Settings** (`/admin/ui/settings`) - export / validate / import the whole config bundle
  (validation first, apply after) and reload with automatic rollback when reload fails.

## Admin API (v1)

REST API under `/admin/api/v1/*`, authenticated with `Authorization: Bearer <primary local
key>` (same key as `/admin`/UI) and protected by the same rate limiter. Errors are typed JSON
(`validation_error`, `authentication_error`, `not_found`, `conflict`, `rate_limited`).

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/admin/api/v1/status` | Service status + version |
| `GET` | `/admin/api/v1/routes` | Current route table |
| `PUT` | `/admin/api/v1/routes` | Replace the route table |
| `GET` | `/admin/api/v1/keys` | Key refs (with set/in-use status) + local keys (fingerprints + labels) |
| `PUT` | `/admin/api/v1/keys/{keyRef}` | Create/ensure a keyRef declaration (no secret yet) |
| `PUT` | `/admin/api/v1/keys/{keyRef}/secret` | Set/rotate the keyRef secret (write-only) |
| `PUT` | `/admin/api/v1/keys/{keyRef}/meta` | Update owner/purpose metadata |
| `DELETE` | `/admin/api/v1/keys/{keyRef}` | Delete the keyRef (refused while in use) |
| `PUT` | `/admin/api/v1/local-keys/{hash}/label` | Set/clear the display label of an extra local key |
| `GET` | `/admin/api/v1/security` | Redaction / inspection settings |
| `PUT` | `/admin/api/v1/security` | Update redaction and/or inspection sections |
| `POST` | `/admin/api/v1/keys/lookup` | Resolve a presented hash to its owner (local key / keyRef) |
| `GET` | `/admin/api/v1/config/export` | Download the full config bundle (as attachment) |
| `POST` | `/admin/api/v1/config/validate` | Validate an import bundle without applying it |
| `POST` | `/admin/api/v1/config/import` | Apply an import bundle (backup + atomic write) |
| `POST` | `/admin/api/v1/config/reload` | Re-read config from disk; restore on failed reload |
| `DELETE` | `/admin/api/v1/logs/activity` | Clears the in-memory activity buffer (admin key required). |
| `DELETE` | `/admin/api/v1/logs/eventlog` | Clears the dedicated "AIRouterProxy" Windows Event Log (admin key required). |
| `GET` | `/admin/api/v1/detections?limit=50` | Recent detection forensics (metadata only: path/layer/kind/length/`name`/`sep`/`quote`/fingerprint; limit 1..200) |
| `DELETE` | `/admin/api/v1/detections` | Clears the in-memory detection forensics buffer (admin key required) |

In a detection row, `quote` is `"` or `'` when the matched context used that quote, `""` for a
`context` finding without quotes (and a `format` that inherits its shape from such an unquoted
`context` also gets `""`), and `null` for a layer without shape (`field`, `entropy`, or a `format`
that did not inherit a shape from an overlapping context at the same offset). `name` and `sep` are
`null` wherever `quote` is `null`.

Two dashboard operations exist only as service methods used by the UI (there is no v1 endpoint
for them): adding and removing extra local keys. The legacy `/admin/*` endpoints documented
above under [Verify your changes](#verify-your-changes) remain available and unchanged. The
legacy aliases `DELETE /admin/activity` and `DELETE /admin/logs` now go through the same audited
service path as the v1 log endpoints (audit actions `logs.clear.activity` / `logs.clear.eventlog`),
so every clear - from the API or the dashboard - leaves the same audit trail. In the dashboard,
the **Activity** page carries a single **Logs & activity** panel: a toolbar with the entry counter
and the two destructive buttons (`Clear activity` / `Clear Event Log`), a collapsible paginated
table (25/50/100 per page) and a collapsible note explaining the hashes. Each clear asks
for confirmation and then re-authenticates with the primary local key.

The **Security** page carries the redaction/inspection settings plus a **Detection forensics**
card (off by default): the card's **Enable/Disable** button persists the change immediately (the
form checkbox only stages it - the card keeps showing the saved state until the write is
confirmed), sets the buffer capacity (10..1000) and lists the latest detections - timestamp,
request id, route, **JSON path**, layer (field/format/context/entropy), kind, **pattern** (the
`name` + `sep` + `quote` shape: `context` rows, plus `format` rows that inherited it from an
overlapping context at the same offset), mask span length and an 8-char fingerprint. The value
itself is never recorded, the buffer lives in memory only (nothing on disk, cleared on restart,
on `Clear` or when forensics is disabled) and `Clear` re-authenticates with the primary local key.
See [Triaging detection forensics](#triaging-detection-forensics) for how to read the table.

## Triaging detection forensics

The **Detection forensics** card on `/admin/ui/security` (and `GET /admin/api/v1/detections`)
answers one question: *why was this request redacted, and where did the value come from?* It
records shape, not content - use it to investigate, never to look up a secret.

| Column | Meaning |
|---|---|
| **Time / Req / Route** | When, which request id, which route. `Req` links to `/admin/activity`. |
| **JSON path** | Where the detection fired (`$.messages[0].content`, `$.api_key`, ...). |
| **Layer** | Scanner that produced it: `field`, `format`, `context`, `entropy`. |
| **Kind** | Detector family (`openai`, `github`, `api_key`, `key_in_text`, `suspicious_key`, ...). |
| **Pattern** | `-` for `field`/`entropy` (no shape). `context` shows the identifier, separator and quote that matched (`token =`, `token : "`, `password = '`). `format` rows show the shape inherited from an overlapping context finding at the same offset. The **shape**, never the value. |
| **Len** | Length of the masked span (the union when candidates overlap). For merged rows it is not the detector match length. |
| **Fingerprint** | 8 hex chars of an HMAC keyed per process. |

**Overlaps are unioned.** When two detectors find overlapping candidates, the surviving
finding grows to cover the other one's tail: **overlapping candidates are merged and the
union is masked**, so the proxy never masks less **at the span level** - the union is never
shorter than any single detector's match. Base64 and allow-list exemptions are still
evaluated on the merged span, but a span that covers a `format` finding is **never**
exempted. `Len` is therefore the length of the span actually masked - for merged rows it is
not the detector match length.

**Allow-list + union trade-off (accepted).** The allow-list is evaluated against the **merged**
span, so a `context`/`entropy` union that matches an `allow` pattern exempts the whole span -
including the part only the entropy scanner would have flagged (an isolated entropy finding there
might not have been exempted). The reverse direction is closed: a span that covers a `format`
finding is never exempted. This is the accepted side of "never mask less at the span level".

**Inheritance needs the same offset.** A `format` row only inherits `name`/`sep`/`quote` when the
discarded `context` finding starts at the **same** offset. When the `context` match starts *before*
the `format` one (e.g. `token:=<value>`), the surviving layer is `context` and it keeps its own
shape; there is no inheritance to do. The offset difference comes from the `=`: the `context`
separator group matches only `:`, while the value character class includes `=`, so the `=` is
absorbed into the `value` group and the value starts on the `=` - one character before the real
secret, which makes `Len` one longer and masks the `=` as well.

**Group by fingerprint, not by row.** The same value gives the same fingerprint within one process
run; ten rows with one fingerprint are one secret re-sent ten times, not ten secrets. The key is
ephemeral, so compare within a session, never across restarts. Same fingerprint ⇒ (almost certainly)
same value within the process; **the reverse is not guaranteed** - the same secret can get different
fingerprints when the masked span differs (`field` hashes the whole value, while
`bearer`/`url_cred`/`db_conn` hash only group 2).

**Read the layer before worrying.** The confidence order applies **at the same offset** (the
merge sorts by start first): `format` > `field` > `context` ≈ `entropy`
(`context` and `entropy` are both Medium, and the merge prefers `context` on a tie).
`format`/`field` are actionable (a known shape or a sensitive field name was masked - rotate it if
real); `context`/`entropy` are heuristics and can fire on legitimate text. Length is a quick sanity
check: OpenAI/Anthropic keys are 51/100+ chars, GitHub classic PATs 40, `github_pat_` 93, AWS access
key id 20, Google API keys 39 - an 8–9-char `Len` in `context` is usually a false positive **when the
pattern is not `password`/`secret`** - an 8-char password is exactly what this layer exists to catch.

**Use the path to find the origin.** `$.messages[N].content` is client-supplied history (pasted in
the prompt, or read from a file/tool result) - the common case. `reasoning`/`reasoning_details` is
model output, and OpenRouter duplicates the reasoning text in two fields, so one echo appears
twice. A field path (`$.api_key`, `$.headers.authorization`) means a JSON/config object carried it.

**Correlate.** Take `Req` to `/admin/activity` for the client, model, status and the surrounding
timeline. The same fingerprint in consecutive requests from one client means the same value is
replayed every turn in the agent's history.

**Going further without revealing anything.** Locate the source by *name*, with counts only:

```powershell
rg -c "token|secret|password|api_key|access_key" src\
```

The pattern must mirror the detector's name list (`token`, `secret`, `password`, `api_key`,
`access_key`, `credential`, `authorization`, ...). A bare `key` is **not** detected - `x:Key` in
XAML or `myKey` alone never fires. A false positive observed live: unquoted assignments in source
code (`var token = …`, `$token = …`) fire `context` with `name=token` even though the right-hand
side is not a credential - the `Pattern` column (`token =`) is how you spot it. If the fingerprint
always returns at the same path, a persistent file is in the agent's context: fix it at the source.
`format`/`field` -> rotate the credential. Benign and stable `context`/`entropy` -> add a
`Redaction.allow` regex.

**What the proxy will not do.** There is no "reveal" action and no stored value, prefix, suffix or
snippet - by design: crash dumps and dashboard logs would become a second copy of every secret;
XSS, a shared screen or DevTools would expose it in the UI; and the buffer would retain personal
data the proxy has no business keeping. Never ask an agent to print a detected value to "check"
it: the agent's context and the shell output are exactly the channels the proxy protects.

**Reducing noise.** The `context` layer minimum length (8 today) is **not configurable** - changing
it requires a code change and a rebuild, so it is not a runtime knob. `Redaction.allow` is the
targeted option and applies only to `context`/`entropy` - the `format` and `field` layers are never
exempted, and neither is a merged span that covers a `format` finding. The `name=` base64 exemption
is name-exact as well: a prefixed/suffixed identifier (`OPENAI_API_KEY=`, `MY_SECRET_KEY=`,
`x-SECRET_KEY=`) is not a whitelisted name, so a long base64-looking value after it stays a payload
and produces no row at all - by design.

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
mkcert -key-file proxy-key.pem -cert-file proxy-cert.pem localhost winzone 192.168.1.77 127.0.0.1
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
$cert = New-SelfSignedCertificate -DnsName "localhost","winzone","192.168.1.77" -CertStoreLocation Cert:\LocalMachine\My
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

### Ready-made configs

Two complete, working `opencode.json` examples ship in the repo — pick the one that matches the
route you want as the default:

| File | Default route | Models |
|---|---|---|
| [`opencode_configs/opencode_airouter.json`](opencode_configs/opencode_airouter.json) | `/v1` -> AI Router | `airouter/Qwen3.8`, `airouter/DeepSeek-V4-Flash` |
| [`opencode_configs/opencode_openrouter.json`](opencode_configs/opencode_openrouter.json) | `/openrouter` -> OpenRouter | `openrouter-local/deepseek/deepseek-v4.1-flash-1017` |

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
   [Certificates](#certificates)). Use `https://localhost:4000/...` when the proxy runs on the same
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

![Access to secret files blocked by permissions](images/opencode_file_permissions.png)

### What `watcher.ignore` and `permissions` do

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
helpers (no xUnit). Covers redaction (4 layers), the one-line redaction notice, detection
forensics (JSON path/layer/kind/fingerprint, zero cost when off), fail-closed inspection policy,
route resolution/allowed-path enumeration (traversal, case, `%2f`), auth edges + multi-key, rate
limiter/lockout (including exact concurrency via `Parallel.For`) and the SSE protocol adapters.

```powershell
dotnet run --project tests/Unit/RedactorTests.csproj -c Release
# -> RESULT: 383 PASS, 0 FAIL
```

### Dashboard harness (offline, no framework, no packages)

Same `Check`/`CheckTrue` philosophy (no xUnit), compiled against the dashboard sources
(`AdminServices`, `AdminPersistence`, `AdminValidation`, `AdminUi` facade). Covers the admin
write path (validate -> backup -> atomic write -> re-read/confirm -> audit), route/key/secret
operations, KeyMetaStore persistence (owner/purpose + local-key labels), config export/
validate/import/reload, the security validator + forensics round-trip, the UI session token
rules (restart, key rotation, multi-key) and the `/admin/ui` middleware (`/_blazor` 401),
plus the runtime dashboard state:

```powershell
dotnet run --project tests/Dashboard.Tests/DashboardTests.csproj -c Release
# -> RESULT: 331 PASS, 0 FAIL
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
