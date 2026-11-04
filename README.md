# AiRouterProxy

Local HTTPS proxy for the AI Router with a **multi-upstream router**: a per-path
route table lets you forward to several OpenAI-compatible providers, each with its own key.
**Current version:** 2.0.4 ([releases](https://github.com/jlKampos/AiRouterProxy/releases))

## Table of contents

- [Why: a security layer](#why-a-security-layer-for-development-environments)
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
- [Deploy (installed service)](#deploy-installed-service)

## Why: a security layer for development environments

AiRouterProxy exists to **enforce that secrets never leave the machine** to AI model providers -
in both **personal and corporate development environments**. It is a local HTTPS guardrail that
sits between your AI coding agent and the model provider.

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

- by **field name** (`api_key`, `password`, `token`, ...),
- by **known format** (`sk-...`, `ghp_`, `AIza`, `JWT`, `Bearer`, PEM private keys, ...),
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
- Admin endpoints protected by a local key (`/admin/*`)
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
|   |   |-- Program.cs             #   no framework - 236 PASS
|   |   `-- RedactorTests.csproj
|   `-- Integration/               # black-box integration harness against a REAL deployed proxy
|-- scripts/
|   |-- deploy-update.ps1          # deploy to the installed service (preserves secrets/certs on the destination)
|   `-- genApiKey.ps1              # generates/rotates the local key
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
    "Upstream": "https://api.airrouter.ch",  // upstream used when no route matches ("" prefix)
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
| `Upstream` | `https://api.airrouter.ch` | Fallback upstream when no route matches. |
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
      "LocalKey": "sk-...  (local key clients use to talk to the proxy)"
    },
    "RouteKeys": {
      "OPENROUTER": "sk-or-...  (key used by the /openrouter route)",
      "GROQ": "gsk_...  (optional, used by any route with keyRef GROQ)"
    }
  }
}
```

- `Proxy:Keys:UpstreamKey` - key for the **default route** (`prefix: ""`).
- `Proxy:Keys:LocalKey` - key the proxy accepts from local clients (protects both the proxy and `/admin`). Generate one with `scripts\genApiKey.ps1`.
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
        "upstream": "https://api.airrouter.ch",
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
      }
    ]
  }
}
```

Mapping example:
- `https://localhost:4000/v1/chat/completions` -> `https://api.airrouter.ch/v1/chat/completions` (default route)
- `https://localhost:4000/openrouter/v1/chat/completions` -> `https://openrouter.ai/api/v1/chat/completions` (prefix removed before forwarding)

Rules:
- Only one route can have `prefix: ""`.
- `prefix` must start with `/` and match on a **segment boundary** (`/openrouter` does not match `/openrouterX`).
- `allowedPaths` matches the path **after** prefix removal; supports a trailing `*`.
- A route whose key is missing is **inactive** (returns 502, not a proxy crash).

### redaction.json

Non-secret policy file. Besides the **redaction** rules it also holds the **inspection**
(fail-closed body handling) and **rate limiting** sections - all under the same `Proxy` block.

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
  (`api_key`, `password`, `token`, `senha`, ...). A `*_tokens` family is excluded automatically
  so usage counters like `max_tokens` are never touched.
- `byFormats` - high-confidence formats: OpenAI/Anthropic `sk-...`, `ghp_`, `AIza`, Slack `xox*`,
  AWS `AKIA/ASIA/...`, JWT, `Bearer <value>`, PEM private key blocks.
- `byKeyValueContext` - `"key": "value"` / `KEY=value` config excerpts (only the value is masked).
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

When a request is censored the response carries `X-AIRouter-Redacted: <count>` and, if
`notifyInResponse` is set, a visible notice - use both to confirm a redaction rule behaves as
expected.

### Hot reload

`appsettings.Server.json`, `routes.json` and `redaction.json` are watched with `reloadOnChange` -
edits apply **without a restart**. `Host`/`Port` and the TLS certificates are read at startup
(the Kestrel listener binds once), so changing those still requires a restart.

## Local key

```powershell
# generates a new key in sk- format (OpenAI style) and writes it to deploy/appsettings.Server.json
powershell -ExecutionPolicy Bypass -File .\scripts\genApiKey.ps1
# existing install elsewhere:
powershell -ExecutionPolicy Bypass -File .\scripts\genApiKey.ps1 -DeployDir "C:\Path\To\deploy"
```

The script prints the key hash and stores the key in `LOCAL_KEY.txt` for the client to copy.

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

### Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `401` | Wrong LocalKey | Run `scripts\genApiKey.ps1` and copy `LOCAL_KEY.txt` |
| `404 No proxy route matches` | Prefix not present in routes.json | Check `routes.json` reloaded (hot reload) |
| `502 Route 'X' has no API key configured` | Upstream key missing | Fill `Proxy:RouteKeys:X` or `UpstreamKey` in appsettings.Server.json |
| TLS/certificate error on the client | CA not trusted | `mkcert -install` (or install the CA root store as above) |

## Tests

### Unit harness (offline, no framework, no packages)

Links the proxy's real sources in isolation and asserts them with the in-repo `Check`/`CheckTrue`
helpers (no xUnit). Covers redaction (4 layers), fail-closed inspection policy, route
resolution/allowed-path enumeration (traversal, case, `%2f`), auth edges + multi-key, rate
limiter/lockout (including exact concurrency via `Parallel.For`) and the SSE protocol adapters.

```powershell
dotnet run --project tests/Unit/RedactorTests.csproj -c Release
# -> RESULT: 236 PASS, 0 FAIL
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
battery: TTFT / total SSE latency per model, small token spend).

What it verifies: health/auth (401 vs 200), `/admin` never leaks the key (payload + activity +
refusals + logs), malformed/oversized requests blocked upstream-free (400/415/405+Allow/404/413),
real forward + SSE streaming, redaction observability (`redacted>0` in activity), rate limit
(429 + `Retry-After >= 1`).

> Note: the `Allow` response header is an **entity header** - `HttpClient` exposes it under
> `resp.Content.Headers`, so the harness reads it from both the response and the content headers.

## Deploy (installed service)

The service runs as a Windows Service (`AIRouterProxy`) whose executable is deployed to a service
folder. The recommended layout puts it under `C:\Services` (outside any repo), e.g.
`C:\Services\AiRouterProxy\`. All config files (appsettings.*.json, redaction.json, routes.json and the TLS certs) live in a **`config`** subfolder next to the exe, so the deploy root only has the executable and the configs are easy to find (the server auto-detects `config/`; a flat install without it keeps working).

### Regular update of an existing service

```powershell
# self-contained is REQUIRED: the host has no x64 .NET runtime installed, so a
# framework-dependent publish fails to start ("No frameworks were found").
# Publish to a folder OUTSIDE the repo when you must not touch publish-tmp/.
dotnet publish src/AiRouterProxy/AIRouterProxy.csproj -c Release -r win-x64 --self-contained true -o publish-tmp
# elevated (UAC); deploys to the project's deploy/ folder by default (override with -DeployDir)
powershell -ExecutionPolicy Bypass -File .\scripts\deploy-update.ps1
# installed service under C:\Services:
powershell -ExecutionPolicy Bypass -File .\scripts\deploy-update.ps1 -DeployDir "C:\Services\AiRouterProxy"
```

`deploy-update.ps1` preserves config/certs (keeping them in the destination `config/` folder and migrating an older flat install automatically) and restarts the service (when installed as a Windows Service). If the deploy carries inspection/rate-limit changes, refresh the destination `redaction.json` from the repo copy afterwards (the deploy script preserves the destination file by design).

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
