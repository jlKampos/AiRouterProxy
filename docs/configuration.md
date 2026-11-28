# Configuration

[← Back to README](../README.md)

## Files: secret vs non-secret

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
| `data/endpoint-baseline.json` | TLS endpoint fingerprints per route (IP, cert hashes, issuer, TLS facts — metadata only) | **No** (generated at runtime) |
| `data/pins.json` | Learned endpoint pins per route (SPKI fingerprints — metadata only) | **No** (generated at runtime) |
| `deploy/`, `publish-tmp/` | Local service install and build output | **No** (gitignored) |

> At the installed service, all config files live in a config subfolder next to the exe (the server reads from there when present - see [Deploy (installed service)](operations.md#deploy-installed-service)).

## Quick reference

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
| Enforce endpoint attestation per route (observe/warn/block, pins, grace) | `routes.json` | `Proxy:Routes[].Transport` | ✓ hot reload |

> This is the *dev point of view*. On the installed service the same files are read from the
> `config\` subfolder next to the exe.

## appsettings.json

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

## appsettings.Development.json

Optional overrides applied only when the app runs with `ASPNETCORE_ENVIRONMENT=Development`
(the installed Windows Service does not set it, so this file is ignored there). Use it in dev
to e.g. raise `Verbose` or lower `RequestTimeoutMs` without touching the shipped defaults.

## appsettings.Server.json

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

## routes.json

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
- `keyRef` that is **not declared** in `Proxy:RouteKeys` (nor created in the dashboard **Keys** panel)
  is a **warning, not an error**: the route table is saved and the route stays **inactive** until
  the keyRef exists **and** has a key set. To activate it, add the keyRef in the **Keys** panel
  (`Add keyRef`) and set its secret; the same applies to a declared-but-empty keyRef. Reserved
  headers, invalid upstreams and duplicate/conflicting prefixes remain hard errors that block the save.
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

## redaction.json

Non-secret policy file. Besides the **redaction** rules it also holds the **inspection**
(fail-closed body handling) and **rate limiting** sections - all under the same `Proxy` block.

**Precedence:** config files are loaded in order — `appsettings.json`, `appsettings.{Env}.json`,
`appsettings.Server.json`, then `redaction.json` and `routes.json`. Later files override earlier
ones **per key** (not per block): if the same key exists in both `appsettings.json` and
`redaction.json`, `redaction.json` wins; keys present only in `appsettings.json` keep their value.
Both are watched (hot reload), so edits apply without a restart.

### Redaction — what gets masked

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

## Inspection (fail-closed body handling)

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

## Rate limiting

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

## How to edit

- **Development:** edit the files in `src/AiRouterProxy/` in the repo (`appsettings.json`,
  `redaction.json`, `routes.json`, ...) and run / publish the app.
- **Installed service:** every config file lives in the **`config\` subfolder** next to the exe
  (e.g. `C:\Services\AiRouterProxy\config\`). Edit the files there directly - the service reads
  from `config\` when it exists and falls back to the exe folder otherwise.
- **Keep valid JSON:** the examples here use `jsonc` (with comments) only for readability. The
  real files must be **strict JSON** - no comments, no trailing commas.
- **Back up before editing:** keep a copy of the current file (the deploy scripts already
  preserve `config\appsettings.*.json`, `redaction.json`, `routes.json` and the certs on update).

## Verify your changes

`/admin` endpoints are protected by the local key (`Proxy:Keys:LocalKey`). The admin REST API
v1 is the current interface; the legacy endpoints below still work unchanged:

```powershell
# admin API v1 (current)
curl.exe --ssl-no-revoke https://localhost:4000/admin/api/v1/status -H "Authorization: Bearer <LocalKey>"
# {"status":"ok","version":"2.8.0","routes":N,"redactionEnabled":true,...}

curl.exe --ssl-no-revoke https://localhost:4000/admin/api/v1/routes -H "Authorization: Bearer <LocalKey>"
# the current route table (key refs, never key values)

curl.exe --ssl-no-revoke https://localhost:4000/admin/api/v1/keys -H "Authorization: Bearer <LocalKey>"
# key refs (set/not set, in use) + local keys (fingerprints + labels)

# legacy endpoints (still available, same answers)
curl.exe --ssl-no-revoke https://localhost:4000/admin/health -H "Authorization: Bearer <LocalKey>"
# {"status":"ok","version":"2.8.0",...}

curl.exe --ssl-no-revoke https://localhost:4000/admin/endpoints -H "Authorization: Bearer <LocalKey>"
# routes + allowed paths + current redaction flags (including exemptBase64)

curl.exe --ssl-no-revoke https://localhost:4000/admin/activity?hours=6 -H "Authorization: Bearer <LocalKey>"
# recent requests; entries with "redacted" > 0 had content masked
```

## Who can access `/admin` (dashboard UI + admin REST API v1)

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

## Hot reload

`appsettings.Server.json`, `routes.json` and `redaction.json` are watched with
`reloadOnChange` - edits apply **without a restart**. `Host`/`Port` and the TLS certificates are
read at startup (the Kestrel listener binds once), so changing those still requires a restart.
