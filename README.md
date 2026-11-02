# AiRouterProxy

Local HTTPS proxy for the AI Router with a **multi-upstream router**: a per-path
route table lets you forward to several OpenAI-compatible providers, each with its own key.

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

### In action

The agent gets a visible notice when a request was censored:

![Proxy notice when a request contained censored content](images/proxy_guardrails.png)

And the model only ever sees the masked value - never the real secret:

![The request as it reaches the model, sensitive value masked](images/proxy_guardrails_II.png)

## Stack

- .NET 10 / ASP.NET Core (Kestrel + TLS)
- Path-prefix router (`routes.json`)
- Sensitive-content redaction on outgoing requests (`redaction.json`, hot reload)
- Admin endpoints protected by a local key (`/admin/*`)
- Windows Service (`AIRouterProxy`, port 4000)

## Structure

```
AiRouterProxy/
|-- AiRouterProxy/                 # C# source
|   |-- ProxyOptions.cs            # Proxy/Routes/Redaction options
|   |-- RouteResolver.cs           # route resolution (longest prefix)
|   |-- ProxyMiddleware.cs         # proxy + redaction + notice
|   |-- SecretRedactor.cs          # secret detection (4 layers)
|   |-- NoticeInjector.cs          # notice at the end of the response (SSE/JSON)
|   |-- ActivityStore.cs           # activity log (/admin/activity)
|   |-- appsettings.json           # non-secret config
|   |-- appsettings.Server.example.json  # TEMPLATE for the keys (copy to appsettings.Server.json)
|   |-- redaction.json             # redaction flags (non-secret)
|   `-- routes.json                # route table (non-secret)
|-- tests/                         # unit test harness (no framework)
|-- deploy-update.ps1              # build/publish + deploy to the service
`-- genApiKey.ps1                  # generates/rotates the local key
```

## Configuration

### Files: secret vs non-secret

| File | Content | In the repo? |
|---|---|---|
| `appsettings.Server.json` | Keys and certificates config (SECRET) | **No** (gitignored). Copy it from `appsettings.Server.example.json` |
| `appsettings.json` | Non-secret proxy defaults (host, port) | Yes |
| `routes.json` | Route table (upstreams, prefixes, key refs by name - no key values) | Yes |
| `redaction.json` | Redaction flags and mask | Yes |
| `proxy-cert.pem` / `proxy-key.pem` | TLS certificate + private key (SECRET) | **No** (gitignored). Generated on the server |
| `LOCAL_KEY.txt` | Last local key generated (SECRET) | **No** (gitignored) |
| `deploy/`, `publish-tmp/` | Local service install and build output | **No** (gitignored) |

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
- `Proxy:Keys:LocalKey` - key the proxy accepts from local clients (protects both the proxy and `/admin`). Generate one with `genApiKey.ps1`.
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

Redacts sensitive content (API keys, passwords, tokens) in outgoing request bodies:

```jsonc
{
  "Proxy": {
    "Redaction": {
      "enabled": true,
      "mask": "******",
      "notifyInResponse": true,     // appends a visible notice to the model response (SSE/JSON)
      "warnTemplate": "",           // optional template; {Count} and {Kinds} placeholders
      "detect": {
        "byFieldName": true,        // api_key, password, token, senha...
        "byFormats": true,          // sk-, ghp_, AIza, JWT, Bearer, PEM...
        "byKeyValueContext": true,  // "key": "value" / KEY=value in text
        "byLongStrings": true       // long URL-safe tokens (>= 28 chars) with mixed case
      }
    }
  }
}
```

### Hot reload

`appsettings.Server.json`, `routes.json` and `redaction.json` are watched with `reloadOnChange` -
edits apply **without a restart**.

## Local key

```powershell
# generates a new key in sk- format (OpenAI style) and writes it to deploy/appsettings.Server.json
powershell -ExecutionPolicy Bypass -File .\genApiKey.ps1
# existing install elsewhere:
powershell -ExecutionPolicy Bypass -File .\genApiKey.ps1 -DeployDir "C:\Path\To\deploy"
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

### OpenRouter route - working example

Use a **custom provider ID** such as `openrouter-local`, not the reserved `openrouter` ID: the custom ID
forces the agent to honor the proxy `baseURL` and keeps the model list limited to what you define (the
reserved ID merges the whole models.dev catalog and may ignore `baseURL`).

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
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
| `401` | Wrong LocalKey | Run `genApiKey.ps1` and copy `LOCAL_KEY.txt` |
| `404 No proxy route matches` | Prefix not present in routes.json | Check `routes.json` reloaded (hot reload) |
| `502 Route 'X' has no API key configured` | Upstream key missing | Fill `Proxy:RouteKeys:X` or `UpstreamKey` in appsettings.Server.json |
| TLS/certificate error on the client | CA not trusted | `mkcert -install` (or install the CA root store as above) |

## Tests

```powershell
dotnet run --project tests/RedactorTests.csproj
```

## Deploy (installed service)

### Regular update of an existing service

```powershell
dotnet publish AiRouterProxy/AIRouterProxy.csproj -c Release -r win-x64 --self-contained true -o publish-tmp
# elevated (UAC); deploys to the project's deploy/ folder by default (override with -DeployDir)
powershell -ExecutionPolicy Bypass -File .\deploy-update.ps1
# existing install elsewhere:
powershell -ExecutionPolicy Bypass -File .\deploy-update.ps1 -DeployDir "C:\Omni\AIRouterProxy\deploy"
```

`deploy-update.ps1` preserves config/certs on the destination and restarts the service (when installed as a Windows Service).

### Moving the deployed service to a new folder (e.g. from C:\Omni to the repo)

1. **Stop the old service** (elevated):
   ```powershell
   sc.exe stop AIRouterProxy
   ```
2. **Build and deploy into the new folder** (from the repo root):
   ```powershell
   dotnet publish AiRouterProxy/AIRouterProxy.csproj -c Release -r win-x64 --self-contained true -o publish-tmp
   powershell -ExecutionPolicy Bypass -File .\deploy-update.ps1
   ```
   The publish does not include secrets. Copy them manually once into `deploy/`:
   ```powershell
   Copy-Item "C:\Omni\AIRouterProxy\deploy\appsettings.Server.json" deploy\
   Copy-Item "C:\Omni\AIRouterProxy\deploy\proxy-cert.pem" deploy\
   Copy-Item "C:\Omni\AIRouterProxy\deploy\proxy-key.pem" deploy\
   ```
   (`deploy-update.ps1` preserves these files on future updates, so you only do this once.)
3. **Point the Windows Service at the new path** (elevated):
   ```powershell
   sc.exe config AIRouterProxy binPath= "C:\Users\jlkampos\Documents\GitHub\AiRouterProxy\deploy\AIRouterProxy.exe"
   ```
4. **Start and verify** (elevated):
   ```powershell
   sc.exe start AIRouterProxy
   Get-NetTCPConnection -LocalPort 4000 -State Listen       # should show listening
   ```
   

> The service runs under LocalSystem; the new deploy path must be readable by it (a plain user folder is fine).
