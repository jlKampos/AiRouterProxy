# AiRouterProxy

Local HTTPS proxy for the AI Router (api.airrouter.ch) with a **multi-upstream router**: a per-path
route table lets you forward to several OpenAI-compatible providers, each with its own key.

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

Local clients send the proxy's **LocalKey** (Bearer); the proxy authenticates the request with it and
injects the correct upstream key per route. Configure two providers pointing at the local proxy:

```jsonc
{
  "provider": {
    "airouter-local": {
      "name": "airouter-local",
      "npm": "@ai-sdk/openai-compatible",
      "options": {
        "baseURL": "https://localhost:4000/v1",          // default route -> aiRouter
        "apiKey": "sk-...your-LocalKey..."               // the proxy's LOCAL key, not the upstream one
      },
      "models": { /* same model list as a direct aiRouter provider */ }
    },
    "openrouter-local": {
      "name": "openrouter-local",
      "npm": "@ai-sdk/openai-compatible",
      "options": {
        "baseURL": "https://localhost:4000/openrouter/v1", // /openrouter route -> OpenRouter
        "apiKey": "sk-...your-LocalKey..."
      },
      "models": { /* the OpenRouter models you want */ }
    }
  }
}
```

Then use them as `airouter-local/Model-Id` or `openrouter-local/Model-Id`.

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
5. **Delete the old folder only after** the new service is Running and responding:
   ```powershell
   Remove-Item -Recurse -Force "C:\Omni\AIRouterProxy"
   ```

> The service runs under LocalSystem; the new deploy path must be readable by it (a plain user folder is fine).
