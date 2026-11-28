# Operations: interactive menu and deploy

[← Back to README](../README.md)

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
`proxy-cert.pem` / `proxy-key.pem` (see [Certificates](certificates.md) / menu option 7).

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

`deploy-update.ps1` preserves config/certs (keeping them in the destination `config/` folder and migrating an older flat install automatically), registers the service when it is missing (**first install**, see above) and restarts it (when installed as a Windows Service). Runtime data under `data\` (endpoint baseline, pins, audit log, key-meta, backups) is never part of the publish output and is never touched by the update. If the deploy carries inspection/rate-limit changes, refresh the destination `redaction.json` from the repo copy afterwards (the deploy script preserves the destination file by design).

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
