# deploy-update.ps1 - stops, copies from publish-tmp to deploy (preserving config/cert in the
# deploy's config/ subfolder) and starts the service.
# Usage (deploy in the project's 'deploy' folder): powershell -ExecutionPolicy Bypass -File .\scripts\deploy-update.ps1
# Usage (existing install elsewhere):             powershell -ExecutionPolicy Bypass -File .\scripts\deploy-update.ps1 -DeployDir "C:\Path\To\deploy"
param(
    [string]$DeployDir = (Join-Path (Split-Path $PSScriptRoot -Parent) 'deploy')
)
# This script ships in scripts/, so the repo root is one level up from $PSScriptRoot.
$repoRoot = Split-Path $PSScriptRoot -Parent
$ErrorActionPreference = 'Continue'
$log = Join-Path $repoRoot 'deploy-update.log'
function W($m){ $m | Add-Content $log }
Set-Content $log '=== deploy-update start ==='
# publish-tmp lives in the repo root (publish output); deploy is relative to the repo root by default (override with -DeployDir)
$src = Join-Path $repoRoot 'publish-tmp'
$dst = $DeployDir
$cfg = Join-Path $dst 'config'
$svc = Get-Service AIRouterProxy -EA SilentlyContinue

# Config files that keep their values across updates (preserved at the destination).
# Priority: destination config\ (new layout), then the legacy deploy root (migrated to config\).
$keep = @('appsettings.json','appsettings.Server.json','redaction.json','routes.json','proxy-cert.pem','proxy-key.pem')

W "stopping service..."
if ($svc) {
    Stop-Service AIRouterProxy -Force -EA SilentlyContinue
    Start-Sleep -Seconds 3
    W "status after stop: $((Get-Service AIRouterProxy).Status)"
} else {
    W "AIRouterProxy service not found - file copy only"
}

if (-not (Test-Path $cfg)) { New-Item -ItemType Directory -Path $cfg | Out-Null }

# 1) Back up the current config (from config\ or the legacy root) as *.prev inside config\
foreach ($name in $keep) {
    $fromCfg   = Join-Path $cfg $name
    $fromRoot  = Join-Path $dst $name
    $from = if (Test-Path $fromCfg) { $fromCfg } elseif (Test-Path $fromRoot) { $fromRoot } else { $null }
    if ($from) { Copy-Item $from "$cfg\$name.prev" -Force -EA SilentlyContinue }
}

W "copying publish -> deploy..."
Copy-Item "$src\*" $dst -Recurse -Force -EA Continue

# 2) Restore the preserved config values into config\
foreach ($name in $keep) {
    $prev = Join-Path $cfg "$name.prev"
    if (Test-Path $prev) { Copy-Item $prev (Join-Path $cfg $name) -Force -EA SilentlyContinue }
}
Remove-Item "$cfg\*.prev" -Force -EA SilentlyContinue

# 3) Legacy migration: anything still at the deploy root moves into config\ (only when absent)
foreach ($name in $keep) {
    $atRoot = Join-Path $dst $name
    $atCfg  = Join-Path $cfg $name
    if ((Test-Path $atRoot) -and -not (Test-Path $atCfg)) { Copy-Item $atRoot $atCfg -Force -EA SilentlyContinue }
}

if (Test-Path "$dst\AIRouterProxy.exe") { W "exe deploy: $((Get-Item "$dst\AIRouterProxy.exe").LastWriteTime)" }
W "Server.json exists: $(Test-Path "$cfg\appsettings.Server.json")"
if (Test-Path "$cfg\proxy-cert.pem") { W "cert deploy: $((Get-Item "$cfg\proxy-cert.pem").LastWriteTime)" }

W "starting service..."
if ($svc) {
    Start-Service AIRouterProxy -EA SilentlyContinue
    Start-Sleep -Seconds 3
    W "status: $((Get-Service AIRouterProxy).Status)"
    W "port 4000: $([bool](Get-NetTCPConnection -LocalPort 4000 -State Listen -EA SilentlyContinue))"
} else {
    W "service not installed - start the exe manually: $dst\AIRouterProxy.exe"
}
W '=== deploy-update end ==='