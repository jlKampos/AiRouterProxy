# deploy-update.ps1 - stops, copies from publish-tmp to deploy (preserving config/cert) and starts the service
# Usage (deploy in the project's 'deploy' folder): powershell -ExecutionPolicy Bypass -File .\deploy-update.ps1
# Usage (existing install elsewhere):             powershell -ExecutionPolicy Bypass -File .\deploy-update.ps1 -DeployDir "C:\Path\To\deploy"
param(
    [string]$DeployDir = (Join-Path $PSScriptRoot 'deploy')
)
$ErrorActionPreference = 'Continue'
$log = Join-Path $PSScriptRoot 'deploy-update.log'
function W($m){ $m | Add-Content $log }
Set-Content $log '=== deploy-update start ==='
# publish-tmp lives in the project (source); deploy is relative to the project by default (override with -DeployDir)
$src = Join-Path $PSScriptRoot 'publish-tmp'
$dst = $DeployDir
$svc = Get-Service AIRouterProxy -EA SilentlyContinue

W "stopping service..."
if ($svc) {
    Stop-Service AIRouterProxy -Force -EA SilentlyContinue
    Start-Sleep -Seconds 3
    W "status after stop: $((Get-Service AIRouterProxy).Status)"
} else {
    W "AIRouterProxy service not found - file copy only"
}

Copy-Item "$dst\appsettings.json" "$dst\appsettings.json.prev" -Force -EA SilentlyContinue
Copy-Item "$dst\proxy-cert.pem" "$dst\proxy-cert.pem.prev" -Force -EA SilentlyContinue
Copy-Item "$dst\proxy-key.pem" "$dst\proxy-key.pem.prev" -Force -EA SilentlyContinue
Copy-Item "$dst\redaction.json" "$dst\redaction.json.prev" -Force -EA SilentlyContinue
Copy-Item "$dst\routes.json" "$dst\routes.json.prev" -Force -EA SilentlyContinue

W "copying publish -> deploy..."
Copy-Item "$src\*" $dst -Recurse -Force -EA Continue

Copy-Item "$dst\appsettings.json.prev" "$dst\appsettings.json" -Force -EA SilentlyContinue
Copy-Item "$dst\proxy-cert.pem.prev" "$dst\proxy-cert.pem" -Force -EA SilentlyContinue
Copy-Item "$dst\proxy-key.pem.prev" "$dst\proxy-key.pem" -Force -EA SilentlyContinue
Copy-Item "$dst\redaction.json.prev" "$dst\redaction.json" -Force -EA SilentlyContinue
Copy-Item "$dst\routes.json.prev" "$dst\routes.json" -Force -EA SilentlyContinue
Remove-Item "$dst\appsettings.json.prev","$dst\proxy-cert.pem.prev","$dst\proxy-key.pem.prev","$dst\redaction.json.prev","$dst\routes.json.prev" -Force -EA SilentlyContinue

if (Test-Path "$dst\AIRouterProxy.exe") { W "exe deploy: $((Get-Item "$dst\AIRouterProxy.exe").LastWriteTime)" }
W "Server.json exists: $(Test-Path "$dst\appsettings.Server.json")"
if (Test-Path "$dst\proxy-cert.pem") { W "cert deploy: $((Get-Item "$dst\proxy-cert.pem").LastWriteTime)" }

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
