# genApiKey.ps1 - generates local keys for AIRouterProxy
#
# Usage:
#   (no flags)                         -> prints this help
#   -Print                             -> generate a key and PRINT it to the console.
#                                          Use for an engineer/agent key: add it to
#                                          Proxy:Keys:LocalKeys on the server - it gets
#                                          /v1/* but NOT /admin/*.
#   -Write                             -> generate a key and write it as the PRIMARY
#                                          LocalKey into appsettings.Server.json (rotate
#                                          behaviour), plus LOCAL_KEY.txt for the client.
#   -DeployDir "C:\Path\To\deploy"     -> target install (used with -Write)
#
# Examples:
#   powershell -ExecutionPolicy Bypass -File .\scripts\genApiKey.ps1 -Print
#   powershell -ExecutionPolicy Bypass -File .\scripts\genApiKey.ps1 -Write
#   powershell -ExecutionPolicy Bypass -File .\scripts\genApiKey.ps1 -Write -DeployDir "C:\Services\AIRouterProxy"

param(
    [switch]$Print,                              # print a generated key to the console (engineer key)
    [switch]$Write,                              # write the generated key as LocalKey into appsettings.Server.json
    [string]$DeployDir = (Join-Path (Split-Path $PSScriptRoot -Parent) 'deploy')
)

$ErrorActionPreference = 'Stop'

function Show-Help {
@"
genApiKey.ps1 - generate AIRouterProxy local keys

USAGE (no flags shows this help):
  -Print              Generate a key and print it to the console. Use for an engineer
                      key: add it to Proxy:Keys:LocalKeys on the server. It gets /v1/*
                      but NOT /admin/*.
  -Write              Generate a key and write it as the PRIMARY LocalKey into the
                      deployed appsettings.Server.json (rotate behaviour) + LOCAL_KEY.txt
                      + immediate /v1 test.
  -DeployDir <path>   Target install (used with -Write). Default: <repo>\deploy.

EXAMPLES:
  powershell -ExecutionPolicy Bypass -File .\scripts\genApiKey.ps1 -Print
  powershell -ExecutionPolicy Bypass -File .\scripts\genApiKey.ps1 -Write
  powershell -ExecutionPolicy Bypass -File .\scripts\genApiKey.ps1 -Write -DeployDir "C:\Services\AIRouterProxy"
"@
}

if (-not $Print -and -not $Write) { Show-Help; exit 0 }
if ($Print -and $Write) {
    Write-Host "ERROR: -Print and -Write are mutually exclusive - use only one." -ForegroundColor Red
    Show-Help
    exit 1
}

# 1) New key (OpenAI format: "sk-" prefix + unpadded base64url, 46 chars)
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$entropy = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
$newKey = 'sk-' + $entropy

# 2) -Print: key to the console only, no config changes, no network test
if ($Print) {
    Write-Host $newKey
    Write-Host "Add to Proxy:Keys:LocalKeys on the server - gets /v1/* but NOT /admin/*."
    exit 0
}

# 3) -Write: rotate the PRIMARY local key (current behaviour, unchanged)
$deploy     = $DeployDir
# configs live in deploy\config (new layout); fall back to the legacy flat deploy root
$configFile = Join-Path (Join-Path $deploy 'config') 'appsettings.Server.json'
if (-not (Test-Path $configFile)) { $configFile = Join-Path $deploy 'appsettings.Server.json' }
$keyFile    = Join-Path $deploy 'LOCAL_KEY.txt'

if (-not (Test-Path $configFile)) {
    Write-Host "ERROR: could not find $configFile" -ForegroundColor Red
    exit 1
}

# Backup of the current config
Copy-Item $configFile "$configFile.bak" -Force

# Write the local key into the config (preserves UpstreamKey and all other fields)
$json = Get-Content $configFile -Raw | ConvertFrom-Json
$json.Proxy.Keys.LocalKey = $newKey
$json | ConvertTo-Json -Depth 10 | Set-Content $configFile -Encoding UTF8

# Key ready for the client to copy, without errors
$newKey | Set-Content $keyFile

# Confirmation (without exposing the key)
$hash = [BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::Create().ComputeHash(
        [Text.Encoding]::UTF8.GetBytes($newKey))).Replace('-','')
Write-Host "New key written to:  $configFile"
Write-Host ("Length = {0}  (expected 46, sk- format)" -f $newKey.Length)
Write-Host "Hash    = $hash"
Write-Host "For the client (copy): $keyFile"

# Immediate test (reloadOnChange activates the key without a restart)
$code = curl.exe --ssl-no-revoke -s -o NUL -w "%{http_code}" -H "Authorization: Bearer $newKey" https://localhost:4000/v1/models
Write-Host "Test with the new key -> HTTP $code"
if ($code -ne '200') {
    Write-Host "If it returns 401, restart the service (elevated):  Restart-Service AIRouterProxy" -ForegroundColor Yellow
}
