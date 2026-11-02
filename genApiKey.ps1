# genApiKey.ps1 - generates a new local key AND writes it to the AIRouterProxy config
# Usage: powershell -ExecutionPolicy Bypass -File .\genApiKey.ps1
#        powershell -ExecutionPolicy Bypass -File .\genApiKey.ps1 -DeployDir "C:\Path\To\deploy"
param(
    [string]$DeployDir = (Join-Path $PSScriptRoot 'deploy')
)

$ErrorActionPreference = 'Stop'

$deploy     = $DeployDir
$configFile = Join-Path $deploy 'appsettings.Server.json'
$keyFile    = Join-Path $deploy 'LOCAL_KEY.txt'

if (-not (Test-Path $configFile)) {
    Write-Host "ERROR: could not find $configFile" -ForegroundColor Red
    exit 1
}

# 1) New key (OpenAI format: "sk-" prefix + unpadded base64url, 46 chars)
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$entropy = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
$newKey = 'sk-' + $entropy

# 2) Backup of the current config
Copy-Item $configFile "$configFile.bak" -Force

# 3) Write the local key into the config (preserves UpstreamKey and all other fields)
$json = Get-Content $configFile -Raw | ConvertFrom-Json
$json.Proxy.Keys.LocalKey = $newKey
$json | ConvertTo-Json -Depth 10 | Set-Content $configFile -Encoding UTF8

# 4) Key ready for the client to copy, without errors
$newKey | Set-Content $keyFile

# 5) Confirmation (without exposing the key)
$hash = [BitConverter]::ToString(
    [System.Security.Cryptography.SHA256]::Create().ComputeHash(
        [Text.Encoding]::UTF8.GetBytes($newKey))).Replace('-','')
Write-Host "New key written to:  $configFile"
Write-Host ("Length = {0}  (expected 46, sk- format)" -f $newKey.Length)
Write-Host "Hash    = $hash"
Write-Host "For the client (copy): $keyFile"

# 6) Immediate test (reloadOnChange activates the key without a restart)
$code = curl.exe --ssl-no-revoke -s -o NUL -w "%{http_code}" -H "Authorization: Bearer $newKey" https://localhost:4000/v1/models
Write-Host "Test with the new key -> HTTP $code"
if ($code -ne '200') {
    Write-Host "If it returns 401, restart the service (elevated):  Restart-Service AIRouterProxy" -ForegroundColor Yellow
}
