# ======================================================================
# proxy-menu.ps1 - AIRouterProxy interactive tools (human-friendly frontend)
#
# THE single entry point for day-to-day operations. It DELEGATES to the
# existing engine scripts - it never re-implements them and never reads
# sensitive files (appsettings.Server.json, *.pem, LOCAL_KEY.txt, ...).
#
#   scripts\deploy-update.ps1  -> deploy engine (preserves secrets/certs)
#   scripts\genApiKey.ps1      -> key generation/rotation engine
#
# Usage:
#   .\scripts\proxy-menu.ps1                             # interactive menu
#   .\scripts\proxy-menu.ps1 -DeployDir "..."            # override destination
#   .\scripts\proxy-menu.ps1 -ServiceName "Name"         # service name override (sandbox)
#   .\scripts\proxy-menu.ps1 -Action Deploy              # (internal) elevated child
#
# Options that write to the service (1, 3, 8) self-elevate: a UAC prompt
# opens a second (elevated) window where the deploy/rotation runs and
# shows its own result summary. Confirmations for dangerous actions run
# inside that elevated window, next to the write itself.
# ======================================================================

[CmdletBinding()]
param(
    [string]$DeployDir = 'C:\Services\AiRouterProxy',
    [string]$ServiceName = 'AIRouterProxy',
    [ValidateSet('BuildDeploy','Build','Deploy','RotateKey','EventLog','Verify')]
    [string]$Action = '',
    [switch]$NonInteractive,
    [switch]$NoClear
)

$ErrorActionPreference = 'Continue'

$script:ScriptDir   = $PSScriptRoot
if ([string]::IsNullOrEmpty($script:ScriptDir)) { $script:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$script:RepoRoot    = Split-Path -Parent $script:ScriptDir
$script:PublishDir  = Join-Path $script:RepoRoot 'publish-tmp'
$script:ProjectFile = Join-Path $script:RepoRoot 'src\AiRouterProxy\AIRouterProxy.csproj'
$script:ServiceName = $ServiceName
$script:Port        = 4000
$script:DeployDir   = $DeployDir
$script:CfgDir      = Join-Path $DeployDir 'config'

# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

function Write-Ok   { Write-Host "  ✓  $($args[0])" -ForegroundColor Green }
function Write-Info { Write-Host "►  $($args[0])" -ForegroundColor Cyan }
function Write-Warn { Write-Host "  ⚠  $($args[0])" -ForegroundColor Yellow }
function Write-Err  { Write-Host "  ✗  $($args[0])" -ForegroundColor Red }

function Wait-Key {
    Write-Host -NoNewline "  Press Enter to return to the menu: " -ForegroundColor Gray
    $null = Read-Host
}

function Wait-Close {
    Write-Host -NoNewline "  Press Enter to close this window: " -ForegroundColor Gray
    $null = Read-Host
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# TCP connect test - works in both elevated and non-elevated contexts
# (Get-NetTCPConnection -State Listen silently returns nothing without admin).
function Test-PortOpen {
    param([int]$TimeoutMs = 1500)
    $client = New-Object Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect('localhost', $script:Port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            $client.EndConnect($iar)
            return $true
        }
        return $false
    } catch { return $false }
    finally { $client.Close() }
}

function Wait-PortListening {
    param([int]$TimeoutSeconds = 30)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        if (Test-PortOpen) { return $true }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Get-HealthCode {
    try {
        $code = & curl.exe --ssl-no-revoke -s -o NUL -w "%{http_code}" "https://localhost:$($script:Port)/admin/health" 2>$null
        if ("$code" -eq '000') { return '' }   # connection refused -> treat as unreachable
        return "$code"
    } catch { return '' }
}

function Invoke-Elevated {
    param([Parameter(Mandatory = $true)][string]$ActionName)

    # already elevated -> run the action right here
    if (Test-IsAdmin) {
        switch ($ActionName) {
            'Deploy'   { Invoke-Deploy }
            'EventLog' { Invoke-EventLog }
        }
        return $true
    }

    Write-Host ""
    Write-Info "Requesting elevation (UAC) - please confirm the prompt..."
    $items  = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-Action', $ActionName, '-DeployDir', $script:DeployDir, '-ServiceName', $script:ServiceName)
    $argStr = ($items | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argStr -Wait | Out-Null
        return $true
    } catch {
        if ($_.Exception.Message -match 'canceled|was cancelled|was canceled') { Write-Warn "Elevation cancelled by the user." }
        else { Write-Err "Elevation failed: $($_.Exception.Message)" }
        return $false
    }
}

# ---------------------------------------------------------------------------
# actions
# ---------------------------------------------------------------------------

function Invoke-Preflight {
    Write-Host ""
    Write-Info "Pre-flight checks..."
    $ok = $true

    if (-not (Get-Command dotnet -EA SilentlyContinue)) { Write-Err "dotnet SDK not found (needed for publish)."; $ok = $false }
    if (-not (Test-Path $script:ProjectFile))            { Write-Err "Project file not found: $($script:ProjectFile)"; $ok = $false }

    $svc = Get-Service $script:ServiceName -EA SilentlyContinue
    if ($svc) { Write-Ok "Service $($script:ServiceName): $($svc.Status)" } else { Write-Warn "Service not installed - this is a FIRST INSTALL (deploy will register it)." }

    $cert = Join-Path $script:CfgDir 'proxy-cert.pem'
    $key  = Join-Path $script:CfgDir 'proxy-key.pem'
    $srv  = Join-Path $script:CfgDir 'appsettings.Server.json'
    if (Test-Path $cert) { Write-Ok "Cert present (proxy-cert.pem)" } else { Write-Warn "proxy-cert.pem missing at destination (first install? see option 7)." }
    if (Test-Path $key)  { Write-Ok "Cert present (proxy-key.pem)" } else { Write-Warn "proxy-key.pem missing at destination (first install? see option 7)." }
    if (Test-Path $srv)  { Write-Ok "appsettings.Server.json present" } else { Write-Warn "appsettings.Server.json missing - no server config at destination to preserve." }
    Write-Host ""
    return $ok
}

function Invoke-Build {
    Write-Host ""
    Write-Info "Build (self-contained win-x64)..."
    if (-not (Get-Command dotnet -EA SilentlyContinue)) { Write-Err "dotnet SDK not found. Install it first."; return $false }
    if (-not (Test-Path $script:ProjectFile))           { Write-Err "Project file not found: $($script:ProjectFile)"; return $false }

    Push-Location $script:RepoRoot
    try {
        & dotnet publish $script:ProjectFile -c Release -r win-x64 --self-contained true -o $script:PublishDir
    } finally { Pop-Location }

    if ($LASTEXITCODE -ne 0) { Write-Err "Publish failed (dotnet exit $LASTEXITCODE)."; return $false }

    $exe = Join-Path $script:PublishDir 'AIRouterProxy.exe'
    if (Test-Path $exe) {
        $v = (Get-Item $exe).VersionInfo.FileVersion
        Write-Ok "Publish done: AIRouterProxy.exe (version $v)"
        return $true
    }
    Write-Warn "Publish finished but AIRouterProxy.exe not found in publish-tmp."
    return $false
}

function Ensure-ProxyService {
    # FIRST INSTALL support: register + auto-start the Windows service when it
    # does not exist yet. On normal updates the service is present and this is a no-op.
    $svc = Get-Service $script:ServiceName -EA SilentlyContinue
    if ($svc) { return $true }

    $exe = Join-Path $script:DeployDir 'AIRouterProxy.exe'
    if (-not (Test-Path $exe)) {
        Write-Err "AIRouterProxy.exe not found at '$exe' - cannot install the service."
        return $false
    }

    Write-Host ""
    Write-Info "Service '$($script:ServiceName)' not registered - installing (first install)..."
    try {
        New-Service -Name $script:ServiceName -BinaryPathName $exe -StartupType Automatic -EA Stop | Out-Null
        Start-Sleep -Milliseconds 800
    } catch {
        Write-Err "Could not create service '$($script:ServiceName)': $($_.Exception.Message)"
        return $false
    }

    $created = Get-Service $script:ServiceName -EA SilentlyContinue
    if (-not $created) {
        Write-Err "Service '$($script:ServiceName)' not found after creation - investigate."
        return $false
    }
    Write-Ok "Service '$($script:ServiceName)' registered (auto-start, LocalSystem)."
    return $true
}

function Test-FirstInstallWarning {
    # Runs BEFORE the deploy in the non-elevated menu: a destination without
    # appsettings.Server.json is a FIRST INSTALL - warn so it is a conscious choice.
    $srv = Join-Path $script:CfgDir 'appsettings.Server.json'
    if (Test-Path $srv) { return $true }
    Write-Host ""
    Write-Warn "Destination has NO appsettings.Server.json - this is a FIRST INSTALL."
    Write-Host "  The service will be registered but will NOT serve until you add" -ForegroundColor Yellow
    Write-Host "  appsettings.Server.json + certs to $($script:CfgDir) (see option 7)." -ForegroundColor Yellow
    Write-Host ""
    $ans = Read-Host "  Continue anyway? [y/N]"
    if ($ans -notmatch '^[yY]') { Write-Info "Aborted."; return $false }
    return $true
}

function Get-SmartAppControlState {
    # Returns: 0 = Off, 1 = On (enforced), 2 = Evaluation, $null = unknown.
    $v = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name VerifiedAndReputablePolicyState -EA SilentlyContinue
    if ($null -eq $v -or $null -eq $v.VerifiedAndReputablePolicyState) { return $null }
    return [int]$v.VerifiedAndReputablePolicyState
}

function Test-SmartAppControl {
    # Smart App Control (SAC), when ON, blocks unsigned builds (like the locally-built
    # AIRouterProxy.exe) at the OS level. Warn before a deploy so it is a conscious choice.
    if ((Get-SmartAppControlState) -ne 1) { return $true }
    Write-Host ""
    Write-Warn "Smart App Control (SAC) is ON - Windows will BLOCK unsigned builds like AIRouterProxy.exe."
    Write-Host "  Fix: Windows Security > App & browser control > Smart App Control > select OFF." -ForegroundColor Yellow
    Write-Host "  (Defender AV stays active; SAC can be turned back on later.)" -ForegroundColor Yellow
    Write-Host ""
    $ans = Read-Host "  Continue anyway? [y/N]"
    if ($ans -notmatch '^[yY]') { Write-Info "Aborted."; return $false }
    return $true
}

function Invoke-Deploy {
    # Deployed inside the elevated window (child process, -Action Deploy).
    $engine = Join-Path $script:ScriptDir 'deploy-update.ps1'
    if (-not (Test-Path $engine)) { Write-Err "deploy-update.ps1 not found next to proxy-menu.ps1"; exit 1 }
    if (-not (Test-Path (Join-Path $script:PublishDir 'AIRouterProxy.exe'))) {
        Write-Err "No build output in publish-tmp. Build first (menu option 1/2)."
        exit 1
    }

    Write-Host ""
    Write-Info "Running deploy-update.ps1 -> $($script:DeployDir)"
    & $engine -DeployDir $script:DeployDir -ServiceName $script:ServiceName

    # FIRST INSTALL: deploy-update.ps1 only does a file copy when the service is
    # missing - register + start the Windows service here.
    $null = Ensure-ProxyService
    $svc = Get-Service $script:ServiceName -EA SilentlyContinue
    if ($svc -and $svc.Status -ne 'Running') {
        Write-Info "Starting service '$($script:ServiceName)'..."
        Start-Service $script:ServiceName -EA SilentlyContinue
        Start-Sleep -Seconds 2
    }

    Write-Host ""
    Write-Info "Waiting for port $($script:Port) (up to 30 s)..."
    if (Wait-PortListening -TimeoutSeconds 30) {
        Write-Ok "Port $($script:Port) listening."
    } else {
        Write-Warn "Port $($script:Port) did not come up - trying Restart-Service $($script:ServiceName)..."
        $svc = Get-Service $script:ServiceName -EA SilentlyContinue
        if ($svc) {
            if ($svc.Status -eq 'Running') { Restart-Service $script:ServiceName -Force -EA SilentlyContinue }
            else                           { Start-Service $script:ServiceName -EA SilentlyContinue }
            Start-Sleep -Seconds 2
        }
        if (Wait-PortListening -TimeoutSeconds 30) { Write-Ok "Port $($script:Port) listening after restart." }
        else { Write-Err "Port $($script:Port) still not listening. Check the Event Log (menu 6)." }
    }

    Show-DeploySummary
}

function Show-DeploySummary {
    Write-Host ""
    Write-Host "  ------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host "  ✓  DEPLOY COMPLETED" -ForegroundColor Green

    $exe = Join-Path $script:DeployDir 'AIRouterProxy.exe'
    if (Test-Path $exe) { Write-Host "    Installed version : $((Get-Item $exe).VersionInfo.FileVersion)" -ForegroundColor White }

    $svc = Get-Service $script:ServiceName -EA SilentlyContinue
    if ($svc) { Write-Host "    Service          : $($svc.Status)" -ForegroundColor White }

    if (Test-PortOpen) {
        Write-Host "    Port $($script:Port)       : listening" -ForegroundColor White
    } else {
        Write-Host "    Port $($script:Port)       : NOT listening" -ForegroundColor Yellow
    }

    $code = Get-HealthCode
    if ($code) {
        if ($code -eq '401') { Write-Host "    GET /admin/health: HTTP 401 (up - key required)" -ForegroundColor White }
        else                 { Write-Host "    GET /admin/health: HTTP $code" -ForegroundColor White }
    } else {
        Write-Host "    GET /admin/health: unreachable" -ForegroundColor Yellow
    }

    Write-Host "  Next: curl.exe --ssl-no-revoke https://localhost:4000/v1/models -H `"Authorization: Bearer <key>`"" -ForegroundColor Gray
    Write-Host "  Note: if you changed redaction.json on the service, sync" -ForegroundColor Gray
    Write-Host "        C:\Services\ProxyConfigsBank manually." -ForegroundColor Gray

    Show-FirstInstallNote

    Write-Host "  ------------------------------------------------" -ForegroundColor DarkCyan
}

function Show-FirstInstallNote {
    # A fresh destination has no secrets - the service is registered but not yet serving.
    $srv = Join-Path $script:CfgDir 'appsettings.Server.json'
    if (Test-Path $srv) { return }
    Write-Host ""
    Write-Host "  ⚠  FIRST INSTALL - service registered, but NOT serving yet:" -ForegroundColor Yellow
    Write-Host "      add appsettings.Server.json + proxy-cert.pem/proxy-key.pem to" -ForegroundColor Yellow
    Write-Host "      $($script:CfgDir)  (see menu option 7), then restart the service." -ForegroundColor Yellow
}

function Invoke-BuildDeploy {
    if (-not (Invoke-Preflight)) { Write-Err "Pre-flight failed - fix the problems above."; return }
    if (-not (Invoke-Build))      { Write-Err "Build failed - deploy aborted."; return }

    $go = Read-Host "  Build OK. Proceed with the deploy? [y/N]"
    if ($go -notmatch '^[yY]') { Write-Info "Deploy skipped."; return }
    if (-not (Test-FirstInstallWarning)) { return }
    if (-not (Test-SmartAppControl)) { return }
    $null = Invoke-Elevated 'Deploy'
}

function Invoke-DeployOnly {
    Write-Host ""
    if (-not (Test-Path (Join-Path $script:PublishDir 'AIRouterProxy.exe'))) {
        Write-Warn "No build output in publish-tmp yet."
        $go = Read-Host "  Build first? [y/N]"
        if ($go -match '^[yY]') {
            if (-not (Invoke-Build)) { return }
        } else {
            Write-Info "Aborted."
            return
        }
    }
    if (-not (Test-FirstInstallWarning)) { return }
    if (-not (Test-SmartAppControl)) { return }
    $null = Invoke-Elevated 'Deploy'
}

function Invoke-Verify {
    Write-Host ""
    Write-Info "Verifying service at $($script:DeployDir)..."

    $svc = Get-Service $script:ServiceName -EA SilentlyContinue
    if ($svc) { Write-Ok "Service $($script:ServiceName): $($svc.Status)" } else { Write-Warn "Service not installed - run menu option 1/3 to install it." }

    $exe = Join-Path $script:DeployDir 'AIRouterProxy.exe'
    if (Test-Path $exe) { Write-Ok "Installed: AIRouterProxy.exe (version $((Get-Item $exe).VersionInfo.FileVersion))" }
    else                { Write-Warn "Deployed exe not found: $exe" }

    if (Test-PortOpen) { Write-Ok "Port $($script:Port): listening" }
    else { Write-Warn "Port $($script:Port): not listening" }

    $code = Get-HealthCode
    if ($code) {
        if ($code -eq '401') { Write-Ok "GET /admin/health -> HTTP 401 (service up; auth required)" }
        elseif ($code -eq '200') { Write-Ok "GET /admin/health -> HTTP 200" }
        else { Write-Warn "GET /admin/health -> HTTP $code" }
    } else {
        Write-Warn "Could not reach https://localhost:$($script:Port)/admin/health"
    }

    if ((Get-SmartAppControlState) -eq 1) {
        Write-Warn "Smart App Control (SAC) is ON - unsigned builds like AIRouterProxy.exe may be blocked at startup."
        Write-Host "    Fix: Windows Security > App & browser control > Smart App Control > select OFF." -ForegroundColor Yellow
    }
    Write-Host ""
}

function Invoke-EngineerKey {
    Write-Host ""
    Write-Info "Generating engineer key (prints only - writes nothing)..."
    & (Join-Path $script:ScriptDir 'genApiKey.ps1') -Print
    Write-Host ""
    Write-Host "  Add it to Proxy:Keys:LocalKeys on the server. Gives /v1/*" -ForegroundColor Gray
    Write-Host "  access but NOT /admin/*." -ForegroundColor Gray
    Write-Host ""
}

function Invoke-EventLog {
    Write-Host ""
    Write-Info "Reading '$($script:ServiceName)' events..."

    $events = $null
    try { $events = Get-WinEvent -LogName $script:ServiceName -MaxEvents 10 -EA Stop }
    catch {
        try { $events = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = $script:ServiceName } -MaxEvents 10 -EA Stop }
        catch { $events = $null }
    }

    if (-not $events) {
        if (Test-IsAdmin) {
            Write-Warn "No recent events found for '$($script:ServiceName)' (or the log does not exist yet)."
        } else {
            Write-Warn "Could not read the event log - it may need elevation."
            $yes = Read-Host "  Open the Event Log elevated? [y/N]"
            if ($yes -match '^[yY]') { $null = Invoke-Elevated 'EventLog' } else { Write-Info "Skipped." }
        }
        return
    }

    $i = 0
    foreach ($e in $events) {
        $i++
        $first = ($e.Message -split "`r?`n")[0]
        if ($first.Length -gt 110) { $first = $first.Substring(0, 110) + '...' }
        $color = if ($e.LevelDisplayName -match 'Erro|Error|Crit') { 'Red' }
                 elseif ($e.LevelDisplayName -match 'Aviso|Warning') { 'Yellow' }
                 else { 'Gray' }
        Write-Host ("  {0,2}  {1,-10}  {2}  {3}" -f $i, $e.LevelDisplayName, $e.TimeCreated.ToString('dd/MM HH:mm:ss'), $first) -ForegroundColor $color
    }
    Write-Host "  (hashes are truncated - the full key is never shown.)" -ForegroundColor DarkGray
    Write-Host ""
}

function Show-CertDocs {
    Write-Host ""
    Write-Info "Certificates (first install only - deploys preserve these files):"
    Write-Host ""
    Write-Host "    winget install FiloSottile.mkcert" -ForegroundColor White
    Write-Host "    mkcert -install                              # creates the root CA" -ForegroundColor White
    Write-Host "    cd C:\Services\AiRouterProxy\config" -ForegroundColor White
    Write-Host "    mkcert -key-file proxy-key.pem -cert-file proxy-cert.pem localhost winzone 192.168.1.77" -ForegroundColor White
    Write-Host ""
    Write-Host "  No need to regenerate on routine updates." -ForegroundColor Gray
    Write-Host ""
}

function Invoke-RotateKey {
    if (-not (Test-IsAdmin)) {
        Write-Host ""
        Write-Warn "Primary-key rotation writes to $($script:CfgDir)\appsettings.Server.json"
        Write-Host "  and needs admin rights. The confirmations will run in the elevated window."
        $null = Invoke-Elevated 'RotateKey'
        return
    }

    Write-Host ""
    Write-Host "  ⚠  DANGER - Rotating the PRIMARY KEY" -ForegroundColor Red
    Write-Host "  ├─  The current key will stop working on ALL clients (OpenCode, etc.)" -ForegroundColor Yellow
    Write-Host "  ├─  Only keys in Proxy:Keys:LocalKeys will keep working" -ForegroundColor Yellow
    Write-Host "  └─  Automatic backup: appsettings.Server.json.bak" -ForegroundColor Yellow
    Write-Host ""
    $ans = Read-Host "  Are you sure you want to continue? [y/N]"
    if ($ans -notmatch '^[yY]') { Write-Info "Cancelled."; return }
    $confirm = Read-Host "  Type ROTATE to confirm"
    if ($confirm -ne 'ROTATE')  { Write-Info "Cancelled."; return }

    Write-Host ""
    & (Join-Path $script:ScriptDir 'genApiKey.ps1') -Write -DeployDir $script:DeployDir
    Write-Host ""
    Write-Host "  Update your clients with the new key from LOCAL_KEY.txt." -ForegroundColor Yellow
    Write-Host ""
}

# ---------------------------------------------------------------------------
# menu
# ---------------------------------------------------------------------------

function Show-Menu {
    if (-not $NoClear) { Clear-Host }
    Write-Host "================================================================" -ForegroundColor DarkCyan
    Write-Host "  AIRouterProxy - Tools" -ForegroundColor Cyan
    Write-Host "  Repo  : $($script:RepoRoot)" -ForegroundColor Gray
    Write-Host "  Deploy: $($script:DeployDir)" -ForegroundColor Gray
    Write-Host "  Service: $($script:ServiceName)" -ForegroundColor Gray
    Write-Host "================================================================" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  1) Build + Deploy + Verify   (full pipeline, end-to-end)" -ForegroundColor White
    Write-Host "  2) Build only                (dotnet publish -> publish-tmp)" -ForegroundColor White
    Write-Host "  3) Deploy only               (from an existing publish-tmp)" -ForegroundColor White
    Write-Host "  4) Verify service            (port 4000 + version + status)" -ForegroundColor White
    Write-Host "  5) Generate engineer key     (prints a new key, writes nothing)" -ForegroundColor White
    Write-Host "  6) View Event Log            (latest $($script:ServiceName) events)" -ForegroundColor White
    Write-Host "  7) Certificate docs          (show mkcert setup commands)" -ForegroundColor White
    Write-Host "  8) ⚠  ROTATE PRIMARY KEY     (LocalKey - edits appsettings.Server.json)" -ForegroundColor White
    Write-Host "  0) Exit" -ForegroundColor White
    Write-Host ""
    Write-Host "  Options 1/3/8 self-elevate (UAC) and run in a second window." -ForegroundColor DarkGray
    Write-Host -NoNewline "  Pick an option [0-8]: " -ForegroundColor Cyan
}

function Invoke-Menu {
    while ($true) {
        Show-Menu
        $choice = Read-Host
        switch ($choice) {
            '0' { Write-Host ""; Write-Host "  Bye! :)" -ForegroundColor Cyan; return }
            '1' { Invoke-BuildDeploy; Wait-Key }
            '2' { if (-not (Invoke-Build)) { Write-Host "" }; Wait-Key }
            '3' { Invoke-DeployOnly; Wait-Key }
            '4' { Invoke-Verify; Wait-Key }
            '5' { Invoke-EngineerKey; Wait-Key }
            '6' { Invoke-EventLog; Wait-Key }
            '7' { Show-CertDocs; Wait-Key }
            '8' { Invoke-RotateKey; Wait-Key }
            default { Write-Warn "Invalid option: '$choice'. Use 0-8."; Start-Sleep -Milliseconds 800 }
        }
    }
}

# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------

if ($Action) {
    switch ($Action) {
        'BuildDeploy' { Invoke-BuildDeploy }
        'Build'       { $null = Invoke-Build }
        'Deploy'      { Invoke-Deploy }
        'RotateKey'   { Invoke-RotateKey }
        'EventLog'    { Invoke-EventLog }
        'Verify'      { Invoke-Verify }
    }
    if (-not $NonInteractive) { Write-Host ""; Wait-Close }
    exit 0
}

Invoke-Menu
