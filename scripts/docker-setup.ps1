<#
.SYNOPSIS
    Zero-step Docker setup for AIRouterProxy (Windows).

.DESCRIPTION
    Creates config/ and data/, copies the non-secret config templates (never
    overwriting existing files) and runs `docker compose up -d --build`.

    Keys and the host port are exported ONLY when you pass them as parameters.
    Otherwise docker-compose.yml applies its own ${VAR:-default} (dummy keys, port
    4000) and an existing environment variable or `.env` keeps precedence - the
    script never overwrites a value that is already defined.

    The container generates a self-signed TLS certificate on first start and seeds
    config/ from the image defaults, so no manual step is required. Replace the
    dummy keys with real ones for actual upstream calls.

    When mkcert is installed and config/ has no certificate yet, the script generates
    a trusted one (mkcert -install + proxy-cert.pem/proxy-key.pem) BEFORE the up.
    Existing certificates are never overwritten. Node/OpenCode ignore the Windows
    store, so the summary also prints the NODE_EXTRA_CA_CERTS command to run before
    opening OpenCode.

.PARAMETER UpstreamKey
    Upstream (AI Router) API key exported as AIROUTER_API_KEY. Omit to keep the
    existing environment/.env value or let the compose default (dummy) apply.

.PARAMETER LocalKey
    Local key used by clients / dashboard login, exported as LOCAL_PROXY_KEY.
    Omit to keep the existing environment/.env value or the compose default (dummy).

.PARAMETER HostPort
    Host port published on 127.0.0.1 (container port stays 4000). Omit to keep the
    existing environment/.env value or the compose default (4000).

.PARAMETER SkipUp
    Only prepare folders/config/env; do not run `docker compose up`.

.EXAMPLE
    .\scripts\docker-setup.ps1

.EXAMPLE
    .\scripts\docker-setup.ps1 -UpstreamKey 'sk-real-upstream' -LocalKey 'sk-local' -HostPort 5000

.NOTES
    Usage: powershell -ExecutionPolicy Bypass -File .\scripts\docker-setup.ps1 [-UpstreamKey <k>]
           [-LocalKey <k>] [-HostPort <n>] [-SkipUp]
#>
param(
    [string]$UpstreamKey,
    [string]$LocalKey,
    [int]$HostPort,
    [switch]$SkipUp,
    [Alias('?')]
    [switch]$Help
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Show-Help {
@"
docker-setup.ps1 - zero-step Docker setup for AIRouterProxy (Windows)

USAGE:
  powershell -ExecutionPolicy Bypass -File .\scripts\docker-setup.ps1 [options]

OPTIONS:
  -UpstreamKey <key>   Upstream (AI Router) key -> AIROUTER_API_KEY  (default: unset)
  -LocalKey <key>      Local client/dashboard key -> LOCAL_PROXY_KEY (default: unset)
  -HostPort <port>     Host port on 127.0.0.1                       (default: unset)
  -SkipUp              Prepare folders/config/env only (no docker compose up)
  -Help, -?            Show this help

WHAT IT DOES:
  1. Creates config/ and data/.
  2. Copies appsettings.json, routes.json, redaction.json into config/ (only when missing).
  3. If mkcert is installed and config/ has no cert yet, runs `mkcert -install` and
     generates config/proxy-cert.pem + config/proxy-key.pem (existing certs kept).
  4. Exports AIROUTER_API_KEY / LOCAL_PROXY_KEY / HOST_PORT - only the ones you pass.
  5. Runs `docker compose up -d --build` (unless -SkipUp).

Keys/port you do NOT pass are left to docker-compose.yml, which applies
`${VAR:-default} (dummy keys, port 4000). An existing environment variable or a
`.env` file keeps precedence and is never overwritten by this script.

Without mkcert the container generates a self-signed certificate on first start and
the browser warns. Node/OpenCode do not use the Windows store: with mkcert, the
summary prints the NODE_EXTRA_CA_CERTS command to run before opening OpenCode.
"@
}

# Effective published host port, as Compose resolves it (environment, .env, override).
# Returns $null when Compose cannot be queried (docker missing or config error).
function Get-EffectiveHostPort {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { return $null }
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $config = & docker compose config 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $config) { return $null }
        $match = [regex]::Match(($config -join "`n"), 'published:\s*"?(\d+)"?')
        if (-not $match.Success) { return $null }
        return [int]$match.Groups[1].Value
    }
    catch {
        return $null
    }
    finally {
        $ErrorActionPreference = $previous
    }
}

if ($Help) { Show-Help; exit 0 }

$repoRoot = Split-Path $PSScriptRoot -Parent
$configDir = Join-Path $repoRoot 'config'
$dataDir = Join-Path $repoRoot 'data'

Push-Location $repoRoot
try {
    # 1. Folders (config is editable; data is created by the proxy too)
    New-Item -ItemType Directory -Force -Path $configDir, $dataDir | Out-Null
    Write-Host "Folders ready: $configDir, $dataDir"

    # 2. Non-secret config templates - never overwrite an existing (edited) file
    $configFiles = @('appsettings.json', 'routes.json', 'redaction.json')
    foreach ($name in $configFiles) {
        $source = Join-Path $repoRoot "src/AiRouterProxy/Config/$name"
        $target = Join-Path $configDir $name
        if (Test-Path $target) {
            Write-Host "Kept existing config/$name"
        }
        else {
            Copy-Item -Path $source -Destination $target
            Write-Host "Copied config/$name"
        }
    }

    # 3. Trusted local TLS certificate - only when mkcert exists AND config/ has no cert.
    #    An existing cert (yours, another machine's, or one the entrypoint generated) is
    #    always kept: never overwrite the user's certificate/key pair.
    $mkcertCmd = Get-Command mkcert -ErrorAction SilentlyContinue
    $certPath = Join-Path $configDir 'proxy-cert.pem'
    $keyPath = Join-Path $configDir 'proxy-key.pem'
    $hasCert = (Test-Path $certPath) -and (Test-Path $keyPath)
    $certAction = 'none'
    if ($mkcertCmd -and -not $hasCert) {
        Write-Host 'Generating a trusted local certificate with mkcert...'
        & mkcert -install
        if ($LASTEXITCODE -ne 0) { throw "mkcert -install failed (exit code $LASTEXITCODE)." }
        & mkcert -cert-file $certPath -key-file $keyPath localhost 127.0.0.1 '::1'
        if ($LASTEXITCODE -ne 0) { throw "mkcert failed to generate the certificate (exit code $LASTEXITCODE)." }
        $certAction = 'generated'
        Write-Host 'trusted local cert generated with mkcert'
    }
    elseif ($hasCert) {
        $certAction = 'kept'
        Write-Host 'Kept existing config/proxy-cert.pem + config/proxy-key.pem'
    }

    # 4. Keys + host port for Compose interpolation. Only explicitly passed values are
    #    exported: docker-compose.yml already applies ${VAR:-default} (dummy keys, port
    #    4000) and an existing env var or .env keeps precedence (never overwritten).
    if ($PSBoundParameters.ContainsKey('UpstreamKey')) {
        $env:AIROUTER_API_KEY = $UpstreamKey
        Write-Host 'Exported AIROUTER_API_KEY (from -UpstreamKey)'
    }
    if ($PSBoundParameters.ContainsKey('LocalKey')) {
        $env:LOCAL_PROXY_KEY = $LocalKey
        Write-Host 'Exported LOCAL_PROXY_KEY (from -LocalKey)'
    }
    if ($PSBoundParameters.ContainsKey('HostPort')) {
        $env:HOST_PORT = "$HostPort"
        Write-Host "Exported HOST_PORT=$HostPort (from -HostPort)"
    }

    # 5. Build + start (the entrypoint seeds config, creates the cert and fixes the volumes)
    if (-not $SkipUp) {
        Write-Host 'Running: docker compose up -d --build'
        & docker compose up -d --build
        if ($LASTEXITCODE -ne 0) { throw "docker compose up failed (exit code $LASTEXITCODE)." }
    }
    else {
        Write-Host 'Skipping docker compose up (-SkipUp).'
    }

    # 6. Summary - show the port Compose actually resolved, not just our default
    $effectivePort = Get-EffectiveHostPort
    $portIsResolved = $null -ne $effectivePort
    if (-not $portIsResolved) {
        $effectivePort = if ($env:HOST_PORT) { $env:HOST_PORT } else { '4000' }
    }

    Write-Host ''
    Write-Host '------------------------------------------------------------'
    Write-Host ' AIRouterProxy (Docker)'
    Write-Host '------------------------------------------------------------'
    Write-Host " Proxy:     https://localhost:$effectivePort"
    Write-Host " Dashboard: https://localhost:$effectivePort/admin/ui"
    if (-not $portIsResolved) {
        Write-Host ' Port:  HOST_PORT/4000 assumed - a docker-compose.override.yml or .env'
        Write-Host '        can still publish a different port.'
    }
    Write-Host ''
    if ($mkcertCmd) {
        if ($certAction -eq 'generated') {
            Write-Host ' Certificate: trusted local cert generated with mkcert (config/proxy-cert.pem,'
            Write-Host '              config/proxy-key.pem).'
        }
        else {
            Write-Host ' Certificate: config/proxy-cert.pem + config/proxy-key.pem (existing certs kept).'
        }
        Write-Host '              mkcert is installed; the Node hint below points at its local CA.'
        Write-Host ''
        Write-Host ' OpenCode / Node: run this BEFORE opening OpenCode (Node does not use the Windows store):'
        Write-Host '  $env:NODE_EXTRA_CA_CERTS = "$(mkcert -CAROOT)\rootCA.pem"'
        Write-Host '  # then reopen your terminal (and OpenCode) - variables defined after start are not picked up'
    }
    elseif (-not $hasCert) {
        Write-Host ' Certificate: mkcert not found - the entrypoint will generate a SELF-SIGNED cert'
        Write-Host '              on first start. The browser warns and OpenCode/Node REJECTS it'
        Write-Host '              (DEPTH_ZERO_SELF_SIGNED_CERT). Two options:'
        Write-Host '              a) install mkcert (https://github.com/FiloSottile/mkcert) and re-run'
        Write-Host '                 this script - it generates a trusted cert and prints the Node hint;'
        Write-Host '              b) for a quick test ONLY, disable TLS verification in the OpenCode'
        Write-Host '                 process (never for normal use):'
        Write-Host "                   `$env:NODE_TLS_REJECT_UNAUTHORIZED='0'"
    }
    else {
        Write-Host ' Certificate: using the existing config/proxy-cert.pem + config/proxy-key.pem.'
        Write-Host '              Install mkcert for a trusted CA and the NODE_EXTRA_CA_CERTS hint.'
    }
    if (-not $PSBoundParameters.ContainsKey('UpstreamKey') -and
        -not $PSBoundParameters.ContainsKey('LocalKey')) {
        Write-Host ''
        Write-Host ' Keys: this script exported none - docker-compose.yml falls back to dummy'
        Write-Host '       keys unless AIROUTER_API_KEY/LOCAL_PROXY_KEY already exist in the'
        Write-Host '       environment or .env. Dummy is fine for a smoke test, but upstream'
        Write-Host '       calls return 401; pass -UpstreamKey/-LocalKey for real keys.'
    }
    Write-Host ''
    Write-Host ' Logs:  docker compose logs -f'
    Write-Host ' Stop:  docker compose down'
    Write-Host '------------------------------------------------------------'
}
finally {
    Pop-Location
}
