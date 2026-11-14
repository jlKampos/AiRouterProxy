<#
.SYNOPSIS
  api-monitor - watches the upstream API changelogs/docs used by AiRouterProxy (Anthropic,
  OpenAI, OpenRouter), compares SHA-256 content hashes against the previous run (state.json)
  and opens an automatic GitHub issue (label api-monitor) when content changed AND the
  changes hit keywords relevant to the proxy. No auto-fix: the issue IS the alert.

.DESCRIPTION
  - Sources + keyword/area map: sources.json (same folder).
  - state.json (same folder) persists, per source, the last hash, the last normalized
    content (gzip+base64, so the old/new line diff for the issue snippet works), and the
    last issue metadata. On the GitHub runner the updated state is committed and pushed.
  - -BakeBaseline: fetch every source and record hashes + content snapshots. Opens NO
    issue, commits NOTHING. Used to seed state.json. Idempotent: a second run over an
    unchanged set re-bakes identical hashes.
  - -DryRun: simulate detection only - print what WOULD happen, write nothing, call gh
    nowhere.

.PARAMETER BakeBaseline
  Record the current state of every source without opening issues or touching git.

.PARAMETER DryRun
  Simulate: report UNCHANGED / CHANGED (would open issue / no relevant keywords). No writes.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\api-monitor\api-monitor.ps1 -BakeBaseline

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\api-monitor\api-monitor.ps1 -DryRun

.NOTES
  Exit codes:
    0 - completed; individual source failures are tolerated (no false "failed run" alerts)
    1 - every source failed (total failure - noticed and alerted)
    2 - usage or config error before any source was processed

  The updated state.json is committed and pushed ONLY when running on GitHub Actions
  (GITHUB_ACTIONS=true and GH_TOKEN set). Local runs never touch git.
#>
[CmdletBinding()]
param(
    [switch]$BakeBaseline,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
$SourcesPath = Join-Path $PSScriptRoot 'sources.json'
$StatePath   = Join-Path $PSScriptRoot 'state.json'
$UserAgent   = 'AiRouterProxy-api-monitor/1.0'
$AtomEntryMarker = '--- entry ---'

$script:results = New-Object System.Collections.Generic.List[string]
$script:failures = New-Object System.Collections.Generic.List[string]
$script:sources = @()
$script:orderedNames = @()
$script:watchMap = @{}
$script:state = $null

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Result {
    param([string]$Line)
    $script:results.Add($Line)
    Write-Output $Line
}

function Get-TextLines {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return ,@() }
    return @($Text -split '\r?\n')
}

function Get-NormalizedText {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $lines = Get-TextLines -Text $Text
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($l in $lines) {
        $out.Add($l.TrimEnd([char[]]@(' ', "`t")))
    }
    # drop trailing empty lines
    while ($out.Count -gt 0 -and $out[$out.Count - 1] -eq '') {
        $out.RemoveAt($out.Count - 1)
    }
    return ($out -join "`n")
}

function Get-AtomFlattened {
    # Atom -> plain text with only entry title + content (no feed-level <updated>,
    # so the feed timestamp cannot change the hash every day). Entries are delimited
    # by $AtomEntryMarker so the issue snippet can isolate the NEW entries.
    param([string]$XmlText)
    $doc = New-Object System.Xml.XmlDocument
    $doc.LoadXml($XmlText)
    $sb = New-Object System.Text.StringBuilder
    $entries = $doc.SelectNodes('//*[local-name()="entry"]')
    foreach ($e in $entries) {
        [void]$sb.AppendLine($AtomEntryMarker)
        $title = $e.SelectSingleNode('*[local-name()="title"]')
        $content = $e.SelectSingleNode('*[local-name()="content"]')
        if ($title) { [void]$sb.AppendLine($title.InnerText) }
        if ($content) {
            $c = [regex]::Replace([string]$content.InnerText, '<[^>]+>', ' ')
            $c = [regex]::Replace($c, '\s+', ' ').Trim()
            if ($c) { [void]$sb.AppendLine($c) }
        }
    }
    return $sb.ToString()
}

function Get-Sha256Hex {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $hashBytes = $sha.ComputeHash($bytes)
        $sb = New-Object System.Text.StringBuilder
        foreach ($b in $hashBytes) { [void]$sb.Append($b.ToString('x2')) }
        return $sb.ToString()
    }
    finally {
        $sha.Dispose()
    }
}

function Compress-Text {
    # gzip + base64. The gzip header is deterministic (mtime=0), but the DEFLATE
    # payload can compress byte-identically or not depending on the .NET version -
    # that is harmless because lastContent is only ever round-tripped through
    # Expand-Text (never hashed): the hash is computed over the normalized UTF-8
    # text, which IS deterministic across Windows PowerShell 5.1 and pwsh 7.
    param([string]$Text)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $ms = New-Object System.IO.MemoryStream
    $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress, $true)
    try {
        $gz.Write($bytes, 0, $bytes.Length)
    }
    finally {
        $gz.Dispose()
    }
    return [Convert]::ToBase64String($ms.ToArray())
}

function Expand-Text {
    param([string]$B64)
    $bytes = [Convert]::FromBase64String($B64)
    $ms = New-Object System.IO.MemoryStream(,$bytes)
    $gz = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
    try {
        $sr = New-Object System.IO.StreamReader($gz, [System.Text.Encoding]::UTF8)
        return $sr.ReadToEnd()
    }
    finally {
        $gz.Dispose()
    }
}

function Get-FirstDiffIndex {
    param([string[]]$Old, [string[]]$New)
    $n = [Math]::Min($Old.Count, $New.Count)
    for ($i = 0; $i -lt $n; $i++) {
        if ($Old[$i] -ne $New[$i]) { return $i }
    }
    return $n
}

function Test-Keywords {
    # Case-insensitive regex match of the watch patterns against the changed lines
    # (removed AND added), passed in as a single text block.
    param([string]$Text, [object[]]$Watch)
    $areas = New-Object System.Collections.Generic.List[string]
    $pats  = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrEmpty($Text)) {
        foreach ($w in $Watch) {
            $re = [string]$w.pattern
            try {
                if ($Text -match $re) {
                    $ar = [string]$w.area
                    if (-not $areas.Contains($ar)) { $areas.Add($ar) }
                    if (-not $pats.Contains($re))   { $pats.Add($re) }
                }
            }
            catch {
                Write-Warning ("api-monitor: bad watch pattern '{0}' - {1}" -f $re, $_.Exception.Message)
            }
        }
    }
    return [pscustomobject]@{ matched = $areas; patterns = $pats }
}

function Get-AtomSnippet {
    # First 3-5 NEW entries (from the diff region) as title/content blocks.
    param([string[]]$Lines)
    if (-not $Lines -or $Lines.Count -eq 0) { return '' }
    $joined = $Lines -join "`n"
    $blocks = @($joined -split [regex]::Escape($AtomEntryMarker) |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -ne '' })
    if ($blocks.Count -eq 0) { return '' }
    $chosen = @($blocks | Select-Object -First 5)
    $out = New-Object System.Collections.Generic.List[string]
    $idx = 0
    foreach ($b in $chosen) {
        $idx++
        if ($b.Length -gt 1200) { $b = $b.Substring(0, 1200) + ' ... (truncated)' }
        $out.Add(("--- entry {0} ---`n{1}" -f $idx, $b))
    }
    if ($blocks.Count -gt 5) { $out.Add('... (truncated)') }
    return ($out -join "`n`n")
}

function Get-IssueBody {
    param(
        [string]$Name,
        [string]$Provider,
        [string]$Url,
        [string]$ShortHash,
        [string]$Snippet,
        [System.Collections.Generic.List[string]]$Areas,
        [System.Collections.Generic.List[string]]$Patterns,
        [string]$Hash
    )
    # Non-ASCII glyphs are composed at runtime so this script stays pure ASCII and
    # parses cleanly under Windows PowerShell 5.1 regardless of file encoding/BOM.
    # The magnifier emoji (U+1F50D) is outside the BMP -> UTF-16 surrogate pair.
    $mag    = [string][char]0xD83D + [char]0xDD0D   # magnifying glass emoji
    $emDash = [string][char]0x2014                  # em dash
    $middot = [string][char]0x00B7                  # middle dot

    $data = [DateTime]::UtcNow.ToString('yyyy-MM-dd')
    $areaList = ($Areas | ForEach-Object { "- [ ] $_" }) -join "`n"
    $kw = ($Patterns) -join ', '

    $tpl = @'
## {MAG} Upstream API docs changed {EMDASH} {NAME}

**Detected by** `api-monitor` pipeline {MIDDOT} {DATA} UTC {MIDDOT} provider: {PROVIDER}

- Source: [{NAME}]({URL})
- Content hash: `{SHORT}`

### What changed (newest first)

```text
{SNIPPET}
```

### Areas of the proxy that may be affected

{AREAS}

### Keywords matched
`{KEYWORDS}`

<!-- source: {NAME} --> <!-- hash: {HASH} -->
_This issue was opened automatically by the api-monitor workflow. Close it after triage._
'@

    $body = $tpl
    $body = $body.Replace('{MAG}', $mag).Replace('{EMDASH}', $emDash).Replace('{MIDDOT}', $middot)
    $body = $body.Replace('{NAME}', $Name).Replace('{DATA}', $data).Replace('{PROVIDER}', $Provider)
    $body = $body.Replace('{URL}', $Url).Replace('{SHORT}', $ShortHash).Replace('{HASH}', $Hash)
    $body = $body.Replace('{AREAS}', $areaList).Replace('{KEYWORDS}', $kw)
    # snippet last: it is untrusted doc text and must not be re-tokenized. Inside the
    # ```text fence a literal ``` would close the block - split it so it cannot.
    $safeSnippet = $Snippet.Replace('```', '` ``')
    $body = $body.Replace('{SNIPPET}', $safeSnippet)
    return $body
}

# ---------------------------------------------------------------------------
# gh wrappers (native stderr is merged under EAP=Continue to stay PS 5.1-safe,
# where 2>&1 of a native command can throw under EAP=Stop)
# ---------------------------------------------------------------------------
function Invoke-GhLabelEnsure {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $null = & gh label create 'api-monitor' --color 'A4C8E1' --description 'Automated alert: upstream API docs changed (api-monitor)' 2>&1
    }
    catch {
        # "already exists" (or any label hiccup) is fine - issue create validates anyway
    }
    finally {
        $ErrorActionPreference = $prev
    }
}

function Invoke-GhListOpenIssues {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $out = @()
    $code = 0
    try {
        $out = @(& gh issue list -R $env:REPO --label 'api-monitor' --state open --json number,body --limit 1000 2>&1)
        $code = $LASTEXITCODE
    }
    catch {
        $code = 1
    }
    finally {
        $ErrorActionPreference = $prev
    }
    if ($code -ne 0) { throw ("gh issue list failed (exit {0})" -f $code) }
    $json = ($out | Out-String).Trim()
    if ([string]::IsNullOrEmpty($json)) { return ,@() }
    $arr = $json | ConvertFrom-Json
    if ($null -eq $arr) { return ,@() }
    return @($arr)
}

function New-GhIssue {
    param([string]$Title, [string]$Body)
    $bodyPath = Join-Path ([System.IO.Path]::GetTempPath()) ("api-monitor-issue-{0}.md" -f [guid]::NewGuid().ToString('N'))
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($bodyPath, $Body, $enc)
    try {
        Invoke-GhLabelEnsure
        $prev = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $out = @()
        $code = 0
        try {
            $out = @(& gh issue create -R $env:REPO --label 'api-monitor' --title $Title --body-file $bodyPath 2>&1)
            $code = $LASTEXITCODE
        }
        catch {
            $code = 1
        }
        finally {
            $ErrorActionPreference = $prev
        }
        if ($code -ne 0) {
            throw ("gh issue create failed (exit {0}): {1}" -f $code, (($out | Out-String).Trim()))
        }
        return (($out | Out-String).Trim())
    }
    finally {
        Remove-Item $bodyPath -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------------------
# State persistence
# ---------------------------------------------------------------------------
function Write-StateFile {
    $out = [ordered]@{ version = $script:state.version; sources = [ordered]@{} }
    foreach ($name in $script:orderedNames) {
        $e = $script:state.sources[$name]
        if (-not $e) {
            $e = @{ lastHash = ''; lastContent = ''; lastIssueHash = ''; lastIssueUrl = ''; lastIssueAt = '' }
        }
        $out.sources[$name] = [ordered]@{
            lastHash      = [string]$e.lastHash
            lastContent   = [string]$e.lastContent
            lastIssueHash = [string]$e.lastIssueHash
            lastIssueUrl  = [string]$e.lastIssueUrl
            lastIssueAt   = [string]$e.lastIssueAt
        }
    }
    $json = $out | ConvertTo-Json -Depth 10
    # UTF-8 without BOM (PS 5.1 compatible), written atomically: write a *.tmp file in
    # the same directory, then move it over the destination, so a crash mid-write can
    # never leave state.json truncated/corrupt.
    $enc = New-Object System.Text.UTF8Encoding($false)
    $tmpPath = Join-Path (Split-Path -Parent $StatePath) 'state.json.tmp'
    try {
        [System.IO.File]::WriteAllText($tmpPath, $json, $enc)
        Move-Item -LiteralPath $tmpPath -Destination $StatePath -Force
    }
    finally {
        if (Test-Path -LiteralPath $tmpPath) { Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue }
    }
    return $json
}

function Update-SourceStateGit {
    # Runner-only (GITHUB_ACTIONS=true plus GH_TOKEN): commit + push the updated
    # state.json. The token goes into the remote URL and is NEVER printed.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        # the script lives in <repo>\scripts\api-monitor\ -> repo root is TWO levels up
        $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        Write-Output ("[api-monitor] repo root: {0}" -f $repoRoot)
        Push-Location $repoRoot
        try {
            $null = & git config user.name 'github-actions[bot]' 2>&1
            $null = & git config user.email '41898282+github-actions[bot]@users.noreply.github.com' 2>&1

            $null = & git add 'scripts/api-monitor/state.json' 2>&1
            if ($LASTEXITCODE -ne 0) { throw ("git add failed (exit {0})" -f $LASTEXITCODE) }

            # nothing staged (file already identical to HEAD) -> no commit/push needed
            $null = & git diff --cached --quiet 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Output '[api-monitor] state file unchanged since last commit - nothing to push'
                return
            }
            if ($LASTEXITCODE -ge 128) { throw ("git diff --cached failed (exit {0})" -f $LASTEXITCODE) }

            $null = & git remote set-url origin ("https://{0}@github.com/{1}.git" -f $env:GH_TOKEN, $env:REPO) 2>&1
            if ($LASTEXITCODE -ne 0) { throw ("git remote set-url failed (exit {0})" -f $LASTEXITCODE) }

            $headBefore = @(& git rev-parse HEAD 2>&1)
            $headBefore = ($headBefore | Out-String).Trim()
            $commitOut = @(& git commit -m 'api-monitor: update state' 2>&1)
            if ($LASTEXITCODE -ne 0) {
                throw ('git commit failed (exit {0}): {1}' -f $LASTEXITCODE, (($commitOut | Out-String).Trim()))
            }
            $headAfter = @(& git rev-parse HEAD 2>&1)
            $headAfter = ($headAfter | Out-String).Trim()
            $committed = (-not [string]::IsNullOrWhiteSpace($headAfter)) -and ($headAfter -ne $headBefore)

            # checkout leaves a detached HEAD - push with an explicit destination branch
            $pushSpec = 'HEAD'
            if ($env:GITHUB_REF -and $env:GITHUB_REF -like 'refs/heads/*') {
                $pushSpec = 'HEAD:' + $env:GITHUB_REF.Substring('refs/heads/'.Length)
            }
            if ($committed) {
                $null = & git push origin $pushSpec 2>&1
                if ($LASTEXITCODE -ne 0) { throw ("git push failed (exit {0})" -f $LASTEXITCODE) }
                $short = $headAfter
                if ($short.Length -gt 8) { $short = $short.Substring(0, 8) }
                Write-Output ("[api-monitor] state committed and pushed ({0})" -f $short)
            }
            else {
                Write-Output ("[api-monitor] no new commit produced (HEAD {0} -> {1}) - nothing to push" -f $headBefore, $headAfter)
            }
        }
        finally {
            Pop-Location
        }
    }
    catch {
        Write-Warning ('api-monitor: state commit/push failed (next run reconciles): {0}' -f $_.Exception.Message)
    }
    finally {
        $ErrorActionPreference = $prev
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if ($BakeBaseline -and $DryRun) {
    Write-Error '-BakeBaseline and -DryRun are mutually exclusive.' -ErrorAction Continue
    exit 2
}

if (-not (Test-Path $SourcesPath)) {
    Write-Error "sources.json not found: $SourcesPath" -ErrorAction Continue
    exit 2
}

$cfg = Get-Content -Raw -Path $SourcesPath | ConvertFrom-Json
$script:sources = @($cfg.sources)
$script:orderedNames = @($script:sources | ForEach-Object { [string]$_.name })
foreach ($src in $script:sources) {
    $script:watchMap[[string]$src.name] = @($src.watch)
}

# Load previous state (absent or corrupt -> empty baseline with an explicit warning;
# never abort the run, never rebaseline silently)
$script:state = [ordered]@{ version = 1; sources = @{} }
$stateLoadFailed = $false
if (Test-Path $StatePath) {
    try {
        $raw = Get-Content -Raw -Path $StatePath
        if (-not [string]::IsNullOrWhiteSpace($raw)) {
            $parsed = $raw | ConvertFrom-Json
            $script:state.version = $parsed.version
            foreach ($p in $parsed.sources.PSObject.Properties) {
                $s = $p.Value
                $script:state.sources[$p.Name] = @{
                    lastHash      = [string]$s.lastHash
                    lastContent   = [string]$s.lastContent
                    lastIssueHash = [string]$s.lastIssueHash
                    lastIssueUrl  = [string]$s.lastIssueUrl
                    lastIssueAt   = [string]$s.lastIssueAt
                }
            }
        }
    }
    catch {
        $stateLoadFailed = $true
    }
}
if ($stateLoadFailed) {
    Write-Warning ("api-monitor: {0} is unreadable/corrupt - starting from an empty baseline this run" -f $StatePath)
    $script:state = [ordered]@{ version = 1; sources = @{} }
}

$okCount = 0
$stateChanged = $false

foreach ($src in $script:sources) {
    $name = [string]$src.name
    try {
        # 1) fetch
        $resp = Invoke-WebRequest -UseBasicParsing -Uri ([string]$src.url) -Method Get -TimeoutSec 90 -UserAgent $UserAgent -MaximumRedirection 5
        if ($resp.StatusCode -ne 200) {
            throw ("HTTP {0} for {1}" -f $resp.StatusCode, $src.url)
        }

        # 1b) content-type guard: the pipeline diff/issue body is text - skip binary
        # (octet-stream, archive, pdf, ...) sources with a warning, never open an issue.
        $respContentType = $resp.Headers['Content-Type']
        if ($respContentType -is [array]) { $respContentType = $respContentType -join '; ' }
        $respContentType = [string]$respContentType
        if ($respContentType -match '(?i)(?:^|[;,])[ \t]*(?:application/(?:octet-stream|zip|gzip|x-gzip|pdf|vnd\.[0-9a-z.+-]+)|(?:image|audio|video)/)') {
            Write-Warning ("api-monitor: {0}: non-text content type '{1}' - source skipped" -f $name, $respContentType)
            $script:failures.Add(("{0}: skipped (non-text content type {1})" -f $name, $respContentType))
            Write-Result ("[api-monitor] {0}: SKIPPED (non-text content type '{1}')" -f $name, $respContentType)
            continue
        }

        # 1c) decode the bytes explicitly as UTF-8. [string]$resp.Content relies on the
        # declared charset - PS 5.1 defaults to ISO-8859-1 when absent, pwsh 7 to UTF-8 -
        # so the hash would differ between hosts. RawContentStream exists on both with
        # -UseBasicParsing; Content itself may be byte[] for non-text responses.
        $text = $null
        if ($resp.Content -is [byte[]]) {
            $text = [System.Text.Encoding]::UTF8.GetString($resp.Content)
        }
        elseif ($resp.RawContentStream) {
            $text = [System.Text.Encoding]::UTF8.GetString($resp.RawContentStream.ToArray())
        }
        else {
            Write-Warning ("api-monitor: {0}: no byte stream available - decoding from string (may differ across PS versions)" -f $name)
            $text = [string]$resp.Content
        }
        if ([string]::IsNullOrWhiteSpace($text)) { throw 'empty response body' }

        # 2) normalize (atom: extract titles+contents of the entries only)
        if ($src.kind -eq 'atom') { $text = Get-AtomFlattened -XmlText $text }
        $norm = Get-NormalizedText -Text $text

        # 3) hash
        $hash = Get-Sha256Hex -Text $norm
        $shortHash = $hash.Substring(0, [Math]::Min(12, $hash.Length))

        $st = $script:state.sources[$name]
        $lastHash = ''
        if ($st) { $lastHash = [string]$st.lastHash }

        # 4) baseline?
        if (-not $lastHash) {
            $script:state.sources[$name] = @{
                lastHash = $hash; lastContent = (Compress-Text -Text $norm)
                lastIssueHash = ''; lastIssueUrl = ''; lastIssueAt = ''
            }
            $stateChanged = $true
            Write-Result ("[api-monitor] {0}: baseline ({1})" -f $name, $shortHash)
            $okCount++
            continue
        }

        # 5) unchanged?
        if ($hash -eq $lastHash) {
            Write-Result ("[api-monitor] {0}: UNCHANGED" -f $name)
            $okCount++
            continue
        }

        # ---- CHANGED ----
        $oldNorm = ''
        if ($st) {
            $oldContent = [string]$st.lastContent
            if ([string]::IsNullOrEmpty($oldContent)) { $oldNorm = '' }
            else { $oldNorm = Expand-Text -B64 $oldContent }
        }
        $oldLines = @(Get-TextLines -Text $oldNorm)
        $newLines = @(Get-TextLines -Text $norm)
        $fdi = Get-FirstDiffIndex -Old $oldLines -New $newLines

        # Keyword matching runs over ALL lines that differ (removed AND added), not just
        # the first diverging region - so a removal (e.g. a deleted rate-limit notice)
        # is still detected. The issue snippet below stays limited to ~25 new lines.
        $diffLines = New-Object System.Collections.Generic.List[string]
        $maxIdx = [Math]::Max($oldLines.Count, $newLines.Count)
        for ($i = 0; $i -lt $maxIdx; $i++) {
            if ($i -lt $oldLines.Count -and $i -lt $newLines.Count -and $oldLines[$i] -eq $newLines[$i]) { continue }
            if ($i -lt $oldLines.Count) { $diffLines.Add('-' + $oldLines[$i]) }
            if ($i -lt $newLines.Count) { $diffLines.Add('+' + $newLines[$i]) }
        }
        if ($diffLines.Count -gt 0) { $diffText = $diffLines -join "`n" } else { $diffText = '' }

        # snippet (issue body context): ~25 new lines from the first point of difference
        # (atom: first 3-5 entries)
        $snippet = ''
        if ($fdi -lt $newLines.Count) {
            if ($src.kind -eq 'atom') {
                $snippet = Get-AtomSnippet -Lines $newLines[$fdi..($newLines.Count - 1)]
            }
            else {
                $snippetEnd = [Math]::Min($newLines.Count - 1, $fdi + 24)
                $snippet = ($newLines[$fdi..$snippetEnd] -join "`n")
                if ($snippetEnd -lt ($newLines.Count - 1)) { $snippet = $snippet + "`n... (truncated)" }
            }
        }
        else {
            $snippet = '... (content removed at the end of the document)'
        }
        if ([string]::IsNullOrWhiteSpace($snippet)) {
            $snippet = '(no textual context available - see source link)'
        }

        $match = Test-Keywords -Text $diffText -Watch $script:watchMap[$name]

        # 5b) DryRun: report only
        if ($DryRun) {
            if ($match.matched.Count -gt 0) {
                Write-Result ("[api-monitor] {0}: CHANGED (would open issue)" -f $name)
            }
            else {
                Write-Result ("[api-monitor] {0}: CHANGED (no relevant keywords)" -f $name)
            }
            $okCount++
            continue
        }

        # 5c) BakeBaseline: store hash + snapshot, never open an issue
        if ($BakeBaseline) {
            $script:state.sources[$name].lastHash = $hash
            $script:state.sources[$name].lastContent = (Compress-Text -Text $norm)
            $stateChanged = $true
            Write-Result ("[api-monitor] {0}: CHANGED (baseline update {1})" -f $name, $shortHash)
            $okCount++
            continue
        }

        # ---- normal run ----
        # State is advanced ONLY on success. In particular, if gh fails (rate limit,
        # network, label, outage) the catch below leaves lastHash untouched so the next
        # run re-detects the change instead of consuming it silently.
        $newContent = Compress-Text -Text $norm

        if ($match.matched.Count -eq 0) {
            # no relevant keywords: consume the change without opening an issue
            $script:state.sources[$name].lastHash = $hash
            $script:state.sources[$name].lastContent = $newContent
            $stateChanged = $true
            Write-Result ("[api-monitor] {0}: CHANGED (no relevant keywords - hash updated)" -f $name)
            $okCount++
            continue
        }

        # 6) dedupe against open issues (gh; throws on failure -> state NOT advanced)
        $dupUrl = $null
        $dupNum = $null
        $openIssues = Invoke-GhListOpenIssues
        foreach ($issue in $openIssues) {
            $b = [string]$issue.body
            if ($b -like "*<!-- source: $name -->*" -and $b -like "*<!-- hash: $hash -->*") {
                $dupNum = $issue.number
                $dupUrl = "https://github.com/$env:REPO/issues/$($issue.number)"
                break
            }
        }
        if ($dupNum) {
            # already alerted for this hash - advance state
            $script:state.sources[$name].lastHash = $hash
            $script:state.sources[$name].lastContent = $newContent
            $script:state.sources[$name].lastIssueHash = $hash
            $script:state.sources[$name].lastIssueUrl = $dupUrl
            $script:state.sources[$name].lastIssueAt = [DateTime]::UtcNow.ToString('o')
            $stateChanged = $true
            Write-Result ("[api-monitor] {0}: CHANGED (issue #{1} already open)" -f $name, $dupNum)
            $okCount++
            continue
        }

        # 7) open the issue; advance state ONLY after gh confirms success
        $dateStamp = [DateTime]::UtcNow.ToString('yyyy-MM-dd')
        $title = "[api-monitor] {0}: upstream docs changed ({1})" -f $name, $dateStamp
        $body = Get-IssueBody -Name $name -Provider ([string]$src.provider) -Url ([string]$src.url) `
            -ShortHash $shortHash -Snippet $snippet -Areas $match.matched -Patterns $match.patterns -Hash $hash
        $newUrl = New-GhIssue -Title $title -Body $body
        if ($newUrl -notmatch '/issues/\d+') {
            throw ("gh issue create returned no issue URL: {0}" -f $newUrl)
        }
        $script:state.sources[$name].lastHash = $hash
        $script:state.sources[$name].lastContent = $newContent
        $script:state.sources[$name].lastIssueHash = $hash
        $script:state.sources[$name].lastIssueUrl = $newUrl
        $script:state.sources[$name].lastIssueAt = [DateTime]::UtcNow.ToString('o')
        $stateChanged = $true
        if ($newUrl -match '/issues/(\d+)') {
            Write-Result ("[api-monitor] {0}: CHANGED (issue #{1})" -f $name, $Matches[1])
        }
        else {
            Write-Result ("[api-monitor] {0}: CHANGED (issue created: {1})" -f $name, $newUrl)
        }
        $okCount++
    }
    catch {
        $err = (($_.Exception.Message) -split '\r?\n' | Select-Object -First 1)
        $script:failures.Add(("{0}: {1}" -f $name, $err))
        Write-Result ("[api-monitor] {0}: ERROR ({1})" -f $name, $err)
    }
}

# ---------------------------------------------------------------------------
# Finalize
# ---------------------------------------------------------------------------
if (-not $DryRun) {
    $null = Write-StateFile
}

$total = $script:sources.Count
$failCount = $script:failures.Count
Write-Output ''
Write-Output ("RESULT: {0} ok, {1} skipped (errors)" -f $okCount, $failCount)
foreach ($f in $script:failures) {
    Write-Output ("  ERROR: {0}" -f $f)
}

# Runner-only: commit + push the state back. Requires GITHUB_ACTIONS=true AND
# GH_TOKEN - a dev machine with a stray GH_TOKEN exported must never commit/push.
if (-not $DryRun -and -not $BakeBaseline) {
    if ($stateChanged) {
        if ($env:GH_TOKEN -and $env:GITHUB_ACTIONS -eq 'true') {
            Update-SourceStateGit
        }
        elseif ($env:GH_TOKEN) {
            Write-Warning 'api-monitor: state changed but GITHUB_ACTIONS is not set - state.json updated in place, not committed'
        }
        else {
            Write-Warning 'api-monitor: state changed but GH_TOKEN is missing - state.json updated in place, not committed'
        }
    }
}

# Monitor semantics: partial failures exit 0 (no false "failed run" email alerts);
# only a total failure (every source errored) exits 1 so the failure is noticed.
if ($failCount -ge $total) { exit 1 }
exit 0
