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
  - Noise reduction: three mechanisms keep the alert stream usable. (a) Per-source
    cooldown: a source may set "cooldownHours" in sources.json (hours; 0 or absent
    means disabled). While a source is inside its window, detected changes are
    consumed silently - the hash advances and no issue is opened, and those changes
    are never alerted afterwards either. Only real runs are affected (-DryRun and
    -BakeBaseline bypass it). (b) Supersede: when a new issue is opened for a source,
    every still-open api-monitor issue of the SAME source is closed with a
    "Superseded by #N" comment, so at most one alert per source stays open (newest
    wins). (c) Sanitize: at the end of every real run, for each source that still has
    more than one open issue, all but the newest (highest issue number) are closed
    with a comment - a safety net for failed closes, manual re-runs or a state reset.
    In (b) and (c) an issue is attributed to a source only by the official
    "<!-- source: NAME -->" footer (falling back to the last marker occurrence), and
    only when NAME is a known name from sources.json; untrusted upstream text quoted
    in an issue snippet can therefore never close another source's issue.

.PARAMETER BakeBaseline
  Record the current state of every source without opening issues or touching git.

.PARAMETER DryRun
  Simulate: report UNCHANGED / CHANGED (would open issue / no relevant keywords). No writes.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\.github\api-monitor\api-monitor.ps1 -BakeBaseline

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\.github\api-monitor\api-monitor.ps1 -DryRun

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

function Get-SourceNameFromIssueBody {
    # Resolves which api-monitor source an issue body belongs to, or $null when it
    # cannot be resolved to a KNOWN source. The body embeds untrusted upstream text
    # (the ```text snippet and the keyword context lines), so a spoofed
    # "<!-- source: X -->" marker must never be able to close another source's issue.
    # Attribution therefore only looks at the TAIL of the body, never the whole text:
    #   1) only the last two NON-EMPTY lines (after normalizing CRLF -> LF) are
    #      candidates - both official formats end the body with the marker/footer
    #      followed by the "_This issue was opened automatically..." sentinel, while
    #      the untrusted snippet sits in the middle;
    #   2) inside that tail the OFFICIAL footer written by Get-IssueBody
    #      ("<!-- source: NAME --> <!-- hash: HASH -->" on its own line) wins; if the
    #      tail has no footer, a plain marker ("<!-- source: NAME -->") is used - this
    #      covers legacy issues that carry the marker but no footer;
    #   3) the extracted name must match $script:orderedNames (sources.json), and the
    #      canonical spelling from sources.json is returned (never the raw marker
    #      text), so it is always validated before it reaches logs or grouping.
    # No marker in the tail -> $null (fail-closed).
    # The patterns avoid overlapping quantifiers (\S+ next to [ \t]*) so a hostile
    # body full of spaces cannot trigger catastrophic backtracking (ReDoS), and they
    # are anchored to a whole line so only a clean marker line can match.
    param([string]$Body)
    if ([string]::IsNullOrEmpty($Body)) { return $null }
    if (-not $script:orderedNames -or $script:orderedNames.Count -eq 0) { return $null }

    # last two non-empty lines, in body order (oldest first)
    $tail = New-Object System.Collections.Generic.List[string]
    $lines = @(Get-TextLines -Text $Body)
    for ($i = $lines.Count - 1; $i -ge 0 -and $tail.Count -lt 2; $i--) {
        $line = ([string]$lines[$i]).Trim()
        if ($line.Length -gt 0) { $tail.Insert(0, $line) }
    }
    if ($tail.Count -eq 0) { return $null }

    $footerRx = [regex]'^<!--[ \t]*source:[ \t]*(\S+)[ \t]*-->[ \t]*<!--[ \t]*hash:[ \t]*[0-9a-fA-F]{64}[ \t]*-->$'
    $markerRx = [regex]'^<!--[ \t]*source:[ \t]*(\S+)[ \t]*-->$'

    $candidate = $null
    for ($i = $tail.Count - 1; $i -ge 0 -and -not $candidate; $i--) {
        $m = $footerRx.Match($tail[$i])
        if ($m.Success) { $candidate = $m.Groups[1].Value }
    }
    if (-not $candidate) {
        for ($i = $tail.Count - 1; $i -ge 0 -and -not $candidate; $i--) {
            $m = $markerRx.Match($tail[$i])
            if ($m.Success) { $candidate = $m.Groups[1].Value }
        }
    }
    if (-not $candidate) { return $null }

    foreach ($known in $script:orderedNames) {
        if ([string]::Equals([string]$known, [string]$candidate, [System.StringComparison]::OrdinalIgnoreCase)) {
            return [string]$known
        }
    }
    return $null
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

function Get-SectionKey {
    # Key used to match a section between snapshots: "<occurrence>::<heading>".
    # Occurrence is the n-th appearance of the exact heading text, so inserting or
    # removing one section does NOT re-key every later section (a positional index
    # would shift and flag the whole tail of the document as changed).
    param([string]$Heading, [int]$Occurrence)
    return ("{0}::{1}" -f $Occurrence, $Heading)
}

function Get-MarkdownSections {
    # Split normalized markdown lines into sections on heading lines (^#{1,6} ).
    # The text before the first heading is its own section with Heading='' (the
    # preamble - never dropped). Each section carries: Index (document order),
    # Heading (raw heading line, empty for the preamble), Lines (content lines,
    # heading excluded) and Key (occurrence-based match key, see Get-SectionKey).
    param([string[]]$Lines)
    $sections = New-Object System.Collections.Generic.List[object]
    if ($Lines -and $Lines.Count -gt 0) {
        $curHeading = ''
        $curLines = New-Object System.Collections.Generic.List[string]
        $occCount = @{}
        foreach ($l in $Lines) {
            if ($l -match '^#{1,6}\s+') {
                $occ = 0
                if ($occCount.ContainsKey($curHeading)) { $occ = $occCount[$curHeading] }
                $sections.Add([pscustomobject]@{
                    Index   = $sections.Count
                    Heading = $curHeading
                    Lines   = @($curLines)
                    Key     = (Get-SectionKey -Heading $curHeading -Occurrence $occ)
                })
                $occCount[$curHeading] = $occ + 1
                $curHeading = $l
                $curLines = New-Object System.Collections.Generic.List[string]
            }
            else {
                $curLines.Add($l)
            }
        }
        # flush the last section
        $occ = 0
        if ($occCount.ContainsKey($curHeading)) { $occ = $occCount[$curHeading] }
        $sections.Add([pscustomobject]@{
            Index   = $sections.Count
            Heading = $curHeading
            Lines   = @($curLines)
            Key     = (Get-SectionKey -Heading $curHeading -Occurrence $occ)
        })
    }
    return $sections
}

function Get-SectionText {
    # Full section text for hashing: the heading line (if any) plus its content.
    param([object]$Section)
    $parts = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace([string]$Section.Heading)) { $parts.Add([string]$Section.Heading) }
    foreach ($l in $Section.Lines) { $parts.Add([string]$l) }
    return ($parts -join "`n")
}

function Get-SectionHash {
    param([object]$Section)
    return Get-Sha256Hex -Text (Get-SectionText -Section $Section)
}

function Get-SectionMap {
    # Lookup table keyed by section Key for fast old/new matching.
    param([object[]]$Sections)
    $map = @{}
    foreach ($s in $Sections) {
        $map[[string]$s.Key] = $s
    }
    return $map
}

function Get-SaneHeading {
    # Sanitize a markdown heading for use in an issue title: strip markdown syntax
    # characters, collapse whitespace, cap at 60 chars. A preamble (no heading) is
    # reported as (preamble).
    param([string]$Heading)
    $h = [string]$Heading
    if ([string]::IsNullOrWhiteSpace($h)) { return '(preamble)' }
    $h = [regex]::Replace($h, '[#*_`\[\]()]', '')
    $h = [regex]::Replace($h, '\s+', ' ').Trim()
    if ($h.Length -gt 60) {
        $h = $h.Substring(0, 60).TrimEnd() + '...'
    }
    if ([string]::IsNullOrWhiteSpace($h)) { return '(preamble)' }
    return $h
}

function Get-MarkdownDiffInfo {
    # Section-scoped diff for markdown sources (P1). Matches old/new sections by
    # occurrence-based heading keys, restricts the diff to the changed sections and
    # reports:
    #   UseSections - $true when sections give a meaningful scoped diff
    #   Count       - number of changed sections
    #   Heading     - sanitized heading of the first changed section ((preamble))
    #   Snippet     - first changed section: heading + up to 40 content lines
    #   DiffText    - +/- prefixed lines restricted to the changed sections only
    # Falls back (UseSections=$false) when the document has no sections, no section
    # changed, or the changed sections cover >= 90% of the document's lines (a full
    # page rewrite - the positional diff is the honest answer there).
    param([string[]]$OldLines, [string[]]$NewLines)
    $fallback = [pscustomobject]@{ UseSections = $false; Count = 0; Heading = ''; Snippet = ''; DiffText = '' }

    $oldSecs = @(Get-MarkdownSections -Lines $OldLines)
    $newSecs = @(Get-MarkdownSections -Lines $NewLines)
    $oldMap = Get-SectionMap -Sections $oldSecs
    $newMap = Get-SectionMap -Sections $newSecs

    $changed = New-Object System.Collections.Generic.List[object]
    $changedKeys = @{}
    foreach ($s in $newSecs) {
        $key = [string]$s.Key
        $old = $oldMap[$key]
        if (($null -eq $old) -or ((Get-SectionHash -Section $s) -ne (Get-SectionHash -Section $old))) {
            $changed.Add($s)
            $changedKeys[$key] = $true
        }
    }
    foreach ($s in $oldSecs) {
        $key = [string]$s.Key
        if (-not $newMap.ContainsKey($key)) {
            $changed.Add($s)
            $changedKeys[$key] = $true
        }
    }
    if ($changed.Count -eq 0) { return $fallback }

    # coverage guard: >= 90% of the document lines belong to changed sections ->
    # effectively a rewrite of the page -> positional diff
    $totalLines = [Math]::Max($OldLines.Count, $NewLines.Count)
    $changedLines = 0
    foreach ($s in $changed) {
        $changedLines += @($s.Lines).Count
        if (-not [string]::IsNullOrWhiteSpace([string]$s.Heading)) { $changedLines++ }
    }
    if (($totalLines -gt 0) -and (($changedLines / [double]$totalLines)) -ge 0.9) {
        return $fallback
    }

    # diff text: line-level diff INSIDE changed sections (matched pairs), all new
    # lines for added sections, all old lines for removed sections
    $diffLines = New-Object System.Collections.Generic.List[string]
    $handledKeys = @{}
    foreach ($s in $newSecs) {
        $key = [string]$s.Key
        if (-not $changedKeys.ContainsKey($key)) { continue }
        $handledKeys[$key] = $true
        $old = $oldMap[$key]
        if ($null -eq $old) {
            # added section: every new line
            if (-not [string]::IsNullOrWhiteSpace([string]$s.Heading)) { $diffLines.Add('+' + [string]$s.Heading) }
            foreach ($l in $s.Lines) { $diffLines.Add('+' + [string]$l) }
            continue
        }
        # changed section: pairwise diff of its own lines (keeps the keyword text tight)
        $oldSecLines = @($old.Lines)
        $newSecLines = @($s.Lines)
        $maxS = [Math]::Max($oldSecLines.Count, $newSecLines.Count)
        for ($j = 0; $j -lt $maxS; $j++) {
            if (($j -lt $oldSecLines.Count) -and ($j -lt $newSecLines.Count) -and ($oldSecLines[$j] -eq $newSecLines[$j])) { continue }
            if ($j -lt $oldSecLines.Count) { $diffLines.Add('-' + [string]$oldSecLines[$j]) }
            if ($j -lt $newSecLines.Count) { $diffLines.Add('+' + [string]$newSecLines[$j]) }
        }
    }
    foreach ($s in $oldSecs) {
        $key = [string]$s.Key
        if ($handledKeys.ContainsKey($key)) { continue }
        if (-not $changedKeys.ContainsKey($key)) { continue }
        # removed section: every old line
        if (-not [string]::IsNullOrWhiteSpace([string]$s.Heading)) { $diffLines.Add('-' + [string]$s.Heading) }
        foreach ($l in $s.Lines) { $diffLines.Add('-' + [string]$l) }
    }

    # snippet: first changed section (heading + up to 40 content lines) plus notes
    $first = $changed[0]
    $firstRemoved = -not $newMap.ContainsKey([string]$first.Key)
    $snipLines = New-Object System.Collections.Generic.List[string]
    if (-not [string]::IsNullOrWhiteSpace([string]$first.Heading)) { $snipLines.Add([string]$first.Heading) }
    $firstBody = @($first.Lines)
    $headCount = $snipLines.Count
    $take = [Math]::Min(40 - $headCount, $firstBody.Count)
    for ($k = 0; $k -lt $take; $k++) { $snipLines.Add([string]$firstBody[$k]) }
    if ($firstRemoved) {
        $snipLines.Add('(section removed from the source)')
    }
    elseif ($changed.Count -gt 1) {
        $snipLines.Add(('... (truncated: {0} sections changed - snippet shows the first)' -f $changed.Count))
    }
    elseif ($firstBody.Count -gt $take) {
        $snipLines.Add('... (truncated)')
    }
    $snippet = ($snipLines -join "`n")
    if ([string]::IsNullOrWhiteSpace($snippet)) { $snippet = '(section changed - see source link)' }

    return [pscustomobject]@{
        UseSections = $true
        Count       = $changed.Count
        Heading     = Get-SaneHeading -Heading ([string]$first.Heading)
        Snippet     = $snippet
        DiffText    = ($diffLines -join "`n")
    }
}

function Split-PatternAlternatives {
    # Split a watch pattern into individual sub-patterns on '|' when it is safe to
    # do so (no escaped pipe, no capture/non-capture groups). Ambiguous patterns
    # stay whole - the full group is the keyword entry in that case.
    param([string]$Pattern)
    if ([string]::IsNullOrWhiteSpace($Pattern)) { return @() }
    if ($Pattern.Contains('\|') -or $Pattern.Contains('(')) { return @($Pattern) }
    $subs = @($Pattern -split '\|' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($subs.Count -lt 2) { return @($Pattern) }
    return @($subs)
}

function Test-Keywords {
    # Case-insensitive regex match of the watch patterns against the changed lines
    # (removed AND added), passed in as a single text block.
    #
    # A missing/empty "watch" in sources.json arrives here as @($null). Without a
    # guard the pattern would degrade to '' and '-match ""' would match EVERY
    # string - opening an issue with an empty area on any change. Null/empty watch
    # is treated as "no relevant keywords" -> empty match list, the change is
    # consumed without an issue.
    param([string]$Text, [object[]]$Watch)
    $areas = New-Object System.Collections.Generic.List[string]
    $pats  = New-Object System.Collections.Generic.List[string]
    $ctxs  = New-Object System.Collections.Generic.List[string]
    $watchList = @($Watch | Where-Object { $null -ne $_ })
    if (-not [string]::IsNullOrEmpty($Text) -and $watchList.Count -gt 0) {
        $diffLines = @(Get-TextLines -Text $Text)
        foreach ($w in $watchList) {
            $re = [string]$w.pattern
            try {
                if ($Text -match $re) {
                    $ar = [string]$w.area
                    if (-not $areas.Contains($ar)) { $areas.Add($ar) }
                    # report the individual sub-patterns that actually matched (P2),
                    # each with the first changed line where it appears as context
                    foreach ($sub in @(Split-PatternAlternatives -Pattern $re)) {
                        if (-not $pats.Contains($sub) -and $Text -match $sub) {
                            $pats.Add($sub)
                            $ctx = ''
                            foreach ($dl in $diffLines) {
                                if ($dl -match $sub) { $ctx = $dl; break }
                            }
                            if ($ctx.Length -gt 140) { $ctx = $ctx.Substring(0, 140) + '...' }
                            $ctxs.Add($ctx)
                        }
                    }
                }
            }
            catch {
                Write-Warning ("api-monitor: bad watch pattern '{0}' - {1}" -f $re, $_.Exception.Message)
            }
        }
    }
    return [pscustomobject]@{ matched = $areas; patterns = $pats; contexts = $ctxs }
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
        [System.Collections.Generic.List[string]]$Contexts,
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
    # one bullet per matched sub-pattern, each with the first matching changed line
    # as context (P2). The context is untrusted doc text: strip backticks so it can
    # never break the inline-code span, and keep it within one line.
    $patternLines = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $Patterns.Count; $i++) {
        $p = [string]$Patterns[$i]
        $c = ''
        if ($Contexts -and ($i -lt $Contexts.Count)) { $c = [string]$Contexts[$i] }
        $c = ($c -replace '[`]', '').Trim()
        if ($c.Length -gt 140) { $c = $c.Substring(0, 140) + '...' }
        if ([string]::IsNullOrWhiteSpace($c)) { $c = '(no context line)' }
        $patternLines.Add(('- `{0}` -> "{1}"' -f $p, $c))
    }
    $patternsBlock = ($patternLines -join "`n")
    if ([string]::IsNullOrWhiteSpace($patternsBlock)) { $patternsBlock = '_(none)_' }

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

{PATTERNS}

<!-- source: {NAME} --> <!-- hash: {HASH} -->
_This issue was opened automatically by the api-monitor workflow. Close it after triage._
'@

    $body = $tpl
    $body = $body.Replace('{MAG}', $mag).Replace('{EMDASH}', $emDash).Replace('{MIDDOT}', $middot)
    $body = $body.Replace('{NAME}', $Name).Replace('{DATA}', $data).Replace('{PROVIDER}', $Provider)
    $body = $body.Replace('{URL}', $Url).Replace('{SHORT}', $ShortHash).Replace('{HASH}', $Hash)
    $body = $body.Replace('{AREAS}', $areaList).Replace('{PATTERNS}', $patternsBlock)
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

function Invoke-GhCloseIssue {
    # Closes an issue with a comment. NEVER throws: closing is cleanup, so a gh hiccup
    # (rate limit, network, permissions) must not fail the run - the new alert is
    # already open and the state has already advanced. Returns $true on success and
    # $false on failure (the failure detail goes to the warning).
    param([int]$Number, [string]$Comment)
    # A non-positive number is never a real issue: skip it (no gh call, no warning).
    if ($Number -le 0) { return $false }
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $out = @()
    $code = 0
    try {
        $out = @(& gh issue close $Number -R $env:REPO --comment $Comment 2>&1)
        $code = $LASTEXITCODE
    }
    catch {
        $code = 1
    }
    finally {
        $ErrorActionPreference = $prev
    }
    if ($code -ne 0) {
        Write-Warning ('api-monitor: gh issue close #{0} failed (exit {1}): {2}' -f $Number, $code, (($out | Out-String).Trim()))
        return $false
    }
    return $true
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
        # the script lives in <repo>\.github\api-monitor\ -> repo root is TWO levels up
        $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        Write-Output ("[api-monitor] repo root: {0}" -f $repoRoot)
        Push-Location $repoRoot
        try {
            $null = & git config user.name 'github-actions[bot]' 2>&1
            $null = & git config user.email '41898282+github-actions[bot]@users.noreply.github.com' 2>&1

            $null = & git add '.github/api-monitor/state.json' 2>&1
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

            # Each rev-parse exit code is checked: if both fail with the same error
            # text the old code saw $committed=false and reported "no new commit
            # produced - nothing to push" even though a local commit might exist.
            # A failing rev-parse now throws (visible failure, no false state report).
            $headBefore = @(& git rev-parse HEAD 2>&1)
            if ($LASTEXITCODE -ne 0) { throw ("git rev-parse HEAD failed before commit (exit {0})" -f $LASTEXITCODE) }
            $headBefore = ($headBefore | Out-String).Trim()
            $commitOut = @(& git commit -m 'api-monitor: update state' 2>&1)
            if ($LASTEXITCODE -ne 0) {
                throw ('git commit failed (exit {0}): {1}' -f $LASTEXITCODE, (($commitOut | Out-String).Trim()))
            }
            $headAfter = @(& git rev-parse HEAD 2>&1)
            if ($LASTEXITCODE -ne 0) { throw ("git rev-parse HEAD failed after commit (exit {0})" -f $LASTEXITCODE) }
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

        # P1: for markdown sources, narrow the diff to the changed SECTION(S), so a
        # large page (e.g. openrouter's llms-full.txt) no longer matches every keyword
        # area. Falls back to the positional page-wide diff when the document has no
        # usable headings, nothing matched section-wise, or >=90% of the page changed
        # (rewrite -> the page-level alert is the honest one).
        $sectionCount = 0
        $sectionHeading = ''
        $useSections = $false
        $diffText = ''
        $snippet = ''
        if ($src.kind -eq 'markdown') {
            $secInfo = Get-MarkdownDiffInfo -OldLines $oldLines -NewLines $newLines
            if ($null -ne $secInfo -and $secInfo.UseSections) {
                $useSections = $true
                $sectionCount = [int]$secInfo.Count
                $sectionHeading = [string]$secInfo.Heading
                $diffText = [string]$secInfo.DiffText
                $snippet = [string]$secInfo.Snippet
            }
        }
        if (-not $useSections) {
            # Keyword matching runs over ALL lines that differ (removed AND added), not
            # just the first diverging region - so a removal (e.g. a deleted rate-limit
            # notice) is still detected.
            $diffLines = New-Object System.Collections.Generic.List[string]
            $maxIdx = [Math]::Max($oldLines.Count, $newLines.Count)
            for ($i = 0; $i -lt $maxIdx; $i++) {
                if ($i -lt $oldLines.Count -and $i -lt $newLines.Count -and $oldLines[$i] -eq $newLines[$i]) { continue }
                if ($i -lt $oldLines.Count) { $diffLines.Add('-' + $oldLines[$i]) }
                if ($i -lt $newLines.Count) { $diffLines.Add('+' + $newLines[$i]) }
            }
            if ($diffLines.Count -gt 0) { $diffText = $diffLines -join "`n" } else { $diffText = '' }

            # snippet (issue body context): ~25 new lines from the first point of
            # difference (atom: first 3-5 entries)
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

        # 5d) per-source cooldown: chatty sources (e.g. openrouter-docs) must not open
        # more than one alert per window. The change is consumed silently (like "no
        # relevant keywords"), so a later window can still alert. DryRun/BakeBaseline
        # already returned above, so the cooldown only applies to real runs. An absent
        # or null cooldownHours is treated as 0 (disabled); a PRESENT but unparsable
        # value also falls back to 0 but emits a warning, so a config typo is visible
        # instead of silently disabling the cooldown. An unparsable lastIssueAt
        # disables the cooldown for this run.
        $cooldownHours = 0
        $cdProp = $src.PSObject.Properties['cooldownHours']
        if ($null -ne $cdProp -and $null -ne $cdProp.Value) {
            $cdParsed = 0
            if ([int]::TryParse([string]$cdProp.Value, [ref]$cdParsed)) { $cooldownHours = $cdParsed }
            else {
                Write-Warning ("api-monitor: {0}: cooldownHours '{1}' is not an integer - cooldown disabled for this source" -f $name, [string]$cdProp.Value)
            }
        }
        if ($cooldownHours -gt 0 -and $st) {
            $lastIssueAtRaw = [string]$st.lastIssueAt
            if (-not [string]::IsNullOrWhiteSpace($lastIssueAtRaw)) {
                $lastIssueAt = [DateTime]::MinValue
                $cooldownActive = $false
                try {
                    $lastIssueAt = [datetime]::Parse($lastIssueAtRaw, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)
                    $elapsedHours = ([DateTime]::UtcNow - $lastIssueAt.ToUniversalTime()).TotalHours
                    if ($elapsedHours -lt $cooldownHours) { $cooldownActive = $true }
                }
                catch {
                    $cooldownActive = $false
                }
                if ($cooldownActive) {
                    $script:state.sources[$name].lastHash = $hash
                    $script:state.sources[$name].lastContent = $newContent
                    $stateChanged = $true
                    Write-Result ("[api-monitor] {0}: COOLDOWN (skip issue - last alert {1:0.#} h ago)" -f $name, $elapsedHours)
                    $okCount++
                    continue
                }
            }
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
        if ($useSections -and $sectionCount -gt 0) {
            if ($sectionCount -eq 1) {
                $title = "[api-monitor] {0}: '{1}' section changed ({2})" -f $name, $sectionHeading, $dateStamp
            }
            else {
                $title = "[api-monitor] {0}: {1} sections changed ({2})" -f $name, $sectionCount, $dateStamp
            }
        }
        $body = Get-IssueBody -Name $name -Provider ([string]$src.provider) -Url ([string]$src.url) `
            -ShortHash $shortHash -Snippet $snippet -Areas $match.matched -Patterns $match.patterns `
            -Contexts $match.contexts -Hash $hash
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
            $newNum = [int]$Matches[1]
            Write-Result ("[api-monitor] {0}: CHANGED (issue #{1})" -f $name, $newNum)

            # 7b) one open issue per source: the new alert supersedes any older open
            # alert of the SAME source, so close those (newest wins). This is cleanup
            # only - the state has already advanced above, so a close failure is just a
            # warning (the end-of-run sanitize retries it on the next run).
            try {
                $sameSource = Invoke-GhListOpenIssues
                foreach ($old in $sameSource) {
                    $oldNum = [int]$old.number
                    if ($oldNum -eq $newNum -or $oldNum -le 0) { continue }
                    # Same validated extraction as the end-of-run sanitize: only an
                    # official footer (or the last marker) naming a KNOWN source
                    # counts, so a marker pasted from untrusted upstream text can
                    # never close another source's issue.
                    $oldSource = Get-SourceNameFromIssueBody -Body ([string]$old.body)
                    if (-not $oldSource -or $oldSource -ne $name) { continue }
                    $closed = Invoke-GhCloseIssue -Number $oldNum -Comment ("Superseded by #{0} - see the new alert." -f $newNum)
                    if ($closed) {
                        Write-Result ("[api-monitor] {0}: closed old issue #{1} (superseded by #{2})" -f $name, $oldNum, $newNum)
                    }
                }
            }
            catch {
                Write-Warning ('api-monitor: {0}: superseded-issue cleanup skipped: {1}' -f $name, $_.Exception.Message)
            }
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
# Self-sanitize: at most one open issue per source
# ---------------------------------------------------------------------------
# Safety net for the one-alert-per-source rule (supersede on open + cooldown): if
# duplicates ever pile up (manual re-runs, a close that failed earlier, a state
# reset), keep only the newest (highest number) open issue of each source and close
# the rest. Never affects the run result: any failure is a warning. Attribution uses
# Get-SourceNameFromIssueBody, so an issue is only touched when its official footer
# (or last marker) names a known source from sources.json - untrusted text quoted in
# the snippet can never steer the cleanup to another source.
if (-not $DryRun -and -not $BakeBaseline) {
    try {
        $allOpen = Invoke-GhListOpenIssues
        $bySource = @{}
        foreach ($issue in $allOpen) {
            $issueNum = [int]$issue.number
            if ($issueNum -le 0) { continue }
            $markerName = Get-SourceNameFromIssueBody -Body ([string]$issue.body)
            if (-not $markerName) { continue }
            if ($bySource.ContainsKey($markerName)) {
                $bySource[$markerName] += $issueNum
            }
            else {
                $bySource[$markerName] = @($issueNum)
            }
        }
        foreach ($markerName in @($bySource.Keys)) {
            $nums = @($bySource[$markerName] | Sort-Object -Unique)
            if ($nums.Count -le 1) { continue }
            $keepNum = [int]$nums[$nums.Count - 1]
            foreach ($n in $nums) {
                if ([int]$n -eq $keepNum) { continue }
                $closed = Invoke-GhCloseIssue -Number ([int]$n) -Comment ("Old alert - superseded by #{0}." -f $keepNum)
                if ($closed) {
                    Write-Result ("[api-monitor] {0}: closed duplicate issue #{1} (keeping #{2})" -f $markerName, $n, $keepNum)
                }
            }
        }
    }
    catch {
        Write-Warning ('api-monitor: duplicate-issue cleanup skipped: {0}' -f $_.Exception.Message)
    }
}

# ---------------------------------------------------------------------------
# Finalize
# ---------------------------------------------------------------------------
# A state-write failure (disk full, locked file, ACL) is a PARTIAL failure: with
# EAP=Stop it would otherwise kill the script before the RESULT/summary and exit
# as a "total failure". Tolerate it (documented exit semantics: 0 = ok with
# partial failures) - report clearly and keep going; the next run re-writes it.
if (-not $DryRun) {
    try {
        $null = Write-StateFile
    }
    catch {
        $msg = ('ERROR writing state.json: {0}' -f $_.Exception.Message)
        Write-Warning $msg
        $script:failures.Add($msg)
    }
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
