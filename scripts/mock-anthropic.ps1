<#
.SYNOPSIS
  Local mock of the Anthropic Messages API (POST /v1/messages) for offline testing of the
  AiRouterProxy /anthropic route - no account, no API key, no cost.

.DESCRIPTION
  Emulates the two response shapes of api.anthropic.com:
    - SSE stream when the request body has "stream": true
    - JSON when stream is false/absent
  Enforces the same contract the real API does:
    - 400 when the "anthropic-version" header is missing (proves the proxy forwards it)
    - 401 when "Authorization: Bearer" is missing/empty (proves the proxy injects the route key)
  Responses carry representative `request-id` + `anthropic-ratelimit-*` headers
  (requests / input-tokens / output-tokens / tokens × limit-remaining-reset) so the proxy's
  response-header forwarding (HeadersToForward) can be verified offline, without a real account.
  Logs what arrived (version header, model, stream flag, redaction mask) so the proxy
  plumbing can be verified end to end.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\mock-anthropic.ps1
  # listens on http://127.0.0.1:9999/ - Ctrl+C to stop
#>
param(
    [int]$Port = 9999,
    [string]$Prefix = "http://127.0.0.1:$Port/"
)

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add($Prefix)
try {
    $listener.Start()
    Write-Host "mock anthropic listening on $Prefix (Ctrl+C to stop)" -ForegroundColor Green
}
catch {
    Write-Host "Could not start listener on $Prefix -> $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

function Set-RateLimitHeaders([System.Net.HttpListenerResponse]$response) {
    $reset = "2026-11-13T10:00:00Z"   # fixed representative timestamp (ISO 8601, like the real API)
    $response.Headers.Add("request-id", "req_mock_0001")
    $response.Headers.Add("anthropic-ratelimit-requests-limit", "100")
    $response.Headers.Add("anthropic-ratelimit-requests-remaining", "99")
    $response.Headers.Add("anthropic-ratelimit-requests-reset", $reset)
    $response.Headers.Add("anthropic-ratelimit-input-tokens-limit", "111000")
    $response.Headers.Add("anthropic-ratelimit-input-tokens-remaining", "110900")
    $response.Headers.Add("anthropic-ratelimit-input-tokens-reset", $reset)
    $response.Headers.Add("anthropic-ratelimit-output-tokens-limit", "111000")
    $response.Headers.Add("anthropic-ratelimit-output-tokens-remaining", "110950")
    $response.Headers.Add("anthropic-ratelimit-output-tokens-reset", $reset)
    $response.Headers.Add("anthropic-ratelimit-tokens-limit", "222000")
    $response.Headers.Add("anthropic-ratelimit-tokens-remaining", "221850")
    $response.Headers.Add("anthropic-ratelimit-tokens-reset", $reset)
}

function Send-Json([System.Net.HttpListenerResponse]$response, [int]$status, [object]$payload) {
    Set-RateLimitHeaders $response
    $bytes = [System.Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Depth 20 -Compress))
    $response.StatusCode = $status
    $response.ContentType = "application/json; charset=utf-8"
    $response.ContentLength64 = $bytes.Length
    $response.OutputStream.Write($bytes, 0, $bytes.Length)
    $response.Close()
}

function Send-Sse([System.Net.HttpListenerResponse]$response, [string]$model) {
    Set-RateLimitHeaders $response
    $events = @()

    $events += "event: message_start" + "`n" + "data: " + (@{
        type    = "message_start"
        message = @{
            id            = "msg_mock_0001"
            type          = "message"
            role          = "assistant"
            model         = $model
            content       = @()
            stop_reason   = $null
            stop_sequence = $null
            usage         = @{ input_tokens = 11; output_tokens = 1 }
        }
    } | ConvertTo-Json -Depth 10 -Compress)

    $events += "event: content_block_start" + "`n" + "data: " + (@{
        type          = "content_block_start"
        index         = 0
        content_block = @{ type = "text"; text = "" }
    } | ConvertTo-Json -Depth 10 -Compress)

    foreach ($part in @("Hello from the ", "mock Anthropic server.")) {
        $events += "event: content_block_delta" + "`n" + "data: " + (@{
            type  = "content_block_delta"
            index = 0
            delta = @{ type = "text_delta"; text = $part }
        } | ConvertTo-Json -Depth 10 -Compress)
    }

    $events += "event: content_block_stop" + "`n" + "data: " + (@{
        type  = "content_block_stop"
        index = 0
    } | ConvertTo-Json -Depth 10 -Compress)

    $events += "event: message_delta" + "`n" + "data: " + (@{
        type  = "message_delta"
        delta = @{ stop_reason = "end_turn"; stop_sequence = $null }
        usage = @{ output_tokens = 12 }
    } | ConvertTo-Json -Depth 10 -Compress)

    $events += "event: message_stop" + "`n" + "data: " + (@{
        type = "message_stop"
    } | ConvertTo-Json -Depth 10 -Compress)

    $body = ($events -join "`n`n") + "`n`n"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
    $response.StatusCode = 200
    $response.ContentType = "text/event-stream; charset=utf-8"
    $response.ContentLength64 = $bytes.Length
    $response.OutputStream.Write($bytes, 0, $bytes.Length)
    $response.Close()
}

try {
    while ($listener.IsListening) {
        $ctx = $listener.GetContext()
        $req = $ctx.Request
        $res = $ctx.Response

        $version = [string]$req.Headers["anthropic-version"]
        $auth = [string]$req.Headers["Authorization"]

        if ($req.HttpMethod -ne "POST" -or $req.Url.AbsolutePath -ne "/v1/messages") {
            Send-Json $res 404 @{ error = @{ type = "invalid_request_error"; message = "not found. POST /v1/messages only." } }
            continue
        }

        if ([string]::IsNullOrWhiteSpace($version)) {
            Send-Json $res 400 @{ error = @{ type = "invalid_request_error"; message = "missing anthropic-version header" } }
            continue
        }

        $bearer = ""
        if ($auth -match "^Bearer\s+(.+)$") { $bearer = $matches[1].Trim() }
        if ([string]::IsNullOrWhiteSpace($bearer)) {
            Send-Json $res 401 @{ error = @{ type = "authentication_error"; message = "missing Authorization: Bearer" } }
            continue
        }

        $raw = $null
        if ($req.HasEntityBody) {
            $reader = [System.IO.StreamReader]::new($req.InputStream, $req.ContentEncoding)
            $raw = $reader.ReadToEnd()
        }

        $model = "unknown-model"
        $stream = $false
        if ($raw) {
            try {
                $body = $raw | ConvertFrom-Json
                $model = [string]$body.model
                $stream = [bool]$body.stream
            }
            catch { }
        }

        # The proxy replaces secrets with the fixed mask (U+2022 bullets) - flag it when present.
        $redacted = $false
        if ($raw -and $raw.Contains([char]0x2022)) { $redacted = $true }

        $rawLen = if ($null -eq $raw) { 0 } else { $raw.Length }
        $authTail = if ($bearer.Length -gt 6) { $bearer.Substring(0, 6) } else { $bearer }
        Write-Host ("-> POST /v1/messages  anthropic-version={0}  model={1}  stream={2}  auth={3}...  bytes={4}{5}" -f `
            $version, $model, $stream, $authTail, $rawLen, $(if ($redacted) { "  [MASK PRESENT]" } else { "" }))

        if ($stream) {
            Send-Sse $res $model
        }
        else {
            Send-Json $res 200 @{
                id            = "msg_mock_0002"
                type          = "message"
                role          = "assistant"
                model         = $model
                content       = @(@{ type = "text"; text = "Hello from the mock Anthropic server." })
                stop_reason   = "end_turn"
                stop_sequence = $null
                usage         = @{ input_tokens = 11; output_tokens = 12 }
            }
        }
    }
}
finally {
    $listener.Stop()
    $listener.Close()
}
