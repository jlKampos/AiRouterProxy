using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace AIRouterProxy;

/// <summary>
/// Streams an SSE response through while injecting a redaction notice as a well-formed SSE
/// event just before the terminal "[DONE]" (or appended at the end when the stream has no
/// terminator, mirroring NoticeInjector's behavior).
///
/// Incremental: only the current event is held back until the next one completes (a one-event
/// look-behind needed to know where to place the notice); everything else flows as it arrives,
/// and the raw bytes are replayed verbatim. When the notice is empty the stream is passed
/// through byte-for-byte.
///
/// Protocol detection (chat / Responses API / Anthropic) is a lightweight mirror of
/// NoticeInjector; Sprint 5 will replace it with the adapter-based detection.
/// </summary>
public static class SseStreamProcessor
{
    public static async Task ProcessAsync(
        Stream source,
        Stream destination,
        string notice,
        CancellationToken cancellationToken,
        int readBufferSize = 81920)
    {
        if (source is null || destination is null)
        {
            return;
        }

        var parser = new SseParser();
        var state = new State(notice);
        var buffer = new byte[Math.Clamp(readBufferSize, 1, 1 << 20)];

        int read;
        while ((read = await source.ReadAsync(buffer.AsMemory(), cancellationToken)) > 0)
        {
            state.Append(buffer.AsMemory(0, read));
            var events = parser.Feed(buffer.AsSpan(0, read));

            foreach (var e in events)
            {
                if (e.IsDone)
                {
                    await state.TerminateAsync(destination, e, cancellationToken);
                }
                else
                {
                    await state.HoldAsync(destination, e, cancellationToken);
                }
            }
        }

        await state.FinishAsync(destination, parser.EndOfStream(), cancellationToken);
        await destination.FlushAsync(cancellationToken);
    }

    // ------------------------------------------------------------------

    private sealed class State
    {
        private const int CompactionThreshold = 64 * 1024;

        private readonly string _notice;
        private readonly MemoryStream _raw = new();
        private long _rawBase;   // absolute offset of _raw[0]
        private long _flushed;   // absolute offset already written to the destination
        private SseEvent? _held; // last complete event not yet written (one-event look-behind)
        private string? _protocol;
        private bool _sawEvent;
        private bool _terminated;

        public State(string notice)
        {
            _notice = notice;
        }

        public void Append(ReadOnlyMemory<byte> bytes)
        {
            _raw.Write(bytes.Span);
        }

        public async ValueTask HoldAsync(Stream destination, SseEvent e, CancellationToken cancellationToken)
        {
            TrackProtocol(e);
            _sawEvent = true;

            // A *new* non-terminal event completed, so the previously held one is safe to flush
            // (it is not immediately before the terminal event).
            if (_held is not null)
            {
                await FlushUpToAsync(destination, _held.EndOffset, cancellationToken);
            }

            _held = e;
        }

        public async ValueTask TerminateAsync(Stream destination, SseEvent terminal, CancellationToken cancellationToken)
        {
            // Everything up to the terminal event (including the held one), then the notice,
            // then the terminal event itself.
            await FlushUpToAsync(destination, terminal.StartOffset, cancellationToken);
            if (!string.IsNullOrEmpty(_notice))
            {
                await WriteNoticeAsync(destination, cancellationToken);
            }

            await FlushUpToAsync(destination, terminal.EndOffset, cancellationToken);
            _held = null;
            _sawEvent = true;
            _terminated = true;
        }

        public async ValueTask FinishAsync(Stream destination, SseEvent? finalEvent, CancellationToken cancellationToken)
        {
            if (finalEvent is { IsDone: true })
            {
                // Trailing "[DONE]" without a blank-line terminator: notice still goes before it.
                await FlushUpToAsync(destination, finalEvent.StartOffset, cancellationToken);
                if (!string.IsNullOrEmpty(_notice))
                {
                    await WriteNoticeAsync(destination, cancellationToken);
                }

                await FlushUpToAsync(destination, finalEvent.EndOffset, cancellationToken);
                _terminated = true;
                return;
            }

            if (_terminated)
            {
                // A "[DONE]" was already handled during streaming: the notice was injected once;
                // just drain whatever (rare) bytes may have arrived after it.
                await FlushUpToAsync(destination, _rawBase + _raw.Length, cancellationToken);
                return;
            }

            if (_held is not null)
            {
                await FlushUpToAsync(destination, _held.EndOffset, cancellationToken);
            }

            await FlushUpToAsync(destination, _rawBase + _raw.Length, cancellationToken); // trailing partial

            // Stream ended with no terminator: append the notice at the very end (matches
            // NoticeInjector's behavior on a stream without "[DONE]").
            if (!string.IsNullOrEmpty(_notice) && (_sawEvent || finalEvent is not null))
            {
                await WriteNoticeAsync(destination, cancellationToken);
            }
        }

        private void TrackProtocol(SseEvent e)
        {
            if (_protocol is not null)
            {
                return;
            }

            if ((e.EventName is not null && e.EventName.StartsWith("response.", StringComparison.Ordinal))
                || e.Data.Contains("\"type\":\"response.output_text.delta\"", StringComparison.Ordinal))
            {
                _protocol = "responses";
                return;
            }

            if (e.EventName == "content_block_delta"
                || e.Data.Contains("\"type\":\"content_block_delta\"", StringComparison.Ordinal))
            {
                _protocol = "anthropic";
            }
        }

        private async ValueTask FlushUpToAsync(Stream destination, long absoluteEnd, CancellationToken cancellationToken)
        {
            if (absoluteEnd <= _flushed)
            {
                return;
            }

            var count = (int)(absoluteEnd - _flushed);
            var offset = (int)(_flushed - _rawBase);
            await destination.WriteAsync(_raw.GetBuffer().AsMemory(offset, count), cancellationToken);
            _flushed = absoluteEnd;
            Compact();
        }

        private async ValueTask WriteNoticeAsync(Stream destination, CancellationToken cancellationToken)
        {
            await destination.WriteAsync(BuildNoticeChunk(_protocol, _notice), cancellationToken);
        }

        private void Compact()
        {
            var consumed = (int)(_flushed - _rawBase);
            if (consumed < CompactionThreshold)
            {
                return;
            }

            var remaining = (int)(_raw.Length - consumed);
            if (remaining <= 0)
            {
                _raw.SetLength(0);
                _rawBase = _flushed;
                return;
            }

            var tail = new byte[remaining];
            Array.Copy(_raw.GetBuffer(), consumed, tail, 0, remaining);
            _raw.SetLength(0);
            _raw.Write(tail);
            _rawBase = _flushed;
        }
    }

    private static byte[] BuildNoticeChunk(string? protocol, string notice)
    {
        var options = new JsonSerializerOptions { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
        string payload;
        string prefix;

        switch (protocol)
        {
            case "responses":
                payload = JsonSerializer.Serialize(
                    new { type = "response.output_text.delta", delta = "\n\n" + notice }, options);
                prefix = "event: response.output_text.delta\ndata: ";
                break;

            case "anthropic":
                payload = JsonSerializer.Serialize(new
                {
                    type = "content_block_delta",
                    index = 0,
                    delta = new { type = "text_delta", text = "\n\n" + notice },
                }, options);
                prefix = "event: content_block_delta\ndata: ";
                break;

            default: // chat completions (OpenAI-compatible)
                payload = JsonSerializer.Serialize(new
                {
                    choices = new[] { new { delta = new { content = "\n\n" + notice } } },
                }, options);
                prefix = "\ndata: ";
                break;
        }

        return Encoding.UTF8.GetBytes(prefix + payload + "\n\n");
    }
}
