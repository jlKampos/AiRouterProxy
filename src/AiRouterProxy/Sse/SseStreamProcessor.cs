using System.Threading;
using System.Threading.Tasks;

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
/// The protocol family is resolved on the first event through SseProtocolRegistry; each
/// ISseProtocolAdapter classifies terminal events and builds the notice chunk for its own
/// protocol. This keeps the streaming behavior protocol-independent: adding a new protocol
/// is a new adapter, never a change to this processor.
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
                if (state.ResolveAdapter(e).Classify(e) == SseEventKind.Terminal)
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
        private ISseProtocolAdapter? _adapter;
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

        /// <summary>
        /// Returns the stream's protocol adapter, resolving it once on the first event
        /// (a stream is homogeneous; the protocol never changes mid-stream).
        /// </summary>
        public ISseProtocolAdapter ResolveAdapter(SseEvent e)
        {
            if (_adapter is null)
            {
                _adapter = SseProtocolRegistry.Resolve(e);
            }

            return _adapter;
        }

        public async ValueTask HoldAsync(Stream destination, SseEvent e, CancellationToken cancellationToken)
        {
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
            if (_terminated)
            {
                // A terminal event already ended the stream (e.g. content_block_stop on an
                // Anthropic stream that later emits message_stop): the notice was injected
                // exactly once, before the first terminal. Drain everything through this
                // second terminal without injecting again.
                await FlushUpToAsync(destination, terminal.EndOffset, cancellationToken);
                _held = null;
                return;
            }

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
                if (_adapter is null)
                {
                    _adapter = SseProtocolRegistry.Resolve(finalEvent);
                }

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
                if (_adapter is null && finalEvent is not null)
                {
                    _adapter = SseProtocolRegistry.Resolve(finalEvent);
                }

                await WriteNoticeAsync(destination, cancellationToken);
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
            await destination.WriteAsync(_adapter!.BuildNoticeChunk(_notice), cancellationToken);
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
}
