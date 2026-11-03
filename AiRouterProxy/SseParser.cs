using System.Text;

namespace AIRouterProxy;

/// <summary>
/// Incremental, byte-level parser for Server-Sent Events (SSE). Feed raw bytes in any chunk
/// boundaries; it returns the events completed by each chunk. Handles LF and CRLF,
/// event/data/id/retry fields, multi-line data (joined with "\n"), comments, the "[DONE]"
/// terminator, and events split across arbitrary chunk boundaries.
///
/// All framing syntax is ASCII, so parsing is done on bytes and each line is only decoded to
/// text when complete (no partial-multibyte pitfalls). Event spans are absolute byte offsets
/// into the stream, so callers can slice the original bytes verbatim.
///
/// Per the SSE spec, an event is only dispatched when it carries at least one "data:" line;
/// comment-only blocks and empty events are discarded.
/// </summary>
public sealed class SseParser
{
    private readonly List<byte> _line = new();
    private EventBuilder? _current;
    private long _offset;

    private sealed class EventBuilder
    {
        public long Start;
        public string? EventName;
        public readonly List<string> DataLines = new();
        public string? Id;
        public int? Retry;
    }

    /// <summary>Feeds a chunk of raw bytes and returns the events completed by that chunk.</summary>
    public IReadOnlyList<SseEvent> Feed(ReadOnlySpan<byte> chunk)
    {
        var events = new List<SseEvent>();

        foreach (var b in chunk)
        {
            _offset++;

            if (b == (byte)'\n')
            {
                CompleteLine(events);
                _line.Clear();
            }
            else
            {
                _line.Add(b);
            }
        }

        return events;
    }

    /// <summary>
    /// End-of-stream: dispatches whatever was left without a blank-line terminator (e.g. a
    /// trailing "data: [DONE]"). Returns null when nothing is pending.
    /// </summary>
    public SseEvent? EndOfStream()
    {
        if (_current is null && _line.Count == 0)
        {
            return null;
        }

        if (_current is null)
        {
            _current = new EventBuilder { Start = _offset - _line.Count };
        }

        if (_line.Count > 0)
        {
            var text = Encoding.UTF8.GetString(_line.ToArray());
            ParseField(text, _current);
            _line.Clear();
        }

        var final = Build(_current, _offset);
        _current = null;
        return final;
    }

    private void CompleteLine(List<SseEvent> events)
    {
        if (_line.Count > 0 && _line[^1] == (byte)'\r')
        {
            _line.RemoveAt(_line.Count - 1); // CRLF
        }

        if (_line.Count == 0)
        {
            // Blank line: the event ends here. Dispatch only when it has data (spec).
            if (_current is not null)
            {
                if (_current.DataLines.Count > 0)
                {
                    events.Add(Build(_current, _offset));
                }

                _current = null;
            }

            return;
        }

        _current ??= new EventBuilder { Start = _offset - _line.Count - 1 }; // _offset already includes the '\n'
        var text = Encoding.UTF8.GetString(_line.ToArray());
        ParseField(text, _current);
    }

    private static SseEvent Build(EventBuilder builder, long endOffset)
        => new(
            builder.EventName,
            string.Join("\n", builder.DataLines),
            builder.Id,
            builder.Retry,
            builder.Start,
            endOffset);

    private static void ParseField(string line, EventBuilder builder)
    {
        if (line.Length == 0 || line[0] == ':')
        {
            return; // empty or comment line
        }

        var colon = line.IndexOf(':');
        var name = colon < 0 ? line : line[..colon];
        var value = colon < 0 ? string.Empty : line[(colon + 1)..];

        if (value.StartsWith(' '))
        {
            value = value[1..]; // spec: a single leading space is stripped
        }

        switch (name)
        {
            case "event":
                builder.EventName = value;
                break;
            case "data":
                builder.DataLines.Add(value);
                break;
            case "id":
                builder.Id = value;
                break;
            case "retry":
                if (int.TryParse(value, out var retry))
                {
                    builder.Retry = retry;
                }

                break;
        }
    }
}
