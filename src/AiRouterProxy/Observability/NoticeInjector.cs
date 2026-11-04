using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AIRouterProxy;

/// <summary>
/// Injects a user-readable notice at the end of the model's response when the proxy
/// redacted sensitive content in the request.
/// SSE: detects the stream family (chat-completions, Responses API or Anthropic) and injects
/// an appropriate event before "data: [DONE]". JSON: appends to the last choice (chat) or the
/// last output (Responses API). If the transform cannot be done safely, returns
/// null (the original body stays intact and the notice stays in the header + activity).
/// </summary>
public static class NoticeInjector
{
    /// <summary>Returns the transformed body, or null when there is no safe way to inject.</summary>
    public static byte[]? Inject(byte[] body, string contentType, string notice)
    {
        if (body is null || body.Length == 0)
        {
            return null;
        }

        if (contentType.Contains("text/event-stream", StringComparison.OrdinalIgnoreCase))
        {
            return InjectSse(body, notice);
        }

        if (contentType.Contains("application/json", StringComparison.OrdinalIgnoreCase))
        {
            return InjectJson(body, notice);
        }

        return null;
    }

    // ------------------------------------------------------------------
    // SSE
    // ------------------------------------------------------------------

    private static byte[] InjectSse(byte[] body, string notice)
    {
        var text = Encoding.UTF8.GetString(body);
        const string done = "data: [DONE]";

        // Responses API
        if (text.Contains("\"type\":\"response.output_text.delta\"", StringComparison.Ordinal)
            || text.Contains("event: response.output_text", StringComparison.Ordinal))
        {
            var chunk = "event: response.output_text.delta\ndata: "
                + Serialize(new { type = "response.output_text.delta", delta = "\n\n" + notice }) + "\n\n";
            return InsertSseChunk(text, chunk, done);
        }

        // Anthropic (evento + data)
        if (text.Contains("\"type\":\"content_block_delta\"", StringComparison.Ordinal)
            || text.Contains("event: content_block_delta", StringComparison.Ordinal))
        {
            var chunk = "event: content_block_delta\ndata: "
                + Serialize(new
                {
                    type = "content_block_delta",
                    index = 0,
                    delta = new { type = "text_delta", text = "\n\n" + notice },
                }) + "\n\n";
            return InsertSseChunk(text, chunk, done);
        }

        // Default: chat completions (OpenAI-compatible) - content delta.
        var chatChunk = "\ndata: " + Serialize(new
        {
            choices = new[]
            {
                new { delta = new { content = "\n\n" + notice } },
            },
        }) + "\n\n";
        return InsertSseChunk(text, chatChunk, done);
    }

    private static byte[] InsertSseChunk(string text, string chunk, string done)
    {
        var index = text.LastIndexOf(done, StringComparison.Ordinal);
        return Encoding.UTF8.GetBytes(index >= 0 ? text.Insert(index, chunk) : text + "\n" + chunk);
    }

    // ------------------------------------------------------------------
    // Non-streaming JSON (chat completions and Responses API)
    // ------------------------------------------------------------------

    private static byte[]? InjectJson(byte[] body, string notice)
    {
        JsonNode? root;
        try
        {
            root = JsonNode.Parse(body, documentOptions: new JsonDocumentOptions { MaxDepth = 128 });
        }
        catch (JsonException)
        {
            return null;
        }

        var done = TryAppendToLastChoice(root, notice) || TryAppendToResponsesOutput(root, notice);

        return done ? JsonSerializer.SerializeToUtf8Bytes(root, JsonOptions) : null;
    }

    private static bool TryAppendToLastChoice(JsonNode? root, string notice)
    {
        if (root is not JsonObject obj
            || obj["choices"] is not JsonArray choices
            || choices.Count == 0
            || choices[^1] is not JsonObject choice
            || choice["message"] is not JsonObject message)
        {
            return false;
        }

        var content = message["content"];

        if (content is null)
        {
            message["content"] = notice;
            return true;
        }

        if (content is JsonValue value && value.TryGetValue<string>(out var text))
        {
            message["content"] = text + "\n\n" + notice;
            return true;
        }

        return content is JsonArray parts && AppendTextPart(parts, notice, "text");
    }

    private static bool TryAppendToResponsesOutput(JsonNode? root, string notice)
    {
        if (root is not JsonObject obj
            || obj["output"] is not JsonArray output
            || output.Count == 0)
        {
            return false;
        }

        for (var i = output.Count - 1; i >= 0; i--)
        {
            if (output[i] is not JsonObject item || item["type"]?.GetValue<string>() != "message")
            {
                continue;
            }

            if (item["content"] is JsonArray parts)
            {
                return AppendTextPart(parts, notice, "output_text");
            }

            item["content"] = new JsonArray(new JsonObject { ["type"] = "output_text", ["text"] = notice });
            return true;
        }

        return false;
    }

    /// <summary>Appends the notice to the last text part, or creates a new part.</summary>
    private static bool AppendTextPart(JsonArray parts, string notice, string partType)
    {
        for (var i = parts.Count - 1; i >= 0; i--)
        {
            if (parts[i] is JsonObject part
                && part["type"]?.GetValue<string>() == partType)
            {
                var partText = part["text"]?.GetValue<string>();
                part["text"] = partText + "\n\n" + notice;
                return true;
            }
        }

        parts.Add(new JsonObject { ["type"] = partType, ["text"] = notice });
        return true;
    }

    private static string Serialize(object payload)
        => JsonSerializer.Serialize(payload, JsonOptions);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };
}
