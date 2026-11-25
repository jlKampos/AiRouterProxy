namespace AIRouterProxy;

/// <summary>
/// Builds the visible notice appended to a response when the request body was redacted.
/// The default text is a single line: the category summary (e.g. "OpenAI key × 6") already
/// carries the information, so the old ". Detected values: ..." suffix was redundant.
/// A configured warnTemplate keeps working exactly as before ({Count}/{Kinds}/{Previews}).
/// </summary>
public static class RedactionNotice
{
    /// <param name="count">Number of redacted occurrences.</param>
    /// <param name="kinds">Category summary from <see cref="SecretRedactor.Summarize"/> (may be empty).</param>
    /// <param name="warnTemplate">Optional template; when set it wins over the default text.</param>
    /// <param name="previews">Only used by the template path ({Previews}) - kept for compatibility.</param>
    public static string Build(
        int count,
        string kinds,
        string? warnTemplate,
        IReadOnlyList<SecretRedactor.RedactionPreview>? previews)
    {
        if (!string.IsNullOrWhiteSpace(warnTemplate))
        {
            return warnTemplate
                .Replace("{Count}", count.ToString(), StringComparison.Ordinal)
                .Replace("{Kinds}", kinds, StringComparison.Ordinal)
                .Replace("{Previews}", SecretRedactor.FormatPreviews(previews), StringComparison.Ordinal);
        }

        var what = count == 1
            ? "1 sensitive value was redacted"
            : $"{count} sensitive values were redacted";

        var text = $"⚠️ **Proxy notice:** {what} before reaching the AI Router";

        if (!string.IsNullOrWhiteSpace(kinds))
        {
            text += $" ({kinds})";
        }

        return text + ".";
    }
}
