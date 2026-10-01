// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Observability;

/// <summary>
/// Known-sensitive header and field names (observability architecture RD-01 and RD-05). This is the scrubbing
/// processor's named second line of defence, not the primary control: a field that is not in the reviewed export
/// vocabulary is dropped whether or not its name appears here. The same lists are recorded in
/// <c>eng/policy/telemetry-policy.json</c> and a test keeps both identical.
/// </summary>
internal static class SensitiveFieldNames
{
    /// <summary>Whole names, compared case-insensitively after removing every separator ("X-Api-Key" is "xapikey").</summary>
    internal static IReadOnlyList<string> ExactNames { get; } = Array.AsReadOnly(
    [
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-amz-security-token",
    ]);

    /// <summary>A name is sensitive when any one of its words (split on separators and camel-case boundaries) is listed.</summary>
    internal static IReadOnlyList<string> Segments { get; } = Array.AsReadOnly(
    [
        // Credentials, secrets and one-time material.
        "auth", "authorization", "bearer", "byok", "cookie", "cookies", "credential", "credentials", "jwt", "otp",
        "passkey", "passkeys", "passwd", "password", "passwords", "secret", "secrets", "token", "tokens",
        // Request and response carriers that may hold any of the above.
        "header", "headers",
        // User and model content.
        "prompt", "prompts", "completion", "completions", "message", "messages", "content", "contents", "body",
        "payload", "payloads", "text", "note", "notes", "annotation", "annotations", "attachment", "attachments",
        "document", "documents",
        // File paths and raw URLs.
        "file", "files", "filename", "filepath", "path", "paths", "directory", "folder", "url", "uri", "query",
        "querystring",
        // Exception text that can embed user input (RD-07).
        "exception", "stacktrace", "stack",
    ]);

    /// <summary>A name is also sensitive when it contains these words one directly after the other.</summary>
    internal static IReadOnlyList<IReadOnlyList<string>> Sequences { get; } = Array.AsReadOnly<IReadOnlyList<string>>(
    [
        Array.AsReadOnly(["api", "key"]),
        Array.AsReadOnly(["private", "key"]),
        Array.AsReadOnly(["access", "key"]),
        Array.AsReadOnly(["signing", "key"]),
        Array.AsReadOnly(["one", "time", "code"]),
        Array.AsReadOnly(["raw", "sync"]),
    ]);

    private static readonly HashSet<string> JoinedExact = new(ExactNames.Select(Join), StringComparer.OrdinalIgnoreCase);
    private static readonly HashSet<string> SegmentSet = new(Segments, StringComparer.OrdinalIgnoreCase);

    /// <summary>True when the name matches a known-sensitive header or field name. Empty names are treated as sensitive.</summary>
    internal static bool IsSensitive(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return true;
        }

        string joined = Join(name);
        if (JoinedExact.Contains(joined))
        {
            return true;
        }

        List<string> words = Split(name);
        if (words.Any(SegmentSet.Contains))
        {
            return true;
        }

        foreach (IReadOnlyList<string> sequence in Sequences)
        {
            for (int start = 0; start + sequence.Count <= words.Count; start++)
            {
                bool match = true;
                for (int offset = 0; offset < sequence.Count && match; offset++)
                {
                    match = string.Equals(words[start + offset], sequence[offset], StringComparison.OrdinalIgnoreCase);
                }

                if (match)
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static string Join(string name)
    {
        var builder = new System.Text.StringBuilder(name.Length);
        foreach (char character in name)
        {
            if (char.IsLetterOrDigit(character))
            {
                builder.Append(character);
            }
        }

        return builder.ToString();
    }

    private static List<string> Split(string name)
    {
        var words = new List<string>();
        int start = -1;
        for (int index = 0; index < name.Length; index++)
        {
            char current = name[index];
            if (!char.IsLetterOrDigit(current))
            {
                Flush(words, name, ref start, index);
                continue;
            }

            if (start >= 0 && StartsNewWord(name, index))
            {
                Flush(words, name, ref start, index);
            }

            if (start < 0)
            {
                start = index;
            }
        }

        Flush(words, name, ref start, name.Length);
        return words;
    }

    private static bool StartsNewWord(string name, int index)
    {
        char previous = name[index - 1];
        char current = name[index];
        return (char.IsLower(previous) && char.IsUpper(current))
            || (char.IsUpper(previous) && char.IsUpper(current) && index + 1 < name.Length && char.IsLower(name[index + 1]));
    }

    private static void Flush(List<string> words, string name, ref int start, int end)
    {
        if (start >= 0)
        {
            words.Add(name[start..end]);
            start = -1;
        }
    }
}
