// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.ObjectModel;
using System.Diagnostics;

namespace ArcForges.Observability;

/// <summary>An export-safe, immutable copy of one finished span: only reviewed fields, never the live <see cref="Activity"/>.</summary>
public sealed class ScrubbedSpan
{
    internal ScrubbedSpan(string sourceName, string name, string traceId, string spanId, string? parentSpanId,
        ActivityKind kind, DateTime startTimeUtc, TimeSpan duration, ActivityStatusCode status,
        IReadOnlyDictionary<string, object?> tags, IReadOnlyList<ScrubbedSpanEvent> events)
    {
        SourceName = sourceName;
        Name = name;
        TraceId = traceId;
        SpanId = spanId;
        ParentSpanId = parentSpanId;
        Kind = kind;
        StartTimeUtc = startTimeUtc;
        Duration = duration;
        Status = status;
        Tags = tags;
        Events = events;
    }

    public string SourceName { get; }
    public string Name { get; }
    public string TraceId { get; }
    public string SpanId { get; }
    public string? ParentSpanId { get; }
    public ActivityKind Kind { get; }
    public DateTime StartTimeUtc { get; }
    public TimeSpan Duration { get; }

    /// <summary>The status code only. A status description is free text and is never exported.</summary>
    public ActivityStatusCode Status { get; }

    public IReadOnlyDictionary<string, object?> Tags { get; }
    public IReadOnlyList<ScrubbedSpanEvent> Events { get; }
}

/// <summary>A span event reduced to its name, time and reviewed fields.</summary>
public sealed class ScrubbedSpanEvent
{
    internal ScrubbedSpanEvent(string name, DateTimeOffset timestamp, IReadOnlyDictionary<string, object?> tags)
    {
        Name = name;
        Timestamp = timestamp;
        Tags = tags;
    }

    public string Name { get; }
    public DateTimeOffset Timestamp { get; }
    public IReadOnlyDictionary<string, object?> Tags { get; }
}

/// <summary>
/// The scrubbing processor that every ArcForges signal passes through; it runs in the telemetry pipeline as a second line of defence (observability
/// architecture RD-05). It is a safety net behind the typed emission surface, which has no free-text field to leak
/// through. Whatever reaches it, only a field that is in the reviewed export vocabulary, is not a known-sensitive
/// header or field name, and carries exactly the reviewed value shape for its field is exported. Everything else,
/// including every header, cookie, token, prompt, note, path, raw URL and exception text, is removed.
/// </summary>
public static class RedactionProcessor
{
    internal const string RedactedName = "redacted";

    /// <summary>True when the name matches a known-sensitive header or field name from the reviewed list.</summary>
    public static bool IsSensitiveFieldName(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        return SensitiveFieldNames.IsSensitive(name);
    }

    /// <summary>
    /// Returns the exportable subset of the fields. A removed field leaves no trace of its value. A name that
    /// appears more than once keeps its last value, as a span does.
    /// </summary>
    public static IReadOnlyDictionary<string, object?> ScrubFields(IEnumerable<KeyValuePair<string, object?>> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);
        return new ReadOnlyDictionary<string, object?>(Scrub(fields));
    }

    /// <summary>
    /// Copies a finished span for export. Its name must be a dotted operation identifier of ASCII words, and its status
    /// description, links and baggage are dropped; its tags and event fields pass through <see cref="ScrubFields"/>.
    /// </summary>
    public static ScrubbedSpan Scrub(Activity activity)
    {
        ArgumentNullException.ThrowIfNull(activity);
        var events = new List<ScrubbedSpanEvent>();
        foreach (ActivityEvent activityEvent in activity.Events)
        {
            events.Add(new ScrubbedSpanEvent(OperationName(activityEvent.Name), activityEvent.Timestamp,
                new ReadOnlyDictionary<string, object?>(Scrub(activityEvent.Tags))));
        }

        return new ScrubbedSpan(
            OperationName(activity.Source.Name),
            OperationName(activity.DisplayName),
            activity.TraceId.ToHexString(),
            activity.SpanId.ToHexString(),
            activity.ParentSpanId == default ? null : activity.ParentSpanId.ToHexString(),
            activity.Kind,
            activity.StartTimeUtc,
            activity.Duration,
            activity.Status,
            new ReadOnlyDictionary<string, object?>(Scrub(activity.TagObjects)),
            Array.AsReadOnly(events.ToArray()));
    }

    internal static Dictionary<string, object?> Scrub(IEnumerable<KeyValuePair<string, object?>> fields)
    {
        var kept = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (KeyValuePair<string, object?> field in fields)
        {
            if (field.Key is not { Length: > 0 } name
                || SensitiveFieldNames.IsSensitive(name)
                || !TelemetryFields.TryGetRule(name, out TelemetryFieldRule? rule)
                || !TelemetryFields.IsValid(rule, field.Value))
            {
                continue;
            }

            kept[name] = field.Value;
        }

        return kept;
    }

    /// <summary>
    /// Operation names are written by instrumentation authors, not computed from data. Only a dotted identifier of
    /// ASCII words is exported; a display name such as a request line or URL becomes <see cref="RedactedName"/>.
    /// </summary>
    private static string OperationName(string? name) => IsOperationName(name) ? name! : RedactedName;

    private static bool IsOperationName(string? name)
    {
        if (name is not { Length: > 0 and <= 80 })
        {
            return false;
        }

        bool wordStart = true;
        foreach (char character in name)
        {
            if (character == '.')
            {
                if (wordStart)
                {
                    return false;
                }

                wordStart = true;
            }
            else if (char.IsAsciiLetter(character) || (!wordStart && char.IsAsciiDigit(character)))
            {
                wordStart = false;
            }
            else
            {
                return false;
            }
        }

        return !wordStart;
    }
}
