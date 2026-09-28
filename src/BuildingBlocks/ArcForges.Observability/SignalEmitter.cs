// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Globalization;

namespace ArcForges.Observability;

/// <summary>
/// The single emission surface for metrics, traces, and structured events. High-cardinality identifiers
/// are attached to traces/events only; metric labels are deliberately limited to low-cardinality identity.
/// </summary>
public sealed class SignalEmitter
{
    public const string SourceName = "ArcForges.Observability";
    public const string MeterName = "ArcForges.Observability";

    private static readonly ActivitySource Activities = new(SourceName);
    private static readonly Meter Meter = new(MeterName);
    private static readonly Counter<long> SignalCount = Meter.CreateCounter<long>("arcf_signal_count", "{signal}");
    private static readonly Histogram<double> SignalDuration = Meter.CreateHistogram<double>("arcf_signal_duration", "ms");

    private readonly IStructuredEventSink _sink;

    public SignalEmitter(IStructuredEventSink sink)
    {
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
    }

    /// <summary>Emits one event and applies the same ambient dimensions to traces and structured logs.</summary>
    public StructuredSignal Emit(
        string eventName,
        SignalLevel level,
        IReadOnlyDictionary<string, object?>? eventProperties = null)
    {
        ValidateEventName(eventName);
        if (!Enum.IsDefined(level))
        {
            throw new ArgumentOutOfRangeException(nameof(level));
        }

        var context = ObservabilityScope.Current
            ?? throw new InvalidOperationException("A complete observability context must be installed before emitting a signal.");
        var properties = context.MaterializeDimensions();
        AppendEventProperties(properties, eventProperties);
        var timestamp = DateTimeOffset.UtcNow;
        var signal = new StructuredSignal(eventName, level, timestamp, properties);

        using (var activity = Activities.StartActivity(eventName, ActivityKind.Internal))
        {
            if (activity is not null)
            {
                foreach (var property in properties)
                {
                    activity.SetTag(property.Key, property.Value);
                }

                if (level == SignalLevel.Error)
                {
                    activity.SetStatus(ActivityStatusCode.Error);
                }
            }

            var metricTags = GetMetricTags(context);
            SignalCount.Add(1, metricTags);
            if (context.Duration is { } duration)
            {
                SignalDuration.Record(duration.TotalMilliseconds, metricTags);
            }

            _sink.Write(signal);
        }

        return signal;
    }

    private static TagList GetMetricTags(ObservabilityContext context)
    {
        var tags = new TagList
        {
            { "application.id", context.ApplicationId },
            { "build.id", context.BuildId },
            { "deployment.environment", context.Environment },
        };
        if (context.Service is { } service)
        {
            tags.Add("service.name", service);
        }

        return tags;
    }

    private static void AppendEventProperties(Dictionary<string, object?> target, IReadOnlyDictionary<string, object?>? source)
    {
        if (source is null)
        {
            return;
        }

        foreach (var (key, value) in source)
        {
            ValidatePropertyName(key);
            if (target.ContainsKey(key))
            {
                throw new ArgumentException($"Event property '{key}' conflicts with a standard observability dimension.", nameof(source));
            }

            if (value is not (string or bool or byte or sbyte or short or ushort or int or uint or long or ulong or float or double or decimal or Guid))
            {
                throw new ArgumentException($"Event property '{key}' must be a non-null scalar value.", nameof(source));
            }

            if (value is string text && (text.Length > 4096 || text.Any(char.IsControl)))
            {
                throw new ArgumentException($"Event property '{key}' must be at most 4096 characters and contain no controls.", nameof(source));
            }

            if (value is float single && !float.IsFinite(single) || value is double number && !double.IsFinite(number))
            {
                throw new ArgumentException($"Event property '{key}' must be finite.", nameof(source));
            }

            target.Add(key, value is Guid guid ? guid.ToString("N", CultureInfo.InvariantCulture) : value);
        }
    }

    private static void ValidateEventName(string eventName)
    {
        if (string.IsNullOrWhiteSpace(eventName) || eventName.Length > 128 || eventName.Any(character =>
                !(character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '-')))
        {
            throw new ArgumentException("Event names must be bounded lowercase identifiers.", nameof(eventName));
        }
    }

    private static void ValidatePropertyName(string key)
    {
        if (string.IsNullOrWhiteSpace(key) || key.Length > 128 || key.Any(character =>
                !(character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '-')))
        {
            throw new ArgumentException("Event property names must be bounded lowercase identifiers.", nameof(key));
        }

        if (SensitiveFragments.Any(fragment => key.Contains(fragment, StringComparison.Ordinal)))
        {
            throw new ArgumentException("Event property names cannot describe secret or raw request content.", nameof(key));
        }
    }

    private static readonly string[] SensitiveFragments =
    [
        "secret", "password", "credential", "token", "authorization", "payload", "prompt", "content", "raw",
    ];
}
