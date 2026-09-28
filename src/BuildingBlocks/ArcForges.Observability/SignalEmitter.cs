// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace ArcForges.Observability;

/// <summary>
/// The single emission surface for metrics, traces, and structured events. High-cardinality identifiers
/// are attached to traces/events and instrumentation-scope identity; metric point labels remain low-cardinality.
/// </summary>
public sealed class SignalEmitter : IDisposable
{
    public const string SourceName = "ArcForges.Observability";
    public const string MeterName = "ArcForges.Observability";

    private static readonly ActivitySource Activities = new(SourceName);
    private readonly object _metricsGate = new();
    private readonly IStructuredEventSink _sink;
    private Metrics? _metrics;
    private bool _disposed;

    public SignalEmitter(IStructuredEventSink sink)
    {
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
    }

    /// <summary>Emits one event and applies the same ambient dimensions to traces and structured logs.</summary>
    public StructuredSignal Emit(string eventName, SignalLevel level)
    {
        ValidateEventName(eventName);
        if (!Enum.IsDefined(level))
        {
            throw new ArgumentOutOfRangeException(nameof(level));
        }

        var context = ObservabilityScope.Current
            ?? throw new InvalidOperationException("A complete observability context must be installed before emitting a signal.");
        var metrics = GetMetrics(context);
        var properties = context.MaterializeDimensions();
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
            metrics.SignalCount.Add(1, metricTags);
            if (context.Duration is { } duration)
            {
                metrics.SignalDuration.Record(duration.TotalMilliseconds, metricTags);
            }

            _sink.Write(signal);
        }

        return signal;
    }

    public void Dispose()
    {
        lock (_metricsGate)
        {
            if (_disposed) return;
            _disposed = true;
            _metrics?.Dispose();
        }
    }

    private Metrics GetMetrics(ObservabilityContext context)
    {
        lock (_metricsGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_metrics is not null)
            {
                if (_metrics.Identity != SignalIdentity.From(context))
                {
                    throw new InvalidOperationException("A SignalEmitter is bound to one application/build/instance identity.");
                }

                return _metrics;
            }

            var identity = SignalIdentity.From(context);
            _metrics = new Metrics(identity);
            return _metrics;
        }
    }

    private static TagList GetMetricTags(ObservabilityContext context)
    {
        var tags = new TagList();
        if (context.Service is { } service)
        {
            tags.Add("service.name", service);
        }

        return tags;
    }

    private static Meter CreateMeter(SignalIdentity identity) => new(new MeterOptions(MeterName)
    {
        Tags = new KeyValuePair<string, object?>[]
        {
            new("application.id", identity.ApplicationId),
            new("instance.id", identity.InstanceId),
            new("build.id", identity.BuildId),
            new("deployment.environment", identity.Environment),
        },
    });

    private sealed class Metrics : IDisposable
    {
        public Metrics(SignalIdentity identity)
        {
            Identity = identity;
            Meter = CreateMeter(identity);
            try
            {
                SignalCount = Meter.CreateCounter<long>("arcf_signal_count", "{signal}");
                SignalDuration = Meter.CreateHistogram<double>("arcf_signal_duration", "ms");
            }
            catch
            {
                Meter.Dispose();
                throw;
            }
        }

        public SignalIdentity Identity { get; }
        public Meter Meter { get; }
        public Counter<long> SignalCount { get; }
        public Histogram<double> SignalDuration { get; }

        public void Dispose() => Meter.Dispose();
    }

    private readonly record struct SignalIdentity(string ApplicationId, string InstanceId, string BuildId, string Environment)
    {
        public static SignalIdentity From(ObservabilityContext context) => new(context.ApplicationId,
            context.InstanceId.Value.ToString("N", System.Globalization.CultureInfo.InvariantCulture), context.BuildId,
            context.Environment);
    }

    private static void ValidateEventName(string eventName)
    {
        if (string.IsNullOrWhiteSpace(eventName) || eventName.Length > 128 || eventName.Any(character =>
                !(character is >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '-')))
        {
            throw new ArgumentException("Event names must be bounded lowercase identifiers.", nameof(eventName));
        }
    }

}
