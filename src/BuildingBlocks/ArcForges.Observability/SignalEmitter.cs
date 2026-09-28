// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace ArcForges.Observability;

/// <summary>
/// The single emission surface for metrics, traces, and structured events. High-cardinality identifiers
/// are attached to traces/events and instrumentation-scope identity; metrics use only the optional,
/// closed-vocabulary service dimension as a point label.
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

    /// <summary>Emits an event from the finite, reviewed telemetry vocabulary.</summary>
    public StructuredSignal Emit(SignalEventName eventName, SignalLevel level)
    {
        ValidateEventName(eventName);
        if (!Enum.IsDefined(level))
        {
            throw new ArgumentOutOfRangeException(nameof(level));
        }

        string stableEventName = EventName(eventName);

        var context = ObservabilityScope.Current
            ?? throw new InvalidOperationException("A complete observability context must be installed before emitting a signal.");
        var properties = context.MaterializeDimensions();
        var metrics = GetMetrics(context);
        var timestamp = DateTimeOffset.UtcNow;
        var signal = new StructuredSignal(stableEventName, level, timestamp, properties);

        using (var activity = Activities.StartActivity(stableEventName, ActivityKind.Internal))
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

            TagList metricTags = default;
            if (context.Service is { } service)
            {
                metricTags.Add("service.name", service.ToString());
            }

            metrics.SignalCount.Add(1, in metricTags);
            if (context.Duration is { } duration)
            {
                metrics.SignalDuration.Record(duration.TotalMilliseconds, in metricTags);
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

    private static Meter CreateMeter(SignalIdentity identity) => new(new MeterOptions(MeterName)
    {
        Tags = new KeyValuePair<string, object?>[]
        {
            new("application.id", identity.ApplicationId),
            new("instance.id", identity.InstanceId),
            new("build.id", identity.BuildId),
            new("deployment.environment", identity.Environment.ToString()),
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

    private readonly record struct SignalIdentity(string ApplicationId, string InstanceId, string BuildId, SignalEnvironment Environment)
    {
        public static SignalIdentity From(ObservabilityContext context) => new(context.ApplicationId,
            context.InstanceId.Value.ToString("N", System.Globalization.CultureInfo.InvariantCulture), context.BuildId,
            context.Environment);
    }

    private static string EventName(SignalEventName eventName) => eventName switch
    {
        SignalEventName.ApplicationStarted => "application.started",
        SignalEventName.StorageCommitted => "storage.commit",
        SignalEventName.SecretUsed => "secret.used",
        SignalEventName.OperationCompleted => "operation.completed",
        SignalEventName.OperationFailed => "operation.failed",
        SignalEventName.HealthChanged => "health.changed",
        _ => throw new ArgumentOutOfRangeException(nameof(eventName)),
    };

    private static void ValidateEventName(SignalEventName eventName)
    {
        if (!Enum.IsDefined(eventName)) throw new ArgumentOutOfRangeException(nameof(eventName));
    }

}
