// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.Metrics;

namespace ArcForges.Observability.Desktop;

internal sealed class OtlpMetricCollector : IDisposable
{
    private readonly object _gate = new();
    private readonly MeterListener _listener = new();
    private readonly Dictionary<Instrument, Dictionary<string, Series>> _series = new();
    private readonly OtlpHttpExporter _exporter;
    private readonly TelemetryConsent _consent;
    private readonly TimeProvider _time;
    private readonly ObservabilityContext _identity;
    private bool _disposed;

    internal OtlpMetricCollector(OtlpHttpExporter exporter, TelemetryConsent consent, ObservabilityContext identity, TimeProvider time)
    {
        _exporter = exporter;
        _consent = consent;
        _identity = identity;
        _time = time;
        _listener.InstrumentPublished = Published;
        _listener.MeasurementsCompleted = (instrument, _) => { lock (_gate) _series.Remove(instrument); };
        _listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) => Measure(instrument, value, tags));
        _listener.SetMeasurementEventCallback<int>((instrument, value, tags, _) => Measure(instrument, value, tags));
        _listener.SetMeasurementEventCallback<double>((instrument, value, tags, _) => Measure(instrument, value, tags));
        _listener.Start();
    }

    internal void Collect() => _listener.RecordObservableInstruments();

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _disposed = true;
            _series.Clear();
        }
        _listener.Dispose();
    }

    private void Published(Instrument instrument, MeterListener listener)
    {
        if (instrument.Meter.Name is not (SignalEmitter.MeterName or TracePolicy.MeterName) || !Known(instrument.Name)
            || !KnownShape(instrument)
            || !MatchesIdentity(instrument.Meter.Tags)) return;
        lock (_gate)
        {
            if (_disposed || _series.Count >= 16 || !_series.TryAdd(instrument, new(StringComparer.Ordinal))) return;
            listener.EnableMeasurementEvents(instrument);
        }
    }

    private bool MatchesIdentity(IEnumerable<KeyValuePair<string, object?>>? tags)
    {
        if (tags is null) return false;
        var identity = RedactionProcessor.ScrubFields(tags);
        return identity.TryGetValue("application.id", out object? application) && Equals(application, _identity.ApplicationId)
            && identity.TryGetValue("instance.id", out object? instance) && Equals(instance, _identity.InstanceId.Value.ToString("N"))
            && identity.TryGetValue("build.id", out object? build) && Equals(build, _identity.BuildId)
            && identity.TryGetValue("deployment.environment", out object? environment) && Equals(environment, _identity.Environment.ToString());
    }

    private void Measure(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
    {
        if (!double.IsFinite(value) || value < 0) return;
        IReadOnlyDictionary<string, object?> labels = MetricLabelPolicy.ScrubLabels(tags.ToArray());
        string key = labels.TryGetValue("service.name", out object? service) ? (string)service! : "";
        lock (_gate)
        {
            if (_disposed || !_series.TryGetValue(instrument, out Dictionary<string, Series>? points)) return;
            long epoch = _consent.Revocations;
            DateTimeOffset now = _time.GetUtcNow();
            if (!points.TryGetValue(key, out Series? previous) || previous.Epoch != epoch)
            {
                if (points.Count >= MetricLabelPolicy.MaximumSeriesPerInstrument && previous is null) return;
                previous = new(epoch, now, value, _consent.IsGranted);
                points[key] = previous;
                // Observable counters must first establish a baseline after every grant/epoch: earlier consent-free
                // cumulative activity is never retroactively uploaded. Synchronous instruments are deltas already.
                if (instrument is ObservableCounter<long> || !_consent.IsGranted) return;
            }
            if (!_consent.IsGranted) { points[key] = new(epoch, now, value, false); return; }
            MetricShape shape = instrument.Name == "arcf_signal_duration" ? MetricShape.Histogram
                : instrument.Name == "arcf_trace_buffer_bytes" ? MetricShape.Gauge : MetricShape.DeltaSum;
            double exportValue = value;
            if (instrument is ObservableCounter<long>)
            {
                if (!previous.Granted) { points[key] = new(epoch, now, value, true); return; }
                exportValue = value - previous.Value;
                if (exportValue < 0) { points[key] = new(epoch, now, value, true); return; }
            }
            DateTimeOffset start = previous.At < now ? previous.At : now.AddTicks(-1);
            points[key] = new(epoch, now, value, true);
            _exporter.Metric(instrument.Name, shape, exportValue, labels, start, now);
        }
    }

    private static bool Known(string name) => name is
        "arcf_signal_count" or "arcf_signal_duration" or "arcf_span_error_count" or "arcf_trace_span_head_sampled"
        or "arcf_trace_span_promoted" or "arcf_trace_span_lost_overflow" or "arcf_trace_span_lost_late"
        or "arcf_trace_span_lost_oversize" or "arcf_trace_error_span_not_retained" or "arcf_trace_buffer_bytes";

    private static bool KnownShape(Instrument instrument) => instrument.Name switch
    {
        "arcf_signal_duration" => instrument is Histogram<double>,
        "arcf_signal_count" or "arcf_span_error_count" => instrument is Counter<long>,
        "arcf_trace_buffer_bytes" => instrument is ObservableGauge<long>,
        _ => instrument is ObservableCounter<long>,
    };

    private sealed record Series(long Epoch, DateTimeOffset At, double Value, bool Granted);
}
