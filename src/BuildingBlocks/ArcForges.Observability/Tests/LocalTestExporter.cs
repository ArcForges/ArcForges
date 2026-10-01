// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Globalization;
using System.Text;

namespace ArcForges.Observability.Tests;

/// <summary>
/// An offline stand-in for a telemetry backend. It records everything a real exporter would be handed: structured
/// events from the sink, spans copied through the scrubbing processor exactly as a host exporter must copy them, and
/// metric instrument scope, point labels and values. It never opens a socket.
/// </summary>
internal sealed class LocalTestExporter : IStructuredEventSink, IDisposable
{
    private readonly List<StructuredSignal> _signals = [];
    private readonly List<ScrubbedSpan> _spans = [];
    private readonly List<string> _metrics = [];
    private readonly ActivityListener _activities;
    private readonly MeterListener _meters;
    private readonly object _gate = new();

    /// <param name="instance">Only emitter spans and metrics of this application instance are recorded, so tests that run concurrently cannot see one another.</param>
    /// <param name="extraActivitySources">Hostile or foreign instrumentation sources whose spans are exported through the processor.</param>
    public LocalTestExporter(ArcForges.Contracts.Foundation.Values.InstanceId instance, params string[] extraActivitySources)
    {
        string instanceTag = instance.Value.ToString("N", CultureInfo.InvariantCulture);
        var foreign = new HashSet<string>(extraActivitySources, StringComparer.Ordinal);
        _activities = new ActivityListener
        {
            ShouldListenTo = source => source.Name == SignalEmitter.SourceName || foreign.Contains(source.Name),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity =>
            {
                if (!foreign.Contains(activity.Source.Name) && !Equals(activity.GetTagItem("instance.id"), instanceTag))
                {
                    return;
                }

                ScrubbedSpan span = RedactionProcessor.Scrub(activity);
                lock (_gate)
                {
                    _spans.Add(span);
                }
            },
        };
        ActivitySource.AddActivityListener(_activities);

        _meters = new MeterListener
        {
            InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == SignalEmitter.MeterName
                    && instrument.Meter.Tags?.Any(tag => tag.Key == "instance.id" && Equals(tag.Value, instanceTag)) == true)
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            },
        };
        _meters.SetMeasurementEventCallback<long>((instrument, value, tags, _) => RecordMetric(instrument, value, tags));
        _meters.SetMeasurementEventCallback<double>((instrument, value, tags, _) => RecordMetric(instrument, value, tags));
        _meters.Start();
    }

    public IReadOnlyList<StructuredSignal> Signals
    {
        get
        {
            lock (_gate)
            {
                return _signals.ToArray();
            }
        }
    }

    public IReadOnlyList<ScrubbedSpan> Spans
    {
        get
        {
            lock (_gate)
            {
                return _spans.ToArray();
            }
        }
    }

    public void Write(StructuredSignal signal)
    {
        lock (_gate)
        {
            _signals.Add(signal);
        }
    }

    /// <summary>Every exported name and value of every signal, as one searchable text.</summary>
    public string ExportedText()
    {
        var text = new StringBuilder();
        lock (_gate)
        {
            foreach (StructuredSignal signal in _signals)
            {
                text.Append("event ").Append(signal.Name).Append(' ').Append(signal.Level).Append(' ').AppendLine(signal.OccurredAt.ToString("O", CultureInfo.InvariantCulture));
                Append(text, signal.Properties);
            }

            foreach (ScrubbedSpan span in _spans)
            {
                text.Append("span ").Append(span.SourceName).Append(' ').Append(span.Name).Append(' ').Append(span.Status).Append(' ').Append(span.Kind)
                    .Append(' ').Append(span.TraceId).Append(' ').Append(span.SpanId).Append(' ').AppendLine(span.ParentSpanId);
                Append(text, span.Tags);
                foreach (ScrubbedSpanEvent spanEvent in span.Events)
                {
                    text.Append("span-event ").AppendLine(spanEvent.Name);
                    Append(text, spanEvent.Tags);
                }
            }

            foreach (string metric in _metrics)
            {
                text.AppendLine(metric);
            }
        }

        return text.ToString();
    }

    public int ExportedFieldCount()
    {
        lock (_gate)
        {
            return _signals.Sum(signal => signal.Properties.Count)
                + _spans.Sum(span => span.Tags.Count + span.Events.Sum(spanEvent => spanEvent.Tags.Count));
        }
    }

    public void Dispose()
    {
        _activities.Dispose();
        _meters.Dispose();
    }

    private void RecordMetric<T>(Instrument instrument, T value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
        where T : struct
    {
        var line = new StringBuilder("metric ").Append(instrument.Meter.Name).Append(' ').Append(instrument.Name).Append(' ')
            .Append(Convert.ToString(value, CultureInfo.InvariantCulture));
        foreach (KeyValuePair<string, object?> scope in instrument.Meter.Tags ?? [])
        {
            line.Append(" scope:").Append(scope.Key).Append('=').Append(Convert.ToString(scope.Value, CultureInfo.InvariantCulture));
        }

        foreach (KeyValuePair<string, object?> tag in tags)
        {
            line.Append(" label:").Append(tag.Key).Append('=').Append(Convert.ToString(tag.Value, CultureInfo.InvariantCulture));
        }

        lock (_gate)
        {
            _metrics.Add(line.ToString());
        }
    }

    private static void Append(StringBuilder text, IReadOnlyDictionary<string, object?> fields)
    {
        foreach (KeyValuePair<string, object?> field in fields)
        {
            text.Append("  ").Append(field.Key).Append('=').AppendLine(Convert.ToString(field.Value, CultureInfo.InvariantCulture));
        }
    }
}
