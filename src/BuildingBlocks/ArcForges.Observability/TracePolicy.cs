// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace ArcForges.Observability;

/// <summary>
/// The host-owned bridge to its trace exporter. It receives only spans already copied through the scrubbing processor.
/// <see cref="Write"/> is called from whichever thread ends a span, concurrently and outside any lock of this library, so
/// an implementation must be thread-safe.
/// </summary>
public interface IScrubbedSpanSink
{
    void Write(ScrubbedSpan span);
}

/// <summary>
/// A point-in-time reading of what a <see cref="TracePolicy"/> has exported, discarded and lost. It is always available
/// locally, whatever the consent state, because local diagnostics never depend on consent (observability architecture DG-02).
/// </summary>
/// <param name="HeadSampledSpans">Spans exported because head sampling selected their trace.</param>
/// <param name="PromotedTraces">Traces promoted out of the diagnostic buffer by an error or slow span.</param>
/// <param name="PromotedSpans">Spans exported by promotion: the spans still held plus the spans that arrived after it.</param>
/// <param name="ExpiredUnpromotedSpans">Held spans discarded at the end of their trace's retention; the expected end of a healthy unsampled trace.</param>
/// <param name="SpansLostToOverflow">Held spans evicted before their trace's retention ended because the buffer was full.</param>
/// <param name="TracesEvictedForOverflow">Traces, or promotion states, evicted because the buffer was full.</param>
/// <param name="LateSpans">Spans dropped because their trace's window had already closed.</param>
/// <param name="OversizeSpans">Spans dropped because one span alone costs more than the buffer.</param>
/// <param name="ErrorSpansNotRetained">Error spans that were not exported because their trace's window had already closed; their error facts were still recorded. An error or slow span is never refused for size: promotion exports it, and promotion export is not capped in volume.</param>
/// <param name="ErrorFacts">Redacted error events written and counter increments recorded, independent of sampling; a fact whose event sink threw is not counted here.</param>
/// <param name="ConsentSuppressedSpans">Spans that arrived, or were held, while consent was absent and were discarded.</param>
/// <param name="PurgedSpans">Held spans discarded by <see cref="TracePolicy.PurgeBuffer"/>, by the next span or instrument read that found consent absent, or by disposal.</param>
/// <param name="ExportFailures">Spans whose export failed inside the sink or the listener, counted and swallowed.</param>
/// <param name="BufferedSpans">Spans held now.</param>
/// <param name="BufferedBytes">Accounted cost of everything the buffer retains now. Windows that ended are applied when this is read or the next span arrives, never by a timer.</param>
/// <param name="ClosedTraces">Closed-trace markers retained now.</param>
public readonly record struct TracePolicyStatistics(
    long HeadSampledSpans,
    long PromotedTraces,
    long PromotedSpans,
    long ExpiredUnpromotedSpans,
    long SpansLostToOverflow,
    long TracesEvictedForOverflow,
    long LateSpans,
    long OversizeSpans,
    long ErrorSpansNotRetained,
    long ErrorFacts,
    long ConsentSuppressedSpans,
    long PurgedSpans,
    long ExportFailures,
    long BufferedSpans,
    long BufferedBytes,
    long ClosedTraces);

/// <summary>
/// Bounded trace policy (observability architecture SG-03, CC-01 to CC-03; WP-12.03). Head sampling selects traces for
/// export. Spans of every other trace are held in a bounded diagnostic buffer, scrubbed, for at most 30 seconds, and an
/// error or slow span promotes only the spans still held. Loss, overflow and late spans are counted and exposed as
/// instruments and as <see cref="Statistics"/>, and nothing promises that every error trace is retained. What remains
/// guaranteed is the mandatory error fact: every error span, sampled or not, is recorded as a redacted structured event
/// and a counter increment.
/// </summary>
/// <remarks>
/// <para>
/// With consent absent nothing is exported or held, and no error fact or instrument measurement is produced. Consent is
/// read live on every span, but <see cref="ITelemetryConsent"/> has no change notification, so held spans are purged only
/// when the next span ends, or an instrument is read, while consent is absent, or when the host calls
/// <see cref="PurgeBuffer"/>. A host that revokes and re-grants consent with neither in between would otherwise let spans
/// collected before the revocation be exported after the re-grant: the host wiring must call <see cref="PurgeBuffer"/>
/// when consent is revoked. The attached listener keeps creating and populating spans, and keeps setting the head-sampled
/// flag that propagates on outgoing context, while consent is absent; only export, holding and facts stop. The
/// <see cref="SignalEmitter"/>'s own sink and instruments are not gated by this class.
/// </para>
/// <para>
/// Head selection is parent-based: a root span is selected when its trace identifier falls under its ratio, and a child
/// span follows the sampled flag of its parent, so one trace is exported whole or not at all at the head. A remote
/// parent's sampled flag is trusted: a caller that sends a sampled trace context forces recording and export here whatever
/// the ratio. Retention is a logical window checked when a span arrives or statistics are read; no timer runs, so on an
/// idle process held spans stay in memory, within the buffer budget and never exported, until the next call. Promotion
/// exports the promoting span and the rest of its trace without a volume cap; the bound is on the buffer, not on export.
/// Sinks are called concurrently from arbitrary threads.
/// </para>
/// </remarks>
public sealed class TracePolicy : IDisposable
{
    public const string MeterName = "ArcForges.Observability.TracePolicy";

    /// <summary>The name of the redacted structured event recorded for every error span.</summary>
    public const string ErrorFactEventName = "trace.error";

    internal const string ErrorCounterName = "arcf_span_error_count";

    /// <summary>The loss and retention instruments, every one without point labels, so none adds a metric series.</summary>
    internal static readonly IReadOnlyList<string> CounterNames = Array.AsReadOnly(
    [
        "arcf_trace_span_head_sampled",
        "arcf_trace_span_promoted",
        "arcf_trace_span_lost_overflow",
        "arcf_trace_span_lost_late",
        "arcf_trace_span_lost_oversize",
        "arcf_trace_error_span_not_retained",
    ]);

    internal const string BufferBytesGaugeName = "arcf_trace_buffer_bytes";

    private const string RouteField = "http.route";

    private readonly object _gate = new();
    private readonly TracePolicyOptions _options;
    private readonly IScrubbedSpanSink _spans;
    private readonly IStructuredEventSink _events;
    private readonly ITelemetryConsent _consent;
    private readonly TimeProvider _time;
    private readonly DiagnosticSpanBuffer _buffer;
    private readonly Dictionary<string, double> _routeRatios;
    private readonly Dictionary<string, double> _signalRatios;
    private readonly Dictionary<string, object?> _identityFields;
    private readonly Meter _meter;
    private readonly Counter<long> _errorCounter;
    private readonly List<ActivityListener> _listeners = [];
    private long _headSampled;
    private long _errorSpansNotRetained;
    private long _errorFacts;
    private long _consentSuppressed;
    private long _exportFailures;
    private bool _disposed;

    /// <param name="options">The sampling and buffer configuration.</param>
    /// <param name="identity">The application, build, instance and environment these signals are attributed to (SG-05).</param>
    /// <param name="spans">Receives spans selected for export.</param>
    /// <param name="events">Receives the redacted error facts.</param>
    /// <param name="consent">The live consent state; a desktop client passes the one its user controls.</param>
    /// <param name="time">The clock for buffer retention; the system clock when omitted.</param>
    public TracePolicy(TracePolicyOptions options, ObservabilityContext identity, IScrubbedSpanSink spans, IStructuredEventSink events,
        ITelemetryConsent consent, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(spans);
        ArgumentNullException.ThrowIfNull(events);
        ArgumentNullException.ThrowIfNull(consent);

        _options = options;
        _spans = spans;
        _events = events;
        _consent = consent;
        _time = time ?? TimeProvider.System;
        _buffer = new DiagnosticSpanBuffer(options.BufferBytes, _time);
        _routeRatios = options.RouteRules.ToDictionary(rule => rule.Route.Template, rule => rule.Ratio, StringComparer.Ordinal);
        _signalRatios = options.SignalRules.ToDictionary(rule => SignalEmitter.EventName(rule.Signal), rule => rule.Ratio, StringComparer.Ordinal);
        _identityFields = RedactionProcessor.Scrub(identity.MaterializeDimensions());

        _meter = new Meter(new MeterOptions(MeterName)
        {
            Tags = MetricLabelPolicy.ScopeTags(identity.ApplicationId,
                identity.InstanceId.Value.ToString("N", System.Globalization.CultureInfo.InvariantCulture), identity.BuildId, identity.Environment),
        });
        try
        {
            _errorCounter = _meter.CreateCounter<long>(ErrorCounterName, "{span}");
            Observe(CounterNames[0], () => Volatile.Read(ref _headSampled));
            Observe(CounterNames[1], () => _buffer.Counters().PromotedSpans);
            Observe(CounterNames[2], () => _buffer.Counters().SpansLostToOverflow);
            Observe(CounterNames[3], () => _buffer.Counters().LateSpans);
            Observe(CounterNames[4], () => _buffer.Counters().OversizeSpans);
            Observe(CounterNames[5], () => Volatile.Read(ref _errorSpansNotRetained));
            _meter.CreateObservableGauge(BufferBytesGaugeName, ReadBufferBytes, "By");
        }
        catch
        {
            _meter.Dispose();
            throw;
        }
    }

    /// <summary>The current counters. Readable regardless of consent: local diagnostics never depend on it.</summary>
    public TracePolicyStatistics Statistics
    {
        get
        {
            BufferCounters buffer = _buffer.Counters();
            return new TracePolicyStatistics(
                Volatile.Read(ref _headSampled),
                buffer.PromotedTraces,
                buffer.PromotedSpans,
                buffer.ExpiredUnpromotedSpans,
                buffer.SpansLostToOverflow,
                buffer.TracesEvictedForOverflow,
                buffer.LateSpans,
                buffer.OversizeSpans,
                Volatile.Read(ref _errorSpansNotRetained),
                Volatile.Read(ref _errorFacts),
                Volatile.Read(ref _consentSuppressed),
                buffer.PurgedSpans,
                Volatile.Read(ref _exportFailures),
                buffer.BufferedSpans,
                buffer.BufferedBytes,
                buffer.ClosedTraces);
        }
    }

    /// <summary>
    /// Listens to the activity sources the host selects. Every span of those sources is recorded, so an unselected trace can
    /// still be promoted, but only head-selected spans carry the sampled flag a downstream hop inherits. The returned handle
    /// stops listening; disposing the policy stops every listener it created.
    /// </summary>
    public IDisposable Attach(Func<ActivitySource, bool> shouldListenTo)
    {
        ArgumentNullException.ThrowIfNull(shouldListenTo);
        ObjectDisposedException.ThrowIf(_disposed, this);
        var listener = new ActivityListener
        {
            ShouldListenTo = shouldListenTo,
            Sample = SampleAtHead,
            ActivityStopped = Stopped,
        };
        lock (_gate)
        {
            _listeners.Add(listener);
        }

        ActivitySource.AddActivityListener(listener);
        return listener;
    }

    /// <summary>
    /// Applies the policy to one finished span. <see cref="Attach"/> calls this for every span it hears; a host that
    /// drives its own listener may call it directly. It never throws for a failing sink: the span is counted in
    /// <see cref="TracePolicyStatistics.ExportFailures"/> instead, because telemetry must not break the instrumented code.
    /// </summary>
    public void OnSpanEnded(Activity activity)
    {
        ArgumentNullException.ThrowIfNull(activity);
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_consent.IsGranted)
        {
            Withdraw();
            return;
        }

        ScrubbedSpan span = RedactionProcessor.Scrub(activity);
        bool failed = span.Status == ActivityStatusCode.Error;
        if (failed)
        {
            Guarded(() => RecordErrorFact(span));
        }

        if (activity.Recorded)
        {
            if (Export(span))
            {
                Interlocked.Increment(ref _headSampled);
            }

            return;
        }

        var release = new List<ScrubbedSpan>();
        BufferOutcome outcome = _buffer.Offer(span, failed || span.Duration >= _options.SlowSpanThreshold, release);
        foreach (ScrubbedSpan released in release)
        {
            Export(released);
        }

        // A promoting span is never refused for size, so the only error span that is not retained is a late one.
        if (failed && outcome == BufferOutcome.Late)
        {
            Interlocked.Increment(ref _errorSpansNotRetained);
        }
    }

    /// <summary>Discards every span held in the diagnostic buffer, as when consent is withdrawn.</summary>
    public void PurgeBuffer() => _buffer.Purge();

    public void Dispose()
    {
        ActivityListener[] listeners;
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            listeners = [.. _listeners];
            _listeners.Clear();
        }

        foreach (ActivityListener listener in listeners)
        {
            listener.Dispose();
        }

        _buffer.Purge();
        _meter.Dispose();
    }

    private ActivitySamplingResult SampleAtHead(ref ActivityCreationOptions<ActivityContext> creation)
    {
        // Every span is recorded so the buffer can promote it; the Recorded flag alone says whether head sampling selected the trace.
        ActivityContext parent = creation.Parent;
        bool selected = parent != default
            ? (parent.TraceFlags & ActivityTraceFlags.Recorded) != 0
            : IsSelected(creation.TraceId, RatioForRoot(ref creation));
        return selected ? ActivitySamplingResult.AllDataAndRecorded : ActivitySamplingResult.AllData;
    }

    private double RatioForRoot(ref ActivityCreationOptions<ActivityContext> creation)
    {
        if (_routeRatios.Count > 0 && creation.Tags is { } tags)
        {
            foreach (KeyValuePair<string, object?> tag in tags)
            {
                if (tag.Key == RouteField && tag.Value is string route && _routeRatios.TryGetValue(route, out double routeRatio))
                {
                    return routeRatio;
                }
            }
        }

        return _signalRatios.TryGetValue(creation.Name, out double signalRatio) ? signalRatio : _options.DefaultTraceRatio;
    }

    /// <summary>Selects a trace deterministically from its identifier, the same way on every hop that uses the same ratio.</summary>
    internal static bool IsSelected(ActivityTraceId traceId, double ratio)
    {
        if (ratio >= 1d)
        {
            return true;
        }

        if (ratio <= 0d)
        {
            return false;
        }

        Span<byte> bytes = stackalloc byte[16];
        traceId.CopyTo(bytes);
        ulong sample = BinaryPrimitives.ReadUInt64BigEndian(bytes[8..]) >> 1;
        return sample < (ulong)(ratio * 9223372036854775808d);
    }

    private void Stopped(Activity activity) => Guarded(() => OnSpanEnded(activity));

    private bool Export(ScrubbedSpan span)
    {
        if (!_consent.IsGranted)
        {
            Withdraw();
            return false;
        }

        try
        {
            _spans.Write(span);
            return true;
        }
#pragma warning disable CA1031 // Telemetry must never break the instrumented code: a failing sink is counted, not propagated.
        catch (Exception)
#pragma warning restore CA1031
        {
            Interlocked.Increment(ref _exportFailures);
            return false;
        }
    }

    private void Guarded(Action action)
    {
        try
        {
            action();
        }
#pragma warning disable CA1031 // Telemetry must never break the instrumented code: a failing sink or listener is counted, not propagated.
        catch (Exception)
#pragma warning restore CA1031
        {
            Interlocked.Increment(ref _exportFailures);
        }
    }

    private void Withdraw()
    {
        Interlocked.Increment(ref _consentSuppressed);
        _buffer.Purge();
    }

    private void RecordErrorFact(ScrubbedSpan span)
    {
        var fields = new Dictionary<string, object?>(_identityFields, StringComparer.Ordinal);
        foreach (KeyValuePair<string, object?> tag in span.Tags)
        {
            fields.TryAdd(tag.Key, tag.Value);
        }

        SignalService? service = span.Tags.TryGetValue("service.name", out object? name)
            && name is string text && Enum.TryParse(text, ignoreCase: false, out SignalService parsed) && Enum.IsDefined(parsed)
            ? parsed
            : null;
        _events.Write(new StructuredSignal(ErrorFactEventName, SignalLevel.Error, _time.GetUtcNow(), fields));
        TagList labels = MetricLabelPolicy.CreateTags(service);
        _errorCounter.Add(1, in labels);
        Interlocked.Increment(ref _errorFacts);
    }

    private void Observe(string name, Func<long> read) =>
        _meter.CreateObservableCounter(name, () => ConsentedMeasurement(read()), "{span}");

    private IEnumerable<Measurement<long>> ReadBufferBytes() => ConsentedMeasurement(_buffer.Counters().BufferedBytes);

    // With consent absent an instrument reports nothing, so no measurement can leave the device, and an exporter polling the
    // instruments is also the moment a revocation is observed, so what was held is purged.
    private IEnumerable<Measurement<long>> ConsentedMeasurement(long value)
    {
        if (_consent.IsGranted)
        {
            return [new Measurement<long>(value)];
        }

        _buffer.Purge();
        return [];
    }
}
