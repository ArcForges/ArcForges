// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Globalization;
using ArcForges.Contracts.Foundation.Values;

namespace ArcForges.Observability.Tests;

/// <summary>A clock the tests move by hand, so buffer retention is exercised without waiting.</summary>
internal sealed class FakeClock : TimeProvider
{
    private static readonly DateTimeOffset Origin = new(2026, 10, 2, 0, 0, 0, TimeSpan.Zero);
    private long _ticks;

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public override long GetTimestamp() => Interlocked.Read(ref _ticks);

    public override DateTimeOffset GetUtcNow() => Origin + TimeSpan.FromTicks(Interlocked.Read(ref _ticks));

    public void Advance(TimeSpan by) => Interlocked.Add(ref _ticks, by.Ticks);
}

internal sealed class ToggleConsent(bool granted) : ITelemetryConsent
{
    public bool IsGranted { get; set; } = granted;
}

internal sealed class CapturingSpanSink : IScrubbedSpanSink
{
    private readonly List<ScrubbedSpan> _spans = [];
    private readonly object _gate = new();

    public bool Fail { get; set; }

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

    public void Write(ScrubbedSpan span)
    {
        if (Fail)
        {
            throw new InvalidOperationException("the exporter is down");
        }

        lock (_gate)
        {
            _spans.Add(span);
        }
    }
}

internal sealed class CapturingEventSink : IStructuredEventSink
{
    private readonly List<StructuredSignal> _signals = [];
    private readonly object _gate = new();

    public bool Fail { get; set; }

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

    public void Write(StructuredSignal signal)
    {
        if (Fail)
        {
            throw new InvalidOperationException("the log backend is down");
        }

        lock (_gate)
        {
            _signals.Add(signal);
        }
    }
}

/// <summary>One trace policy wired to capturing sinks, a hand-moved clock and a consent switch.</summary>
internal sealed class TracePolicyRig : IDisposable
{
    public static readonly TimeSpan Slow = TimeSpan.FromSeconds(2);
    public static readonly TimeSpan Fast = TimeSpan.FromMilliseconds(5);

    public TracePolicyRig(double ratio = 0d, long? bufferBytes = null, bool consent = true,
        IReadOnlyList<SignalSamplingRule>? signalRules = null, IReadOnlyList<RouteSamplingRule>? routeRules = null)
    {
        Clock = new FakeClock();
        Consent = new ToggleConsent(consent);
        Identity = new ObservabilityContext(SignalApplicationDimension.ArcScope, new InstanceId(Guid.NewGuid()), SignalEnvironment.Test);
        var options = new TracePolicyOptions(ratio, Slow)
        {
            BufferBytes = bufferBytes ?? TracePolicyOptions.DefaultBufferBytes,
            SignalRules = signalRules ?? [],
            RouteRules = routeRules ?? [],
        };
        Policy = new TracePolicy(options, Identity, Spans, Events, Consent, Clock);
    }

    public FakeClock Clock { get; }
    public ToggleConsent Consent { get; }
    public ObservabilityContext Identity { get; }
    public CapturingSpanSink Spans { get; } = new();
    public CapturingEventSink Events { get; } = new();
    public TracePolicy Policy { get; }

    public string InstanceTag => Identity.InstanceId.Value.ToString("N", CultureInfo.InvariantCulture);

    public TracePolicyStatistics Statistics => Policy.Statistics;

    public void Dispose() => Policy.Dispose();

    /// <summary>
    /// A distinct, valid trace identifier for <paramref name="serial"/>. Head selection reads only the last eight bytes, so
    /// <paramref name="low"/> chooses its position: 0 is selected for any ratio above zero, the maximum for ratio 1 only.
    /// </summary>
    public static ActivityTraceId Trace(int serial, ulong low = ulong.MaxValue)
    {
        Span<byte> bytes = stackalloc byte[16];
        System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(bytes, serial + 1);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(bytes[8..], low);
        return ActivityTraceId.CreateFromBytes(bytes);
    }

    /// <summary>A finished span in a given trace, with an explicit duration, so nothing depends on the real clock.</summary>
    public static Activity Span(ActivityTraceId trace, bool sampled = false, TimeSpan? duration = null, bool error = false,
        string name = "operation.completed", params (string Name, object? Value)[] tags)
    {
        var activity = new Activity(name);
        activity.SetIdFormat(ActivityIdFormat.W3C);
        activity.SetParentId(trace, ActivitySpanId.CreateRandom(), sampled ? ActivityTraceFlags.Recorded : ActivityTraceFlags.None);
        var start = new DateTime(2026, 10, 2, 0, 0, 0, DateTimeKind.Utc);
        activity.SetStartTime(start);
        activity.Start();
        foreach ((string tagName, object? value) in tags)
        {
            activity.SetTag(tagName, value);
        }

        if (error)
        {
            activity.SetStatus(ActivityStatusCode.Error);
        }

        activity.SetEndTime(start + (duration ?? Fast));
        activity.Stop();
        return activity;
    }

    /// <summary>The accounted cost of the scrubbed copy of a span, which is what the buffer charges.</summary>
    public static long Cost(Activity activity) => DiagnosticSpanBuffer.Cost(RedactionProcessor.Scrub(activity));

    /// <summary>Instrument readings of this rig's policy: observable instruments are pulled, counters are collected as they are added.</summary>
    public MeterReadings Listen() => new(this);

    internal sealed class MeterReadings : IDisposable
    {
        private readonly MeterListener _listener = new();
        private readonly List<(string Instrument, long Value, string[] Labels)> _readings = [];
        private readonly object _gate = new();

        public MeterReadings(TracePolicyRig rig)
        {
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == TracePolicy.MeterName
                    && instrument.Meter.Tags?.Any(tag => tag.Key == "instance.id" && Equals(tag.Value, rig.InstanceTag)) == true)
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            };
            _listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
            {
                lock (_gate)
                {
                    _readings.Add((instrument.Name, value, tags.ToArray().Select(tag => tag.Key + "=" + tag.Value).ToArray()));
                }
            });
            _listener.Start();
        }

        public IReadOnlyList<(string Instrument, long Value, string[] Labels)> Pull()
        {
            lock (_gate)
            {
                _readings.Clear();
            }

            _listener.RecordObservableInstruments();
            lock (_gate)
            {
                return _readings.ToArray();
            }
        }

        public IReadOnlyList<(string Instrument, long Value, string[] Labels)> Collected
        {
            get
            {
                lock (_gate)
                {
                    return _readings.ToArray();
                }
            }
        }

        public void Dispose() => _listener.Dispose();
    }
}

/// <summary>Writes the first span it is given and then withdraws consent, as a user revoking mid-export would.</summary>
internal sealed class RevokingSpanSink(ToggleConsent consent) : IScrubbedSpanSink
{
    private int _written;

    public int Written => Volatile.Read(ref _written);

    public void Write(ScrubbedSpan span)
    {
        Interlocked.Increment(ref _written);
        consent.IsGranted = false;
    }
}
