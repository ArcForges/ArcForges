// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Contracts.Foundation.Values;
using ArcForges.Foundation.Errors;
using Xunit;

namespace ArcForges.Observability.Desktop.Tests;

/// <summary>A unique temporary directory standing in for the host's local diagnostics location.</summary>
internal sealed class TestDirectory : IDisposable
{
    public TestDirectory()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "arcf-diag-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException)
        {
            // A leftover temporary directory is not a test failure.
        }
    }
}

/// <summary>A deterministic clock: wall time and the monotonic timestamp move independently, and timers fire on demand.</summary>
internal sealed class ManualTimeProvider : TimeProvider
{
    private readonly List<ManualTimer> _timers = [];
    private long _timestamp = 1_000;
    private DateTimeOffset _now = DateTimeOffset.UtcNow;

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    /// <summary>When false, advancing the clock never runs a timer, so only the evaluate-on-read path can end a session.</summary>
    public bool RunTimers { get; set; } = true;

    public override DateTimeOffset GetUtcNow() => _now;

    public override long GetTimestamp() => _timestamp;

    /// <summary>Moves both the wall clock and the monotonic clock forward and runs every timer that has come due.</summary>
    public void Advance(TimeSpan span)
    {
        _now += span;
        _timestamp += span.Ticks;
        RunDueTimers();
    }

    /// <summary>Moves the monotonic clock forward and the wall clock by a different amount (a clock adjustment).</summary>
    public void Advance(TimeSpan monotonic, TimeSpan wall)
    {
        _now += wall;
        _timestamp += monotonic.Ticks;
        RunDueTimers();
    }

    /// <summary>Runs every live timer now, before the clock has reached its due time: a timer that fires slightly early.</summary>
    public void FireTimersEarly()
    {
        foreach (ManualTimer timer in _timers.ToArray())
        {
            if (!timer.Disposed)
            {
                timer.Disposed = true;
                timer.Fire();
            }
        }
    }

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new ManualTimer(this, callback, state, _timestamp + dueTime.Ticks);
        _timers.Add(timer);
        return timer;
    }

    private void RunDueTimers()
    {
        if (!RunTimers)
        {
            return;
        }

        foreach (ManualTimer timer in _timers.ToArray())
        {
            if (!timer.Disposed && timer.DueAt <= _timestamp)
            {
                timer.Disposed = true;
                timer.Fire();
            }
        }
    }

    private sealed class ManualTimer(ManualTimeProvider owner, TimerCallback callback, object? state, long dueAt) : ITimer
    {
        public long DueAt { get; private set; } = dueAt;

        public bool Disposed { get; set; }

        public void Fire() => callback(state);

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            DueAt = owner._timestamp + dueTime.Ticks;
            Disposed = false;
            return true;
        }

        public void Dispose() => Disposed = true;

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}

internal sealed class RecordingTransport : IClientTelemetryTransport
{
    private readonly object _gate = new();
    private readonly List<StructuredSignal> _signals = [];
    private readonly List<ScrubbedSpan> _spans = [];

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

    public int Total => Signals.Count + Spans.Count;

    public Action? OnSend { get; set; }

    public void Send(StructuredSignal signal)
    {
        OnSend?.Invoke();
        lock (_gate)
        {
            _signals.Add(signal);
        }
    }

    public void Send(ScrubbedSpan span)
    {
        OnSend?.Invoke();
        lock (_gate)
        {
            _spans.Add(span);
        }
    }
}

internal sealed class RecordingUploader : IDiagnosticReportUploader
{
    public List<DiagnosticReportUpload> Uploads { get; } = [];

    public Exception? Failure { get; set; }

    public ValueTask UploadAsync(DiagnosticReportUpload upload, CancellationToken cancellationToken)
    {
        Uploads.Add(upload);
        return Failure is null ? ValueTask.CompletedTask : ValueTask.FromException(Failure);
    }
}

internal static class Fixtures
{
    public static ObservabilityContext Identity() =>
        new(SignalApplicationDimension.ArcScope, new InstanceId(Guid.NewGuid()), SignalEnvironment.Test);

    public static DesktopDiagnosticsOptions Options(string directory, TimeProvider? time = null) => new()
    {
        Directory = directory,
        Identity = Identity(),
        TimeProvider = time ?? TimeProvider.System,
    };

    public static DesktopDiagnostics Open(string directory, TimeProvider? time = null) =>
        DesktopDiagnostics.Open(Options(directory, time));

    /// <summary>Emits real typed signals through the shared emission surface into the given sink.</summary>
    public static void Emit(IStructuredEventSink sink, SignalEventName name, SignalLevel level, int count = 1)
    {
        using var emitter = new SignalEmitter(sink);
        ObservabilityContext context = Identity();
        using (ObservabilityScope.Push(context))
        {
            for (int index = 0; index < count; index++)
            {
                emitter.Emit(name, level);
            }
        }
    }

    public static string FailureCode(Outcome<DiagnosticReportReceipt> outcome)
    {
        Assert.True(outcome.TryGetFailure(out TypedFailure? failure));
        return failure!.Code;
    }

    public static Activity RunningSpan(ActivitySource source, string name)
    {
        Activity? activity = source.StartActivity(name);
        Assert.NotNull(activity);
        return activity!;
    }

    public static ActivityListener ListenTo(string sourceName)
    {
        var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == sourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
        };
        ActivitySource.AddActivityListener(listener);
        return listener;
    }
}
