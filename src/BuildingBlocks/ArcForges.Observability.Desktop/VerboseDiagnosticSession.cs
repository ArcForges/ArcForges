// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Foundation;

namespace ArcForges.Observability.Desktop;

/// <summary>The state of the verbose session, for the indicator the shell must show while a session is active.</summary>
/// <param name="IsActive">True while the session has not ended.</param>
/// <param name="Remaining">The time left on the monotonic clock; zero when inactive.</param>
/// <param name="ExpiresAt">The wall-clock instant the session will end, for display only; null when inactive.</param>
public readonly record struct VerboseSessionState(bool IsActive, TimeSpan Remaining, Instant? ExpiresAt);

/// <summary>Why <see cref="VerboseDiagnosticSession.Changed"/> was raised.</summary>
public enum VerboseSessionChange
{
    Started = 0,
    Stopped = 1,
    Expired = 2,
}

/// <summary>Data for <see cref="VerboseDiagnosticSession.Changed"/>.</summary>
public sealed class VerboseSessionChangedEventArgs : EventArgs
{
    internal VerboseSessionChangedEventArgs(VerboseSessionChange change)
    {
        Change = change;
    }

    public VerboseSessionChange Change { get; }
}

/// <summary>
/// The time-bounded verbose diagnostic tier (observability architecture DG-05, DG-06). A session is started by an
/// explicit user action for a bounded period, is visible while active, and disables itself: whether it is active is
/// computed from the monotonic clock every time it is asked, so it cannot outlive its period even if nobody polls
/// and a wall-clock change cannot extend it. A session only makes the local store keep more detail; it never uploads.
/// </summary>
public sealed class VerboseDiagnosticSession
{
    private readonly object _gate = new();
    private readonly IClock _clock;
    private readonly TimeProvider _timeProvider;
    private bool _active;
    private MonotonicTimestamp _startedAt;
    private TimeSpan _duration;
    private Instant _expiresAt;
    private ITimer? _timer;
    private bool _closed;

    internal VerboseDiagnosticSession(IClock clock, TimeProvider timeProvider)
    {
        _clock = clock;
        _timeProvider = timeProvider;
    }

    /// <summary>The period used when a user starts a session without choosing one: 30 minutes.</summary>
    public static TimeSpan DefaultDuration { get; } = TimeSpan.FromMinutes(30);

    /// <summary>The longest period one session may be started for: 4 hours. A longer request is refused, not clamped.</summary>
    public static TimeSpan MaximumDuration { get; } = TimeSpan.FromHours(4);

    /// <summary>Raised when a session starts, is stopped by the user, or ends on its own.</summary>
    public event EventHandler<VerboseSessionChangedEventArgs>? Changed;

    /// <summary>The current state. Reading it after the period ended ends the session and raises <see cref="Changed"/> once.</summary>
    public VerboseSessionState State
    {
        get
        {
            (VerboseSessionState state, bool expired) = Evaluate();
            if (expired)
            {
                Raise(VerboseSessionChange.Expired);
            }

            return state;
        }
    }

    /// <summary>True while a session is active.</summary>
    public bool IsActive => State.IsActive;

    /// <summary>
    /// Starts a session of the given period, replacing any session already running. The period must be positive and at
    /// most <see cref="MaximumDuration"/>.
    /// </summary>
    public VerboseSessionState Start(TimeSpan duration)
    {
        if (duration <= TimeSpan.Zero || duration > MaximumDuration)
        {
            throw new ArgumentOutOfRangeException(nameof(duration), "A verbose session must be positive and no longer than the maximum.");
        }

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_closed, this);
            _timer?.Dispose();
            _startedAt = _clock.GetTimestamp();
            _duration = duration;
            _expiresAt = Instant.FromDateTimeOffset(_clock.GetCurrentInstant().ToDateTimeOffset().Add(duration));
            _active = true;
            _timer = _timeProvider.CreateTimer(_ => OnTimer(), null, duration, Timeout.InfiniteTimeSpan);
        }

        Raise(VerboseSessionChange.Started);
        return State;
    }

    /// <summary>Ends the session now. Nothing is kept afterwards beyond what the local store already holds.</summary>
    public VerboseSessionState Stop()
    {
        bool stopped;
        lock (_gate)
        {
            stopped = _active;
            Deactivate();
        }

        if (stopped)
        {
            Raise(VerboseSessionChange.Stopped);
        }

        return new VerboseSessionState(false, TimeSpan.Zero, null);
    }

    internal void Close()
    {
        lock (_gate)
        {
            _closed = true;
            Deactivate();
        }
    }

    private void OnTimer()
    {
        (_, bool expired) = Evaluate();
        if (expired)
        {
            Raise(VerboseSessionChange.Expired);
        }
    }

    private (VerboseSessionState State, bool ExpiredNow) Evaluate()
    {
        lock (_gate)
        {
            if (!_active)
            {
                return (new VerboseSessionState(false, TimeSpan.Zero, null), false);
            }

            TimeSpan elapsed = _clock.GetElapsedTime(_startedAt, _clock.GetTimestamp());
            if (elapsed >= _duration)
            {
                Deactivate();
                return (new VerboseSessionState(false, TimeSpan.Zero, null), true);
            }

            return (new VerboseSessionState(true, _duration - elapsed, _expiresAt), false);
        }
    }

    private void Deactivate()
    {
        _active = false;
        _timer?.Dispose();
        _timer = null;
    }

    private void Raise(VerboseSessionChange change) => Changed?.Invoke(this, new VerboseSessionChangedEventArgs(change));
}
