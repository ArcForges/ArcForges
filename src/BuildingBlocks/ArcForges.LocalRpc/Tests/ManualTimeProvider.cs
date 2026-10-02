// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.LocalRpc.Tests;

/// <summary>
/// A clock that moves only when a test advances it, so queue deadlines and the handshake and idle limits are tested
/// without sleeping. Timers fire synchronously on the advancing thread, in due order.
/// </summary>
internal sealed class ManualTimeProvider : TimeProvider
{
    private readonly object _gate = new();
    private readonly List<ManualTimer> _timers = [];
    private long _ticks;

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public override long GetTimestamp()
    {
        lock (_gate)
        {
            return _ticks;
        }
    }

    public override DateTimeOffset GetUtcNow()
    {
        lock (_gate)
        {
            return new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero).AddTicks(_ticks);
        }
    }

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new ManualTimer(this, callback, state);
        _ = timer.Change(dueTime, period);
        return timer;
    }

    /// <summary>Moves time forward and runs every timer that comes due, each at its own due time.</summary>
    internal void Advance(TimeSpan by)
    {
        long target;
        lock (_gate)
        {
            target = _ticks + by.Ticks;
        }

        while (true)
        {
            ManualTimer? next;
            lock (_gate)
            {
                next = _timers.Where(timer => timer.Due <= target).OrderBy(timer => timer.Due).FirstOrDefault();
                if (next is null)
                {
                    _ticks = target;
                    return;
                }

                _ticks = Math.Max(_ticks, next.Due);
                next.Fired();
            }

            next.Run();
        }
    }

    /// <summary>
    /// Fires the next timer as a real timer sometimes does: <paramref name="early"/> before the clock says its due time has
    /// come. The timer is consumed like any one-shot timer, so a callback that does not re-arm loses its limit.
    /// </summary>
    internal void FireNextEarly(TimeSpan early)
    {
        ManualTimer next;
        lock (_gate)
        {
            next = _timers.OrderBy(timer => timer.Due).First();
            _ticks = Math.Max(_ticks, next.Due - early.Ticks);
            next.Fired();
        }

        next.Run();
    }

    /// <summary>Timers currently armed.</summary>
    internal int ArmedTimers
    {
        get
        {
            lock (_gate)
            {
                return _timers.Count;
            }
        }
    }

    private sealed class ManualTimer(ManualTimeProvider owner, TimerCallback callback, object? state) : ITimer
    {
        private TimeSpan _period = Timeout.InfiniteTimeSpan;

        internal long Due { get; private set; } = long.MaxValue;

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            lock (owner._gate)
            {
                _ = owner._timers.Remove(this);
                _period = period;
                if (dueTime != Timeout.InfiniteTimeSpan)
                {
                    Due = owner._ticks + dueTime.Ticks;
                    owner._timers.Add(this);
                }
                else
                {
                    Due = long.MaxValue;
                }
            }

            return true;
        }

        // Called with the provider lock held: re-arm a periodic timer or disarm a one-shot one.
        internal void Fired()
        {
            _ = owner._timers.Remove(this);
            if (_period != Timeout.InfiniteTimeSpan && _period > TimeSpan.Zero)
            {
                Due += _period.Ticks;
                owner._timers.Add(this);
            }
            else
            {
                Due = long.MaxValue;
            }
        }

        internal void Run() => callback(state);

        public void Dispose()
        {
            lock (owner._gate)
            {
                _ = owner._timers.Remove(this);
                Due = long.MaxValue;
            }
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
