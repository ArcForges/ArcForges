// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// A child-process-only kernel monotonic timer that delivers SIGKILL at an absolute deadline. This must never be
/// armed in the node process. It prevents a suspended worker from resuming user-mode work after expiry; it does not
/// prove cancellation of a syscall already in the kernel or authorize any file effect.
/// </summary>
[SupportedOSPlatform("linux")]
internal sealed unsafe partial class LinuxFatalDeadline : IDisposable
{
    private const long NanosecondsPerSecond = 1_000_000_000;
    private const long MaximumDuration = 10 * NanosecondsPerSecond;
    private nint _timer;
    private bool _created;

    private LinuxFatalDeadline(nint timer)
    {
        _timer = timer;
        _created = true;
    }

    internal static long MonotonicNanoseconds() => ClockNanoseconds(1);

    internal static LinuxFatalDeadline ArmAbsolute(long deadline) => Arm(1, deadline, MaximumDuration);

    /// <summary>An absolute realtime expiry also fires when the host wall clock jumps forward.</summary>
    internal static LinuxFatalDeadline ArmRealtimeExpiry(long expiryMicroseconds) =>
        Arm(0, checked(expiryMicroseconds * 1_000), 300 * NanosecondsPerSecond);

    /// <summary>
    /// An approval may outlive the routed-signature lifetime. Its realtime kill timer is conservatively capped by
    /// this execution's already bound monotonic remainder; neither a long approval TTL nor a clock rollback renews
    /// the independent original monotonic SIGKILL timer. This method never changes the durable approval expiry.
    /// </summary>
    internal static LinuxFatalDeadline ArmRealtimeExpiry(long expiryMicroseconds, long monotonicDeadline)
    {
        var beforeRealtime = MonotonicNanoseconds();
        var realtime = ClockNanoseconds(0);
        var remaining = checked(monotonicDeadline - beforeRealtime);
        if (remaining is <= 0 or > MaximumDuration) throw new ArgumentOutOfRangeException(nameof(monotonicDeadline));
        var cappedExpiry = Math.Min(checked(expiryMicroseconds * 1000), checked(realtime + remaining));
        return Arm(0, cappedExpiry, MaximumDuration);
    }

    private static long ClockNanoseconds(int clock)
    {
        if (ClockGetTime(clock, out var time) != 0 || time.Seconds < 0 || time.Nanoseconds is < 0 or >= NanosecondsPerSecond)
            throw new IOException("The kernel clock is unavailable.");
        return checked(time.Seconds * NanosecondsPerSecond + time.Nanoseconds);
    }

    private static LinuxFatalDeadline Arm(int clock, long deadline, long maximum)
    {
        var now = ClockNanoseconds(clock);
        if (deadline <= now || deadline - now > maximum)
            throw new ArgumentOutOfRangeException(nameof(deadline), "The worker deadline is unavailable or out of bounds.");
        var notification = new SignalEvent { Signal = 9, Notify = 0 }; // SIGKILL, SIGEV_SIGNAL; process-directed.
        if (TimerCreate(clock, &notification, out var timer) != 0)
            throw new IOException("The kernel worker timer is unavailable.", new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()));
        var deadlineTimer = new LinuxFatalDeadline(timer);
        try
        {
            var specification = new TimerSpecification
            {
                Value = new TimeSpec { Seconds = deadline / NanosecondsPerSecond, Nanoseconds = deadline % NanosecondsPerSecond },
            };
            if (TimerSetTime(timer, 1, &specification, null) != 0) // TIMER_ABSTIME on the selected kernel clock.
                throw new IOException("The kernel worker timer could not be armed.", new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()));
            return deadlineTimer;
        }
        catch
        {
            deadlineTimer.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        if (!_created) return;
        _created = false;
        if (TimerDelete(_timer) != 0)
            throw new IOException("The kernel worker timer could not be removed.", new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError()));
        _timer = 0;
    }

    [StructLayout(LayoutKind.Sequential, Size = 64)]
    private struct SignalEvent
    {
        internal nint Value;
        internal int Signal;
        internal int Notify;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TimeSpec
    {
        internal long Seconds;
        internal long Nanoseconds;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TimerSpecification
    {
        internal TimeSpec Interval;
        internal TimeSpec Value;
    }

    [LibraryImport("libc", EntryPoint = "clock_gettime", SetLastError = true)]
    private static partial int ClockGetTime(int clock, out TimeSpec time);

    [LibraryImport("libc", EntryPoint = "timer_create", SetLastError = true)]
    private static partial int TimerCreate(int clock, SignalEvent* signal, out nint timer);

    [LibraryImport("libc", EntryPoint = "timer_settime", SetLastError = true)]
    private static partial int TimerSetTime(nint timer, int flags, TimerSpecification* value, TimerSpecification* oldValue);

    [LibraryImport("libc", EntryPoint = "timer_delete", SetLastError = true)]
    private static partial int TimerDelete(nint timer);
}
