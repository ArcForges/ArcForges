// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// Owns one checked read/write file handle and a native open-exclusion guard. It deliberately exposes no write method:
/// an actual mutation also needs a durable journal, authorization, staging and name revalidation. An observed intact
/// guard is not an atomic guarantee across a later system call, and Linux leases do not lock the namespace.
/// </summary>
internal sealed class WorkspaceWriteGuard : IDisposable
{
    private const int MaximumExpectedBytes = 4 * 1024 * 1024;
    private static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(10);
    private readonly object _sync = new();
    private readonly WorkspaceObjectIdentity _identity;
    private readonly bool _linux;
    private readonly long _started;
    private SafeFileHandle? _file;
    private Timer? _expiry;
    private string _closedReason = "file_guard_closed";

    private WorkspaceWriteGuard(SafeFileHandle file, WorkspaceObjectIdentity identity, bool linux)
    {
        _file = file;
        _identity = identity;
        _linux = linux;
        _started = Stopwatch.GetTimestamp();
        _expiry = new Timer(static state => ((WorkspaceWriteGuard)state!).Expire(), this, Lifetime, Timeout.InfiniteTimeSpan);
    }

    /// <summary>Acquires the native guard on this same verified handle; ownership transfers only on success.</summary>
    internal static WorkspaceWriteGuard Acquire(SafeFileHandle file)
    {
        ArgumentNullException.ThrowIfNull(file);
        var identity = WorkspacePath.Identity(file);
        if (!identity.IsFile || identity.Links != 1)
        {
            throw new WorkspacePathException("file_identity_changed");
        }

        var linux = OperatingSystem.IsLinux();
        if (linux)
        {
            WorkspacePath.RequireLinuxLeaseBreakTime();
            var owner = LinuxLeaseNotifications.Owner;
            var fd = checked((int)file.DangerousGetHandle());
            var expected = new LinuxLeaseNative.Owner { Type = 0, ProcessId = owner };
            if (LinuxLeaseNative.SetOwner(fd, 15, ref expected) < 0 || LinuxLeaseNative.GetOwner(fd, 16, out var actual) < 0 ||
                actual.Type != expected.Type || actual.ProcessId != expected.ProcessId ||
                LinuxLeaseNative.Control(fd, 10, 29) < 0 || LinuxLeaseNative.Control(fd, 11, 0) != 29)
            {
                throw new WorkspacePathException("file_guard_unavailable");
            }

            if (LinuxLeaseNative.Control(fd, 1024, 1) < 0)
            {
                var error = Marshal.GetLastPInvokeError();
                throw new WorkspacePathException(error is 11 or 26 ? "file_in_use" : "file_guard_unavailable");
            }
        }
        else if (!OperatingSystem.IsWindows())
        {
            throw new WorkspacePathException("file_guard_unavailable");
        }

        var guard = new WorkspaceWriteGuard(file, identity, linux);
        try
        {
            if (linux)
            {
                LinuxLeaseNotifications.Register(guard);
            }

            guard.CheckIntact();
            return guard;
        }
        catch
        {
            guard.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Observes the current guard and object identity. On Linux F_GETLEASE also reports an initiated break. This is a
    /// point-in-time observation, not an atomic check-and-write primitive or a directory/name protection.
    /// </summary>
    internal void CheckIntact() => CheckIntact(afterLeaseCheck: null);

    // The callback coordinates a real external open in a component test; production passes no callback.
    internal void CheckIntact(Action? afterLeaseCheck)
    {
        lock (_sync)
        {
            CheckLocked(afterLeaseCheck);
        }
    }

    /// <summary>
    /// Hashes the whole bounded existing file through the guarded handle and compares a precondition. This method has
    /// no filesystem effects; a match alone is insufficient to authorize or safely execute a later mutation.
    /// </summary>
    internal bool MatchesExpectedHash(ReadOnlySpan<byte> expected, CancellationToken cancellationToken)
    {
        if (expected.Length != 32)
        {
            throw new ArgumentException("An expected SHA-256 must be 32 bytes.", nameof(expected));
        }

        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            CheckLocked();
            var file = _file!;
            var length = RandomAccess.GetLength(file);
            if (length < 0 || length > MaximumExpectedBytes)
            {
                throw new WorkspacePathException("file_too_large");
            }

            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[65536];
            long offset = 0;
            while (offset < length)
            {
                cancellationToken.ThrowIfCancellationRequested();
                CheckLocked();
                var count = RandomAccess.Read(file, buffer.AsSpan(0, (int)Math.Min(buffer.Length, length - offset)), offset);
                if (count <= 0)
                {
                    throw new WorkspacePathException("file_identity_changed");
                }

                hash.AppendData(buffer, 0, count);
                offset += count;
            }

            cancellationToken.ThrowIfCancellationRequested();
            CheckLocked();
            if (RandomAccess.GetLength(file) != length)
            {
                throw new WorkspacePathException("file_identity_changed");
            }

            CheckLocked();
            cancellationToken.ThrowIfCancellationRequested();
            var digest = hash.GetHashAndReset();
            return CryptographicOperations.FixedTimeEquals(expected, digest);
        }
    }

    /// <summary>Closes the guarded description and releases its kernel lease or exclusive Windows handle.</summary>
    public void Dispose()
    {
        lock (_sync)
        {
            CloseLocked("file_guard_closed");
        }
    }

    // A SIGIO may describe any of our leases. F_GETLEASE supplies the actual state for each guard.
    internal void InspectAfterSignal()
    {
        lock (_sync)
        {
            if (_file is null || !_linux)
            {
                return;
            }

            var result = LinuxLeaseNative.Control(checked((int)_file.DangerousGetHandle()), 1025, 0);
            if (result != 1)
            {
                CloseLocked(result < 0 ? "file_guard_unavailable" : "file_guard_breaking");
            }
        }
    }

    private void CheckLocked(Action? afterLeaseCheck = null)
    {
        CheckLeaseAndDeadlineLocked();
        afterLeaseCheck?.Invoke();

        WorkspaceObjectIdentity actual;
        try
        {
            actual = WorkspacePath.Identity(_file!);
        }
        catch (WorkspacePathException)
        {
            CloseLocked("file_guard_unavailable");
            throw;
        }

        if (!actual.IsFile || actual.Links != 1 || !_identity.SameObject(actual))
        {
            CloseLocked("file_identity_changed");
            throw new WorkspacePathException(_closedReason);
        }

        // An identity syscall may have blocked while a conflicting open initiated a break.
        CheckLeaseAndDeadlineLocked();
    }

    private void CheckLeaseAndDeadlineLocked()
    {
        if (_file is null)
        {
            throw new WorkspacePathException(_closedReason);
        }

        if (Stopwatch.GetElapsedTime(_started) >= Lifetime)
        {
            CloseLocked("file_guard_expired");
            throw new WorkspacePathException(_closedReason);
        }

        if (_linux)
        {
            if (!LinuxLeaseNotifications.IsAvailable)
            {
                CloseLocked("file_guard_unavailable");
                throw new WorkspacePathException(_closedReason);
            }

            var result = LinuxLeaseNative.Control(checked((int)_file.DangerousGetHandle()), 1025, 0);
            if (result != 1)
            {
                CloseLocked(result < 0 ? "file_guard_unavailable" : "file_guard_breaking");
                throw new WorkspacePathException(_closedReason);
            }
        }
    }

    private void Expire()
    {
        lock (_sync)
        {
            CloseLocked("file_guard_expired");
        }
    }

    private void CloseLocked(string reason)
    {
        var file = _file;
        if (file is null)
        {
            return;
        }

        _file = null;
        _closedReason = reason;
        if (_linux)
        {
            LinuxLeaseNotifications.Unregister(this);
        }

        _expiry?.Dispose();
        _expiry = null;
        file.Dispose();
    }
}

/// <summary>
/// A dedicated thread blocks and consumes SIGIO directed specifically to its Linux TID. It does not change the
/// process-wide signal disposition. Normal SIGIO coalescing is safe because every guard is checked with F_GETLEASE.
/// </summary>
internal static class LinuxLeaseNotifications
{
    private static readonly ConcurrentDictionary<WorkspaceWriteGuard, byte> Guards = new();
    private static readonly ManualResetEventSlim Started = new();
    private static readonly Thread Worker = StartWorker();
    private static int _threadId;
    private static int _healthy;
    private static int _notifications;

    internal static int Owner => IsAvailable ? Volatile.Read(ref _threadId) : throw new WorkspacePathException("file_guard_unavailable");

    internal static bool IsAvailable => Started.Wait(TimeSpan.FromSeconds(2)) && Worker.IsAlive && Volatile.Read(ref _healthy) == 1;

    internal static int NotificationCount => Volatile.Read(ref _notifications);

    internal static void Register(WorkspaceWriteGuard guard)
    {
        if (!IsAvailable || !Guards.TryAdd(guard, 0))
        {
            throw new WorkspacePathException("file_guard_unavailable");
        }

        if (!IsAvailable)
        {
            Guards.TryRemove(guard, out _);
            throw new WorkspacePathException("file_guard_unavailable");
        }
    }

    internal static void Unregister(WorkspaceWriteGuard guard) => Guards.TryRemove(guard, out _);

    private static Thread StartWorker()
    {
        var worker = new Thread(Run) { IsBackground = true, Name = "ArcForges Linux lease signal" };
        worker.Start();
        return worker;
    }

    private static void Inspect(WorkspaceWriteGuard guard)
    {
        try
        {
            guard.InspectAfterSignal();
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            Volatile.Write(ref _healthy, 0);
            try
            {
                guard.Dispose();
            }
            catch (Exception cleanup) when (cleanup is not OutOfMemoryException and not StackOverflowException)
            {
                // All future checks fail closed if the notification mechanism has become unreliable.
            }
        }
    }

    private static void Run()
    {
        try
        {
            var set = new LinuxLeaseNative.SignalSet();
            if (LinuxLeaseNative.EmptySet(ref set) != 0 || LinuxLeaseNative.AddSignal(ref set, 29) != 0 ||
                LinuxLeaseNative.ThreadSignalMask(0, ref set, 0) != 0)
            {
                return;
            }

            var tid = LinuxLeaseNative.GetThreadId();
            if (tid <= 0)
            {
                return;
            }

            Volatile.Write(ref _threadId, tid);
            Volatile.Write(ref _healthy, 1);
            Started.Set();
            while (LinuxLeaseNative.WaitSignal(ref set, out var signal) == 0 && signal == 29)
            {
                Interlocked.Increment(ref _notifications);
                foreach (var guard in Guards.Keys)
                {
                    // One slow identity/read operation must not prevent notification processing for other files.
                    if (!ThreadPool.UnsafeQueueUserWorkItem(static item => Inspect(item), guard, preferLocal: false))
                    {
                        throw new InvalidOperationException("Cannot schedule lease inspection.");
                    }
                }
            }
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not StackOverflowException)
        {
            // Any inability to run the signal thread invalidates guards and makes future acquisitions fail closed.
        }
        finally
        {
            Volatile.Write(ref _healthy, 0);
            Started.Set();
            foreach (var guard in Guards.Keys)
            {
                guard.Dispose();
            }
        }
    }
}

internal static partial class LinuxLeaseNative
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Owner
    {
        public int Type;
        public int ProcessId;
    }

    [StructLayout(LayoutKind.Sequential, Size = 128)]
    internal unsafe struct SignalSet
    {
        private fixed ulong _values[16];
    }

    [LibraryImport("libc", EntryPoint = "fcntl", SetLastError = true)]
    internal static partial int Control(int fd, int command, int value);

    [LibraryImport("libc", EntryPoint = "fcntl", SetLastError = true)]
    internal static partial int SetOwner(int fd, int command, ref Owner owner);

    [LibraryImport("libc", EntryPoint = "fcntl", SetLastError = true)]
    internal static partial int GetOwner(int fd, int command, out Owner owner);

    [LibraryImport("libc", EntryPoint = "sigemptyset")]
    internal static partial int EmptySet(ref SignalSet set);

    [LibraryImport("libc", EntryPoint = "sigaddset")]
    internal static partial int AddSignal(ref SignalSet set, int signal);

    [LibraryImport("libc", EntryPoint = "pthread_sigmask")]
    internal static partial int ThreadSignalMask(int how, ref SignalSet set, nint oldSet);

    [LibraryImport("libc", EntryPoint = "sigwait")]
    internal static partial int WaitSignal(ref SignalSet set, out int signal);

    [LibraryImport("libc", EntryPoint = "gettid")]
    internal static partial int GetThreadId();
}

internal sealed partial class WorkspacePath
{
    internal static void RequireLinuxLeaseBreakTime()
    {
        try
        {
            var raw = OpenAt(-100, "/proc", 0x200000 | 0x80000 | 0x20000 | 0x10000, 0);
            if (raw < 0)
            {
                throw new WorkspacePathException("file_guard_unavailable");
            }

            using var proc = new SafeFileHandle(raw, ownsHandle: true);
            RequireProcFs(proc);
            using var setting = LinuxOpenAt2(proc, "sys/fs/lease-break-time", 0x80000 | 0x20000 | 0x800, 0x08 | 0x04 | 0x02 | 0x01);
            RequireProcFs(setting);
            Span<byte> bytes = stackalloc byte[32];
            var count = RandomAccess.Read(setting, bytes, 0);
            if (count is <= 0 or >= 32 ||
                !int.TryParse(Encoding.ASCII.GetString(bytes[..count]).Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var seconds) ||
                seconds <= 12)
            {
                throw new WorkspacePathException("file_guard_unavailable");
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new WorkspacePathException("file_guard_unavailable", exception);
        }
    }
}
