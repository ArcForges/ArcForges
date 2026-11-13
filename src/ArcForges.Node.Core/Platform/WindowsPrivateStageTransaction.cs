// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

/// <summary>
/// A private-stage-only kernel transaction. Its timeout is armed before empty-object creation and lies within the
/// original QPC budget. This is neither a workspace target-write guard nor permission to write any private body.
/// </summary>
[SupportedOSPlatform("windows")]
internal sealed partial class WindowsPrivateStageTransaction : IDisposable
{
    private readonly long _deadline;
    private readonly long _expiryMicroseconds;
    private bool _completed;
    private bool _disposed;

    private WindowsPrivateStageTransaction(SafeFileHandle handle, long deadline, long expiryMicroseconds, uint timeout)
    {
        Handle = handle;
        _deadline = deadline;
        _expiryMicroseconds = expiryMicroseconds;
        TimeoutMilliseconds = timeout;
        if (!GetTransactionId(handle, out var id)) throw Unavailable();
        Id = id;
    }

    internal SafeFileHandle Handle { get; }
    internal Guid Id { get; }
    internal uint TimeoutMilliseconds { get; }

    internal static WindowsPrivateStageTransaction Arm(long originalDeadline, long expiryMicroseconds)
    {
        var now = Stopwatch.GetTimestamp();
        var remaining = originalDeadline - now;
        if (remaining <= 0 || remaining > checked(10 * Stopwatch.Frequency))
            throw new WorkspacePathException("file_guard_expired");
        var monotonicMilliseconds = checked((long)((decimal)remaining * 1000 / Stopwatch.Frequency));
        var realMilliseconds = (expiryMicroseconds - UtcMicroseconds()) / 1000;
        var timeout = Math.Min(monotonicMilliseconds, realMilliseconds) / 2;
        if (timeout is < 1 or > 10_000) throw new WorkspacePathException("file_guard_expired");
        var handle = CreateTransaction(0, 0, 0, 0, 0, checked((uint)timeout), 0);
        if (handle.IsInvalid) { handle.Dispose(); throw Unavailable(); }
        WindowsPrivateStageTransaction? result = null;
        try
        {
            // A delayed CreateTransaction may not grant a fresh duration after the original operation expired.
            var afterArm = Stopwatch.GetTimestamp();
            var requestedTicks = checked((long)Math.Ceiling((decimal)timeout * Stopwatch.Frequency / 1000));
            if (afterArm >= originalDeadline || checked(afterArm + requestedTicks) > originalDeadline ||
                checked(UtcMicroseconds() + timeout * 1000) > expiryMicroseconds)
                throw new WorkspacePathException("file_guard_expired");
            result = new WindowsPrivateStageTransaction(handle, originalDeadline, expiryMicroseconds, checked((uint)timeout));
            result.RequireActive();
            return result;
        }
        catch
        {
            if (result is not null) result.Dispose();
            else { _ = RollbackTransaction(handle); handle.Dispose(); }
            throw;
        }
    }

    /// <summary>Adopts a duplicate of the exact kernel transaction after the pipe's process identity was verified.</summary>
    internal static WindowsPrivateStageTransaction AdoptDuplicate(SafeFileHandle handle, Guid expectedId,
        long originalDeadline, long expiryMicroseconds, uint timeoutMilliseconds)
    {
        ArgumentNullException.ThrowIfNull(handle);
        WindowsPrivateStageTransaction? result = null;
        try
        {
            if (handle.IsInvalid || timeoutMilliseconds is < 1 or > 10_000) throw Unavailable();
            result = new WindowsPrivateStageTransaction(handle, originalDeadline, expiryMicroseconds, timeoutMilliseconds);
            if (result.Id != expectedId) throw Unavailable();
            result.RequireActive();
            return result;
        }
        catch
        {
            if (result is not null) result.Dispose();
            else handle.Dispose();
            throw;
        }
    }

    internal void RequireActive()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_completed || Stopwatch.GetTimestamp() >= _deadline || UtcMicroseconds() >= _expiryMicroseconds)
            throw new WorkspacePathException("file_guard_expired");
        if (!GetTransactionId(Handle, out var id) || id != Id ||
            !GetTransactionInformation(Handle, out var outcome, out _, out _, out _, 0, 0) || outcome != 1)
            throw new WorkspacePathException("file_guard_expired");
    }

    internal void Commit()
    {
        RequireActive();
        if (!CommitTransaction(Handle)) throw Unavailable();
        _completed = true;
        if (!GetTransactionInformation(Handle, out var outcome, out _, out _, out _, 0, 0) || outcome != 2)
            throw Unavailable();
    }

    internal void ConfirmCommitted()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!GetTransactionId(Handle, out var id) || id != Id ||
            !GetTransactionInformation(Handle, out var outcome, out _, out _, out _, 0, 0) || outcome != 2)
            throw Unavailable();
        _completed = true;
    }

    /// <summary>Thread-scoped only: no await or other file open may occur inside this scope.</summary>
    internal nint EnterCurrent()
    {
        RequireActive();
        var previous = RtlGetCurrentTransaction();
        if (!RtlSetCurrentTransaction(Handle.DangerousGetHandle())) throw Unavailable();
        return previous;
    }

    internal static void RestoreCurrent(nint previous)
    {
        if (!RtlSetCurrentTransaction(previous)) throw Unavailable();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (!_completed) _ = RollbackTransaction(Handle);
        Handle.Dispose();
    }

    private static long UtcMicroseconds() => (DateTime.UtcNow.Ticks - DateTime.UnixEpoch.Ticks) / 10;
    private static IOException Unavailable() => new("The private stage kernel transaction is unavailable.",
        new Win32Exception(Marshal.GetLastPInvokeError()));

    [LibraryImport("KtmW32.dll", SetLastError = true)]
    private static partial SafeFileHandle CreateTransaction(nint attributes, nint unitOfWork, uint createOptions,
        uint isolationLevel, uint isolationFlags, uint timeoutMilliseconds, nint description);

    [LibraryImport("KtmW32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetTransactionId(SafeFileHandle transaction, out Guid id);

    [LibraryImport("KtmW32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetTransactionInformation(SafeFileHandle transaction, out uint outcome,
        out uint isolationLevel, out uint isolationFlags, out uint timeout, uint descriptionLength, nint description);

    [LibraryImport("KtmW32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CommitTransaction(SafeFileHandle transaction);

    [LibraryImport("KtmW32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool RollbackTransaction(SafeFileHandle transaction);

    [LibraryImport("ntdll.dll")]
    private static partial nint RtlGetCurrentTransaction();

    [LibraryImport("ntdll.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool RtlSetCurrentTransaction(nint transaction);
}
