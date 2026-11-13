// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

internal enum WindowsStageProcessObservation { Unknown, Running, Ended }

/// <summary>Persisted process creation identity; an integer HANDLE is never persisted as identity or exit proof.</summary>
[SupportedOSPlatform("windows")]
internal sealed record WindowsOwnedStageIdentity(string BootIdentity, int ProcessId, long CreationTime)
{
    internal WindowsStageProcessObservation Observe()
    {
        if (ProcessId <= 0 || CreationTime <= 0 || string.IsNullOrEmpty(BootIdentity))
            return WindowsStageProcessObservation.Unknown;
        try
        {
            if (!string.Equals(BootIdentity, global::ArcForges.Node.Core.Platform.BootIdentity.Read(), StringComparison.Ordinal))
                return WindowsStageProcessObservation.Ended;
            using var process = WindowsOwnedStageProcess.OpenObservedProcess(ProcessId);
            if (process.IsInvalid)
                return Marshal.GetLastPInvokeError() == 87 ? WindowsStageProcessObservation.Ended : WindowsStageProcessObservation.Unknown;
            if (WindowsOwnedStageProcess.CreationTimeOf(process) != CreationTime)
                return WindowsStageProcessObservation.Ended;
            return WindowsOwnedStageProcess.ObserveHandle(process);
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or UnauthorizedAccessException or Win32Exception)
        {
            return WindowsStageProcessObservation.Unknown;
        }
    }
}

/// <summary>The actual process created for a private producer. Exit checks and termination use its retained native handle.</summary>
[SupportedOSPlatform("windows")]
internal sealed partial class WindowsOwnedStageProcess : IDisposable
{
    private readonly Process _process;
    private readonly WindowsOwnedStageIdentity _identity;
    private bool _disposed;

    internal WindowsOwnedStageProcess(Process process)
    {
        ArgumentNullException.ThrowIfNull(process);
        _process = process;
        var native = process.SafeHandle;
        if (native.IsInvalid || ObserveHandle(native) != WindowsStageProcessObservation.Running)
            throw new IOException("The owned Windows stage process is unavailable.");
        _identity = new WindowsOwnedStageIdentity(BootIdentity.Read(), process.Id, CreationTimeOf(native));
    }

    internal int ProcessId => _identity.ProcessId;
    internal SafeProcessHandle Handle => _process.SafeHandle;

    internal WindowsOwnedStageIdentity SealedIdentity()
    {
        RequireLive();
        return _identity;
    }

    internal void RequireLive()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (ObserveHandle(Handle) != WindowsStageProcessObservation.Running ||
            CreationTimeOf(Handle) != _identity.CreationTime ||
            !string.Equals(BootIdentity.Read(), _identity.BootIdentity, StringComparison.Ordinal))
            throw new IOException("The exact owned Windows stage process is no longer live.");
    }

    internal bool WaitForActualExit(TimeSpan bound)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (bound < TimeSpan.Zero || bound.TotalMilliseconds > int.MaxValue) throw new ArgumentOutOfRangeException(nameof(bound));
        return WaitForSingleObject(Handle, checked((uint)Math.Ceiling(bound.TotalMilliseconds))) == 0;
    }

    /// <summary>Reaper-only wait: no managed exit event substitutes for the actual process becoming signaled.</summary>
    internal bool WaitForActualExit()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return WaitForSingleObject(Handle, uint.MaxValue) == 0;
    }

    internal void TerminateOwnedProcess()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (ObserveHandle(Handle) == WindowsStageProcessObservation.Ended) return;
        if (!TerminateProcess(Handle, 125) && ObserveHandle(Handle) != WindowsStageProcessObservation.Ended)
            throw new IOException("The owned Windows stage process could not be terminated.", new Win32Exception(Marshal.GetLastPInvokeError()));
    }

    internal static WindowsStageProcessObservation ObserveHandle(SafeProcessHandle process) => WaitForSingleObject(process, 0) switch
    {
        0 => WindowsStageProcessObservation.Ended,
        258 => WindowsStageProcessObservation.Running,
        _ => WindowsStageProcessObservation.Unknown,
    };

    internal static long CreationTimeOf(SafeProcessHandle process)
    {
        if (!GetProcessTimes(process, out var created, out _, out _, out _) || created <= 0)
            throw new IOException("The Windows stage process creation identity is unavailable.");
        return created;
    }

    internal static SafeProcessHandle OpenObservedProcess(int pid) => OpenProcess(0x00101000u, false, checked((uint)pid));

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _process.Dispose();
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool TerminateProcess(SafeProcessHandle process, uint exitCode);
}
