// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

internal enum WindowsStageProcessObservation { Unknown, Running, Ended }

/// <summary>Persisted process creation identity; an integer HANDLE is never persisted as identity or exit proof.</summary>
internal sealed record WindowsOwnedStageIdentity(string BootIdentity, int ProcessId, long CreationTime)
{
    [SupportedOSPlatform("windows")]
    internal WindowsStageProcessObservation Observe() =>
        Observe(global::ArcForges.Node.Core.Platform.BootIdentity.Read, ObserveExactProcess);

    internal WindowsStageProcessObservation Observe(Func<string?> readBoot,
        Func<int, long, WindowsStageProcessObservation> observeProcess)
    {
        if (ProcessId <= 0 || CreationTime <= 0 || string.IsNullOrEmpty(BootIdentity))
            return WindowsStageProcessObservation.Unknown;
        try
        {
            if (!global::ArcForges.Node.Core.Platform.BootIdentity.TryCompareWindowsBoot(BootIdentity, readBoot(), out var sameBoot))
                return WindowsStageProcessObservation.Unknown;
            return sameBoot ? observeProcess(ProcessId, CreationTime) : WindowsStageProcessObservation.Ended;
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or UnauthorizedAccessException or
            Win32Exception or System.Security.SecurityException)
        {
            return WindowsStageProcessObservation.Unknown;
        }
    }

    [SupportedOSPlatform("windows")]
    private static WindowsStageProcessObservation ObserveExactProcess(int processId, long creationTime)
    {
        using var process = WindowsOwnedStageProcess.OpenObservedProcess(processId);
        if (process.IsInvalid)
            return Marshal.GetLastPInvokeError() == 87 ? WindowsStageProcessObservation.Ended : WindowsStageProcessObservation.Unknown;
        if (WindowsOwnedStageProcess.CreationTimeOf(process) != creationTime)
            return WindowsStageProcessObservation.Ended;
        return WindowsOwnedStageProcess.ObserveHandle(process);
    }
}

/// <summary>Read-only native process observations for persisted worker identities.</summary>
[SupportedOSPlatform("windows")]
internal static partial class WindowsOwnedStageProcess
{
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

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint WaitForSingleObject(SafeProcessHandle handle, uint milliseconds);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetProcessTimes(SafeProcessHandle process, out long creation, out long exit, out long kernel, out long user);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial SafeProcessHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);
}
