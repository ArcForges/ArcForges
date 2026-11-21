// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Platform;

/// <summary>Creates the native Job for Windows stage lifetime fixtures.</summary>
[SupportedOSPlatform("windows")]
internal sealed partial class WindowsStageJob : IDisposable
{
    private readonly SafeFileHandle _handle;

    internal WindowsStageJob()
    {
        _handle = CreateJobObject(0, 0);
        if (_handle.IsInvalid) { _handle.Dispose(); throw new IOException("The stage job is unavailable."); }
        var limits = new ExtendedLimits { Basic = new BasicLimits { Flags = 0x2000 } }; // KILL_ON_JOB_CLOSE, no breakaway.
        if (!SetInformationJobObject(_handle, 9, ref limits, checked((uint)Marshal.SizeOf<ExtendedLimits>())))
        {
            _handle.Dispose();
            throw new IOException("The stage job lifetime could not be installed.");
        }
    }

    internal void Assign(WindowsOwnedStageProcess process)
    {
        process.RequireLive();
        if (!AssignProcessToJobObject(_handle, process.Handle) ||
            !IsProcessInJob(process.Handle, _handle, out var member) || !member)
            throw new IOException("The owned stage process did not enter its lifetime job.");
    }

    public void Dispose() => _handle.Dispose();

    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimits
    {
        internal long ProcessTime;
        internal long JobTime;
        internal uint Flags;
        internal nuint MinimumWorkingSet;
        internal nuint MaximumWorkingSet;
        internal uint ActiveProcesses;
        internal nuint Affinity;
        internal uint Priority;
        internal uint Scheduling;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        internal ulong ReadOperations;
        internal ulong WriteOperations;
        internal ulong OtherOperations;
        internal ulong ReadBytes;
        internal ulong WriteBytes;
        internal ulong OtherBytes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimits
    {
        internal BasicLimits Basic;
        internal IoCounters Io;
        internal nuint ProcessMemory;
        internal nuint JobMemory;
        internal nuint PeakProcessMemory;
        internal nuint PeakJobMemory;
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateJobObjectW", SetLastError = true)]
    private static partial SafeFileHandle CreateJobObject(nint attributes, nint name);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetInformationJobObject(SafeFileHandle job, int informationClass, ref ExtendedLimits information, uint size);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AssignProcessToJobObject(SafeFileHandle job, SafeProcessHandle process);
    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IsProcessInJob(SafeProcessHandle process, SafeFileHandle job, [MarshalAs(UnmanagedType.Bool)] out bool member);
}
