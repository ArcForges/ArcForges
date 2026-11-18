// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.MxcProbe;

[SupportedOSPlatform("windows")]
internal static partial class ConPtyNative
{
    [StructLayout(LayoutKind.Sequential)] internal readonly record struct Coord(short X, short Y);
    [StructLayout(LayoutKind.Sequential)] internal struct StartupInfo { public int Cb; public nint Reserved, Desktop, Title; public uint X, Y, XSize, YSize, XChars, YChars, FillAttribute, Flags; public ushort ShowWindow, Reserved2Size; public nint Reserved2, StdInput, StdOutput, StdError; }
    [StructLayout(LayoutKind.Sequential)] internal struct StartupInfoEx { public StartupInfo Info; public nint Attributes; }
    [StructLayout(LayoutKind.Sequential)] internal struct ProcessInformation { public nint Process, Thread; public uint ProcessId, ThreadId; }
    [StructLayout(LayoutKind.Sequential)] internal struct BasicLimits { public long ProcessTime, JobTime; public uint LimitFlags; public nuint MinimumWorkingSet, MaximumWorkingSet; public uint ActiveProcessLimit; public nuint Affinity; public uint PriorityClass, SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)] internal struct ExtendedLimits { public BasicLimits Basic; public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes; public nuint ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemory, PeakJobMemory; }
    [StructLayout(LayoutKind.Sequential)] internal struct CpuLimits { public uint Flags, Rate; }
    [StructLayout(LayoutKind.Sequential)] internal struct Accounting { public long UserTime, KernelTime, PeriodUser, PeriodKernel; public uint PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses; }
    [StructLayout(LayoutKind.Sequential)] internal struct UnicodeString { public ushort Length, MaximumLength; public nint Buffer; }

    [LibraryImport("kernel32.dll")] internal static partial int CreatePseudoConsole(Coord size, SafePipeHandle input, SafePipeHandle output, uint flags, out nint console);
    [LibraryImport("kernel32.dll")] internal static partial int ResizePseudoConsole(nint console, Coord size);
    [LibraryImport("kernel32.dll")] internal static partial void ClosePseudoConsole(nint console);
    [LibraryImport("kernel32.dll", EntryPoint = "CreateJobObjectW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)] internal static partial SafeFileHandle CreateJobObject(nint attributes, string? name);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] internal static unsafe partial bool SetInformationJobObject(SafeFileHandle job, int kind, void* info, int length);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] internal static unsafe partial bool QueryInformationJobObject(SafeFileHandle job, int kind, void* info, int length, out int returned);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] internal static partial bool AssignProcessToJobObject(SafeFileHandle job, SafeFileHandle process);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] internal static partial bool IsProcessInJob(nint process, nint job, [MarshalAs(UnmanagedType.Bool)] out bool result);
    [LibraryImport("kernel32.dll")] internal static partial nint GetCurrentProcess();
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] internal static partial bool InitializeProcThreadAttributeList(nint list, int count, uint flags, ref nuint bytes);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] internal static unsafe partial bool UpdateProcThreadAttribute(nint list, uint flags, nuint attribute, void* value, nuint bytes, nint previous, nint returned);
    [LibraryImport("kernel32.dll")] internal static partial void DeleteProcThreadAttributeList(nint list);
    [LibraryImport("kernel32.dll", EntryPoint = "CreateProcessW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)][return: MarshalAs(UnmanagedType.Bool)] internal static unsafe partial bool CreateProcess(string application, char* command, nint processAttributes, nint threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint flags, char* environment, string directory, ref StartupInfoEx startup, out ProcessInformation process);
    [LibraryImport("kernel32.dll", SetLastError = true)] internal static partial uint ResumeThread(nint thread);
    [LibraryImport("kernel32.dll", SetLastError = true)] internal static partial uint WaitForSingleObject(SafeFileHandle handle, uint milliseconds);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] internal static partial bool GetExitCodeProcess(SafeFileHandle process, out uint exitCode);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] internal static partial bool GetProcessTimes(SafeFileHandle process, out long creation, out long exit, out long kernel, out long user);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] internal static partial bool TerminateProcess(SafeFileHandle process, uint exitCode);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] internal static partial bool TerminateJobObject(SafeFileHandle job, uint exitCode);
    [LibraryImport("kernel32.dll")][return: MarshalAs(UnmanagedType.Bool)] internal static partial bool CloseHandle(nint handle);
    [LibraryImport("ntdll.dll")] internal static partial int NtQueryInformationProcess(SafeFileHandle process, int kind, nint information, int length, out int returned);
}
