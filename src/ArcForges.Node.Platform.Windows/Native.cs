// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Platform.Windows;

/// <summary>A kernel object handle closed with <c>CloseHandle</c>.</summary>
[SupportedOSPlatform("windows")]
public sealed class SafeKernelHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    /// <summary>Creates an empty handle (used by the marshaller).</summary>
    public SafeKernelHandle()
        : base(ownsHandle: true)
    {
    }

    /// <summary>Wraps an existing handle.</summary>
    public SafeKernelHandle(nint handle, bool ownsHandle)
        : base(ownsHandle) => SetHandle(handle);

    /// <inheritdoc />
    protected override bool ReleaseHandle() => Native.CloseHandle(handle);
}

/// <summary>A launched Windows process and its owned handles.</summary>
[SupportedOSPlatform("windows")]
public sealed class LaunchedProcess : IDisposable
{
    internal LaunchedProcess(SafeKernelHandle process, SafeKernelHandle thread, int processId)
    {
        Process = process;
        Thread = thread;
        ProcessId = processId;
    }

    /// <summary>The process handle (full access).</summary>
    public SafeKernelHandle Process { get; }

    /// <summary>The primary thread handle (closed once resumed).</summary>
    public SafeKernelHandle Thread { get; }

    /// <summary>The process ID.</summary>
    public int ProcessId { get; }

    /// <summary>The creation time as a FILETIME.</summary>
    public long CreationFileTime => ProcessInfo.CreationFileTime(Process);

    /// <summary>Resumes a process created suspended.</summary>
    public void Resume()
    {
        if (Native.ResumeThread(Thread.DangerousGetHandle()) == uint.MaxValue)
        {
            throw new Win32Exception(Native.LastError, "ResumeThread failed.");
        }

        Thread.Dispose();
    }

    /// <summary>Waits for the process to exit; false on timeout.</summary>
    public bool WaitForExit(TimeSpan timeout) =>
        Native.WaitForSingleObject(Process, timeout == Timeout.InfiniteTimeSpan ? Native.Infinite : (uint)Math.Clamp(timeout.TotalMilliseconds, 0, uint.MaxValue - 1))
            == Native.WaitObject0;

    /// <summary>The exit code (259 while running).</summary>
    public uint ExitCode => Native.GetExitCodeProcess(Process, out var code) ? code : uint.MaxValue;

    /// <summary>Terminates the process.</summary>
    public void Kill(uint exitCode) => Native.TerminateProcess(Process, exitCode);

    /// <summary>Closes the handles.</summary>
    public void Dispose()
    {
        Thread.Dispose();
        Process.Dispose();
    }
}

/// <summary>Process identity helpers.</summary>
[SupportedOSPlatform("windows")]
public static unsafe class ProcessInfo
{
    /// <summary>A process's creation time as a FILETIME, or 0.</summary>
    public static long CreationFileTime(SafeHandle process) => Native.GetProcessTimes(process, out var creation, out _, out _, out _) ? creation : 0;

    /// <summary>A FILETIME as an instant.</summary>
    public static DateTimeOffset FromFileTime(long fileTime) => DateTimeOffset.FromFileTime(fileTime).ToUniversalTime();

    /// <summary>Opens a process for query and synchronize (and terminate when asked), or returns <see langword="null"/>.</summary>
    public static SafeKernelHandle? Open(int processId, bool terminate = false)
    {
        var handle = Native.OpenProcess(Native.ProcessQueryLimitedInformation | Native.Synchronize | (terminate ? Native.ProcessTerminate : 0), inherit: false, processId);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            return null;
        }

        return handle;
    }

    /// <summary>Opens a process only when it is still the one created at <paramref name="creationFileTime"/>.</summary>
    public static SafeKernelHandle? OpenIdentified(int processId, long creationFileTime, bool terminate = false)
    {
        var handle = Open(processId, terminate);
        if (handle is null)
        {
            return null;
        }

        // Stored start times keep microseconds; FILETIME counts 100 ns.
        if (Math.Abs(CreationFileTime(handle) - creationFileTime) >= 10)
        {
            handle.Dispose();
            return null;
        }

        return handle;
    }

    /// <summary>True when the process has not exited.</summary>
    public static bool IsRunning(SafeHandle process) => Native.WaitForSingleObject(process, 0) == Native.WaitTimeout;

    /// <summary>The image file name (no directory), or the process ID as text.</summary>
    public static string ImageName(int processId)
    {
        using var handle = Open(processId);
        return handle is null ? processId.ToString(System.Globalization.CultureInfo.InvariantCulture)
            : ImageName(handle) ?? processId.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>The image file name (no directory) of an open process, or <see langword="null"/>.</summary>
    public static string? ImageName(SafeHandle process)
    {
        var buffer = stackalloc char[1024];
        var size = 1024;
        return Native.QueryFullProcessImageName(process, 0, buffer, ref size) ? Path.GetFileName(new string(buffer, 0, size)) : null;
    }

    /// <summary>Every process with its parent ID and image (a Toolhelp snapshot).</summary>
    public static List<(int Pid, int ParentPid, string Image)> Snapshot()
    {
        var result = new List<(int, int, string)>();
        using var snapshot = Native.CreateToolhelp32Snapshot(Native.Th32csSnapProcess, 0);
        if (snapshot.IsInvalid)
        {
            return result;
        }

        var entry = default(Native.ProcessEntry32);
        entry.Size = sizeof(Native.ProcessEntry32);
        if (!Native.Process32First(snapshot, &entry))
        {
            return result;
        }

        do
        {
            result.Add((entry.ProcessId, entry.ParentProcessId, new string(entry.ExeFile)));
            entry.Size = sizeof(Native.ProcessEntry32);
        }
        while (Native.Process32Next(snapshot, &entry));
        return result;
    }

    /// <summary>The machine's physical memory.</summary>
    public static long PhysicalMemory()
    {
        var status = default(Native.MemoryStatusEx);
        status.Length = sizeof(Native.MemoryStatusEx);
        return Native.GlobalMemoryStatusEx(&status) ? (long)status.TotalPhys : GC.GetGCMemoryInfo().TotalAvailableMemoryBytes;
    }
}

/// <summary>Win32 declarations of the Windows platform (source-generated P/Invoke).</summary>
[SupportedOSPlatform("windows")]
internal static unsafe partial class Native
{
    public const int ErrorFileNotFound = 2;
    public const int ErrorAccessDenied = 5;
    public const int ErrorInvalidHandle = 6;
    public const int ErrorInvalidParameter = 87;
    public const int ErrorBrokenPipe = 109;
    public const int ErrorGenFailure = 31;
    public const uint WaitObject0 = 0;
    public const uint WaitTimeout = 0x102;
    public const uint Infinite = 0xFFFFFFFF;
    public const uint StillActive = 259;

    public const uint CreateSuspended = 0x00000004;
    public const uint DetachedProcess = 0x00000008;
    public const uint CreateNewProcessGroup = 0x00000200;
    public const uint CreateUnicodeEnvironment = 0x00000400;
    public const uint ExtendedStartupInfoPresent = 0x00080000;
    public const uint CreateNoWindow = 0x08000000;
    public const uint SemFailCriticalErrors = 0x0001;
    public const int StartfUseStdHandles = 0x00000100;
    public const nint ProcThreadAttributeHandleList = 0x00020002;
    public const nint ProcThreadAttributeParentProcess = 0x00020000;
    public const uint ProcessCreateProcess = 0x0080;
    public const uint TokenQuery = 0x0008;

    public const uint JobObjectAllAccess = 0x1F001F;
    public const uint JobObjectSetAttributes = 0x0002;
    public const uint JobObjectQuery = 0x0004;
    public const uint JobObjectTerminate = 0x0008;
    public const uint ProcessQueryLimitedInformation = 0x1000;
    public const uint ProcessDuplicateHandle = 0x0040;
    public const uint ProcessTerminate = 0x0001;
    public const uint ProcessSetQuota = 0x0100;
    public const uint Synchronize = 0x00100000;
    public const uint EventModifyState = 0x0002;
    public const uint DuplicateCloseSource = 0x00000001;
    public const uint DuplicateSameAccess = 0x00000002;
    public const uint HandleFlagInherit = 0x00000001;

    public const int JobObjectBasicAccountingInformationClass = 1;
    public const int JobObjectBasicLimitInformationClass = 2;
    public const int JobObjectBasicProcessIdListClass = 3;
    public const int JobObjectAssociateCompletionPortInformationClass = 7;
    public const int JobObjectBasicAndIoAccountingInformationClass = 8;
    public const int JobObjectExtendedLimitInformationClass = 9;
    public const int JobObjectNotificationLimitInformationClass = 12;
    public const int JobObjectLimitViolationInformationClass = 13;
    public const int JobObjectCpuRateControlInformationClass = 15;

    public const uint JobObjectLimitJobTime = 0x00000004;
    public const uint JobObjectLimitActiveProcess = 0x00000008;
    public const uint JobObjectLimitPriorityClass = 0x00000020;
    public const uint JobObjectLimitJobMemory = 0x00000200;
    public const uint JobObjectLimitKillOnJobClose = 0x00002000;

    public const uint BelowNormalPriorityClass = 0x00004000;
    public const uint NormalPriorityClass = 0x00000020;

    public const uint CpuRateControlEnable = 0x1;
    public const uint CpuRateControlWeightBased = 0x2;
    public const uint CpuRateControlHardCap = 0x4;

    public const uint JobMsgEndOfJobTime = 1;
    public const uint JobMsgActiveProcessLimit = 3;
    public const uint JobMsgActiveProcessZero = 4;
    public const uint JobMsgNewProcess = 6;
    public const uint JobMsgExitProcess = 7;
    public const uint JobMsgAbnormalExitProcess = 8;
    public const uint JobMsgProcessMemoryLimit = 9;
    public const uint JobMsgJobMemoryLimit = 10;
    public const uint JobMsgNotificationLimit = 11;

    public const uint CtrlBreakEvent = 1;
    public const uint WmClose = 0x0010;
    public const uint Th32csSnapProcess = 0x00000002;

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public nuint MinimumWorkingSetSize;
        public nuint MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public nuint Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public nuint ProcessMemoryLimit;
        public nuint JobMemoryLimit;
        public nuint PeakProcessMemoryUsed;
        public nuint PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectBasicAccountingInformation
    {
        public long TotalUserTime;
        public long TotalKernelTime;
        public long ThisPeriodTotalUserTime;
        public long ThisPeriodTotalKernelTime;
        public uint TotalPageFaultCount;
        public uint TotalProcesses;
        public uint ActiveProcesses;
        public uint TotalTerminatedProcesses;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectBasicAndIoAccountingInformation
    {
        public JobObjectBasicAccountingInformation BasicInfo;
        public IoCounters IoInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectCpuRateControlInformation
    {
        public uint ControlFlags;
        public uint Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectAssociateCompletionPort
    {
        public nint CompletionKey;
        public nint CompletionPort;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectNotificationLimitInformation
    {
        public ulong IoReadBytesLimit;
        public ulong IoWriteBytesLimit;
        public long PerJobUserTimeLimit;
        public ulong JobMemoryLimit;
        public int RateControlTolerance;
        public int RateControlToleranceInterval;
        public uint LimitFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectLimitViolationInformation
    {
        public uint LimitFlags;
        public uint ViolationLimitFlags;
        public ulong IoReadBytes;
        public ulong IoReadBytesLimit;
        public ulong IoWriteBytes;
        public ulong IoWriteBytesLimit;
        public long PerJobUserTime;
        public long PerJobUserTimeLimit;
        public ulong JobMemory;
        public ulong JobMemoryLimit;
        public int RateControlTolerance;
        public int RateControlToleranceLimit;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct StartupInfo
    {
        public int Cb;
        public nint Reserved;
        public nint Desktop;
        public nint Title;
        public int X;
        public int Y;
        public int XSize;
        public int YSize;
        public int XCountChars;
        public int YCountChars;
        public int FillAttribute;
        public int Flags;
        public short ShowWindow;
        public short Reserved2;
        public nint Reserved3;
        public nint StdInput;
        public nint StdOutput;
        public nint StdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct StartupInfoEx
    {
        public StartupInfo StartupInfo;
        public nint AttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessInformation
    {
        public nint Process;
        public nint Thread;
        public int ProcessId;
        public int ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecurityAttributes
    {
        public int Length;
        public nint SecurityDescriptor;
        public int InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessEntry32
    {
        public int Size;
        public int Usage;
        public int ProcessId;
        public nint DefaultHeapId;
        public int ModuleId;
        public int Threads;
        public int ParentProcessId;
        public int PriorityClassBase;
        public int Flags;
        public fixed char ExeFile[260];
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MemoryStatusEx
    {
        public int Length;
        public int MemoryLoad;
        public ulong TotalPhys;
        public ulong AvailPhys;
        public ulong TotalPageFile;
        public ulong AvailPageFile;
        public ulong TotalVirtual;
        public ulong AvailVirtual;
        public ulong AvailExtendedVirtual;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CloseHandle(nint handle);

    [LibraryImport("kernel32.dll", EntryPoint = "CreateJobObjectW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    public static partial SafeKernelHandle CreateJobObject(nint attributes, string? name);

    [LibraryImport("kernel32.dll", EntryPoint = "OpenJobObjectW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    public static partial SafeKernelHandle OpenJobObject(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, string name);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool AssignProcessToJobObject(SafeHandle job, SafeHandle process);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool SetInformationJobObject(SafeHandle job, int informationClass, void* information, int length);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool QueryInformationJobObject(SafeHandle job, int informationClass, void* information, int length, out int returned);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool TerminateJobObject(SafeHandle job, uint exitCode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool IsProcessInJob(SafeHandle process, nint job, [MarshalAs(UnmanagedType.Bool)] out bool result);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial SafeKernelHandle CreateIoCompletionPort(nint fileHandle, nint existingPort, nuint key, int threads);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetQueuedCompletionStatus(SafeHandle port, out uint bytes, out nuint key, out nint overlapped, uint milliseconds);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool PostQueuedCompletionStatus(SafeHandle port, uint bytes, nuint key, nint overlapped);

    [LibraryImport("kernel32.dll", EntryPoint = "CreateProcessW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CreateProcess(string? application, char* commandLine, nint processAttributes, nint threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint creationFlags, char* environment, string? currentDirectory, StartupInfoEx* startupInfo,
        out ProcessInformation processInformation);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool SetThreadErrorMode(uint newMode, out uint oldMode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool InitializeProcThreadAttributeList(nint list, int count, int flags, ref nint size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool UpdateProcThreadAttribute(nint list, int flags, nint attribute, void* value, nint size, nint previous, nint returnSize);

    [LibraryImport("kernel32.dll")]
    public static partial void DeleteProcThreadAttributeList(nint list);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial uint ResumeThread(nint thread);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial uint WaitForSingleObject(SafeHandle handle, uint milliseconds);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetExitCodeProcess(SafeHandle process, out uint exitCode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetProcessTimes(SafeHandle process, out long creation, out long exit, out long kernel, out long user);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool OpenProcessToken(SafeHandle process, uint access, out SafeKernelHandle token);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial SafeKernelHandle OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, int processId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool TerminateProcess(SafeHandle process, uint exitCode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial nint GetCurrentProcess();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool DuplicateHandle(nint sourceProcess, SafeHandle source, nint targetProcess, out nint target, uint access,
        [MarshalAs(UnmanagedType.Bool)] bool inherit, uint options);

    /// <summary>Duplicates a handle as inheritable with the same access. The caller closes the duplicate.</summary>
    internal static nint DuplicateInheritableHandle(SafeHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        if (!DuplicateHandle(GetCurrentProcess(), handle, GetCurrentProcess(), out var copy, 0, inherit: true, DuplicateSameAccess))
        {
            throw new Win32Exception(LastError, "DuplicateHandle failed.");
        }

        return copy;
    }

    [LibraryImport("kernel32.dll", EntryPoint = "DuplicateHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool DuplicateRemoteHandle(SafeKernelHandle sourceProcess, nint source, nint targetProcess, out nint target,
        uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint options);

    [LibraryImport("KernelBase.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CompareObjectHandles(SafeKernelHandle first, SafeKernelHandle second);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool SetHandleInformation(SafeHandle handle, uint mask, uint flags);

    [LibraryImport("kernel32.dll", EntryPoint = "CreateEventW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    public static partial SafeKernelHandle CreateEvent(nint attributes, [MarshalAs(UnmanagedType.Bool)] bool manualReset,
        [MarshalAs(UnmanagedType.Bool)] bool initialState, string? name);

    [LibraryImport("kernel32.dll", EntryPoint = "OpenEventW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    public static partial SafeKernelHandle OpenEvent(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, string name);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool SetEvent(SafeHandle handle);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool CreatePipe(out nint read, out nint write, ref SecurityAttributes attributes, int size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetFileSizeEx(SafeHandle file, out long size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool FreeConsole();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool AttachConsole(int processId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool SetConsoleCtrlHandler(delegate* unmanaged<uint, int> handler, [MarshalAs(UnmanagedType.Bool)] bool add);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GenerateConsoleCtrlEvent(uint ctrlEvent, int processGroupId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    public static partial SafeKernelHandle CreateToolhelp32Snapshot(uint flags, int processId);

    [LibraryImport("kernel32.dll", EntryPoint = "Process32FirstW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool Process32First(SafeHandle snapshot, ProcessEntry32* entry);

    [LibraryImport("kernel32.dll", EntryPoint = "Process32NextW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool Process32Next(SafeHandle snapshot, ProcessEntry32* entry);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool QueryFullProcessImageName(SafeHandle process, int flags, char* name, ref int size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GlobalMemoryStatusEx(MemoryStatusEx* status);

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    public static partial SafeFileHandle CreateFile(string name, uint access, uint share, ref SecurityAttributes attributes, uint disposition, uint flags, nint template);

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool EnumWindows(delegate* unmanaged<nint, nint, int> callback, nint parameter);

    [LibraryImport("user32.dll", SetLastError = true)]
    public static partial uint GetWindowThreadProcessId(nint window, out int processId);

    [LibraryImport("user32.dll", EntryPoint = "PostMessageW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool PostMessage(nint window, uint message, nint wParam, nint lParam);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static partial bool GetSystemTimes(out long idle, out long kernel, out long user);

    [LibraryImport("ntdll.dll")]
    public static partial int NtQuerySystemInformation(int informationClass, void* information, int length, out int returned);

    [LibraryImport("ntdll.dll")]
    public static partial int RtlNtStatusToDosError(int status);

    /// <summary>The calling thread's last Win32 error.</summary>
    public static int LastError => Marshal.GetLastPInvokeError();
}
