// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Platform.Windows;

/// <summary>A process started by <see cref="ProcessLauncher"/>.</summary>
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

/// <summary>What <see cref="ProcessLauncher.Start"/> starts.</summary>
public sealed class LaunchOptions
{
    /// <summary>The executable (absolute path).</summary>
    public required string Application { get; init; }

    /// <summary>The complete command line.</summary>
    public required string CommandLine { get; init; }

    /// <summary>The working directory (null: the caller's).</summary>
    public string? WorkingDirectory { get; init; }

    /// <summary>The environment as <c>NAME=value</c> entries (null: the caller's).</summary>
    public IReadOnlyList<string>? Environment { get; init; }

    /// <summary>Creation flags beyond <c>EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT</c>.</summary>
    public uint Flags { get; init; }

    /// <summary>The standard handles (all three or none); they are the only handles the process inherits.</summary>
    public SafeHandle? StdInput { get; init; }

    /// <summary>Standard output.</summary>
    public SafeHandle? StdOutput { get; init; }

    /// <summary>Standard error.</summary>
    public SafeHandle? StdError { get; init; }

    /// <summary>
    /// Further handles the process inherits (the holder's job handles, attempt stdio and ack event): already inheritable handles the
    /// caller owns and closes after the call; their values are the same in the new process.
    /// </summary>
    public IReadOnlyList<nint> InheritableHandles { get; init; } = [];

    /// <summary>
    /// The process to create the new one as a child of (<c>PROC_THREAD_ATTRIBUTE_PARENT_PROCESS</c>; needs PROCESS_CREATE_PROCESS on it).
    /// The new process takes that parent's job membership at creation. Only without inherited handles, since those would have to exist
    /// in the parent's handle table.
    /// </summary>
    public SafeHandle? ParentProcess { get; init; }
}

/// <summary>
/// <c>CreateProcessW</c> with <c>STARTUPINFOEX</c> (04 section 3): inheritance restricted to an explicit handle list
/// (<c>PROC_THREAD_ATTRIBUTE_HANDLE_LIST</c>), so a process receives exactly its standard handles and the handles named for it, never
/// another attempt's. Handles in the list are duplicated as inheritable for the call and closed afterwards, so the caller's own handles
/// stay non-inheritable and no later child can inherit them by accident.
/// </summary>
[SupportedOSPlatform("windows")]
public static unsafe class ProcessLauncher
{
    /// <summary>Starts a process; returns it with its identity.</summary>
    /// <exception cref="Win32Exception">The process could not be created (the error code says why).</exception>
    public static LaunchedProcess Start(LaunchOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var duplicates = new List<nint>();
        nint attributeList = 0;
        nint listMemory = 0;
        nint parentMemory = 0;
        try
        {
            nint Inheritable(SafeHandle handle)
            {
                if (!Native.DuplicateHandle(Native.GetCurrentProcess(), handle, Native.GetCurrentProcess(), out var copy, 0, inherit: true,
                    Native.DuplicateSameAccess))
                {
                    throw new Win32Exception(Native.LastError, "DuplicateHandle failed.");
                }

                duplicates.Add(copy);
                return copy;
            }

            var startup = default(Native.StartupInfoEx);
            startup.StartupInfo.Cb = sizeof(Native.StartupInfoEx);
            var listed = new List<nint>();
            if (options.StdInput is not null || options.StdOutput is not null || options.StdError is not null)
            {
                startup.StartupInfo.Flags = Native.StartfUseStdHandles;
                startup.StartupInfo.StdInput = options.StdInput is null ? 0 : Inheritable(options.StdInput);
                startup.StartupInfo.StdOutput = options.StdOutput is null ? 0 : Inheritable(options.StdOutput);
                startup.StartupInfo.StdError = options.StdError is null ? 0 : Inheritable(options.StdError);
                foreach (var handle in (nint[])[startup.StartupInfo.StdInput, startup.StartupInfo.StdOutput, startup.StartupInfo.StdError])
                {
                    if (handle != 0 && !listed.Contains(handle))
                    {
                        listed.Add(handle);
                    }
                }
            }

            foreach (var handle in options.InheritableHandles)
            {
                if (!listed.Contains(handle))
                {
                    listed.Add(handle);
                }
            }

            var inherit = listed.Count > 0;
            if (inherit && options.ParentProcess is not null)
            {
                throw new ArgumentException("A process created under another parent cannot inherit handles from this one.", nameof(options));
            }

            var attributes = (inherit ? 1 : 0) + (options.ParentProcess is null ? 0 : 1);
            if (attributes > 0)
            {
                nint size = 0;
                Native.InitializeProcThreadAttributeList(0, attributes, 0, ref size);
                attributeList = (nint)NativeMemory.Alloc((nuint)size);
                if (!Native.InitializeProcThreadAttributeList(attributeList, attributes, 0, ref size))
                {
                    var error = Native.LastError;
                    NativeMemory.Free((void*)attributeList);
                    attributeList = 0;
                    throw new Win32Exception(error, "InitializeProcThreadAttributeList failed.");
                }

                startup.AttributeList = attributeList;
            }

            if (options.ParentProcess is { } parent)
            {
                var value = (nint*)NativeMemory.Alloc((nuint)IntPtr.Size);
                parentMemory = (nint)value;
                *value = parent.DangerousGetHandle();
                if (!Native.UpdateProcThreadAttribute(attributeList, 0, Native.ProcThreadAttributeParentProcess, value, IntPtr.Size, 0, 0))
                {
                    throw new Win32Exception(Native.LastError, "UpdateProcThreadAttribute(PARENT_PROCESS) failed.");
                }
            }

            if (inherit)
            {
                var array = (nint*)NativeMemory.Alloc((nuint)(listed.Count * IntPtr.Size));
                for (var index = 0; index < listed.Count; index++)
                {
                    array[index] = listed[index];
                }

                // The list must stay valid until CreateProcess returns; it is freed with the attribute list below.
                listMemory = (nint)array;
                if (!Native.UpdateProcThreadAttribute(attributeList, 0, Native.ProcThreadAttributeHandleList, array, listed.Count * IntPtr.Size, 0, 0))
                {
                    throw new Win32Exception(Native.LastError, "UpdateProcThreadAttribute(HANDLE_LIST) failed.");
                }
            }

            var commandLine = (options.CommandLine + "\0").ToCharArray();
            var environment = options.Environment is null ? null : WindowsCommandLine.EnvironmentBlock(options.Environment);
            fixed (char* line = commandLine)
            fixed (char* block = environment)
            {
                var flags = options.Flags | Native.ExtendedStartupInfoPresent | (environment is null ? 0 : Native.CreateUnicodeEnvironment);
                Native.ProcessInformation info;
                bool created;
                var error = 0;

                // A file that is not a program for this machine (ERROR_BAD_EXE_FORMAT, ERROR_EXE_MACHINE_TYPE_MISMATCH) otherwise
                // raises a system hard error, and CreateProcess waits until someone answers its message box: under a process error
                // mode without SEM_FAILCRITICALERRORS in an interactive session, the launch blocks indefinitely. The thread's mode
                // makes it fail at once; the new process keeps inheriting the process error mode.
                var modeSet = Native.SetThreadErrorMode(Native.SemFailCriticalErrors, out var previousMode);
                try
                {
                    created = Native.CreateProcess(options.Application, line, 0, 0, inherit, flags, block, options.WorkingDirectory, &startup, out info);
                    if (!created)
                    {
                        error = Native.LastError;
                    }
                }
                finally
                {
                    if (modeSet)
                    {
                        _ = Native.SetThreadErrorMode(previousMode, out _);
                    }
                }

                if (!created)
                {
                    throw new Win32Exception(error, $"CreateProcess({options.Application}) failed.");
                }

                return new LaunchedProcess(new SafeKernelHandle(info.Process, ownsHandle: true), new SafeKernelHandle(info.Thread, ownsHandle: true), info.ProcessId);
            }
        }
        finally
        {
            if (attributeList != 0)
            {
                Native.DeleteProcThreadAttributeList(attributeList);
                NativeMemory.Free((void*)attributeList);
            }

            if (listMemory != 0)
            {
                NativeMemory.Free((void*)listMemory);
            }

            if (parentMemory != 0)
            {
                NativeMemory.Free((void*)parentMemory);
            }

            foreach (var copy in duplicates)
            {
                Native.CloseHandle(copy);
            }
        }
    }

    /// <summary>An inheritable duplicate of <paramref name="handle"/> that the caller closes (<see cref="Native.CloseHandle"/>).</summary>
    public static nint InheritableCopy(SafeHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        if (!Native.DuplicateHandle(Native.GetCurrentProcess(), handle, Native.GetCurrentProcess(), out var copy, 0, inherit: true, Native.DuplicateSameAccess))
        {
            throw new Win32Exception(Native.LastError, "DuplicateHandle failed.");
        }

        return copy;
    }

    /// <summary>Opens the null device for reading or writing as an inheritable-capable handle.</summary>
    public static SafeFileHandle OpenNull(bool write) =>
        File.OpenHandle("NUL", FileMode.Open, write ? FileAccess.Write : FileAccess.Read, FileShare.ReadWrite);
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
        if (handle is null)
        {
            return processId.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        var buffer = stackalloc char[1024];
        var size = 1024;
        return Native.QueryFullProcessImageName(handle, 0, buffer, ref size)
            ? Path.GetFileName(new string(buffer, 0, size))
            : processId.ToString(System.Globalization.CultureInfo.InvariantCulture);
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
