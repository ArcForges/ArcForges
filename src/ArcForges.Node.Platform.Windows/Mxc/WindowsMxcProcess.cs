// SPDX-License-Identifier: AGPL-3.0-only

using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Platform.Windows.Mxc;

/// <summary>The explicitly inherited standard handles for a pipe-mode MXC execution.</summary>
public sealed record WindowsMxcStandardHandles(SafeHandle Input, SafeHandle Output, SafeHandle Error);

/// <summary>Win32 process creation and identity operations for the official MXC path.</summary>
[SupportedOSPlatform("windows")]
public static partial class WindowsMxcProcess
{
    private const nint JobListAttribute = 0x0002000d;
    private const nint PseudoConsoleAttribute = 0x00020016;
    private const uint DialogSuppression = 0x8003;

    /// <summary>Builds the closed environment used by a trusted owner or native executor.</summary>
    public static IReadOnlyList<string> TrustedEnvironment(string privateControlDirectory)
    {
        var windows = Path.GetDirectoryName(Environment.SystemDirectory)
            ?? throw new IOException("The Windows root directory is unavailable.");
        return ["PATH=", "SystemRoot=" + windows, "TEMP=" + privateControlDirectory, "TMP=" + privateControlDirectory, "WINDIR=" + windows];
    }

    /// <summary>Suppresses Win32 error dialogs in the dedicated owner process.</summary>
    public static void SuppressOwnerErrorDialogs() => _ = SetErrorMode(GetErrorMode() | DialogSuppression);

    /// <summary>Returns the native boot identity used by the Node and the independent owner.</summary>
    public static unsafe string BootIdentity()
    {
        var machine = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography", "MachineGuid", null) as string
            ?? throw new IOException("The Windows machine identity is unavailable.");
        var information = stackalloc long[6];
        var status = NtQuerySystemInformation(3, information, 48, out _);
        if (status != 0)
        {
            throw new IOException(string.Create(CultureInfo.InvariantCulture, $"The Windows boot identity is unavailable (0x{status:x8})."));
        }

        var bootTime = (information[0] - information[4]) / 10_000_000;
        return string.Create(CultureInfo.InvariantCulture, $"windows:{machine}:{bootTime}");
    }

    /// <summary>Reads the held Node or owner process creation identity.</summary>
    public static long CurrentCreationFileTime()
    {
        using var current = ProcessInfo.Open(Environment.ProcessId)
            ?? throw WindowsMxcJob.Error("Open the current native MXC process");
        var stamp = ProcessInfo.CreationFileTime(current);
        return stamp > 0 ? stamp : throw WindowsMxcJob.Error("Read current native MXC process creation time");
    }

    /// <summary>Returns the full native image of the current held process.</summary>
    public static string CurrentImagePath()
    {
        using var current = ProcessInfo.Open(Environment.ProcessId)
            ?? throw WindowsMxcJob.Error("Open the current native MXC process");
        return ImagePath(current);
    }

    /// <summary>Converts millicores into a Job hard cap using the machine's native scheduler topology.</summary>
    public static int CpuRate(uint millicores)
    {
        var total = GetActiveProcessorCount(ushort.MaxValue);
        if (total == 0) throw WindowsMxcJob.Error("Read native Windows processor capacity");
        var rate = (10L * millicores) / total;
        return rate is >= 1 and <= 10_000
            ? (int)rate
            : throw new ArgumentOutOfRangeException(nameof(millicores), "The Windows Job cannot represent this CPU hard cap.");
    }

    /// <summary>Grants the exact held supervisor a noninheritable query and lifetime reference.</summary>
    public static long DuplicateJobToOwner(WindowsMxcJob job, LaunchedProcess owner)
    {
        ArgumentNullException.ThrowIfNull(job);
        ArgumentNullException.ThrowIfNull(owner);
        const uint jobQuery = 4;
        if (!Native.DuplicateHandle(Native.GetCurrentProcess(), job.Handle, owner.Process.DangerousGetHandle(),
                out var target, jobQuery, inherit: false, options: 0))
        {
            throw WindowsMxcJob.Error("Transfer held Job lifetime to the authenticated supervisor");
        }

        GC.KeepAlive(owner);
        return target.ToInt64();
    }

    /// <summary>Creates a process suspended and atomically assigns it to a held Job.</summary>
    public static unsafe LaunchedProcess CreateSuspended(string image, IReadOnlyList<string> arguments, string directory,
        IReadOnlyList<string> environment, WindowsMxcJob job, nint pseudoConsole = 0, WindowsMxcStandardHandles? standard = null)
    {
        ArgumentNullException.ThrowIfNull(job);
        if (!Path.IsPathFullyQualified(image) || !Path.IsPathFullyQualified(directory)
            || (pseudoConsole != 0 && standard is not null))
        {
            throw new ArgumentException("Native MXC launches require absolute paths and an explicit standard-handle mode.");
        }

        var attributes = (nint)0;
        var initialized = false;
        var size = (nint)0;
        var attributeCount = pseudoConsole != 0 || standard is not null ? 2 : 1;
        var duplicate = stackalloc nint[3] { 0, 0, 0 };
        var jobHandle = job.Handle.DangerousGetHandle();
        try
        {
            _ = Native.InitializeProcThreadAttributeList(0, attributeCount, 0, ref size);
            if (size <= 0)
            {
                throw WindowsMxcJob.Error("Size the native MXC startup attributes");
            }

            attributes = (nint)NativeMemory.Alloc(checked((nuint)size));
            if (!Native.InitializeProcThreadAttributeList(attributes, attributeCount, 0, ref size))
            {
                throw WindowsMxcJob.Error("Initialize native MXC startup attributes");
            }

            initialized = true;
            AddAttribute(attributes, JobListAttribute, &jobHandle, sizeof(nint));
            var startup = new Native.StartupInfoEx
            {
                StartupInfo = new Native.StartupInfo { Cb = sizeof(Native.StartupInfoEx) },
                AttributeList = attributes,
            };
            var flags = Native.CreateSuspended | Native.CreateUnicodeEnvironment | Native.ExtendedStartupInfoPresent;
            if (pseudoConsole != 0)
            {
                // The ConPTY API expects HPCON itself and explicit NULL standard handles.
                AddAttribute(attributes, PseudoConsoleAttribute, (void*)pseudoConsole, sizeof(nint));
                startup.StartupInfo.Flags = Native.StartfUseStdHandles;
            }
            else if (standard is not null)
            {
                duplicate[0] = ProcessLauncher.InheritableCopy(standard.Input);
                duplicate[1] = ProcessLauncher.InheritableCopy(standard.Output);
                duplicate[2] = ProcessLauncher.InheritableCopy(standard.Error);
                AddAttribute(attributes, Native.ProcThreadAttributeHandleList, duplicate, sizeof(nint) * 3);
                startup.StartupInfo.Flags = Native.StartfUseStdHandles;
                startup.StartupInfo.StdInput = duplicate[0];
                startup.StartupInfo.StdOutput = duplicate[1];
                startup.StartupInfo.StdError = duplicate[2];
                flags |= Native.CreateNoWindow;
            }
            else
            {
                flags |= Native.DetachedProcess;
            }

            var commandLine = (WindowsCommandLine.Build([image, .. arguments]) + '\0').ToCharArray();
            var environmentBlock = (string.Join('\0', environment) + "\0\0").ToCharArray();
            var modeSet = Native.SetThreadErrorMode(DialogSuppression, out var oldMode);
            try
            {
                fixed (char* command = commandLine)
                fixed (char* env = environmentBlock)
                {
                    if (!Native.CreateProcess(image, command, 0, 0, standard is not null, flags, env, directory, &startup, out var result))
                    {
                        throw WindowsMxcJob.Error("Create suspended native MXC process in its exact Run Job");
                    }

                    return new LaunchedProcess(new SafeKernelHandle(result.Process, ownsHandle: true),
                        new SafeKernelHandle(result.Thread, ownsHandle: true), result.ProcessId);
                }
            }
            finally
            {
                if (modeSet)
                {
                    _ = Native.SetThreadErrorMode(oldMode, out _);
                }
            }
        }
        finally
        {
            if (initialized) Native.DeleteProcThreadAttributeList(attributes);
            NativeMemory.Free((void*)attributes);
            for (var index = 0; index < 3; index++)
            {
                if (duplicate[index] != 0) _ = Native.CloseHandle(duplicate[index]);
            }

            GC.KeepAlive(job);
        }
    }

    /// <summary>Resumes the exact held process only from its initial single-suspension state.</summary>
    public static void Resume(LaunchedProcess process)
    {
        ArgumentNullException.ThrowIfNull(process);
        var previous = Native.ResumeThread(process.Thread.DangerousGetHandle());
        if (previous == uint.MaxValue)
        {
            throw WindowsMxcJob.Error("Resume admitted native MXC process");
        }

        if (previous != 1)
        {
            throw new InvalidDataException("The MXC process did not have its required initial suspend count.");
        }

        process.Thread.Dispose();
    }

    /// <summary>Reads the exact native image and creation time from the held process.</summary>
    public static long RequireIdentity(LaunchedProcess process, string image)
    {
        ArgumentNullException.ThrowIfNull(process);
        var stamp = process.CreationFileTime;
        if (stamp <= 0)
        {
            throw WindowsMxcJob.Error("Read native MXC process creation time");
        }

        RequireImage(process.Process, image);
        return stamp;
    }

    /// <summary>Matches a local authenticated pipe to its held peer's PID, birth identity and image.</summary>
    public static void RequirePeer(SafePipeHandle pipe, bool localIsServer, int pid, long creationFileTime, string image)
    {
        ArgumentNullException.ThrowIfNull(pipe);
        if (!(localIsServer ? GetNamedPipeClientProcessId(pipe, out var observed) : GetNamedPipeServerProcessId(pipe, out observed)))
        {
            throw WindowsMxcJob.Error("Read native MXC control pipe peer");
        }

        if (observed != pid || creationFileTime <= 0)
        {
            throw new InvalidDataException("The native MXC control pipe peer identity differs.");
        }

        using var peer = ProcessInfo.Open(pid);
        if (peer is null || ProcessInfo.CreationFileTime(peer) != creationFileTime || !ProcessInfo.IsRunning(peer))
        {
            throw new InvalidDataException("The native MXC control pipe peer is stale.");
        }

        RequireImage(peer, image);
    }

    /// <summary>Reads the raw exit code from the held process once it is signaled.</summary>
    public static uint? PollExit(LaunchedProcess process)
    {
        ArgumentNullException.ThrowIfNull(process);
        var wait = Native.WaitForSingleObject(process.Process, 0);
        if (wait == Native.WaitTimeout) return null;
        if (wait != Native.WaitObject0 || !Native.GetExitCodeProcess(process.Process, out var code))
        {
            throw WindowsMxcJob.Error("Read native MXC process completion");
        }

        return code;
    }

    private static void RequireImage(SafeHandle process, string image)
    {
        if (!string.Equals(ImagePath(process), image, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("The held native MXC process image differs from the protected executable.");
        }
    }

    private static unsafe string ImagePath(SafeHandle process)
    {
        var buffer = new char[32_768];
        var size = buffer.Length;
        fixed (char* native = buffer)
        {
            if (!Native.QueryFullProcessImageName(process, 0, native, ref size))
            {
                throw WindowsMxcJob.Error("Read the full native MXC process image");
            }
        }

        return new string(buffer, 0, size);
    }

    private static unsafe void AddAttribute(nint list, nint attribute, void* value, nint size)
    {
        if (!Native.UpdateProcThreadAttribute(list, 0, attribute, value, size, 0, 0))
        {
            throw WindowsMxcJob.Error("Configure a native MXC startup attribute");
        }
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);

    [LibraryImport("kernel32.dll")]
    private static partial uint GetErrorMode();

    [LibraryImport("kernel32.dll")]
    private static partial uint SetErrorMode(uint mode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint GetActiveProcessorCount(ushort groupNumber);

    [LibraryImport("ntdll.dll")]
    private static unsafe partial int NtQuerySystemInformation(int informationClass, void* information, uint length, out uint returned);
}
