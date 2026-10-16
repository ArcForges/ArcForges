// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ArcForges.Node.Platform.Linux;

/// <summary>The libc calls of the Linux platform (glibc; source-generated P/Invoke).</summary>
[SupportedOSPlatform("linux")]
internal static unsafe partial class Libc
{
    public const int SigHup = 1;
    public const int SigInt = 2;
    public const int SigQuit = 3;
    public const int SigKill = 9;
    public const int SigPipe = 13;
    public const int SigTerm = 15;

    public const int RlimitCore = 4;
    public const int RlimitNofile = 7;
    public const int RlimitStack = 3;

    public const int WNoHang = 1;
    public const int OCloexec = 0x80000;

    private const string Library = "libc";
    private const int SigSetBytes = 128;
    private const int SpawnStructBytes = 1024;
    private const short SpawnSetPgroup = 0x02;
    private const short SpawnSetSigDef = 0x04;
    private const short SpawnSetSigMask = 0x08;

    [StructLayout(LayoutKind.Sequential)]
    public struct RLimit
    {
        public ulong Current;
        public ulong Maximum;
    }

    public static int LastError => Marshal.GetLastPInvokeError();

    /// <summary>The first real-time signal (glibc's <c>SIGRTMIN</c>, 34 on Linux: glibc keeps 32 and 33 for itself).</summary>
    public static int SigRtMin { get; } = RealTimeBound(minimum: true);

    /// <summary>The last real-time signal (<c>SIGRTMAX</c>, 64 on Linux).</summary>
    public static int SigRtMax { get; } = RealTimeBound(minimum: false);

    [LibraryImport(Library, EntryPoint = "__libc_current_sigrtmin")]
    private static partial int CurrentSigRtMin();

    [LibraryImport(Library, EntryPoint = "__libc_current_sigrtmax")]
    private static partial int CurrentSigRtMax();

    private static int RealTimeBound(bool minimum)
    {
        try
        {
            return minimum ? CurrentSigRtMin() : CurrentSigRtMax();
        }
        catch (Exception exception) when (exception is EntryPointNotFoundException or DllNotFoundException)
        {
            // Not glibc: the kernel's values less glibc's two reserved signals.
            return minimum ? 34 : 64;
        }
    }

    [LibraryImport(Library, EntryPoint = "kill", SetLastError = true)]
    public static partial int Kill(int pid, int signal);

    [LibraryImport(Library, EntryPoint = "getrlimit", SetLastError = true)]
    public static partial int GetRLimit(int resource, out RLimit limit);

    [LibraryImport(Library, EntryPoint = "setrlimit", SetLastError = true)]
    public static partial int SetRLimit(int resource, in RLimit limit);

    [LibraryImport(Library, EntryPoint = "chdir", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    public static partial int ChangeDirectory(string path);

    [LibraryImport(Library, EntryPoint = "waitpid", SetLastError = true)]
    public static partial int WaitPid(int pid, out int status, int options);

    [LibraryImport(Library, EntryPoint = "pipe2", SetLastError = true)]
    public static partial int Pipe2(int* fds, int flags);

    [LibraryImport(Library, EntryPoint = "getpid")]
    public static partial int GetPid();

    [LibraryImport(Library, EntryPoint = "open", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int OpenFile(string path, int flags, int mode);

    /// <summary>Opens a file for the unit's standard streams (close-on-exec in this process; systemd receives a copy over D-Bus).</summary>
    /// <param name="path">The file.</param>
    /// <param name="write">Write (created or truncated, <c>O_APPEND</c>, mode 0600) or read.</param>
    public static Microsoft.Win32.SafeHandles.SafeFileHandle Open(string path, bool write)
    {
        const int WriteOnly = 1, Create = 0x40, Truncate = 0x200, Append = 0x400;
        var fd = OpenFile(path, write ? WriteOnly | Create | Truncate | Append | OCloexec : OCloexec, write ? 0x180 : 0);
        return fd >= 0 ? new Microsoft.Win32.SafeHandles.SafeFileHandle(fd, ownsHandle: true) : throw new Win32Exception(LastError, $"open {path} failed");
    }

    [LibraryImport(Library, EntryPoint = "execve", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int ExecVe(string path, nint* argv, nint* envp);

    [LibraryImport(Library, EntryPoint = "signal")]
    private static partial nint Signal(int signal, nint handler);

    [LibraryImport(Library, EntryPoint = "sigprocmask", SetLastError = true)]
    private static partial int SigProcMask(int how, byte* set, byte* old);

    [LibraryImport(Library, EntryPoint = "sigemptyset")]
    private static partial int SigEmptySet(byte* set);

    [LibraryImport(Library, EntryPoint = "sigfillset")]
    private static partial int SigFillSet(byte* set);

    [LibraryImport(Library, EntryPoint = "sigdelset")]
    private static partial int SigDelSet(byte* set, int signal);

    [LibraryImport(Library, EntryPoint = "posix_spawn", StringMarshalling = StringMarshalling.Utf8)]
    private static partial int PosixSpawn(out int pid, string path, void* fileActions, void* attributes, nint* argv, nint* envp);

    [LibraryImport(Library, EntryPoint = "posix_spawn_file_actions_init")]
    private static partial int FileActionsInit(void* actions);

    [LibraryImport(Library, EntryPoint = "posix_spawn_file_actions_destroy")]
    private static partial int FileActionsDestroy(void* actions);

    [LibraryImport(Library, EntryPoint = "posix_spawn_file_actions_adddup2")]
    private static partial int FileActionsAddDup2(void* actions, int fd, int newFd);

    [LibraryImport(Library, EntryPoint = "posix_spawn_file_actions_addopen", StringMarshalling = StringMarshalling.Utf8)]
    private static partial int FileActionsAddOpen(void* actions, int fd, string path, int flags, int mode);

    [LibraryImport(Library, EntryPoint = "posix_spawn_file_actions_addchdir_np", StringMarshalling = StringMarshalling.Utf8)]
    private static partial int FileActionsAddChdir(void* actions, string path);

    [LibraryImport(Library, EntryPoint = "posix_spawnattr_init")]
    private static partial int AttributesInit(void* attributes);

    [LibraryImport(Library, EntryPoint = "posix_spawnattr_destroy")]
    private static partial int AttributesDestroy(void* attributes);

    [LibraryImport(Library, EntryPoint = "posix_spawnattr_setflags")]
    private static partial int AttributesSetFlags(void* attributes, short flags);

    [LibraryImport(Library, EntryPoint = "posix_spawnattr_setpgroup")]
    private static partial int AttributesSetPgroup(void* attributes, int pgroup);

    [LibraryImport(Library, EntryPoint = "posix_spawnattr_setsigdefault")]
    private static partial int AttributesSetSigDefault(void* attributes, byte* set);

    [LibraryImport(Library, EntryPoint = "posix_spawnattr_setsigmask")]
    private static partial int AttributesSetSigMask(void* attributes, byte* set);

    /// <summary>
    /// Replaces this process with <paramref name="path"/> (<c>execve</c>): signal dispositions the runtime set to ignore (<c>SIGPIPE</c>)
    /// return to their defaults and the signal mask is cleared first, so the program starts as it would from a shell. Returns only on
    /// failure, with the error number.
    /// </summary>
    public static int Exec(string path, IReadOnlyList<string> argv, IReadOnlyList<string> environment)
    {
        ArgumentNullException.ThrowIfNull(argv);
        ArgumentNullException.ThrowIfNull(environment);
        for (var signal = 1; signal <= SigRtMax; signal++)
        {
            // The real-time signals too (the runtime may handle some); glibc's internal 32 and 33 are refused and left alone.
            if (signal is not (SigKill or 19))
            {
                _ = Signal(signal, 0);
            }
        }

        var empty = stackalloc byte[SigSetBytes];
        _ = SigEmptySet(empty);
        _ = SigProcMask(2, empty, null);
        var arguments = Strings(argv);
        var variables = Strings(environment);
        try
        {
            fixed (nint* argumentPointer = arguments)
            fixed (nint* variablePointer = variables)
            {
                ExecVe(path, argumentPointer, variablePointer);
                return LastError;
            }
        }
        finally
        {
            Free(arguments);
            Free(variables);
        }
    }

    /// <summary>
    /// Starts <paramref name="path"/> with <c>posix_spawn</c>: the standard streams from <paramref name="stdio"/> (file descriptors; -1
    /// opens <c>/dev/null</c>), default signal dispositions and an empty mask, an optional working directory, and its own process group
    /// when <paramref name="newProcessGroup"/> is set. Returns the process ID.
    /// </summary>
    /// <exception cref="Win32Exception">The spawn failed.</exception>
    public static int Spawn(string path, IReadOnlyList<string> argv, IReadOnlyList<string> environment, (int Stdin, int Stdout, int Stderr) stdio,
        string? workingDirectory, bool newProcessGroup)
    {
        ArgumentNullException.ThrowIfNull(argv);
        ArgumentNullException.ThrowIfNull(environment);
        var actions = NativeMemory.AllocZeroed(SpawnStructBytes);
        var attributes = NativeMemory.AllocZeroed(SpawnStructBytes);
        var arguments = Strings(argv);
        var variables = Strings(environment);
        try
        {
            _ = FileActionsInit(actions);
            _ = AttributesInit(attributes);
            AddStream(actions, stdio.Stdin, 0, write: false);
            AddStream(actions, stdio.Stdout, 1, write: true);
            AddStream(actions, stdio.Stderr, 2, write: true);
            if (workingDirectory is { Length: > 0 })
            {
                _ = FileActionsAddChdir(actions, workingDirectory);
            }

            var all = stackalloc byte[SigSetBytes];
            _ = SigFillSet(all);
            _ = SigDelSet(all, SigKill);
            _ = SigDelSet(all, 19);
            var empty = stackalloc byte[SigSetBytes];
            _ = SigEmptySet(empty);
            _ = AttributesSetSigDefault(attributes, all);
            _ = AttributesSetSigMask(attributes, empty);
            var flags = (short)(SpawnSetSigDef | SpawnSetSigMask);
            if (newProcessGroup)
            {
                flags |= SpawnSetPgroup;
                _ = AttributesSetPgroup(attributes, 0);
            }

            _ = AttributesSetFlags(attributes, flags);
            fixed (nint* argumentPointer = arguments)
            fixed (nint* variablePointer = variables)
            {
                var error = PosixSpawn(out var pid, path, actions, attributes, argumentPointer, variablePointer);
                return error == 0 ? pid : throw new Win32Exception(error, $"posix_spawn {path} failed");
            }
        }
        finally
        {
            _ = FileActionsDestroy(actions);
            _ = AttributesDestroy(attributes);
            NativeMemory.Free(actions);
            NativeMemory.Free(attributes);
            Free(arguments);
            Free(variables);
        }
    }

    /// <summary>Waits for <paramref name="pid"/> up to <paramref name="timeout"/>; null while it still runs, else its wait status.</summary>
    public static int? Wait(int pid, TimeSpan timeout)
    {
        var deadline = Environment.TickCount64 + (long)timeout.TotalMilliseconds;
        while (true)
        {
            var result = WaitPid(pid, out var status, WNoHang);
            if (result == pid)
            {
                return status;
            }

            if (result < 0 && LastError != 4)
            {
                // ECHILD: not ours or already reaped.
                return -1;
            }

            if (timeout != Timeout.InfiniteTimeSpan && Environment.TickCount64 >= deadline)
            {
                return null;
            }

            Thread.Sleep(10);
        }
    }

    /// <summary>Decodes a wait status: (exited, code or signal, core dumped).</summary>
    public static (bool Exited, int Value, bool CoreDumped) Decode(int status) => (status & 0x7f) == 0
        ? (true, (status >> 8) & 0xff, false)
        : (false, status & 0x7f, (status & 0x80) != 0);

    /// <summary>A pipe (both ends close-on-exec): (read, write).</summary>
    public static (int Read, int Write) Pipe()
    {
        var fds = stackalloc int[2];
        return Pipe2(fds, OCloexec) == 0 ? (fds[0], fds[1]) : throw new Win32Exception(LastError, "pipe2 failed");
    }

    private static void AddStream(void* actions, int fd, int target, bool write)
    {
        if (fd < 0)
        {
            _ = FileActionsAddOpen(actions, target, "/dev/null", write ? 1 : 0, 0);
        }
        else
        {
            _ = FileActionsAddDup2(actions, fd, target);
        }
    }

    private static nint[] Strings(IReadOnlyList<string> values)
    {
        var pointers = new nint[values.Count + 1];
        for (var index = 0; index < values.Count; index++)
        {
            pointers[index] = Marshal.StringToCoTaskMemUTF8(values[index]);
        }

        return pointers;
    }

    private static void Free(nint[] pointers)
    {
        foreach (var pointer in pointers)
        {
            if (pointer != 0)
            {
                Marshal.FreeCoTaskMem(pointer);
            }
        }
    }
}
