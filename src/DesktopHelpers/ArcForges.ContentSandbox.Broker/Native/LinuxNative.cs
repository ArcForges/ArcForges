// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace ArcForges.ContentSandbox.Broker.Native;

/// <summary>
/// The libc calls the Linux launch profile needs and the managed libraries do not expose: connected socket pairs and memory-backed files
/// that are born close-on-exec, a descriptor plan with explicit target numbers, spawning with exactly that plan, waiting for the child and
/// ending it. Every declaration is internal, unique in the repository and covered by the closed native-binding owner test.
/// </summary>
[SuppressMessage("Design", "CA1060", Justification = "One owner type holds the exact closed set of bindings of the Linux launch profile.")]
internal static unsafe partial class LinuxNative
{
    internal const int AfUnix = 1;
    internal const int SockStream = 1;
    internal const int SockCloseOnExec = 0x80000;
    internal const uint MemfdCloseOnExec = 1;
    internal const int FDupFdCloseOnExec = 1030;
    internal const int SigKill = 9;

    [LibraryImport("libc", EntryPoint = "socketpair", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial int SocketPair(int domain, int type, int protocol, int* descriptors);

    [LibraryImport("libc", EntryPoint = "memfd_create", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial int MemfdCreate(string name, uint flags);

    [LibraryImport("libc", EntryPoint = "fcntl", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial int Fcntl(int descriptor, int command, nint argument);

    [LibraryImport("libc", EntryPoint = "close", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial int Close(int descriptor);

    [LibraryImport("libc", EntryPoint = "posix_spawn_file_actions_init")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial int SpawnFileActionsInit(nint actions);

    [LibraryImport("libc", EntryPoint = "posix_spawn_file_actions_adddup2")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial int SpawnFileActionsAddDup2(nint actions, int descriptor, int target);

    [LibraryImport("libc", EntryPoint = "posix_spawn_file_actions_destroy")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial int SpawnFileActionsDestroy(nint actions);

    [LibraryImport("libc", EntryPoint = "posix_spawn")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial int Spawn(out int processId, nint path, nint actions, nint attributes, nint arguments, nint environment);

    [LibraryImport("libc", EntryPoint = "waitpid", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial int WaitPid(int processId, out int status, int options);

    [LibraryImport("libc", EntryPoint = "kill", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial int Kill(int processId, int signal);
}
