// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace ArcForges.ContentSandbox.Native;

/// <summary>
/// The three libc entry points the helper needs to put its own Linux profile in force: <c>prctl</c> (no_new_privs), <c>setrlimit</c>
/// (resource limits) and the generic <c>syscall</c> (seccomp, Landlock and the self-check attempts, which have no libc wrapper or must not go
/// through one). Everything else the helper does is managed.
/// </summary>
[SuppressMessage("Design", "CA1060", Justification = "One owner type holds the closed set of helper bindings of the Linux profile.")]
internal static partial class LinuxNative
{
    internal const int PrSetNoNewPrivs = 38;
    internal const int PrGetNoNewPrivs = 39;
    internal const int RlimitCore = 4;
    internal const int RlimitData = 2;
    internal const int RlimitNofile = 7;
    internal const int RlimitFsize = 1;

    internal const int Eperm = 1;
    internal const int Eacces = 13;

    [LibraryImport("libc", EntryPoint = "prctl", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial int Prctl(int option, nuint argument2, nuint argument3, nuint argument4, nuint argument5);

    [LibraryImport("libc", EntryPoint = "setrlimit", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial int SetRlimit(int resource, ref RlimitValue limit);

    [LibraryImport("libc", EntryPoint = "getppid")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial int GetParentProcessId();

    [LibraryImport("libc", EntryPoint = "syscall", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial nint Syscall(nint number, nint argument1, nint argument2, nint argument3, nint argument4, nint argument5);

    [LibraryImport("libdl.so.2", EntryPoint = "dlopen", StringMarshalling = StringMarshalling.Utf8)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial nint DlOpen(string path, int flags);
    [LibraryImport("libdl.so.2", EntryPoint = "dlsym", StringMarshalling = StringMarshalling.Utf8)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial nint DlSym(nint handle, string name);
    [LibraryImport("libdl.so.2", EntryPoint = "dlclose")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial int DlClose(nint handle);
    [LibraryImport("libdl.so.2", EntryPoint = "dlerror")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
    internal static partial nint DlError();

    [StructLayout(LayoutKind.Sequential)]
    internal struct RlimitValue
    {
        public ulong Current;
        public ulong Maximum;
    }
}
