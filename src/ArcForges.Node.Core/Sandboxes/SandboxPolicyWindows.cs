// SPDX-License-Identifier: AGPL-3.0-only

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.Json;
using ArcForges.Node.Platform.Capabilities;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.Node.Core.Sandboxes;

[SupportedOSPlatform("windows")]
internal static partial class SandboxPolicyWindows
{
    internal static MxcPrerequisites Discover(string installationRoot)
    {
        var flags = MxcPrerequisites.None;
        var executor = Path.Combine(installationRoot, "wxc-exec.exe");
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var windows = Path.GetDirectoryName(system) ?? throw new IOException("Windows system directory unavailable.");
        if (SandboxPolicyHost.Run(executor, installationRoot, ["--probe"], new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["SystemRoot"] = windows,
            ["PATH"] = string.Empty,
        }) is { } output)
        {
            using var report = JsonDocument.Parse(output);
            if (report.RootElement.TryGetProperty("probes", out var probes)
                && probes.TryGetProperty("baseContainerSupportsDenyPaths", out var paths)
                && paths.ValueKind == JsonValueKind.True)
            {
                flags |= MxcPrerequisites.WindowsNativeDenyPaths;
            }
        }

        if (ProbeConPty())
        {
            flags |= MxcPrerequisites.WindowsConPty;
        }

        if (ProbeNestedJobs(executor, installationRoot))
        {
            flags |= MxcPrerequisites.WindowsNestedJob;
        }

        return flags;
    }

    private static bool ProbeConPty()
    {
        var inputCreated = CreatePipe(out var inputRead, out var inputWrite, 0, 0);
        using var read = inputRead;
        using var write = inputWrite;
        if (!inputCreated)
        {
            return false;
        }

        var outputCreated = CreatePipe(out var outputRead, out var outputWrite, 0, 0);
        using var outRead = outputRead;
        using var outWrite = outputWrite;
        if (!outputCreated)
        {
            return false;
        }

        var result = CreatePseudoConsole(new() { X = 80, Y = 24 }, read, outWrite, 0, out var console);
        if (console != 0)
        {
            ClosePseudoConsole(console);
        }

        return result == 0 && console != 0;
    }

    private static unsafe bool ProbeNestedJobs(string image, string workingDirectory)
    {
        using var outer = CreateJobObject(0, null);
        using var inner = CreateJobObject(0, null);
        if (outer.IsInvalid || inner.IsInvalid)
        {
            return false;
        }

        // The immutable, official executor image is created suspended and never resumed.
        // No command body or inherited environment reaches a workload.
        var startup = new StartupInfo { Size = (uint)sizeof(StartupInfo) };
        var environment = stackalloc char[2];
        environment[0] = environment[1] = '\0';
        const uint suspendedNoWindowUnicode = 0x08000404;
        if (!CreateProcess(image, 0, 0, 0, false, suspendedNoWindowUnicode, (nint)environment, workingDirectory,
                ref startup, out var created))
        {
            return false;
        }

        using var child = new SafeFileHandle(created.Process, ownsHandle: true);
        using var initialThread = new SafeFileHandle(created.Thread, ownsHandle: true);
        var assigned = false;
        var exited = false;
        try
        {
            assigned = AssignProcessToJobObject(outer, child) && AssignProcessToJobObject(inner, child)
                && IsProcessInJob(child, outer, out var inOuter) && inOuter
                && IsProcessInJob(child, inner, out var inInner) && inInner;
        }
        finally
        {
            const uint signaled = 0;
            _ = TerminateProcess(child, 1);
            exited = WaitForSingleObject(child, 2_000) == signaled;
        }

        return assigned && exited;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Coordinate
    {
        public short X;
        public short Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        public uint Size;
        public nint Reserved;
        public nint Desktop;
        public nint Title;
        public uint X;
        public uint Y;
        public uint XSize;
        public uint YSize;
        public uint XCountChars;
        public uint YCountChars;
        public uint FillAttribute;
        public uint Flags;
        public ushort ShowWindow;
        public ushort ReservedCount;
        public nint ReservedBytes;
        public nint StdInput;
        public nint StdOutput;
        public nint StdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public nint Process;
        public nint Thread;
        public uint ProcessId;
        public uint ThreadId;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CreatePipe(out SafeFileHandle readPipe, out SafeFileHandle writePipe,
        nint attributes, uint size);

    [LibraryImport("kernel32.dll")]
    private static partial int CreatePseudoConsole(Coordinate size, SafeFileHandle input, SafeFileHandle output,
        uint flags, out nint console);

    [LibraryImport("kernel32.dll")]
    private static partial void ClosePseudoConsole(nint console);

    [LibraryImport("kernel32.dll", EntryPoint = "CreateJobObjectW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial SafeFileHandle CreateJobObject(nint attributes, string? name);

    [LibraryImport("kernel32.dll", EntryPoint = "CreateProcessW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CreateProcess(string applicationName, nint commandLine, nint processAttributes,
        nint threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint creationFlags,
        nint environment, string currentDirectory, ref StartupInfo startup, out ProcessInformation information);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AssignProcessToJobObject(SafeFileHandle job, SafeFileHandle process);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool IsProcessInJob(SafeFileHandle process, SafeFileHandle job,
        [MarshalAs(UnmanagedType.Bool)] out bool result);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool TerminateProcess(SafeFileHandle process, uint exitCode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint WaitForSingleObject(SafeFileHandle handle, uint milliseconds);
}
