// SPDX-License-Identifier: AGPL-3.0-only
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace ArcForges.MxcProbe;

// Bounded, nonterminal admission owner only. ConPTY and the product supervisor
// composition belong to MXC-WIN-01..06; this launcher does not qualify them.
[SupportedOSPlatform("windows")]
internal static partial class WindowsLauncher
{
    public static async Task<CaseReport> RunAsync(string stage, string work)
    {
        var control = Path.Combine(work, "private control");
        var fixture = Path.Combine(work, "fixture 工作区");
        Directory.CreateDirectory(control);
        Directory.CreateDirectory(fixture);
        // This owner-only directory is outside all workload grants. No host ACL
        // fallback is allowed in the exact immutable schema request.
        RestrictControl(control);
        var marker = Path.Combine(fixture, "entered.txt");
        var log = Path.Combine(control, "executor-output.txt");
        var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var request = new WindowsRequest
        {
            Process = new WindowsProcess
            {
                CommandLine = "\"" + Path.Combine(system, "cmd.exe") + "\" /d /c \"echo afv2-windows-ok>entered.txt\"",
                Cwd = fixture,
                Env = ["SystemRoot=" + Directory.GetParent(system)!.FullName, "LOCALAPPDATA=" + fixture, "TEMP=" + fixture, "TMP=" + fixture, "PATH=", "AFV2_SYNTHETIC_SECRET=mxc-probe-secret-not-for-logs"],
            },
            Filesystem = new WindowsFilesystem { ReadwritePaths = [fixture], ReadonlyPaths = [system], DeniedPaths = [control] },
        };
        var policy = Path.Combine(control, "request 配置.json");
        await File.WriteAllTextAsync(policy, JsonSerializer.Serialize(request, WindowsJson.Default.WindowsRequest)).ConfigureAwait(false);
        var watch = Stopwatch.StartNew();
        var result = Launch(Path.Combine(stage, "wxc-exec.exe"), policy, control, log);
        var text = await File.ReadAllTextAsync(log).ConfigureAwait(false);
        Program.Require(!text.Contains("mxc-probe-secret", StringComparison.Ordinal), "Synthetic secret leaked into executor output.");
        Program.Require(result.ExitCode == 0 && File.Exists(marker) && (await File.ReadAllTextAsync(marker).ConfigureAwait(false)).Trim() == "afv2-windows-ok", "Official Windows executor did not complete the synthetic payload; inspect private executor log.");
        return new CaseReport("windows-official-executor", true, result.ProcessId, result.ExitCode, false, result.SpawnMs, watch.Elapsed.TotalMilliseconds,
            "official_executor", "CreateProcess suspended; actual executor command line read back with no sentinel; outer Job assigned before resume; IsProcessInJob true; executor handle signaled; Job active count zero. Payload marker is supplementary, not an isolation assertion.", [], false, true);
    }

    private static void RestrictControl(string directory)
    {
        // An explicit owner-only security descriptor applies to this new fixture
        // only; it never grants an AppContainer access or changes host DACLs.
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor("D:P(A;OICI;FA;;;OW)", 1, out var descriptor, out _)) throw Error("Build fixture DACL");
        try
        {
            if (!SetFileSecurity(directory, 0x80000004, descriptor)) throw Error("Apply fixture DACL");
        }
        finally { _ = LocalFree(descriptor); }
    }

    private static unsafe LaunchResult Launch(string executor, string policy, string work, string log)
    {
        var watch = Stopwatch.StartNew();
        using var output = new FileStream(log, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        using var input = File.OpenHandle("NUL", FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var job = CreateJobObject(0, null);
        if (job.IsInvalid) throw Error("CreateJobObject");
        var limits = new ExtendedLimits { Basic = new BasicLimits { LimitFlags = 0x2000 | 0x8, ActiveProcessLimit = 16 } };
        if (!SetInformationJobObject(job, 9, &limits, sizeof(ExtendedLimits))) throw Error("Set Job kill-on-close/bounded child limit");
        var current = GetCurrentProcess();
        if (!IsProcessInJob(current, 0, out var inheritedJob)) throw Error("Observe inherited Job membership");
        if (!DuplicateHandle(current, output.SafeFileHandle, current, out var stdout, 0, true, 2)) throw Error("Duplicate output handle");
        if (!DuplicateHandle(current, input, current, out var stdin, 0, true, 2))
        {
            _ = CloseHandle(stdout);
            throw Error("Duplicate input handle");
        }

        nint attributes = 0;
        ProcessInformation process = default;
        try
        {
            nuint bytes = 0;
            _ = InitializeProcThreadAttributeList(0, 1, 0, ref bytes);
            attributes = Marshal.AllocHGlobal((nint)bytes);
            if (!InitializeProcThreadAttributeList(attributes, 1, 0, ref bytes)) throw Error("Initialize handle-list attributes");
            nint* handles = stackalloc nint[] { stdin, stdout };
            if (!UpdateProcThreadAttribute(attributes, 0, 0x20002, handles, (nuint)(2 * sizeof(nint)), 0, 0)) throw Error("Set exact inherited handle list");
            var startup = new StartupInfoEx { Info = new StartupInfo { Cb = sizeof(StartupInfoEx), Flags = 0x100, StdInput = stdin, StdOutput = stdout, StdError = stdout }, Attributes = attributes };
            var command = ("\"" + executor + "\" --config \"" + policy + "\"\0").ToCharArray();
            var system = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var environment = ("PATH=\0SystemRoot=" + Directory.GetParent(system)!.FullName + "\0TEMP=" + work + "\0TMP=" + work + "\0\0").ToCharArray();
            fixed (char* commandPtr = command)
            fixed (char* environmentPtr = environment)
            {
                if (!CreateProcess(executor, commandPtr, 0, 0, true, 0x4 | 0x400 | 0x80000 | 0x8000000, environmentPtr, work, ref startup, out process)) throw Error("Create suspended official executor");
            }

            if (!AssignProcessToJobObject(job, process.Process)) throw Error("Assign suspended executor to outer Job");
            if (!IsProcessInJob(process.Process, job.DangerousGetHandle(), out var member) || !member) throw Error("Read back outer Job membership");
            var actualCommand = ReadCommandLine(process.Process);
            Program.Require(actualCommand == new string(command.AsSpan(0, command.Length - 1)) && !actualCommand.Contains("mxc-probe-secret-not-for-logs", StringComparison.Ordinal), "Actual executor argv differs from private-config invocation or leaks the sentinel.");
            if (ResumeThread(process.Thread) == uint.MaxValue) throw Error("Resume official executor");
            var spawnMs = watch.Elapsed.TotalMilliseconds;
            var remaining = (uint)Math.Clamp(30_000 - watch.ElapsedMilliseconds, 0, 30_000);
            if (WaitForSingleObject(process.Process, remaining) != 0) throw new TimeoutException("Official executor exceeded its bounded owner lifetime.");
            if (!GetExitCodeProcess(process.Process, out var exitCode)) throw Error("Read official executor exit status");
            var accounting = default(BasicAccounting);
            do
            {
                if (!QueryInformationJobObject(job, 1, &accounting, sizeof(BasicAccounting), out _)) throw Error("Read outer Job cleanup");
                if (accounting.ActiveProcesses == 0) break;
                Thread.Sleep(10);
            }
            while (watch.Elapsed < TimeSpan.FromSeconds(30));
            Program.Require(accounting.ActiveProcesses == 0, "Official executor left processes in the outer Job.");
            File.WriteAllText(Path.Combine(work, "owner-observation.txt"), "inheritedJob=" + inheritedJob.ToString(CultureInfo.InvariantCulture) + "\nprocessId=" + process.ProcessId.ToString(CultureInfo.InvariantCulture) + "\njobTotalProcesses=" + accounting.TotalProcesses.ToString(CultureInfo.InvariantCulture) + "\njobActiveProcesses=0\n");
            return new LaunchResult(process.ProcessId, unchecked((int)exitCode), spawnMs);
        }
        finally
        {
            // Always bound cleanup, including a create-success/assign-failure.
            if (process.Process != 0)
            {
                if (WaitForSingleObject(process.Process, 0) != 0) { _ = TerminateProcess(process.Process, 125); _ = WaitForSingleObject(process.Process, 5_000); }
                _ = CloseHandle(process.Process);
                _ = CloseHandle(process.Thread);
            }
            _ = TerminateJobObject(job, 125);
            if (attributes != 0) { DeleteProcThreadAttributeList(attributes); Marshal.FreeHGlobal(attributes); }
            _ = CloseHandle(stdout);
            _ = CloseHandle(stdin);
        }
    }

    private static unsafe string ReadCommandLine(nint process)
    {
        const int capacity = 65_536;
        var buffer = Marshal.AllocHGlobal(capacity);
        try
        {
            var status = NtQueryInformationProcess(process, 60, buffer, capacity, out _);
            Program.Require(status == 0, "Unable to read back actual owned executor argv.");
            var text = (UnicodeString*)buffer;
            Program.Require(text->Length % 2 == 0 && text->Buffer >= buffer && text->Buffer + text->Length <= buffer + capacity, "Invalid owned executor command-line readback.");
            return Marshal.PtrToStringUni(text->Buffer, text->Length / 2) ?? "";
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static Win32Exception Error(string operation) => new(Marshal.GetLastPInvokeError(), operation + " failed.");
    private readonly record struct LaunchResult(uint ProcessId, int ExitCode, double SpawnMs);
    [StructLayout(LayoutKind.Sequential)] private struct StartupInfo { public int Cb; public nint Reserved, Desktop, Title; public uint X, Y, XSize, YSize, XChars, YChars, FillAttribute, Flags; public ushort ShowWindow, Reserved2Size; public nint Reserved2, StdInput, StdOutput, StdError; }
    [StructLayout(LayoutKind.Sequential)] private struct StartupInfoEx { public StartupInfo Info; public nint Attributes; }
    [StructLayout(LayoutKind.Sequential)] private struct ProcessInformation { public nint Process, Thread; public uint ProcessId, ThreadId; }
    [StructLayout(LayoutKind.Sequential)] private struct BasicLimits { public long ProcessTime, JobTime; public uint LimitFlags; public nuint MinimumWorkingSet, MaximumWorkingSet; public uint ActiveProcessLimit; public nuint Affinity; public uint PriorityClass, SchedulingClass; }
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimits { public BasicLimits Basic; public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes; public nuint ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemory, PeakJobMemory; }
    [StructLayout(LayoutKind.Sequential)] private struct BasicAccounting { public long UserTime, KernelTime, PeriodUser, PeriodKernel; public uint PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses; }
    [StructLayout(LayoutKind.Sequential)] private struct UnicodeString { public ushort Length, MaximumLength; public nint Buffer; }
    [LibraryImport("ntdll.dll")] private static partial int NtQueryInformationProcess(nint process, int kind, nint information, int length, out int returned);
    [LibraryImport("kernel32.dll", EntryPoint = "CreateJobObjectW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)] private static partial SafeFileHandle CreateJobObject(nint attributes, string? name);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static unsafe partial bool SetInformationJobObject(SafeFileHandle job, int kind, void* info, int length);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static unsafe partial bool QueryInformationJobObject(SafeFileHandle job, int kind, void* info, int length, out int returned);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool AssignProcessToJobObject(SafeFileHandle job, nint process);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool IsProcessInJob(nint process, nint job, [MarshalAs(UnmanagedType.Bool)] out bool result);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool DuplicateHandle(nint sourceProcess, SafeFileHandle source, nint targetProcess, out nint target, uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint options);
    [LibraryImport("kernel32.dll")] private static partial nint GetCurrentProcess();
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool InitializeProcThreadAttributeList(nint list, int count, uint flags, ref nuint bytes);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static unsafe partial bool UpdateProcThreadAttribute(nint list, uint flags, nuint attribute, void* value, nuint bytes, nint previous, nint returned);
    [LibraryImport("kernel32.dll")] private static partial void DeleteProcThreadAttributeList(nint list);
    [LibraryImport("kernel32.dll", EntryPoint = "CreateProcessW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)][return: MarshalAs(UnmanagedType.Bool)] private static unsafe partial bool CreateProcess(string application, char* command, nint processAttributes, nint threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint flags, char* environment, string directory, ref StartupInfoEx startup, out ProcessInformation process);
    [LibraryImport("kernel32.dll", SetLastError = true)] private static partial uint ResumeThread(nint thread);
    [LibraryImport("kernel32.dll", SetLastError = true)] private static partial uint WaitForSingleObject(nint handle, uint milliseconds);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool GetExitCodeProcess(nint process, out uint exitCode);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool TerminateProcess(nint process, uint exitCode);
    [LibraryImport("kernel32.dll", SetLastError = true)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool TerminateJobObject(SafeFileHandle job, uint exitCode);
    [LibraryImport("kernel32.dll")][return: MarshalAs(UnmanagedType.Bool)] private static partial bool CloseHandle(nint handle);
    [LibraryImport("advapi32.dll", EntryPoint = "ConvertStringSecurityDescriptorToSecurityDescriptorW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool ConvertStringSecurityDescriptorToSecurityDescriptor(string text, uint revision, out nint descriptor, out uint bytes);
    [LibraryImport("advapi32.dll", EntryPoint = "SetFileSecurityW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)][return: MarshalAs(UnmanagedType.Bool)] private static partial bool SetFileSecurity(string path, uint information, nint descriptor);
    [LibraryImport("kernel32.dll")] private static partial nint LocalFree(nint memory);
}

internal sealed class WindowsRequest
{
    public string Version { get; set; } = "1.0.0";
    public string Containment { get; set; } = "processcontainer";
    public WindowsProcess Process { get; set; } = new();
    public WindowsFilesystem Filesystem { get; set; } = new();
    public WindowsFallback Fallback { get; set; } = new();
    public WindowsNetwork Network { get; set; } = new();
    public WindowsTelemetry Telemetry { get; set; } = new();
}
internal sealed class WindowsProcess { public string CommandLine { get; set; } = ""; public string Cwd { get; set; } = ""; public string[] Env { get; set; } = []; public uint Timeout { get; set; } = 10_000; }
internal sealed class WindowsFilesystem { public string[] ReadwritePaths { get; set; } = []; public string[] ReadonlyPaths { get; set; } = []; public string[] DeniedPaths { get; set; } = []; }
internal sealed class WindowsFallback { public bool AllowDaclMutation { get; set; } }
internal sealed class WindowsNetwork { public WindowsNetworkDirection Egress { get; set; } = new(); public WindowsNetworkDirection Ingress { get; set; } = new(); }
internal sealed class WindowsNetworkDirection { public string Default { get; set; } = "deny"; }
internal sealed class WindowsTelemetry { public bool Enabled { get; set; } }
[System.Text.Json.Serialization.JsonSourceGenerationOptions(PropertyNamingPolicy = System.Text.Json.Serialization.JsonKnownNamingPolicy.CamelCase, WriteIndented = true)]
[System.Text.Json.Serialization.JsonSerializable(typeof(WindowsRequest))]
internal sealed partial class WindowsJson : System.Text.Json.Serialization.JsonSerializerContext;
